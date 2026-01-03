document.addEventListener("DOMContentLoaded", () => {
    initPageReady();
    initTooltips();
    const yearHolder = document.querySelector("[data-current-year]");
    if (yearHolder) {
        yearHolder.textContent = new Date().getFullYear();
    }

    initKanbanBoard();
    initPreventiveCalendar();
    initSmartActions();
    initCountups();
    initAiDescriptionEnhancer();
    initAiTechnicianRecommendation();
    initAiPredictiveRecommendations();
    initOtpFlow();
});

function initPageReady() {
    document.body.classList.add('page-ready');
}

function initTooltips() {
    if (!window.bootstrap) return;
    const triggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    triggerList.forEach((el) => new bootstrap.Tooltip(el));
}

function readCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') || '' : '';
}

function initOtpFlow() {
    const countdownEl = document.querySelector('[data-otp-countdown]');
    const resendBtn = document.querySelector('[data-otp-resend]');
    if (!countdownEl) return;

    let remaining = Number(countdownEl.dataset.seconds || 0);
    const tick = () => {
        if (remaining <= 0) {
            countdownEl.textContent = 'expired';
            if (resendBtn) resendBtn.disabled = false;
            return;
        }
        const minutes = Math.floor(remaining / 60);
        const seconds = remaining % 60;
        countdownEl.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
        remaining -= 1;
        if (remaining >= 0) setTimeout(tick, 1000);
    };

    if (resendBtn && remaining > 0) {
        resendBtn.disabled = true;
        setTimeout(() => (resendBtn.disabled = false), Math.min(remaining, 90) * 1000);
    }

    tick();
}

function initKanbanBoard() {
    const board = document.querySelector('[data-kanban-board]');
    if (!board || typeof Sortable === 'undefined') return;

    const loader = board.querySelector('[data-kanban-loader]');
    const feedback = board.querySelector('[data-kanban-feedback]');
    const refreshBtn = document.querySelector('[data-kanban-refresh]');
    const autoRefreshToggle = document.querySelector('[data-kanban-autorefresh]');
    const fetchUrl = board.dataset.fetchUrl;
    const moveTemplate = board.dataset.moveUrlTemplate;
    const csrfToken = board.dataset.csrfToken || readCsrfToken();
    let sortables = [];
    let autoRefreshTimer = null;

    const columns = {};
    board.querySelectorAll('[data-kanban-column]').forEach((col) => {
        const status = col.dataset.status;
        columns[status] = {
            list: col.querySelector('[data-kanban-list]'),
            count: col.querySelector('[data-kanban-count]'),
            el: col,
        };
        col.querySelector('[data-kanban-list]').style.position = 'relative';
    });

    let currentData = safeParse(board.dataset.initial) || { columns: {}, counts: {} };
    renderBoard(currentData);

    function safeParse(value) {
        try {
            return JSON.parse(value || '{}');
        } catch (err) {
            console.error('Failed to parse kanban payload', err);
            return {};
        }
    }

    function buildCard(card) {
        const overdueBadge = card.overdue ? '<span class="badge text-bg-danger ms-1">Overdue</span>' : '';
        const scheduled = card.scheduled_date ? `<div class="d-flex align-items-center gap-1 text-secondary x-small"><i class="bi bi-calendar-week"></i><span>${card.scheduled_date}</span></div>` : '';
        const techName = card.assigned_technician.name || 'Unassigned';
        const team = card.team || 'No team';
        const canMove = card.can_move ? 'true' : 'false';
        return `
            <div class="kanban-card" data-request-id="${card.id}" data-status="${card.status}" data-can-move="${canMove}">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <div class="d-flex flex-column">
                        <div class="kanban-pill status-${card.status} text-uppercase fw-bold">${card.status.replace('_',' ')}</div>
                        <div class="fw-semibold mt-1">${card.subject}</div>
                        <div class="text-secondary small">${card.equipment || 'Equipment not set'}</div>
                    </div>
                    <div class="d-flex flex-column align-items-end gap-1">
                        <span class="badge rounded-pill text-bg-${card.request_type === 'preventive' ? 'info' : 'warning'} text-uppercase">${card.request_type === 'preventive' ? 'Preventive' : 'Breakdown'}</span>
                        ${overdueBadge}
                    </div>
                </div>
                <div class="kanban-meta d-flex align-items-center justify-content-between">
                    <div class="d-flex align-items-center gap-2">
                        <div class="tech-avatar" style="--avatar-color: ${card.assigned_technician.color}">${card.assigned_technician.name ? card.assigned_technician.initials : '<i class="bi bi-person"></i>'}</div>
                        <div class="d-flex flex-column">
                            <span class="fw-semibold small">${techName}</span>
                            <span class="text-secondary x-small">${team}</span>
                        </div>
                    </div>
                    ${scheduled}
                </div>
            </div>
        `;
    }

    function renderBoard(data) {
        currentData = data;
        Object.entries(columns).forEach(([status, column]) => {
            const cards = data.columns?.[status] || [];
            column.count.textContent = cards.length;
            if (!cards.length) {
                column.list.innerHTML = '<div class="kanban-empty text-secondary small">No requests in this stage.</div>';
            } else {
                column.list.innerHTML = cards.map(buildCard).join('');
            }
        });
        rebuildSortables();
    }

    function rebuildSortables() {
        sortables.forEach((instance) => instance.destroy());
        sortables = [];
        Object.values(columns).forEach((column) => {
            const sortable = new Sortable(column.list, {
                group: 'kanban-flow',
                animation: 180,
                ghostClass: 'sortable-ghost',
                dragClass: 'sortable-chosen',
                onMove: (evt) => {
                    Object.values(columns).forEach((c) => c.list.classList.remove('sortable-using'));
                    if (evt.to) evt.to.classList.add('sortable-using');
                    return evt.dragged?.dataset?.canMove === 'true';
                },
                onEnd: (evt) => handleDrop(evt),
                onStart: () => column.list.classList.add('sortable-using'),
                onUnchoose: () => column.list.classList.remove('sortable-using'),
                onSort: () => column.list.classList.remove('sortable-using'),
            });
            sortables.push(sortable);
        });
    }

    function handleDrop(evt) {
        const cardEl = evt.item;
        const fromStatus = evt.from.closest('[data-kanban-column]').dataset.status;
        const toStatus = evt.to.closest('[data-kanban-column]').dataset.status;
        const requestId = Number(cardEl.dataset.requestId);
        const canMove = cardEl.dataset.canMove === 'true';

        Object.values(columns).forEach((c) => c.list.classList.remove('sortable-using'));

        if (!canMove) {
            showFeedback('You do not have permission to move this card.', 'negative');
            renderBoard(currentData);
            return;
        }

        if (fromStatus === toStatus) {
            renderBoard(currentData);
            return;
        }

        persistMove(requestId, toStatus);
    }

    function persistMove(id, targetStatus) {
        toggleLoader(true);
        const moveUrl = moveTemplate.replace('/0/move', `/${id}/move`);
        fetch(moveUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken,
            },
            body: JSON.stringify({ target_status: targetStatus }),
        })
            .then(async (res) => {
                const payload = await res.json();
                if (!res.ok) {
                    throw new Error(payload.message || 'Unable to update request');
                }
                return payload;
            })
            .then((payload) => {
                renderBoard(payload.kanban);
                showFeedback('Status updated and synced.', 'positive');
            })
            .catch((err) => {
                console.error(err);
                showFeedback(err.message, 'negative');
                renderBoard(currentData);
            })
            .finally(() => toggleLoader(false));
    }

    function refreshBoard() {
        toggleLoader(true);
        fetch(fetchUrl, {
            headers: {
                'X-CSRFToken': csrfToken,
            },
        })
            .then(async (res) => {
                const payload = await res.json();
                if (!res.ok) {
                    throw new Error(payload.message || 'Failed to refresh board');
                }
                return payload;
            })
            .then((payload) => renderBoard(payload))
            .catch((err) => showFeedback(err.message, 'negative'))
            .finally(() => toggleLoader(false));
    }

    function toggleLoader(show) {
        if (!loader) return;
        loader.hidden = !show;
    }

    function showFeedback(message, tone = 'positive') {
        if (!feedback) return;
        feedback.textContent = message;
        feedback.classList.remove('positive', 'negative');
        feedback.classList.add(tone === 'positive' ? 'positive' : 'negative');
        feedback.hidden = false;
        setTimeout(() => (feedback.hidden = true), 3200);
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', refreshBoard);
    }

    if (autoRefreshToggle) {
        const setup = () => {
            if (autoRefreshToggle.checked) {
                autoRefreshTimer = setInterval(refreshBoard, 30000);
            } else if (autoRefreshTimer) {
                clearInterval(autoRefreshTimer);
                autoRefreshTimer = null;
            }
        };
        autoRefreshToggle.addEventListener('change', setup);
        setup();
    }
}

function initPreventiveCalendar() {
    const calendarShell = document.querySelector('[data-preventive-calendar]');
    if (!calendarShell || typeof FullCalendar === 'undefined') return;

    const calendarEl = calendarShell.querySelector('#preventiveCalendar');
    const eventsUrl = calendarShell.dataset.eventsUrl;
    const createUrl = calendarShell.dataset.createUrl;
    const detailTemplate = calendarShell.dataset.detailUrlTemplate;
    const rescheduleTemplate = calendarShell.dataset.rescheduleUrlTemplate;
    const canCreate = calendarShell.dataset.canCreate === 'true';
    const isAdmin = calendarShell.dataset.isAdmin === 'true';
    const currentUserId = Number(calendarShell.dataset.currentUserId || 0);
    const today = calendarShell.dataset.today;
    const csrfToken = readCsrfToken();
    const loader = calendarShell.querySelector('[data-calendar-loader]');

    const createModalEl = document.getElementById('createPreventiveModal');
    const createModal = createModalEl ? new bootstrap.Modal(createModalEl) : null;
    const createForm = document.getElementById('createPreventiveForm');
    const createFeedback = document.getElementById('createPreventiveFeedback');
    const createDateInput = document.getElementById('preventiveScheduledDate');

    const detailModalEl = document.getElementById('preventiveDetailModal');
    const detailModal = detailModalEl ? new bootstrap.Modal(detailModalEl) : null;
    const detailFeedback = document.getElementById('preventiveDetailFeedback');
    const detailFields = {
        subject: document.getElementById('detailSubject'),
        equipment: document.getElementById('detailEquipment'),
        technician: document.getElementById('detailTechnician'),
        status: document.getElementById('detailStatus'),
        scheduled: document.getElementById('detailSchedule'),
        description: document.getElementById('detailDescription'),
        link: document.getElementById('detailOpenRequest'),
    };

    const rescheduleForm = document.getElementById('preventiveRescheduleForm');
    const rescheduleDate = document.getElementById('rescheduleDate');
    const rescheduleTechnician = document.getElementById('rescheduleTechnician');
    const rescheduleSubmit = document.getElementById('rescheduleSubmit');

    if (createDateInput) {
        createDateInput.setAttribute('min', today);
    }
    if (rescheduleDate) {
        rescheduleDate.setAttribute('min', today);
    }

    const calendar = new FullCalendar.Calendar(calendarEl, {
        initialView: 'dayGridMonth',
        selectable: canCreate,
        navLinks: true,
        height: 'auto',
        headerToolbar: {
            start: 'prev,next today',
            center: 'title',
            end: 'dayGridMonth,timeGridWeek,timeGridDay,listWeek',
        },
        views: {
            dayGridMonth: { titleFormat: { month: 'long', year: 'numeric' } },
            timeGridWeek: { slotMinTime: '06:00:00', slotMaxTime: '22:00:00' },
        },
        buttonText: {
            today: 'Today',
            month: 'Month',
            week: 'Week',
            day: 'Day',
            list: 'Agenda',
        },
        eventTimeFormat: { hour: '2-digit', minute: '2-digit', meridiem: false },
        eventSources: [
            function (info, success, failure) {
                toggleLoader(true);
                const url = `${eventsUrl}?start=${encodeURIComponent(info.startStr)}&end=${encodeURIComponent(info.endStr)}`;
                fetch(url, { headers: { 'X-CSRFToken': csrfToken } })
                    .then(async (res) => {
                        const payload = await res.json();
                        if (!res.ok) throw new Error(payload.message || 'Unable to load preventive schedule');
                        const events = Array.isArray(payload) ? payload : payload.events;
                        success((events || []).map(mapEvent));
                    })
                    .catch((err) => {
                        console.error(err);
                        failure(err);
                    })
                    .finally(() => toggleLoader(false));
            },
        ],
        dateClick: (info) => {
            if (!canCreate || !createModal || !createForm) return;
            createForm.reset();
            createFeedback.hidden = true;
            if (createDateInput) {
                createDateInput.value = info.dateStr;
            }
            createModal.show();
        },
        eventClick: (info) => openDetail(info.event.id),
        eventContent: (arg) => buildEventContent(arg.event),
        eventClassNames: (arg) => {
            const props = arg.event.extendedProps || {};
            const classes = [`req-${props.status || 'new'}`];
            if (props.overdue) classes.push('req-overdue');
            return classes;
        },
    });

    calendar.render();

    function mapEvent(event) {
        return {
            id: String(event.id),
            title: event.title || event.subject,
            start: event.scheduled_date || event.start,
            allDay: true,
            extendedProps: { ...event },
        };
    }

    function toggleLoader(show) {
        if (!loader) return;
        loader.hidden = !show;
    }

    function buildEventContent(event) {
        const props = event.extendedProps || {};
        const tech = props.assigned_technician || 'Unassigned';
        const equipment = props.equipment || 'Equipment TBD';
        const statusLabel = (props.status || '').replace('_', ' ') || 'Scheduled';
        const overdueBadge = props.overdue ? '<span class="badge bg-danger-subtle text-danger ms-1">Overdue</span>' : '';
        return {
            html: `
                <div class="fc-event-rich">
                    <div class="d-flex align-items-center justify-content-between">
                        <span class="fw-semibold text-truncate">${props.subject || event.title}</span>
                        <span class="badge status-pill status-${props.status || 'new'}">${statusLabel}</span>
                    </div>
                    <div class="text-secondary x-small text-truncate">${equipment}</div>
                    <div class="text-secondary x-small text-truncate"><i class="bi bi-person me-1"></i>${tech}${overdueBadge}</div>
                </div>
            `,
        };
    }

    function showFeedback(el, message, tone = 'danger') {
        if (!el) return;
        el.textContent = message;
        el.classList.remove('alert-success', 'alert-danger', 'd-none');
        el.classList.add(tone === 'success' ? 'alert-success' : 'alert-danger');
        el.hidden = false;
    }

    function resetFeedback(el) {
        if (!el) return;
        el.hidden = true;
    }

    function openDetail(eventId) {
        if (!detailModal) return;
        resetFeedback(detailFeedback);
        const detailUrl = detailTemplate.replace('0', eventId);
        toggleLoader(true);
        fetch(detailUrl, { headers: { 'X-CSRFToken': csrfToken } })
            .then(async (res) => {
                const payload = await res.json();
                if (!res.ok) throw new Error(payload.message || 'Unable to load request');
                const evt = payload.event || payload;
                populateDetail(evt);
                detailModal.show();
            })
            .catch((err) => showFeedback(detailFeedback, err.message || 'Unable to load event'))
            .finally(() => toggleLoader(false));
    }

    function populateDetail(evt) {
        if (!evt) return;
        const canEdit = isAdmin || (evt.assigned_technician_id && Number(evt.assigned_technician_id) === currentUserId);
        detailFields.subject.textContent = evt.subject;
        detailFields.equipment.textContent = evt.equipment || 'Not specified';
        detailFields.technician.textContent = evt.assigned_technician || 'Unassigned';
        detailFields.status.innerHTML = `<span class="badge status-pill status-${evt.status}">${(evt.status || '').replace('_',' ')}</span>${evt.overdue ? '<span class="badge bg-danger-subtle text-danger ms-1">Overdue</span>' : ''}`;
        detailFields.scheduled.textContent = evt.scheduled_date;
        detailFields.description.textContent = evt.description || 'No description provided.';
        detailFields.link.href = evt.detail_url;

        if (rescheduleForm) rescheduleForm.dataset.eventId = evt.id;
        if (rescheduleDate) rescheduleDate.value = evt.scheduled_date;
        if (rescheduleTechnician && evt.assigned_technician_id) rescheduleTechnician.value = evt.assigned_technician_id;

        const disable = !canEdit;
        if (rescheduleDate) rescheduleDate.disabled = disable;
        if (rescheduleTechnician) rescheduleTechnician.disabled = disable;
        if (rescheduleSubmit) rescheduleSubmit.disabled = disable;
    }

    if (createForm && createModal) {
        createForm.addEventListener('submit', (evt) => {
            evt.preventDefault();
            resetFeedback(createFeedback);
            const formData = new FormData(createForm);
            const payload = {
                subject: formData.get('subject') || '',
                equipment_id: Number(formData.get('equipment_id') || 0),
                description: formData.get('description') || '',
                scheduled_date: formData.get('scheduled_date') || '',
                assigned_technician_id: Number(formData.get('assigned_technician_id') || 0) || null,
            };

            toggleLoader(true);
            fetch(createUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify(payload),
            })
                .then(async (res) => {
                    const body = await res.json();
                    if (!res.ok) throw new Error(body.message || 'Unable to create request');
                    const eventPayload = body.event || body;
                    calendar.addEvent(mapEvent(eventPayload));
                    createModal.hide();
                    createForm.reset();
                })
                .catch((err) => showFeedback(createFeedback, err.message))
                .finally(() => toggleLoader(false));
        });
    }

    if (rescheduleForm && detailModal) {
        rescheduleForm.addEventListener('submit', (evt) => {
            evt.preventDefault();
            resetFeedback(detailFeedback);
            const eventId = rescheduleForm.dataset.eventId;
            if (!eventId) return;
            const payload = {
                scheduled_date: rescheduleDate ? rescheduleDate.value : null,
                assigned_technician_id: rescheduleTechnician ? Number(rescheduleTechnician.value || 0) || null : null,
            };
            const targetUrl = rescheduleTemplate.replace('0', eventId);
            toggleLoader(true);
            fetch(targetUrl, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify(payload),
            })
                .then(async (res) => {
                    const body = await res.json();
                    if (!res.ok) throw new Error(body.message || 'Unable to update schedule');
                    const updated = body.event || body;
                    const existing = calendar.getEventById(String(updated.id));
                    if (existing) {
                        existing.setStart(updated.scheduled_date);
                        existing.setExtendedProp('scheduled_date', updated.scheduled_date);
                        existing.setExtendedProp('assigned_technician', updated.assigned_technician);
                        existing.setExtendedProp('assigned_technician_id', updated.assigned_technician_id);
                        existing.setExtendedProp('status', updated.status);
                        existing.setExtendedProp('overdue', updated.overdue);
                    } else {
                        calendar.addEvent(mapEvent(updated));
                    }
                    detailModal.hide();
                })
                .catch((err) => showFeedback(detailFeedback, err.message))
                .finally(() => toggleLoader(false));
        });
    }
}

function initSmartActions() {
    const shell = document.querySelector('[data-request-smart-actions]');
    if (!shell) return;

    const actionUrl = shell.dataset.actionUrl;
    const statusTarget = shell.dataset.statusTarget ? document.querySelector(shell.dataset.statusTarget) : null;
    const assigneeTarget = document.querySelector('[data-smart-assignee]');
    const loader = shell.querySelector('[data-smart-loader]');
    const feedback = shell.querySelector('[data-smart-feedback]');
    const buttons = shell.querySelectorAll('[data-smart-action]');
    const csrfToken = readCsrfToken();

    const renderStatus = (status, overdue) => {
        const cls = {
            new: 'status-pill status-new',
            in_progress: 'status-pill status-in_progress',
            repaired: 'status-pill status-repaired',
            scrap: 'status-pill status-scrap',
        }[status] || 'status-pill';
        const icon = {
            new: 'plus-circle',
            in_progress: 'activity',
            repaired: 'check-circle',
            scrap: 'x-octagon',
        }[status] || 'dot';
        const label = (status || '').replace('_', ' ').toUpperCase();
        const overdueBadge = overdue ? '<span class="badge badge-overdue badge-overdue-pulse ms-1">Overdue</span>' : '';
        return `<span class="${cls}"><i class="bi bi-${icon} me-1"></i>${label}</span>${overdueBadge}`;
    };

    const toggleButtons = (state) => {
        buttons.forEach((btn) => {
            const action = btn.dataset.smartAction;
            const key = action === 'repaired' ? 'can_repair' : `can_${action}`;
            if (state?.actions && Object.prototype.hasOwnProperty.call(state.actions, key)) {
                btn.disabled = !state.actions[key];
            }
        });
    };

    const setLoading = (isLoading) => {
        if (loader) loader.hidden = !isLoading;
        buttons.forEach((btn) => {
            if (isLoading) {
                btn.dataset.wasDisabled = btn.disabled ? 'true' : 'false';
                btn.disabled = true;
            } else {
                btn.disabled = btn.dataset.wasDisabled === 'true';
            }
        });
    };

    const showFeedback = (message, tone = 'danger') => {
        if (!feedback) return;
        feedback.textContent = message;
        feedback.classList.remove('alert-success', 'alert-danger', 'd-none');
        feedback.classList.add(tone === 'success' ? 'alert-success' : 'alert-danger');
        feedback.hidden = false;
    };

    const clearFeedback = () => {
        if (!feedback) return;
        feedback.hidden = true;
    };

    buttons.forEach((btn) => {
        btn.addEventListener('click', () => {
            const action = btn.dataset.smartAction;
            if (!actionUrl) return;
            clearFeedback();
            setLoading(true);
            fetch(actionUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken,
                },
                body: JSON.stringify({ action }),
            })
                .then(async (res) => {
                    const payload = await res.json();
                    if (!res.ok) throw new Error(payload.message || 'Unable to update request');
                    return payload.request || payload;
                })
                .then((state) => {
                    if (statusTarget) {
                        statusTarget.innerHTML = renderStatus(state.status, state.overdue);
                    }
                    if (assigneeTarget) {
                        assigneeTarget.textContent = state.assigned_technician || 'Unassigned';
                    }
                    setLoading(false);
                    toggleButtons(state);
                    clearFeedback();
                })
                .catch((err) => {
                    showFeedback(err.message || 'Unable to update request');
                    setLoading(false);
                });
        });
    });
}

function initCountups() {
    const els = document.querySelectorAll('[data-countup-target]');
    if (!els.length || typeof window.requestAnimationFrame === 'undefined') return;

    els.forEach((el) => {
        const target = Number(el.dataset.countupTarget || 0);
        if (Number.isNaN(target)) return;
        const duration = Math.min(1200, 400 + target * 12);
        const start = performance.now();
        const formatter = new Intl.NumberFormat('en-US');

        const tick = (now) => {
            const progress = Math.min(1, (now - start) / duration);
            const value = Math.floor(progress * target);
            el.textContent = formatter.format(value);
            if (progress < 1) requestAnimationFrame(tick);
            else el.textContent = formatter.format(target);
        };

        requestAnimationFrame(tick);
    });
}

function renderMarkdown(text) {
    if (!text) return '';
    // Prefer marked.js if available, with safe defaults.
    if (typeof marked !== 'undefined') {
        marked.setOptions({ mangle: false, headerIds: false, breaks: true });
        const html = marked.parse(text);
        const container = document.createElement('div');
        container.innerHTML = html;
        container.querySelectorAll('script').forEach((node) => node.remove());
        return container.innerHTML;
    }
    // Fallback: escape basic HTML and preserve line breaks.
    const escaped = text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    return escaped.replace(/\n/g, '<br>');
}

function getAiModalElements() {
    const modalEl = document.getElementById('aiModal');
    if (!modalEl) return null;
    if (!modalEl._instance) {
        // Use default backdrop so users can click outside and restore page scroll after closing
        modalEl._instance = new bootstrap.Modal(modalEl, { backdrop: true, keyboard: true, focus: true });
    }
    return {
        modal: modalEl._instance,
        title: modalEl.querySelector('[data-ai-modal-title]'),
        body: modalEl.querySelector('[data-ai-modal-body]'),
        loader: modalEl.querySelector('[data-ai-modal-loader]'),
        hint: modalEl.querySelector('[data-ai-modal-hint]'),
        applyBtn: modalEl.querySelector('[data-ai-modal-apply]'),
    };
}

function showAiModal({ title, body, markdownBody = null, applyLabel = null, onApply = null, hint = null, loading = false }) {
    const nodes = getAiModalElements();
    if (!nodes) return;
    nodes.title.textContent = title || 'AI Intelligence';
    const htmlBody = markdownBody ? renderMarkdown(markdownBody) : body || '';
    nodes.body.innerHTML = htmlBody;
    nodes.hint.textContent = hint || 'Generated with GearGuard India.';
    nodes.loader.hidden = !loading;
    nodes.applyBtn.hidden = !applyLabel;
    nodes.applyBtn.textContent = applyLabel || '';
    nodes.applyBtn.onclick = null;
    if (applyLabel && typeof onApply === 'function') {
        nodes.applyBtn.onclick = () => {
            onApply();
            nodes.modal.hide();
        };
    }
    nodes.modal.show();
}

function setButtonThinking(btn, thinking) {
    if (!btn) return;
    if (thinking) {
        btn.dataset.originalLabel = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status"></span>Thinking';
    } else {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalLabel || btn.innerHTML;
    }
}

function initAiDescriptionEnhancer() {
    const btn = document.querySelector('[data-ai-enhance-btn]');
    const textarea = document.querySelector('[data-ai-enhance-target]');
    if (!btn || !textarea) return;

    const subjectInput = document.querySelector('input[name="subject"]');
    const typeSelect = document.querySelector('select[name="request_type"]');
    const prioritySelect = document.querySelector('select[name="priority"]');
    const equipmentSelect = document.querySelector('select[name="equipment_id"]');

    btn.addEventListener('click', () => {
        setButtonThinking(btn, true);
        const payload = {
            subject: subjectInput ? subjectInput.value : '',
            description: textarea.value || '',
            request_type: typeSelect ? typeSelect.value : 'corrective',
            priority: prioritySelect ? prioritySelect.value : 'normal',
            equipment_id: equipmentSelect ? Number(equipmentSelect.value || 0) || null : null,
        };

        fetch(btn.dataset.aiEnhanceUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': readCsrfToken(),
            },
            body: JSON.stringify(payload),
        })
            .then(async (res) => {
                const body = await res.json();
                if (!res.ok) throw new Error(body.message || 'Unable to enhance description');
                return body.enhanced;
            })
            .then((enhanced) => {
                showAiModal({
                    title: 'AI Description Enhancement',
                    body: `<div class="ai-modal-text">${renderMarkdown(enhanced || '')}</div>`,
                    applyLabel: 'Apply to form',
                    onApply: () => {
                        textarea.value = enhanced;
                    },
                    hint: 'Editable suggestion. GearGuard India used tenant-scoped context.',
                });
            })
            .catch((err) => {
                showAiModal({ title: 'AI Unavailable', body: `<div class="text-danger">${err.message}</div>` });
            })
            .finally(() => setButtonThinking(btn, false));
    });
}

function initAiTechnicianRecommendation() {
    const btn = document.querySelector('[data-ai-tech-recommend]');
    const select = document.querySelector('[data-ai-tech-target]');
    if (!btn || !select) return;

    btn.addEventListener('click', () => {
        setButtonThinking(btn, true);
        fetch(btn.dataset.aiTechUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': readCsrfToken(),
            },
        })
            .then(async (res) => {
                const body = await res.json();
                if (!res.ok) throw new Error(body.message || 'Unable to get recommendation');
                return body.recommendation;
            })
            .then((rec) => {
                const name = rec.name || 'No match';
                const reasoning = rec.reasoning || 'No rationale provided.';
                const confidence = rec.confidence || '';
                showAiModal({
                    title: 'AI Technician Recommendation',
                    body: `
                        <div class="d-flex flex-column gap-2">
                            <div class="ai-chip"><strong>Suggested:</strong> ${name}</div>
                            ${confidence ? `<div class="text-secondary small">Confidence: ${confidence}</div>` : ''}
                            <div class="text-secondary small">${renderMarkdown(reasoning)}</div>
                        </div>
                    `,
                    applyLabel: rec.technician_id ? 'Apply Recommendation' : null,
                    onApply: () => {
                        if (rec.technician_id) {
                            select.value = rec.technician_id;
                        }
                    },
                    hint: 'GearGuard India balanced specialization, workload, and repair speed.',
                });
            })
            .catch((err) => {
                showAiModal({ title: 'AI Unavailable', body: `<div class="text-danger">${err.message}</div>` });
            })
            .finally(() => setButtonThinking(btn, false));
    });
}

function initAiPredictiveRecommendations() {
    const buttons = document.querySelectorAll('[data-ai-predict-btn]');
    if (!buttons.length) return;

    buttons.forEach((btn) => {
        btn.addEventListener('click', () => {
            setButtonThinking(btn, true);
            fetch(btn.dataset.aiPredictUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': readCsrfToken(),
                },
            })
                .then(async (res) => {
                    const body = await res.json();
                    if (!res.ok) throw new Error(body.message || 'Unable to fetch AI recommendation');
                    return body.recommendation;
                })
                .then((rec) => {
                    const risk = rec.risk_level || '—';
                    const probability = rec.probability || '—';
                    const frequency = rec.frequency || '—';
                    const actions = Array.isArray(rec.preventive_actions) ? rec.preventive_actions : [];
                    const guidance = Array.isArray(rec.guidance) ? rec.guidance : [];
                    const narrative = rec.narrative || '';

                    const bodyHtml = `
                        <div class="d-flex flex-column gap-2">
                            <div class="ai-chip text-danger">Risk level: ${risk}</div>
                            <div class="ai-chip text-primary">Breakdown probability: ${probability}</div>
                            <div class="ai-chip text-success">Frequency tweak: ${frequency}</div>
                            ${actions.length ? `<div><div class="fw-semibold mb-1">Preventive actions</div><ul class="mb-2">${actions.map((a) => `<li>${a}</li>`).join('')}</ul></div>` : ''}
                            ${guidance.length ? `<div><div class="fw-semibold mb-1">Guidance</div><ul class="mb-2">${guidance.map((g) => `<li>${g}</li>`).join('')}</ul></div>` : ''}
                            ${narrative ? `<div class="text-secondary small">${narrative}</div>` : ''}
                        </div>`;

                    showAiModal({
                        title: `Predictive Maintenance · ${btn.dataset.equipmentName || ''}`,
                        body: bodyHtml,
                        hint: 'Built from equipment history only within this tenant.',
                    });
                })
                .catch((err) => showAiModal({ title: 'AI Unavailable', body: `<div class="text-danger">${err.message}</div>` }))
                .finally(() => setButtonThinking(btn, false));
        });
    });
}
