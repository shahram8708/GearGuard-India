from __future__ import annotations

from datetime import date, datetime
import csv
import io
import json

from werkzeug.datastructures import MultiDict

from flask import Blueprint, abort, flash, jsonify, make_response, redirect, render_template, request, url_for, current_app
import razorpay
from flask_login import current_user, login_required
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload

from app.extensions import db, csrf
from app.ai_service import ai_service
from app.email_service import send_maintenance_alert, send_subscription_event
from app.forms import (
    EquipmentForm,
    BulkUserUploadForm,
    MaintenanceTeamForm,
    MaintenanceRequestForm,
    MaintenanceStatusForm,
    MaintenanceTechnicianAssignForm,
    OrganizationSettingsForm,
    RegisterUserForm,
    SubscriptionCheckoutForm,
    TechnicianAssignmentForm,
    UserUpdateForm,
)
from app.models import (
    Equipment,
    EquipmentStatus,
    MaintenanceRequest,
    MaintenanceStatus,
    MaintenanceTeam,
    Organization,
    OrganizationSubscription,
    PaymentHistory,
    PaymentStatus,
    RequestType,
    SubscriptionStatus,
    TechnicianMembership,
    User,
    UserRole,
)
from app.tenant import role_required, tenant_query, tenant_required


KANBAN_COLUMNS: tuple[MaintenanceStatus, ...] = (
    MaintenanceStatus.NEW,
    MaintenanceStatus.IN_PROGRESS,
    MaintenanceStatus.REPAIRED,
    MaintenanceStatus.SCRAP,
)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


def _active_admin_count() -> int:
    return tenant_query(User).filter_by(role=UserRole.ADMIN, active=True).count()


def _would_remove_last_admin(target: User, new_role: UserRole, new_active: bool) -> bool:
    if target.role != UserRole.ADMIN or not target.active:
        return False
    admin_count = _active_admin_count()
    if admin_count > 1:
        return False
    # If this is the only active admin, prevent demotion or deactivation
    return new_role != UserRole.ADMIN or not new_active


def _populate_equipment_form_choices(form: EquipmentForm) -> None:
    org_id = current_user.organization_id
    teams = tenant_query(MaintenanceTeam).order_by(MaintenanceTeam.team_name.asc()).all()
    users = tenant_query(User).order_by(User.name.asc()).all()

    form.maintenance_team_id.choices = [(0, "Unassigned")] + [(team.id, team.team_name) for team in teams]
    form.assigned_to_user_id.choices = [(0, "Unassigned")] + [(user.id, user.name) for user in users]


def _build_sort_clause(sort_key: str):
    sort_map = {
        "name": Equipment.name.asc(),
        "name_desc": Equipment.name.desc(),
        "status": Equipment.status.asc(),
        "status_desc": Equipment.status.desc(),
        "created": Equipment.created_at.desc(),
        "created_asc": Equipment.created_at.asc(),
    }
    return sort_map.get(sort_key, Equipment.created_at.desc())


def _user_team_ids(user_id: int | None = None) -> set[int]:
    lookup_id = user_id or current_user.id
    memberships = tenant_query(TechnicianMembership).filter_by(user_id=lookup_id).all()
    return {m.team_id for m in memberships}


def _request_is_visible(req: MaintenanceRequest) -> bool:
    if current_user.role == UserRole.ADMIN:
        return True
    if req.requested_by_id == current_user.id or req.assigned_technician_id == current_user.id:
        return True
    return req.team_id is not None and req.team_id in _user_team_ids()


def _can_modify_request(req: MaintenanceRequest) -> bool:
    if current_user.role == UserRole.ADMIN:
        return True
    if req.assigned_technician_id == current_user.id:
        return True
    if req.team_id and req.team_id in _user_team_ids():
        return True
    return False


def _maintenance_recipients(req: MaintenanceRequest) -> set[str]:
    recipients: set[str] = set()
    technician = req.assigned_technician or (User.query.get(req.assigned_technician_id) if req.assigned_technician_id else None)
    requester = req.requested_by or (User.query.get(req.requested_by_id) if req.requested_by_id else None)

    if technician and technician.email:
        recipients.add(technician.email)
    if requester and requester.email:
        recipients.add(requester.email)

    admins = (
        User.query.filter_by(organization_id=req.organization_id, role=UserRole.ADMIN, active=True)
        .with_entities(User.email)
        .all()
    )
    for admin_email, in admins:
        if admin_email:
            recipients.add(admin_email)

    return recipients


def _send_maintenance_notification(
    req: MaintenanceRequest,
    subject: str,
    message: str,
    extra_items: list[str] | None = None,
) -> None:
    equipment = req.equipment or (Equipment.query.get(req.equipment_id) if req.equipment_id else None)
    team = req.team or (MaintenanceTeam.query.get(req.team_id) if req.team_id else None)
    technician = req.assigned_technician or (User.query.get(req.assigned_technician_id) if req.assigned_technician_id else None)

    items = [
        f"Equipment: {equipment.name if equipment else 'Unassigned'}",
        f"Status: {req.status.value.replace('_', ' ').title()}",
        f"Priority: {req.priority.title()}",
    ]

    if req.scheduled_date:
        items.append(f"Scheduled date: {req.scheduled_date.isoformat()}")
    if team:
        items.append(f"Team: {team.team_name}")
    if technician:
        items.append(f"Technician: {technician.name}")
    if extra_items:
        items.extend(extra_items)

    context = {
        "title": subject,
        "message": message,
        "items": items,
    }

    for email in _maintenance_recipients(req):
        try:
            send_maintenance_alert(email, subject, context)
        except Exception:
            current_app.logger.exception("Failed to send maintenance alert to %s", email)


def _visible_requests_query():
    query = tenant_query(MaintenanceRequest).options(
        joinedload(MaintenanceRequest.equipment),
        joinedload(MaintenanceRequest.team),
        joinedload(MaintenanceRequest.assigned_technician),
        joinedload(MaintenanceRequest.requested_by),
    )
    if current_user.role != UserRole.ADMIN:
        team_ids = _user_team_ids()
        filters = [
            MaintenanceRequest.requested_by_id == current_user.id,
            MaintenanceRequest.assigned_technician_id == current_user.id,
        ]
        if team_ids:
            filters.append(MaintenanceRequest.team_id.in_(team_ids))
        query = query.filter(or_(*filters))
    return query


def _kanban_avatar(user: User | None) -> dict[str, str | None]:
    if not user:
        return {"initials": "NA", "color": "#94a3b8", "name": None}
    parts = [p for p in user.name.split(" ") if p]
    initials = "".join([p[0].upper() for p in parts[:2]]) or user.name[:2].upper()
    palette = [
        "#4f46e5",
        "#0ea5e9",
        "#22c55e",
        "#f59e0b",
        "#a855f7",
        "#ec4899",
        "#14b8a6",
    ]
    color = palette[user.id % len(palette)] if user.id is not None else palette[0]
    return {"initials": initials, "color": color, "name": user.name}


def _serialize_request_for_kanban(req: MaintenanceRequest) -> dict[str, object]:
    avatar = _kanban_avatar(req.assigned_technician)
    return {
        "id": req.id,
        "subject": req.subject,
        "equipment": req.equipment.name if req.equipment else None,
        "team": req.team.team_name if req.team else None,
        "status": req.status.value,
        "request_type": req.request_type.value,
        "priority": req.priority,
        "overdue": req.is_overdue,
        "scheduled_date": req.scheduled_date.isoformat() if req.scheduled_date else None,
        "assigned_technician": avatar,
        "assigned_technician_id": req.assigned_technician_id,
        "can_move": _can_modify_request(req),
        "created_at": req.created_at.isoformat() if req.created_at else None,
    }


def _serialize_request_for_calendar(req: MaintenanceRequest) -> dict[str, object]:
    return {
        "id": req.id,
        "title": req.subject,
        "subject": req.subject,
        "start": req.scheduled_date.isoformat() if req.scheduled_date else None,
        "scheduled_date": req.scheduled_date.isoformat() if req.scheduled_date else None,
        "allDay": True,
        "status": req.status.value,
        "request_type": req.request_type.value,
        "priority": req.priority,
        "overdue": req.is_overdue,
        "equipment": req.equipment.name if req.equipment else None,
        "equipment_id": req.equipment_id,
        "team": req.team.team_name if req.team else None,
        "assigned_technician": req.assigned_technician.name if req.assigned_technician else None,
        "assigned_technician_id": req.assigned_technician_id,
        "requested_by": req.requested_by.name if req.requested_by else None,
        "detail_url": url_for("admin.maintenance_detail", request_id=req.id),
        "created_at": req.created_at.isoformat() if req.created_at else None,
        "description": req.description,
    }


def _kanban_payload(requests: list[MaintenanceRequest]) -> dict[str, object]:
    grouped: dict[str, list[dict[str, object]]] = {status.value: [] for status in KANBAN_COLUMNS}
    for req in requests:
        grouped[req.status.value].append(_serialize_request_for_kanban(req))
    counts = {status.value: len(grouped[status.value]) for status in KANBAN_COLUMNS}
    return {"columns": grouped, "counts": counts}


def _allowed_transitions() -> dict[MaintenanceStatus, set[MaintenanceStatus]]:
    return {
        MaintenanceStatus.NEW: {MaintenanceStatus.IN_PROGRESS, MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP},
        MaintenanceStatus.IN_PROGRESS: {MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP},
        MaintenanceStatus.REPAIRED: {MaintenanceStatus.SCRAP},
        MaintenanceStatus.SCRAP: set(),
    }


def _apply_transition(req: MaintenanceRequest, target_status: MaintenanceStatus) -> None:
    if target_status == req.status:
        return
    allowed = _allowed_transitions().get(req.status, set())
    if target_status not in allowed:
        raise ValueError("Illegal workflow transition")

    now = datetime.utcnow()
    if target_status == MaintenanceStatus.IN_PROGRESS:
        if not req.assigned_technician_id:
            raise ValueError("Assign a technician before starting work")
        req.start(now)

    elif target_status == MaintenanceStatus.REPAIRED:
        if not req.assigned_technician_id:
            raise ValueError("Assign a technician before resolving")
        if req.started_at is None:
            req.started_at = now
        req.mark_repaired(now)

    elif target_status == MaintenanceStatus.SCRAP:
        req.mark_scrap(now)
        if req.equipment:
            req.equipment.status = EquipmentStatus.SCRAPPED


def _populate_request_form_choices(form: MaintenanceRequestForm) -> None:
    equipments = tenant_query(Equipment).order_by(Equipment.name.asc()).all()
    form.equipment_id.choices = [(eq.id, f"{eq.name} · {eq.category}") for eq in equipments]
    if not equipments:
        flash("Add equipment first before creating maintenance requests.", "warning")


def _load_request_or_404(request_id: int) -> MaintenanceRequest:
    req = (
        tenant_query(MaintenanceRequest)
        .options(
            joinedload(MaintenanceRequest.equipment),
            joinedload(MaintenanceRequest.team),
            joinedload(MaintenanceRequest.assigned_technician),
            joinedload(MaintenanceRequest.requested_by),
        )
        .filter_by(id=request_id)
        .first()
    )
    if not req or not _request_is_visible(req):
        abort(404)
    return req


def _ensure_team_membership(user_id: int, team_id: int) -> TechnicianMembership:
    membership = tenant_query(TechnicianMembership).filter_by(user_id=user_id, team_id=team_id).first()
    if not membership:
        flash("Technician is not a member of this maintenance team.", "danger")
        abort(403)
    return membership


def _equipment_overdue_map(equipment_ids: list[int]) -> dict[int, bool]:
    if not equipment_ids:
        return {}
    overdue_rows = (
        db.session.query(MaintenanceRequest.equipment_id, func.count(MaintenanceRequest.id))
        .filter(
            MaintenanceRequest.organization_id == current_user.organization_id,
            MaintenanceRequest.equipment_id.in_(equipment_ids),
            MaintenanceRequest.scheduled_date.isnot(None),
            MaintenanceRequest.scheduled_date < date.today(),
            MaintenanceRequest.status.notin_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]),
        )
        .group_by(MaintenanceRequest.equipment_id)
        .all()
    )
    return {eq_id: count > 0 for eq_id, count in overdue_rows}


def _equipment_history(equipment_id: int, limit: int = 40) -> list[MaintenanceRequest]:
    return (
        tenant_query(MaintenanceRequest)
        .options(
            joinedload(MaintenanceRequest.assigned_technician),
            joinedload(MaintenanceRequest.team),
        )
        .filter_by(equipment_id=equipment_id)
        .order_by(MaintenanceRequest.created_at.desc())
        .limit(limit)
        .all()
    )


def _technician_workload_snapshot(user: User) -> dict[str, object]:
    open_statuses = {MaintenanceStatus.NEW, MaintenanceStatus.IN_PROGRESS}
    open_count = (
        tenant_query(MaintenanceRequest)
        .filter(
            MaintenanceRequest.assigned_technician_id == user.id,
            MaintenanceRequest.status.in_(open_statuses),
        )
        .count()
    )
    completed_rows = (
        tenant_query(MaintenanceRequest)
        .with_entities(
            func.avg(MaintenanceRequest.duration_hours),
            func.count(MaintenanceRequest.id),
        )
        .filter(
            MaintenanceRequest.assigned_technician_id == user.id,
            MaintenanceRequest.status == MaintenanceStatus.REPAIRED,
            MaintenanceRequest.duration_hours.isnot(None),
        )
        .one()
    )
    avg_duration = round(completed_rows[0], 2) if completed_rows[0] else None
    completed_count = completed_rows[1]
    return {
        "id": user.id,
        "name": user.name,
        "open_count": open_count,
        "completed_repairs": completed_count,
        "avg_duration_hours": avg_duration,
    }


def _smart_action_state(req: MaintenanceRequest) -> dict[str, bool]:
    team_ids = _user_team_ids()
    member_of_team = req.team_id is not None and req.team_id in team_ids
    can_assign_me = (member_of_team or current_user.role == UserRole.ADMIN) and req.status != MaintenanceStatus.SCRAP
    can_start = (
        req.status == MaintenanceStatus.NEW
        and _can_modify_request(req)
        and (req.assigned_technician_id is not None or member_of_team or current_user.role == UserRole.ADMIN)
    )
    can_repair = req.status in {MaintenanceStatus.NEW, MaintenanceStatus.IN_PROGRESS} and _can_modify_request(req)
    can_scrap = req.status != MaintenanceStatus.SCRAP and _can_modify_request(req)
    return {
        "can_assign_me": can_assign_me,
        "can_start": can_start,
        "can_repair": can_repair,
        "can_scrap": can_scrap,
    }


def _smart_action_payload(req: MaintenanceRequest) -> dict[str, object]:
    state = _smart_action_state(req)
    return {
        "id": req.id,
        "status": req.status.value,
        "status_label": req.status.value.replace("_", " ").title(),
        "overdue": req.is_overdue,
        "assigned_technician": req.assigned_technician.name if req.assigned_technician else None,
        "assigned_technician_id": req.assigned_technician_id,
        "equipment_status": req.equipment.status.value if req.equipment else None,
        "actions": state,
    }


def _ensure_subscription(org: Organization) -> OrganizationSubscription:
    sub = org.subscription
    if sub:
        return sub
    trial_seats = current_app.config.get("SUBSCRIPTION_TRIAL_SEATS", 5)
    sub = OrganizationSubscription(
        organization_id=org.id,
        is_trial=True,
        is_active_subscription=False,
        base_fee_paid=False,
        max_users_allowed=trial_seats,
        subscription_status=SubscriptionStatus.TRIAL,
    )
    db.session.add(sub)
    db.session.commit()
    return sub


def _pricing_config() -> dict[str, int | str]:
    base_fee_inr = int(current_app.config.get("SUBSCRIPTION_BASE_FEE_INR", 4999))
    per_member_inr = int(current_app.config.get("SUBSCRIPTION_PER_MEMBER_INR", 499))
    currency = current_app.config.get("SUBSCRIPTION_CURRENCY", "INR")
    return {
        "base_fee_inr": base_fee_inr,
        "base_fee_paise": base_fee_inr * 100,
        "per_member_inr": per_member_inr,
        "per_member_paise": per_member_inr * 100,
        "currency": currency,
    }


def _calculate_upgrade(org: Organization, desired_total_seats: int) -> dict[str, object]:
    sub = _ensure_subscription(org)
    pricing = _pricing_config()
    current_cap = sub.max_users_allowed
    if desired_total_seats <= current_cap:
        return {
            "requires_payment": False,
            "reason": "No capacity increase requested",
            "amount_paise": 0,
            "base_fee_applied": False,
            "additional_seats": 0,
        }

    base_fee_applied = not sub.base_fee_paid
    additional_seats = desired_total_seats - current_cap
    amount_paise = additional_seats * int(pricing["per_member_paise"])
    if base_fee_applied:
        amount_paise += int(pricing["base_fee_paise"])

    return {
        "requires_payment": True,
        "amount_paise": amount_paise,
        "currency": pricing["currency"],
        "base_fee_applied": base_fee_applied,
        "additional_seats": additional_seats,
        "pricing": pricing,
    }


def _enforce_user_quota(org: Organization, *, requested_new_users: int = 1) -> None:
    sub = _ensure_subscription(org)
    current_count = tenant_query(User).count()
    if not sub.can_add_users(requested_new_users, current_count):
        flash("User limit reached. Please upgrade your subscription to add more members.", "danger")
        abort(403)


def _normalize_role(raw_role: str | None) -> UserRole | None:
    if not raw_role:
        return UserRole.USER
    value = raw_role.strip().lower()
    if value in {"admin", "administrator", "org admin", "org_admin", "organization admin"}:
        return UserRole.ADMIN
    if value in {"user", "member", "normal", "standard"}:
        return UserRole.USER
    return None


def _parse_bulk_user_csv(file_storage) -> tuple[list[dict[str, object]], list[str]]:
    try:
        raw_bytes = file_storage.read()
        content = raw_bytes.decode("utf-8-sig")
    except Exception:
        return [], ["Unable to read CSV. Please upload a UTF-8 encoded .csv file."]

    reader = csv.DictReader(io.StringIO(content))
    required = {"name", "email", "password", "role"}
    headers = {h.strip().lower() for h in (reader.fieldnames or []) if h}
    missing = required - headers
    if missing:
        return [], [f"Missing column(s): {', '.join(sorted(missing))}. Expected: name, email, password, role."]

    rows: list[dict[str, object]] = []
    errors: list[str] = []
    seen_emails: set[str] = set()

    for idx, row in enumerate(reader, start=2):
        normalized = {k.strip().lower(): (v or "").strip() for k, v in row.items()}
        name = normalized.get("name", "")
        email = normalized.get("email", "").lower()
        password = normalized.get("password", "")
        role_value = normalized.get("role", "")
        role = _normalize_role(role_value)
        if role is None:
            errors.append(f"Row {idx}: role must be admin or user.")
            continue

        form_data = MultiDict(
            {
                "name": name,
                "email": email,
                "password": password,
                "confirm_password": password,
                "role": role.value,
            }
        )
        form = RegisterUserForm(formdata=form_data, meta={"csrf": False})

        if not form.validate():
            form_errors = "; ".join([msg for field_errors in form.errors.values() for msg in field_errors])
            errors.append(f"Row {idx}: {form_errors}")
            continue

        if email in seen_emails:
            errors.append(f"Row {idx}: duplicate email within CSV: {email}")
            continue

        seen_emails.add(email)
        rows.append({"name": name, "email": email, "password": password, "role": role})

    return rows, errors


def _create_bulk_users(rows: list[dict[str, object]], org: Organization) -> tuple[int, list[str], int]:
    if not rows:
        return 0, ["No valid rows to process."], 0

    emails = [row["email"] for row in rows]
    existing = tenant_query(User).filter(User.email.in_(emails)).all()
    existing_emails = {u.email for u in existing}
    duplicate_notes: list[str] = []

    if existing_emails:
        sample = ", ".join(sorted(existing_emails)[:5])
        suffix = " ..." if len(existing_emails) > 5 else ""
        duplicate_notes.append(f"Skipped {len(existing_emails)} existing email(s): {sample}{suffix}")

    pending = [row for row in rows if row["email"] not in existing_emails]
    if not pending:
        return 0, duplicate_notes, len(existing_emails)

    _enforce_user_quota(org, requested_new_users=len(pending))

    for payload in pending:
        user = User(
            name=str(payload["name"]).strip(),
            email=str(payload["email"]).lower().strip(),
            organization_id=org.id,
            role=payload["role"],
            active=True,
        )
        user.set_password(str(payload["password"]))
        db.session.add(user)

    db.session.commit()
    return len(pending), duplicate_notes, len(existing_emails)


@admin_bp.route("/", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def dashboard():
    org: Organization = current_user.organization
    settings_form = OrganizationSettingsForm()

    if settings_form.validate_on_submit():
        new_name = settings_form.organization_name.data.strip()
        if new_name.lower() != org.name.lower():
            name_conflict = Organization.query.filter(
                Organization.name.ilike(new_name), Organization.id != org.id
            ).first()
            if name_conflict:
                flash("Another organization already uses that name.", "danger")
                return redirect(url_for("admin.dashboard"))

            new_slug = Organization.generate_unique_slug(new_name, exclude_id=org.id)
            org.name = new_name
            org.slug = new_slug
            db.session.commit()
            flash(
                f"Organization updated. New login slug: {org.slug}",
                "success",
            )
            return redirect(url_for("admin.dashboard"))
        else:
            flash("No changes detected.", "info")

    if not settings_form.is_submitted():
        settings_form.organization_name.data = org.name

    users = tenant_query(User).order_by(User.created_at.desc()).all()
    stats = {
        "user_count": len(users),
        "admin_count": len([u for u in users if u.role == UserRole.ADMIN]),
        "active_count": len([u for u in users if u.active]),
    }

    return render_template(
        "admin/dashboard.html",
        page_title="Admin Dashboard",
        organization=org,
        users=users,
        settings_form=settings_form,
        stats=stats,
    )


@admin_bp.route("/users/sample.csv", methods=["GET"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def bulk_user_sample():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["name", "email", "password", "role"])
    writer.writerow(["Alex Doe", "alex@example.com", "Str0ngPass!23", "admin"])
    writer.writerow(["Jamie Lee", "jamie@example.com", "Str0ngPass!56", "user"])

    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = "attachment; filename=bulk_users_sample.csv"
    return response


@admin_bp.route("/users/new", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def add_user():
    form = RegisterUserForm()
    bulk_form = BulkUserUploadForm(prefix="bulk")
    org = current_user.organization

    if request.method == "POST" and bulk_form.submit.data and bulk_form.validate_on_submit():
        rows, parse_errors = _parse_bulk_user_csv(bulk_form.file.data)
        for err in parse_errors:
            flash(err, "danger")

        if rows:
            created, duplicate_notes, _ = _create_bulk_users(rows, org)
            for note in duplicate_notes:
                flash(note, "warning")

            if created:
                flash(f"Created {created} user(s) from CSV.", "success")
                return redirect(url_for("admin.dashboard"))

            flash("No new users were created from the CSV file.", "warning")
        else:
            flash("No users were created from the CSV file.", "warning")

    if not form.is_submitted():
        form.role.data = UserRole.USER.value

    if form.submit.data and form.validate_on_submit():
        email = form.email.data.strip().lower()

        existing_email = tenant_query(User).filter(User.email == email, User.id != current_user.id).first()
        if existing_email:
            flash("That email is already registered in the platform.", "warning")
            return render_template("admin/add_user.html", form=form, bulk_form=bulk_form, page_title="Add User")

        _enforce_user_quota(org)

        user = User(
            name=form.name.data.strip(),
            email=email,
            organization_id=org.id,
            role=UserRole(form.role.data),
            active=True,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("User account created successfully.", "success")
        return redirect(url_for("admin.dashboard"))

    return render_template("admin/add_user.html", form=form, bulk_form=bulk_form, page_title="Add User")


@admin_bp.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def edit_user(user_id: int):
    user = tenant_query(User).filter_by(id=user_id).first_or_404()
    form = UserUpdateForm(obj=user)

    if not form.is_submitted():
        form.role.data = user.role.value
        form.active.data = user.active

    if form.validate_on_submit():
        new_email = form.email.data.strip().lower()
        new_role = UserRole(form.role.data)
        new_active = bool(form.active.data)

        email_conflict = tenant_query(User).filter(User.email == new_email, User.id != user.id).first()
        if email_conflict:
            flash("That email is already registered.", "danger")
            return render_template("admin/edit_user.html", form=form, user=user, page_title="Edit User")

        if _would_remove_last_admin(user, new_role, new_active):
            flash("You must keep at least one active admin in the organization.", "danger")
            return render_template("admin/edit_user.html", form=form, user=user, page_title="Edit User")

        user.name = form.name.data.strip()
        user.email = new_email
        user.role = new_role
        user.active = new_active
        db.session.commit()
        flash("User updated successfully.", "success")
        return redirect(url_for("admin.dashboard"))

    return render_template("admin/edit_user.html", form=form, user=user, page_title="Edit User")


@admin_bp.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def toggle_user(user_id: int):
    user = tenant_query(User).filter_by(id=user_id).first_or_404()
    desired_active = not user.active

    if _would_remove_last_admin(user, user.role, desired_active):
        flash("Cannot deactivate the last active admin.", "danger")
        return redirect(url_for("admin.dashboard"))

    user.active = desired_active
    db.session.commit()
    state = "activated" if user.active else "deactivated"
    flash(f"User {state}.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def delete_user(user_id: int):
    user = tenant_query(User).filter_by(id=user_id).first_or_404()
    if user.id == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin.dashboard"))

    if _would_remove_last_admin(user, user.role, False):
        flash("Cannot remove the last active admin.", "danger")
        return redirect(url_for("admin.dashboard"))

    db.session.delete(user)
    db.session.commit()
    flash("User removed from organization.", "success")
    return redirect(url_for("admin.dashboard"))


@admin_bp.route("/equipment", methods=["GET"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def equipment_index():
    search = (request.args.get("search") or "").strip()
    status_filter = (request.args.get("status") or "").strip().lower()
    sort = (request.args.get("sort") or "created").strip()
    page = request.args.get("page", default=1, type=int)

    query = (
        tenant_query(Equipment)
        .options(joinedload(Equipment.maintenance_team), joinedload(Equipment.assigned_to_user))
    )

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                Equipment.name.ilike(like),
                Equipment.category.ilike(like),
                Equipment.serial_number.ilike(like),
                Equipment.department.ilike(like),
                Equipment.location.ilike(like),
            )
        )

    if status_filter:
        try:
            status_enum = EquipmentStatus(status_filter)
            query = query.filter(Equipment.status == status_enum)
        except ValueError:
            flash("Unknown status filter ignored.", "warning")

    query = query.order_by(_build_sort_clause(sort))
    pagination = query.paginate(page=page, per_page=12, error_out=False)
    equipment_items = pagination.items

    request_counts: dict[int | None, int] = {}
    overdue_map: dict[int, bool] = {}
    if equipment_items:
        equipment_ids = [eq.id for eq in equipment_items]
        counts = (
            db.session.query(MaintenanceRequest.equipment_id, func.count(MaintenanceRequest.id))
            .filter(
                MaintenanceRequest.organization_id == current_user.organization_id,
                MaintenanceRequest.equipment_id.in_(equipment_ids),
            )
            .group_by(MaintenanceRequest.equipment_id)
            .all()
        )
        request_counts = {eq_id: count for eq_id, count in counts}
        overdue_map = _equipment_overdue_map(equipment_ids)

    return render_template(
        "admin/equipment_list.html",
        equipment_items=equipment_items,
        pagination=pagination,
        search=search,
        sort=sort,
        status_filter=status_filter,
        request_counts=request_counts,
        equipment_overdue_map=overdue_map,
        EquipmentStatus=EquipmentStatus,
    )


@admin_bp.route("/equipment/new", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def equipment_create():
    form = EquipmentForm()
    _populate_equipment_form_choices(form)

    if form.validate_on_submit():
        org_id = current_user.organization_id
        name = form.name.data.strip()
        serial = form.serial_number.data.strip() if form.serial_number.data else None

        name_conflict = Equipment.query.filter(
            Equipment.organization_id == org_id,
            Equipment.name.ilike(name),
        ).first()
        if name_conflict:
            flash("Equipment name already exists in this organization.", "danger")
            return render_template("admin/equipment_form.html", form=form, page_title="Add Equipment")

        if serial:
            serial_conflict = Equipment.query.filter(
                Equipment.organization_id == org_id,
                Equipment.serial_number.ilike(serial),
            ).first()
            if serial_conflict:
                flash("Serial number already registered in this organization.", "danger")
                return render_template("admin/equipment_form.html", form=form, page_title="Add Equipment")

        team_id = form.maintenance_team_id.data or 0
        assigned_user_id = form.assigned_to_user_id.data or 0
        team = tenant_query(MaintenanceTeam).filter_by(id=team_id).first() if team_id else None
        technician = tenant_query(User).filter_by(id=assigned_user_id).first() if assigned_user_id else None

        equipment = Equipment(
            organization_id=org_id,
            name=name,
            category=form.category.data.strip(),
            serial_number=serial,
            department=form.department.data.strip() if form.department.data else None,
            location=form.location.data.strip() if form.location.data else None,
            purchase_date=form.purchase_date.data,
            warranty_expiry=form.warranty_expiry.data,
            status=EquipmentStatus(form.status.data),
        )
        equipment.assign_team(team)
        equipment.assign_user(technician)

        db.session.add(equipment)
        db.session.commit()
        flash("Equipment created successfully.", "success")
        return redirect(url_for("admin.equipment_index"))

    return render_template("admin/equipment_form.html", form=form, page_title="Add Equipment")


@admin_bp.route("/equipment/<int:equipment_id>/edit", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def equipment_edit(equipment_id: int):
    equipment = tenant_query(Equipment).options(joinedload(Equipment.maintenance_team)).filter_by(id=equipment_id).first_or_404()
    form = EquipmentForm(obj=equipment)
    _populate_equipment_form_choices(form)

    if not form.is_submitted():
        form.maintenance_team_id.data = equipment.maintenance_team_id or 0
        form.assigned_to_user_id.data = equipment.assigned_to_user_id or 0
        form.status.data = equipment.status.value

    if form.validate_on_submit():
        org_id = current_user.organization_id
        name = form.name.data.strip()
        serial = form.serial_number.data.strip() if form.serial_number.data else None

        name_conflict = Equipment.query.filter(
            Equipment.organization_id == org_id,
            Equipment.name.ilike(name),
            Equipment.id != equipment.id,
        ).first()
        if name_conflict:
            flash("Another equipment with this name exists in your organization.", "danger")
            return render_template("admin/equipment_form.html", form=form, page_title="Edit Equipment", equipment=equipment)

        if serial:
            serial_conflict = Equipment.query.filter(
                Equipment.organization_id == org_id,
                Equipment.serial_number.ilike(serial),
                Equipment.id != equipment.id,
            ).first()
            if serial_conflict:
                flash("Serial number already registered in this organization.", "danger")
                return render_template("admin/equipment_form.html", form=form, page_title="Edit Equipment", equipment=equipment)

        team_id = form.maintenance_team_id.data or 0
        assigned_user_id = form.assigned_to_user_id.data or 0
        team = tenant_query(MaintenanceTeam).filter_by(id=team_id).first() if team_id else None
        technician = tenant_query(User).filter_by(id=assigned_user_id).first() if assigned_user_id else None

        equipment.name = name
        equipment.category = form.category.data.strip()
        equipment.serial_number = serial
        equipment.department = form.department.data.strip() if form.department.data else None
        equipment.location = form.location.data.strip() if form.location.data else None
        equipment.purchase_date = form.purchase_date.data
        equipment.warranty_expiry = form.warranty_expiry.data
        equipment.status = EquipmentStatus(form.status.data)
        equipment.assign_team(team)
        equipment.assign_user(technician)

        db.session.commit()
        flash("Equipment updated successfully.", "success")
        return redirect(url_for("admin.equipment_index"))

    return render_template("admin/equipment_form.html", form=form, page_title="Edit Equipment", equipment=equipment)


@admin_bp.route("/equipment/<int:equipment_id>/delete", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def equipment_delete(equipment_id: int):
    equipment = tenant_query(Equipment).filter_by(id=equipment_id).first_or_404()
    has_history = MaintenanceRequest.query.filter_by(organization_id=current_user.organization_id, equipment_id=equipment.id).count() > 0

    if has_history:
        equipment.status = EquipmentStatus.SCRAPPED
        db.session.commit()
        flash("Equipment has maintenance history; marked as scrapped instead of deletion.", "warning")
    else:
        db.session.delete(equipment)
        db.session.commit()
        flash("Equipment removed.", "success")

    return redirect(url_for("admin.equipment_index"))


@admin_bp.route("/equipment/<int:equipment_id>/ai/predict", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def equipment_ai_predict(equipment_id: int):
    equipment = (
        tenant_query(Equipment)
        .options(joinedload(Equipment.maintenance_team), joinedload(Equipment.assigned_to_user))
        .filter_by(id=equipment_id)
        .first_or_404()
    )
    history = _equipment_history(equipment.id)

    try:
        recommendation = ai_service.predictive_recommendations(equipment, history)
        return jsonify({"recommendation": recommendation})
    except Exception as exc:  # pragma: no cover - runtime safety
        current_app.logger.exception("AI predictive recommendations failed")
        return jsonify({"message": str(exc)}), 502


@admin_bp.route("/teams", methods=["GET"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def teams_index():
    org_id = current_user.organization_id
    teams = tenant_query(MaintenanceTeam).order_by(MaintenanceTeam.team_name.asc()).all()

    member_counts = dict(
        db.session.query(TechnicianMembership.team_id, func.count(TechnicianMembership.id))
        .filter_by(organization_id=org_id)
        .group_by(TechnicianMembership.team_id)
        .all()
    )
    equipment_counts = dict(
        db.session.query(Equipment.maintenance_team_id, func.count(Equipment.id))
        .filter_by(organization_id=org_id)
        .group_by(Equipment.maintenance_team_id)
        .all()
    )

    return render_template(
        "admin/team_list.html",
        teams=teams,
        member_counts=member_counts,
        equipment_counts=equipment_counts,
    )


@admin_bp.route("/teams/new", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def team_create():
    form = MaintenanceTeamForm()
    if form.validate_on_submit():
        org_id = current_user.organization_id
        name = form.team_name.data.strip()
        conflict = MaintenanceTeam.query.filter(
            MaintenanceTeam.organization_id == org_id,
            MaintenanceTeam.team_name.ilike(name),
        ).first()
        if conflict:
            flash("A team with this name already exists.", "danger")
            return render_template("admin/team_form.html", form=form, page_title="Create Team")

        team = MaintenanceTeam(
            team_name=name,
            description=form.description.data.strip() if form.description.data else None,
            organization_id=org_id,
        )
        db.session.add(team)
        db.session.commit()
        flash("Team created successfully.", "success")
        return redirect(url_for("admin.teams_index"))

    return render_template("admin/team_form.html", form=form, page_title="Create Team")


@admin_bp.route("/teams/<int:team_id>/edit", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def team_edit(team_id: int):
    team = tenant_query(MaintenanceTeam).filter_by(id=team_id).first_or_404()
    form = MaintenanceTeamForm(obj=team)

    if form.validate_on_submit():
        name = form.team_name.data.strip()
        conflict = MaintenanceTeam.query.filter(
            MaintenanceTeam.organization_id == current_user.organization_id,
            MaintenanceTeam.team_name.ilike(name),
            MaintenanceTeam.id != team.id,
        ).first()
        if conflict:
            flash("A team with this name already exists.", "danger")
            return render_template("admin/team_form.html", form=form, page_title="Edit Team", team=team)

        team.team_name = name
        team.description = form.description.data.strip() if form.description.data else None
        db.session.commit()
        flash("Team updated successfully.", "success")
        return redirect(url_for("admin.teams_index"))

    return render_template("admin/team_form.html", form=form, page_title="Edit Team", team=team)


@admin_bp.route("/teams/<int:team_id>/delete", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def team_delete(team_id: int):
    team = tenant_query(MaintenanceTeam).filter_by(id=team_id).first_or_404()
    has_equipment = Equipment.query.filter_by(organization_id=current_user.organization_id, maintenance_team_id=team.id).count() > 0
    has_members = TechnicianMembership.query.filter_by(organization_id=current_user.organization_id, team_id=team.id).count() > 0

    if has_equipment or has_members:
        flash("Team cannot be deleted while equipment or technicians are assigned.", "danger")
        return redirect(url_for("admin.teams_index"))

    db.session.delete(team)
    db.session.commit()
    flash("Team deleted.", "success")
    return redirect(url_for("admin.teams_index"))


@admin_bp.route("/teams/<int:team_id>", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def team_detail(team_id: int):
    team = tenant_query(MaintenanceTeam)
    team = team.options(joinedload(MaintenanceTeam.technicians).joinedload(TechnicianMembership.user)).filter_by(id=team_id).first_or_404()
    assignment_form = TechnicianAssignmentForm()

    available_users = (
        tenant_query(User)
        .filter(User.active.is_(True))
        .order_by(User.name.asc())
        .all()
    )
    assigned_user_ids = {membership.user_id for membership in team.technicians}
    assignment_form.user_id.choices = [
        (user.id, user.name)
        for user in available_users
        if user.id not in assigned_user_ids
    ]

    if request.method == "POST":
        if assignment_form.validate_on_submit():
            user_id = assignment_form.user_id.data
            if user_id in assigned_user_ids:
                flash("Technician already on this team.", "warning")
            else:
                membership = TechnicianMembership(
                    organization_id=current_user.organization_id,
                    user_id=user_id,
                    team_id=team.id,
                )
                db.session.add(membership)
                db.session.commit()
                flash("Technician added to team.", "success")
            return redirect(url_for("admin.team_detail", team_id=team.id))
        else:
            flash("Please select a valid technician.", "danger")

    team_equipment = tenant_query(Equipment).filter_by(maintenance_team_id=team.id).all()
    team_request_count = tenant_query(MaintenanceRequest).filter_by(team_id=team.id).count()
    team_overdue_count = (
        tenant_query(MaintenanceRequest)
        .filter(
            MaintenanceRequest.team_id == team.id,
            MaintenanceRequest.scheduled_date.isnot(None),
            MaintenanceRequest.scheduled_date < date.today(),
            MaintenanceRequest.status.notin_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]),
        )
        .count()
    )

    return render_template(
        "admin/team_detail.html",
        team=team,
        assignment_form=assignment_form,
        team_equipment=team_equipment,
        team_request_count=team_request_count,
        team_overdue_count=team_overdue_count,
    )


@admin_bp.route("/teams/<int:team_id>/technicians/<int:membership_id>/remove", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def technician_remove(team_id: int, membership_id: int):
    team = tenant_query(MaintenanceTeam).filter_by(id=team_id).first_or_404()
    membership = tenant_query(TechnicianMembership).filter_by(id=membership_id, team_id=team.id).first_or_404()

    db.session.delete(membership)
    db.session.commit()
    flash("Technician removed from team.", "success")
    return redirect(url_for("admin.team_detail", team_id=team.id))


@admin_bp.route("/maintenance", methods=["GET"])
@login_required
@tenant_required
def maintenance_index():
    status_filter = (request.args.get("status") or "").strip().lower()
    type_filter = (request.args.get("type") or "").strip().lower()
    overdue_only = request.args.get("overdue", "false").lower() == "true"
    equipment_filter = request.args.get("equipment_id", type=int)
    team_filter = request.args.get("team_id", type=int)

    query = (
        tenant_query(MaintenanceRequest)
        .options(
            joinedload(MaintenanceRequest.equipment),
            joinedload(MaintenanceRequest.team),
            joinedload(MaintenanceRequest.assigned_technician),
            joinedload(MaintenanceRequest.requested_by),
        )
        .order_by(MaintenanceRequest.created_at.desc())
    )

    if current_user.role != UserRole.ADMIN:
        team_ids = _user_team_ids()
        filters = [MaintenanceRequest.requested_by_id == current_user.id, MaintenanceRequest.assigned_technician_id == current_user.id]
        if team_ids:
            filters.append(MaintenanceRequest.team_id.in_(team_ids))
        query = query.filter(or_(*filters))

    if equipment_filter:
        query = query.filter(MaintenanceRequest.equipment_id == equipment_filter)

    if team_filter:
        query = query.filter(MaintenanceRequest.team_id == team_filter)

    if status_filter:
        try:
            status_enum = MaintenanceStatus(status_filter)
            query = query.filter(MaintenanceRequest.status == status_enum)
        except ValueError:
            flash("Unknown status filter ignored.", "warning")

    if type_filter:
        try:
            type_enum = RequestType(type_filter)
            query = query.filter(MaintenanceRequest.request_type == type_enum)
        except ValueError:
            flash("Unknown request type filter ignored.", "warning")

    if overdue_only:
        query = query.filter(
            MaintenanceRequest.scheduled_date.isnot(None),
            MaintenanceRequest.scheduled_date < date.today(),
            MaintenanceRequest.status.notin_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]),
        )

    requests = query.all()
    equipment_options = tenant_query(Equipment).order_by(Equipment.name.asc()).all()
    technician_options = tenant_query(User).filter(User.active.is_(True)).order_by(User.name.asc()).all()
    team_options = tenant_query(MaintenanceTeam).order_by(MaintenanceTeam.team_name.asc()).all()
    status_counts = {
        status: tenant_query(MaintenanceRequest).filter_by(organization_id=current_user.organization_id, status=status).count()
        for status in MaintenanceStatus
    }
    total_requests = sum(status_counts.values())
    preventive_counts = {
        status: tenant_query(MaintenanceRequest)
        .filter(
            MaintenanceRequest.organization_id == current_user.organization_id,
            MaintenanceRequest.request_type == RequestType.PREVENTIVE,
            MaintenanceRequest.status == status,
        )
        .count()
        for status in MaintenanceStatus
    }
    preventive_overdue = (
        tenant_query(MaintenanceRequest)
        .filter(
            MaintenanceRequest.request_type == RequestType.PREVENTIVE,
            MaintenanceRequest.scheduled_date.isnot(None),
            MaintenanceRequest.scheduled_date < date.today(),
            MaintenanceRequest.status.notin_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]),
        )
        .count()
    )
    overdue_total = (
        tenant_query(MaintenanceRequest)
        .filter(
            MaintenanceRequest.scheduled_date.isnot(None),
            MaintenanceRequest.scheduled_date < date.today(),
            MaintenanceRequest.status.notin_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]),
        )
        .count()
    )

    return render_template(
        "admin/maintenance_list.html",
        requests=requests,
        status_filter=status_filter,
        type_filter=type_filter,
        overdue_only=overdue_only,
        equipment_filter=equipment_filter,
        team_filter=team_filter,
        MaintenanceStatus=MaintenanceStatus,
        RequestType=RequestType,
        status_counts=status_counts,
        total_requests=total_requests,
        preventive_counts=preventive_counts,
        preventive_overdue=preventive_overdue,
        overdue_total=overdue_total,
        equipment_options=equipment_options,
        technician_options=technician_options,
        team_options=team_options,
        today=date.today(),
    )


@admin_bp.route("/maintenance/ai/enhance-description", methods=["POST"])
@login_required
@tenant_required
def maintenance_ai_enhance_description():
    body = request.get_json(silent=True) or {}
    subject = (body.get("subject") or "").strip()
    description = (body.get("description") or "").strip()
    request_type_raw = (body.get("request_type") or RequestType.CORRECTIVE.value)
    priority = (body.get("priority") or "normal").strip()
    equipment_id = body.get("equipment_id")

    if not subject and not description:
        return jsonify({"message": "Subject or description is required for enhancement."}), 400

    try:
        req_type = RequestType(request_type_raw)
    except ValueError:
        return jsonify({"message": "Invalid request type."}), 400

    equipment = None
    if equipment_id:
        equipment = tenant_query(Equipment).filter_by(id=equipment_id).first()
        if not equipment:
            return jsonify({"message": "Equipment not found for this tenant."}), 404

    try:
        enhanced = ai_service.enhance_description(
            subject=subject,
            description=description,
            equipment=equipment,
            request_type=req_type,
            priority=priority,
        )
        return jsonify({"enhanced": enhanced})
    except Exception as exc:  # pragma: no cover - runtime safety
        current_app.logger.exception("AI description enhancement failed")
        return jsonify({"message": str(exc)}), 502


@admin_bp.route("/maintenance/new", methods=["GET", "POST"])
@login_required
@tenant_required
def maintenance_create():
    form = MaintenanceRequestForm()
    _populate_request_form_choices(form)

    if form.validate_on_submit():
        equipment = tenant_query(Equipment).filter_by(id=form.equipment_id.data).first_or_404()
        if equipment.organization_id != current_user.organization_id:
            abort(403)
        if equipment.status == EquipmentStatus.SCRAPPED:
            flash("Cannot create a request for scrapped equipment.", "danger")
            return render_template("admin/maintenance_form.html", form=form, page_title="Create Maintenance Request")

        req = MaintenanceRequest(
            subject=form.subject.data.strip(),
            description=form.description.data.strip() if form.description.data else None,
            request_type=RequestType(form.request_type.data),
            priority=form.priority.data,
            equipment_id=equipment.id,
            scheduled_date=form.scheduled_date.data,
            organization_id=current_user.organization_id,
            requested_by_id=current_user.id,
        )
        req.apply_auto_context()
        db.session.add(req)
        db.session.commit()
        try:
            _send_maintenance_notification(
                req,
                "New maintenance request",
                f"{current_user.name} opened '{req.subject}'.",
                extra_items=[
                    f"Request type: {req.request_type.value.title()}",
                    f"Opened by: {current_user.name}",
                ],
            )
        except Exception:
            current_app.logger.exception("Failed to send maintenance creation alert")
        flash("Maintenance request created.", "success")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    return render_template("admin/maintenance_form.html", form=form, page_title="Create Maintenance Request")


def _technician_choices_for_request(req: MaintenanceRequest) -> list[tuple[int, str]]:
    # If no team is set, fall back to all active users in the tenant so AI and manual assignment still work.
    if not req.team_id:
        users = tenant_query(User).filter(User.active.is_(True)).order_by(User.name.asc()).all()
        return [(u.id, u.name) for u in users]

    memberships = (
        tenant_query(TechnicianMembership)
        .join(User, TechnicianMembership.user_id == User.id)
        .options(joinedload(TechnicianMembership.user))
        .filter(TechnicianMembership.team_id == req.team_id, User.active.is_(True))
        .order_by(User.name.asc())
        .all()
    )
    return [(m.user.id, m.user.name) for m in memberships]


@admin_bp.route("/maintenance/<int:request_id>", methods=["GET"])
@login_required
@tenant_required
def maintenance_detail(request_id: int):
    req = _load_request_or_404(request_id)

    assign_form = MaintenanceTechnicianAssignForm()
    assign_form.technician_id.choices = _technician_choices_for_request(req)

    status_form = MaintenanceStatusForm()
    return render_template(
        "admin/maintenance_detail.html",
        req=req,
        assign_form=assign_form,
        status_form=status_form,
        MaintenanceStatus=MaintenanceStatus,
        smart_actions=_smart_action_state(req),
    )


@admin_bp.route("/maintenance/<int:request_id>/ai/recommend-technician", methods=["POST"])
@login_required
@tenant_required
def maintenance_ai_recommend_technician(request_id: int):
    req = _load_request_or_404(request_id)

    # Visibility: admins see all; technicians limited to their requests/teams
    allowed_user_ids = {req.assigned_technician_id, req.requested_by_id}
    if current_user.role != UserRole.ADMIN and current_user.id not in allowed_user_ids and (req.team_id not in _user_team_ids() if req.team_id else True):
        return jsonify({"message": "You are not allowed to request an AI recommendation for this item."}), 403

    technician_choices = _technician_choices_for_request(req)

    # Fallback: if the request has no team or the team has no members, consider all active technicians in the org.
    if not technician_choices:
        memberships = (
            tenant_query(TechnicianMembership)
            .join(User, TechnicianMembership.user_id == User.id)
            .options(joinedload(TechnicianMembership.user))
            .order_by(User.name.asc())
            .all()
        )
        seen: set[int] = set()
        for membership in memberships:
            user = membership.user
            if not user or not user.active:
                continue
            if user.id in seen:
                continue
            seen.add(user.id)
            technician_choices.append((user.id, user.name))

    if not technician_choices:
        return jsonify({"message": "No eligible technicians found. Add technicians to the organization or assign a maintenance team."}), 400

    technicians: list[dict[str, object]] = []
    for tech_id, name in technician_choices:
        tech = tenant_query(User).filter_by(id=tech_id).first()
        if not tech:
            continue
        workload = _technician_workload_snapshot(tech)
        workload.update(
            {
                "teams": list(_user_team_ids(tech.id)),
                "role": tech.role.value,
            }
        )
        technicians.append(workload)

    history_query = (
        tenant_query(MaintenanceRequest)
        .options(joinedload(MaintenanceRequest.assigned_technician), joinedload(MaintenanceRequest.team))
        .order_by(MaintenanceRequest.created_at.desc())
    )
    if req.team_id:
        history_query = history_query.filter_by(team_id=req.team_id)
    elif req.equipment_id:
        history_query = history_query.filter_by(equipment_id=req.equipment_id)
    history = history_query.limit(40).all()

    try:
        recommendation = ai_service.recommend_technician(req, technicians, history)
        return jsonify({"recommendation": recommendation})
    except Exception as exc:  # pragma: no cover - runtime safety
        current_app.logger.exception("AI technician recommendation failed")
        return jsonify({"message": str(exc)}), 502


@admin_bp.route("/maintenance/<int:request_id>/assign", methods=["POST"])
@login_required
@tenant_required
def maintenance_assign(request_id: int):
    req = _load_request_or_404(request_id)
    form = MaintenanceTechnicianAssignForm()
    form.technician_id.choices = _technician_choices_for_request(req)

    if not form.technician_id.choices:
        flash("No eligible technicians for this team. Add team members first.", "warning")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    if not form.validate_on_submit():
        flash("Select a technician to assign.", "danger")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    technician_id = form.technician_id.data

    if current_user.role != UserRole.ADMIN and technician_id != current_user.id:
        flash("Only admins can assign others. Technicians may self-assign.", "danger")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    if not req.team_id:
        flash("Request is missing a maintenance team. Set a team on the equipment to continue.", "danger")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    _ensure_team_membership(technician_id, req.team_id)

    req.assigned_technician_id = technician_id
    if req.status == MaintenanceStatus.NEW:
        try:
            req.start()
        except ValueError as exc:  # defensive guard
            flash(str(exc), "danger")
            return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    db.session.commit()
    try:
        _send_maintenance_notification(
            req,
            "Technician assigned",
            f"{current_user.name} assigned work to {req.assigned_technician.name if req.assigned_technician else 'a technician'}.",
            extra_items=["Status moved to In Progress"],
        )
    except Exception:
        current_app.logger.exception("Failed to send maintenance assignment alert")
    flash("Technician assigned and work started.", "success")
    return redirect(url_for("admin.maintenance_detail", request_id=req.id))


@admin_bp.route("/maintenance/<int:request_id>/transition", methods=["POST"])
@login_required
@tenant_required
def maintenance_transition(request_id: int):
    req = _load_request_or_404(request_id)
    form = MaintenanceStatusForm()

    if not form.validate_on_submit():
        flash("Choose a valid status transition.", "danger")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    target_status = MaintenanceStatus(form.transition.data)

    if current_user.role != UserRole.ADMIN and req.assigned_technician_id != current_user.id:
        flash("Only admins or the assigned technician can change status.", "danger")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    try:
        if target_status == MaintenanceStatus.IN_PROGRESS:
            if req.status != MaintenanceStatus.NEW:
                raise ValueError("Only NEW requests can move to In Progress.")
            if not req.assigned_technician_id:
                raise ValueError("Assign a technician before starting work.")
            req.start()

        elif target_status == MaintenanceStatus.REPAIRED:
            if req.status not in {MaintenanceStatus.IN_PROGRESS, MaintenanceStatus.NEW}:
                raise ValueError("Request must be active to be marked repaired.")
            if not req.assigned_technician_id:
                raise ValueError("Assign a technician before resolving.")
            req.mark_repaired()

        elif target_status == MaintenanceStatus.SCRAP:
            req.mark_scrap()
            if req.equipment:
                req.equipment.status = EquipmentStatus.SCRAPPED

    except ValueError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("admin.maintenance_detail", request_id=req.id))

    db.session.commit()
    try:
        _send_maintenance_notification(
            req,
            "Maintenance status updated",
            f"Status changed to {req.status.value.replace('_', ' ').title()}.",
        )
    except Exception:
        current_app.logger.exception("Failed to send maintenance status alert")
    flash("Status updated successfully.", "success")
    return redirect(url_for("admin.maintenance_detail", request_id=req.id))


@admin_bp.route("/maintenance/<int:request_id>/smart-action", methods=["POST"])
@login_required
@tenant_required
def maintenance_smart_action(request_id: int):
    req = _load_request_or_404(request_id)
    body = request.get_json(silent=True) or {}
    action = (body.get("action") or "").strip().lower()
    team_ids = _user_team_ids()

    if not action:
        return jsonify({"message": "Action is required."}), 400

    # Permission gate
    if not _can_modify_request(req):
        return jsonify({"message": "You are not allowed to change this request."}), 403

    try:
        if action == "assign_me":
            if req.status == MaintenanceStatus.SCRAP:
                raise ValueError("Scrapped requests cannot be reassigned.")
            if req.team_id and current_user.role != UserRole.ADMIN and req.team_id not in team_ids:
                raise ValueError("You are not a technician on this team.")
            if req.assigned_technician_id and req.assigned_technician_id != current_user.id and current_user.role != UserRole.ADMIN:
                raise ValueError("Already assigned to another technician.")
            req.assigned_technician_id = current_user.id

        elif action == "start":
            if req.status != MaintenanceStatus.NEW:
                raise ValueError("Only NEW requests can start.")
            if not req.assigned_technician_id:
                if req.team_id and current_user.role != UserRole.ADMIN and req.team_id not in team_ids:
                    raise ValueError("You are not a technician on this team.")
                req.assigned_technician_id = current_user.id
            req.start()

        elif action == "repaired":
            if req.status not in {MaintenanceStatus.IN_PROGRESS, MaintenanceStatus.NEW}:
                raise ValueError("Request must be active to mark repaired.")
            if not req.assigned_technician_id:
                if req.team_id and current_user.role != UserRole.ADMIN and req.team_id not in team_ids:
                    raise ValueError("You are not a technician on this team.")
                req.assigned_technician_id = current_user.id
            req.mark_repaired()

        elif action == "scrap":
            req.mark_scrap()
            if req.equipment:
                req.equipment.status = EquipmentStatus.SCRAPPED

        else:
            return jsonify({"message": "Unknown action."}), 400

    except ValueError as exc:  # workflow validation failures
        return jsonify({"message": str(exc)}), 400

    db.session.commit()
    try:
        _send_maintenance_notification(
            req,
            "Maintenance updated",
            f"{current_user.name} performed '{action}' on '{req.subject}'.",
        )
    except Exception:
        current_app.logger.exception("Failed to send maintenance smart-action alert")
    return jsonify({"message": "Request updated.", "request": _smart_action_payload(req)})


@admin_bp.route("/maintenance/kanban", methods=["GET"])
@login_required
@tenant_required
def maintenance_kanban():
    requests = _visible_requests_query().order_by(MaintenanceRequest.created_at.desc()).all()
    payload = _kanban_payload(requests)
    grouped = {status.value: [] for status in KANBAN_COLUMNS}
    for req in requests:
        grouped[req.status.value].append(req)

    return render_template(
        "admin/maintenance_kanban.html",
        page_title="Maintenance Kanban",
        MaintenanceStatus=MaintenanceStatus,
        RequestType=RequestType,
        grouped_requests=grouped,
        kanban_payload=payload,
    )


@admin_bp.route("/maintenance/kanban/data", methods=["GET"])
@login_required
@tenant_required
def maintenance_kanban_data():
    requests = _visible_requests_query().order_by(MaintenanceRequest.created_at.desc()).all()
    return jsonify(_kanban_payload(requests))


@admin_bp.route("/maintenance/kanban/<int:request_id>/move", methods=["POST"])
@login_required
@tenant_required
def maintenance_kanban_move(request_id: int):
    req = _load_request_or_404(request_id)
    body = request.get_json(silent=True) or {}
    target_raw = (body.get("target_status") or "").strip().lower()

    try:
        target_status = MaintenanceStatus(target_raw)
    except ValueError:
        return jsonify({"message": "Unknown target status."}), 400

    if not _can_modify_request(req):
        return jsonify({"message": "You are not allowed to move this request."}), 403

    try:
        # Auto-assign the mover as technician when moving work into execution states
        if target_status in {MaintenanceStatus.IN_PROGRESS, MaintenanceStatus.REPAIRED} and req.assigned_technician_id is None:
            if req.team_id:
                _ensure_team_membership(current_user.id, req.team_id)
            req.assigned_technician_id = current_user.id

        _apply_transition(req, target_status)
    except ValueError as exc:
        return jsonify({"message": str(exc)}), 400

    db.session.commit()
    try:
        _send_maintenance_notification(
            req,
            "Maintenance status updated",
            f"Card moved to {req.status.value.replace('_', ' ').title()} by {current_user.name}.",
        )
    except Exception:
        current_app.logger.exception("Failed to send maintenance kanban alert")
    refreshed = _visible_requests_query().order_by(MaintenanceRequest.created_at.desc()).all()
    return jsonify({"message": "Request updated.", "kanban": _kanban_payload(refreshed), "request": _serialize_request_for_kanban(req)})


def _parse_iso_date(raw: str | None) -> date | None:
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", ""))
        return parsed.date()
    except ValueError:
        return None


@admin_bp.route("/maintenance/calendar/events", methods=["GET"])
@login_required
@tenant_required
def preventive_calendar_events():
    start_raw = request.args.get("start")
    end_raw = request.args.get("end")
    start_date = _parse_iso_date(start_raw)
    end_date = _parse_iso_date(end_raw)

    query = _visible_requests_query().filter(
        MaintenanceRequest.request_type == RequestType.PREVENTIVE,
        MaintenanceRequest.scheduled_date.isnot(None),
    )
    if start_date:
        query = query.filter(MaintenanceRequest.scheduled_date >= start_date)
    if end_date:
        query = query.filter(MaintenanceRequest.scheduled_date <= end_date)

    requests = query.order_by(MaintenanceRequest.scheduled_date.asc()).all()
    return jsonify({"events": [_serialize_request_for_calendar(req) for req in requests]})


@admin_bp.route("/maintenance/calendar/<int:request_id>", methods=["GET"])
@login_required
@tenant_required
def preventive_calendar_detail(request_id: int):
    req = _load_request_or_404(request_id)
    if req.request_type != RequestType.PREVENTIVE or not req.scheduled_date:
        abort(404)
    return jsonify({"event": _serialize_request_for_calendar(req)})


@admin_bp.route("/maintenance/calendar", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def preventive_calendar_create():
    body = request.get_json(silent=True) or {}
    subject = (body.get("subject") or "").strip()
    description = (body.get("description") or "").strip() or None
    equipment_id = int(body.get("equipment_id")) if body.get("equipment_id") else None
    scheduled_raw = (body.get("scheduled_date") or "").strip()
    technician_id = int(body.get("assigned_technician_id")) if body.get("assigned_technician_id") else None

    if not subject or not equipment_id or not scheduled_raw:
        return jsonify({"message": "Subject, equipment, and scheduled date are required."}), 400

    equipment = tenant_query(Equipment).filter_by(id=equipment_id).first()
    if not equipment:
        return jsonify({"message": "Equipment not found for this tenant."}), 404
    if equipment.status == EquipmentStatus.SCRAPPED:
        return jsonify({"message": "Scrapped equipment cannot receive new preventive requests."}), 400

    scheduled_date = _parse_iso_date(scheduled_raw)
    if not scheduled_date:
        return jsonify({"message": "Invalid scheduled date."}), 400
    if scheduled_date < date.today():
        return jsonify({"message": "Scheduled date cannot be in the past."}), 400

    technician = None
    if technician_id:
        technician = tenant_query(User).filter_by(id=technician_id, active=True).first()
        if not technician:
            return jsonify({"message": "Technician not found in tenant."}), 404
        if equipment.maintenance_team_id:
            _ensure_team_membership(technician.id, equipment.maintenance_team_id)

    req = MaintenanceRequest(
        subject=subject,
        description=description,
        request_type=RequestType.PREVENTIVE,
        priority=body.get("priority") or "normal",
        equipment_id=equipment.id,
        scheduled_date=scheduled_date,
        organization_id=current_user.organization_id,
        requested_by_id=current_user.id,
        assigned_technician_id=technician.id if technician else None,
    )
    req.apply_auto_context()
    db.session.add(req)
    db.session.commit()
    try:
        _send_maintenance_notification(
            req,
            "Preventive maintenance scheduled",
            f"{current_user.name} scheduled preventive work for {req.scheduled_date.isoformat()}.",
        )
    except Exception:
        current_app.logger.exception("Failed to send preventive maintenance alert")
    return jsonify({"message": "Preventive maintenance scheduled.", "event": _serialize_request_for_calendar(req)}), 201


@admin_bp.route("/maintenance/calendar/<int:request_id>/reschedule", methods=["PATCH"])
@login_required
@tenant_required
def preventive_calendar_reschedule(request_id: int):
    req = _load_request_or_404(request_id)
    if req.request_type != RequestType.PREVENTIVE:
        abort(404)

    if current_user.role != UserRole.ADMIN and req.assigned_technician_id != current_user.id:
        return jsonify({"message": "You are not allowed to reschedule this request."}), 403

    body = request.get_json(silent=True) or {}
    scheduled_raw = (body.get("scheduled_date") or "").strip()
    technician_id = int(body.get("assigned_technician_id")) if body.get("assigned_technician_id") else None

    new_date = _parse_iso_date(scheduled_raw)
    if not new_date:
        return jsonify({"message": "Provide a valid scheduled date."}), 400
    if new_date < date.today():
        return jsonify({"message": "Scheduled date cannot be in the past."}), 400

    if technician_id:
        technician = tenant_query(User).filter_by(id=technician_id, active=True).first()
        if not technician:
            return jsonify({"message": "Technician not found in tenant."}), 404
        if req.team_id:
            _ensure_team_membership(technician.id, req.team_id)
        req.assigned_technician_id = technician.id

    req.scheduled_date = new_date
    db.session.commit()
    try:
        _send_maintenance_notification(
            req,
            "Maintenance schedule updated",
            f"{current_user.name} rescheduled work to {req.scheduled_date.isoformat()}.",
        )
    except Exception:
        current_app.logger.exception("Failed to send maintenance reschedule alert")
    return jsonify({"message": "Schedule updated.", "event": _serialize_request_for_calendar(req)})


def _subscription_context(org: Organization) -> dict[str, object]:
    sub = _ensure_subscription(org)
    pricing = _pricing_config()
    current_users = tenant_query(User).count()
    remaining = sub.capacity_remaining(current_users)
    payments = (
        PaymentHistory.query.filter_by(organization_id=org.id)
        .order_by(PaymentHistory.created_at.desc())
        .all()
    )
    return {
        "subscription": sub,
        "current_users": current_users,
        "remaining": remaining,
        "pricing": pricing,
        "payments": payments,
    }


def _subscription_recipients(org: Organization) -> set[str]:
    admins = (
        User.query.filter_by(organization_id=org.id, role=UserRole.ADMIN, active=True)
        .with_entities(User.email)
        .all()
    )
    return {email for email, in admins if email}


def _send_subscription_update(
    org: Organization,
    *,
    subject: str,
    heading: str,
    message: str,
    details: list[str] | None = None,
) -> None:
    recipients = _subscription_recipients(org)
    context = {
        "heading": heading,
        "message": message,
        "details": details or [],
    }
    for email in recipients:
        try:
            send_subscription_event(email, subject, context)
        except Exception:
            current_app.logger.exception("Failed to send subscription email to %s", email)


def _razorpay_client() -> razorpay.Client:
    key_id = current_app.config.get("RAZORPAY_KEY_ID")
    key_secret = current_app.config.get("RAZORPAY_KEY_SECRET")
    if not key_id or not key_secret:
        raise RuntimeError("Razorpay API keys are not configured.")
    client = razorpay.Client(auth=(key_id, key_secret))
    client.set_app_details({"title": "GearGuard", "version": current_app.config.get("ASSET_VERSION", "1")})
    return client


@admin_bp.route("/subscription", methods=["GET"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def subscription():
    org = current_user.organization
    sub = _ensure_subscription(org)
    ctx = _subscription_context(org)
    form = SubscriptionCheckoutForm()
    suggested = max(sub.max_users_allowed, ctx["current_users"]) + 5
    form.total_members.data = suggested
    return render_template(
        "admin/subscription.html",
        page_title="Subscription & Billing",
        form=form,
        config=current_app.config,
        **ctx,
    )


@admin_bp.route("/subscription/checkout", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def subscription_checkout():
    org = current_user.organization
    sub = _ensure_subscription(org)
    form = SubscriptionCheckoutForm()
    if not form.validate_on_submit():
        return jsonify({"message": "Invalid input", "errors": form.errors}), 400

    desired_total = int(form.total_members.data or 0)
    trial_floor = current_app.config.get("SUBSCRIPTION_TRIAL_SEATS", 5)
    if desired_total < max(sub.max_users_allowed, trial_floor):
        return jsonify({"message": "Requested capacity must exceed current allowance."}), 400

    pricing = _calculate_upgrade(org, desired_total)
    if not pricing.get("requires_payment") or int(pricing["amount_paise"]) <= 0:
        return jsonify({"message": "No upgrade payment required."}), 400

    try:
        client = _razorpay_client()
    except RuntimeError as exc:
        current_app.logger.exception("Razorpay not configured")
        return jsonify({"message": str(exc)}), 500

    receipt = f"sub-{org.id}-{int(datetime.utcnow().timestamp())}"
    order = client.order.create(
        {
            "amount": int(pricing["amount_paise"]),
            "currency": pricing.get("currency", "INR"),
            "payment_capture": 1,
            "notes": {
                "organization_id": org.id,
                "organization": org.name,
                "requested_capacity": desired_total,
            },
            "receipt": receipt,
        }
    )

    payment = PaymentHistory(
        organization_id=org.id,
        subscription_id=sub.id,
        razorpay_order_id=order["id"],
        amount=int(pricing["amount_paise"]),
        currency=pricing.get("currency", "INR"),
        status=PaymentStatus.CREATED,
        purchased_user_capacity=desired_total,
        base_fee_included=bool(pricing.get("base_fee_applied", False)),
    )
    db.session.add(payment)
    db.session.commit()

    return jsonify(
        {
            "order_id": order["id"],
            "amount": order["amount"],
            "currency": order["currency"],
            "key_id": current_app.config.get("RAZORPAY_KEY_ID"),
            "org_name": org.name,
            "org_email": current_user.email,
            "purchased_capacity": desired_total,
            "base_fee_applied": pricing.get("base_fee_applied", False),
        }
    )


@admin_bp.route("/subscription/verify", methods=["POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def subscription_verify():
    payload = request.get_json(silent=True) or request.form
    order_id = payload.get("razorpay_order_id")
    payment_id = payload.get("razorpay_payment_id")
    signature = payload.get("razorpay_signature")
    if not order_id or not payment_id or not signature:
        return jsonify({"message": "Missing payment parameters."}), 400

    payment = PaymentHistory.query.filter_by(
        razorpay_order_id=order_id,
        organization_id=current_user.organization_id,
    ).first()
    if not payment:
        return jsonify({"message": "Payment order not found for this tenant."}), 404

    org = current_user.organization

    try:
        client = _razorpay_client()
        client.utility.verify_payment_signature(
            {
                "razorpay_order_id": order_id,
                "razorpay_payment_id": payment_id,
                "razorpay_signature": signature,
            }
        )
    except razorpay.errors.SignatureVerificationError:
        payment.status = PaymentStatus.FAILED
        db.session.commit()
        try:
            _send_subscription_update(
                org,
                subject="Subscription payment failed",
                heading="Payment could not be verified",
                message="We could not verify the payment signature. No charges were applied.",
                details=[
                    f"Order: {order_id}",
                    f"Payment: {payment_id or 'N/A'}",
                ],
            )
        except Exception:
            current_app.logger.exception("Failed to send subscription failure email")
        return jsonify({"message": "Payment signature invalid."}), 400

    payment.mark_captured(payment_id, signature)
    sub = payment.subscription or _ensure_subscription(current_user.organization)
    sub.activate(purchased_capacity=payment.purchased_user_capacity, base_fee_paid=payment.base_fee_included)
    db.session.commit()

    amount_inr = round((payment.amount or 0) / 100, 2)
    try:
        _send_subscription_update(
            org,
            subject="Subscription activated",
            heading="GearGuard subscription updated",
            message=f"Payment {payment_id} captured. Member capacity now {sub.max_users_allowed}.",
            details=[
                f"Order: {order_id}",
                f"Seats purchased: {payment.purchased_user_capacity}",
                f"Max members allowed: {sub.max_users_allowed}",
                f"Amount paid: Rs. {amount_inr:.2f} {payment.currency}",
            ],
        )
    except Exception:
        current_app.logger.exception("Failed to send subscription activation email")

    return jsonify(
        {
            "message": "Subscription activated successfully.",
            "max_users_allowed": sub.max_users_allowed,
            "status": sub.subscription_status.value,
        }
    )


@admin_bp.route("/subscription/webhook", methods=["POST"])
@csrf.exempt
def subscription_webhook():
    raw_body = request.get_data(as_text=True)
    signature = request.headers.get("X-Razorpay-Signature", "")
    secret = current_app.config.get("RAZORPAY_WEBHOOK_SECRET")
    if not secret:
        return jsonify({"message": "Webhook secret not configured."}), 500

    try:
        client = _razorpay_client()
        client.utility.verify_webhook_signature(raw_body, signature, secret)
    except razorpay.errors.SignatureVerificationError:
        return jsonify({"message": "Invalid webhook signature."}), 400
    except RuntimeError as exc:
        return jsonify({"message": str(exc)}), 500

    try:
        payload = json.loads(raw_body)
    except json.JSONDecodeError:
        return jsonify({"message": "Invalid webhook payload."}), 400

    payment_entity = payload.get("payload", {}).get("payment", {}).get("entity", {})
    order_id = payment_entity.get("order_id")
    payment_id = payment_entity.get("id")
    status = payment_entity.get("status")

    if not order_id:
        return jsonify({"message": "Webhook missing order id."}), 400

    payment = PaymentHistory.query.filter_by(razorpay_order_id=order_id).first()
    if not payment:
        return jsonify({"message": "Order not tracked."}), 404

    previous_status = payment.status
    org = payment.organization

    if status == "captured" and previous_status != PaymentStatus.CAPTURED:
        payment.mark_captured(payment_id or "", signature)
        sub = payment.subscription or _ensure_subscription(org)
        sub.activate(purchased_capacity=payment.purchased_user_capacity, base_fee_paid=payment.base_fee_included)
        db.session.commit()
        amount_inr = round((payment.amount or 0) / 100, 2)
        try:
            _send_subscription_update(
                org,
                subject="Subscription activated",
                heading="GearGuard subscription updated",
                message=f"Webhook confirmation captured payment {payment_id or ''}.",
                details=[
                    f"Order: {order_id}",
                    f"Seats purchased: {payment.purchased_user_capacity}",
                    f"Max members allowed: {sub.max_users_allowed}",
                    f"Amount paid: Rs. {amount_inr:.2f} {payment.currency}",
                ],
            )
        except Exception:
            current_app.logger.exception("Failed to send webhook subscription activation email")
    elif status == "failed" and previous_status != PaymentStatus.FAILED:
        payment.status = PaymentStatus.FAILED
        db.session.commit()
        try:
            _send_subscription_update(
                org,
                subject="Subscription payment failed",
                heading="Payment failed",
                message="Razorpay reported a failed subscription payment.",
                details=[f"Order: {order_id}", f"Payment: {payment_id or 'N/A'}"],
            )
        except Exception:
            current_app.logger.exception("Failed to send webhook subscription failure email")
    else:
        db.session.commit()

    return jsonify({"message": "Webhook processed."})
