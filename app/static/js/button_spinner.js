document.addEventListener('DOMContentLoaded', () => {
    // Decorate submit buttons with label + spinner so we can animate cleanly
    document.querySelectorAll('button[type="submit"]:not([data-spinner-prepared])').forEach((btn) => {
        btn.dataset.spinnerPrepared = 'true';
        const currentHtml = btn.innerHTML;
        const label = document.createElement('span');
        label.className = 'btn-label';
        label.innerHTML = currentHtml;
        const spinner = document.createElement('span');
        spinner.className = 'spinner-border spinner-border-sm submit-spinner';
        spinner.setAttribute('role', 'status');
        spinner.setAttribute('aria-hidden', 'true');
        spinner.hidden = true;
        btn.innerHTML = '';
        btn.append(label, spinner);
    });

    // Bind once per form to avoid double-disabling
    document.querySelectorAll('form').forEach((form) => {
        if (form.dataset.spinnerBound) return;
        form.dataset.spinnerBound = 'true';

        form.addEventListener('submit', (event) => {
            const submitter = event.submitter || form.querySelector('button[type="submit"], input[type="submit"]');
            if (!submitter || submitter.dataset.submitting === 'true') return;
            if (form.checkValidity && !form.checkValidity()) return; // Let native validation surface

            submitter.dataset.submitting = 'true';
            const spinner = submitter.querySelector('.spinner-border');
            const label = submitter.querySelector('.btn-label');

            if (spinner) spinner.hidden = false;
            if (label) label.classList.add('visually-hidden');

            // Defer disabling until after the native submit fires to avoid blocking it
            requestAnimationFrame(() => {
                submitter.classList.add('is-loading');
                submitter.disabled = true;
            });
        });
    });
});
