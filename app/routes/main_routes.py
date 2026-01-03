from __future__ import annotations

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, url_for, session
from flask_login import current_user, login_required, login_user, logout_user

from app.extensions import db
from app.forms import (
    ForgotPasswordForm,
    LoginForm,
    OrganizationSignupForm,
    OTPVerificationForm,
    RegisterUserForm,
    ResendOtpForm,
    ResetPasswordForm,
    SupportRequestForm,
)
from app.models import (
    EmailOtp,
    OTPPurpose,
    Organization,
    OrganizationStatus,
    OrganizationSubscription,
    SecurityEvent,
    SubscriptionStatus,
    SupportRequest,
    SupportCategory,
    User,
    UserRole,
    SuperAdminOtp,
)
from app.email_service import send_otp_email, send_password_reset_email, send_super_admin_otp, send_security_alert, send_support_request_notification
from app.tenant import role_required, set_tenant_session, tenant_required, clear_tenant_session, tenant_query, get_current_organization
from app.super_admin import super_admin_configured, super_admin_identity, super_admin_password_matches

main_bp = Blueprint("main", __name__)

OTP_SESSION_USER_KEY = "otp_user_id"
OTP_SESSION_CONTEXT_KEY = "otp_context"
OTP_SESSION_ORG_KEY = "otp_org_id"
OTP_SESSION_NEXT_KEY = "otp_next"
OTP_SESSION_MODE_KEY = "otp_mode"
OTP_SUPERADMIN_EMAIL_KEY = "otp_superadmin_email"
SUPERADMIN_SESSION_KEY = "superadmin_session_active"


def _ensure_org_subscription(org: Organization) -> OrganizationSubscription:
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
    db.session.flush()
    return sub


def _safe_next_url(next_url: Optional[str]) -> Optional[str]:
    if not next_url:
        return None
    if next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return None


def _mask_email(email: str) -> str:
    parts = email.split("@")
    if len(parts) != 2:
        return email
    name, domain = parts
    visible = name[:2]
    return f"{visible}***@{domain}"


def _active_otp(user_id: int, purpose: OTPPurpose) -> EmailOtp | None:
    return (
        EmailOtp.query.filter_by(user_id=user_id, purpose=purpose, is_used=False)
        .order_by(EmailOtp.created_at.desc())
        .first()
    )


def _otp_rate_limited(user_id: int, purpose: OTPPurpose) -> bool:
    window_start = datetime.utcnow() - timedelta(hours=1)
    recent = (
        EmailOtp.query.filter(
            EmailOtp.user_id == user_id,
            EmailOtp.purpose == purpose,
            EmailOtp.created_at >= window_start,
        ).count()
    )
    max_per_hour = current_app.config.get("OTP_MAX_PER_HOUR", 6)
    return recent >= max_per_hour


def _support_rate_limited(email: str | None, ip_address: str | None) -> bool:
    window = datetime.utcnow() - timedelta(minutes=int(current_app.config.get("SUPPORT_RATE_LIMIT_MINUTES", 3)))
    threshold = int(current_app.config.get("SUPPORT_RATE_LIMIT_COUNT", 3))
    query = SupportRequest.query.filter(SupportRequest.created_at >= window)
    if email:
        query = query.filter(SupportRequest.email == email)
    elif ip_address:
        query = query.filter(SupportRequest.ip_address == ip_address)
    return query.count() >= threshold


def _issue_otp(user: User, purpose: OTPPurpose, *, client_fingerprint: str | None = None) -> EmailOtp:
    if _otp_rate_limited(user.id, purpose):
        raise ValueError("Too many verification attempts. Please wait before retrying.")

    existing = _active_otp(user.id, purpose)
    if existing:
        existing.is_used = True

    config_expiry = int(current_app.config.get("OTP_EXPIRY_MINUTES", 10))
    otp_code = f"{secrets.randbelow(10**6):06d}"
    otp = EmailOtp(
        user_id=user.id,
        organization_id=user.organization_id,
        purpose=purpose,
        otp_hash=EmailOtp._hash(otp_code),
        expires_at=datetime.utcnow() + timedelta(minutes=config_expiry),
        max_attempts=int(current_app.config.get("OTP_MAX_ATTEMPTS", 5)),
        client_fingerprint=client_fingerprint,
        last_sent_at=datetime.utcnow(),
    )
    db.session.add(otp)
    db.session.flush()
    send_otp_email(user, otp_code, purpose=purpose, expires_in_minutes=config_expiry)
    return otp


def _is_super_admin_email(email: str) -> bool:
    configured = current_app.config.get("SUPERADMIN_EMAIL")
    return bool(configured and configured.strip().lower() == email.strip().lower())


def _super_admin_rate_limited(ip_address: str | None) -> bool:
    if not ip_address:
        return False
    window_minutes = int(current_app.config.get("SUPERADMIN_RATE_LIMIT_WINDOW_MINUTES", 30))
    limit = int(current_app.config.get("SUPERADMIN_RATE_LIMIT_PER_IP", 15))
    window_start = datetime.utcnow() - timedelta(minutes=window_minutes)
    recent = (
        SecurityEvent.query.filter(
            SecurityEvent.event_type.in_(["superadmin_login_failed", "superadmin_lockout"]),
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.created_at >= window_start,
        ).count()
    )
    return recent >= limit


def _active_super_admin_otp(purpose: OTPPurpose) -> SuperAdminOtp | None:
    return (
        SuperAdminOtp.query.filter_by(purpose=purpose, is_used=False)
        .order_by(SuperAdminOtp.created_at.desc())
        .first()
    )


def _issue_super_admin_otp(purpose: OTPPurpose, *, client_fingerprint: str | None = None) -> SuperAdminOtp:
    identity = super_admin_identity()
    if not identity:
        raise RuntimeError("Super admin is not configured")

    existing = _active_super_admin_otp(purpose)
    if existing:
        existing.is_used = True

    otp_code = f"{secrets.randbelow(10**6):06d}"
    expiry_minutes = int(current_app.config.get("SUPERADMIN_OTP_EXPIRY_MINUTES", 8))
    otp = SuperAdminOtp(
        email=identity.email,
        purpose=purpose,
        otp_hash=SuperAdminOtp._hash(otp_code),
        expires_at=datetime.utcnow() + timedelta(minutes=expiry_minutes),
        max_attempts=int(current_app.config.get("SUPERADMIN_OTP_MAX_ATTEMPTS", 5)),
        client_fingerprint=client_fingerprint,
        last_sent_at=datetime.utcnow(),
    )
    db.session.add(otp)
    db.session.flush()
    send_super_admin_otp(identity, otp_code, expires_in_minutes=expiry_minutes)
    return otp


def _notify_root_alert(subject: str, message: str, actions: list[str] | None = None) -> None:
    recipient = current_app.config.get("SUPERADMIN_ALERT_EMAIL") or current_app.config.get("SUPERADMIN_EMAIL")
    if not recipient:
        return
    try:
        send_security_alert(
            recipient,
            subject,
            {
                "title": subject,
                "message": message,
                "actions": actions or ["Review security logs", "Rotate credentials if unexpected"],
            },
        )
    except Exception:
        current_app.logger.exception("Failed to send root security alert")


def _can_resend_otp(otp: EmailOtp) -> bool:
    cooldown = int(current_app.config.get("OTP_RESEND_COOLDOWN_SECONDS", 90))
    if not otp.last_sent_at:
        return True
    return datetime.utcnow() - otp.last_sent_at >= timedelta(seconds=cooldown)


def _can_resend_super_admin_otp(otp: SuperAdminOtp) -> bool:
    cooldown = int(current_app.config.get("SUPERADMIN_OTP_RESEND_COOLDOWN_SECONDS", 60))
    if not otp.last_sent_at:
        return True
    return datetime.utcnow() - otp.last_sent_at >= timedelta(seconds=cooldown)


def _record_security_event(
    *,
    event_type: str,
    severity: str = "info",
    actor_type: str = "user",
    actor_id: int | None = None,
    actor_email: str | None = None,
    organization_id: int | None = None,
    meta: dict | None = None,
) -> None:
    try:
        SecurityEvent.record(
            event_type=event_type,
            severity=severity,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_email=actor_email,
            organization_id=organization_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            meta=meta,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception("Failed to record security event")


@main_bp.route("/")
def home():
    organization = None
    if current_user.is_authenticated:
        organization = get_current_organization()
    return render_template("home.html", current_organization=organization)


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    form = LoginForm()
    if request.method == "GET" and not form.organization_slug.data:
        form.organization_slug.data = current_app.config.get("SUPERADMIN_ORG_SLUG", "gearguard-india")

    if form.is_submitted():
        email_candidate = (form.email.data or "").strip().lower()
        if _is_super_admin_email(email_candidate) and not form.organization_slug.data:
            form.organization_slug.data = current_app.config.get("SUPERADMIN_ORG_SLUG", "gearguard-india")

    if form.validate_on_submit():
        session.clear()
        email_input = form.email.data.strip().lower()
        org_slug = (form.organization_slug.data or "").strip().lower()

        # Super admin path (root authority shares login surface)
        if _is_super_admin_email(email_input):
            if not super_admin_configured():
                flash("Root access is not configured. Contact platform security.", "danger")
                return render_template("auth/login.html", form=form, page_title="Sign In")
            if _super_admin_rate_limited(request.remote_addr):
                flash("Too many root attempts from this IP. Try again later.", "danger")
                _record_security_event(
                    event_type="superadmin_login_rate_limited",
                    severity="high",
                    actor_type="super_admin",
                    actor_email=email_input,
                )
                _notify_root_alert(
                    "Root login rate limited",
                    f"IP {request.remote_addr} hit the rate limit for super admin login attempts.",
                )
                return render_template("auth/login.html", form=form, page_title="Sign In")

            if not super_admin_password_matches(form.password.data):
                _record_security_event(
                    event_type="superadmin_login_failed",
                    severity="critical",
                    actor_type="super_admin",
                    actor_email=email_input,
                    meta={"slug": org_slug},
                )
                _notify_root_alert(
                    "Root credential failure",
                    f"A root login failed for {email_input}. If this was not you, rotate secrets immediately.",
                )
                flash("Invalid root credentials. All failures are logged.", "danger")
                return render_template("auth/login.html", form=form, page_title="Sign In")

            try:
                _issue_super_admin_otp(OTPPurpose.SUPERADMIN_LOGIN, client_fingerprint=request.remote_addr)
                db.session.commit()
                _record_security_event(
                    event_type="superadmin_login_challenge",
                    severity="medium",
                    actor_type="super_admin",
                    actor_email=email_input,
                )
            except Exception as exc:  # pragma: no cover - runtime safety
                db.session.rollback()
                current_app.logger.exception("Failed to issue super admin OTP")
                flash("Unable to send verification code. Root access paused.", "danger")
                return render_template("auth/login.html", form=form, page_title="Sign In")

            session[OTP_SESSION_MODE_KEY] = "superadmin"
            session[OTP_SUPERADMIN_EMAIL_KEY] = email_input
            session[OTP_SESSION_CONTEXT_KEY] = OTPPurpose.SUPERADMIN_LOGIN.value
            session["otp_remember"] = True
            session[OTP_SESSION_NEXT_KEY] = _safe_next_url(request.args.get("next"))
            flash("Enter the root verification code we sent to your secure inbox.", "info")
            return redirect(url_for("main.verify_otp"))

        org = Organization.query.filter_by(slug=org_slug).first()
        if not org:
            flash("Organization not found. Check the slug and try again.", "danger")
            return render_template("auth/login.html", form=form, page_title="Sign In")
        if org.status != OrganizationStatus.ACTIVE:
            flash("Organization is suspended. Contact your administrator.", "danger")
            return render_template("auth/login.html", form=form, page_title="Sign In")

        user = User.query.filter_by(email=email_input, organization_id=org.id).first()
        if not user:
            flash("Invalid credentials. Please try again.", "danger")
            return render_template("auth/login.html", form=form, page_title="Sign In")

        if user.login_locked_until and datetime.utcnow() < user.login_locked_until:
            flash("Account temporarily locked due to repeated failures. Try again later.", "danger")
            return render_template("auth/login.html", form=form, page_title="Sign In")

        if not user.check_password(form.password.data):
            user.record_failed_login(current_app.config.get("LOGIN_MAX_FAILURES", 10))
            db.session.commit()
            if user.failed_login_attempts >= current_app.config.get("LOGIN_MAX_FAILURES", 10):
                try:
                    from app.email_service import send_security_alert

                    send_security_alert(
                        user.email,
                        "GearGuard: account locked after failed attempts",
                        {
                            "title": "Account locked for your security",
                            "message": "We detected repeated failed sign-in attempts and temporarily locked access.",
                            "actions": [
                                "Wait a few minutes before trying again",
                                "Reset your password if this wasn't you",
                                "Notify your admin if attempts persist",
                            ],
                        },
                    )
                except Exception:
                    current_app.logger.exception("Failed to send security alert")
            _record_security_event(
                event_type="user_login_failed",
                severity="medium",
                actor_id=user.id,
                actor_email=user.email,
                organization_id=org.id,
            )
            flash("Invalid credentials. Please try again.", "danger")
            return render_template("auth/login.html", form=form, page_title="Sign In")

        if not user.email_verified:
            otp_purpose = OTPPurpose.REGISTRATION
        elif not user.active:
            flash("This account is inactive. Contact your administrator.", "danger")
            return render_template("auth/login.html", form=form, page_title="Sign In")
        else:
            otp_purpose = OTPPurpose.LOGIN

        try:
            _issue_otp(user, otp_purpose, client_fingerprint=request.remote_addr)
            db.session.commit()
        except Exception as exc:  # pragma: no cover - runtime safety
            db.session.rollback()
            current_app.logger.exception("Failed to issue login OTP")
            flash(str(exc), "danger")
            return render_template("auth/login.html", form=form, page_title="Sign In")

        session[OTP_SESSION_MODE_KEY] = "user"
        session[OTP_SESSION_USER_KEY] = user.id
        session[OTP_SESSION_CONTEXT_KEY] = otp_purpose.value
        session[OTP_SESSION_ORG_KEY] = org.id
        session["otp_remember"] = True
        session[OTP_SESSION_NEXT_KEY] = _safe_next_url(request.args.get("next"))
        flash("Enter the verification code we sent to your email to finish signing in.", "info")
        return redirect(url_for("main.verify_otp"))

    return render_template("auth/login.html", form=form, page_title="Sign In")


def _pending_otp_context():
    mode = session.get(OTP_SESSION_MODE_KEY, "user")
    if mode == "superadmin":
        identity = super_admin_identity()
        if not identity or not _is_super_admin_email(session.get(OTP_SUPERADMIN_EMAIL_KEY, "")):
            abort(400, description="Super admin session is invalid")
        return identity, OTPPurpose.SUPERADMIN_LOGIN, mode

    user_id = session.get(OTP_SESSION_USER_KEY)
    context_value = session.get(OTP_SESSION_CONTEXT_KEY)
    org_id = session.get(OTP_SESSION_ORG_KEY)
    if not user_id or not context_value:
        abort(400, description="No OTP session is active")
    user = User.query.get(user_id)
    if not user:
        abort(400, description="Account not found for OTP")
    try:
        purpose = OTPPurpose(context_value)
    except ValueError:
        abort(400, description="Invalid OTP context")
    if org_id and user.organization_id != org_id:
        abort(400, description="OTP session organization mismatch")
    return user, purpose, mode


@main_bp.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    try:
        subject, purpose, mode = _pending_otp_context()
    except Exception:
        clear_tenant_session()
        session.clear()
        return redirect(url_for("main.login"))

    is_super_admin = mode == "superadmin"
    otp = _active_super_admin_otp(purpose) if is_super_admin else _active_otp(subject.id, purpose)
    form = OTPVerificationForm()
    resend_form = ResendOtpForm()
    now = datetime.utcnow()
    expires_in_seconds = max(int((otp.expires_at - now).total_seconds()), 0) if otp else 0
    attempts_left = otp.remaining_attempts if otp else current_app.config.get("OTP_MAX_ATTEMPTS", 5)

    if form.validate_on_submit():
        if not otp:
            flash("Code expired. Please resend a new code.", "warning")
            return render_template(
                "auth/verify_otp.html",
                form=form,
                resend_form=resend_form,
                masked_email=_mask_email(subject.email),
                expires_in_seconds=expires_in_seconds,
                attempts_left=attempts_left,
                page_title="Verify Code",
            )
        if otp.expired:
            otp.is_used = True
            db.session.commit()
            flash("Code expired. Request a new one.", "warning")
            return redirect(url_for("main.verify_otp"))
        if otp.attempts >= otp.max_attempts:
            flash("Too many failed attempts. Request a new code.", "danger")
            return redirect(url_for("main.verify_otp"))

        if not otp.verify(form.otp_code.data.strip()):
            otp.bump_attempts()
            db.session.commit()
            if is_super_admin:
                _record_security_event(
                    event_type="superadmin_otp_failed",
                    severity="high",
                    actor_type="super_admin",
                    actor_email=getattr(subject, "email", None),
                )
            flash("Incorrect code. Please try again.", "danger")
            return redirect(url_for("main.verify_otp"))

        otp.mark_used()
        if not is_super_admin:
            subject.mark_email_verified()
            subject.reset_login_failures()
        db.session.commit()

        clear_tenant_session()
        remember = bool(session.pop("otp_remember", True))
        session.pop(OTP_SESSION_USER_KEY, None)
        session.pop(OTP_SESSION_CONTEXT_KEY, None)
        session.pop(OTP_SESSION_ORG_KEY, None)
        session.pop(OTP_SESSION_MODE_KEY, None)
        session.pop(OTP_SUPERADMIN_EMAIL_KEY, None)
        next_url = _safe_next_url(session.pop(OTP_SESSION_NEXT_KEY, None))

        if is_super_admin:
            session[SUPERADMIN_SESSION_KEY] = True
            session.permanent = True
            login_user(subject, remember=remember, duration=timedelta(hours=current_app.config.get("SUPERADMIN_SESSION_LIFETIME_HOURS", 6)))
            _record_security_event(
                event_type="superadmin_login_success",
                severity="critical",
                actor_type="super_admin",
                actor_email=getattr(subject, "email", None),
            )
            flash("Root verification successful. Platform governance console unlocked.", "success")
            return redirect(next_url or url_for("super_admin.dashboard"))

        session.permanent = True
        login_user(subject, remember=remember)
        set_tenant_session(subject)
        _record_security_event(
            event_type="user_login_success",
            severity="info",
            actor_id=subject.id,
            actor_email=subject.email,
            organization_id=subject.organization_id,
        )

        flash("Verification successful. Welcome back!", "success")
        return redirect(next_url or url_for("main.home"))

    return render_template(
        "auth/verify_otp.html",
        form=form,
        resend_form=resend_form,
        masked_email=_mask_email(subject.email),
        expires_in_seconds=expires_in_seconds,
        attempts_left=attempts_left,
        page_title="Verify Code",
    )


@main_bp.route("/resend-otp", methods=["POST"])
def resend_otp():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    try:
        subject, purpose, mode = _pending_otp_context()
    except Exception:
        clear_tenant_session()
        session.clear()
        return redirect(url_for("main.login"))

    is_super_admin = mode == "superadmin"
    otp = _active_super_admin_otp(purpose) if is_super_admin else _active_otp(subject.id, purpose)
    if otp:
        if is_super_admin and not _can_resend_super_admin_otp(otp):
            flash("Please wait before requesting another code.", "warning")
            return redirect(url_for("main.verify_otp"))
        if not is_super_admin and not _can_resend_otp(otp):
            flash("Please wait before requesting another code.", "warning")
            return redirect(url_for("main.verify_otp"))

    # Invalidate old OTPs for clarity
    if otp:
        otp.is_used = True

    try:
        if is_super_admin:
            _issue_super_admin_otp(purpose, client_fingerprint=request.remote_addr)
        else:
            _issue_otp(subject, purpose, client_fingerprint=request.remote_addr)
        db.session.commit()
        flash("We sent a fresh code to your email.", "info")
    except Exception as exc:  # pragma: no cover - runtime safety
        db.session.rollback()
        flash(str(exc), "danger")

    return redirect(url_for("main.verify_otp"))


@main_bp.route("/logout")
@login_required
def logout():
    actor_email = getattr(current_user, "email", None)
    actor_id = getattr(current_user, "id", None) if not getattr(current_user, "is_super_admin", False) else None
    actor_type = "super_admin" if getattr(current_user, "is_super_admin", False) else "user"
    clear_tenant_session()
    logout_user()
    session.clear()
    _record_security_event(
        event_type="logout",
        severity="info",
        actor_type=actor_type,
        actor_id=actor_id,
        actor_email=actor_email,
    )
    flash("You have been signed out.", "info")
    return redirect(url_for("main.login"))


@main_bp.route("/register-organization", methods=["GET", "POST"])
def register_organization():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))

    form = OrganizationSignupForm()
    if form.validate_on_submit():
        org_name = form.organization_name.data.strip()
        existing_name = Organization.query.filter_by(name=org_name).first()
        if existing_name:
            flash("An organization with this name already exists.", "danger")
            return render_template("auth/register_org.html", form=form, page_title="Register Organization")

        admin_email = form.admin_email.data.strip().lower()
        if User.query.filter_by(email=admin_email).first():
            flash("That email is already registered.", "danger")
            return render_template("auth/register_org.html", form=form, page_title="Register Organization")

        slug = Organization.generate_unique_slug(org_name)
        org = Organization(name=org_name, slug=slug)
        db.session.add(org)
        db.session.flush()

        _ensure_org_subscription(org)

        admin_user = User(
            name=form.admin_name.data.strip(),
            email=admin_email,
            organization_id=org.id,
            role=UserRole.ADMIN,
            active=False,
            email_verified=False,
        )
        admin_user.set_password(form.admin_password.data)
        db.session.add(admin_user)
        db.session.flush()

        try:
            _issue_otp(admin_user, OTPPurpose.REGISTRATION, client_fingerprint=request.remote_addr)
            db.session.commit()
        except Exception as exc:  # pragma: no cover - runtime safety
            db.session.rollback()
            current_app.logger.exception("Failed to send registration OTP")
            flash("Could not send verification code. Please try again.", "danger")
            return render_template("auth/register_org.html", form=form, page_title="Register Organization")

        session[OTP_SESSION_USER_KEY] = admin_user.id
        session[OTP_SESSION_CONTEXT_KEY] = OTPPurpose.REGISTRATION.value
        session[OTP_SESSION_ORG_KEY] = org.id
        flash("We sent a verification code to your email. Verify to activate your account.", "info")
        return redirect(url_for("main.verify_otp"))

    return render_template("auth/register_org.html", form=form, page_title="Register Organization")


@main_bp.route("/users/new", methods=["GET", "POST"])
@login_required
@tenant_required
@role_required(UserRole.ADMIN)
def register_user():
    form = RegisterUserForm()
    if not form.is_submitted():
        form.role.data = UserRole.USER.value
    if form.validate_on_submit():
        org = current_user.organization
        sub = _ensure_org_subscription(org)
        current_count = tenant_query(User).count()
        if current_count >= sub.max_users_allowed:
            flash(
                "You have reached your member limit. Upgrade your subscription to add more users.",
                "danger",
            )
            return redirect(url_for("admin.subscription"))
        email = form.email.data.strip().lower()
        existing = tenant_query(User).filter(User.email == email, User.id != current_user.id).first()
        if existing:
            flash("A user with this email already exists in the platform.", "warning")
            return render_template("auth/register_user.html", form=form, page_title="Add User")

        user = User(
            name=form.name.data.strip(),
            email=email,
            organization_id=org.id,
            role=UserRole(form.role.data),
            active=False,
            email_verified=False,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.flush()

        try:
            _issue_otp(user, OTPPurpose.REGISTRATION, client_fingerprint=request.remote_addr)
            db.session.commit()
            flash(
                "User created. A verification code was emailed for activation.",
                "success",
            )
        except Exception as exc:  # pragma: no cover - runtime safety
            db.session.rollback()
            current_app.logger.exception("Failed to send user onboarding OTP")
            flash("User saved but verification email could not be sent. Retry from user profile.", "warning")

        return redirect(url_for("admin.dashboard"))

    return render_template("auth/register_user.html", form=form, page_title="Add User")


@main_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        org = Organization.query.filter_by(slug=form.organization_slug.data.strip().lower()).first()
        if org and org.status == OrganizationStatus.ACTIVE:
            user = User.query.filter_by(
                email=form.email.data.strip().lower(), organization_id=org.id
            ).first()
            if user:
                raw_token = secrets.token_urlsafe(32)
                expires = int(current_app.config.get("OTP_EXPIRY_MINUTES", 10))
                user.issue_reset_token(raw_token, expires_in_minutes=expires)
                db.session.commit()
                reset_link = url_for("main.reset_password", token=raw_token, _external=True)
                try:
                    send_password_reset_email(
                        user,
                        reset_link,
                        expires_in_minutes=expires,
                    )
                except Exception:
                    current_app.logger.exception("Failed to send password reset email")
                if current_app.config.get("ENV") == "development":
                    flash(f"Development reset link: {reset_link}", "secondary")

        flash("If the account exists, a password reset link has been sent.", "info")
        return redirect(url_for("main.login"))

    return render_template("auth/forgot_password.html", form=form, page_title="Forgot Password")


@main_bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token: str):
    if current_user.is_authenticated:
        return redirect(url_for("main.home"))

    form = ResetPasswordForm()
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    user: Optional[User] = User.query.filter_by(reset_token_hash=token_hash).first()

    if not user or not user.reset_token_is_valid(token):
        flash("Reset link is invalid or has expired.", "danger")
        return redirect(url_for("main.login"))
    if not user.active or user.organization.status != OrganizationStatus.ACTIVE:
        flash("Account is inactive or organization suspended.", "danger")
        return redirect(url_for("main.login"))

    if form.validate_on_submit():
        user.set_password(form.password.data)
        user.clear_reset_token()
        db.session.commit()
        flash("Password reset successful. Please sign in.", "success")
        return redirect(url_for("main.login"))

    return render_template("auth/reset_password.html", form=form, page_title="Reset Password")


@main_bp.route("/about")
def about_page():
    return render_template("about.html", page_title="About GearGuard India")


@main_bp.route("/terms")
def terms_page():
    return render_template("terms.html", page_title="Terms & Conditions")


@main_bp.route("/privacy")
def privacy_page():
    return render_template("privacy.html", page_title="Privacy Policy")


@main_bp.route("/support", methods=["GET", "POST"])
def support_page():
    form = SupportRequestForm()

    if current_user.is_authenticated and not form.is_submitted():
        form.full_name.data = getattr(current_user, "name", "")
        form.email.data = getattr(current_user, "email", "")
        org = get_current_organization()
        if org:
            form.organization.data = org.name

    if form.validate_on_submit():
        email = form.email.data.strip().lower()
        if _support_rate_limited(email, request.remote_addr):
            flash("We received a recent request. Please wait a few minutes before submitting again.", "warning")
            return render_template("support.html", form=form, page_title="Contact & Support")

        org = get_current_organization() if current_user.is_authenticated else None
        support = SupportRequest(
            full_name=form.full_name.data.strip(),
            email=email,
            subject=form.subject.data.strip(),
            message=form.message.data.strip(),
            category=SupportCategory(form.category.data),
            organization_name=form.organization.data.strip() if form.organization.data else (org.name if org else None),
            organization_id=org.id if org else None,
            user_id=current_user.id if current_user.is_authenticated else None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
        )

        db.session.add(support)
        db.session.commit()

        admin_recipient = (
            current_app.config.get("SUPPORT_INBOX")
            or current_app.config.get("SUPERADMIN_EMAIL")
            or current_app.config.get("MAIL_SENDER")
            or "support@gearguard.in"
        )
        try:
            send_support_request_notification(support, admin_recipient)
            flash("Request received. Our support desk has been notified.", "success")
        except Exception:
            current_app.logger.exception("Failed to dispatch support notification")
            flash("We saved your request. If email delivery fails, our team will review it directly.", "warning")

        return redirect(url_for("main.support_page"))

    return render_template("support.html", form=form, page_title="Contact & Support")
