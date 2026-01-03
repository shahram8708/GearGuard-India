from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for, current_app
from flask_login import current_user, login_required
from sqlalchemy import func

from app.extensions import db
from app.forms import SuperAdminOrgActionForm, SuperAdminUserActionForm, SuperAdminSecurityActionForm
from app.models import (
    Equipment,
    MaintenanceRequest,
    MaintenanceStatus,
    Organization,
    OrganizationStatus,
    OrganizationSubscription,
    PaymentHistory,
    PaymentStatus,
    SecurityEvent,
    SubscriptionStatus,
    SupportRequest,
    User,
    UserRole,
)
from app.email_service import send_password_reset_email, send_security_alert

super_admin_bp = Blueprint("super_admin", __name__, url_prefix="/root")


def superadmin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, "is_super_admin", False):
            abort(403, description="Root authority required")
        return func(*args, **kwargs)

    return wrapper


def _audit(event_type: str, *, severity: str = "info", meta: dict | None = None, organization_id: int | None = None):
    try:
        SecurityEvent.record(
            event_type=event_type,
            severity=severity,
            actor_type="super_admin",
            actor_email=getattr(current_user, "email", None),
            organization_id=organization_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            meta=meta,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()


def _month_bucket(column):
    dialect = db.session.bind.dialect.name if db.session.bind else "sqlite"
    if dialect == "postgresql":
        return func.to_char(func.date_trunc("month", column), "YYYY-MM")
    if dialect in {"mysql", "mariadb"}:
        return func.date_format(column, "%Y-%m")
    return func.strftime("%Y-%m", column)


@super_admin_bp.route("/", methods=["GET"])
@login_required
@superadmin_required
def dashboard():
    org_count = Organization.query.count()
    active_orgs = Organization.query.filter_by(status=OrganizationStatus.ACTIVE).count()
    suspended_orgs = Organization.query.filter_by(status=OrganizationStatus.SUSPENDED).count()
    total_users = User.query.count()
    inactive_users = User.query.filter_by(active=False).count()

    sub_rows = (
        db.session.query(
            OrganizationSubscription.subscription_status,
            func.count(OrganizationSubscription.id)
        )
        .group_by(OrganizationSubscription.subscription_status)
        .all()
    )
    subscription_overview = {row.subscription_status.value: row[1] for row in sub_rows}

    payment_rows = (
        db.session.query(PaymentHistory.status, func.count(PaymentHistory.id), func.coalesce(func.sum(PaymentHistory.amount), 0))
        .group_by(PaymentHistory.status)
        .all()
    )
    payment_status_mix = {row.status.value: {"count": row[1], "amount": int(row[2] or 0)} for row in payment_rows}
    captured_revenue = payment_status_mix.get(PaymentStatus.CAPTURED.value, {}).get("amount", 0)

    maintenance_rows = (
        db.session.query(MaintenanceRequest.status, func.count(MaintenanceRequest.id))
        .group_by(MaintenanceRequest.status)
        .all()
    )
    maintenance_overview = {row.status.value: row[1] for row in maintenance_rows}

    overdue_requests = (
        db.session.query(func.count(MaintenanceRequest.id))
        .filter(
            MaintenanceRequest.scheduled_date.isnot(None),
            MaintenanceRequest.scheduled_date < func.current_date(),
            MaintenanceRequest.status.notin_([MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP]),
        )
        .scalar()
    )

    failed_payments = (
        PaymentHistory.query.filter(PaymentHistory.status == PaymentStatus.FAILED)
        .order_by(PaymentHistory.created_at.desc())
        .limit(8)
        .all()
    )

    security_events = (
        SecurityEvent.query.order_by(SecurityEvent.created_at.desc())
        .limit(12)
        .all()
    )

    top_orgs = (
        db.session.query(Organization, func.count(User.id).label("user_count"))
        .outerjoin(User, User.organization_id == Organization.id)
        .group_by(Organization.id)
        .order_by(func.count(User.id).desc())
        .limit(6)
        .all()
    )

    # Growth analytics
    period_org = _month_bucket(Organization.created_at)
    org_growth_rows = (
        db.session.query(period_org.label("period"), func.count(Organization.id))
        .group_by("period")
        .order_by("period")
        .all()
    )
    org_growth = {
        "labels": [row.period for row in org_growth_rows],
        "values": [row[1] for row in org_growth_rows],
    }

    period_user = _month_bucket(User.created_at)
    user_growth_rows = (
        db.session.query(period_user.label("period"), func.count(User.id))
        .group_by("period")
        .order_by("period")
        .all()
    )
    user_growth = {
        "labels": [row.period for row in user_growth_rows],
        "values": [row[1] for row in user_growth_rows],
    }

    role_rows = (
        db.session.query(User.role, func.count(User.id))
        .group_by(User.role)
        .order_by(func.count(User.id).desc())
        .all()
    )
    role_mix = {
        "labels": [row.role.value for row in role_rows],
        "values": [row[1] for row in role_rows],
    }

    request_type_rows = (
        db.session.query(MaintenanceRequest.request_type, func.count(MaintenanceRequest.id))
        .group_by(MaintenanceRequest.request_type)
        .all()
    )
    request_type_mix = {
        "labels": [row.request_type.value for row in request_type_rows],
        "values": [row[1] for row in request_type_rows],
    }

    period_request = _month_bucket(MaintenanceRequest.created_at)
    maintenance_trend_rows = (
        db.session.query(period_request.label("period"), MaintenanceRequest.status, func.count(MaintenanceRequest.id))
        .group_by("period", MaintenanceRequest.status)
        .order_by("period")
        .all()
    )
    periods = sorted({row.period for row in maintenance_trend_rows})
    status_map = {status: [0 for _ in periods] for status in MaintenanceStatus}
    period_index = {p: i for i, p in enumerate(periods)}
    for row in maintenance_trend_rows:
        status_map[row.status][period_index[row.period]] = row[2]
    maintenance_trend = {
        "labels": periods,
        "datasets": {status.value: status_map[status] for status in MaintenanceStatus},
    }

    # Seat saturation and org adoption
    seat_rows = (
        db.session.query(
            Organization.id,
            Organization.name,
            Organization.status,
            func.count(User.id).label("user_count"),
            func.coalesce(OrganizationSubscription.max_users_allowed, 5).label("capacity"),
        )
        .outerjoin(User, User.organization_id == Organization.id)
        .outerjoin(OrganizationSubscription, OrganizationSubscription.organization_id == Organization.id)
        .group_by(Organization.id, Organization.name, Organization.status, OrganizationSubscription.max_users_allowed)
        .all()
    )
    seat_utilization = []
    for row in seat_rows:
        capacity = row.capacity or 0
        utilization = (row.user_count / capacity) if capacity else 0
        seat_utilization.append(
            {
                "organization": row.name,
                "users": row.user_count,
                "capacity": capacity,
                "utilization": round(utilization, 2),
                "status": row.status.value,
            }
        )
    seat_utilization = sorted(seat_utilization, key=lambda r: r["utilization"], reverse=True)[:6]
    avg_saturation = round(sum(item["utilization"] for item in seat_utilization) / len(seat_utilization), 2) if seat_utilization else 0

    equipment_rows = (
        db.session.query(Organization.name, func.count(Equipment.id))
        .outerjoin(Equipment, Equipment.organization_id == Organization.id)
        .group_by(Organization.name)
        .order_by(func.count(Equipment.id).desc())
        .all()
    )
    equipment_mix = {
        "labels": [row[0] for row in equipment_rows],
        "values": [row[1] for row in equipment_rows],
    }

    security_window = datetime.utcnow() - timedelta(days=30)
    severity_rows = (
        db.session.query(SecurityEvent.severity, func.count(SecurityEvent.id))
        .filter(SecurityEvent.created_at >= security_window)
        .group_by(SecurityEvent.severity)
        .all()
    )
    security_severity_mix = {
        "labels": [row.severity for row in severity_rows],
        "values": [row[1] for row in severity_rows],
    }

    top_security_events = (
        db.session.query(SecurityEvent.event_type, func.count(SecurityEvent.id).label("count"))
        .filter(SecurityEvent.created_at >= security_window)
        .group_by(SecurityEvent.event_type)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(6)
        .all()
    )

    period_payment = _month_bucket(PaymentHistory.created_at)
    revenue_trend_rows = (
        db.session.query(period_payment.label("period"), func.coalesce(func.sum(PaymentHistory.amount), 0))
        .filter(PaymentHistory.status == PaymentStatus.CAPTURED)
        .group_by("period")
        .order_by("period")
        .all()
    )
    revenue_trend = {
        "labels": [row.period for row in revenue_trend_rows],
        "values": [int(row[1] or 0) for row in revenue_trend_rows],
    }

    support_rows = (
        db.session.query(SupportRequest.category, func.count(SupportRequest.id))
        .group_by(SupportRequest.category)
        .all()
    )
    support_mix = {
        "labels": [row.category.value for row in support_rows],
        "values": [row[1] for row in support_rows],
    }

    return render_template(
        "super_admin/dashboard.html",
        page_title="Root Governance",
        org_count=org_count,
        active_orgs=active_orgs,
        suspended_orgs=suspended_orgs,
        total_users=total_users,
        inactive_users=inactive_users,
        subscription_overview=subscription_overview,
        payment_status_mix=payment_status_mix,
        captured_revenue=captured_revenue,
        maintenance_overview=maintenance_overview,
        overdue_requests=overdue_requests,
        failed_payments=failed_payments,
        security_events=security_events,
        top_orgs=top_orgs,
        org_growth=org_growth,
        user_growth=user_growth,
        role_mix=role_mix,
        request_type_mix=request_type_mix,
        maintenance_trend=maintenance_trend,
        seat_utilization=seat_utilization,
        avg_saturation=avg_saturation,
        equipment_mix=equipment_mix,
        security_severity_mix=security_severity_mix,
        top_security_events=top_security_events,
        revenue_trend=revenue_trend,
        support_mix=support_mix,
    )


@super_admin_bp.route("/organizations", methods=["GET"])
@login_required
@superadmin_required
def organizations():
    orgs = (
        Organization.query
        .order_by(Organization.created_at.desc())
        .all()
    )
    form = SuperAdminOrgActionForm()
    return render_template(
        "super_admin/organizations.html",
        organizations=orgs,
        action_form=form,
        page_title="Organizations",
    )


@super_admin_bp.route("/organizations/<int:org_id>/action", methods=["POST"])
@login_required
@superadmin_required
def organization_action(org_id: int):
    form = SuperAdminOrgActionForm()
    if not form.validate_on_submit():
        flash("Invalid request. Refresh and retry.", "danger")
        return redirect(url_for("super_admin.organizations"))

    org = Organization.query.get_or_404(org_id)
    action = form.action.data
    sub = org.subscription
    if not sub:
        sub = OrganizationSubscription(
            organization_id=org.id,
            is_trial=True,
            subscription_status=SubscriptionStatus.TRIAL,
            max_users_allowed=current_app.config.get("SUBSCRIPTION_TRIAL_SEATS", 5),
        )
        db.session.add(sub)

    if action == "activate":
        org.status = OrganizationStatus.ACTIVE
        _audit("org_activated", severity="high", organization_id=org.id)
        flash("Organization reactivated.", "success")
    elif action == "suspend":
        org.status = OrganizationStatus.SUSPENDED
        _audit("org_suspended", severity="critical", organization_id=org.id)
        flash("Organization suspended.", "warning")
    elif action == "delete":
        db.session.delete(org)
        _audit("org_deleted", severity="critical", organization_id=org.id)
        flash("Organization deleted with cascade.", "warning")
    elif action == "extend_trial":
        seats = form.seats.data or sub.max_users_allowed
        sub.move_to_trial(seats)
        _audit("org_trial_extended", severity="medium", organization_id=org.id, meta={"seats": seats})
        flash("Trial extended and capacity refreshed.", "success")
    elif action == "increase_capacity":
        seats = form.seats.data or sub.max_users_allowed
        sub.max_users_allowed = max(sub.max_users_allowed, seats)
        _audit("org_capacity_increased", severity="medium", organization_id=org.id, meta={"seats": seats})
        flash("Member capacity updated.", "success")
    elif action == "activate_subscription":
        sub.activate(purchased_capacity=form.seats.data or sub.max_users_allowed, base_fee_paid=True)
        _audit("org_subscription_forced_active", severity="high", organization_id=org.id)
        flash("Subscription forced to active.", "success")
    else:
        flash("Unknown action.", "danger")
        return redirect(url_for("super_admin.organizations"))

    db.session.commit()
    return redirect(url_for("super_admin.organizations"))


@super_admin_bp.route("/users", methods=["GET"])
@login_required
@superadmin_required
def users():
    users = (
        User.query
        .order_by(User.created_at.desc())
        .all()
    )
    form = SuperAdminUserActionForm()
    return render_template(
        "super_admin/users.html",
        users=users,
        action_form=form,
        page_title="Users",
    )


@super_admin_bp.route("/users/<int:user_id>/action", methods=["POST"])
@login_required
@superadmin_required
def user_action(user_id: int):
    form = SuperAdminUserActionForm()
    if not form.validate_on_submit():
        flash("Invalid request.", "danger")
        return redirect(url_for("super_admin.users"))

    user = User.query.get_or_404(user_id)
    action = form.action.data

    if action == "deactivate":
        user.active = False
        _audit("user_deactivated", severity="high", organization_id=user.organization_id, meta={"user": user.email})
        flash("User deactivated.", "success")
    elif action == "activate":
        user.active = True
        user.failed_login_attempts = 0
        user.login_locked_until = None
        _audit("user_activated", severity="medium", organization_id=user.organization_id, meta={"user": user.email})
        flash("User reactivated.", "success")
    elif action == "make_admin":
        user.role = UserRole.ADMIN
        _audit("user_promoted_admin", severity="high", organization_id=user.organization_id, meta={"user": user.email})
        flash("User promoted to organization admin.", "success")
    elif action == "make_user":
        user.role = UserRole.USER
        _audit("user_demoted", severity="medium", organization_id=user.organization_id, meta={"user": user.email})
        flash("User role set to member.", "success")
    elif action == "force_reset":
        raw_token = secrets.token_urlsafe(32)
        user.issue_reset_token(raw_token, expires_in_minutes=60)
        reset_link = url_for("main.reset_password", token=raw_token, _external=True)
        send_password_reset_email(user, reset_link, expires_in_minutes=60)
        _audit("user_password_reset_forced", severity="critical", organization_id=user.organization_id, meta={"user": user.email})
        flash("Reset link sent to the user.", "info")
    else:
        flash("Unknown action.", "danger")
        return redirect(url_for("super_admin.users"))

    db.session.commit()
    return redirect(url_for("super_admin.users"))


@super_admin_bp.route("/security", methods=["GET", "POST"])
@login_required
@superadmin_required
def security_center():
    form = SuperAdminSecurityActionForm()
    if form.validate_on_submit():
        action = form.action.data
        target = form.target.data
        _audit("superadmin_security_action", severity="high", meta={"action": action, "target": target})
        flash("Security directive logged and queued.", "info")
        return redirect(url_for("super_admin.security_center"))

    recent_events = SecurityEvent.query.order_by(SecurityEvent.created_at.desc()).limit(50).all()
    return render_template(
        "super_admin/security.html",
        page_title="Security Center",
        recent_events=recent_events,
        form=form,
    )
