from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
from typing import Callable, Type, TypeVar

from flask import abort, g, session
from flask_login import current_user

from .extensions import db
from .models import (
    Equipment,
    EquipmentStatus,
    MaintenanceRequest,
    MaintenanceStatus,
    MaintenanceTeam,
    Organization,
    OrganizationSubscription,
    OrganizationStatus,
    RequestType,
    SubscriptionStatus,
    TechnicianMembership,
    User,
    UserRole,
)

T = TypeVar("T")

ORG_SESSION_KEY = "org_id"


def get_current_user() -> User | None:
    if current_user and current_user.is_authenticated:
        g.current_user = current_user
        return current_user
    return None


def get_current_organization() -> Organization | None:
    user = get_current_user()
    if not user:
        return None
    org_id = session.get(ORG_SESSION_KEY)
    if org_id and org_id != user.organization_id:
        clear_tenant_session()
        abort(403, description="Organization context mismatch")

    org = user.organization
    if not org:
        abort(403, description="Organization missing for user")
    if org.status != OrganizationStatus.ACTIVE:
        clear_tenant_session()
        abort(403, description="Organization is suspended")

    g.current_organization = org
    return org


def set_tenant_session(user: User) -> None:
    session.permanent = True
    session[ORG_SESSION_KEY] = user.organization_id
    g.current_user = user
    g.current_organization = user.organization


def clear_tenant_session() -> None:
    session.pop(ORG_SESSION_KEY, None)
    g.pop("current_user", None)
    g.pop("current_organization", None)


def tenant_query(model: Type[db.Model]):
    organization = get_current_organization()
    if not organization:
        abort(403, description="Tenant context missing")
    if not hasattr(model, "organization_id"):
        raise ValueError("Model is not tenant-scoped: organization_id missing")
    return model.query.filter_by(organization_id=organization.id)


def enforce_same_tenant(record: db.Model) -> None:
    if record is None:
        abort(404, description="Resource not found")
    organization = get_current_organization()
    if not organization:
        abort(403, description="Tenant context missing")
    record_org = getattr(record, "organization_id", None)
    if record_org != organization.id:
        abort(403, description="Cross-tenant access is not allowed")


def validate_same_org(org_id: int, *records: db.Model) -> None:
    for record in records:
        if record is None:
            continue
        record_org = getattr(record, "organization_id", None)
        if record_org != org_id:
            abort(403, description="Cross-tenant relation is not allowed")


def tenant_required(func: Callable[..., T]) -> Callable[..., T]:
    @wraps(func)
    def wrapper(*args, **kwargs):
        user = get_current_user()
        org = get_current_organization()
        if not user:
            abort(401, description="Authentication required")
        if not org:
            abort(403, description="Organization context required")
        if not user.is_active:
            clear_tenant_session()
            abort(403, description="Account inactive or organization suspended")
        if session.get(ORG_SESSION_KEY) != user.organization_id:
            clear_tenant_session()
            abort(403, description="Tenant session mismatch")
        return func(*args, **kwargs)

    return wrapper


def role_required(role: UserRole) -> Callable[[Callable[..., T]], Callable[..., T]]:
    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                abort(401, description="Authentication required")
            if not user.has_role(role):
                abort(403, description="Insufficient permissions")
            enforce_same_tenant(user)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def roles_required(*roles: UserRole) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Allow multiple roles for a route while enforcing tenant scope."""

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not user:
                abort(401, description="Authentication required")
            if roles and user.role not in roles:
                abort(403, description="Insufficient permissions")
            enforce_same_tenant(user)
            return func(*args, **kwargs)

        return wrapper

    return decorator


def bootstrap_demo_tenant() -> tuple[Organization, User]:
    organization = Organization.query.filter_by(slug="acme").first()
    if not organization:
        organization = Organization(name="Acme Corp", slug="acme")
        db.session.add(organization)
        db.session.flush()

    user = User.query.filter_by(email="founder@acme.test").first()
    if not user:
        user = User(
            email="founder@acme.test",
            name="Founding Admin",
            organization_id=organization.id,
            role=UserRole.ADMIN,
        )
        user.set_password("ChangeMeNow!123")
        db.session.add(user)

    db.session.commit()

    has_team = MaintenanceTeam.query.filter_by(organization_id=organization.id).first()
    if not has_team:
        core_team = MaintenanceTeam(
            team_name="Plant Ops",
            description="Primary maintenance team for production assets",
            organization_id=organization.id,
        )
        db.session.add(core_team)
        db.session.flush()
    else:
        core_team = has_team

    has_equipment = Equipment.query.filter_by(organization_id=organization.id).first()
    if not has_equipment:
        demo_equipment = [
            Equipment(
                name="Hydraulic Press",
                category="machine",
                serial_number="HP-1000-ACME",
                department="Manufacturing",
                status=EquipmentStatus.ACTIVE,
                organization_id=organization.id,
                assigned_to_user_id=user.id,
                maintenance_team_id=core_team.id,
                location="Bay A",
            ),
            Equipment(
                name="CNC Router",
                category="machine",
                serial_number="CNC-22",
                department="Fabrication",
                status=EquipmentStatus.MAINTENANCE,
                organization_id=organization.id,
                maintenance_team_id=core_team.id,
                location="Bay B",
            ),
            Equipment(
                name="HVAC Unit",
                category="facility",
                serial_number="HVAC-9",
                department="Facilities",
                status=EquipmentStatus.OUT_OF_SERVICE,
                organization_id=organization.id,
                location="Roof",
            ),
        ]
        db.session.add_all(demo_equipment)
        db.session.flush()

    membership = TechnicianMembership.query.filter_by(user_id=user.id, organization_id=organization.id).first()
    if not membership:
        db.session.add(
            TechnicianMembership(
                organization_id=organization.id,
                user_id=user.id,
                team_id=core_team.id,
            )
        )
        db.session.flush()

    has_requests = MaintenanceRequest.query.filter_by(organization_id=organization.id).first()
    if not has_requests:
        equipment_map = {eq.name: eq for eq in Equipment.query.filter_by(organization_id=organization.id).all()}
        demo_requests = [
            MaintenanceRequest.create_request(
                organization_id=organization.id,
                subject="Replace hydraulic seals",
                description="Oil leakage detected on actuator. Replace seals and test pressure.",
                request_type=RequestType.CORRECTIVE,
                equipment=equipment_map.get("Hydraulic Press"),
                team=core_team,
                assigned_technician=user,
                requested_by=user,
            ),
            MaintenanceRequest.create_request(
                organization_id=organization.id,
                subject="Quarterly HVAC tune-up",
                description="Preventive maintenance for HVAC including filter swap and coil cleaning.",
                request_type=RequestType.PREVENTIVE,
                equipment=equipment_map.get("HVAC Unit"),
                team=core_team,
                requested_by=user,
                scheduled_date=datetime.utcnow().date() + timedelta(days=7),
            ),
            MaintenanceRequest.create_request(
                organization_id=organization.id,
                subject="Recalibrate CNC sensors",
                description="Laser alignment drifting; recalibrate before next production run.",
                request_type=RequestType.CORRECTIVE,
                equipment=equipment_map.get("CNC Router"),
                team=core_team,
                assigned_technician=user,
                requested_by=user,
            ),
            MaintenanceRequest.create_request(
                organization_id=organization.id,
                subject="Lubrication schedule - conveyors",
                description="Preventive lubrication on line 2 conveyors",
                request_type=RequestType.PREVENTIVE,
                team=core_team,
                requested_by=user,
                scheduled_date=datetime.utcnow().date() + timedelta(days=3),
            ),
        ]
        # Mark one request as already repaired to seed workflow history
        demo_requests[2].start()
        demo_requests[2].mark_repaired()
        db.session.add_all(demo_requests)

    if not organization.subscription:
        db.session.add(
            OrganizationSubscription(
                organization_id=organization.id,
                is_trial=True,
                is_active_subscription=False,
                base_fee_paid=False,
                max_users_allowed=5,
                subscription_status=SubscriptionStatus.TRIAL,
            )
        )

    db.session.commit()
    return organization, user
