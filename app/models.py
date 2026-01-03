from __future__ import annotations

from datetime import date, datetime, timedelta
import hashlib
import re
from enum import Enum

from flask_login import UserMixin
from sqlalchemy import event, select
from sqlalchemy.ext.declarative import declared_attr
from werkzeug.security import generate_password_hash, check_password_hash

from .extensions import db


class BaseModel(db.Model):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False
    )

    @declared_attr  # type: ignore[misc]
    def __tablename__(cls) -> str:  # noqa: N805
        return cls.__name__.lower()


class OrganizationStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"


class SubscriptionStatus(str, Enum):
    TRIAL = "trial"
    ACTIVE = "active"
    EXPIRED = "expired"


class UserRole(str, Enum):
    SUPERADMIN = "super_admin"
    ADMIN = "admin"
    USER = "user"


class EquipmentStatus(str, Enum):
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    OUT_OF_SERVICE = "out_of_service"
    SCRAPPED = "scrapped"


class MaintenanceStatus(str, Enum):
    NEW = "new"
    IN_PROGRESS = "in_progress"
    REPAIRED = "repaired"
    SCRAP = "scrap"


class RequestType(str, Enum):
    CORRECTIVE = "corrective"
    PREVENTIVE = "preventive"


class PaymentStatus(str, Enum):
    CREATED = "created"
    CAPTURED = "captured"
    FAILED = "failed"
    REFUNDED = "refunded"


class SupportCategory(str, Enum):
    ACCOUNT = "account_login"
    BILLING = "billing_payments"
    TECHNICAL = "technical_issue"
    FEATURE = "feature_request"
    TEAM = "team_management"
    MAINTENANCE = "maintenance_support"
    SECURITY = "security_abuse"
    OTHER = "other"


class OTPPurpose(str, Enum):
    REGISTRATION = "registration"
    LOGIN = "login"
    PASSWORD_RESET = "password_reset"
    SUPERADMIN_LOGIN = "superadmin_login"


def _validate_org_match(parent_org_id: int, *records: db.Model) -> None:
    for record in records:
        if record is None:
            continue
        record_org = getattr(record, "organization_id", None)
        if record_org != parent_org_id:
            raise ValueError("Cross-organization relation is not allowed")


def _resolve_org_id(connection, table, pk_value: int | None) -> int | None:
    if pk_value is None:
        return None
    result = connection.execute(select(table.c.organization_id).where(table.c.id == pk_value)).scalar()
    return int(result) if result is not None else None


class Organization(BaseModel):
    __tablename__ = "organizations"

    name = db.Column(db.String(255), nullable=False, unique=True)
    slug = db.Column(db.String(128), nullable=False, unique=True, index=True)
    status = db.Column(
        db.Enum(OrganizationStatus, native_enum=False),
        default=OrganizationStatus.ACTIVE,
        nullable=False,
    )

    subscription = db.relationship(
        "OrganizationSubscription",
        back_populates="organization",
        uselist=False,
        cascade="all, delete-orphan",
    )

    users = db.relationship(
        "User",
        back_populates="organization",
        lazy="select",
        cascade="all, delete-orphan",
    )

    @staticmethod
    def _slugify(value: str) -> str:
        slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
        return slug or "org"

    @classmethod
    def generate_unique_slug(cls, name: str, exclude_id: int | None = None) -> str:
        base_slug = cls._slugify(name)
        candidate = base_slug
        counter = 2
        while True:
            existing = cls.query.filter_by(slug=candidate).first()
            if not existing or (exclude_id and existing.id == exclude_id):
                break
            candidate = f"{base_slug}-{counter}"
            counter += 1
        return candidate

    def __repr__(self) -> str:  # pragma: no cover - repr utility
        return f"<Organization {self.slug} ({self.status})>"

    @property
    def current_user_count(self) -> int:
        return len(self.users) if self.users else User.query.filter_by(organization_id=self.id).count()

    @property
    def max_users_allowed(self) -> int:
        if self.subscription:
            return self.subscription.max_users_allowed
        return 5

    @property
    def is_trial(self) -> bool:
        return bool(self.subscription and self.subscription.subscription_status == SubscriptionStatus.TRIAL)

    @property
    def has_active_subscription(self) -> bool:
        return bool(self.subscription and self.subscription.subscription_status == SubscriptionStatus.ACTIVE)


class User(UserMixin, BaseModel):
    __tablename__ = "users"

    __table_args__ = (
        db.UniqueConstraint("email", "organization_id", name="uq_user_email_org"),
    )

    email = db.Column(db.String(255), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRole, native_enum=False), nullable=False, default=UserRole.USER)
    active = db.Column(db.Boolean, nullable=False, default=True)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    login_locked_until = db.Column(db.DateTime, nullable=True)

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    organization = db.relationship(
        "Organization",
        back_populates="users",
        lazy="joined",
    )

    reset_token_hash = db.Column(db.String(255), nullable=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def has_role(self, role: UserRole) -> bool:
        return self.role == role or self.role == UserRole.SUPERADMIN

    @property
    def is_super_admin(self) -> bool:
        return self.role == UserRole.SUPERADMIN

    @property
    def is_active(self) -> bool:
        return bool(
            self.organization
            and self.organization.status == OrganizationStatus.ACTIVE
            and self.active
            and (self.email_verified is True or self.email_verified is None)
        )

    def mark_email_verified(self) -> None:
        self.email_verified = True
        self.active = True
        self.failed_login_attempts = 0
        self.login_locked_until = None

    def record_failed_login(self, max_failures: int, lock_minutes: int = 15) -> None:
        now = datetime.utcnow()
        if self.login_locked_until and now < self.login_locked_until:
            return
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_failures:
            self.login_locked_until = now + timedelta(minutes=lock_minutes)

    def reset_login_failures(self) -> None:
        self.failed_login_attempts = 0
        self.login_locked_until = None

    def issue_reset_token(self, raw_token: str, expires_in_minutes: int = 60) -> str:
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        self.reset_token_hash = token_hash
        self.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=expires_in_minutes)
        return token_hash

    def clear_reset_token(self) -> None:
        self.reset_token_hash = None
        self.reset_token_expires_at = None

    def reset_token_is_valid(self, raw_token: str) -> bool:
        if not self.reset_token_hash or not self.reset_token_expires_at:
            return False
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        return (
            self.reset_token_hash == token_hash
            and datetime.utcnow() <= self.reset_token_expires_at
        )

    def __repr__(self) -> str:  # pragma: no cover - repr utility
        return f"<User {self.email} org={self.organization_id}>"


class OrganizationSubscription(BaseModel):
    __tablename__ = "organization_subscriptions"

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    is_trial = db.Column(db.Boolean, nullable=False, default=True)
    is_active_subscription = db.Column(db.Boolean, nullable=False, default=False)
    base_fee_paid = db.Column(db.Boolean, nullable=False, default=False)
    max_users_allowed = db.Column(db.Integer, nullable=False, default=5)
    subscription_status = db.Column(
        db.Enum(SubscriptionStatus, native_enum=False),
        nullable=False,
        default=SubscriptionStatus.TRIAL,
    )

    organization = db.relationship("Organization", back_populates="subscription")
    payments = db.relationship("PaymentHistory", back_populates="subscription", lazy="select")

    def capacity_remaining(self, current_users: int) -> int:
        return max(self.max_users_allowed - current_users, 0)

    def can_add_users(self, requested: int, current_users: int) -> bool:
        return current_users + requested <= self.max_users_allowed

    def activate(self, *, purchased_capacity: int, base_fee_paid: bool) -> None:
        self.is_trial = False
        self.is_active_subscription = True
        self.base_fee_paid = self.base_fee_paid or base_fee_paid
        self.subscription_status = SubscriptionStatus.ACTIVE
        self.max_users_allowed = max(self.max_users_allowed, purchased_capacity)

    def move_to_trial(self, trial_seats: int) -> None:
        self.is_trial = True
        self.is_active_subscription = False
        self.base_fee_paid = False
        self.subscription_status = SubscriptionStatus.TRIAL
        self.max_users_allowed = trial_seats


class PaymentHistory(BaseModel):
    __tablename__ = "payment_history"

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    subscription_id = db.Column(
        db.Integer,
        db.ForeignKey("organization_subscriptions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    razorpay_order_id = db.Column(db.String(128), nullable=False, unique=True)
    razorpay_payment_id = db.Column(db.String(128), nullable=True)
    razorpay_signature = db.Column(db.String(255), nullable=True)
    amount = db.Column(db.Integer, nullable=False)  # stored in paise
    status = db.Column(db.Enum(PaymentStatus, native_enum=False), nullable=False, default=PaymentStatus.CREATED)
    purchased_user_capacity = db.Column(db.Integer, nullable=False)
    currency = db.Column(db.String(8), nullable=False, default="INR")
    base_fee_included = db.Column(db.Boolean, nullable=False, default=False)

    subscription = db.relationship("OrganizationSubscription", back_populates="payments", lazy="joined")
    organization = db.relationship("Organization", lazy="joined")

    __table_args__ = (
        db.Index("ix_payment_org_order", "organization_id", "razorpay_order_id"),
    )

    def mark_captured(self, payment_id: str, signature: str) -> None:
        self.razorpay_payment_id = payment_id
        self.razorpay_signature = signature
        self.status = PaymentStatus.CAPTURED



class MaintenanceTeam(BaseModel):
    __tablename__ = "maintenance_teams"

    team_name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    organization = db.relationship("Organization", lazy="joined")
    technicians = db.relationship(
        "TechnicianMembership",
        back_populates="team",
        lazy="select",
        cascade="all, delete-orphan",
    )
    equipment = db.relationship(
        "Equipment",
        back_populates="maintenance_team",
        lazy="select",
    )
    maintenance_requests = db.relationship(
        "MaintenanceRequest",
        back_populates="team",
        lazy="select",
    )

    __table_args__ = (
        db.UniqueConstraint("organization_id", "team_name", name="uq_team_name_org"),
    )

    def __repr__(self) -> str:  # pragma: no cover - repr utility
        return f"<MaintenanceTeam {self.team_name} org={self.organization_id}>"


class TechnicianMembership(BaseModel):
    __tablename__ = "technician_memberships"

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    team_id = db.Column(
        db.Integer,
        db.ForeignKey("maintenance_teams.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    organization = db.relationship("Organization", lazy="joined")
    user = db.relationship("User", lazy="joined")
    team = db.relationship("MaintenanceTeam", back_populates="technicians", lazy="joined")

    __table_args__ = (
        db.UniqueConstraint("organization_id", "user_id", "team_id", name="uq_technician_team_org"),
    )

    def __repr__(self) -> str:  # pragma: no cover - repr utility
        return f"<TechnicianMembership user={self.user_id} team={self.team_id} org={self.organization_id}>"


class Equipment(BaseModel):
    __tablename__ = "equipment"

    name = db.Column(db.String(255), nullable=False)
    category = db.Column(db.String(128), nullable=False)
    serial_number = db.Column(db.String(128), nullable=True)
    department = db.Column(db.String(128), nullable=True)
    assigned_to_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    purchase_date = db.Column(db.Date, nullable=True)
    warranty_expiry = db.Column(db.Date, nullable=True)
    location = db.Column(db.String(255), nullable=True)
    maintenance_team_id = db.Column(
        db.Integer,
        db.ForeignKey("maintenance_teams.id"),
        nullable=True,
        index=True,
    )
    status = db.Column(
        db.Enum(EquipmentStatus, native_enum=False),
        nullable=False,
        default=EquipmentStatus.ACTIVE,
    )

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    organization = db.relationship("Organization", lazy="joined")
    assigned_to_user = db.relationship("User", lazy="joined")
    maintenance_team = db.relationship("MaintenanceTeam", back_populates="equipment", lazy="joined")
    maintenance_requests = db.relationship(
        "MaintenanceRequest",
        back_populates="equipment",
        lazy="select",
    )

    __table_args__ = (
        db.UniqueConstraint("organization_id", "name", name="uq_equipment_name_org"),
        db.UniqueConstraint("organization_id", "serial_number", name="uq_equipment_serial_org"),
    )

    def assign_team(self, team: MaintenanceTeam | None) -> None:
        if team:
            _validate_org_match(self.organization_id, team)
        self.maintenance_team = team

    def assign_user(self, user: User | None) -> None:
        if user:
            _validate_org_match(self.organization_id, user)
        self.assigned_to_user = user

    def __repr__(self) -> str:  # pragma: no cover - repr utility
        return f"<Equipment {self.name} org={self.organization_id}>"


class MaintenanceRequest(BaseModel):
    __tablename__ = "maintenance_requests"

    subject = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(
        db.Enum(MaintenanceStatus, native_enum=False),
        nullable=False,
        default=MaintenanceStatus.NEW,
    )
    request_type = db.Column(
        db.Enum(RequestType, native_enum=False),
        nullable=False,
        default=RequestType.CORRECTIVE,
    )
    priority = db.Column(db.String(32), nullable=False, default="normal")
    equipment_category_snapshot = db.Column(db.String(128), nullable=True)
    scheduled_date = db.Column(db.Date, nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    duration_hours = db.Column(db.Float, nullable=True)

    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    equipment_id = db.Column(db.Integer, db.ForeignKey("equipment.id"), nullable=True)
    team_id = db.Column(db.Integer, db.ForeignKey("maintenance_teams.id"), nullable=True)
    assigned_technician_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    requested_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    organization = db.relationship("Organization", lazy="joined")
    equipment = db.relationship("Equipment", back_populates="maintenance_requests", lazy="joined")
    team = db.relationship("MaintenanceTeam", back_populates="maintenance_requests", lazy="joined")
    assigned_technician = db.relationship("User", foreign_keys=[assigned_technician_id], lazy="joined")
    requested_by = db.relationship("User", foreign_keys=[requested_by_id], lazy="joined")

    __table_args__ = (
        db.Index("ix_requests_org_status", "organization_id", "status"),
        db.Index("ix_requests_org_type", "organization_id", "request_type"),
    )

    def apply_auto_context(self) -> None:
        if self.equipment:
            _validate_org_match(self.organization_id, self.equipment)
            self.equipment_category_snapshot = self.equipment.category
            if not self.team_id and self.equipment.maintenance_team_id:
                self.team_id = self.equipment.maintenance_team_id
            if not self.assigned_technician_id and self.equipment.assigned_to_user_id:
                self.assigned_technician_id = self.equipment.assigned_to_user_id
        if self.team:
            _validate_org_match(self.organization_id, self.team)
        if self.assigned_technician:
            _validate_org_match(self.organization_id, self.assigned_technician)

    @property
    def is_overdue(self) -> bool:
        if not self.scheduled_date:
            return False
        if self.status in {MaintenanceStatus.REPAIRED, MaintenanceStatus.SCRAP}:
            return False
        return self.scheduled_date < date.today()

    def start(self, started_at: datetime | None = None) -> None:
        if self.status is None:
            self.status = MaintenanceStatus.NEW
        if self.status != MaintenanceStatus.NEW:
            raise ValueError("Only NEW requests can move to IN_PROGRESS")
        self.status = MaintenanceStatus.IN_PROGRESS
        self.started_at = started_at or datetime.utcnow()

    def mark_repaired(self, completed_at: datetime | None = None) -> None:
        if self.status not in {MaintenanceStatus.IN_PROGRESS, MaintenanceStatus.NEW}:
            raise ValueError("Request must be active to be repaired")
        self.status = MaintenanceStatus.REPAIRED
        self.completed_at = completed_at or datetime.utcnow()
        if self.started_at and self.completed_at:
            duration = self.completed_at - self.started_at
            self.duration_hours = round(duration.total_seconds() / 3600, 2)

    def mark_scrap(self, completed_at: datetime | None = None) -> None:
        self.status = MaintenanceStatus.SCRAP
        self.completed_at = completed_at or datetime.utcnow()
        if self.started_at and self.completed_at:
            duration = self.completed_at - self.started_at
            self.duration_hours = round(duration.total_seconds() / 3600, 2)

    @classmethod
    def create_request(
        cls,
        *,
        organization_id: int,
        subject: str,
        description: str | None,
        request_type: RequestType,
        equipment: Equipment | None = None,
        team: MaintenanceTeam | None = None,
        assigned_technician: User | None = None,
        requested_by: User | None = None,
        scheduled_date: date | None = None,
        priority: str = "normal",
    ) -> "MaintenanceRequest":
        if request_type == RequestType.PREVENTIVE and not scheduled_date:
            raise ValueError("Preventive requests require a scheduled date")
        if equipment:
            _validate_org_match(organization_id, equipment)
        if team:
            _validate_org_match(organization_id, team)
        if assigned_technician:
            _validate_org_match(organization_id, assigned_technician)
        if requested_by:
            _validate_org_match(organization_id, requested_by)

        request = cls(
            organization_id=organization_id,
            subject=subject.strip(),
            description=description or "",
            request_type=request_type,
            status=MaintenanceStatus.NEW,
            equipment=equipment,
            team=team,
            assigned_technician=assigned_technician,
            requested_by=requested_by,
            scheduled_date=scheduled_date,
            priority=priority,
        )
        request.apply_auto_context()
        return request

    def __repr__(self) -> str:  # pragma: no cover - repr utility
        return (
            f"<MaintenanceRequest {self.subject} status={self.status} type={self.request_type} "
            f"org={self.organization_id}>"
        )


class EmailOtp(BaseModel):
    __tablename__ = "email_otps"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    organization_id = db.Column(
        db.Integer,
        db.ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    purpose = db.Column(db.Enum(OTPPurpose, native_enum=False), nullable=False)
    otp_hash = db.Column(db.String(128), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, nullable=False, default=False)
    used_at = db.Column(db.DateTime, nullable=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    max_attempts = db.Column(db.Integer, nullable=False, default=5)
    resend_count = db.Column(db.Integer, nullable=False, default=0)
    last_sent_at = db.Column(db.DateTime, nullable=True)
    client_fingerprint = db.Column(db.String(255), nullable=True)

    user = db.relationship("User", lazy="joined")
    organization = db.relationship("Organization", lazy="joined")

    __table_args__ = (
        db.Index("ix_otp_user_purpose", "user_id", "purpose"),
    )

    @staticmethod
    def _hash(otp_code: str) -> str:
        return hashlib.sha256(otp_code.encode()).hexdigest()

    @property
    def expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    @property
    def remaining_attempts(self) -> int:
        return max(self.max_attempts - self.attempts, 0)

    def verify(self, otp_code: str) -> bool:
        return not self.expired and not self.is_used and self.otp_hash == self._hash(otp_code)

    def mark_used(self) -> None:
        self.is_used = True
        self.used_at = datetime.utcnow()

    def bump_attempts(self) -> None:
        self.attempts += 1


class SuperAdminOtp(BaseModel):
    __tablename__ = "super_admin_otps"

    email = db.Column(db.String(255), nullable=False, index=True)
    purpose = db.Column(db.Enum(OTPPurpose, native_enum=False), nullable=False)
    otp_hash = db.Column(db.String(128), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, nullable=False, default=False)
    used_at = db.Column(db.DateTime, nullable=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    max_attempts = db.Column(db.Integer, nullable=False, default=5)
    resend_count = db.Column(db.Integer, nullable=False, default=0)
    last_sent_at = db.Column(db.DateTime, nullable=True)
    client_fingerprint = db.Column(db.String(255), nullable=True)

    __table_args__ = (
        db.Index("ix_super_admin_otp_email", "email"),
    )

    @staticmethod
    def _hash(otp_code: str) -> str:
        return hashlib.sha256(otp_code.encode()).hexdigest()

    @property
    def expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    @property
    def remaining_attempts(self) -> int:
        return max(self.max_attempts - self.attempts, 0)

    def verify(self, otp_code: str) -> bool:
        return not self.expired and not self.is_used and self.otp_hash == self._hash(otp_code)

    def mark_used(self) -> None:
        self.is_used = True
        self.used_at = datetime.utcnow()

    def bump_attempts(self) -> None:
        self.attempts += 1


class SecurityEvent(BaseModel):
    __tablename__ = "security_events"

    event_type = db.Column(db.String(64), nullable=False, index=True)
    severity = db.Column(db.String(16), nullable=False, default="info")
    actor_type = db.Column(db.String(32), nullable=False, default="user")
    actor_id = db.Column(db.Integer, nullable=True)
    actor_email = db.Column(db.String(255), nullable=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    meta = db.Column("metadata", db.JSON, nullable=True)

    organization = db.relationship("Organization", lazy="joined")

    __table_args__ = (
        db.Index("ix_security_event_type_created", "event_type", "created_at"),
    )

    @classmethod
    def record(
        cls,
        *,
        event_type: str,
        severity: str = "info",
        actor_type: str = "user",
        actor_id: int | None = None,
        actor_email: str | None = None,
        organization_id: int | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        meta: dict | None = None,
    ) -> "SecurityEvent":
        event = cls(
            event_type=event_type,
            severity=severity,
            actor_type=actor_type,
            actor_id=actor_id,
            actor_email=actor_email,
            organization_id=organization_id,
            ip_address=ip_address,
            user_agent=user_agent,
            meta=meta,
        )
        db.session.add(event)
        return event


class SupportRequest(BaseModel):
    __tablename__ = "support_requests"

    full_name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, index=True)
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    category = db.Column(db.Enum(SupportCategory, native_enum=False), nullable=False)
    status = db.Column(db.String(32), nullable=False, default="open")
    organization_name = db.Column(db.String(255), nullable=True)
    organization_id = db.Column(db.Integer, db.ForeignKey("organizations.id"), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    ip_address = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)

    organization = db.relationship("Organization", lazy="joined")
    user = db.relationship("User", lazy="joined")

    __table_args__ = (
        db.Index("ix_support_email_created", "email", "created_at"),
    )

    def __repr__(self) -> str:  # pragma: no cover - repr utility
        return f"<SupportRequest {self.category} {self.email}>"


@event.listens_for(Equipment, "before_insert")
@event.listens_for(Equipment, "before_update")
def _equipment_org_guard(mapper, connection, target: Equipment) -> None:  # noqa: D401
    user_org = _resolve_org_id(connection, User.__table__, target.assigned_to_user_id)
    team_org = _resolve_org_id(connection, MaintenanceTeam.__table__, target.maintenance_team_id)
    if user_org and user_org != target.organization_id:
        raise ValueError("Assigned user must belong to the same organization")
    if team_org and team_org != target.organization_id:
        raise ValueError("Maintenance team must belong to the same organization")


@event.listens_for(TechnicianMembership, "before_insert")
@event.listens_for(TechnicianMembership, "before_update")
def _technician_org_guard(mapper, connection, target: TechnicianMembership) -> None:  # noqa: D401
    user_org = _resolve_org_id(connection, User.__table__, target.user_id)
    team_org = _resolve_org_id(connection, MaintenanceTeam.__table__, target.team_id)
    if not user_org or not team_org:
        raise ValueError("Technician and team must be provided")
    if target.organization_id not in {user_org, team_org} or user_org != team_org:
        raise ValueError("Technician assignments must stay within the same organization")


@event.listens_for(MaintenanceRequest, "before_insert")
@event.listens_for(MaintenanceRequest, "before_update")
def _request_org_guard(mapper, connection, target: MaintenanceRequest) -> None:  # noqa: D401
    if target.request_type == RequestType.PREVENTIVE and not target.scheduled_date:
        raise ValueError("Preventive maintenance requires a scheduled date")

    equipment_org = _resolve_org_id(connection, Equipment.__table__, target.equipment_id)
    team_org = _resolve_org_id(connection, MaintenanceTeam.__table__, target.team_id)
    tech_org = _resolve_org_id(connection, User.__table__, target.assigned_technician_id)
    requested_by_org = _resolve_org_id(connection, User.__table__, target.requested_by_id)

    for related_org in [equipment_org, team_org, tech_org, requested_by_org]:
        if related_org and related_org != target.organization_id:
            raise ValueError("Cross-organization maintenance relations are not allowed")

    # Populate default context after validation
    target.apply_auto_context()


@event.listens_for(SupportRequest, "before_insert")
@event.listens_for(SupportRequest, "before_update")
def _support_request_guard(mapper, connection, target: SupportRequest) -> None:  # noqa: D401
    if target.user_id:
        user_org = _resolve_org_id(connection, User.__table__, target.user_id)
        if target.organization_id and user_org and user_org != target.organization_id:
            raise ValueError("Support request user must belong to the same organization")
        if not target.organization_id:
            target.organization_id = user_org


__all__ = [
    "BaseModel",
    "Organization",
    "OrganizationStatus",
    "UserRole",
    "User",
    "EmailOtp",
    "OTPPurpose",
    "MaintenanceTeam",
    "TechnicianMembership",
    "Equipment",
    "EquipmentStatus",
    "MaintenanceRequest",
    "MaintenanceStatus",
    "RequestType",
    "SuperAdminOtp",
    "SecurityEvent",
    "SupportCategory",
    "SupportRequest",
]
