from __future__ import annotations

import hmac
from dataclasses import dataclass
from typing import Optional

from flask import current_app
from flask_login import UserMixin
from werkzeug.security import check_password_hash

from .models import UserRole


@dataclass
class SuperAdminIdentity(UserMixin):
    email: str
    name: str

    @property
    def role(self) -> UserRole:
        return UserRole.SUPERADMIN

    @property
    def is_super_admin(self) -> bool:  # pragma: no cover - simple property
        return True

    @property
    def is_active(self) -> bool:  # pragma: no cover - flask-login hook
        return True

    @property
    def is_authenticated(self) -> bool:  # pragma: no cover - flask-login hook
        return True

    @property
    def organization_id(self) -> None:
        return None

    @property
    def organization_slug(self) -> str:
        return str(current_app.config.get("SUPERADMIN_ORG_SLUG", "gearguard-india"))

    @property
    def organization(self):
        return None

    def get_id(self) -> str:  # pragma: no cover - flask-login hook
        return "superadmin"


def is_super_admin_id(user_id: str | None) -> bool:
    return user_id == "superadmin"


def super_admin_configured() -> bool:
    cfg = current_app.config
    return bool(cfg.get("SUPERADMIN_EMAIL") and (cfg.get("SUPERADMIN_PASSWORD") or cfg.get("SUPERADMIN_PASSWORD_HASH")))


def super_admin_identity() -> Optional[SuperAdminIdentity]:
    if not super_admin_configured():
        return None
    cfg = current_app.config
    return SuperAdminIdentity(email=str(cfg.get("SUPERADMIN_EMAIL")), name=str(cfg.get("SUPERADMIN_NAME", "Platform Root")))


def _compare_secret(secret: str, candidate: str) -> bool:
    try:
        return hmac.compare_digest(secret.encode(), candidate.encode())
    except Exception:
        return False


def super_admin_password_matches(password: str) -> bool:
    cfg = current_app.config
    hashed = cfg.get("SUPERADMIN_PASSWORD_HASH")
    if hashed:
        try:
            return check_password_hash(hashed, password)
        except Exception:
            return False
    plain = cfg.get("SUPERADMIN_PASSWORD") or ""
    return _compare_secret(plain, password)


__all__ = [
    "SuperAdminIdentity",
    "super_admin_configured",
    "super_admin_identity",
    "super_admin_password_matches",
    "is_super_admin_id",
]
