import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import inspect
from flask import Flask, g, render_template, request
from flask_login import current_user
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_migrate import upgrade as migrate_upgrade

from .config import INSTANCE_DIR, get_config_class
from .extensions import csrf, db, login_manager, migrate
from .models import (
    Equipment,
    EmailOtp,
    MaintenanceRequest,
    MaintenanceTeam,
    Organization,
    OrganizationSubscription,
    PaymentHistory,
    SecurityEvent,
    SuperAdminOtp,
    TechnicianMembership,
    User,
)
from .tenant import bootstrap_demo_tenant, get_current_organization, get_current_user, set_tenant_session
from .super_admin import SuperAdminIdentity, is_super_admin_id, super_admin_identity

def create_app(config_name: str | None = None) -> Flask:
    """Application factory that sets up extensions, config, and blueprints."""
    base_dir = Path(__file__).resolve().parent.parent
    load_dotenv(base_dir / ".env")

    app = Flask(__name__, instance_path=str(INSTANCE_DIR), instance_relative_config=True)

    app.config.from_object(get_config_class(config_name))

    if app.config.get("ENV") == "production" and app.config.get("SECRET_KEY") == "dev-insecure-key":
        raise RuntimeError("SECRET_KEY must be set via environment variables for production deployments.")

    if app.config.get("USE_PROXY_FIX"):
        app.wsgi_app = ProxyFix(  # type: ignore[attr-defined]
            app.wsgi_app,
            x_for=app.config.get("TRUSTED_PROXY_COUNT", 1),
            x_proto=app.config.get("TRUSTED_PROXY_COUNT", 1),
            x_host=app.config.get("TRUSTED_PROXY_COUNT", 1),
            x_port=app.config.get("TRUSTED_PROXY_COUNT", 1),
        )

    _configure_logging(app)

    os.makedirs(app.instance_path, exist_ok=True)

    db.init_app(app)
    migrations_dir = base_dir / "migrations"
    migrate.init_app(app, db, directory=str(migrations_dir))
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "main.login"
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    @login_manager.unauthorized_handler
    def _on_unauthorized():  # pragma: no cover - view glue
        return render_template("errors/401.html", message="Please sign in to continue."), 401

    from .routes import admin_bp, dashboard_bp, main_bp, super_admin_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(super_admin_bp)

    @login_manager.user_loader
    def load_user(user_id: str):  # pragma: no cover - simple loader
        if is_super_admin_id(user_id):
            return super_admin_identity()
        try:
            return User.query.get(int(user_id))
        except (TypeError, ValueError):
            return None

    with app.app_context():
        if app.config.get("RUN_DB_UPGRADE_ON_START"):
            try:
                if migrations_dir.exists() and any(migrations_dir.iterdir()):
                    migrate_upgrade(directory=str(migrations_dir))
                else:
                    app.logger.info(
                        "Skipping automatic database upgrade because the migrations directory is missing or empty."
                    )
            except Exception:
                app.logger.exception("Automatic database upgrade failed")
                raise

        # Create tables automatically when no schema exists (helps first run/local dev)
        inspector = inspect(db.engine)
        if not inspector.get_table_names():
            db.create_all()
        if app.config.get("BOOTSTRAP_DEMO_DATA"):
            bootstrap_demo_tenant()

    @app.before_request
    def attach_request_context():
        user = get_current_user()
        if user and user.is_authenticated and not getattr(user, "is_super_admin", False):
            set_tenant_session(user)

    @app.after_request
    def apply_security_headers(response):  # pragma: no cover - response mutation
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if app.config.get("SESSION_COOKIE_SECURE") and request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response

    @app.teardown_appcontext
    def remove_user(exception=None):
        g.pop("current_user", None)
        g.pop("current_organization", None)

    @app.shell_context_processor
    def shell_context():
        return {
            "db": db,
            "User": User,
            "Organization": Organization,
            "OrganizationSubscription": OrganizationSubscription,
            "PaymentHistory": PaymentHistory,
            "Equipment": Equipment,
            "MaintenanceRequest": MaintenanceRequest,
            "MaintenanceTeam": MaintenanceTeam,
            "TechnicianMembership": TechnicianMembership,
            "EmailOtp": EmailOtp,
            "SuperAdminOtp": SuperAdminOtp,
            "SecurityEvent": SecurityEvent,
            "SuperAdminIdentity": SuperAdminIdentity,
        }

    @app.context_processor
    def inject_tenant_context():
        org = None
        if current_user and current_user.is_authenticated and not getattr(current_user, "is_super_admin", False):
            org = get_current_organization()
        return {
            "current_user": current_user if current_user and current_user.is_authenticated else None,
            "current_organization": org,
            "asset_version": app.config.get("ASSET_VERSION", "1"),
        }

    def _render_error(status: int, error: Exception):
        description = getattr(error, "description", None) or ""
        known_templates = {401, 403, 404, 500}
        template_status = status if status in known_templates else 500
        template = f"errors/{template_status}.html"
        return render_template(template, message=description, status_code=status), status

    @app.errorhandler(CSRFError)
    def handle_csrf_error(error):  # pragma: no cover - framework hook
        return _render_error(403, error)

    @app.errorhandler(401)
    def handle_unauthorized(error):  # pragma: no cover - framework hook
        return _render_error(401, error)

    @app.errorhandler(403)
    def handle_forbidden(error):  # pragma: no cover - framework hook
        return _render_error(403, error)

    @app.errorhandler(404)
    def handle_not_found(error):  # pragma: no cover - framework hook
        return _render_error(404, error)

    @app.errorhandler(Exception)
    def handle_exception(error):  # pragma: no cover - framework hook
        if isinstance(error, HTTPException):
            return _render_error(error.code or 500, error)
        logging.exception("Unhandled server error", exc_info=error)
        return _render_error(500, error)

    return app


def _configure_logging(app: Flask) -> None:
    level = getattr(logging, str(app.config.get("LOG_LEVEL", "INFO")).upper(), logging.INFO)
    logging.basicConfig(level=level, format=app.config.get("LOG_FORMAT"))
    app.logger.setLevel(level)
