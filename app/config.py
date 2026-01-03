import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
INSTANCE_DIR = BASE_DIR / "instance"

# Load .env before any config values are read so os.getenv sees them
load_dotenv(BASE_DIR / ".env")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _database_uri() -> str:
    explicit = os.getenv("DATABASE_URL") or os.getenv("DATABASE_URI")
    if explicit:
        # Allow the common postgres:// prefix and normalize it for SQLAlchemy
        if explicit.startswith("postgres://"):
            explicit = explicit.replace("postgres://", "postgresql://", 1)
        return explicit
    db_path_env = os.getenv("DATABASE_PATH", str(INSTANCE_DIR / "GearGuard.db"))
    db_path = Path(db_path_env)
    if not db_path.is_absolute():
        db_path = (BASE_DIR / db_path).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path.as_posix()}"


class BaseConfig:
    SECRET_KEY = os.getenv("SECRET_KEY") or "dev-insecure-key"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": int(os.getenv("DB_POOL_RECYCLE_SECONDS", "280")),
    }
    DB_PATH = os.getenv("DATABASE_PATH", str(INSTANCE_DIR / "app.db"))
    TEMPLATES_AUTO_RELOAD = False
    SESSION_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Strict")
    REMEMBER_COOKIE_SAMESITE = os.getenv("REMEMBER_COOKIE_SAMESITE", "Strict")
    REMEMBER_COOKIE_DURATION = timedelta(days=int(os.getenv("REMEMBER_COOKIE_DAYS", "365")))
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", True)
    REMEMBER_COOKIE_SECURE = SESSION_COOKIE_SECURE
    SESSION_REFRESH_EACH_REQUEST = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=int(os.getenv("SESSION_LIFETIME_HOURS", str(24 * 365))))
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 60 * 60
    PREFERRED_URL_SCHEME = os.getenv("PREFERRED_URL_SCHEME", "https")
    SEND_FILE_MAX_AGE_DEFAULT = int(os.getenv("SEND_FILE_MAX_AGE_SECONDS", "604800"))
    ASSET_VERSION = os.getenv("ASSET_VERSION", "1")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_FORMAT = os.getenv(
        "LOG_FORMAT",
        "%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    TRUSTED_PROXY_COUNT = int(os.getenv("TRUSTED_PROXY_COUNT", "0"))
    USE_PROXY_FIX = _env_bool("USE_PROXY_FIX", False)
    RUN_DB_UPGRADE_ON_START = _env_bool("RUN_DB_UPGRADE_ON_START", False)
    BOOTSTRAP_DEMO_DATA = _env_bool("BOOTSTRAP_DEMO_DATA", False)
    AI_API_KEY = os.getenv("GENAI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    MAX_CONTENT_LENGTH = int(os.getenv("MAX_CONTENT_LENGTH", str(16 * 1024 * 1024)))
    # Email / SMTP
    MAIL_SENDER = os.getenv("MAIL_SENDER", "smtp.gmail.com")
    MAIL_SMTP_HOST = os.getenv("MAIL_SMTP_HOST")
    MAIL_SMTP_PORT = int(os.getenv("MAIL_SMTP_PORT", "587"))
    MAIL_SMTP_USERNAME = os.getenv("MAIL_SMTP_USERNAME")
    MAIL_SMTP_PASSWORD = os.getenv("MAIL_SMTP_PASSWORD")
    MAIL_USE_TLS = _env_bool("MAIL_USE_TLS", True)
    MAIL_USE_SSL = _env_bool("MAIL_USE_SSL", False)
    MAIL_TIMEOUT = int(os.getenv("MAIL_TIMEOUT_SECONDS", "20"))
    MAIL_CONSOLE_FALLBACK = _env_bool("MAIL_CONSOLE_FALLBACK", False)

    # OTP / token security
    OTP_EXPIRY_MINUTES = int(os.getenv("OTP_EXPIRY_MINUTES", "10"))
    OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))
    OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "90"))
    OTP_MAX_PER_HOUR = int(os.getenv("OTP_MAX_PER_HOUR", "6"))
    LOGIN_MAX_FAILURES = int(os.getenv("LOGIN_MAX_FAILURES", "10"))

    # Super admin (root) controls
    SUPERADMIN_EMAIL = os.getenv("SUPERADMIN_EMAIL")
    SUPERADMIN_PASSWORD = os.getenv("SUPERADMIN_PASSWORD")
    SUPERADMIN_PASSWORD_HASH = os.getenv("SUPERADMIN_PASSWORD_HASH")
    SUPERADMIN_NAME = os.getenv("SUPERADMIN_NAME", "Platform Root")
    SUPERADMIN_ORG_SLUG = os.getenv("SUPERADMIN_ORG_SLUG", "gearguard-india")
    SUPERADMIN_OTP_EXPIRY_MINUTES = int(os.getenv("SUPERADMIN_OTP_EXPIRY_MINUTES", "8"))
    SUPERADMIN_OTP_MAX_ATTEMPTS = int(os.getenv("SUPERADMIN_OTP_MAX_ATTEMPTS", "5"))
    SUPERADMIN_OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("SUPERADMIN_OTP_RESEND_COOLDOWN_SECONDS", "60"))
    SUPERADMIN_LOGIN_MAX_FAILURES = int(os.getenv("SUPERADMIN_LOGIN_MAX_FAILURES", "6"))
    SUPERADMIN_LOGIN_LOCK_MINUTES = int(os.getenv("SUPERADMIN_LOGIN_LOCK_MINUTES", "20"))
    SUPERADMIN_RATE_LIMIT_PER_IP = int(os.getenv("SUPERADMIN_RATE_LIMIT_PER_IP", "15"))
    SUPERADMIN_RATE_LIMIT_WINDOW_MINUTES = int(os.getenv("SUPERADMIN_RATE_LIMIT_WINDOW_MINUTES", "30"))
    SUPERADMIN_SESSION_LIFETIME_HOURS = int(os.getenv("SUPERADMIN_SESSION_LIFETIME_HOURS", "6"))
    SUPERADMIN_ALERT_EMAIL = os.getenv("SUPERADMIN_ALERT_EMAIL")

    # Subscription & billing (Razorpay)
    SUBSCRIPTION_TRIAL_SEATS = int(os.getenv("SUBSCRIPTION_TRIAL_SEATS", "5"))
    SUBSCRIPTION_BASE_FEE_INR = int(os.getenv("SUBSCRIPTION_BASE_FEE_INR", "4999"))
    SUBSCRIPTION_PER_MEMBER_INR = int(os.getenv("SUBSCRIPTION_PER_MEMBER_INR", "499"))
    SUBSCRIPTION_CURRENCY = os.getenv("SUBSCRIPTION_CURRENCY", "INR")
    RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
    RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")
    RAZORPAY_WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET")


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    ENV = "development"
    TEMPLATES_AUTO_RELOAD = True
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    RUN_DB_UPGRADE_ON_START = _env_bool("RUN_DB_UPGRADE_ON_START", True)
    BOOTSTRAP_DEMO_DATA = _env_bool("BOOTSTRAP_DEMO_DATA", True)
    MAIL_CONSOLE_FALLBACK = _env_bool("MAIL_CONSOLE_FALLBACK", True)


class ProductionConfig(BaseConfig):
    DEBUG = False
    ENV = "production"
    SESSION_COOKIE_SECURE = True
    REMEMBER_COOKIE_SECURE = True
    TEMPLATES_AUTO_RELOAD = False
    RUN_DB_UPGRADE_ON_START = _env_bool("RUN_DB_UPGRADE_ON_START", False)
    BOOTSTRAP_DEMO_DATA = _env_bool("BOOTSTRAP_DEMO_DATA", False)
    PREFERRED_URL_SCHEME = "https"


def get_config_class(config_name: str | None = None):
    env = (config_name or os.getenv("APP_ENV") or os.getenv("FLASK_ENV", "development")).lower()
    if env == "production":
        return ProductionConfig
    return DevelopmentConfig
