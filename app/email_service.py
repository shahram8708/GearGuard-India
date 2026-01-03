from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Iterable, Mapping

from flask import current_app, render_template

from .models import OTPPurpose, User, SupportRequest
from .super_admin import SuperAdminIdentity


class MailDeliveryError(RuntimeError):
    pass


def _build_message(*, subject: str, recipient: str, html: str, text: str | None = None) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = current_app.config.get("MAIL_SENDER", "security@gearguard.app")
    msg["To"] = recipient
    msg.set_content(text or "This email requires an HTML capable client.")
    msg.add_alternative(html, subtype="html")
    return msg


def _smtp_config() -> dict:
    return {
        "host": current_app.config.get("MAIL_SMTP_HOST"),
        "port": current_app.config.get("MAIL_SMTP_PORT", 587),
        "username": current_app.config.get("MAIL_SMTP_USERNAME"),
        "password": current_app.config.get("MAIL_SMTP_PASSWORD"),
        "use_tls": current_app.config.get("MAIL_USE_TLS", True),
        "use_ssl": current_app.config.get("MAIL_USE_SSL", False),
        "timeout": current_app.config.get("MAIL_TIMEOUT", 20),
    }


def send_email(subject: str, recipient: str, *, html: str, text: str | None = None) -> None:
    cfg = _smtp_config()
    if not cfg["host"]:
        if current_app.config.get("MAIL_CONSOLE_FALLBACK"):
            payload = text or html
            current_app.logger.warning("SMTP host not configured; delivering email to console for %s", recipient)
            print("\n=== DEV EMAIL (console fallback) ===")
            print(f"To: {recipient}")
            print(f"Subject: {subject}")
            print("Body:\n" + (payload if payload else "<no body>"))
            print("=== END DEV EMAIL ===\n")
            return
        raise MailDeliveryError("SMTP host not configured; set MAIL_SMTP_HOST to send emails.")

    msg = _build_message(subject=subject, recipient=recipient, html=html, text=text)

    try:
        if cfg["use_ssl"]:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=cfg["timeout"], context=context) as server:
                if cfg["username"]:
                    server.login(cfg["username"], cfg["password"] or "")
                server.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=cfg["timeout"]) as server:
                server.ehlo()
                if cfg["use_tls"]:
                    server.starttls(context=ssl.create_default_context())
                if cfg["username"]:
                    server.login(cfg["username"], cfg["password"] or "")
                server.send_message(msg)
    except Exception as exc:  # pragma: no cover - delivery safety
        current_app.logger.exception("Email delivery failed: %s", exc)
        raise MailDeliveryError(str(exc)) from exc


def send_otp_email(user: User, otp_code: str, *, purpose: OTPPurpose, expires_in_minutes: int) -> None:
    html = render_template(
        "emails/otp_email.html",
        user=user,
        otp_code=otp_code,
        purpose=purpose.value.replace("_", " ").title(),
        expires_in_minutes=expires_in_minutes,
    )
    send_email(
        subject=f"GearGuard verification code for {purpose.value.replace('_', ' ')}",
        recipient=user.email,
        html=html,
        text=f"Your GearGuard verification code is {otp_code}. It expires in {expires_in_minutes} minutes.",
    )


def send_password_reset_email(user: User, reset_link: str, *, expires_in_minutes: int) -> None:
    html = render_template(
        "emails/password_reset.html",
        user=user,
        reset_link=reset_link,
        expires_in_minutes=expires_in_minutes,
    )
    send_email(
        subject="Reset your GearGuard password",
        recipient=user.email,
        html=html,
        text=f"Reset your GearGuard password using this secure link (expires in {expires_in_minutes} minutes): {reset_link}",
    )


def send_subscription_event(recipient: str, subject: str, context: Mapping[str, str]) -> None:
    html = render_template("emails/subscription_event.html", **context)
    send_email(subject, recipient, html=html)


def send_maintenance_alert(recipient: str, subject: str, context: Mapping[str, str | Iterable[str]]) -> None:
    html = render_template("emails/maintenance_alert.html", **context)
    send_email(subject, recipient, html=html)


def send_security_alert(recipient: str, subject: str, context: Mapping[str, str]) -> None:
    html = render_template("emails/security_alert.html", **context)
    send_email(subject, recipient, html=html)


def send_super_admin_otp(identity: SuperAdminIdentity, otp_code: str, *, expires_in_minutes: int) -> None:
    html = render_template(
        "emails/super_admin_otp.html",
        identity=identity,
        otp_code=otp_code,
        expires_in_minutes=expires_in_minutes,
    )
    send_email(
        subject="GearGuard root access verification",
        recipient=identity.email,
        html=html,
        text=(
            f"Your root access code is {otp_code}. This one-time code expires in "
            f"{expires_in_minutes} minutes."
        ),
    )


def send_support_request_notification(support: SupportRequest, recipient: str) -> None:
    html = render_template(
        "emails/support_notification.html",
        support=support,
    )
    text = (
        f"Support request from {support.full_name} <{support.email}>\n"
        f"Category: {support.category.value}\n"
        f"Subject: {support.subject}\n"
        f"Message: {support.message[:500]}..."
    )
    send_email(
        subject=f"[GearGuard Support] {support.subject}",
        recipient=recipient,
        html=html,
        text=text,
    )


__all__ = [
    "send_email",
    "send_otp_email",
    "send_password_reset_email",
    "send_subscription_event",
    "send_maintenance_alert",
    "send_security_alert",
    "send_super_admin_otp",
    "send_support_request_notification",
    "MailDeliveryError",
]
