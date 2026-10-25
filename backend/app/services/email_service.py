"""Email delivery for security-sensitive account messages.

Password reset codes are never written to logs in deployed environments. When
SMTP is not configured, development and testing log the code so the local flow
remains usable; staging and production raise instead of silently dropping it.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage

from backend.app.config import settings

logger = logging.getLogger(__name__)

PASSWORD_RESET_OTP_EXPIRY_MINUTES = 15


class EmailDeliveryError(RuntimeError):
    """Raised when a security email cannot be handed to the SMTP server."""


def _build_password_reset_message(
    recipient: str,
    code: str,
    expires_minutes: int,
) -> EmailMessage:
    message = EmailMessage()
    message["Subject"] = "Your TrustVault password reset code"
    message["From"] = f"TrustVault <{settings.SMTP_FROM_EMAIL}>"
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your TrustVault password.\n\n"
        f"Your verification code is: {code}\n\n"
        f"This code expires in {expires_minutes} minutes and can be used once. "
        "If you did not request a password reset, you can ignore this email.\n"
    )
    return message


def _deliver(server: smtplib.SMTP, message: EmailMessage) -> None:
    if settings.SMTP_USERNAME:
        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
    server.send_message(message)


def send_password_reset_otp(
    recipient: str,
    code: str,
    expires_minutes: int = PASSWORD_RESET_OTP_EXPIRY_MINUTES,
) -> None:
    """Deliver a password reset code by SMTP or log it in development."""
    host = settings.SMTP_HOST.strip()
    if not host:
        if settings.is_deployed:
            raise EmailDeliveryError(
                "SMTP is not configured; password reset email cannot be delivered"
            )
        logger.warning(
            "Password reset code for %s (development delivery, no SMTP configured): %s",
            recipient,
            code,
        )
        return

    message = _build_password_reset_message(recipient, code, expires_minutes)
    try:
        if settings.SMTP_USE_SSL:
            with smtplib.SMTP_SSL(
                host,
                settings.SMTP_PORT,
                timeout=settings.SMTP_TIMEOUT_SECONDS,
                context=ssl.create_default_context(),
            ) as server:
                _deliver(server, message)
        else:
            with smtplib.SMTP(
                host,
                settings.SMTP_PORT,
                timeout=settings.SMTP_TIMEOUT_SECONDS,
            ) as server:
                server.ehlo()
                if settings.SMTP_USE_TLS:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                _deliver(server, message)
    except (OSError, smtplib.SMTPException) as exc:
        raise EmailDeliveryError(
            "Password reset email could not be delivered"
        ) from exc
