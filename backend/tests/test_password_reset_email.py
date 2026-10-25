"""Password reset email delivery tests."""

import logging
import re
from email.message import EmailMessage

import pytest
from httpx import AsyncClient
from sqlalchemy.orm import Session

from backend.app.models.otp import PasswordResetOTP
from backend.app.security.otp import verify_otp_code
from backend.app.services import email_service
from backend.app.services.email_service import (
    EmailDeliveryError,
    send_password_reset_otp,
)
from backend.tests.test_otp_reset import make_user


class FakeSMTP:
    sent: list[EmailMessage] = []
    login_args: tuple[str, str] | None = None

    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.started_tls = False

    def __enter__(self) -> "FakeSMTP":
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def ehlo(self) -> None:
        return None

    def starttls(self, context: object | None = None) -> None:
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        type(self).login_args = (username, password)

    def send_message(self, message: EmailMessage) -> None:
        type(self).sent.append(message)


class FailingSMTP:
    def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
        raise ConnectionRefusedError("SMTP server unavailable")


@pytest.fixture
def smtp_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(email_service.settings, "SMTP_PORT", 587)
    monkeypatch.setattr(email_service.settings, "SMTP_USERNAME", "mailer")
    monkeypatch.setattr(email_service.settings, "SMTP_PASSWORD", "smtp-secret")
    monkeypatch.setattr(email_service.settings, "SMTP_FROM_EMAIL", "security@trustvault.test")
    monkeypatch.setattr(email_service.settings, "SMTP_USE_TLS", True)
    monkeypatch.setattr(email_service.settings, "SMTP_USE_SSL", False)
    FakeSMTP.sent.clear()
    FakeSMTP.login_args = None


@pytest.mark.asyncio
async def test_request_reset_emails_the_otp(
    async_client: AsyncClient,
    db_session: Session,
    smtp_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "email.reset@example.com"
    make_user(db_session, email)
    monkeypatch.setattr(email_service.smtplib, "SMTP", FakeSMTP)

    response = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert response.status_code == 200, response.text

    assert len(FakeSMTP.sent) == 1
    message = FakeSMTP.sent[0]
    assert message["To"] == email
    assert message["From"] == "TrustVault <security@trustvault.test>"
    assert FakeSMTP.login_args == ("mailer", "smtp-secret")

    db_session.expire_all()
    otp_record = (
        db_session.query(PasswordResetOTP)
        .filter(PasswordResetOTP.email == email)
        .one()
    )
    assert otp_record.is_used is False
    assert len(otp_record.otp_code) == 64
    code_match = re.search(r"\b(\d{6})\b", message.get_content())
    assert code_match is not None
    code = code_match.group(1)
    assert otp_record.otp_code != code
    assert verify_otp_code(code, otp_record.otp_code)


@pytest.mark.asyncio
async def test_delivery_failure_invalidates_the_otp(
    async_client: AsyncClient,
    db_session: Session,
    smtp_settings: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    email = "email.failure@example.com"
    make_user(db_session, email)
    monkeypatch.setattr(email_service.smtplib, "SMTP", FailingSMTP)

    response = await async_client.post(
        "/api/v1/auth/request-reset",
        json={"email": email},
    )
    assert response.status_code == 200, response.text
    assert "sent" in response.json()["message"]

    db_session.expire_all()
    otp_record = (
        db_session.query(PasswordResetOTP)
        .filter(PasswordResetOTP.email == email)
        .one()
    )
    assert otp_record.is_used is True
    assert len(otp_record.otp_code) == 64

    verify = await async_client.post(
        "/api/v1/auth/verify-otp",
        json={"email": email, "otp_code": "000000"},
    )
    assert verify.status_code == 400
    assert verify.json()["detail"] == "Invalid or expired OTP code"


def test_development_logs_the_otp_without_smtp(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "")
    monkeypatch.setattr(email_service.settings, "ENVIRONMENT", "testing")
    caplog.set_level(logging.WARNING)

    send_password_reset_otp("dev.user@example.com", "123456")

    assert "123456" in caplog.text
    assert "dev.user@example.com" in caplog.text


def test_deployed_environment_requires_smtp(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(email_service.settings, "SMTP_HOST", "")
    monkeypatch.setattr(email_service.settings, "ENVIRONMENT", "production")

    with pytest.raises(EmailDeliveryError):
        send_password_reset_otp("deployed.user@example.com", "654321")
