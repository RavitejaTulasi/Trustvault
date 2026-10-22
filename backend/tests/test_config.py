import pytest
from pydantic import ValidationError

from backend.app.config import Settings

PRODUCTION_DATABASE_URL = (
    "postgresql+psycopg://trustvault_app:test-only-db-password@db:5432/trustvault"
)


def make_settings(**overrides: object) -> Settings:
    values: dict[str, object] = {
        "_env_file": None,
        "ENVIRONMENT": "production",
        "SESSION_COOKIE_SECURE": True,
        "DATABASE_URL": PRODUCTION_DATABASE_URL,
        "AUDIT_ANCHOR_MODE": "local_file",
        "AUDIT_ANCHOR_HMAC_KEY": "k" * 64,
    }
    values.update(overrides)
    return Settings(**values)


@pytest.mark.parametrize("environment", ["development", "production", "testing"])
def test_supported_environments_are_accepted(environment: str):
    configured = make_settings(ENVIRONMENT=environment)

    assert configured.ENVIRONMENT == environment


@pytest.mark.parametrize(
    "environment",
    ["", "Production", "PRODUCTION", "prod", "staging", "production "],
)
def test_invalid_environment_values_are_rejected(environment: str):
    with pytest.raises(ValidationError):
        make_settings(ENVIRONMENT=environment)


def test_s3_is_not_a_supported_checkpoint_mode():
    with pytest.raises(ValidationError, match="AUDIT_ANCHOR_MODE"):
        make_settings(AUDIT_ANCHOR_MODE="s3")


def test_nonproduction_allows_sqlite_and_insecure_session_cookies():
    configured = make_settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite:///:memory:",
        SESSION_COOKIE_SECURE=False,
    )

    assert configured.DATABASE_URL == "sqlite:///:memory:"
    assert configured.SESSION_COOKIE_SECURE is False


def test_production_rejects_insecure_session_cookie():
    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE"):
        make_settings(SESSION_COOKIE_SECURE=False)


def test_production_rejects_default_insecure_session_cookie():
    with pytest.raises(ValidationError, match="SESSION_COOKIE_SECURE"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DATABASE_URL=PRODUCTION_DATABASE_URL,
            AUDIT_ANCHOR_MODE="disabled",
        )


def test_production_rejects_default_sqlite_database():
    with pytest.raises(ValidationError, match="PostgreSQL"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            SESSION_COOKIE_SECURE=True,
            AUDIT_ANCHOR_MODE="disabled",
        )


def test_production_rejects_explicit_sqlite_database():
    with pytest.raises(ValidationError, match="PostgreSQL"):
        make_settings(DATABASE_URL="sqlite:///./production.db")


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://trustvault_app@db:5432/trustvault",
        "postgresql+psycopg://:test-only-db-password@db:5432/trustvault",
        "postgresql+psycopg://   :   @db:5432/trustvault",
    ],
)
def test_production_requires_database_username_and_password(database_url: str):
    with pytest.raises(ValidationError, match="username and password"):
        make_settings(DATABASE_URL=database_url)


@pytest.mark.parametrize(
    "password",
    [
        "trustvault_password",
        "trustvault%5Fpassword",
        "POSTGRES",
        "password",
        "changeme",
        "replace_with_a_long_random_password",
    ],
)
def test_production_rejects_known_default_database_passwords(password: str):
    database_url = (
        f"postgresql+psycopg://trustvault_app:{password}@db:5432/trustvault"
    )

    with pytest.raises(ValidationError, match="known default"):
        make_settings(DATABASE_URL=database_url)


def test_production_rejects_malformed_database_url():
    with pytest.raises(ValidationError, match="valid database URL"):
        make_settings(DATABASE_URL="not-a-url")


@pytest.mark.parametrize(
    "database_url",
    [
        "postgresql+psycopg://trustvault_app:unique-test-password@db:5432/trustvault",
        "postgresql://trustvault_app:unique-test-password@db:5432/trustvault",
        "postgres://trustvault_app:unique-test-password@db:5432/trustvault",
    ],
)
def test_production_accepts_postgresql_url_with_explicit_credentials(
    database_url: str,
):
    configured = make_settings(DATABASE_URL=database_url)

    assert configured.DATABASE_URL == database_url
    assert configured.SESSION_COOKIE_SECURE is True


def test_production_rejects_disabled_audit_anchoring():
    with pytest.raises(ValidationError, match="AUDIT_ANCHOR_MODE"):
        make_settings(AUDIT_ANCHOR_MODE="disabled")


def test_production_accepts_local_file_audit_anchoring():
    configured = make_settings(
        AUDIT_ANCHOR_MODE="local_file",
        AUDIT_ANCHOR_HMAC_KEY="k" * 64,
    )

    assert configured.AUDIT_ANCHOR_MODE == "local_file"


def test_local_file_audit_anchoring_requires_hmac_key_in_production():
    with pytest.raises(ValidationError, match="AUDIT_ANCHOR_HMAC_KEY"):
        make_settings(AUDIT_ANCHOR_MODE="local_file", AUDIT_ANCHOR_HMAC_KEY="")


def test_nonproduction_allows_disabled_audit_anchoring():
    configured = make_settings(
        ENVIRONMENT="testing",
        DATABASE_URL="sqlite:///:memory:",
        SESSION_COOKIE_SECURE=False,
        AUDIT_ANCHOR_MODE="disabled",
    )

    assert configured.AUDIT_ANCHOR_MODE == "disabled"


def test_enabled_anchor_requires_max_age_at_least_interval():
    with pytest.raises(ValidationError, match="AUDIT_CHECKPOINT_MAX_AGE_SECONDS"):
        make_settings(
            AUDIT_CHECKPOINT_INTERVAL_SECONDS=7200,
            AUDIT_CHECKPOINT_MAX_AGE_SECONDS=3600,
        )
