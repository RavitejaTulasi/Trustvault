from pathlib import Path
from typing import Any
from urllib.parse import quote

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine

from backend.app.config import Settings
from backend.app.services.checkpoint_store import PostgresCheckpointStore

TEST_CA_FILE = Path(__file__).resolve()
_TLS_QUERY = (
    "?sslmode=verify-full&sslrootcert="
    f"{quote(str(TEST_CA_FILE), safe='/')}"
)
PRODUCTION_ANCHOR_DATABASE_URL = (
    "postgresql+psycopg://trustvault_anchor:test-only-anchor-password"
    "@audit-db:5432/trustvault_anchor"
)

PRODUCTION_DATABASE_URL = (
    "postgresql+psycopg://trustvault_app:test-only-db-password@db:5432/trustvault"
)


PRODUCTION_DATABASE_URL_TLS = f"{PRODUCTION_DATABASE_URL}{_TLS_QUERY}"
PRODUCTION_ANCHOR_DATABASE_URL_TLS = (
    f"{PRODUCTION_ANCHOR_DATABASE_URL}{_TLS_QUERY}"
)


def make_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "_env_file": None,
        "ENVIRONMENT": "production",
        "SESSION_COOKIE_SECURE": True,
        "DATABASE_URL": PRODUCTION_DATABASE_URL_TLS,
        "AUDIT_ANCHOR_MODE": "postgresql",
        "AUDIT_ANCHOR_HMAC_KEY": "k" * 64,
        "AUDIT_ANCHOR_DATABASE_URL": PRODUCTION_ANCHOR_DATABASE_URL_TLS,
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


def test_local_storage_does_not_require_supabase_credentials():
    configured = make_settings(
        STORAGE_BACKEND="local",
        SUPABASE_URL="",
        SUPABASE_SERVICE_ROLE_KEY="",
    )

    assert configured.STORAGE_BACKEND == "local"


def test_settings_repr_does_not_expose_credentials_or_seed_passwords():
    configured = make_settings(
        SECRET_KEY="synthetic-secret-key",
        DATABASE_URL=(
            "postgresql+psycopg://test-user:synthetic-db-password"
            f"@db.example.test/trustvault{_TLS_QUERY}"
        ),
        AUDIT_ANCHOR_HMAC_KEY="synthetic-audit-hmac-key-that-is-long-enough",
        AUDIT_ANCHOR_DATABASE_URL=(
            "postgresql+psycopg://anchor:synthetic-anchor-password"
            f"@audit-db.example.test/trustvault_anchor{_TLS_QUERY}"
        ),
        SUPABASE_SERVICE_ROLE_KEY="synthetic-supabase-service-key",
        SEED_ADMIN_PASSWORD="synthetic-admin-password",
        SEED_OWNER_PASSWORD="synthetic-owner-password",
        SEED_VIEWER_PASSWORD="synthetic-viewer-password",
    )

    representation = repr(configured)
    for sensitive_value in (
        "synthetic-secret-key",
        "synthetic-db-password",
        "synthetic-audit-hmac-key",
        "synthetic-anchor-password",
        "synthetic-supabase-service-key",
        "synthetic-admin-password",
        "synthetic-owner-password",
        "synthetic-viewer-password",
    ):
        assert sensitive_value not in representation


def test_supabase_storage_requires_url():
    with pytest.raises(ValidationError, match="SUPABASE_URL"):
        make_settings(
            STORAGE_BACKEND="supabase",
            SUPABASE_URL="",
            SUPABASE_SERVICE_ROLE_KEY="test-only-placeholder-key",
            SUPABASE_STORAGE_BUCKET="trustvault-bucket",
        )


def test_supabase_storage_requires_service_role_key():
    with pytest.raises(ValidationError, match="SUPABASE_SERVICE_ROLE_KEY"):
        make_settings(
            STORAGE_BACKEND="supabase",
            SUPABASE_URL="https://example.supabase.co",
            SUPABASE_SERVICE_ROLE_KEY="",
            SUPABASE_STORAGE_BUCKET="trustvault-bucket",
        )


def test_supabase_storage_requires_bucket_name():
    with pytest.raises(ValidationError, match="SUPABASE_STORAGE_BUCKET"):
        make_settings(
            STORAGE_BACKEND="supabase",
            SUPABASE_URL="https://example.supabase.co",
            SUPABASE_SERVICE_ROLE_KEY="test-only-placeholder-key",
            SUPABASE_STORAGE_BUCKET="",
        )


@pytest.mark.parametrize(
    "url",
    [
        "http://example.supabase.co",
        "https://",
        "https://user:password@example.supabase.co",
        "https://example.supabase.co/storage",
        "https://example.supabase.co?query=value",
        "https://example.supabase.co#fragment",
    ],
)
def test_supabase_storage_rejects_invalid_project_urls(url: str):
    with pytest.raises(ValidationError, match="SUPABASE_URL"):
        make_settings(
            STORAGE_BACKEND="supabase",
            SUPABASE_URL=url,
            SUPABASE_SERVICE_ROLE_KEY="test-only-placeholder-key",
            SUPABASE_STORAGE_BUCKET="trustvault-bucket",
        )


@pytest.mark.parametrize("bucket", ["", "trust vault", "TrustVault", "-bucket", "ab"])
def test_supabase_storage_rejects_invalid_bucket_names(bucket: str):
    with pytest.raises(ValidationError, match="SUPABASE_STORAGE_BUCKET"):
        make_settings(
            STORAGE_BACKEND="supabase",
            SUPABASE_URL="https://example.supabase.co",
            SUPABASE_SERVICE_ROLE_KEY="test-only-placeholder-key",
            SUPABASE_STORAGE_BUCKET=bucket,
        )


def test_supabase_storage_accepts_valid_project_url_and_bucket():
    configured = make_settings(
        STORAGE_BACKEND="supabase",
        SUPABASE_URL="https://example.supabase.co",
        SUPABASE_SERVICE_ROLE_KEY="test-only-placeholder-key",
        SUPABASE_STORAGE_BUCKET="trustvault-bucket",
    )

    assert configured.STORAGE_BACKEND == "supabase"
    assert configured.SUPABASE_STORAGE_BUCKET == "trustvault-bucket"


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


def test_production_rejects_session_cookie_without_httponly():
    with pytest.raises(ValidationError, match="SESSION_COOKIE_HTTPONLY"):
        make_settings(SESSION_COOKIE_HTTPONLY=False)


@pytest.mark.parametrize(
    "samesite",
    ["", "invalid", "Lax"],
)
def test_production_rejects_invalid_session_cookie_samesite(samesite: str):
    with pytest.raises(ValidationError, match="SESSION_COOKIE_SAMESITE"):
        make_settings(SESSION_COOKIE_SAMESITE=samesite)


@pytest.mark.parametrize("samesite", ["lax", "strict", "none"])
def test_production_accepts_supported_session_cookie_samesite(samesite: str):
    configured = make_settings(SESSION_COOKIE_SAMESITE=samesite)

    assert configured.SESSION_COOKIE_SAMESITE == samesite


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
    database_url = f"{database_url}{_TLS_QUERY}"
    configured = make_settings(DATABASE_URL=database_url)

    assert configured.DATABASE_URL == database_url
    assert configured.SESSION_COOKIE_SECURE is True


@pytest.mark.parametrize(
    "tls_query",
    [
        "",
        "?sslmode=require&sslrootcert=%2Fetc%2Fsecrets%2Fpostgres-ca.crt",
        "?sslmode=verify-full",
    ],
)
def test_production_requires_verified_database_tls(tls_query: str):
    with pytest.raises(ValidationError, match="DATABASE_URL.*verify-full"):
        make_settings(
            DATABASE_URL=(
                "postgresql+psycopg://app:test-only-password"
                f"@db.example.test/trustvault{tls_query}"
            )
        )


@pytest.mark.parametrize(
    "tls_query",
    [
        "",
        "?sslmode=require&sslrootcert=%2Fetc%2Fsecrets%2Fpostgres-ca.crt",
        "?sslmode=verify-full",
    ],
)
def test_production_requires_verified_anchor_tls(tls_query: str):
    with pytest.raises(
        ValidationError,
        match="AUDIT_ANCHOR_DATABASE_URL.*verify-full",
    ):
        make_settings(
            AUDIT_ANCHOR_DATABASE_URL=(
                "postgresql+psycopg://anchor:test-only-password"
                f"@audit-db.example.test/trustvault_anchor{tls_query}"
            )
        )


def test_psycopg_receives_verified_tls_options_for_both_engines():
    application_engine = create_engine(PRODUCTION_DATABASE_URL_TLS)
    try:
        _, application_options = (
            application_engine.dialect.create_connect_args(
                application_engine.url
            )
        )
    finally:
        application_engine.dispose()

    anchor_store = PostgresCheckpointStore(
        PRODUCTION_ANCHOR_DATABASE_URL_TLS,
        b"k" * 32,
    )
    try:
        _, anchor_options = anchor_store._engine.dialect.create_connect_args(
            anchor_store._engine.url
        )
    finally:
        anchor_store.close()

    assert application_options["sslmode"] == "verify-full"
    assert application_options["sslrootcert"] == str(TEST_CA_FILE)
    assert anchor_options["sslmode"] == "verify-full"
    assert anchor_options["sslrootcert"] == str(TEST_CA_FILE)


@pytest.mark.parametrize(
    "setting_name",
    ["DATABASE_URL", "AUDIT_ANCHOR_DATABASE_URL"],
)
@pytest.mark.parametrize("path_kind", ["missing", "directory"])
def test_production_rejects_unreadable_ca_file(
    tmp_path: Path,
    setting_name: str,
    path_kind: str,
):
    ca_path = tmp_path / "missing-ca.crt"
    if path_kind == "directory":
        ca_path.mkdir()
    ca_query = (
        "?sslmode=verify-full&sslrootcert="
        f"{quote(str(ca_path), safe='/')}"
    )
    ca_url = (
        "postgresql+psycopg://synthetic-user:synthetic-password"
        f"@synthetic-db.example.test/trustvault{ca_query}"
    )

    with pytest.raises(
        ValidationError,
        match=f"{setting_name}.*readable CA certificate file",
    ):
        make_settings(**{setting_name: ca_url})


def test_production_rejects_disabled_audit_anchoring():
    with pytest.raises(ValidationError, match="AUDIT_ANCHOR_MODE"):
        make_settings(AUDIT_ANCHOR_MODE="disabled")


def test_production_requires_independent_audit_anchoring():
    with pytest.raises(ValidationError, match="must be 'postgresql'"):
        make_settings(AUDIT_ANCHOR_MODE="local_file")


def test_independent_audit_anchoring_requires_hmac_key():
    with pytest.raises(ValidationError, match="AUDIT_ANCHOR_HMAC_KEY"):
        make_settings(AUDIT_ANCHOR_HMAC_KEY="")


def test_production_requires_anchor_database_url():
    with pytest.raises(ValidationError, match="AUDIT_ANCHOR_DATABASE_URL"):
        make_settings(AUDIT_ANCHOR_DATABASE_URL="")


def test_production_rejects_anchor_database_on_application_host():
    with pytest.raises(ValidationError, match="separately administered"):
        make_settings(
            AUDIT_ANCHOR_DATABASE_URL=(
                "postgresql+psycopg://anchor:other-password"
                "@db:5432/separate_name"
            )
        )


def test_production_requires_postgresql_anchor_instead_of_disabled():
    with pytest.raises(ValidationError, match="must be 'postgresql'"):
        make_settings(AUDIT_ANCHOR_MODE="disabled")


def test_production_rejects_non_postgresql_anchor_database():
    with pytest.raises(ValidationError, match="AUDIT_ANCHOR_DATABASE_URL"):
        make_settings(AUDIT_ANCHOR_DATABASE_URL="sqlite:///anchor.db")


def test_production_accepts_separate_postgresql_anchor():
    configured = make_settings()

    assert configured.AUDIT_ANCHOR_MODE == "postgresql"
    assert (
        configured.AUDIT_ANCHOR_DATABASE_URL
        == PRODUCTION_ANCHOR_DATABASE_URL_TLS
    )


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
