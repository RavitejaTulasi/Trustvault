"""
TrustVault Configuration Settings
Loads environment variables safely using Pydantic Settings.
Enforces defense-in-depth defaults.
"""

import ipaddress
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

BASE_DIR = Path(__file__).resolve().parent.parent.parent

KNOWN_DEFAULT_DATABASE_PASSWORDS = frozenset(
    {
        "admin",
        "change-me",
        "change_me",
        "changeme",
        "password",
        "postgres",
        "replace-me",
        "replace_me",
        "replace_with_a_long_random_password",
        "secret",
        "trustvault_password",
        "url_encoded_password",
        "your-password",
        "your_password",
    }
)
SUPPORTED_DATABASE_BACKENDS = frozenset({"postgres", "postgresql"})


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Application Settings
    ENVIRONMENT: Literal["development", "production", "testing"] = Field(
        default="development",
        description="Exact runtime environment: development, production, or testing",
    )
    APP_NAME: str = "TrustVault"
    API_V1_PREFIX: str = "/api/v1"
    DEBUG: bool = False

    # Security & Cryptography
    SECRET_KEY: str = Field(
        default="trustvault_insecure_default_secret_key_change_in_production_32bytes",
        description="Key used for cryptographic signatures and session sealing",
    )

    # Cookie & Session Controls
    SESSION_COOKIE_NAME: str = "trustvault_session"
    SESSION_COOKIE_SECURE: bool = False  # Set to True in production (requires HTTPS)
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "lax"
    SESSION_MAX_AGE_SECONDS: int = 86400  # 24 hours
    CSRF_COOKIE_NAME: str = "trustvault_csrf"

    # Database Configuration
    DATABASE_URL: str = Field(
        default="sqlite:///./trustvault.db",
        description="PostgreSQL connection string (psycopg3 driver) or SQLite fallback",
    )

    # Storage Settings
    STORAGE_DIR: str = Field(
        default="./private_storage",
        description="Location for private persistent file storage (outside web root)",
    )
    MAX_FILE_SIZE_BYTES: int = Field(
        default=10 * 1024 * 1024,
        ge=1,
        description="Maximum single file upload size in bytes (10 MB default)",
    )
    MAX_MULTIPART_OVERHEAD_BYTES: int = Field(
        default=1024 * 1024,
        ge=1,
        description=(
            "Additional request-body allowance for multipart headers, boundaries, "
            "and ordinary form fields"
        ),
    )
    MAX_JSON_BODY_BYTES: int = Field(
        default=64 * 1024,
        ge=1,
        description="Maximum request-body size for non-multipart requests",
    )
    ALLOWED_EXTENSIONS: str = ".pdf,.txt,.md,.png,.jpg,.jpeg,.docx,.xlsx"
    STORAGE_ORPHAN_GRACE_SECONDS: int = Field(
        default=3600,
        ge=1,
        description=(
            "Age before an unreferenced or stale staging file is eligible for "
            "startup cleanup, which protects uploads in progress in other workers"
        ),
    )

    # Per-User and Global Storage Quotas
    MAX_USER_STORAGE_BYTES: int = Field(
        default=100 * 1024 * 1024,
        ge=1,
        description="Maximum bytes stored across a user's active documents",
    )
    MAX_GLOBAL_STORAGE_BYTES: int = Field(
        default=1024 * 1024 * 1024,
        ge=1,
        description="Maximum bytes stored across all active documents",
    )
    MAX_UPLOADS_PER_USER: int = Field(
        default=1000,
        ge=1,
        description="Maximum number of active documents a single user may own",
    )

    # Audit Retention Policy
    # The online hash chain is never deleted by the application. This value is
    # the retention objective for independently held archive copies.
    AUDIT_RETENTION_DAYS: int = Field(
        default=2555,
        ge=30,
        description=(
            "Retention objective in days for independently held audit archive "
            "copies; the online chain itself is retained indefinitely"
        ),
    )
    AUDIT_RETENTION_AUTO_DELETE: bool = Field(
        default=False,
        description=(
            "Unsupported destructive option: automatic deletion of online audit "
            "records is rejected because it breaks checkpoint verification"
        ),
    )

    # Rate Limiting
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = Field(
        default=5,
        ge=1,
        description="Maximum failed login attempts per IP and per IP+email window",
    )
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=300,
        ge=1,
        description="Shared fixed-window duration for login rate limiting",
    )
    LOGIN_RATE_LIMIT_MAX_BUCKETS: int = Field(
        default=50_000,
        ge=100,
        description=(
            "Maximum number of login rate-limit buckets retained; new buckets are "
            "refused when the bounded table is full"
        ),
    )

    # Reverse-Proxy Client IP Resolution
    TRUSTED_PROXY_IPS: str = Field(
        default="",
        description=(
            "Comma-separated proxy CIDRs allowed to supply X-Forwarded-For; "
            "empty means forwarded headers are never trusted"
        ),
    )

    # Audit Chain Verification Resource Controls
    AUDIT_VERIFY_MAX_RECORDS: int = Field(
        default=100_000,
        ge=1,
        description="Maximum audit-chain length accepted for a complete verification pass",
    )
    AUDIT_VERIFY_BATCH_SIZE: int = Field(
        default=1_000,
        ge=1,
        le=10_000,
        description="Audit rows fetched per verification batch",
    )
    AUDIT_VERIFY_TIMEOUT_SECONDS: int = Field(
        default=30,
        ge=1,
        description="Wall-clock budget for a complete audit-chain verification pass",
    )
    AUDIT_VERIFY_RATE_LIMIT_MAX_REQUESTS: int = Field(
        default=5,
        ge=1,
        description="Verification requests allowed per administrator per window",
    )
    AUDIT_VERIFY_RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        ge=1,
        description="Sliding window for verification request rate limiting",
    )

    # Audit Checkpoint Anchoring
    # "local_file" is HMAC-protected but shares the application host and is not
    # independent anchoring.
    AUDIT_ANCHOR_MODE: Literal["disabled", "local_file"] = Field(
        default="disabled",
        description=(
            "Checkpoint storage: 'disabled' or same-host 'local_file'"
        ),
    )
    AUDIT_ANCHOR_DIR: str = Field(
        default="./audit_checkpoints",
        description="Directory used by the local checkpoint adapter",
    )
    AUDIT_ANCHOR_HMAC_KEY: str = Field(
        default="",
        description=(
            "HMAC key (>= 32 characters) used to integrity-protect local checkpoint files"
        ),
    )
    AUDIT_CHECKPOINT_RATE_LIMIT_MAX_REQUESTS: int = Field(
        default=5,
        ge=1,
        description="Checkpoint create/verify requests allowed per administrator per window",
    )
    AUDIT_CHECKPOINT_RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60,
        ge=1,
        description="Sliding window for checkpoint operation rate limiting",
    )
    AUDIT_CHECKPOINT_INTERVAL_SECONDS: int = Field(
        default=3600,
        ge=1,
        description=(
            "Interval between scheduled audit checkpoint attempts when anchoring "
            "is enabled"
        ),
    )
    AUDIT_CHECKPOINT_MAX_AGE_SECONDS: int = Field(
        default=7200,
        ge=1,
        description=(
            "Maximum acceptable age of the most recent successful checkpoint "
            "before health reports it as overdue"
        ),
    )

    # CORS
    CORS_ORIGINS: str | list[str] = "http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000"

    # Seed Accounts
    SEED_ADMIN_EMAIL: str = "admin@trustvault.local"
    SEED_ADMIN_PASSWORD: str = "AdminSecurePass123!"
    SEED_OWNER_EMAIL: str = "owner@trustvault.local"
    SEED_OWNER_PASSWORD: str = "OwnerSecurePass123!"
    SEED_VIEWER_EMAIL: str = "viewer@trustvault.local"
    SEED_VIEWER_PASSWORD: str = "ViewerSecurePass123!"

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @field_validator("TRUSTED_PROXY_IPS", mode="after")
    @classmethod
    def validate_trusted_proxy_ips(cls, value: str) -> str:
        for entry in value.split(","):
            candidate = entry.strip()
            if not candidate:
                continue
            try:
                network = ipaddress.ip_network(candidate, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"TRUSTED_PROXY_IPS contains an invalid network: {candidate!r}"
                ) from exc
            if network.prefixlen == 0:
                raise ValueError(
                    "TRUSTED_PROXY_IPS must not trust every address; configure "
                    "the specific proxy networks instead."
                )
        return value

    @model_validator(mode="after")
    def validate_production_settings(self) -> "Settings":
        if self.ENVIRONMENT != "production":
            return self

        if not self.SESSION_COOKIE_SECURE:
            raise ValueError(
                "SESSION_COOKIE_SECURE must be true in production; "
                "plaintext session cookies are not permitted."
            )

        try:
            database_url = make_url(self.DATABASE_URL)
        except ArgumentError as exc:
            raise ValueError(
                "DATABASE_URL must be a valid database URL in production."
            ) from exc

        if database_url.get_backend_name() not in SUPPORTED_DATABASE_BACKENDS:
            raise ValueError(
                "DATABASE_URL must use PostgreSQL in production; "
                "SQLite and other backends are not permitted."
            )

        username = database_url.username or ""
        password = database_url.password or ""
        if not username.strip() or not password.strip():
            raise ValueError(
                "DATABASE_URL must include non-empty database username and "
                "password in production."
            )
        if password.strip().lower() in KNOWN_DEFAULT_DATABASE_PASSWORDS:
            raise ValueError(
                "DATABASE_URL must not use a known default database password "
                "in production."
            )

        return self

    @model_validator(mode="after")
    def validate_anchor_settings(self) -> "Settings":
        if self.ENVIRONMENT == "production" and self.AUDIT_ANCHOR_MODE == "disabled":
            raise ValueError(
                "AUDIT_ANCHOR_MODE must be enabled in production; use 'local_file' "
                "to store HMAC-protected checkpoints on persistent local storage."
            )

        if self.AUDIT_ANCHOR_MODE == "disabled":
            return self

        if self.AUDIT_CHECKPOINT_MAX_AGE_SECONDS < self.AUDIT_CHECKPOINT_INTERVAL_SECONDS:
            raise ValueError(
                "AUDIT_CHECKPOINT_MAX_AGE_SECONDS must be greater than or equal to "
                "AUDIT_CHECKPOINT_INTERVAL_SECONDS."
            )

        if len(self.AUDIT_ANCHOR_HMAC_KEY) < 32:
            raise ValueError(
                "AUDIT_ANCHOR_HMAC_KEY must be at least 32 characters when "
                "AUDIT_ANCHOR_MODE is 'local_file'."
            )

        if self.AUDIT_ANCHOR_MODE == "local_file":
            return self

        return self

    @model_validator(mode="after")
    def validate_audit_retention_settings(self) -> "Settings":
        if self.AUDIT_RETENTION_AUTO_DELETE:
            raise ValueError(
                "AUDIT_RETENTION_AUTO_DELETE is not supported. Online audit-chain "
                "records must be retained for verification; archive copies must be "
                "managed outside the application."
            )
        return self

    @property
    def allowed_extensions_set(self) -> set[str]:
        return {ext.strip().lower() for ext in self.ALLOWED_EXTENSIONS.split(",") if ext.strip()}

    @property
    def resolved_storage_path(self) -> Path:
        path = Path(self.STORAGE_DIR)
        if not path.is_absolute():
            path = BASE_DIR / path
        return path

    @property
    def resolved_audit_anchor_path(self) -> Path:
        path = Path(self.AUDIT_ANCHOR_DIR)
        if not path.is_absolute():
            path = BASE_DIR / path
        return path


settings = Settings()
