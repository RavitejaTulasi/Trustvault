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
    # "local_file" is a development adapter only. It is not independent of the
    # application host and must never be treated as production-grade anchoring.
    # "s3" selects the external object-storage adapter and requires an
    # independently controlled bucket; no bucket or credentials ship with this
    # repository, so an unconfigured deployment fails closed.
    AUDIT_ANCHOR_MODE: Literal["disabled", "local_file", "s3"] = Field(
        default="disabled",
        description=(
            "Checkpoint anchoring adapter: 'disabled', development-only "
            "'local_file', or external 's3'"
        ),
    )
    AUDIT_ANCHOR_DIR: str = Field(
        default="./audit_checkpoints",
        description="Directory used by the development-only local checkpoint adapter",
    )
    AUDIT_ANCHOR_HMAC_KEY: str = Field(
        default="",
        description=(
            "HMAC key (>= 32 characters) used to integrity-protect checkpoints; "
            "required for 'local_file' and 's3' modes"
        ),
    )
    AUDIT_ANCHOR_S3_BUCKET: str = Field(
        default="",
        description="Bucket for the external S3 checkpoint adapter (required for mode 's3')",
    )
    AUDIT_ANCHOR_S3_PREFIX: str = Field(
        default="trustvault-audit-checkpoints",
        description="Object key prefix for checkpoints in the external bucket",
    )
    AUDIT_ANCHOR_S3_REGION: str = Field(
        default="",
        description="AWS region for the external checkpoint bucket (required for mode 's3')",
    )
    AUDIT_ANCHOR_S3_ENDPOINT_URL: str = Field(
        default="",
        description=(
            "Optional custom endpoint for S3-compatible services; must be https "
            "in production"
        ),
    )
    AUDIT_ANCHOR_S3_KMS_KEY_ID: str = Field(
        default="",
        description="Optional KMS key ID for server-side encryption of checkpoint objects",
    )
    AUDIT_ANCHOR_S3_OBJECT_LOCK_MODE: Literal["", "GOVERNANCE", "COMPLIANCE"] = Field(
        default="",
        description=(
            "Optional S3 Object Lock mode; the bucket must have Object Lock enabled"
        ),
    )
    AUDIT_ANCHOR_S3_OBJECT_LOCK_DAYS: int = Field(
        default=30,
        ge=1,
        description="Retention period applied when S3 Object Lock mode is configured",
    )
    AUDIT_ANCHOR_S3_CONNECT_TIMEOUT_SECONDS: int = Field(
        default=5,
        ge=1,
        description="Connect timeout for external checkpoint store requests",
    )
    AUDIT_ANCHOR_S3_READ_TIMEOUT_SECONDS: int = Field(
        default=10,
        ge=1,
        description="Read timeout for external checkpoint store requests",
    )
    AUDIT_ANCHOR_S3_MAX_ATTEMPTS: int = Field(
        default=3,
        ge=1,
        description="Maximum attempts for retryable external checkpoint store requests",
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
                "AUDIT_ANCHOR_MODE must be 's3' in production; production cannot "
                "start without external audit checkpoint anchoring."
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
                "AUDIT_ANCHOR_MODE is 'local_file' or 's3'."
            )

        if self.AUDIT_ANCHOR_MODE == "local_file":
            if self.ENVIRONMENT == "production":
                raise ValueError(
                    "AUDIT_ANCHOR_MODE=local_file is development-only; it is not "
                    "independent production anchoring. Disable it or configure a "
                    "supported external checkpoint adapter."
                )
            return self

        # AUDIT_ANCHOR_MODE == "s3": required provider configuration is explicit
        if not self.AUDIT_ANCHOR_S3_BUCKET.strip():
            raise ValueError(
                "AUDIT_ANCHOR_S3_BUCKET is required when AUDIT_ANCHOR_MODE=s3."
            )
        if not self.AUDIT_ANCHOR_S3_REGION.strip():
            raise ValueError(
                "AUDIT_ANCHOR_S3_REGION is required when AUDIT_ANCHOR_MODE=s3."
            )
        if (
            self.ENVIRONMENT == "production"
            and self.AUDIT_ANCHOR_S3_ENDPOINT_URL
            and not self.AUDIT_ANCHOR_S3_ENDPOINT_URL.startswith("https://")
        ):
            raise ValueError(
                "AUDIT_ANCHOR_S3_ENDPOINT_URL must use https in production; "
                "plaintext endpoints are not permitted for checkpoint anchoring."
            )
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
