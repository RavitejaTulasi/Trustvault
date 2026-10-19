"""
TrustVault Configuration Settings
Loads environment variables safely using Pydantic Settings.
Enforces defense-in-depth defaults.
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Core Application Settings
    ENVIRONMENT: str = Field(default="development", description="development, production, or testing")
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
    MAX_FILE_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    ALLOWED_EXTENSIONS: str = ".pdf,.txt,.md,.png,.jpg,.jpeg,.docx,.xlsx"

    # Rate Limiting
    LOGIN_RATE_LIMIT_MAX_ATTEMPTS: int = 5
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = 300

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

    @model_validator(mode="after")
    def validate_anchor_settings(self) -> "Settings":
        if self.AUDIT_ANCHOR_MODE == "disabled":
            return self

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
