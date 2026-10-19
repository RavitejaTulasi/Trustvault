"""
TrustVault Configuration Settings
Loads environment variables safely using Pydantic Settings.
Enforces defense-in-depth defaults.
"""

from pathlib import Path

from pydantic import Field, field_validator
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

    @property
    def allowed_extensions_set(self) -> set[str]:
        return {ext.strip().lower() for ext in self.ALLOWED_EXTENSIONS.split(",") if ext.strip()}

    @property
    def resolved_storage_path(self) -> Path:
        path = Path(self.STORAGE_DIR)
        if not path.is_absolute():
            path = BASE_DIR / path
        return path


settings = Settings()
