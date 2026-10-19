"""
Pydantic Schemas for User Authentication and Account Management
"""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegisterRequest(BaseModel):
    """Request body for new user registration."""
    email: EmailStr = Field(description="Valid email address (used as login identifier)")
    password: str = Field(
        min_length=12,
        max_length=128,
        description="Password (12–128 characters, must contain upper, lower, digit, and symbol)",
    )
    full_name: str = Field(
        min_length=2,
        max_length=255,
        description="User's display name",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Enforce OWASP-aligned minimum password complexity."""
        errors = []
        if not any(c.isupper() for c in v):
            errors.append("at least one uppercase letter")
        if not any(c.islower() for c in v):
            errors.append("at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            errors.append("at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in v):
            errors.append("at least one special character")
        if errors:
            raise ValueError(f"Password must contain {', '.join(errors)}")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str) -> str:
        stripped = v.strip()
        if len(stripped) < 2:
            raise ValueError("Full name must be at least 2 characters")
        return stripped


class UserLoginRequest(BaseModel):
    """Request body for user login."""
    email: EmailStr = Field(description="Registered email address")
    password: str = Field(
        min_length=1,
        max_length=128,
        description="Account password",
    )


class UserResponse(BaseModel):
    """Safe user representation for API responses (never exposes password hash)."""
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserUpdateRequest(BaseModel):
    """Request body for updating user profile (self-service or admin)."""
    full_name: str | None = Field(
        default=None,
        min_length=2,
        max_length=255,
        description="Updated display name",
    )
    password: str | None = Field(
        default=None,
        min_length=12,
        max_length=128,
        description="New password (optional)",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str | None) -> str | None:
        if v is None:
            return v
        errors = []
        if not any(c.isupper() for c in v):
            errors.append("at least one uppercase letter")
        if not any(c.islower() for c in v):
            errors.append("at least one lowercase letter")
        if not any(c.isdigit() for c in v):
            errors.append("at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?" for c in v):
            errors.append("at least one special character")
        if errors:
            raise ValueError(f"Password must contain {', '.join(errors)}")
        return v

    @field_validator("full_name")
    @classmethod
    def validate_full_name(cls, v: str | None) -> str | None:
        if v is None:
            return v
        stripped = v.strip()
        if len(stripped) < 2:
            raise ValueError("Full name must be at least 2 characters")
        return stripped


class AdminUserUpdateRequest(BaseModel):
    """Admin-only: update role or activation status of a user."""
    role: str | None = Field(
        default=None,
        description="New role: 'admin', 'owner', or 'viewer'",
    )
    is_active: bool | None = Field(
        default=None,
        description="Activate or deactivate user account",
    )

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is None:
            return v
        from backend.app.models.user import UserRole
        if v not in UserRole.ALL_ROLES:
            raise ValueError(f"Role must be one of: {sorted(UserRole.ALL_ROLES)}")
        return v


class UserListResponse(BaseModel):
    """Paginated user list response."""
    users: list[UserResponse]
    total: int
    page: int
    page_size: int
