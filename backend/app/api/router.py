"""
Main API Router for TrustVault
Aggregates all sub-routers under structured prefixes.
"""

from fastapi import APIRouter

from backend.app.api.auth import router as auth_router
from backend.app.api.health import router as health_router
from backend.app.api.users import router as users_router

api_router = APIRouter()

# Health router mounted at both root and /api/v1 for deployment compatibility
api_router.include_router(health_router)

# Authentication: /api/v1/auth/*
api_router.include_router(auth_router)

# Admin user management: /api/v1/admin/users/*
api_router.include_router(users_router)
