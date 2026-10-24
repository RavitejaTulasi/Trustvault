"""
Main API Router for TrustVault
Aggregates all sub-routers under structured prefixes.
"""

from fastapi import APIRouter

from backend.app.api.audit import router as audit_router
from backend.app.api.auth import router as auth_router
from backend.app.api.documents import router as documents_router
from backend.app.api.health import router as health_router
from backend.app.api.storage_operations import router as storage_operations_router
from backend.app.api.users import router as users_router

api_router = APIRouter()

# Health router mounted at both root and /api/v1 for deployment compatibility
api_router.include_router(health_router)

# Authentication: /api/v1/auth/*
api_router.include_router(auth_router)

# Documents & Storage: /api/v1/documents/*
api_router.include_router(documents_router)

# Admin user management: /api/v1/admin/users/*
api_router.include_router(users_router)

# Admin storage recovery: /api/v1/admin/storage-operations/*
api_router.include_router(storage_operations_router)

# Admin audit trail and document activity: /api/v1/admin/audit*, /api/v1/admin/documents/activity
api_router.include_router(audit_router)
