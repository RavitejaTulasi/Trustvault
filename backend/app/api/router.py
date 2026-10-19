"""
Main API Router for TrustVault
Aggregates all sub-routers under structured prefixes.
"""

from fastapi import APIRouter

from backend.app.api.health import router as health_router

api_router = APIRouter()

# Health router mounted at both root and /api/v1 for deployment compatibility
api_router.include_router(health_router)
