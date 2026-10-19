"""
Pydantic Schemas for System Health Monitoring
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(description="System status: 'healthy', 'degraded', or 'unhealthy'")
    app: str = Field(description="Application name")
    environment: str = Field(description="Current running environment")
    version: str = Field(description="Application version")
    timestamp: datetime = Field(description="Current server UTC timestamp")
    database: str = Field(description="Database connectivity status: 'connected' or 'disconnected'")
    storage: str = Field(description="Private storage accessibility status: 'available' or 'unavailable'")
    components: dict[str, Any] = Field(default_factory=dict, description="Detailed status breakdown")
