"""Specialist endpoint contract definitions for CyberClaw Core.

The endpoint is the boundary between global Core coordination and
local Specialist autonomy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus


class SpecialistHealth(str, Enum):
    """Health status of a specialist subsystem."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


class SpecialistRequest(BaseModel):
    """Structured request dispatched from Core to a Specialist."""

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    capability_id: str
    action: str = Field(default="execute", description="Action verb requested from specialist")
    parameters: Dict[str, Any] = Field(default_factory=dict)
    context: ExecutionContext = Field(default_factory=ExecutionContext)


class SpecialistResponse(BaseModel):
    """Structured response returned by Specialist to Core."""

    specialist_id: str
    request_id: str
    status: ExecutionStatus
    result: ExecutionResult
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_result(
        cls, specialist_id: str, request_id: str, result: ExecutionResult, metadata: Optional[Dict[str, Any]] = None
    ) -> SpecialistResponse:
        return cls(
            specialist_id=specialist_id,
            request_id=request_id,
            status=result.status,
            result=result,
            metadata=metadata or {},
        )


class SpecialistEndpoint(ABC):
    """Abstract contract that every Specialist endpoint must implement."""

    @abstractmethod
    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        """Invoke specialist capability and return structured response."""
        pass

    @abstractmethod
    def health(self) -> SpecialistHealth:
        """Report current health status of the specialist."""
        pass
