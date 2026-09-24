"""Information Requirements model for goal-directed investigation coordination."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RequirementStatus(str, Enum):
    """Lifecycle status of an Information Requirement."""

    OPEN = "OPEN"
    ASSIGNED = "ASSIGNED"
    SATISFIED = "SATISFIED"
    SATISFIED_EMPTY = "SATISFIED_EMPTY"  # Specialist completed normally but found no relevant evidence
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class InformationRequirement(BaseModel):
    """A generic, domain-agnostic information need in an investigation.

    Specifies WHAT intelligence is needed (e.g. 'Need DNS info for target X')
    rather than micro-managing which specific raw tool must execute.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    description: str
    evidence_types_sought: List[str] = Field(default_factory=list)
    target_or_entity: str
    priority: int = Field(default=50, ge=1, le=100)
    status: RequirementStatus = RequirementStatus.OPEN
    assigned_specialist_id: Optional[str] = None
    assigned_capability_id: Optional[str] = None
    requesting_component: str = "core.coordinator"
    dependencies: List[str] = Field(default_factory=list, description="IDs of requirements that must complete first")
    completion_criteria: Dict[str, Any] = Field(default_factory=dict)
    resulting_evidence_ids: List[str] = Field(default_factory=list)
    error: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_resolved(self) -> bool:
        return self.status in (RequirementStatus.SATISFIED, RequirementStatus.SATISFIED_EMPTY, RequirementStatus.FAILED)
