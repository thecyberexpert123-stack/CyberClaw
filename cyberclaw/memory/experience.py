"""Structured experience representation capturing what happened and what was learned.

Experience records operational outcomes, condition-cause-consequence lessons,
and supports revision when new evidence contradicts prior conclusions.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.evidence.result import ExecutionStatus


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExperienceRecord(BaseModel):
    """Structured experience object adhering to CyberClaw Core contract."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: Optional[str] = Field(default=None)
    action: str = Field(description="Action, capability, or transition executed")
    context: Dict[str, Any] = Field(
        default_factory=dict, description="Contextual parameters and operational state"
    )
    result_status: ExecutionStatus = Field(description="SUCCESS, SUCCESS_EMPTY, or FAILURE")
    evidence_ids: List[str] = Field(
        default_factory=list, description="IDs of evidence produced or referenced"
    )
    success: bool = Field(description="True if operation completed normally")
    failure_reason: Optional[str] = Field(
        default=None, description="Detailed diagnostic reason if failed"
    )
    lesson: str = Field(
        description="Actionable condition-cause rule learned from this experience"
    )
    conditions: Dict[str, Any] = Field(
        default_factory=dict, description="Operational conditions under which this lesson is valid"
    )
    scope: str = Field(
        default="global", description="Scope of applicability, e.g. 'capability.foo', 'specialist.bar'"
    )
    revision: int = Field(default=1, description="Revision counter")
    superseded_by: Optional[str] = Field(
        default=None, description="ID of newer experience record if revised"
    )
    revises_experience_id: Optional[str] = Field(
        default=None, description="ID of prior experience this record revises"
    )
    contradiction_evidence_ids: List[str] = Field(
        default_factory=list, description="IDs of new evidence that prompted this revision"
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        """True if this experience has not been superseded by a newer revision."""
        return self.superseded_by is None
