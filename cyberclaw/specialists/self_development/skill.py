"""Experimental Skill data model and metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.specialists.self_development.maturity import (
    ALLOWED_MATURITY_TRANSITIONS,
    InvalidMaturityTransitionError,
    SkillMaturityState,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ExperimentalSkill(BaseModel):
    """An experimental skill or workflow artifact created within a Specialist's workspace."""

    skill_id: str
    version: str = "0.1.0-exp"
    purpose: str
    inputs: Dict[str, Any] = Field(default_factory=dict)
    expected_outputs: Dict[str, Any] = Field(default_factory=dict)
    capabilities_required: List[str] = Field(default_factory=list)
    permissions_required: List[str] = Field(default_factory=list)
    author_origin: str = Field(description="Originating specialist ID")
    source_experiences: List[str] = Field(default_factory=list)
    source_patterns: List[str] = Field(default_factory=list)
    hypothesis: str = Field(description="Testable proposition about why this skill is advantageous")
    maturity: SkillMaturityState = SkillMaturityState.EXPERIMENTAL
    validation_status: str = "PENDING"
    procedure: Dict[str, Any] = Field(default_factory=dict, description="Structured execution procedure or steps")
    evaluation_id: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def transition_maturity(
        self,
        target_state: SkillMaturityState,
        reason: str = "",
    ) -> SkillMaturityState:
        """Deterministic transition enforcing the maturity model."""
        allowed = ALLOWED_MATURITY_TRANSITIONS.get(self.maturity, set())
        if target_state not in allowed:
            raise InvalidMaturityTransitionError(
                current_state=self.maturity,
                target_state=target_state,
                reason=reason or f"Transition from {self.maturity.value} to {target_state.value} is not in maturity table.",
            )
        self.maturity = target_state
        self.updated_at = utc_now()
        return self.maturity

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()
