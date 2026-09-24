"""Skill proposal model representing AI-suggested experimental improvements."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.specialists.self_development.skill import ExperimentalSkill


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SkillProposal(BaseModel):
    """A formal proposal for an experimental skill derived from observed patterns."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    originating_specialist: str
    source_pattern_ids: List[str] = Field(default_factory=list)
    source_experience_ids: List[str] = Field(default_factory=list)
    intended_objective: str
    proposed_procedure: Dict[str, Any]
    expected_benefit: str
    required_capabilities: List[str] = Field(default_factory=list)
    required_permissions: List[str] = Field(default_factory=list)
    known_risks: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    hypothesis: str
    proposed_evaluation_criteria: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    status: str = "PROPOSED"

    def to_experimental_skill(self, skill_id: str, version: str = "0.1.0-exp") -> ExperimentalSkill:
        """Instantiate an unvalidated ExperimentalSkill from this proposal."""
        return ExperimentalSkill(
            skill_id=skill_id,
            version=version,
            purpose=self.intended_objective,
            capabilities_required=self.required_capabilities,
            permissions_required=self.required_permissions,
            author_origin=self.originating_specialist,
            source_experiences=self.source_experience_ids,
            source_patterns=self.source_pattern_ids,
            hypothesis=self.hypothesis,
            procedure=self.proposed_procedure,
            metadata={
                "proposal_id": self.id,
                "expected_benefit": self.expected_benefit,
                "known_risks": self.known_risks,
            },
        )
