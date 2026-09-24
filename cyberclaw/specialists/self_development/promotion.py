"""Promotion management and authorization boundaries for experimental skills.

Enforces:
1. AI proposes promotion.
2. Validation verifies.
3. Policy / human decides.
4. Hard boundary: Experimental cannot promote itself directly to Trusted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.permissions.policy import ActionScope
from cyberclaw.specialists.self_development.evaluation import SkillEvaluation
from cyberclaw.specialists.self_development.maturity import (
    InvalidMaturityTransitionError,
    SkillMaturityState,
)
from cyberclaw.specialists.self_development.skill import ExperimentalSkill


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class UnauthorizedPromotionError(Exception):
    """Raised when an attempt is made to bypass approval or self-promote."""

    def __init__(self, message: str) -> None:
        super().__init__(f"Unauthorized promotion: {message}")


class PromotionProposal(BaseModel):
    """A formal request to transition an experimental skill to production/trusted status."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    skill_id: str
    version: str
    evaluation_id: str
    supporting_experiments: List[str] = Field(default_factory=list)
    supporting_experiences: List[str] = Field(default_factory=list)
    requested_maturity: SkillMaturityState = SkillMaturityState.APPROVED
    required_approval_scope: ActionScope = ActionScope.CONSEQUENTIAL
    rationale: str
    risks: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    submitted_at: datetime = Field(default_factory=utc_now)


class ApprovalDecision(BaseModel):
    """Explicit human or policy authorization record approving or rejecting promotion."""

    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    proposal_id: str
    approver: str
    approved: bool
    reason: str
    decision_timestamp: datetime = Field(default_factory=utc_now)


class PromotionManager:
    """Governs the transition boundary between experimental and trusted skills."""

    def __init__(self) -> None:
        self._proposals: Dict[str, PromotionProposal] = {}
        self._decisions: Dict[str, ApprovalDecision] = {}
        self._trusted_skills: Dict[str, ExperimentalSkill] = {}

    def submit_proposal(
        self,
        skill: ExperimentalSkill,
        evaluation: SkillEvaluation,
        rationale: str,
        risks: Optional[List[str]] = None,
    ) -> PromotionProposal:
        """Specialist requests promotion based on evaluation evidence."""
        if skill.maturity != SkillMaturityState.EVALUATED:
            raise UnauthorizedPromotionError(
                f"Skill must be in 'EVALUATED' state to propose promotion, currently '{skill.maturity.value}'."
            )

        if evaluation.recommendation != "PROPOSE_PROMOTION":
            raise UnauthorizedPromotionError(
                f"Cannot propose promotion with evaluation recommendation '{evaluation.recommendation}'."
            )

        proposal = PromotionProposal(
            skill_id=skill.skill_id,
            version=skill.version,
            evaluation_id=evaluation.id,
            supporting_experiments=[evaluation.experiment_id],
            rationale=rationale,
            risks=risks or evaluation.limitations,
            limitations=evaluation.limitations,
        )

        # Transition skill maturity from EVALUATED -> PROPOSED
        skill.transition_maturity(SkillMaturityState.PROPOSED, reason="Submitted promotion proposal")
        self._proposals[proposal.id] = proposal
        return proposal

    def review_proposal(
        self,
        proposal_id: str,
        skill: ExperimentalSkill,
        approver: str,
        approved: bool,
        reason: str,
    ) -> ApprovalDecision:
        """Policy or human authority approves or rejects a proposal."""
        proposal = self._proposals.get(proposal_id)
        if not proposal:
            raise KeyError(f"Proposal '{proposal_id}' not found.")

        # Self-approval check: originating specialist cannot approve its own proposal
        if approver == skill.author_origin:
            raise UnauthorizedPromotionError(
                f"Specialist '{skill.author_origin}' cannot self-approve its own promotion proposal."
            )

        decision = ApprovalDecision(
            proposal_id=proposal_id,
            approver=approver,
            approved=approved,
            reason=reason,
        )
        self._decisions[decision.decision_id] = decision

        if approved:
            # Transition skill maturity from PROPOSED -> APPROVED
            skill.transition_maturity(SkillMaturityState.APPROVED, reason=f"Approved by {approver}: {reason}")
        else:
            skill.transition_maturity(SkillMaturityState.REJECTED, reason=f"Rejected by {approver}: {reason}")

        return decision

    def deploy_to_trusted(
        self,
        skill: ExperimentalSkill,
        approval_decision: ApprovalDecision,
    ) -> ExperimentalSkill:
        """Deploy an approved skill into the trusted catalog."""
        if not approval_decision.approved:
            raise UnauthorizedPromotionError("Cannot deploy a rejected skill.")

        if skill.maturity != SkillMaturityState.APPROVED:
            raise UnauthorizedPromotionError(
                f"Skill must be in 'APPROVED' maturity before deployment to TRUSTED, currently '{skill.maturity.value}'."
            )

        # Transition skill maturity from APPROVED -> TRUSTED
        skill.transition_maturity(SkillMaturityState.TRUSTED, reason=f"Deployed under approval {approval_decision.decision_id}")
        self._trusted_skills[skill.skill_id] = skill
        return skill

    def get_trusted_skill(self, skill_id: str) -> Optional[ExperimentalSkill]:
        return self._trusted_skills.get(skill_id)

    def list_trusted_skills(self) -> List[ExperimentalSkill]:
        return list(self._trusted_skills.values())
