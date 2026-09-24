"""Bridge integrating Capability lifecycle with Self-Development and Adaptive Planning."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import CapabilityGovernanceError
from cyberclaw.capabilities.models import (
    CapabilityCandidate,
    CapabilityLifecycleState,
    CapabilityProvenance,
    CapabilityTrustState,
    CapabilityValidationRecord,
)
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import CapabilityGap
from cyberclaw.specialists.self_development.evaluation import SkillEvaluation
from cyberclaw.specialists.self_development.maturity import SkillMaturityState
from cyberclaw.specialists.self_development.skill import ExperimentalSkill


class CapabilityBridge:
    """Safely mediates capability proposals between experimental skills, gaps, and formal registration."""

    @classmethod
    def candidate_from_gap(
        cls,
        gap: CapabilityGap,
        proposed_capability_id: str,
        name: str,
        description: str,
        category: str = "general",
        action_scope: ActionScope = ActionScope.REVERSIBLE,
        required_permissions: Optional[List[str]] = None,
    ) -> CapabilityCandidate:
        """Formulate a CapabilityCandidate from an unresolved planning CapabilityGap."""
        return CapabilityCandidate(
            capability_id=proposed_capability_id,
            name=name,
            version="0.1.0",
            description=description,
            category=category,
            originating_gap_id=gap.gap_id,
            provenance=CapabilityProvenance.CORE_REGISTERED,
            action_scope=action_scope,
            required_permissions=required_permissions or [],
            rationale=f"Generated in response to intelligence gap for '{gap.target_or_entity}' ({gap.desired_evidence_type}): {gap.reason}",
        )

    @classmethod
    def candidate_from_experimental_skill(
        cls,
        skill: ExperimentalSkill,
        evaluation: SkillEvaluation,
        proposed_capability_id: Optional[str] = None,
    ) -> CapabilityCandidate:
        """Convert a thoroughly evaluated ExperimentalSkill into a formal CapabilityCandidate.

        Crucially: does NOT register or trust the capability. It creates a candidate for governance review.
        """
        # Enforce that skill must be in EVALUATED maturity state and have PROPOSE_PROMOTION
        if skill.maturity != SkillMaturityState.EVALUATED:
            raise CapabilityGovernanceError(
                f"Skill '{skill.skill_id}' must be in EVALUATED maturity state, currently '{skill.maturity.value}'."
            )

        if evaluation.recommendation != "PROPOSE_PROMOTION":
            raise CapabilityGovernanceError(
                f"Cannot create capability candidate with evaluation recommendation '{evaluation.recommendation}'."
            )

        cap_id = proposed_capability_id or f"capability.skill.{skill.skill_id}"
        return CapabilityCandidate(
            capability_id=cap_id,
            name=skill.purpose,
            version=skill.version,
            description=skill.hypothesis,
            specialist_id=skill.author_origin,
            originating_skill_id=skill.skill_id,
            provenance=CapabilityProvenance.PROMOTED_SKILL,
            input_schema=skill.inputs,
            output_schema=skill.expected_outputs,
            required_permissions=skill.permissions_required,
            action_scope=ActionScope.CONSEQUENTIAL,
            rationale=f"Derived from experimental skill '{skill.skill_id}' (v{skill.version}) following successful evaluation {evaluation.id}.",
            metadata={
                "evaluation_id": evaluation.id,
                "differences": evaluation.differences,
            },
        )

    @classmethod
    def realize_candidate(
        cls,
        candidate: CapabilityCandidate,
        initial_state: CapabilityLifecycleState = CapabilityLifecycleState.PROPOSED,
        initial_trust: CapabilityTrustState = CapabilityTrustState.UNTRUSTED,
    ) -> Capability:
        """Materialize a candidate into a formal Capability instance in PROPOSED state."""
        return Capability(
            id=candidate.capability_id,
            name=candidate.name,
            version=candidate.version,
            description=candidate.description,
            category=candidate.category,
            specialist_id=candidate.specialist_id,
            input_schema=candidate.input_schema,
            output_schema=candidate.output_schema,
            required_permissions=candidate.required_permissions,
            action_scope=candidate.action_scope,
            lifecycle_state=initial_state,
            trust_state=initial_trust,
            provenance=candidate.provenance,
            metadata=dict(candidate.metadata),
        )
