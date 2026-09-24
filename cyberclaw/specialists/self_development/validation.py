"""Multi-phase validation for experimental skills and proposals.

Enforces structural, safety, and architectural validity before any experimental
execution is permitted in the sandbox.
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field

from cyberclaw.specialists.self_development.proposals import SkillProposal
from cyberclaw.specialists.self_development.skill import ExperimentalSkill


class SkillValidationError(Exception):
    """Raised when an experimental skill fails validation checks."""

    def __init__(self, failure_type: str, reason: str) -> None:
        self.failure_type = failure_type
        self.reason = reason
        super().__init__(f"Skill validation failed [{failure_type}]: {reason}")


class SkillValidationResult(BaseModel):
    """Structured report of skill validation."""

    is_valid: bool
    structural_valid: bool
    safety_valid: bool
    architectural_valid: bool
    rejection_reasons: List[str] = Field(default_factory=list)


class SkillValidator:
    """Enforces validation checks on candidate experimental skills."""

    @classmethod
    def validate_proposal(
        cls,
        proposal: SkillProposal,
        specialist_permissions: List[str],
        known_capabilities: List[str],
    ) -> SkillValidationResult:
        """Validate a SkillProposal before converting it into an executable experimental artifact."""
        rejection_reasons: List[str] = []
        struct_valid = True
        safe_valid = True
        arch_valid = True

        # 1. Structural validity
        if not proposal.intended_objective:
            rejection_reasons.append("Missing intended_objective")
            struct_valid = False
        if not proposal.hypothesis:
            rejection_reasons.append("Missing hypothesis")
            struct_valid = False
        if not proposal.proposed_procedure:
            rejection_reasons.append("Missing proposed_procedure steps")
            struct_valid = False

        # Validate capabilities exist
        for cap in proposal.required_capabilities:
            if cap not in known_capabilities:
                rejection_reasons.append(f"Referenced unknown capability '{cap}'")
                struct_valid = False

        # 2. Safety validity: permissions must be subset of specialist's authority
        for perm in proposal.required_permissions:
            if perm not in specialist_permissions:
                rejection_reasons.append(
                    f"Requested permission '{perm}' exceeds specialist authority {specialist_permissions}"
                )
                safe_valid = False

        # Prohibit destructive scopes without human approval
        if "destructive" in str(proposal.proposed_procedure).lower():
            rejection_reasons.append("Cannot introduce unapproved destructive actions in experimental skill")
            safe_valid = False

        # 3. Architectural validity
        # Cannot mutate Core or permission policies
        restricted_targets = ["cyberclaw.core", "dfa.transition", "permission.policy", "eval(", "exec("]
        proc_str = str(proposal.proposed_procedure)
        for restricted in restricted_targets:
            if restricted in proc_str:
                rejection_reasons.append(f"Skill procedure illegally references architectural component '{restricted}'")
                arch_valid = False

        is_valid = struct_valid and safe_valid and arch_valid
        return SkillValidationResult(
            is_valid=is_valid,
            structural_valid=struct_valid,
            safety_valid=safe_valid,
            architectural_valid=arch_valid,
            rejection_reasons=rejection_reasons,
        )

    @classmethod
    def validate_skill(
        cls,
        skill: ExperimentalSkill,
        specialist_permissions: List[str],
        known_capabilities: List[str],
    ) -> SkillValidationResult:
        """Validate an instantiated ExperimentalSkill."""
        rejection_reasons: List[str] = []
        struct_valid = True
        safe_valid = True
        arch_valid = True

        if not skill.skill_id:
            rejection_reasons.append("Missing skill_id")
            struct_valid = False
        if not skill.purpose:
            rejection_reasons.append("Missing purpose")
            struct_valid = False

        # Self-promotion check: initial maturity cannot be TRUSTED or APPROVED
        if skill.maturity.value in ("TRUSTED", "APPROVED"):
            rejection_reasons.append(f"Candidate skill cannot initialize in '{skill.maturity.value}' state")
            arch_valid = False

        # Capabilities validation
        for cap in skill.capabilities_required:
            if cap not in known_capabilities:
                rejection_reasons.append(f"Referenced unknown capability '{cap}'")
                struct_valid = False

        # Permissions validation
        for perm in skill.permissions_required:
            if perm not in specialist_permissions:
                rejection_reasons.append(f"Permission '{perm}' exceeds specialist authority")
                safe_valid = False

        is_valid = struct_valid and safe_valid and arch_valid
        return SkillValidationResult(
            is_valid=is_valid,
            structural_valid=struct_valid,
            safety_valid=safe_valid,
            architectural_valid=arch_valid,
            rejection_reasons=rejection_reasons,
        )

    @classmethod
    def enforce_valid_skill(
        cls,
        skill: ExperimentalSkill,
        specialist_permissions: List[str],
        known_capabilities: List[str],
    ) -> None:
        res = cls.validate_skill(skill, specialist_permissions, known_capabilities)
        if not res.is_valid:
            raise SkillValidationError("VALIDATION_ERROR", "; ".join(res.rejection_reasons))
