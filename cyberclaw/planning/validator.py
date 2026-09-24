"""Deterministic validation for InvestigationPlans and RequirementCandidates."""

from __future__ import annotations

from typing import List, Optional, Set
from pydantic import BaseModel, Field

from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.investigation import Investigation
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import (
    InvestigationPlan,
    PlanStatus,
    RequirementCandidate,
)
from cyberclaw.specialists.registry import SpecialistRegistry


class PlanValidationResult(BaseModel):
    """Detailed validation outcome report for an InvestigationPlan."""

    is_valid: bool
    structural_valid: bool
    capability_valid: bool
    permission_valid: bool
    safety_valid: bool
    rejection_reasons: List[str] = Field(default_factory=list)


class PlanValidator:
    """Enforces multi-phase validation on generated plans before execution."""

    @classmethod
    def validate_candidate(
        cls,
        candidate: RequirementCandidate,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        permissions: PermissionManager,
        actor: str = "core.system",
    ) -> PlanValidationResult:
        rejection_reasons: List[str] = []
        struct_valid = True
        cap_valid = True
        perm_valid = True
        safe_valid = True

        # 1. Structural Validation
        if not candidate.target_or_entity:
            rejection_reasons.append("Missing target_or_entity in candidate")
            struct_valid = False

        if not candidate.requested_evidence_types and not candidate.required_capability:
            rejection_reasons.append("Candidate must specify either requested_evidence_types or required_capability")
            struct_valid = False

        # Validate supporting evidence references exist
        for eid in candidate.supporting_evidence_ids:
            if not investigation.evidence_store.get(eid):
                rejection_reasons.append(f"Referenced supporting evidence '{eid}' does not exist in investigation")
                struct_valid = False

        # Validate supporting hypothesis references exist
        for hid in candidate.supporting_hypothesis_ids:
            if hid not in investigation.hypotheses:
                rejection_reasons.append(f"Referenced supporting hypothesis '{hid}' does not exist in investigation")
                struct_valid = False

        # 2. Capability Validation
        # Check if an eligible capability / specialist exists
        all_specialist_caps: Set[str] = set()
        for spec in specialists.list_specialists():
            all_specialist_caps.update(spec.capabilities)

        if candidate.required_capability:
            if candidate.required_capability not in all_specialist_caps and not capabilities.get_capability(candidate.required_capability):
                rejection_reasons.append(f"Requested capability '{candidate.required_capability}' has no registered provider or specialist")
                cap_valid = False

        # 3. Permission Validation
        if candidate.risk_classification == ActionScope.DESTRUCTIVE:
            # Destructive candidates require explicit human authorization
            allowed, reason = permissions.check_permission(actor, "execute_destructive", scope=ActionScope.DESTRUCTIVE)
            if not allowed:
                rejection_reasons.append(f"Candidate requires DESTRUCTIVE authorization: {reason}")
                perm_valid = False

        for perm in candidate.permission_requirements:
            allowed, reason = permissions.check_permission(actor, f"execute:{perm}", required_permission=perm)
            if not allowed:
                rejection_reasons.append(f"Actor '{actor}' lacks required permission '{perm}'")
                perm_valid = False

        # 4. Safety & Evasion Validation
        restricted_patterns = ["eval(", "exec(", "system(", "__import__", "rm -rf", "drop table"]
        cand_str = f"{candidate.purpose} {candidate.expected_information_value} {candidate.target_or_entity}".lower()
        for p in restricted_patterns:
            if p in cand_str:
                rejection_reasons.append(f"Candidate contains forbidden command pattern '{p}'")
                safe_valid = False

        is_valid = struct_valid and cap_valid and perm_valid and safe_valid
        return PlanValidationResult(
            is_valid=is_valid,
            structural_valid=struct_valid,
            capability_valid=cap_valid,
            permission_valid=perm_valid,
            safety_valid=safe_valid,
            rejection_reasons=rejection_reasons,
        )

    @classmethod
    def validate_plan(
        cls,
        plan: InvestigationPlan,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        permissions: PermissionManager,
        actor: str = "core.system",
    ) -> PlanValidationResult:
        """Validate all candidates in an InvestigationPlan."""
        all_rejections: List[str] = []
        is_all_valid = True

        for candidate in plan.candidate_next_requirements:
            res = cls.validate_candidate(candidate, investigation, specialists, capabilities, permissions, actor)
            if not res.is_valid:
                is_all_valid = False
                all_rejections.extend(res.rejection_reasons)

        if is_all_valid:
            plan.plan_status = PlanStatus.VALIDATED
        else:
            plan.plan_status = PlanStatus.REJECTED

        return PlanValidationResult(
            is_valid=is_all_valid,
            structural_valid=is_all_valid,
            capability_valid=is_all_valid,
            permission_valid=is_all_valid,
            safety_valid=is_all_valid,
            rejection_reasons=all_rejections,
        )
