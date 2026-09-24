"""Adaptive planning engine orchestrating planning cycles, validation, and controlled termination."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.coordination.coordinator import InvestigationCoordinator
from cyberclaw.coordination.requirements import (
    InformationRequirement,
    RequirementStatus,
)
from cyberclaw.investigation import Investigation
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.planning.models import (
    InvestigationPlan,
    PlanStatus,
    RequirementCandidate,
    StoppingCondition,
)
from cyberclaw.planning.planner import DeterministicPlanner
from cyberclaw.planning.validator import PlanValidationResult, PlanValidator
from cyberclaw.specialists.registry import SpecialistRegistry


class AdaptivePlanningEngine:
    """Coordinates deterministic investigation planning cycles and controlled loop progression."""

    def __init__(
        self,
        planner: Optional[DeterministicPlanner] = None,
        validator: Optional[PlanValidator] = None,
    ) -> None:
        self.planner = planner or DeterministicPlanner()
        self.validator = validator or PlanValidator()

    def plan_cycle(
        self,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        permissions: PermissionManager,
        actor: str = "core.system",
        max_candidates: int = 5,
        auto_convert_candidates: bool = True,
    ) -> Tuple[InvestigationPlan, PlanValidationResult]:
        """Generate, validate, and optionally convert candidates into executable requirements."""
        # 1. Generate Plan
        plan = self.planner.generate_plan(
            investigation=investigation,
            specialists=specialists,
            capabilities=capabilities,
            max_candidates=max_candidates,
        )

        # 2. Validate Plan
        val_res = self.validator.validate_plan(
            plan=plan,
            investigation=investigation,
            specialists=specialists,
            capabilities=capabilities,
            permissions=permissions,
            actor=actor,
        )

        # 3. Convert Valid Candidates to InformationRequirements
        if val_res.is_valid and auto_convert_candidates and plan.candidate_next_requirements:
            for cand in plan.candidate_next_requirements:
                req = InformationRequirement(
                    investigation_id=investigation.id,
                    description=cand.purpose,
                    evidence_types_sought=cand.requested_evidence_types,
                    target_or_entity=cand.target_or_entity,
                    assigned_capability_id=cand.required_capability,
                    priority=cand.priority,
                    dependencies=cand.dependencies,
                    metadata={
                        "candidate_id": cand.candidate_id,
                        "value_dimension": cand.value_dimension.value,
                        "uncertainty_type": cand.uncertainty_type.value,
                    },
                )
                investigation.information_requirements[req.id] = req

            plan.plan_status = PlanStatus.EXECUTED

        return plan, val_res

    def run_adaptive_loop(
        self,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        permissions: PermissionManager,
        coordinator: InvestigationCoordinator,
        max_cycles: int = 3,
        actor: str = "core.system",
    ) -> List[InvestigationPlan]:
        """Execute a controlled multi-cycle adaptive investigation loop until an explicit stopping condition."""
        executed_plans: List[InvestigationPlan] = []

        for cycle in range(1, max_cycles + 1):
            # Step A: Correlate current evidence
            coordinator.correlate(investigation)

            # Step B: Evaluate working hypotheses
            coordinator.evaluate_hypotheses(investigation)

            # Step C: Generate and validate next plan
            plan, val_res = self.plan_cycle(
                investigation=investigation,
                specialists=specialists,
                capabilities=capabilities,
                permissions=permissions,
                actor=actor,
                auto_convert_candidates=True,
            )
            executed_plans.append(plan)

            # Step D: Check for stopping condition
            if plan.stopping_condition:
                break

            # Step E: Fulfill newly converted open requirements
            open_reqs = [
                r for r in investigation.information_requirements.values()
                if r.status == RequirementStatus.OPEN
            ]

            if not open_reqs:
                plan.stopping_condition = StoppingCondition.NO_ACTIONABLE_INFORMATION_GAPS
                break

            for req in open_reqs:
                coordinator.fulfill_requirement(investigation, req.id)

            # Check if all cycles exhausted
            if cycle == max_cycles:
                plan.stopping_condition = StoppingCondition.MAX_CYCLES_REACHED

        # Final correlation & hypothesis review on terminal state
        coordinator.correlate(investigation)
        coordinator.evaluate_hypotheses(investigation)

        return executed_plans
