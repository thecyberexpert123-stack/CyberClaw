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
        policy_engine: Optional[Any] = None,
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
            policy_engine=policy_engine,
        )

        # 3. Convert Valid Candidates to InformationRequirements
        if val_res.is_valid and auto_convert_candidates and plan.candidate_next_requirements:
            for cand in plan.candidate_next_requirements:
                req = investigation.create_information_requirement(
                    description=cand.purpose,
                    evidence_types_sought=cand.requested_evidence_types,
                    target_or_entity=cand.target_or_entity,
                    assigned_capability_id=cand.required_capability,
                    priority=cand.priority,
                    dependencies=cand.dependencies,
                )
                req.metadata = {
                    "candidate_id": cand.candidate_id,
                    "value_dimension": cand.value_dimension.value,
                    "uncertainty_type": cand.uncertainty_type.value,
                }

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
        policy_engine: Optional[Any] = None,
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
                policy_engine=policy_engine,
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

    def request_strategy_candidates(
        self,
        investigation: Investigation,
        learning_registry: Any,
        knowledge_gaps: Optional[List[Any]] = None,
        available_capabilities: Optional[List[str]] = None,
        available_specialists: Optional[List[str]] = None,
        actor_permissions: Optional[List[str]] = None,
        policy_engine: Optional[Any] = None,
        actor: str = "core.planner",
        actor_role: str = "lead_investigator",
    ) -> Any:
        """Ask the learning registry for applicable strategy candidates.

        The planner remains the decision maker. Candidates are structured data
        and are never executed by this method.
        """
        from cyberclaw.learning.applicability import ApplicabilityEngine
        from cyberclaw.learning.governance import StrategyGovernance
        from cyberclaw.learning.models import InvestigationContext, StrategyLifecycle

        gaps = knowledge_gaps or []
        gap_types = []
        for gap in gaps:
            value = getattr(gap, "uncertainty_type", None) or (gap.get("uncertainty_type") if isinstance(gap, dict) else None)
            if value:
                gap_types.append(str(value))
        open_reqs = [
            req for req in investigation.information_requirements.values()
            if not req.is_resolved
        ]
        for req in open_reqs:
            gap_types.extend(req.evidence_types_sought)
            if req.metadata.get("uncertainty_type"):
                gap_types.append(str(req.metadata["uncertainty_type"]))
        context = InvestigationContext(
            investigation_id=investigation.id,
            objective=" ".join(part for part in (investigation.title, investigation.description) if part),
            case_stage=investigation.current_state.value,
            information_gap_structure=sorted(set(gap_types)),
            uncertainty_characteristics=sorted(set(gap_types)),
            evidence_characteristics=sorted({ev.type for ev in investigation.evidence_store.list_all()}),
            available_capabilities=sorted(set(available_capabilities or [])),
            available_specialists=sorted(set(available_specialists or investigation.participating_specialists)),
            actor_permissions=sorted(set(actor_permissions or [])),
        )
        strategies = learning_registry.list_strategies(StrategyLifecycle.AVAILABLE)
        precheck: Dict[str, str] = {}
        decision_ids: Dict[str, List[str]] = {}
        if policy_engine is not None:
            for strategy in strategies:
                result = StrategyGovernance.precheck(
                    strategy,
                    policy_engine,
                    investigation_id=investigation.id,
                    actor=actor,
                    actor_role=actor_role,
                    case_stage=investigation.current_state.value,
                )
                precheck[strategy.strategy_id] = result.decision
                decision_ids[strategy.strategy_id] = result.decision_ids
        support = {}
        for strategy in strategies:
            try:
                pattern = learning_registry.get_pattern(strategy.created_from_pattern_id, strategy.created_from_pattern_version)
                support[strategy.created_from_pattern_id] = {
                    "independent_case_count": pattern.independent_case_count,
                }
            except Exception:
                continue
        return ApplicabilityEngine.query_candidates(
            strategies,
            context,
            learning_registry.threshold_policy,
            pattern_support=support,
            policy_precheck=precheck,
            policy_decision_ids=decision_ids,
        )
