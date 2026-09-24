"""Deterministic Planner for CyberClaw investigations."""

from __future__ import annotations

from typing import Dict, List, Optional, Set
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.coordination.requirements import RequirementStatus
from cyberclaw.investigation import Investigation
from cyberclaw.planning.models import (
    CapabilityGap,
    InvestigationPlan,
    PlanStatus,
    RequirementCandidate,
    StoppingCondition,
)
from cyberclaw.planning.rules import (
    ContradictionResolutionPlanningRule,
    EntityEnrichmentPlanningRule,
    HypothesisTestingPlanningRule,
    PlanningRule,
)
from cyberclaw.specialists.registry import SpecialistRegistry


class DeterministicPlanner:
    """Evaluates investigation state to propose structured, prioritized next information needs."""

    def __init__(self, custom_rules: Optional[List[PlanningRule]] = None) -> None:
        self.rules = custom_rules or [
            EntityEnrichmentPlanningRule(),
            ContradictionResolutionPlanningRule(),
            HypothesisTestingPlanningRule(),
        ]

    def generate_plan(
        self,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        max_candidates: int = 5,
    ) -> InvestigationPlan:
        """Analyze current investigation state and formulate an InvestigationPlan."""
        # 1. Compute set of satisfied / in-flight keys to prevent duplication
        satisfied_keys: Set[str] = set()
        for req in investigation.information_requirements.values():
            key_base = f"{investigation.id}:{req.target_or_entity}:{','.join(sorted(req.evidence_types_sought))}:{req.assigned_capability_id or ''}"
            satisfied_keys.add(key_base)
            # Generic target key
            satisfied_keys.add(f"{investigation.id}:{req.target_or_entity}:{req.assigned_capability_id or ''}")

        # 2. Run planning rules
        all_candidates: List[RequirementCandidate] = []
        all_gaps: List[CapabilityGap] = []
        seen_cand_keys: Set[str] = set()

        for rule in self.rules:
            cands, gaps = rule.evaluate(investigation, specialists, capabilities, satisfied_keys)

            for cand in cands:
                key = cand.deduplication_key(investigation.id)
                if key not in seen_cand_keys and key not in satisfied_keys:
                    seen_cand_keys.add(key)
                    all_candidates.append(cand)

            for gap in gaps:
                if not any(g.desired_evidence_type == gap.desired_evidence_type and g.target_or_entity == gap.target_or_entity for g in all_gaps):
                    all_gaps.append(gap)

        # Sort candidates by priority (ascending: 1 is highest priority)
        all_candidates.sort(key=lambda c: c.priority)
        selected_candidates = all_candidates[:max_candidates]

        # 3. Determine Stopping Condition if applicable
        stopping_condition: Optional[StoppingCondition] = None

        if not selected_candidates:
            if all_gaps:
                stopping_condition = StoppingCondition.NO_AUTHORIZED_CAPABILITIES
            else:
                # Check if hypotheses are settled
                open_hyps = [h for h in investigation.hypotheses.values() if h.status == "OPEN"]
                if not open_hyps and investigation.evidence_store.count() > 0:
                    stopping_condition = StoppingCondition.OBJECTIVE_SATISFIED
                else:
                    stopping_condition = StoppingCondition.NO_ACTIONABLE_INFORMATION_GAPS

        # Build plan artifact
        plan = InvestigationPlan(
            investigation_id=investigation.id,
            current_investigation_state=investigation.current_state.value,
            observed_evidence_references=[e.id for e in investigation.evidence_store.list_all()],
            current_hypotheses=[h.id for h in investigation.hypotheses.values()],
            unresolved_contradictions=[c.id for c in investigation.contradictions if not c.resolved],
            open_information_requirements=[r.id for r in investigation.information_requirements.values() if not r.is_resolved],
            candidate_next_requirements=selected_candidates,
            capability_gaps=all_gaps,
            reasoning_basis=f"Evaluated {len(investigation.entities)} entities, {len(investigation.hypotheses)} hypotheses, {len(investigation.contradictions)} contradictions across {len(self.rules)} deterministic planning rules.",
            plan_status=PlanStatus.GENERATED,
            stopping_condition=stopping_condition,
        )

        return plan
