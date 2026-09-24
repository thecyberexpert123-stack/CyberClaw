"""Domain-neutral collaboration router with explainable multi-specialist candidate selection."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.collaboration.models import CollaborationRequest, RoutingDecision
from cyberclaw.specialists.endpoint import SpecialistHealth
from cyberclaw.specialists.registry import SpecialistRegistry

if TYPE_CHECKING:
    from cyberclaw.specialists.base import Specialist


class CollaborationRouter:
    """Deterministically routes collaboration requests based on capability, health, workload, and clearance contracts."""

    def __init__(
        self,
        specialist_registry: SpecialistRegistry,
        capability_registry: CapabilityRegistry,
    ) -> None:
        self.specialists = specialist_registry
        self.capabilities = capability_registry

    def route(
        self,
        request: CollaborationRequest,
    ) -> RoutingDecision:
        """Evaluate registered specialists and select the optimal authorized candidate for the collaboration request."""
        all_specialists = self.specialists.list_specialists()
        if not all_specialists:
            return RoutingDecision(
                request_id=request.request_id,
                rationale="No specialists registered in Core.",
                is_successful=False,
            )

        candidate_evaluations: List[Dict[str, Any]] = []

        # Target specialist explicitly specified by request
        if request.target_specialist:
            spec = self.specialists.get_specialist(request.target_specialist)
            if not spec:
                return RoutingDecision(
                    request_id=request.request_id,
                    rationale=f"Requested target specialist '{request.target_specialist}' not found.",
                    is_successful=False,
                )

            eval_record = self._evaluate_candidate(spec, request)
            candidate_evaluations.append(eval_record)

            if not eval_record["is_eligible"]:
                return RoutingDecision(
                    request_id=request.request_id,
                    candidate_evaluations=candidate_evaluations,
                    rationale=f"Specified specialist '{spec.id}' is ineligible: {eval_record['reasons']}",
                    is_successful=False,
                )

            selected_cap = eval_record["matched_capability"] or (request.required_capabilities[0] if request.required_capabilities else None)
            return RoutingDecision(
                request_id=request.request_id,
                selected_specialist_id=spec.id,
                selected_capability_id=selected_cap,
                candidate_evaluations=candidate_evaluations,
                rationale=f"Explicitly assigned specialist '{spec.id}' is eligible and ready.",
                is_successful=True,
            )

        # Dynamic routing across all eligible registered specialists
        eligible_candidates: List[Dict[str, Any]] = []
        for spec in all_specialists:
            eval_record = self._evaluate_candidate(spec, request)
            candidate_evaluations.append(eval_record)
            if eval_record["is_eligible"]:
                eligible_candidates.append(eval_record)

        if not eligible_candidates:
            reasons_summary = "; ".join(
                f"{c['specialist_id']}: {','.join(c['reasons'])}"
                for c in candidate_evaluations
            )
            return RoutingDecision(
                request_id=request.request_id,
                candidate_evaluations=candidate_evaluations,
                rationale=f"No eligible specialists found for request objective. Evaluations: {reasons_summary}",
                is_successful=False,
            )

        # Deterministic explainable selection:
        # Sort key: 1) has exact capability match, 2) available capacity descending, 3) stable alphabetical ID
        eligible_candidates.sort(
            key=lambda c: (
                1 if c["matched_capability"] else 0,
                c["available_capacity"],
                c["specialist_id"],
            ),
            reverse=True,
        )

        chosen = eligible_candidates[0]
        selected_cap = chosen["matched_capability"] or (request.required_capabilities[0] if request.required_capabilities else None)

        return RoutingDecision(
            request_id=request.request_id,
            selected_specialist_id=chosen["specialist_id"],
            selected_capability_id=selected_cap,
            candidate_evaluations=candidate_evaluations,
            rationale=(
                f"Selected '{chosen['specialist_id']}' with capability '{selected_cap}' "
                f"based on contract match and available capacity ({chosen['available_capacity']})."
            ),
            is_successful=True,
        )

    def _evaluate_candidate(
        self,
        specialist: Specialist,
        request: CollaborationRequest,
    ) -> Dict[str, Any]:
        """Perform granular contract evaluation for a single candidate specialist."""
        reasons: List[str] = []
        is_eligible = True
        matched_cap: Optional[str] = None

        # 1. Health check
        try:
            health = specialist.get_health()
            if health != SpecialistHealth.HEALTHY:
                is_eligible = False
                reasons.append(f"Specialist health is {health.value}")
        except Exception as e:
            is_eligible = False
            reasons.append(f"Health check failed: {e}")

        # 2. Capacity check
        capacity = getattr(specialist, "capacity", 10)
        active_workload = getattr(specialist, "active_workload", 0)
        available_capacity = max(0, capacity - active_workload)
        if available_capacity <= 0:
            is_eligible = False
            reasons.append(f"Workload at capacity ({active_workload}/{capacity})")

        # 3. Sensitivity clearance check
        clearance = getattr(specialist, "max_sensitivity_level", "SENSITIVE")
        if not request.sensitivity.is_accessible_by(clearance):
            is_eligible = False
            reasons.append(f"Clearance '{clearance}' below requested sensitivity '{request.sensitivity.value}'")

        # 4. Capability verification
        if request.required_capabilities:
            for cap_id in request.required_capabilities:
                if cap_id in specialist.capabilities:
                    matched_cap = cap_id
                    break
            if not matched_cap:
                is_eligible = False
                reasons.append(f"Lacks required capabilities: {request.required_capabilities}")
        elif specialist.capabilities:
            # First available capability that is active in registry
            matched_cap = specialist.capabilities[0]

        # 5. Permission prerequisite check
        if request.requested_permissions:
            missing_perms = [p for p in request.requested_permissions if p not in specialist.permissions]
            if missing_perms:
                is_eligible = False
                reasons.append(f"Missing permissions: {missing_perms}")

        return {
            "specialist_id": specialist.id,
            "is_eligible": is_eligible,
            "matched_capability": matched_cap,
            "available_capacity": available_capacity,
            "reasons": reasons,
        }
