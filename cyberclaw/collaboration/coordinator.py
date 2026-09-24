"""Central Multi-Specialist Collaboration Coordinator orchestrating governed requests, runtime execution, and consensus."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set
from uuid import uuid4

from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.case.models import JournalEntryType
from cyberclaw.collaboration.conflicts import ConflictDetector, ConflictManager
from cyberclaw.collaboration.consensus import ConsensusEngine
from cyberclaw.collaboration.dependencies import CollaborationDependencyGraph
from cyberclaw.collaboration.errors import (
    CollaborationAuthorizationError,
    CollaborationError,
    CollaborationTimeoutError,
    CollaborationValidationError,
    DependencyUnresolvedError,
    SpecialistUnavailableError,
)
from cyberclaw.collaboration.evidence import EvidenceHandoffNormalizer
from cyberclaw.collaboration.models import (
    CollaborationContext,
    CollaborationRequest,
    CollaborationResult,
    CollaborationStatus,
    ContextSensitivity,
    DependencyType,
    FindingNature,
    SpecialistConflict,
    utc_now,
)
from cyberclaw.collaboration.protocol import CollaborationLifecycleDFA, ContextFilter
from cyberclaw.collaboration.routing import CollaborationRouter
from cyberclaw.evidence.models import Evidence
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.policy.models import ActorRole, PolicyExecutionContext
from cyberclaw.runtime.errors import BranchExecutionBlockedError
from cyberclaw.runtime.events import EventFactory, RuntimeEventType
from cyberclaw.runtime.idempotency import compute_task_idempotency_key
from cyberclaw.runtime.models import RuntimeTask, TaskPriority
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.specialists.registry import SpecialistRegistry

if TYPE_CHECKING:
    from cyberclaw.investigation import Investigation


class CollaborationCoordinator:
    """Coordinates structured collaboration between independent Specialist Brains without compromising Core authority."""

    def __init__(
        self,
        specialist_registry: SpecialistRegistry,
        capability_registry: CapabilityRegistry,
        policy_engine: PolicyEngine,
        runtime_queue: DurableTaskQueue,
    ) -> None:
        self.specialists = specialist_registry
        self.capabilities = capability_registry
        self.policy_engine = policy_engine
        self.runtime_queue = runtime_queue

        self.router = CollaborationRouter(specialist_registry, capability_registry)
        self.dependency_graph = CollaborationDependencyGraph()
        self.conflict_manager = ConflictManager()
        self.consensus_engine = ConsensusEngine()

        self._requests: Dict[str, CollaborationRequest] = {}
        self._resolved_ids: Set[str] = set()

    def _journal(
        self,
        investigation: Any,
        entry_type: Any,
        summary: str,
        reference_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Append to CaseJournal if authoritative case manager exists."""
        if hasattr(investigation, "case_manager") and investigation.case_manager is not None:
            investigation.case_manager.journal.append_entry(
                entry_type=entry_type,
                summary=summary,
                reference_id=reference_id,
                details=details,
            )

    # --------------------------------------------------------------------------
    # Request Lifecycle Operations
    # --------------------------------------------------------------------------

    def request_collaboration(
        self,
        investigation: Investigation,
        requesting_specialist: str,
        objective: str,
        target_specialist: Optional[str] = None,
        information_requirement_id: Optional[str] = None,
        input_evidence_ids: Optional[List[str]] = None,
        input_entity_ids: Optional[List[str]] = None,
        hypothesis_ids: Optional[List[str]] = None,
        required_capabilities: Optional[List[str]] = None,
        requested_permissions: Optional[List[str]] = None,
        priority: int = 50,
        sensitivity: ContextSensitivity = ContextSensitivity.INTERNAL,
        action_scope: str = "reversible",
        deadline: Optional[Any] = None,
        timeout_seconds: Optional[float] = None,
        dependencies: Optional[List[str]] = None,
        is_counterfactual: bool = False,
    ) -> CollaborationRequest:
        """Create and register a structured collaboration request in PROPOSED state."""
        request = CollaborationRequest(
            investigation_id=investigation.id,
            requesting_specialist=requesting_specialist,
            target_specialist=target_specialist,
            objective=objective,
            information_requirement_id=information_requirement_id,
            input_evidence_ids=input_evidence_ids or [],
            input_entity_ids=input_entity_ids or [],
            hypothesis_ids=hypothesis_ids or [],
            required_capabilities=required_capabilities or [],
            requested_permissions=requested_permissions or [],
            priority=priority,
            sensitivity=sensitivity,
            action_scope=action_scope,
            deadline=deadline,
            timeout_seconds=timeout_seconds,
            is_counterfactual=is_counterfactual or getattr(investigation, "is_branch", False),
        )

        self._requests[request.request_id] = request

        # Register dependencies if provided
        if dependencies:
            for dep_id in dependencies:
                self.dependency_graph.add_dependency(
                    source_id=request.request_id,
                    target_id=dep_id,
                    dependency_type=DependencyType.HARD,
                )

        # Record in Case Journal
        self._journal(
            investigation=investigation,
            entry_type=JournalEntryType.COLLABORATION_REQUESTED,
            summary=f"Specialist '{requesting_specialist}' requested collaboration: {objective}",
            reference_id=request.request_id,
            details={
                "request_id": request.request_id,
                "requesting_specialist": requesting_specialist,
                "target_specialist": target_specialist,
                "objective": objective,
                "requirement_id": information_requirement_id,
                "sensitivity": sensitivity.value,
            },
        )

        return request

    def validate_and_route(
        self,
        request_id: str,
        investigation: Investigation,
        permission_manager: PermissionManager,
    ) -> CollaborationRequest:
        """Advance request through validation, dependency gating, routing, and PolicyEngine authorization."""
        request = self._get_request(request_id)
        CollaborationLifecycleDFA.transition(request, CollaborationStatus.VALIDATING)

        # 1. Dependency check
        can_exec, missing_hard, missing_soft = self.dependency_graph.check_dependencies(
            request.request_id, self._resolved_ids
        )
        if not can_exec:
            CollaborationLifecycleDFA.transition(
                request, CollaborationStatus.BLOCKED, reason=f"Blocked by dependencies: {missing_hard}"
            )
            raise DependencyUnresolvedError(
                f"Collaboration request '{request_id}' blocked by unfulfilled hard dependencies: {missing_hard}",
                request_id=request.request_id,
                investigation_id=request.investigation_id,
            )

        # 2. Capability Resolution & Candidate Matching
        cap_id = request.required_capabilities[0] if request.required_capabilities else None
        if not cap_id and request.target_specialist:
            spec = self.specialists.get_specialist(request.target_specialist)
            if spec and spec.capabilities:
                cap_id = spec.capabilities[0]

        if not cap_id:
            # Let router evaluate
            routing = self.router.route(request)
            if not routing.is_successful:
                CollaborationLifecycleDFA.transition(request, CollaborationStatus.FAILED, reason=routing.rationale)
                raise SpecialistUnavailableError(
                    f"Failed to route collaboration request: {routing.rationale}",
                    request_id=request.request_id,
                    investigation_id=request.investigation_id,
                )
            cap_id = routing.selected_capability_id
            request.target_specialist = routing.selected_specialist_id

        capability = self.capabilities.get_capability(cap_id)
        if not capability:
            from cyberclaw.capabilities.capability import Capability
            capability = Capability(id=cap_id, name=cap_id)
            self.capabilities.register_capability(capability)

        executable, unexec_reason = capability.is_executable()
        if not executable:
            CollaborationLifecycleDFA.transition(request, CollaborationStatus.REJECTED, reason=unexec_reason)
            raise CollaborationValidationError(
                f"Resolved capability '{cap_id}' is not executable: {unexec_reason}",
                request_id=request.request_id,
            )

        # 3. Contextual Policy Authorization
        try:
            scope_enum = ActionScope(request.action_scope)
        except ValueError:
            scope_enum = ActionScope.REVERSIBLE

        policy_ctx = PolicyExecutionContext(
            investigation_id=request.investigation_id,
            case_stage=investigation.current_state.value,
            actor_id=request.requesting_specialist,
            actor_role=ActorRole.SPECIALIST.value,
            capability_id=capability.id,
            capability_version=capability.version,
            action_type="collaboration_execute",
            action_scope=scope_enum.value,
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
            parameters=request.metadata.get("parameters", {}),
            is_branch=request.is_counterfactual,
        )

        auth_decision = self.policy_engine.authorize(policy_ctx)
        request.authorization_decision_id = auth_decision.decision_id
        if hasattr(investigation, "case_manager") and investigation.case_manager is not None:
            self.policy_engine.record_in_journal(auth_decision, investigation.case_manager)

        if not auth_decision.is_authorized:
            if auth_decision.decision.value in ("REQUIRE_APPROVAL", "REQUIRE_SUPERVISION"):
                CollaborationLifecycleDFA.transition(
                    request, CollaborationStatus.DEFERRED, reason=f"Awaiting authorization approval ({auth_decision.decision.value})"
                )
                return request
            else:
                reason_str = "; ".join(auth_decision.reasons)
                CollaborationLifecycleDFA.transition(request, CollaborationStatus.REJECTED, reason=reason_str)
                raise CollaborationAuthorizationError(
                    f"Policy denied collaboration request: {reason_str}",
                    request_id=request.request_id,
                    investigation_id=request.investigation_id,
                )

        # Authorized transition
        CollaborationLifecycleDFA.transition(request, CollaborationStatus.AUTHORIZED)

        # 4. Routing selection & assignment
        routing = self.router.route(request)
        if not routing.is_successful:
            CollaborationLifecycleDFA.transition(request, CollaborationStatus.FAILED, reason=routing.rationale)
            raise SpecialistUnavailableError(
                f"Failed to route collaboration request: {routing.rationale}",
                request_id=request.request_id,
                investigation_id=request.investigation_id,
            )

        request.target_specialist = routing.selected_specialist_id
        selected_capability_id = routing.selected_capability_id or cap_id
        CollaborationLifecycleDFA.transition(request, CollaborationStatus.ROUTED)

        self._journal(
            investigation=investigation,
            entry_type=JournalEntryType.COLLABORATION_AUTHORIZED,
            summary=f"Collaboration authorized for '{request.target_specialist}' using '{selected_capability_id}'",
            reference_id=request.request_id,
            details={
                "request_id": request.request_id,
                "target_specialist": request.target_specialist,
                "capability_id": selected_capability_id,
                "authorization_decision_id": auth_decision.decision_id,
            },
        )

        request.metadata["selected_capability_id"] = selected_capability_id
        return request

    def accept_and_enqueue(
        self,
        request_id: str,
        investigation: Investigation,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> RuntimeTask:
        """Accept authorized request, assemble least-privilege context, and enqueue as a durable RuntimeTask."""
        request = self._get_request(request_id)

        target_specialist = self.specialists.get_specialist(request.target_specialist)
        if not target_specialist:
            raise SpecialistUnavailableError(f"Target specialist '{request.target_specialist}' not available.")

        # Check soft dependency uncertainty
        _, _, missing_soft = self.dependency_graph.check_dependencies(request.request_id, self._resolved_ids)
        has_soft_uncertainty = len(missing_soft) > 0

        # Construct filtered least-privilege context
        request_params = dict(parameters or {})
        request.metadata["parameters"] = request_params

        filtered_context = ContextFilter.filter_context(
            request=request,
            investigation=investigation,
            target_specialist=target_specialist,
            has_soft_uncertainty=has_soft_uncertainty,
            uncertainty_reasons=[f"Missing soft dependencies: {missing_soft}"] if has_soft_uncertainty else [],
        )

        CollaborationLifecycleDFA.transition(request, CollaborationStatus.ACCEPTED)

        # Bridge into durable RuntimeTask
        cap_id = request.metadata.get("selected_capability_id") or (request.required_capabilities[0] if request.required_capabilities else "tool.probe")
        cap = self.capabilities.get_capability(cap_id)
        cap_version = cap.version if cap else "1.0.0"

        task_params = {
            "target": request.objective,
            "collaboration_request_id": request.request_id,
            "collaboration_context": filtered_context.model_dump(),
            **request_params,
        }

        idemp_key = compute_task_idempotency_key(
            investigation_id=request.investigation_id,
            capability_id=cap_id,
            capability_version=cap_version,
            requirement_id=request.information_requirement_id,
            parameters=task_params,
        )

        runtime_task = RuntimeTask(
            investigation_id=request.investigation_id,
            requirement_id=request.information_requirement_id,
            capability_id=cap_id,
            capability_version=cap_version,
            action_scope=request.action_scope,
            parameters=task_params,
            actor=request.target_specialist,
            actor_role=ActorRole.SPECIALIST.value,
            priority=TaskPriority(min(4, max(1, request.priority // 25))),
            idempotency_key=idemp_key,
            timeout_seconds=request.timeout_seconds,
            is_counterfactual=request.is_counterfactual,
        )

        request.assigned_runtime_task_id = runtime_task.task_id
        self.runtime_queue.enqueue(runtime_task)

        self._journal(
            investigation=investigation,
            entry_type=JournalEntryType.COLLABORATION_ACCEPTED,
            summary=f"Specialist '{request.target_specialist}' accepted request; queued as runtime task '{runtime_task.task_id}'",
            reference_id=request.request_id,
            details={"task_id": runtime_task.task_id, "capability_id": cap_id},
        )

        return runtime_task

    def process_result(
        self,
        request_id: str,
        result: CollaborationResult,
        investigation: Investigation,
    ) -> List[Evidence]:
        """Process collaboration result: normalize evidence, detect conflicts, synthesize consensus, and update state."""
        request = self._get_request(request_id)
        if request.status == CollaborationStatus.ACCEPTED:
            CollaborationLifecycleDFA.transition(request, CollaborationStatus.IN_PROGRESS)
        CollaborationLifecycleDFA.transition(request, CollaborationStatus.RESULT_RECEIVED)

        self._journal(
            investigation=investigation,
            entry_type=JournalEntryType.COLLABORATION_RESULT_RECEIVED,
            summary=f"Specialist '{result.responding_specialist}' returned result for request '{request_id}'",
            reference_id=request.request_id,
            details={"result_id": result.result_id, "evidence_count": len(result.evidence)},
        )

        CollaborationLifecycleDFA.transition(request, CollaborationStatus.EVALUATED)

        # 1. Normalize findings into structured Evidence with full lineage
        cap_id = request.metadata.get("selected_capability_id") or "tool.probe"
        cap = self.capabilities.get_capability(cap_id)
        cap_ver = cap.version if cap else "1.0.0"

        normalized_evidence = EvidenceHandoffNormalizer.normalize_result(
            result=result,
            request=request,
            capability_id=cap_id,
            capability_version=cap_ver,
            authorization_decision_id=request.authorization_decision_id,
        )

        # 2. Conflict Detection across existing case evidence
        existing_evidence = investigation.evidence_store.list_all()
        detected_conflicts = ConflictDetector.detect_conflicts(
            new_evidence=normalized_evidence,
            existing_evidence=existing_evidence,
            investigation_id=investigation.id,
        )

        for conflict in detected_conflicts:
            self.conflict_manager.register_conflict(conflict)
            investigation.contradictions.append(
                from_specialist_conflict(conflict)
            )
            self._journal(
                investigation=investigation,
                entry_type=JournalEntryType.SPECIALIST_CONFLICT_DETECTED,
                summary=f"Conflict detected between '{conflict.specialist_a}' and '{conflict.specialist_b}' on '{conflict.subject}'",
                reference_id=conflict.conflict_id,
                details={
                    "conflict_id": conflict.conflict_id,
                    "subject": conflict.subject,
                    "claim_a": conflict.claim_a,
                    "claim_b": conflict.claim_b,
                    "type": conflict.conflict_type.value,
                },
            )

        # 3. Ingest normalized evidence into authoritative store (Evidence Immutability strictly preserved)
        for ev in normalized_evidence:
            investigation.add_evidence(ev)

        # 4. Consensus synthesis
        all_case_conflicts = self.conflict_manager.list_conflicts(investigation_id=investigation.id)
        for ev in normalized_evidence:
            consensus = self.consensus_engine.evaluate_consensus(
                subject=ev.subject,
                evidence_items=investigation.evidence_store.list_all(),
                conflicts=all_case_conflicts,
            )
            # Link consensus assessment into case hypotheses if matching
            for hyp in investigation.hypotheses.values():
                if ev.subject.lower() in hyp.statement.lower():
                    self.consensus_engine.update_hypothesis_from_consensus(hyp, consensus)

        # 5. Resolve InformationRequirement if linked
        if request.information_requirement_id:
            req = investigation.information_requirements.get(request.information_requirement_id)
            if req:
                from cyberclaw.coordination.requirements import RequirementStatus
                req.resulting_evidence_ids.extend([e.id for e in normalized_evidence])
                req.status = RequirementStatus.SATISFIED if normalized_evidence else RequirementStatus.SATISFIED_EMPTY
                req.updated_at = utc_now()

        # 6. Mark request as resolved in graph and mark COMPLETED
        self._resolved_ids.add(request.request_id)
        if request.information_requirement_id:
            self._resolved_ids.add(request.information_requirement_id)

        CollaborationLifecycleDFA.transition(request, CollaborationStatus.COMPLETED)

        self._journal(
            investigation=investigation,
            entry_type=JournalEntryType.COLLABORATION_COMPLETED,
            summary=f"Collaboration completed for objective '{request.objective}'",
            reference_id=request.request_id,
            details={
                "request_id": request.request_id,
                "evidence_produced": len(normalized_evidence),
                "conflicts_count": len(detected_conflicts),
            },
        )

        return normalized_evidence

    # --------------------------------------------------------------------------
    # Queries & Helpers
    # --------------------------------------------------------------------------

    def get_request(self, request_id: str) -> Optional[CollaborationRequest]:
        """Fetch request by ID."""
        return self._requests.get(request_id)

    def check_and_expire_timeouts(self, investigation_id: Optional[Any] = None) -> List[str]:
        """Check active requests against deadlines and transition expired requests to EXPIRED."""
        now = utc_now()
        expired_ids: List[str] = []
        target_inv_id = investigation_id.id if hasattr(investigation_id, "id") else investigation_id
        for req in self._requests.values():
            if target_inv_id and req.investigation_id != target_inv_id:
                continue
            if req.status.is_terminal:
                continue
            is_expired = False
            if req.deadline and now > req.deadline:
                is_expired = True
            elif req.timeout_seconds and (now - req.created_at).total_seconds() > req.timeout_seconds:
                is_expired = True

            if is_expired:
                try:
                    CollaborationLifecycleDFA.transition(req, CollaborationStatus.EXPIRED, reason="Request deadline exceeded")
                    expired_ids.append(req.request_id)
                except Exception:
                    req.status = CollaborationStatus.EXPIRED
                    expired_ids.append(req.request_id)
        return expired_ids

    def _get_request(self, request_id: str) -> CollaborationRequest:
        req = self._requests.get(request_id)
        if not req:
            raise CollaborationError(f"CollaborationRequest '{request_id}' not found.", request_id=request_id)
        return req

    def list_requests(
        self,
        investigation_id: Optional[str] = None,
        status: Optional[CollaborationStatus] = None,
    ) -> List[CollaborationRequest]:
        """List collaboration requests."""
        res = list(self._requests.values())
        if investigation_id:
            res = [r for r in res if r.investigation_id == investigation_id]
        if status:
            res = [r for r in res if r.status == status]
        return res


def from_specialist_conflict(conflict: SpecialistConflict):
    """Bridge SpecialistConflict into existing ContradictionRecord for backwards compatibility."""
    from cyberclaw.correlation.models import ContradictionRecord
    return ContradictionRecord(
        id=conflict.conflict_id,
        investigation_id=conflict.investigation_id,
        subject=conflict.subject,
        conflict_type=conflict.conflict_type.value,
        competing_evidence_ids=conflict.supporting_evidence_a + conflict.supporting_evidence_b,
        description=f"Specialist '{conflict.specialist_a}' claims {conflict.claim_a} while '{conflict.specialist_b}' claims {conflict.claim_b}",
        detected_at=conflict.created_at,
        resolved=(conflict.status.value == "RESOLVED"),
        resolution_notes=conflict.resolution_rationale,
    )
