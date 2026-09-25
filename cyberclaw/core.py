"""CyberClaw Core: Global orchestration, deterministic control, and contract enforcement."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cyberclaw.authority.dispatch import stamp_governed_dispatch
from cyberclaw.authority.outcomes import classify_provider_result
from cyberclaw.authority.resolution import execution_boundary, require_registered_capability
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import CapabilityTrustError, CapabilityUnavailableError
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.dfa.machine import CoreDFA, InvalidTransitionError
from cyberclaw.dfa.states import CoreState
from cyberclaw.events.bus import EventBus
from cyberclaw.events.event import Event
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.investigation import Investigation
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.case.models import (
    CaseState,
    DecisionRecord,
    DecisionType,
    InvestigationSnapshot,
    JournalEntry,
    JournalEntryType,
    SnapshotDelta,
)
from cyberclaw.memory.store import ExperienceStore
from cyberclaw.observability.logger import StructuredLogger
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import (
    ActionScope,
    PERM_CAPABILITY_EXECUTE,
    PERM_INVESTIGATION_CREATE,
    PERM_INVESTIGATION_UPDATE,
    PERM_INVESTIGATION_VIEW,
    PERM_SPECIALIST_INVOKE,
)
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistRequest
from cyberclaw.specialists.registry import SpecialistRegistry
from cyberclaw.validation.pipeline import ValidationPipeline
from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.policy.models import (
    ActorRole,
    AuthorizationDecision,
    AuthorizationDecisionType,
    PolicyExecutionContext,
    RiskLevel,
)
from cyberclaw.policy.errors import (
    ApprovalRequiredError,
    AuthorizationDeferredError,
    AuthorizationDeniedError,
    PolicyValidationError,
    SupervisionRequiredError,
)


class CyberClawCore:
    """The central CyberClaw orchestrator.

    Follows the principle: Local autonomy, global coordination.
    Coordinates semi-autonomous Specialists through stable contracts, manages
    deterministic state machines, structured evidence, and workspace persistence.
    """

    def __init__(self, workspace_path: Optional[Path] = None) -> None:
        ws_root = workspace_path or Path("./workspace")
        from cyberclaw.workspace.manager import WorkspaceManager
        self.workspace = WorkspaceManager(ws_root)
        self.event_bus = EventBus()
        self.capabilities = CapabilityRegistry()
        self.specialists = SpecialistRegistry()
        self.permissions = PermissionManager()
        self.experiences = ExperienceStore()
        self.logger = StructuredLogger()
        self._investigations: Dict[str, Investigation] = {}
        self._is_running = False

        # Initialize Global Correlation & Coordination
        from cyberclaw.coordination.coordinator import InvestigationCoordinator
        from cyberclaw.correlation.engine import CorrelationEngine
        self.correlation = CorrelationEngine()
        self.coordinator = InvestigationCoordinator(
            specialists=self.specialists,
            capabilities=self.capabilities,
            event_bus=self.event_bus,
            correlation_engine=self.correlation,
        )
        # Coordination routes. It does not invoke specialists by itself.
        self.coordinator.governed_executor = self.execute_action

        # Initialize Adaptive Planning Engine
        from cyberclaw.planning.engine import AdaptivePlanningEngine
        from cyberclaw.planning.planner import DeterministicPlanner
        from cyberclaw.planning.validator import PlanValidator
        self.planner = DeterministicPlanner()
        self.plan_validator = PlanValidator()
        self.planning_engine = AdaptivePlanningEngine(
            planner=self.planner,
            validator=self.plan_validator,
        )

        # Initialize Policy Engine
        self.policy_engine = PolicyEngine()

        # Initialize Durable Event-Driven Runtime
        from cyberclaw.runtime.queue import DurableTaskQueue
        from cyberclaw.runtime.idempotency import IdempotencyRegistry
        from cyberclaw.runtime.dispatcher import SpecialistDispatcher
        from cyberclaw.runtime.executor import RuntimeExecutor
        from cyberclaw.runtime.scheduler import RuntimeScheduler
        self.runtime_queue = DurableTaskQueue()
        self.runtime_idempotency = IdempotencyRegistry()
        self.runtime_dispatcher = SpecialistDispatcher(self.specialists, self.capabilities)
        self.runtime_executor = RuntimeExecutor(
            capabilities=self.capabilities,
            policy_engine=self.policy_engine,
            dispatcher=self.runtime_dispatcher,
            queue=self.runtime_queue,
            idempotency_registry=self.runtime_idempotency,
        )
        self.runtime_scheduler = RuntimeScheduler(self.runtime_queue, self.runtime_executor)

        # Initialize Multi-Specialist Collaboration Coordinator
        from cyberclaw.collaboration.coordinator import CollaborationCoordinator
        self.collaboration = CollaborationCoordinator(
            specialist_registry=self.specialists,
            capability_registry=self.capabilities,
            policy_engine=self.policy_engine,
            runtime_queue=self.runtime_queue,
        )

        self._knowledge_graphs: Dict[str, Any] = {}

        from cyberclaw.learning.proposals import LearningService
        from cyberclaw.learning.registry import LearningRegistry
        self.learning = LearningRegistry()
        self.learning_service = LearningService(self.learning)

    def _resolve_actor_role(self, actor: str) -> str:
        """Resolve an actor identifier to a recognized ActorRole value."""
        if actor == "core.system" or actor.startswith("system."):
            return ActorRole.SYSTEM.value
        if actor.startswith("specialist.") or actor == "specialist":
            return ActorRole.SPECIALIST.value
        if actor.startswith("lead.") or actor.startswith("lead_investigator") or actor == "lead":
            return ActorRole.LEAD_INVESTIGATOR.value
        if actor.startswith("operator.") or actor == "operator":
            return ActorRole.OPERATOR.value
        if actor.startswith("auditor.") or actor == "auditor":
            return ActorRole.AUDITOR.value
        if "analyst" in actor:
            return ActorRole.ANALYST.value

        # Check assigned roles in permission manager
        roles = self.permissions.get_roles(actor)
        if "admin" in roles or "lead_investigator" in roles:
            return ActorRole.LEAD_INVESTIGATOR.value
        if "specialist" in roles:
            return ActorRole.SPECIALIST.value
        if "operator" in roles:
            return ActorRole.OPERATOR.value
        if "auditor" in roles:
            return ActorRole.AUDITOR.value
        if "analyst" in roles:
            return ActorRole.ANALYST.value

        return ActorRole.ANALYST.value

    @property
    def is_running(self) -> bool:
        """True if the Core system is active."""
        return self._is_running

    def startup(self) -> None:
        """Initialize Core systems, verify workspace, and transition to ready state."""
        self._is_running = True
        self.logger.record(
            operation="core.startup",
            component="Core",
            state="INITIALIZED",
            result="success",
            reason="Core subsystems initialized and workspace verified",
        )
        self.event_bus.publish(
            Event(
                type="core.started",
                source="core",
                payload={"workspace_root": str(self.workspace.base_path)},
            )
        )

    def shutdown(self) -> None:
        """Gracefully shut down Core systems."""
        self._is_running = False
        self.logger.record(
            operation="core.shutdown",
            component="Core",
            state="STOPPED",
            result="success",
            reason="Core gracefully halted",
        )
        self.event_bus.publish(
            Event(
                type="core.stopped",
                source="core",
            )
        )

    # --------------------------------------------------------------------------
    # Investigations
    # --------------------------------------------------------------------------

    def create_investigation(
        self,
        title: str,
        description: str = "",
        targets: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor: str = "core.system",
    ) -> Investigation:
        """Create a new investigation, transition its DFA to READY, and persist it."""
        # Permission check
        self.permissions.enforce_permission(
            actor=actor,
            action="investigation.create",
            required_permission=PERM_INVESTIGATION_CREATE,
            scope=ActionScope.CONSEQUENTIAL,
        )

        inv = Investigation(
            title=title,
            description=description,
            targets=targets or [],
            metadata=metadata or {},
        )
        # Establish initial DFA state transition INITIALIZE -> READY
        inv.dfa.transition(
            target_state=CoreState.READY,
            event="investigation.initialized",
            context={"actor": actor, "investigation_id": inv.id},
        )

        self._investigations[inv.id] = inv

        # Observability
        self.logger.record(
            operation="investigation.create",
            component="Core",
            state=inv.current_state.value,
            correlation_id=inv.id,
            result="success",
            reason=f"Created investigation '{title}'",
            metadata={"investigation_id": inv.id, "title": title},
        )

        # Event Bus
        self.event_bus.publish(
            Event(
                type="investigation.created",
                source="core",
                correlation_id=inv.id,
                payload={"investigation_id": inv.id, "title": title},
            )
        )

        # Record initial case state and capture initial snapshot
        inv.case_manager.record_state_transition(
            from_state="INITIALIZE",
            to_state="READY",
            event="investigation.initialized",
            reason=f"Created investigation '{title}'",
            context={"actor": actor, "investigation_id": inv.id},
        )
        inv.capture_snapshot(trigger="investigation_created")

        # Persist full case
        self._persist_case(inv)

        return inv

    def _persist_case(self, inv: Investigation) -> None:
        """Persist investigation state, evidence, snapshots, journal, decisions, and branches."""
        self.workspace.persist_state(inv.id, inv.to_dict())
        self.workspace.persist_evidence(inv.id, inv.evidence_store.list_all())
        self.workspace.persist_snapshots(inv.id, inv.case_manager.snapshots.snapshots)
        self.workspace.persist_journal(inv.id, inv.case_manager.journal.entries)
        self.workspace.persist_decisions(inv.id, inv.case_manager.journal.decisions)
        if inv.branches:
            self.workspace.persist_branches(inv.id, list(inv.branches.values()))

    def get_investigation(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ) -> Optional[Investigation]:
        """Retrieve an investigation by ID after checking read permission."""
        self.permissions.enforce_permission(
            actor=actor,
            action="investigation.view",
            required_permission=PERM_INVESTIGATION_VIEW,
            scope=ActionScope.REVERSIBLE,
        )
        inv = self._investigations.get(investigation_id)
        if inv is not None:
            return inv
        for parent_inv in self._investigations.values():
            if hasattr(parent_inv, "branches") and investigation_id in parent_inv.branches:
                return parent_inv.branches[investigation_id]
        return None

    def list_investigations(self, actor: str = "core.system") -> List[Investigation]:
        """List all investigations."""
        self.permissions.enforce_permission(
            actor=actor,
            action="investigation.view",
            required_permission=PERM_INVESTIGATION_VIEW,
            scope=ActionScope.REVERSIBLE,
        )
        return list(self._investigations.values())

    def transition_investigation(
        self,
        investigation_id: str,
        target_state: CoreState,
        event: str,
        actor: str = "core.system",
        context: Optional[Dict[str, Any]] = None,
    ) -> CoreState:
        """Deterministic state transition for an investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        self.permissions.enforce_permission(
            actor=actor,
            action="investigation.update",
            required_permission=PERM_INVESTIGATION_UPDATE,
            scope=ActionScope.CONSEQUENTIAL,
        )

        ctx = context or {}
        ctx.update({"actor": actor, "investigation_id": investigation_id})

        old_state = inv.current_state
        try:
            new_state = inv.dfa.transition(target_state, event=event, context=ctx)
            # Observability for successful transition
            self.logger.record(
                operation="dfa.transition",
                component="DFA",
                state=new_state.value,
                event=event,
                correlation_id=investigation_id,
                result="success",
                reason=f"Transitioned from {old_state.value} to {new_state.value}",
                metadata={"from_state": old_state.value, "to_state": new_state.value},
            )
            self.event_bus.publish(
                Event(
                    type="dfa.transition",
                    source="core.dfa",
                    correlation_id=investigation_id,
                    payload={"from": old_state.value, "to": new_state.value, "event": event},
                )
            )
            # Record state transition and capture sealed snapshot
            inv.case_manager.record_state_transition(
                from_state=old_state.value,
                to_state=new_state.value,
                event=event,
                reason=f"Transitioned from {old_state.value} to {new_state.value}",
                context=ctx,
            )
            inv.capture_snapshot(trigger=f"state_transition:{new_state.value}")
            self._persist_case(inv)
            return new_state
        except InvalidTransitionError as ite:
            # Observability for rejected transition
            self.logger.record(
                operation="dfa.transition",
                component="DFA",
                state=old_state.value,
                event=event,
                correlation_id=investigation_id,
                result="rejected",
                error=ite.reason,
                reason=f"Rejected transition to {target_state.value}: {ite.reason}",
                metadata={"from_state": old_state.value, "target_state": target_state.value},
            )
            raise

    # --------------------------------------------------------------------------
    # Registration Contracts
    # --------------------------------------------------------------------------

    def register_capability(self, capability: Capability) -> None:
        """Register a domain-agnostic capability definition."""
        self.capabilities.register_capability(capability)
        self.logger.record(
            operation="capability.register",
            component="CapabilityRegistry",
            result="success",
            reason=f"Registered capability '{capability.id}'",
            metadata={"capability_id": capability.id, "category": capability.category},
        )

    def register_provider(self, provider: CapabilityProvider) -> None:
        """Register a provider backing a capability."""
        self.capabilities.register_provider(provider)
        self.logger.record(
            operation="provider.register",
            component="CapabilityRegistry",
            result="success",
            reason=f"Registered provider '{provider.id}' for capability '{provider.capability_id}'",
            metadata={"provider_id": provider.id, "capability_id": provider.capability_id},
        )

    def register_specialist(self, specialist: Specialist) -> None:
        """Register a semi-autonomous specialist subsystem."""
        self.specialists.register_specialist(specialist)
        # Also ensure specialist permissions exist
        self.permissions.assign_role(f"specialist.{specialist.id}", "specialist")
        for perm in specialist.permissions:
            self.permissions.grant_permission(f"specialist.{specialist.id}", perm)

        self.logger.record(
            operation="specialist.register",
            component="SpecialistRegistry",
            result="success",
            reason=f"Registered specialist '{specialist.id}' (v{specialist.version})",
            metadata={
                "specialist_id": specialist.id,
                "version": specialist.version,
                "capabilities": specialist.capabilities,
            },
        )
        self.event_bus.publish(
            Event(
                type="specialist.registered",
                source="core",
                payload={"specialist_id": specialist.id, "capabilities": specialist.capabilities},
            )
        )

    # --------------------------------------------------------------------------
    # Action Execution & Investigation Lifecycle
    # --------------------------------------------------------------------------

    def execute_action(
        self,
        investigation_id: str,
        capability_id: str,
        parameters: Dict[str, Any],
        actor: str = "core.system",
        target_specialist_id: Optional[str] = None,
        scope: ActionScope = ActionScope.CONSEQUENTIAL,
        approval_granted: bool = False,  # ignored; not an approval record
        custom_lesson: Optional[str] = None,
        actor_role: Optional[str] = None,
        policy_id: Optional[str] = None,
        supervision_acknowledged: bool = False,
        approval_token: Optional[str] = None,
        requirement_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Orchestrate the full end-to-end execution lifecycle.

        `approval_granted` is accepted for caller compatibility and ignored.
        It is not an approval record. Pass `approval_token` only when
        PolicyEngine.request_approval has issued one for this request.

        1. Validate current DFA state, parameters schema, and permissions.
        2. Evaluate contextual Policy and assess risk.
        3. Route request to Specialist endpoint (or Capability Provider).
        4. Validate execution result.
        5. Ingest and index produced structured Evidence.
        6. Emit structured events across the bus.
        7. Deterministically update DFA state.
        8. Record an actionable Experience with conditions, causes, and consequences.
        9. Persist state, evidence, and experience to isolated workspace.
        """
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        # Advertisement, a queued id, and a provider object are not registration.
        capability = require_registered_capability(self.capabilities, capability_id)
        boundary = execution_boundary(capability)
        if boundary == "NOT_TRUSTED":
            raise CapabilityTrustError(
                f"Capability '{capability.versioned_id}' has trust state "
                f"'{capability.trust_state.value}' and cannot be executed.",
                capability_id=capability.id,
            )
        if boundary == "NOT_EXECUTABLE":
            raise CapabilityUnavailableError(
                f"Capability '{capability.versioned_id}' is in lifecycle state "
                f"'{capability.lifecycle_state.value}' and cannot be executed.",
                capability_id=capability.id,
            )

        # 1. Multi-phase pre-execution validation
        allowed_dfa_states = [CoreState.READY, CoreState.CLASSIFY, CoreState.INVESTIGATE, CoreState.VERIFY]
        # The caller boolean is not approval evidence. Destructive approval is
        # decided by the policy engine against an issued approval record.
        ValidationPipeline.validate_request(
            capability=capability,
            parameters=parameters,
            actor=actor,
            permission_manager=self.permissions,
            current_state=inv.current_state,
            allowed_states=allowed_dfa_states,
            scope=scope,
            approval_granted=False,
            approval_delegated=True,
        )

        # 2. Contextual Policy Authorization Evaluation & Risk Assessment
        effective_role = actor_role or self._resolve_actor_role(actor)
        policy_ctx = PolicyExecutionContext(
            investigation_id=investigation_id,
            case_stage=inv.current_state.value,
            actor_id=actor,
            actor_role=effective_role,
            capability_id=capability.id,
            capability_version=capability.version,
            action_type="execute",
            action_scope=scope.value,
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
            parameters=parameters,
            is_branch=getattr(inv, "is_branch", False),
            branch_id=getattr(inv, "branch_id", None),
            approval_token=approval_token,
            requires_supervision_acknowledged=supervision_acknowledged,
        )
        auth_decision = self.policy_engine.authorize(policy_ctx, policy_id=policy_id)
        self.policy_engine.record_in_journal(auth_decision, inv.case_manager)

        # Enforce authorization decision
        if not auth_decision.is_authorized:
            if auth_decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL:
                raise ApprovalRequiredError(
                    f"Action '{capability_id}' with {scope.value} scope requires explicit approval: {'; '.join(auth_decision.reasons)}",
                    decision_id=auth_decision.decision_id,
                    policy_id=auth_decision.policy_id,
                )
            elif auth_decision.decision == AuthorizationDecisionType.REQUIRE_SUPERVISION:
                raise SupervisionRequiredError(
                    f"Execution requires operational supervision: {'; '.join(auth_decision.reasons)}",
                    decision_id=auth_decision.decision_id,
                    policy_id=auth_decision.policy_id,
                )
            elif auth_decision.decision == AuthorizationDecisionType.DEFER:
                raise AuthorizationDeferredError(
                    f"Execution deferred by policy: {'; '.join(auth_decision.reasons)}",
                    decision_id=auth_decision.decision_id,
                    policy_id=auth_decision.policy_id,
                )
            else:
                raise AuthorizationDeniedError(
                    f"Execution denied by policy: {'; '.join(auth_decision.reasons)}",
                    decision_id=auth_decision.decision_id,
                    policy_id=auth_decision.policy_id,
                )

        # If DFA was in READY or CLASSIFY, transition to INVESTIGATE
        if inv.current_state in (CoreState.READY, CoreState.CLASSIFY):
            self.transition_investigation(
                investigation_id=investigation_id,
                target_state=CoreState.INVESTIGATE,
                event="action.started",
                actor=actor,
            )

        # Prepare execution context. The stamp records the authorization that
        # already succeeded. It is not a second policy decision.
        exec_ctx = stamp_governed_dispatch(
            ExecutionContext(
                execution_id=str(uuid4()),
                investigation_id=investigation_id,
                correlation_id=investigation_id,
                actor=actor,
                granted_permissions=list(self.permissions.get_effective_permissions(actor)),
                environment={"state": inv.current_state.value},
            ),
            authorization_decision_id=auth_decision.decision_id,
            policy_id=auth_decision.policy_id,
            policy_version=auth_decision.policy_version,
            capability_id=capability.id,
            capability_version=capability.version,
            actor=actor,
            requirement_id=requirement_id,
        )

        # 2. Invoke Specialist or direct Provider
        # Prefer specialist routing if specialist handles this capability
        candidate_specialists = self.specialists.find_by_capability(capability_id)
        resolved_specialist_id = None
        if target_specialist_id or candidate_specialists:
            req = SpecialistRequest(
                investigation_id=investigation_id,
                capability_id=capability_id,
                action="execute",
                parameters=parameters,
                context=exec_ctx,
            )
            spec_resp = self.specialists.route_request(req, target_specialist_id=target_specialist_id)
            resolved_specialist_id = spec_resp.specialist_id
            result = spec_resp.result
        else:
            # Execute through registered capability provider
            result = self.capabilities.execute_capability(capability_id, parameters, exec_ctx)

        # 3. Post-execution result validation
        ValidationPipeline.validate_result(result)

        # 4. Ingest and structure evidence
        if result.is_success and result.evidence:
            for ev in result.evidence:
                # Ensure investigation_id, specialist_id, and capability_id in provenance
                if not ev.provenance.investigation_id:
                    ev.provenance.investigation_id = investigation_id
                if not ev.provenance.specialist_id and resolved_specialist_id:
                    ev.provenance.specialist_id = resolved_specialist_id
                if not ev.provenance.capability_id:
                    ev.provenance.capability_id = capability_id
                inv.add_evidence(ev)

            # 5. Propagate evidence event
            self.event_bus.publish(
                Event(
                    type="evidence.created",
                    source="core",
                    correlation_id=investigation_id,
                    payload={
                        "evidence_ids": [ev.id for ev in result.evidence],
                        "count": len(result.evidence),
                        "capability_id": capability_id,
                    },
                )
            )

        # Record execution in case history
        provider_outcome = classify_provider_result(result)
        inv.case_manager.record_execution(
            requirement_id=requirement_id or str(uuid4()),
            specialist_id=resolved_specialist_id or "core.registry",
            capability_id=capability_id,
            capability_version=capability.version,
            status=result.status.value,
            duration_ms=result.duration_ms,
            evidence_count=len(result.evidence),
            evidence_ids=[ev.id for ev in result.evidence],
            error=result.error,
            lifecycle_state=capability.lifecycle_state.value,
            trust_state=capability.trust_state.value,
            permission_scope=scope.value,
            action_scope=scope.value,
            authorization_decision_id=auth_decision.decision_id,
            risk_level=auth_decision.risk_assessment.overall_risk.value,
            policy_id=auth_decision.policy_id,
            policy_version=auth_decision.policy_version,
            decision=auth_decision.decision.value,
            actor=actor,
            provider_id=resolved_specialist_id,
            provider_outcome=provider_outcome.value,
            investigation_id=investigation_id,
        )

        # Observability for execution
        evidence_ids = [ev.id for ev in result.evidence]
        self.logger.record(
            operation="capability.execute",
            component="Core",
            state=inv.current_state.value,
            correlation_id=investigation_id,
            result=result.status.value,
            evidence_ids=evidence_ids,
            error=result.error,
            duration_ms=result.duration_ms,
            reason=f"Executed capability '{capability_id}' via {target_specialist_id or 'registry'}",
            metadata={"capability_id": capability_id, "parameters": parameters},
        )

        # 6. Formulate actionable condition-cause lesson
        if custom_lesson:
            lesson = custom_lesson
        elif result.is_success:
            lesson = f"Executing '{capability_id}' under parameters {list(parameters.keys())} successfully yielded {len(result.evidence)} evidence findings."
        elif result.is_empty:
            lesson = f"Executing '{capability_id}' completed successfully without finding artifacts for parameters {parameters}; absence of findings confirmed."
        else:
            lesson = f"Executing '{capability_id}' failed due to '{result.error}'; preconditions and target availability must be checked prior to re-execution."

        # 7. Record Experience
        exp_record = self.experiences.record(
            action=f"execute:{capability_id}",
            context={"parameters": parameters, "investigation_id": investigation_id, "state": inv.current_state.value},
            result=result,
            lesson=lesson,
            conditions=parameters,
            scope=f"capability:{capability_id}",
            investigation_id=investigation_id,
            metadata={"duration_ms": result.duration_ms},
        )

        self.event_bus.publish(
            Event(
                type="experience.recorded",
                source="core.memory",
                correlation_id=investigation_id,
                payload={"experience_id": exp_record.id, "lesson": exp_record.lesson, "success": exp_record.success},
            )
        )

        # 8. Workspace Persistence
        self.workspace.persist_evidence(investigation_id, inv.evidence_store.list_all())
        self.workspace.persist_experience(investigation_id, self.experiences.list_all(include_superseded=True))
        self.workspace.persist_state(investigation_id, inv.to_dict())

        return result

    # --------------------------------------------------------------------------
    # Global Coordination & Evidence Correlation
    # --------------------------------------------------------------------------

    def create_information_requirement(
        self,
        investigation_id: str,
        description: str,
        target_or_entity: str,
        evidence_types_sought: Optional[List[str]] = None,
        assigned_capability_id: Optional[str] = None,
        priority: int = 50,
        dependencies: Optional[List[str]] = None,
        actor: str = "core.system",
    ):
        """Create and track an InformationRequirement in the global investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        req = self.coordinator.create_requirement(
            investigation=inv,
            description=description,
            target_or_entity=target_or_entity,
            evidence_types_sought=evidence_types_sought,
            assigned_capability_id=assigned_capability_id,
            priority=priority,
            dependencies=dependencies,
        )
        self.workspace.persist_state(investigation_id, inv.to_dict())
        return req

    def fulfill_information_requirement(
        self,
        investigation_id: str,
        requirement_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        actor: str = "core.system",
    ):
        """Route and execute an InformationRequirement across eligible Specialists."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        req = self.coordinator.fulfill_requirement(
            investigation=inv,
            requirement_id=requirement_id,
            parameters=parameters,
            actor=actor,
        )

        # The governed executor already authorized and recorded the capability
        # execution. This entry records the requirement outcome for replay.
        # It copies the recorded policy reference and does not authorize again.
        latest = inv.case_manager.execution_history[-1] if inv.case_manager.execution_history else None
        inv.case_manager.record_execution(
            requirement_id=req.id,
            specialist_id=req.assigned_specialist_id or "unassigned",
            capability_id=req.assigned_capability_id or "unassigned",
            status=req.status.value,
            evidence_count=len(req.resulting_evidence_ids),
            evidence_ids=list(req.resulting_evidence_ids),
            policy_id=getattr(latest, "policy_id", None),
            policy_version=getattr(latest, "policy_version", None),
            decision=getattr(latest, "decision", None),
            actor=actor,
            investigation_id=investigation_id,
            capability_version=getattr(latest, "capability_version", "1.0.0"),
            lifecycle_state=getattr(latest, "lifecycle_state", "AVAILABLE"),
            trust_state=getattr(latest, "trust_state", "TRUSTED_WITH_SCOPE"),
            permission_scope=getattr(latest, "permission_scope", "consequential"),
            action_scope=getattr(latest, "action_scope", "consequential"),
            authorization_decision_id=getattr(latest, "authorization_decision_id", None),
            provider_outcome=getattr(latest, "provider_outcome", None),
        )
        if req.resulting_evidence_ids:
            inv.record_journal_entry(
                entry_type=JournalEntryType.EVIDENCE_INGESTED,
                summary=f"Ingested {len(req.resulting_evidence_ids)} evidence item(s) from requirement '{req.id}'",
                reference_id=req.id,
                details={"evidence_ids": list(req.resulting_evidence_ids)},
            )
        inv.record_decision(
            decision_type=DecisionType.REQUIREMENT_RESOLUTION,
            actor="core.coordinator",
            rationale=f"Requirement '{req.id}' reached status {req.status.value}",
            inputs={"target": req.target_or_entity, "evidence_types": req.evidence_types_sought},
            outcome={"status": req.status.value, "evidence_count": len(req.resulting_evidence_ids)},
        )
        inv.capture_snapshot(trigger=f"requirement_resolved:{req.status.value}")
        self._persist_case(inv)
        return req

    def correlate_investigation(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ):
        """Execute the CorrelationEngine over all accumulated investigation evidence."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        result = self.coordinator.correlate(inv)
        self._persist_case(inv)
        return result

    def create_hypothesis(
        self,
        investigation_id: str,
        statement: str,
        initial_confidence: float = 0.5,
        actor: str = "core.system",
    ):
        """Formulate an investigative hypothesis."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        hyp = self.coordinator.create_hypothesis(
            investigation=inv,
            statement=statement,
            initial_confidence=initial_confidence,
        )
        inv.record_decision(
            decision_type=DecisionType.HYPOTHESIS_TRANSITION,
            actor="core.coordinator",
            rationale=f"Hypothesis '{hyp.id}' formulated: '{statement}'",
            inputs={"statement": statement, "initial_confidence": initial_confidence},
            outcome={"status": "OPEN", "confidence": initial_confidence},
        )
        self._persist_case(inv)
        return hyp

    def evaluate_hypotheses(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ):
        """Evaluate open hypotheses based on evidence, corroborations, and contradictions."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        res = self.coordinator.evaluate_hypotheses(inv)
        for hyp in res:
            inv.record_decision(
                decision_type=DecisionType.HYPOTHESIS_TRANSITION,
                actor="core.coordinator",
                rationale=f"Evaluated hypothesis '{hyp.id}' to status '{hyp.status}' (confidence: {hyp.confidence:.2f})",
                inputs={"statement": hyp.statement, "supporting_count": len(hyp.supporting_evidence_ids), "refuting_count": len(hyp.refuting_evidence_ids)},
                outcome={"status": hyp.status, "confidence": hyp.confidence},
            )
        if res:
            inv.capture_snapshot(trigger="hypotheses_evaluated")
        self._persist_case(inv)
        return res

    # --------------------------------------------------------------------------
    # Adaptive Investigation Planning
    # --------------------------------------------------------------------------

    def plan_investigation(
        self,
        investigation_id: str,
        actor: str = "core.system",
        max_candidates: int = 5,
        auto_convert_candidates: bool = False,
    ):
        """Generate and validate a structured InvestigationPlan."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        plan, val_res = self.planning_engine.plan_cycle(
            investigation=inv,
            specialists=self.specialists,
            capabilities=self.capabilities,
            permissions=self.permissions,
            actor=actor,
            max_candidates=max_candidates,
            auto_convert_candidates=auto_convert_candidates,
            policy_engine=self.policy_engine,
        )
        inv.case_manager.record_plan(plan)
        inv.record_decision(
            decision_type=DecisionType.PLANNING_SELECTION if val_res.is_valid else DecisionType.PLANNING_REJECTION,
            actor="core.planner",
            rationale=plan.reasoning_basis,
            inputs={"candidates_count": len(plan.candidate_next_requirements), "gaps_count": len(plan.capability_gaps)},
            outcome={"is_valid": val_res.is_valid, "plan_status": plan.plan_status.value, "stopping_condition": plan.stopping_condition.value if plan.stopping_condition else None},
        )
        inv.capture_snapshot(
            trigger="plan_generated",
            active_plan_id=plan.plan_id,
            stopping_condition=plan.stopping_condition.value if plan.stopping_condition else None,
        )
        self._persist_case(inv)
        return plan, val_res

    def run_adaptive_investigation(
        self,
        investigation_id: str,
        max_cycles: int = 3,
        actor: str = "core.system",
    ):
        """Execute the full adaptive planning and investigation loop until stopping condition."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        plans = self.planning_engine.run_adaptive_loop(
            investigation=inv,
            specialists=self.specialists,
            capabilities=self.capabilities,
            permissions=self.permissions,
            coordinator=self.coordinator,
            max_cycles=max_cycles,
            actor=actor,
        )
        for plan in plans:
            inv.case_manager.record_plan(plan)
        inv.capture_snapshot(
            trigger="adaptive_investigation_completed",
            active_plan_id=plans[-1].plan_id if plans else None,
            stopping_condition=plans[-1].stopping_condition.value if (plans and plans[-1].stopping_condition) else None,
        )
        self._persist_case(inv)
        return plans

    # --------------------------------------------------------------------------
    # Long-Horizon Case Memory & State Queries
    # --------------------------------------------------------------------------

    def capture_case_snapshot(
        self,
        investigation_id: str,
        trigger: str = "manual",
        metadata: Optional[Dict[str, Any]] = None,
        actor: str = "core.system",
    ) -> InvestigationSnapshot:
        """Capture an immutable, sealed snapshot of the investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        snap = inv.capture_snapshot(trigger=trigger, metadata=metadata)
        self._persist_case(inv)
        return snap

    def get_case_snapshot(
        self,
        investigation_id: str,
        sequence_or_id: Any,
        actor: str = "core.system",
    ) -> Optional[InvestigationSnapshot]:
        """Retrieve a specific snapshot by sequence or ID."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.get_snapshot(sequence_or_id)

    def list_case_snapshots(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ) -> List[InvestigationSnapshot]:
        """List all snapshots of an investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.list_snapshots()

    def compare_case_snapshots(
        self,
        investigation_id: str,
        first: Any,
        second: Any,
        actor: str = "core.system",
    ) -> SnapshotDelta:
        """Compare two snapshots and return an explainable delta."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.compare_snapshots(first, second)

    def explain_case_at(
        self,
        investigation_id: str,
        sequence_or_id: Any,
        actor: str = "core.system",
    ) -> Dict[str, Any]:
        """Explain the complete posture of an investigation at a specific snapshot."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.explain_state_at(sequence_or_id)

    def get_case_timeline(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ) -> List[Dict[str, Any]]:
        """Retrieve the linear chronological journal timeline for a case."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.get_timeline()

    def get_case_state(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ) -> CaseState:
        """Retrieve the assembled comprehensive CaseState object."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.get_case_state()

    # --------------------------------------------------------------------------
    # Deterministic Investigation Replay & Time-Travel
    # --------------------------------------------------------------------------

    def replay_investigation(
        self,
        investigation_id: str,
        until_sequence: Optional[int] = None,
        from_snapshot: Optional[Union[int, str]] = None,
        until_snapshot: Optional[Union[int, str]] = None,
        actor: str = "core.system",
    ):
        """Deterministically reconstruct historical state without executing live tools or mutating state."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        from cyberclaw.replay.engine import ReplayEngine
        return ReplayEngine.replay(
            inv,
            until_sequence=until_sequence,
            from_snapshot=from_snapshot,
            until_snapshot=until_snapshot,
        )

    def query_historical_state(
        self,
        investigation_id: str,
        sequence: Optional[int] = None,
        actor: str = "core.system",
    ):
        """Perform a read-only time-travel query at a specific sequence index."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        from cyberclaw.replay.engine import ReplayEngine
        return ReplayEngine.replay(inv, until_sequence=sequence)

    def explain_case_progression(
        self,
        investigation_id: str,
        from_sequence: int = 1,
        to_sequence: Optional[int] = None,
        actor: str = "core.system",
    ):
        """Explain state progression and historical delta between two sequences."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        from cyberclaw.replay.engine import ReplayEngine
        max_seq = len(inv.case_manager.journal.entries)
        return ReplayEngine.explain_progression(
            inv, from_sequence=from_sequence, to_sequence=to_sequence or max_seq
        )

    def validate_case_history(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ) -> bool:
        """Validate sequence ordering, snapshot integrity, and decision references for a case."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        from cyberclaw.replay.engine import ReplayEngine
        ReplayEngine.validate_case_history(
            inv.case_manager.journal.entries,
            inv.case_manager.snapshots.snapshots,
            inv.case_manager.journal.decisions,
        )
        return True

    # --------------------------------------------------------------------------
    # Investigation Branching & Counterfactual Analysis
    # --------------------------------------------------------------------------

    def create_investigation_branch(
        self,
        investigation_id: str,
        source_snapshot: Union[int, str],
        purpose: str,
        originating_decision_id: Optional[str] = None,
        parent_branch_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        actor: str = "core.system",
    ):
        """Create an isolated investigation branch rooted at a cryptographically verified snapshot."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        branch = inv.create_branch(
            source_snapshot=source_snapshot,
            purpose=purpose,
            originating_decision_id=originating_decision_id,
            parent_branch_id=parent_branch_id,
            metadata=metadata,
        )
        self._persist_case(inv)
        return branch

    def get_investigation_branch(
        self,
        investigation_id: str,
        branch_id: str,
        actor: str = "core.system",
    ):
        """Retrieve a specific investigation branch by ID."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.get_branch(branch_id)

    def list_investigation_branches(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ):
        """List all derived branches for an investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.list_branches()

    def replay_investigation_branch(
        self,
        investigation_id: str,
        branch_id: str,
        until_local_sequence: Optional[int] = None,
        actor: str = "core.system",
    ):
        """Deterministically reconstruct historical state of a branch up to a local sequence index."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.replay_branch(branch_id, until_local_sequence=until_local_sequence)

    def compare_investigation_branches(
        self,
        investigation_id: str,
        branch_a_id: str,
        branch_b_id: str,
        actor: str = "core.system",
    ):
        """Factually compare two investigation branches without scoring or ranking."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.compare_branches(branch_a_id, branch_b_id)

    def compare_branch_to_snapshot(
        self,
        investigation_id: str,
        branch_id: str,
        snapshot_seq_or_id: Union[int, str],
        actor: str = "core.system",
    ):
        """Factually compare a branch derived state against an authoritative snapshot."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return inv.compare_branch_with_snapshot(branch_id, snapshot_seq_or_id)

    def promote_investigation_branch(
        self,
        investigation_id: str,
        branch_id: str,
        reason: str,
        actor: str = "core.system",
    ):
        """Promote a branch for authoritative consideration (does not mutate facts directly)."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        decision = inv.promote_branch(branch_id, reason=reason, actor=actor)
        self._persist_case(inv)
        return decision

    def validate_branch_history(
        self,
        investigation_id: str,
        branch_id: str,
        actor: str = "core.system",
    ) -> bool:
        """Validate structural and cryptographic integrity of a branch."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        branch = inv.get_branch(branch_id)
        if not branch:
            from cyberclaw.branching.errors import BranchNotFoundError
            raise BranchNotFoundError(f"Branch '{branch_id}' not found.")
        from cyberclaw.branching.validator import BranchValidator
        BranchValidator.validate_all(
            branch=branch,
            snapshots=inv.case_manager.snapshots.snapshots,
            authoritative_evidence_ids={e.id for e in inv.evidence_store.list_all()},
        )
        return True

    # --------------------------------------------------------------------------
    # Capability Lifecycle & Governance
    # --------------------------------------------------------------------------

    def validate_capability(
        self,
        capability_id: str,
        validation_record: Any,
        actor: str = "core.system",
    ):
        """Record formal validation for a capability."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        return CapabilityGovernance.validate_capability(cap, validation_record, actor=actor)

    def approve_capability(
        self,
        capability_id: str,
        approver: str = "core.admin",
        rationale: str = "",
        target_state: Any = None,
        trust_state: Any = None,
    ):
        """Formally approve a capability for operational use."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
        return CapabilityGovernance.approve_capability(
            capability=cap,
            approver=approver,
            rationale=rationale,
            target_state=target_state or CapabilityLifecycleState.AVAILABLE,
            trust_state=trust_state or CapabilityTrustState.TRUSTED_WITH_SCOPE,
        )

    def enable_capability(
        self,
        capability_id: str,
        actor: str = "core.admin",
        rationale: str = "",
    ):
        """Re-enable a previously disabled capability."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        return CapabilityGovernance.enable_capability(cap, actor=actor, rationale=rationale)

    def disable_capability(
        self,
        capability_id: str,
        actor: str = "core.admin",
        rationale: str = "",
    ):
        """Temporarily disable a capability from execution."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        return CapabilityGovernance.disable_capability(cap, actor=actor, rationale=rationale)

    def deprecate_capability(
        self,
        capability_id: str,
        actor: str = "core.admin",
        rationale: str = "",
    ):
        """Mark a capability as deprecated."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        return CapabilityGovernance.deprecate_capability(cap, actor=actor, rationale=rationale)

    def retire_capability(
        self,
        capability_id: str,
        actor: str = "core.admin",
        rationale: str = "",
    ):
        """Permanently retire a capability from active selection."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        return CapabilityGovernance.retire_capability(cap, actor=actor, rationale=rationale)

    def grant_capability_trust(
        self,
        capability_id: str,
        trust_state: Any,
        actor: str = "core.admin",
        rationale: str = "",
    ):
        """Assign trust tier to a capability."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        return CapabilityGovernance.grant_trust(cap, target_trust=trust_state, actor=actor, rationale=rationale)

    def revoke_capability_trust(
        self,
        capability_id: str,
        actor: str = "core.admin",
        rationale: str = "",
    ):
        """Revoke trust tier from a capability."""
        cap = self.capabilities.get_capability(capability_id)
        if not cap:
            raise KeyError(f"Capability '{capability_id}' not found.")
        from cyberclaw.capabilities.governance import CapabilityGovernance
        return CapabilityGovernance.revoke_trust(cap, actor=actor, rationale=rationale)

    def get_capability_health(
        self,
        capability_id: str,
    ):
        """Evaluate operational health status of a capability."""
        return self.capabilities.get_capability_health(capability_id)

    def discover_capabilities_for_gap(
        self,
        gap: Any,
    ):
        """Discover existing, unavailable, deprecated, or candidate capabilities for an intelligence gap."""
        from cyberclaw.capabilities.governance import CapabilityGovernance
        all_caps = self.capabilities.list_capabilities(include_retired=True, include_disabled=True)
        return CapabilityGovernance.discover_capabilities_for_gap(gap, all_caps)

    # --------------------------------------------------------------------------
    # Durable Event-Driven Runtime APIs
    # --------------------------------------------------------------------------

    def submit_task_to_runtime(
        self,
        investigation_id: str,
        capability_id: str,
        parameters: Dict[str, Any],
        requirement_id: Optional[str] = None,
        priority: Any = None,
        scope: Optional[ActionScope] = None,
        actor: str = "core.system",
        actor_role: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
        is_counterfactual: bool = False,
    ):
        """Submit an executable task into the durable runtime queue."""
        from cyberclaw.runtime.models import RuntimeTask, TaskPriority
        from cyberclaw.runtime.idempotency import compute_task_idempotency_key

        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        cap = self.capabilities.get_capability(capability_id)
        cap_version = cap.version if cap else "1.0.0"
        task_scope = scope if scope is not None else (cap.action_scope if cap else ActionScope.REVERSIBLE)

        idemp_key = compute_task_idempotency_key(
            investigation_id=investigation_id,
            capability_id=capability_id,
            capability_version=cap_version,
            requirement_id=requirement_id,
            parameters=parameters,
        )

        task_priority = priority or TaskPriority.NORMAL
        effective_role = actor_role or self._resolve_actor_role(actor)

        task = RuntimeTask(
            investigation_id=investigation_id,
            requirement_id=requirement_id,
            capability_id=capability_id,
            capability_version=cap_version,
            action_scope=task_scope.value if isinstance(task_scope, ActionScope) else str(task_scope),
            parameters=parameters,
            actor=actor,
            actor_role=effective_role,
            priority=task_priority,
            idempotency_key=idemp_key,
            timeout_seconds=timeout_seconds,
            is_counterfactual=is_counterfactual or getattr(inv, "is_branch", False),
        )

        enqueued = self.runtime_queue.enqueue(task)

        # Journal the queued event
        inv.case_manager.journal.append_entry(
            entry_type=JournalEntryType.TASK_QUEUED,
            summary=f"Runtime task '{task.task_id}' queued for capability '{capability_id}' (priority {int(task_priority)})",
            reference_id=task.task_id,
            details={
                "capability_id": capability_id,
                "requirement_id": requirement_id,
                "idempotency_key": idemp_key,
                "priority": int(task_priority),
            },
        )
        return enqueued

    def submit_requirement_to_runtime(
        self,
        investigation_id: str,
        requirement_id: str,
        priority: Any = None,
        actor: str = "core.system",
    ):
        """Convert an existing InformationRequirement into a durable runtime task."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        req = inv.information_requirements.get(requirement_id)
        if not req:
            raise KeyError(f"Requirement '{requirement_id}' not found in investigation '{investigation_id}'.")

        capability_id = req.assigned_capability_id
        if not capability_id:
            candidates = self.specialists.find_by_capability(req.target_or_entity)
            if candidates:
                capability_id = req.target_or_entity
            else:
                capability_id = "general.discovery"

        params = {"target": req.target_or_entity, "sought_types": req.evidence_types_sought}

        return self.submit_task_to_runtime(
            investigation_id=investigation_id,
            capability_id=capability_id,
            parameters=params,
            requirement_id=requirement_id,
            priority=priority,
            actor=actor,
        )

    def process_runtime_queue(
        self,
        investigation_id: str,
        max_steps: int = 50,
        actor: str = "core.system",
        custom_lesson: Optional[str] = None,
    ):
        """Process queued tasks for an investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        processed = self.runtime_scheduler.process_all(
            investigation=inv,
            permission_manager=self.permissions,
            max_steps=max_steps,
            custom_lesson=custom_lesson,
            experience_store=self.experiences,
        )

        self._persist_case(inv)
        self.persist_runtime_state(investigation_id)
        return processed

    def step_runtime(
        self,
        investigation_id: str,
        actor: str = "core.system",
        custom_lesson: Optional[str] = None,
    ):
        """Execute a single step from the runtime queue."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        task = self.runtime_scheduler.step(
            investigation=inv,
            permission_manager=self.permissions,
            custom_lesson=custom_lesson,
            experience_store=self.experiences,
        )
        if task:
            self._persist_case(inv)
            self.persist_runtime_state(investigation_id)
        return task

    def pause_investigation_runtime(
        self,
        investigation_id: str,
        reason: str = "",
        actor: str = "core.system",
    ) -> None:
        """Pause runtime execution for an investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        self.runtime_scheduler.pause_investigation(investigation_id, reason=reason)
        inv.case_manager.journal.append_entry(
            entry_type=JournalEntryType.DECISION_RECORDED,
            summary=f"Investigation runtime PAUSED: {reason or 'Manual operator pause'}",
            reference_id=investigation_id,
            details={"decision": "PAUSE_RUNTIME", "reason": reason, "actor": actor},
        )

    def resume_investigation_runtime(
        self,
        investigation_id: str,
        actor: str = "core.system",
    ) -> None:
        """Resume runtime execution for a paused investigation."""
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        self.runtime_scheduler.resume_investigation(investigation_id)
        inv.case_manager.journal.append_entry(
            entry_type=JournalEntryType.DECISION_RECORDED,
            summary="Investigation runtime RESUMED",
            reference_id=investigation_id,
            details={"decision": "RESUME_RUNTIME", "actor": actor},
        )

    def recover_runtime(self):
        """Recover runtime from process restart or crash."""
        from cyberclaw.runtime.recovery import RuntimeRecoveryManager
        return RuntimeRecoveryManager.recover(self.runtime_queue, self.runtime_idempotency)

    def persist_runtime_state(self, investigation_id: Optional[str] = None) -> None:
        """Atomically persist runtime queue and idempotency records."""
        from cyberclaw.runtime.persistence import RuntimePersistenceManager
        base_dir = self.workspace.base_path
        if investigation_id:
            layout = self.workspace.get_investigation_workspace(investigation_id)
            base_dir = layout.root
        RuntimePersistenceManager.persist_state(self.runtime_queue, self.runtime_idempotency, base_dir)

    def load_runtime_state(self, investigation_id: Optional[str] = None) -> bool:
        """Load persisted runtime queue and idempotency records."""
        from cyberclaw.runtime.persistence import RuntimePersistenceManager
        base_dir = self.workspace.base_path
        if investigation_id:
            layout = self.workspace.get_investigation_workspace(investigation_id)
            base_dir = layout.root
        return RuntimePersistenceManager.load_state(self.runtime_queue, self.runtime_idempotency, base_dir)

    # --------------------------------------------------------------------------
    # Multi-Specialist Collaboration APIs
    # --------------------------------------------------------------------------

    def request_collaboration(
        self,
        investigation_id: str,
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
        sensitivity: Any = "INTERNAL",
        action_scope: str = "reversible",
        deadline: Optional[Any] = None,
        timeout_seconds: Optional[float] = None,
        dependencies: Optional[List[str]] = None,
        is_counterfactual: bool = False,
    ):
        """Submit a structured collaboration request from one specialist to another."""
        from cyberclaw.collaboration.models import ContextSensitivity
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        sens_enum = ContextSensitivity(sensitivity) if isinstance(sensitivity, str) else sensitivity
        return self.collaboration.request_collaboration(
            investigation=inv,
            requesting_specialist=requesting_specialist,
            objective=objective,
            target_specialist=target_specialist,
            information_requirement_id=information_requirement_id,
            input_evidence_ids=input_evidence_ids,
            input_entity_ids=input_entity_ids,
            hypothesis_ids=hypothesis_ids,
            required_capabilities=required_capabilities,
            requested_permissions=requested_permissions,
            priority=priority,
            sensitivity=sens_enum,
            action_scope=action_scope,
            deadline=deadline,
            timeout_seconds=timeout_seconds,
            dependencies=dependencies,
            is_counterfactual=is_counterfactual,
        )

    def validate_and_route_collaboration(
        self,
        investigation_id: str,
        request_id: str,
    ):
        """Validate dependencies, route to an eligible specialist, and verify policy authorization."""
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return self.collaboration.validate_and_route(request_id, inv, self.permissions)

    def accept_collaboration_request(
        self,
        investigation_id: str,
        request_id: str,
        parameters: Optional[Dict[str, Any]] = None,
    ):
        """Target specialist accepts request, packages least-privilege context, and enqueues runtime task."""
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        return self.collaboration.accept_and_enqueue(request_id, inv, parameters=parameters)

    def process_collaboration_result(
        self,
        investigation_id: str,
        request_id: str,
        result: Any,
    ):
        """Process returned specialist result: normalize findings, discover conflicts, update consensus and case."""
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        evs = self.collaboration.process_result(request_id, result, inv)
        self._persist_case(inv)
        self.persist_collaboration_state(investigation_id)
        return evs

    def resolve_specialist_conflict(
        self,
        investigation_id: str,
        conflict_id: str,
        resolution_evidence_id: str,
        rationale: str,
    ):
        """Explicitly resolve a recorded specialist conflict using resolution evidence."""
        inv = self.get_investigation(investigation_id)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")
        conflict = self.collaboration.conflict_manager.resolve_conflict(
            conflict_id=conflict_id,
            resolution_evidence_id=resolution_evidence_id,
            rationale=rationale,
        )
        inv.case_manager.journal.append_entry(
            entry_type=JournalEntryType.SPECIALIST_CONFLICT_RESOLVED,
            summary=f"Specialist conflict '{conflict_id}' resolved: {rationale}",
            reference_id=conflict_id,
            details={"resolution_evidence_id": resolution_evidence_id, "rationale": rationale},
        )
        self._persist_case(inv)
        return conflict

    def persist_collaboration_state(self, investigation_id: Optional[str] = None) -> None:
        """Atomically persist collaboration requests and conflicts."""
        from cyberclaw.collaboration.persistence import CollaborationPersistenceManager
        base_dir = self.workspace.base_path
        if investigation_id:
            layout = self.workspace.get_investigation_workspace(investigation_id)
            base_dir = layout.root
        CollaborationPersistenceManager.persist_state(self.collaboration, base_dir)

    def load_collaboration_state(self, investigation_id: Optional[str] = None) -> bool:
        """Load persisted collaboration requests and conflicts."""
        from cyberclaw.collaboration.persistence import CollaborationPersistenceManager
        base_dir = self.workspace.base_path
        if investigation_id:
            layout = self.workspace.get_investigation_workspace(investigation_id)
            base_dir = layout.root
        return CollaborationPersistenceManager.load_state(self.collaboration, base_dir)

    # --------------------------------------------------------------------------
    # Temporal Knowledge Graph APIs
    # --------------------------------------------------------------------------

    def get_knowledge_graph(self, investigation_id: str) -> Any:
        """Retrieve or initialize the in-memory TemporalKnowledgeGraph for an investigation."""
        inv = self.get_investigation(investigation_id)
        if investigation_id not in self._knowledge_graphs:
            from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
            self._knowledge_graphs[investigation_id] = TemporalKnowledgeGraph(
                investigation_id=investigation_id,
                case_id=getattr(inv, "case_id", ""),
                is_counterfactual=getattr(inv, "is_counterfactual", False),
                branch_id=getattr(inv, "branch_id", None),
            )
        return self._knowledge_graphs[investigation_id]

    def materialize_knowledge_graph(self, investigation_id: str) -> Any:
        """Deterministically materialize the knowledge graph from authoritative Case State and Evidence."""
        from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
        from cyberclaw.knowledge.materialization import KnowledgeMaterializer
        inv = self.get_investigation(investigation_id)
        fresh_graph = TemporalKnowledgeGraph(
            investigation_id=investigation_id,
            case_id=getattr(inv, "case_id", ""),
            is_counterfactual=getattr(inv, "is_counterfactual", False),
            branch_id=getattr(inv, "branch_id", None),
        )
        materialized = KnowledgeMaterializer.materialize_from_investigation(inv, target_graph=fresh_graph)
        self._knowledge_graphs[investigation_id] = materialized
        self.persist_knowledge_graph(investigation_id)
        return materialized

    def mutate_knowledge_graph(self, investigation_id: str, request: Any) -> Any:
        """Apply a governed mutation to the knowledge graph through PolicyEngine and CaseJournal."""
        from cyberclaw.knowledge.mutations import GraphMutationPipeline
        inv = self.get_investigation(investigation_id)
        graph = self.get_knowledge_graph(investigation_id)
        result = GraphMutationPipeline.apply_mutation(
            graph=graph,
            request=request,
            policy_engine=self.policy_engine,
            investigation=inv,
        )
        if result.is_successful:
            self.persist_knowledge_graph(investigation_id)
        return result

    def explain_knowledge_node(self, investigation_id: str, node_id: str) -> Any:
        """Produce an audit-ready, provenance-preserving explanation of a knowledge node."""
        from cyberclaw.knowledge.queries import KnowledgeQueryEngine
        inv = self.get_investigation(investigation_id)
        graph = self.get_knowledge_graph(investigation_id)
        evidence_items = inv.evidence_store.list_all() if hasattr(inv, "evidence_store") else []
        return KnowledgeQueryEngine.explain_node(graph, node_id, evidence_items=evidence_items)

    def explain_knowledge_edge(self, investigation_id: str, edge_id: str) -> Any:
        """Produce an audit-ready, provenance-preserving explanation of a knowledge edge."""
        from cyberclaw.knowledge.queries import KnowledgeQueryEngine
        inv = self.get_investigation(investigation_id)
        graph = self.get_knowledge_graph(investigation_id)
        evidence_items = inv.evidence_store.list_all() if hasattr(inv, "evidence_store") else []
        return KnowledgeQueryEngine.explain_edge(graph, edge_id, evidence_items=evidence_items)

    def find_knowledge_gaps(self, investigation_id: str) -> List[Any]:
        """Detect uncertainties, uncorroborated hypotheses, and active contradictions in the knowledge graph."""
        from cyberclaw.knowledge.queries import KnowledgeQueryEngine
        graph = self.get_knowledge_graph(investigation_id)
        return KnowledgeQueryEngine.find_knowledge_gaps(graph)

    def check_knowledge_consistency(self, investigation_id: str) -> List[Any]:
        """Perform comprehensive consistency verification on the investigation's knowledge graph."""
        from cyberclaw.knowledge.consistency import KnowledgeConsistencyEngine
        inv = self.get_investigation(investigation_id)
        graph = self.get_knowledge_graph(investigation_id)
        ev_store = getattr(inv, "evidence_store", None)
        return KnowledgeConsistencyEngine.check_consistency(graph, evidence_store=ev_store)

    def persist_knowledge_graph(self, investigation_id: str) -> Any:
        """Atomically persist knowledge graph state to workspace layout."""
        from cyberclaw.knowledge.persistence import KnowledgePersistenceManager
        graph = self.get_knowledge_graph(investigation_id)
        layout = self.workspace.get_investigation_workspace(investigation_id)
        return KnowledgePersistenceManager.save_graph(graph, layout.root)

    def load_knowledge_graph(
        self,
        investigation_id: str,
        is_counterfactual: bool = False,
        branch_id: Optional[str] = None,
    ) -> Any:
        """Restore and verify knowledge graph state from workspace layout."""
        from cyberclaw.knowledge.persistence import KnowledgePersistenceManager
        layout = self.workspace.get_investigation_workspace(investigation_id)
        graph = KnowledgePersistenceManager.load_graph(
            investigation_id=investigation_id,
            workspace_path=layout.root,
            is_counterfactual=is_counterfactual,
            branch_id=branch_id,
        )
        if graph:
            self._knowledge_graphs[investigation_id] = graph
        return graph







    # --------------------------------------------------------------------------
    # Cross-Case Experience & Strategy Learning APIs
    # --------------------------------------------------------------------------

    def ingest_investigation_experience(self, investigation_id: str, actor: str = "learning.engine") -> Any:
        """Extract, normalize, and detect patterns. Does not approve or execute."""
        inv = self.get_investigation(investigation_id, actor="core.system")
        return self.learning_service.ingest(inv, actor=actor)

    def propose_learned_strategy(self, pattern_id: str, proposer_id: str, pattern_version: Optional[str] = None) -> Any:
        """Propose a strategy from a validated pattern. Does not approve it."""
        return self.learning_service.propose(pattern_id, proposer_id, pattern_version=pattern_version)

    def simulate_learned_strategy(
        self,
        strategy_id: str,
        version: Optional[str] = None,
        experience_ids: Optional[List[str]] = None,
        actor: str = "lead.simulator",
    ) -> List[Any]:
        """Counterfactual simulation. Does not execute providers or mutate cases."""
        from cyberclaw.learning.simulation import StrategySimulator

        strategy = self.learning.get_strategy(strategy_id, version)
        if experience_ids is None:
            experiences = self.learning.authoritative_experiences()
        else:
            experiences = [self.learning.get_experience(eid) for eid in experience_ids]
            experiences = [exp for exp in experiences if exp is not None]
        reports = StrategySimulator.simulate(
            strategy,
            experiences,
            policy_engine=self.policy_engine,
            actor=actor,
        )
        self.learning_service.record_simulation(strategy.strategy_id, strategy.version, actor)
        return reports

    def evaluate_learned_strategy(
        self,
        strategy_id: str,
        version: Optional[str] = None,
        actor: str = "lead.evaluator",
    ) -> Any:
        from cyberclaw.learning.evaluation import StrategyEvaluator
        from cyberclaw.learning.simulation import StrategySimulator

        strategy = self.learning.get_strategy(strategy_id, version)
        experiences = [
            self.learning.get_experience(eid)
            for eid in strategy.provenance.get("supporting_experience_ids", [])
        ]
        experiences = [exp for exp in experiences if exp is not None]
        reports = StrategySimulator.simulate(strategy, experiences, policy_engine=self.policy_engine, actor=actor)
        evaluation = StrategyEvaluator.evaluate(strategy, reports, experiences)
        self.learning_service.record_evaluation(evaluation, actor)
        return evaluation

    def review_learned_strategy(self, strategy_id: str, version: str, actor: str) -> Any:
        return self.learning_service.mark_reviewed(strategy_id, version, actor)

    def approve_learned_strategy(
        self,
        strategy_id: str,
        version: str,
        actor: str,
        decision: Any,
        reason: str,
        evidence_refs: Optional[List[str]] = None,
    ) -> Any:
        policy = self.policy_engine.registry.get_default_policy()
        return self.learning_service.approve(
            strategy_id,
            version,
            actor,
            decision,
            reason,
            evidence_refs=evidence_refs,
            policy_id=policy.policy_id,
            policy_version=policy.version,
        )

    def publish_learned_strategy(
        self,
        strategy_id: str,
        version: str,
        actor: str,
        actor_role: str = "lead_investigator",
        investigation_id: str = "learning-registry",
    ) -> Any:
        return self.learning_service.publish(
            strategy_id,
            version,
            actor,
            actor_role,
            self.policy_engine,
            investigation_id,
        )

    def query_learned_strategies(
        self,
        investigation_id: str,
        available_capabilities: Optional[List[str]] = None,
        available_specialists: Optional[List[str]] = None,
        actor_permissions: Optional[List[str]] = None,
        actor: str = "lead.planner",
        actor_role: str = "lead_investigator",
    ) -> Any:
        inv = self.get_investigation(investigation_id, actor="core.system")
        gaps = []
        if investigation_id in self._knowledge_graphs:
            gaps = self.find_knowledge_gaps(investigation_id)
        return self.planning_engine.request_strategy_candidates(
            investigation=inv,
            learning_registry=self.learning,
            knowledge_gaps=gaps,
            available_capabilities=available_capabilities,
            available_specialists=available_specialists,
            actor_permissions=actor_permissions,
            policy_engine=self.policy_engine,
            actor=actor,
            actor_role=actor_role,
        )

    def record_strategy_outcome(self, outcome: Any, actor: str = "lead.reviewer") -> Any:
        return self.learning.record_outcome(outcome, actor=actor)

    def replay_learning_state(self, until_sequence: Optional[int] = None) -> Any:
        from cyberclaw.replay.engine import ReplayEngine

        return ReplayEngine.replay_learning_state(self.learning.events, until_sequence=until_sequence)

    def explain_learned_strategy(self, strategy_id: str, version: Optional[str] = None) -> Any:
        from cyberclaw.replay.engine import ReplayEngine

        return ReplayEngine.explain_strategy_origin(self.learning.events, strategy_id, version=version)

    def persist_learning_state(self) -> Any:
        from cyberclaw.learning.persistence import LearningPersistenceManager

        return LearningPersistenceManager.save(self.learning, self.workspace.base_path)

    def load_learning_state(self) -> Any:
        from cyberclaw.learning.persistence import LearningPersistenceManager
        from cyberclaw.learning.proposals import LearningService

        self.learning = LearningPersistenceManager.load(self.workspace.base_path)
        self.learning_service = LearningService(self.learning)
        return self.learning

    def project_learning_knowledge_graph(self) -> Any:
        """Project learned relationships onto a registry-owned graph, not a case graph."""
        return self.learning.project_learning_graph()







