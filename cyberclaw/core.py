"""CyberClaw Core: Global orchestration, deterministic control, and contract enforcement."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from cyberclaw.capabilities.capability import Capability
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

        # Persist to workspace
        self.workspace.persist_state(inv.id, inv.to_dict())

        return inv

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
        return self._investigations.get(investigation_id)

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
            # Persist state
            self.workspace.persist_state(investigation_id, inv.to_dict())
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
        approval_granted: bool = False,
        custom_lesson: Optional[str] = None,
    ) -> ExecutionResult:
        """Orchestrate the full end-to-end execution lifecycle:
        1. Validate current DFA state, parameters schema, and permissions.
        2. Route request to Specialist endpoint (or Capability Provider).
        3. Validate execution result.
        4. Ingest and index produced structured Evidence.
        5. Emit structured events across the bus.
        6. Deterministically update DFA state.
        7. Record an actionable Experience with conditions, causes, and consequences.
        8. Persist state, evidence, and experience to isolated workspace.
        """
        inv = self.get_investigation(investigation_id, actor=actor)
        if not inv:
            raise KeyError(f"Investigation '{investigation_id}' not found.")

        capability = self.capabilities.get_capability(capability_id)
        if not capability:
            # Fallback check: maybe specialist advertises it
            capability = Capability(
                id=capability_id,
                name=capability_id,
                description="Dynamically resolved capability",
            )
            self.capabilities.register_capability(capability)

        # 1. Multi-phase pre-execution validation
        allowed_dfa_states = [CoreState.READY, CoreState.CLASSIFY, CoreState.INVESTIGATE, CoreState.VERIFY]
        ValidationPipeline.validate_request(
            capability=capability,
            parameters=parameters,
            actor=actor,
            permission_manager=self.permissions,
            current_state=inv.current_state,
            allowed_states=allowed_dfa_states,
            scope=scope,
            approval_granted=approval_granted,
        )

        # If DFA was in READY or CLASSIFY, transition to INVESTIGATE
        if inv.current_state in (CoreState.READY, CoreState.CLASSIFY):
            self.transition_investigation(
                investigation_id=investigation_id,
                target_state=CoreState.INVESTIGATE,
                event="action.started",
                actor=actor,
            )

        # Prepare execution context
        exec_ctx = ExecutionContext(
            execution_id=str(uuid4()),
            investigation_id=investigation_id,
            correlation_id=investigation_id,
            actor=actor,
            granted_permissions=list(self.permissions.get_effective_permissions(actor)),
            environment={"state": inv.current_state.value},
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
                inv.evidence_store.add(ev)

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
