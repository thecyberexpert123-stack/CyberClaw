"""OSINT Specialist v0.1: Autonomous passive intelligence subsystem.

Local autonomy, global coordination.
Encapsulates local DFA, local investigation model, capabilities, providers,
local memory, experience, and isolated workspace behind SpecialistEndpoint.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
    CAPABILITY_WHOIS_LOOKUP,
    get_osint_capabilities,
)
from cyberclaw.specialists.osint.dfa.machine import OSINTDFA
from cyberclaw.specialists.osint.dfa.states import OSINTState
from cyberclaw.specialists.osint.investigation import (
    OSINTInvestigation,
    OSINTTargetType,
    classify_target,
)
from cyberclaw.specialists.osint.memory.store import (
    OSINTExperienceStore,
    OSINTLocalMemory,
)
from cyberclaw.specialists.osint.providers.base import OSINTProvider
from cyberclaw.specialists.osint.providers.mock_providers import (
    MockCertMetadataProvider,
    MockDnsLookupProvider,
    MockDomainMetadataProvider,
    MockWhoisLookupProvider,
)
from cyberclaw.specialists.osint.workflows.base import OSINTWorkflow
from cyberclaw.specialists.osint.workflows.domain_triage import DomainTriageWorkflow
from cyberclaw.specialists.osint.workspace.manager import OSINTWorkspaceManager


class OSINTSpecialist(SpecialistEndpoint):
    """The OSINT Specialist subsystem.

    Coordinates all OSINT investigations internally. Interacts with Core
    exclusively through the SpecialistEndpoint contract.
    """

    SPECIALIST_ID = "osint_specialist"
    SPECIALIST_NAME = "CyberClaw OSINT Specialist"
    VERSION = "0.1.0"

    def __init__(
        self,
        workspace_base: Optional[Path] = None,
        use_default_mock_providers: bool = True,
    ) -> None:
        self.workspace = OSINTWorkspaceManager(workspace_base)
        self.memory = OSINTLocalMemory()
        self.experiences = OSINTExperienceStore()

        # Local provider registry: capability_id -> list of OSINTProvider
        self._providers: Dict[str, List[OSINTProvider]] = {}
        # Local workflow registry: workflow_id -> OSINTWorkflow
        self._workflows: Dict[str, OSINTWorkflow] = {}
        # Local active investigations: investigation_id -> OSINTInvestigation
        self._active_investigations: Dict[str, OSINTInvestigation] = {}
        # Health state
        self._health = SpecialistHealth.HEALTHY

        # Register default workflows
        self.register_workflow(DomainTriageWorkflow())

        # Register default mock providers for offline deterministic operation
        if use_default_mock_providers:
            self.register_provider(MockDomainMetadataProvider())
            self.register_provider(MockDnsLookupProvider())
            self.register_provider(MockCertMetadataProvider())
            self.register_provider(MockWhoisLookupProvider())

    # --------------------------------------------------------------------------
    # SpecialistEndpoint Contract
    # --------------------------------------------------------------------------

    def health(self) -> SpecialistHealth:
        """Report current health of the OSINT Specialist."""
        return self._health

    def set_health(self, health: SpecialistHealth) -> None:
        """Explicitly override health status (e.g. for testing degraded states)."""
        self._health = health

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        """Execute a requested action or capability behind the contract boundary."""
        # 1. Obtain or initialize local investigation context
        local_inv = self._get_or_create_local_investigation(
            investigation_id=request.investigation_id,
            target=request.parameters.get("target", "unknown"),
        )

        try:
            # 2. Local DFA: Transition to TARGET_RECEIVED
            if local_inv.current_state == OSINTState.READY:
                local_inv.dfa.transition(OSINTState.TARGET_RECEIVED, event="target.received")

            # 3. Local DFA: Classify target
            if local_inv.current_state == OSINTState.TARGET_RECEIVED:
                target_type = classify_target(local_inv.target)
                local_inv.target_type = target_type
                local_inv.dfa.transition(
                    OSINTState.CLASSIFY,
                    event="target.classified",
                    context={"target_type": target_type.value},
                )
                self.memory.cache_target_info(
                    local_inv.target, {"target_type": target_type.value}
                )

            # 4. Local DFA: Formulate Plan
            if local_inv.current_state == OSINTState.CLASSIFY:
                local_inv.dfa.transition(
                    OSINTState.PLAN,
                    event="plan.established",
                    context={"capability": request.capability_id},
                )

            # 5. Execute capability or workflow
            result = self._execute_request_action(request, local_inv)

            # 6. Post-execution local state updates
            if result.is_failure:
                # Local DFA transition to FAILED
                if local_inv.dfa.can_transition(OSINTState.FAILED)[0]:
                    local_inv.dfa.transition(OSINTState.FAILED, event="execution.failed")
            else:
                # Ingest evidence into local investigation
                for ev in result.evidence:
                    local_inv.add_evidence(ev)

                # Local DFA transitions: VERIFY -> COMPLETE
                if local_inv.current_state in (OSINTState.COLLECT, OSINTState.CORRELATE):
                    if local_inv.dfa.can_transition(OSINTState.VERIFY)[0]:
                        local_inv.dfa.transition(OSINTState.VERIFY, event="findings.verified")
                    if local_inv.dfa.can_transition(OSINTState.COMPLETE)[0]:
                        local_inv.dfa.transition(OSINTState.COMPLETE, event="investigation.complete")

            # 7. Record local experience
            self.experiences.record_provider_run(
                capability_id=request.capability_id,
                provider_id="osint.dispatcher",
                target=local_inv.target,
                result=result,
                investigation_id=request.investigation_id,
            )

            # 8. Persist to specialist local workspace
            self.workspace.persist_local_evidence(request.investigation_id, local_inv.evidence)
            self.workspace.persist_investigation_state(request.investigation_id, local_inv.to_dict())

            return SpecialistResponse.from_result(
                specialist_id=self.SPECIALIST_ID,
                request_id=request.request_id,
                result=result,
                metadata={
                    "local_state": local_inv.current_state.value,
                    "target_type": local_inv.target_type.value,
                },
            )

        except Exception as exc:
            # Deterministically handle unexpected exceptions
            if local_inv.dfa.can_transition(OSINTState.FAILED)[0]:
                local_inv.dfa.transition(OSINTState.FAILED, event="exception.caught")

            fail_res = ExecutionResult.failure(
                error=f"OSINT Specialist internal failure: {str(exc)}",
                error_code="OSINT_INTERNAL_EXCEPTION",
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(
                specialist_id=self.SPECIALIST_ID,
                request_id=request.request_id,
                result=fail_res,
                metadata={"local_state": local_inv.current_state.value},
            )

    # --------------------------------------------------------------------------
    # Internal Execution Routing & Provider Selection
    # --------------------------------------------------------------------------

    def _execute_request_action(
        self,
        request: SpecialistRequest,
        local_inv: OSINTInvestigation,
    ) -> ExecutionResult:
        """Route to workflow or specific capability provider."""
        capability_id = request.capability_id

        # Case A: Composite Workflow Execution
        if capability_id in self._workflows or capability_id.startswith("osint.workflow:"):
            wf_id = capability_id
            workflow = self._workflows.get(wf_id)
            if not workflow:
                return ExecutionResult.failure(
                    error=f"Workflow '{wf_id}' not found in OSINT Specialist",
                    error_code="WORKFLOW_NOT_FOUND",
                    execution_id=request.context.execution_id,
                )

            # Local DFA transition: PLAN -> COLLECT
            if local_inv.current_state == OSINTState.PLAN:
                local_inv.dfa.transition(OSINTState.COLLECT, event="workflow.collection_started")

            # Execute workflow using specialist capability invoker callback
            def invoker(cap_id: str, params: Dict[str, Any], ctx: ExecutionContext) -> ExecutionResult:
                return self.execute_local_capability(cap_id, params, ctx)

            res = workflow.execute(request.parameters, request.context, invoker)

            # Local DFA transition: COLLECT -> CORRELATE
            if local_inv.current_state == OSINTState.COLLECT:
                local_inv.dfa.transition(OSINTState.CORRELATE, event="correlating_workflow_findings")

            return res

        # Case B: Direct Capability Execution
        # Local DFA transition: PLAN -> COLLECT
        if local_inv.current_state == OSINTState.PLAN:
            local_inv.dfa.transition(OSINTState.COLLECT, event="capability.collection_started")

        return self.execute_local_capability(capability_id, request.parameters, request.context)

    def execute_local_capability(
        self,
        capability_id: str,
        parameters: Dict[str, Any],
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Select a ready provider and execute capability with fallback support."""
        providers = self._providers.get(capability_id, [])
        if not providers:
            return ExecutionResult.failure(
                error=f"No provider registered in OSINT Specialist for capability '{capability_id}'",
                error_code="NO_OSINT_PROVIDER",
                execution_id=context.execution_id,
            )

        # Provider Selection: pick highest priority provider that is ready
        selected_provider: Optional[OSINTProvider] = None
        unready_reasons: List[str] = []

        for p in providers:
            ready, reason = p.is_ready(context)
            if ready:
                selected_provider = p
                break
            unready_reasons.append(f"{p.id}: {reason}")

        if not selected_provider:
            return ExecutionResult.failure(
                error=f"All providers for '{capability_id}' are unready: {'; '.join(unready_reasons)}",
                error_code="ALL_PROVIDERS_UNREADY",
                execution_id=context.execution_id,
            )

        # Execute chosen provider
        result = selected_provider.execute(parameters, context)

        # If primary provider experienced an operational failure, attempt fallback if available
        if result.is_failure and len(providers) > 1:
            for fallback in providers:
                if fallback.id != selected_provider.id:
                    ready, _ = fallback.is_ready(context)
                    if ready:
                        fallback_result = fallback.execute(parameters, context)
                        if fallback_result.completed_normally:
                            fallback_result.metadata["fallback_from"] = selected_provider.id
                            return fallback_result

        return result

    # --------------------------------------------------------------------------
    # Registration & Configuration
    # --------------------------------------------------------------------------

    def register_provider(self, provider: OSINTProvider) -> None:
        """Register an OSINT capability provider with priority ordering."""
        prov_list = self._providers.setdefault(provider.capability_id, [])
        # Avoid duplicate registration
        prov_list = [p for p in prov_list if p.id != provider.id]
        prov_list.append(provider)
        # Sort descending by priority
        prov_list.sort(key=lambda p: p.priority, reverse=True)
        self._providers[provider.capability_id] = prov_list

    def get_providers(self, capability_id: str) -> List[OSINTProvider]:
        return list(self._providers.get(capability_id, []))

    def register_workflow(self, workflow: OSINTWorkflow) -> None:
        """Register an OSINT investigative workflow."""
        self._workflows[workflow.id] = workflow

    def list_capabilities(self) -> List[str]:
        """List all capabilities and workflows advertised by this Specialist."""
        caps = [
            CAPABILITY_DOMAIN_METADATA,
            CAPABILITY_DNS_LOOKUP,
            CAPABILITY_CERT_METADATA,
            CAPABILITY_WHOIS_LOOKUP,
        ]
        caps.extend(self._workflows.keys())
        return caps

    def as_specialist(self) -> Specialist:
        """Produce the Core-compatible Specialist contract object."""
        return Specialist(
            id=self.SPECIALIST_ID,
            name=self.SPECIALIST_NAME,
            version=self.VERSION,
            capabilities=self.list_capabilities(),
            endpoint=self,
            permissions=["network:read"],
            metadata={"description": "Autonomous passive OSINT intelligence subsystem"},
        )

    # --------------------------------------------------------------------------
    # Internal Helpers
    # --------------------------------------------------------------------------

    def _get_or_create_local_investigation(
        self,
        investigation_id: str,
        target: str,
    ) -> OSINTInvestigation:
        if investigation_id in self._active_investigations:
            return self._active_investigations[investigation_id]

        inv = OSINTInvestigation(
            investigation_id=investigation_id,
            target=target,
        )
        inv.dfa.transition(OSINTState.READY, event="specialist.initialized")
        self._active_investigations[investigation_id] = inv
        return inv
