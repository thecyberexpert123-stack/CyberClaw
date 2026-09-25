"""Comprehensive verification suite for CyberClaw Core v0.1.

Validates the 15 explicit requirements from Section 26 and demonstrates
the complete Core v0.1 Definition of Done lifecycle from Section 36.
"""

from pathlib import Path
from typing import Any, Dict, Tuple
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.machine import InvalidTransitionError
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.permissions.manager import PermissionDeniedError
from cyberclaw.permissions.policy import ActionScope, PERM_CAPABILITY_EXECUTE
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source
from cyberclaw.validation.errors import SchemaValidationError


def _register_governed_capability(core: CyberClawCore, capability_id: str) -> Capability:
    """Advertisement is not registration.

    Authority hardening closed the path that materialized a capability from a
    specialist manifest. Tests that route to a specialist must register the
    capability explicitly.
    """
    capability = Capability(id=capability_id, name=capability_id)
    core.register_capability(capability)
    return capability


# --------------------------------------------------------------------------
# Controlled Test Fixtures & Mocks
# --------------------------------------------------------------------------

class MockSpecialistEndpoint(SpecialistEndpoint):
    """Controlled mock specialist endpoint for verifying contract boundaries."""

    def __init__(self, specialist_id: str = "mock_specialist") -> None:
        self.specialist_id = specialist_id
        self._health = SpecialistHealth.HEALTHY
        self.invocations = []

    def health(self) -> SpecialistHealth:
        return self._health

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        self.invocations.append(request)
        source = Source(type="specialist", name=self.specialist_id)
        target = request.parameters.get("target", "domain.mock")

        if request.parameters.get("simulate_failure"):
            res = ExecutionResult.failure(
                error="Controlled mock failure occurred",
                error_code="MOCK_FAILURE",
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)

        if request.parameters.get("simulate_empty"):
            res = ExecutionResult.success_empty(
                output={"queried_target": target, "findings_count": 0},
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)

        # Standard successful execution with findings
        ev = Evidence(
            type="observation",
            subject=target,
            value={"discovered_attribute": "sample_val", "score": 95},
            source=source,
            confidence=0.92,
        )
        res = ExecutionResult.success(
            evidence=[ev],
            output={"queried_target": target, "findings_count": 1},
            execution_id=request.context.execution_id,
        )
        return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)


class MockDirectProvider(CapabilityProvider):
    """Direct capability provider for testing non-specialist execution."""

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, str | None]:
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        source = Source(type="provider", name=self.name)
        ev = Evidence(
            type="direct_finding",
            subject=parameters.get("seed", "seed_default"),
            value={"hash": "abcd1234ef"},
            source=source,
        )
        return ExecutionResult.success(evidence=[ev], output={"executed": True})


# --------------------------------------------------------------------------
# Section 26 Verification: Minimum 15 Requirements
# --------------------------------------------------------------------------

def test_req_01_core_initializes(tmp_path: Path):
    """Req 1: Core initializes."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    assert core.is_running is True
    assert core.workspace.base_path.exists()
    assert (core.workspace.base_path / "skills").exists()
    core.shutdown()
    assert core.is_running is False


def test_req_02_specialist_can_register(tmp_path: Path):
    """Req 2: A specialist can register."""
    core = CyberClawCore(workspace_path=tmp_path)
    endpoint = MockSpecialistEndpoint("spec-osint")
    specialist = Specialist(
        id="spec-osint",
        name="Mock OSINT Specialist",
        version="0.1.0",
        capabilities=["intel.gather"],
        endpoint=endpoint,
        permissions=["network:read"],
    )
    core.register_specialist(specialist)

    registered = core.specialists.get_specialist("spec-osint")
    assert registered is not None
    assert registered.name == "Mock OSINT Specialist"
    assert registered.get_health() == SpecialistHealth.HEALTHY


def test_req_03_capability_can_register(tmp_path: Path):
    """Req 3: A capability can register."""
    core = CyberClawCore(workspace_path=tmp_path)
    cap = Capability(
        id="intel.gather",
        name="Gather Intelligence",
        category="reconnaissance",
        input_schema={"required": ["target"]},
    )
    core.register_capability(cap)

    registered_cap = core.capabilities.get_capability("intel.gather")
    assert registered_cap is not None
    assert registered_cap.name == "Gather Intelligence"
    assert registered_cap.category == "reconnaissance"


def test_req_04_investigation_can_be_created(tmp_path: Path):
    """Req 4: An investigation can be created."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation(
        title="Incident 2026-ALPHA",
        description="Suspicious activity triage",
    )

    assert inv.id is not None
    assert inv.title == "Incident 2026-ALPHA"
    # Starts at INITIALIZE then transitions to READY
    assert inv.current_state == CoreState.READY
    assert core.get_investigation(inv.id) is not None


def test_req_05_request_can_be_validated(tmp_path: Path):
    """Req 5: A request can be validated."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="param.check",
        name="Parameter Checker",
        input_schema={
            "required": ["mandatory_param"],
            "properties": {"mandatory_param": {"type": "string"}},
        },
    )
    core.register_capability(cap)
    inv = core.create_investigation(title="Validation Test")

    # Failing schema validation
    with pytest.raises(SchemaValidationError) as exc:
        core.execute_action(
            investigation_id=inv.id,
            capability_id="param.check",
            parameters={},  # Missing mandatory_param
        )
    assert "Missing required parameter 'mandatory_param'" in str(exc.value)


def test_req_06_request_can_be_routed_to_specialist(tmp_path: Path):
    """Req 6: A request can be routed to a specialist."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistEndpoint("spec-router")
    specialist = Specialist(
        id="spec-router",
        name="Router Specialist",
        capabilities=["route.test"],
        endpoint=endpoint,
    )
    core.register_specialist(specialist)
    _register_governed_capability(core, "route.test")
    inv = core.create_investigation(title="Routing Test")

    result = core.execute_action(
        investigation_id=inv.id,
        capability_id="route.test",
        parameters={"target": "target.domain"},
    )

    assert result.is_success is True
    assert len(endpoint.invocations) == 1
    assert endpoint.invocations[0].capability_id == "route.test"


def test_req_07_capability_can_execute_through_mock_provider(tmp_path: Path):
    """Req 7: A capability can execute through a controlled/mock provider."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(id="direct.cap", name="Direct Cap")
    core.register_capability(cap)
    provider = MockDirectProvider(id="mock_prov_1", name="Mock Prov", capability_id="direct.cap")
    core.register_provider(provider)

    inv = core.create_investigation(title="Provider Test")
    result = core.execute_action(
        investigation_id=inv.id,
        capability_id="direct.cap",
        parameters={"seed": "hash_sample"},
    )

    assert result.is_success is True
    assert len(result.evidence) == 1
    assert result.evidence[0].subject == "hash_sample"


def test_req_08_structured_evidence_object_can_be_produced(tmp_path: Path):
    """Req 8: A structured evidence object can be produced."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistEndpoint("spec-evidence")
    specialist = Specialist(
        id="spec-evidence",
        name="Evidence Specialist",
        capabilities=["evidence.sample"],
        endpoint=endpoint,
    )
    core.register_specialist(specialist)
    _register_governed_capability(core, "evidence.sample")
    inv = core.create_investigation(title="Evidence Test")

    result = core.execute_action(
        investigation_id=inv.id,
        capability_id="evidence.sample",
        parameters={"target": "subject-node"},
    )

    assert len(result.evidence) == 1
    ev = result.evidence[0]
    assert isinstance(ev, Evidence)
    assert ev.subject == "subject-node"
    assert ev.confidence == 0.92
    assert ev.provenance.investigation_id == inv.id
    assert ev.source.name == "spec-evidence"


def test_req_09_evidence_and_events_enter_core_communication_mechanism(tmp_path: Path):
    """Req 9: Evidence/events can enter the Core communication mechanism (EventBus)."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    received_events = []
    core.event_bus.subscribe("evidence.created", lambda e: received_events.append(e))

    endpoint = MockSpecialistEndpoint("spec-bus")
    specialist = Specialist(
        id="spec-bus",
        name="Bus Specialist",
        capabilities=["bus.action"],
        endpoint=endpoint,
    )
    core.register_specialist(specialist)
    _register_governed_capability(core, "bus.action")
    inv = core.create_investigation(title="Bus Test")

    core.execute_action(
        investigation_id=inv.id,
        capability_id="bus.action",
        parameters={"target": "bus-subject"},
    )

    assert len(received_events) >= 1
    assert received_events[0].type == "evidence.created"
    assert received_events[0].correlation_id == inv.id
    assert received_events[0].payload["count"] == 1


def test_req_10_dfa_state_transitions_correctly(tmp_path: Path):
    """Req 10: DFA state can transition correctly."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation(title="State Transition Test")
    assert inv.current_state == CoreState.READY

    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start_scan")
    assert inv.current_state == CoreState.INVESTIGATE

    core.transition_investigation(inv.id, CoreState.VERIFY, event="corroborate")
    assert inv.current_state == CoreState.VERIFY

    core.transition_investigation(inv.id, CoreState.RESOLVE, event="resolve_case")
    assert inv.current_state == CoreState.RESOLVE


def test_req_11_invalid_dfa_transitions_are_rejected(tmp_path: Path):
    """Req 11: Invalid transitions are rejected."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation(title="Invalid Transition Test")
    assert inv.current_state == CoreState.READY

    # Directly jumping from READY to RESOLVE without investigation/verification is illegal
    with pytest.raises(InvalidTransitionError) as exc:
        core.transition_investigation(inv.id, CoreState.RESOLVE, event="unverified_close")

    assert "not in the allowed transition table" in str(exc.value)
    assert inv.current_state == CoreState.READY


def test_req_12_experiences_are_recorded(tmp_path: Path):
    """Req 12: Experiences are recorded."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistEndpoint("spec-exp")
    specialist = Specialist(
        id="spec-exp",
        name="Experience Specialist",
        capabilities=["exp.action"],
        endpoint=endpoint,
    )
    core.register_specialist(specialist)
    _register_governed_capability(core, "exp.action")
    inv = core.create_investigation(title="Experience Test")

    core.execute_action(
        investigation_id=inv.id,
        capability_id="exp.action",
        parameters={"target": "exp-target"},
    )

    records = core.experiences.list_all()
    assert len(records) >= 1
    exp = records[0]
    assert exp.action == "execute:exp.action"
    assert exp.success is True
    assert "yielded 1 evidence findings" in exp.lesson
    assert exp.investigation_id == inv.id


def test_req_13_workspace_state_persists_correctly(tmp_path: Path):
    """Req 13: Workspace state persists correctly."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistEndpoint("spec-persist")
    specialist = Specialist(
        id="spec-persist",
        name="Persist Specialist",
        capabilities=["persist.action"],
        endpoint=endpoint,
    )
    core.register_specialist(specialist)
    _register_governed_capability(core, "persist.action")
    inv = core.create_investigation(title="Persistence Test")

    core.execute_action(
        investigation_id=inv.id,
        capability_id="persist.action",
        parameters={"target": "persist-node"},
    )

    # Verify workspace files are physically saved to disk
    inv_ws = core.workspace.get_investigation_workspace(inv.id)
    assert (inv_ws.root / "state.json").exists()
    assert (inv_ws.evidence / "evidence.json").exists()
    assert (inv_ws.experience / "experiences.json").exists()

    # Load back using workspace manager
    loaded_ev = core.workspace.load_evidence(inv.id)
    assert len(loaded_ev) == 1
    assert loaded_ev[0].subject == "persist-node"

    loaded_state = core.workspace.load_state(inv.id)
    assert loaded_state is not None
    assert loaded_state["id"] == inv.id
    assert loaded_state["title"] == "Persistence Test"


def test_req_14_permission_boundaries_are_enforced(tmp_path: Path):
    """Req 14: Permission boundaries are enforced."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="sensitive.action",
        name="Sensitive Action",
        required_permissions=["privileged:execute"],
    )
    core.register_capability(cap)
    inv = core.create_investigation(title="Permission Boundary Test")

    # Regular analyst who has standard view access but lacks privileged:execute
    core.permissions.assign_role("untrusted_analyst", "analyst")

    with pytest.raises(Exception) as exc:
        core.execute_action(
            investigation_id=inv.id,
            capability_id="sensitive.action",
            parameters={},
            actor="untrusted_analyst",
        )
    assert "lacks permission 'privileged:execute'" in str(exc.value)


def test_req_15_failure_and_empty_result_states_remain_distinguishable(tmp_path: Path):
    """Req 15: Failure and empty-result states remain distinguishable."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistEndpoint("spec-distinguish")
    specialist = Specialist(
        id="spec-distinguish",
        name="Distinguish Specialist",
        capabilities=["distinguish.action"],
        endpoint=endpoint,
    )
    core.register_specialist(specialist)
    _register_governed_capability(core, "distinguish.action")
    inv = core.create_investigation(title="Distinction Test")

    # 1. Empty findings execution
    empty_result = core.execute_action(
        investigation_id=inv.id,
        capability_id="distinguish.action",
        parameters={"target": "empty-target", "simulate_empty": True},
    )
    assert empty_result.status == ExecutionStatus.SUCCESS_EMPTY
    assert empty_result.is_empty is True
    assert empty_result.is_failure is False
    assert len(empty_result.evidence) == 0

    # 2. Failure execution
    failure_result = core.execute_action(
        investigation_id=inv.id,
        capability_id="distinguish.action",
        parameters={"target": "fail-target", "simulate_failure": True},
    )
    assert failure_result.status == ExecutionStatus.FAILURE
    assert failure_result.is_empty is False
    assert failure_result.is_failure is True
    assert failure_result.error == "Controlled mock failure occurred"

    # Distinct states verified in recorded experiences
    experiences = core.experiences.list_all()
    assert any(e.result_status == ExecutionStatus.SUCCESS_EMPTY for e in experiences)
    assert any(e.result_status == ExecutionStatus.FAILURE for e in experiences)


# --------------------------------------------------------------------------
# Section 36: Complete Core v0.1 Lifecycle Integration Test
# --------------------------------------------------------------------------

def test_section_36_full_lifecycle_end_to_end(tmp_path: Path):
    """Demonstrate the entire end-to-end lifecycle described in Section 36:
    Core Startup
        ↓
    Investigation Created
        ↓
    DFA State Established
        ↓
    Specialist Registered
        ↓
    Capability Available
        ↓
    Request Validated
        ↓
    Specialist Invoked
        ↓
    Result Produced
        ↓
    Evidence Structured
        ↓
    Event / Evidence Propagated
        ↓
    DFA Updated
        ↓
    Experience Recorded
        ↓
    State Persisted
        ↓
    Tests Pass
    """
    # 1. Core Startup
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    assert core.is_running is True

    # 2. Investigation Created
    inv = core.create_investigation(
        title="APT Incident Triaging",
        description="Investigation into host anomalous behavior",
    )
    assert inv is not None

    # 3. DFA State Established (INITIALIZE -> READY)
    assert inv.current_state == CoreState.READY

    # 4. Specialist Registered
    endpoint = MockSpecialistEndpoint("recon_specialist")
    specialist = Specialist(
        id="recon_specialist",
        name="Reconnaissance Specialist",
        version="0.1.0",
        capabilities=["recon.entity_inspection"],
        endpoint=endpoint,
    )
    core.register_specialist(specialist)

    # 5. Capability Available
    cap = Capability(
        id="recon.entity_inspection",
        name="Entity Inspection",
        category="reconnaissance",
        input_schema={
            "required": ["target"],
            "properties": {"target": {"type": "string"}},
        },
    )
    core.register_capability(cap)

    # 6. Request Validated & 7. Specialist Invoked & 8. Result Produced
    result = core.execute_action(
        investigation_id=inv.id,
        capability_id="recon.entity_inspection",
        parameters={"target": "10.10.10.50"},
    )

    # 9. Evidence Structured
    assert result.is_success is True
    assert len(result.evidence) == 1
    evidence_item = result.evidence[0]
    assert evidence_item.subject == "10.10.10.50"
    assert evidence_item.confidence == 0.92
    assert evidence_item.provenance.specialist_id == "recon_specialist"
    assert inv.evidence_store.count() == 1

    # 10. Event / Evidence Propagated across EventBus
    bus_history = core.event_bus.get_history(correlation_id=inv.id)
    event_types = [e.type for e in bus_history]
    assert "investigation.created" in event_types
    assert "evidence.created" in event_types
    assert "experience.recorded" in event_types

    # 11. DFA Updated (from READY to INVESTIGATE upon action execution)
    assert inv.current_state == CoreState.INVESTIGATE

    # Transition to VERIFY and RESOLVE
    core.transition_investigation(inv.id, CoreState.VERIFY, event="verify_findings")
    assert inv.current_state == CoreState.VERIFY

    core.transition_investigation(inv.id, CoreState.RESOLVE, event="resolve_investigation")
    assert inv.current_state == CoreState.RESOLVE

    # 12. Experience Recorded with actionable lesson
    investigation_experiences = core.experiences.find_by_scope("capability:recon.entity_inspection")
    assert len(investigation_experiences) == 1
    assert investigation_experiences[0].success is True
    assert "10.10.10.50" in str(investigation_experiences[0].conditions)

    # 13. State Persisted to disk
    persisted_state = core.workspace.load_state(inv.id)
    assert persisted_state is not None
    assert persisted_state["current_state"] == CoreState.RESOLVE.value

    persisted_evidence = core.workspace.load_evidence(inv.id)
    assert len(persisted_evidence) == 1
    assert persisted_evidence[0].subject == "10.10.10.50"

    # Observability checks: full audit log of operations exists
    logs = core.logger.get_records(correlation_id=inv.id)
    assert len(logs) >= 3
    # Answering: What happened? What state? Why?
    exec_log = [l for l in logs if l.operation == "capability.execute"][0]
    assert exec_log.state == CoreState.INVESTIGATE.value
    assert len(exec_log.evidence_ids) == 1

    core.shutdown()
