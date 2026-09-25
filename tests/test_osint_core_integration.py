"""Comprehensive integration tests proving the Core <-> OSINT Specialist boundary.

Validates:
1. Local autonomy, global coordination.
2. End-to-end execution of capabilities and workflows through Core.
3. Provenance preservation and EventBus dispatch.
4. Core remains domain-agnostic.
5. Architectural Test: A Network Specialist operates alongside OSINT Specialist
   without any Core modifications or cross-specialist coupling.
"""

from pathlib import Path
from typing import Any, Dict
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
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
from cyberclaw.specialists.osint.specialist import OSINTSpecialist
from cyberclaw.types import Source


def test_core_osint_end_to_end_lifecycle(tmp_path: Path):
    """Verify complete lifecycle of Core coordinating OSINT Specialist."""
    core_ws = tmp_path / "core_workspace"
    specialist_ws = tmp_path / "osint_workspace"

    # 1. Initialize Core
    core = CyberClawCore(workspace_path=core_ws)
    core.startup()

    # 2. Instantiate and register OSINT Specialist
    osint_specialist = OSINTSpecialist(workspace_base=specialist_ws)
    for cap in get_osint_capabilities():
        core.register_capability(cap)
    core.register_specialist(osint_specialist.as_specialist())

    # 3. Create Investigation
    inv = core.create_investigation(
        title="OSINT Target Reconnaissance",
        description="Passive discovery of external attack surface",
    )
    assert inv.current_state == CoreState.READY

    # Setup EventBus subscriber to verify event propagation
    received_events = []
    core.event_bus.subscribe("evidence.created", lambda e: received_events.append(e))
    core.event_bus.subscribe("experience.recorded", lambda e: received_events.append(e))

    # 4. Execute OSINT DNS Capability via Core
    result = core.execute_action(
        investigation_id=inv.id,
        capability_id=CAPABILITY_DNS_LOOKUP,
        parameters={"target": "target-corp.com"},
    )

    # 5. Verify Core ingested normalized evidence with preserved provenance
    assert result.is_success is True
    assert len(result.evidence) >= 1
    assert inv.evidence_store.count() >= 1

    ev = inv.evidence_store.list_all()[0]
    assert ev.subject == "target-corp.com"
    assert ev.provenance.specialist_id == "osint_specialist"
    assert ev.provenance.capability_id == CAPABILITY_DNS_LOOKUP
    assert ev.provenance.investigation_id == inv.id

    # 6. Verify EventBus published events
    assert len(received_events) >= 2
    types = [e.type for e in received_events]
    assert "evidence.created" in types
    assert "experience.recorded" in types

    # 7. Verify Core DFA progressed to INVESTIGATE
    assert inv.current_state == CoreState.INVESTIGATE

    # 8. Verify Core recorded actionable experience
    core_exp = core.experiences.list_all()
    assert len(core_exp) >= 1
    assert core_exp[0].success is True

    # 9. Verify Core persisted state and evidence
    loaded_ev = core.workspace.load_evidence(inv.id)
    assert len(loaded_ev) >= 1

    core.shutdown()


def test_core_osint_workflow_execution(tmp_path: Path):
    """Verify executing composite OSINT DomainTriageWorkflow through Core."""
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()

    osint_specialist = OSINTSpecialist(workspace_base=tmp_path / "osint")
    for cap in get_osint_capabilities():
        core.register_capability(cap)
    core.register_specialist(osint_specialist.as_specialist())
    # The workflow id is an advertisement. Execution still requires registration.
    core.register_capability(
        Capability(id="osint.workflow:domain_triage", name="Domain Passive Triage Workflow", category="osint")
    )

    inv = core.create_investigation(title="Triage Case")

    # Execute workflow
    result = core.execute_action(
        investigation_id=inv.id,
        capability_id="osint.workflow:domain_triage",
        parameters={"target": "victim-corp.com"},
    )

    assert result.is_success is True
    assert inv.evidence_store.count() >= 3
    evidence_types = {e.type for e in inv.evidence_store.list_all()}
    assert "osint.domain_metadata" in evidence_types
    assert "osint.dns_record" in evidence_types
    assert "osint.certificate" in evidence_types


def test_architectural_multi_specialist_coexistence(tmp_path: Path):
    """Section 13 Architectural Test:
    Demonstrates that a Network Specialist can be registered and operated
    alongside the OSINT Specialist using identical Core contracts without
    introducing OSINT-specific logic or coupling into Core.
    """
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()

    # 1. Register OSINT Specialist
    osint_specialist = OSINTSpecialist(workspace_base=tmp_path / "osint")
    for cap in get_osint_capabilities():
        core.register_capability(cap)
    core.register_specialist(osint_specialist.as_specialist())

    # 2. Construct Mock Network Specialist adhering to SpecialistEndpoint
    class MockNetworkEndpoint(SpecialistEndpoint):
        def health(self) -> SpecialistHealth:
            return SpecialistHealth.HEALTHY

        def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
            source = Source(type="network_probe", name="syn_scanner")
            ev = Evidence(
                type="network.port_scan",
                subject=request.parameters.get("target_ip", "10.0.0.1"),
                value={"open_ports": [22, 80, 443], "status": "active"},
                source=source,
            )
            res = ExecutionResult.success(evidence=[ev], output={"probed": True})
            return SpecialistResponse.from_result("network_specialist", request.request_id, res)

    net_endpoint = MockNetworkEndpoint()
    net_specialist = Specialist(
        id="network_specialist",
        name="CyberClaw Network Specialist",
        capabilities=["network.port_scan"],
        endpoint=net_endpoint,
        permissions=["network:read"],
    )
    core.register_capability(
        Capability(
            id="network.port_scan",
            name="Network Port Scan",
            category="network",
            required_permissions=["network:read"],
        )
    )
    core.register_specialist(net_specialist)

    # 3. Create single Core investigation coordinating both specialists
    inv = core.create_investigation(title="Multi-Specialist Joint Operation")

    # Step A: Invoke OSINT Specialist
    osint_res = core.execute_action(
        investigation_id=inv.id,
        capability_id=CAPABILITY_DNS_LOOKUP,
        parameters={"target": "victim-site.org"},
    )
    assert osint_res.is_success is True
    assert osint_res.evidence[0].provenance.specialist_id == "osint_specialist"

    # Step B: Invoke Network Specialist
    net_res = core.execute_action(
        investigation_id=inv.id,
        capability_id="network.port_scan",
        parameters={"target_ip": "93.184.216.34"},
    )
    assert net_res.is_success is True
    assert net_res.evidence[0].provenance.specialist_id == "network_specialist"

    # 4. Verify Core Evidence Store holds structured evidence from BOTH specialists
    all_evidence = inv.evidence_store.list_all()
    specialist_ids = {e.provenance.specialist_id for e in all_evidence}
    assert "osint_specialist" in specialist_ids
    assert "network_specialist" in specialist_ids

    # Core remains completely domain-agnostic: both specialists coexist seamlessly!
    core.shutdown()
