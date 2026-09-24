"""Multi-specialist coordination, failure isolation, and Section 22 End-to-End lifecycle tests."""

from pathlib import Path
from typing import Any, Dict
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.coordination.requirements import RequirementStatus
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
from cyberclaw.specialists.network.specialist import NetworkSpecialist
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
    get_osint_capabilities,
)
from cyberclaw.specialists.osint.specialist import OSINTSpecialist
from cyberclaw.types import Source


def test_failure_isolation_between_specialists(tmp_path: Path):
    """Verify Section 18: One specialist failing does not corrupt the global investigation."""
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()

    # 1. Register OSINT Specialist (Healthy)
    osint_spec = OSINTSpecialist(workspace_base=tmp_path / "osint")
    for cap in get_osint_capabilities():
        core.register_capability(cap)
    core.register_specialist(osint_spec.as_specialist())

    # 2. Register Network Specialist (Simulates Failure)
    net_spec = NetworkSpecialist(workspace_base=tmp_path / "network")
    for cap_id in net_spec.list_capabilities():
        core.register_capability(
            Capability(id=cap_id, name=cap_id, category="network", required_permissions=["network:read"])
        )
    core.register_specialist(net_spec.as_specialist())

    inv = core.create_investigation(title="Failure Isolation Test")

    # Step A: OSINT succeeds
    req_osint = core.create_information_requirement(
        investigation_id=inv.id,
        description="Lookup DNS for target",
        target_or_entity="secure-target.com",
        assigned_capability_id=CAPABILITY_DNS_LOOKUP,
    )
    res_osint = core.fulfill_information_requirement(inv.id, req_osint.id)
    assert res_osint.status == RequirementStatus.SATISFIED
    assert inv.evidence_store.count() >= 1

    # Step B: Network fails
    req_net = core.create_information_requirement(
        investigation_id=inv.id,
        description="Scan ports on IP",
        target_or_entity="192.168.1.100",
        assigned_capability_id=NetworkSpecialist.CAPABILITY_PORT_SCAN,
    )
    res_net = core.fulfill_information_requirement(inv.id, req_net.id, parameters={"simulate_failure": True})
    assert res_net.status == RequirementStatus.FAILED
    assert "Host unreachable" in res_net.error

    # Verify Global Investigation state remains healthy, valid, and uncorrupted
    assert inv.current_state.value in ("READY", "INVESTIGATE")
    assert len(inv.information_requirements) == 2
    assert inv.evidence_store.count() >= 1
    assert "osint_specialist" in inv.participating_specialists
    assert "network_specialist" in inv.participating_specialists

    core.shutdown()


def test_specialist_workspace_isolation(tmp_path: Path):
    """Verify Section 19: One specialist cannot read/write another specialist's workspace."""
    osint_spec = OSINTSpecialist(workspace_base=tmp_path / "osint")
    net_spec = NetworkSpecialist(workspace_base=tmp_path / "network")

    # OSINT workspace manager strictly prevents writing into network specialist workspace
    with pytest.raises(PermissionError):
        target_in_net = net_spec.workspace_base / "tampered.txt"
        osint_spec.workspace.atomic_write(target_in_net, "unauthorized content")


def test_coexistence_with_future_specialist(tmp_path: Path):
    """Verify Section 24: Core coordinates OSINT, Network, and an Unknown Future Specialist without modifying Core."""
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()

    # Register OSINT
    osint = OSINTSpecialist(workspace_base=tmp_path / "osint")
    for cap in get_osint_capabilities():
        core.register_capability(cap)
    core.register_specialist(osint.as_specialist())

    # Register Network
    network = NetworkSpecialist(workspace_base=tmp_path / "network")
    for cap_id in network.list_capabilities():
        core.register_capability(Capability(id=cap_id, name=cap_id, category="network"))
    core.register_specialist(network.as_specialist())

    # Register an Unknown Future Specialist (e.g. Forensics / Cloud Specialist)
    class FutureCloudSpecialist(SpecialistEndpoint):
        def health(self) -> SpecialistHealth:
            return SpecialistHealth.HEALTHY

        def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
            ev = Evidence(
                type="cloud.iam_audit",
                subject=request.parameters.get("target", "cloud_env"),
                value={"mfa_enabled": True, "stale_roles": 0},
                source=Source(type="cloud_scanner", name="cloud_prov"),
            )
            return SpecialistResponse.from_result("cloud_specialist", request.request_id, ExecutionResult.success(evidence=[ev]))

    core.register_capability(Capability(id="cloud.audit", name="Cloud Audit", category="cloud"))
    core.register_specialist(
        Specialist(
            id="cloud_specialist",
            name="Future Cloud Specialist",
            capabilities=["cloud.audit"],
            endpoint=FutureCloudSpecialist(),
        )
    )

    inv = core.create_investigation(title="Multi-Specialist Coexistence")

    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Audit cloud IAM configuration",
        target_or_entity="prod_aws_account",
        assigned_capability_id="cloud.audit",
    )
    res = core.fulfill_information_requirement(inv.id, req.id)

    assert res.status == RequirementStatus.SATISFIED
    assert "cloud_specialist" in inv.participating_specialists
    assert inv.evidence_store.count() == 1

    core.shutdown()


def test_section_22_end_to_end_coordination_demonstration(tmp_path: Path):
    """Section 22 End-to-End Demonstration:
    Create Investigation
          ↓
    Initial Information Requirement
          ↓
    OSINT Specialist
          ↓
    Domain Evidence
          ↓
    IP Evidence
          ↓
    Correlation (Extracts IP entity & resolves_to link)
          ↓
    New Network Information Requirement (Targeting discovered IP)
          ↓
    Network Specialist
          ↓
    Network Evidence (Open Ports / Services)
          ↓
    Cross-Specialist Correlation (Domain -> IP -> Service)
          ↓
    Hypothesis Updated
          ↓
    Investigation Update
    """
    # 1. Initialize Core & Event Monitoring
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()

    events_captured = []
    core.event_bus.subscribe_all(lambda e: events_captured.append(e))

    # 2. Register OSINT Specialist
    osint_spec = OSINTSpecialist(workspace_base=tmp_path / "osint")
    for cap in get_osint_capabilities():
        core.register_capability(cap)
    core.register_specialist(osint_spec.as_specialist())

    # 3. Register Network Specialist
    net_spec = NetworkSpecialist(workspace_base=tmp_path / "network")
    for cap_id in net_spec.list_capabilities():
        core.register_capability(
            Capability(id=cap_id, name=cap_id, category="network", required_permissions=["network:read"])
        )
    core.register_specialist(net_spec.as_specialist())

    # 4. Create Global Investigation
    inv = core.create_investigation(
        title="Joint Cross-Specialist Operation",
        description="Multi-specialist reconnaissance on suspicious target",
    )
    assert inv.current_state == CoreState.READY

    # 5. Formulate initial hypothesis
    hyp = core.create_hypothesis(
        investigation_id=inv.id,
        statement="Target apex-corp.org hosts active web application infrastructure",
    )
    assert hyp.status == "OPEN"

    # 6. Create Initial Information Requirement: Need DNS records for domain
    req1 = core.create_information_requirement(
        investigation_id=inv.id,
        description="Obtain DNS resource records for domain",
        target_or_entity="apex-corp.org",
        evidence_types_sought=["osint.dns_record"],
    )
    assert req1.status == RequirementStatus.OPEN

    # 7. Core routes requirement to OSINT Specialist
    fulfilled_req1 = core.fulfill_information_requirement(inv.id, req1.id)
    assert fulfilled_req1.status == RequirementStatus.SATISFIED
    assert fulfilled_req1.assigned_specialist_id == "osint_specialist"
    assert inv.evidence_store.count() >= 1

    # 8. Run Correlation Engine: Derives Domain entity, IP entity, and observed resolves_to relationship
    corr_res1 = core.correlate_investigation(inv.id)
    assert len(inv.entities) >= 2
    assert "apex-corp.org" in inv.entities
    # Discovered IP entity from DNS
    discovered_ip = [e.name for e in inv.entities.values() if e.type == "ip"][0]
    assert discovered_ip == "93.184.216.34"

    # Check observed relationship was established with evidence provenance
    resolves_links = [r for r in inv.relationships if r.relation_type == "resolves_to"]
    assert len(resolves_links) >= 1
    assert resolves_links[0].source_id == "apex-corp.org"
    assert resolves_links[0].target_id == discovered_ip
    assert resolves_links[0].is_inferred is False

    # 9. Create New Network Information Requirement for the discovered IP
    req2 = core.create_information_requirement(
        investigation_id=inv.id,
        description=f"Scan network ports on newly discovered IP {discovered_ip}",
        target_or_entity=discovered_ip,
        evidence_types_sought=["network.port_scan"],
        dependencies=[fulfilled_req1.id],
    )

    # 10. Core routes requirement to Network Specialist
    fulfilled_req2 = core.fulfill_information_requirement(inv.id, req2.id)
    assert fulfilled_req2.status == RequirementStatus.SATISFIED
    assert fulfilled_req2.assigned_specialist_id == "network_specialist"

    # 11. Run Cross-Specialist Correlation Engine
    # Links Domain -> IP (from OSINT) and IP -> Service (from Network)
    corr_res2 = core.correlate_investigation(inv.id)
    assert len(inv.entities) >= 3  # Domain + IP + Service entities
    service_entities = [e.name for e in inv.entities.values() if e.type == "service"]
    assert len(service_entities) >= 1

    # Check network service relationship
    service_links = [r for r in inv.relationships if r.relation_type == "exposes_service"]
    assert len(service_links) >= 1
    assert service_links[0].source_id == discovered_ip
    assert service_links[0].is_inferred is False

    # 12. Evaluate Hypothesis based on cross-specialist findings
    evaluated_hyps = core.evaluate_hypotheses(inv.id)
    assert len(evaluated_hyps) == 1
    h = evaluated_hyps[0]
    assert h.status == "SUPPORTED"
    assert h.confidence > 0.7
    assert len(h.supporting_evidence_ids) >= 2

    # 13. Verify Event Bus published all coordination events
    event_types = [e.type for e in events_captured]
    assert "requirement.created" in event_types
    assert "requirement.assigned" in event_types
    assert "specialist.invoked" in event_types
    assert "evidence.created" in event_types
    assert "relationship.created" in event_types
    assert "requirement.completed" in event_types
    assert "hypothesis.updated" in event_types
    assert "investigation.updated" in event_types

    # 14. Verify Investigation state summary and persistence
    persisted_state = core.workspace.load_state(inv.id)
    assert persisted_state is not None
    assert "osint_specialist" in persisted_state["participating_specialists"]
    assert "network_specialist" in persisted_state["participating_specialists"]
    assert persisted_state["requirements_count"] == 2
    assert persisted_state["relationships_count"] >= 2

    core.shutdown()
