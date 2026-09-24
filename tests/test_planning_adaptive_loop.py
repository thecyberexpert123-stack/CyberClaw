"""Tests for the Adaptive Planning Loop across multiple specialists and unknown future specialists."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.core import CyberClawCore
from cyberclaw.evidence.models import Evidence, Observation, Provenance
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.planning.models import StoppingCondition
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source


class MockOsintEndpoint(SpecialistEndpoint):
    """Simulates OSINT specialist endpoint returning certificate evidence."""

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        domain = request.parameters.get("domain") or request.parameters.get("target") or "target.corp"
        ev = Evidence(
            type="osint.certificate",
            subject=domain,
            value={"san": "api.target.corp", "ip": "198.51.100.25", "issuer": "Let's Encrypt"},
            source=Source(type="mock_cert_provider", name="cert_authority"),
            provenance=Provenance(specialist_id="specialist.osint", execution_id=request.request_id),
            confidence=0.9,
        )
        return SpecialistResponse.from_result("specialist.osint", request.request_id, ExecutionResult.success(evidence=[ev]))


class MockNetworkEndpoint(SpecialistEndpoint):
    """Simulates Network specialist endpoint returning open port evidence."""

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        target = request.parameters.get("target") or "198.51.100.25"
        ev = Evidence(
            type="network.port_scan",
            subject=target,
            value={"ports": {"443": {"state": "open", "service": "https"}}},
            source=Source(type="mock_port_scanner", name="port_scanner"),
            provenance=Provenance(specialist_id="specialist.network", execution_id=request.request_id),
            confidence=0.95,
        )
        return SpecialistResponse.from_result("specialist.network", request.request_id, ExecutionResult.success(evidence=[ev]))


class FutureSatelliteEndpoint(SpecialistEndpoint):
    """Simulates an unknown future specialist (e.g. satellite recon) endpoint."""

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        ev = Evidence(
            type="satellite.imagery",
            subject=request.parameters.get("target", "coords"),
            value={"datacenter_detected": True, "confidence": 0.88},
            source=Source(type="mock_satellite", name="satellite_feed"),
            provenance=Provenance(specialist_id="specialist.satellite", execution_id=request.request_id),
            confidence=0.88,
        )
        return SpecialistResponse.from_result("specialist.satellite", request.request_id, ExecutionResult.success(evidence=[ev]))


def test_adaptive_investigation_multi_cycle_loop(tmp_path):
    """Verify full adaptive planning loop: OSINT cert -> IP discovery -> Network port scan -> Loop completion."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register OSINT and Network capabilities and specialists
    osint_spec = Specialist(
        id="specialist.osint",
        name="OSINT Specialist",
        capabilities=["osint.cert_metadata", "osint.dns_lookup"],
        endpoint=MockOsintEndpoint(),
    )
    network_spec = Specialist(
        id="specialist.network",
        name="Network Specialist",
        capabilities=["network.port_scan"],
        endpoint=MockNetworkEndpoint(),
    )
    core.register_specialist(osint_spec)
    core.register_specialist(network_spec)

    core.register_capability(Capability(id="osint.cert_metadata", name="Cert Metadata", description="Cert lookup"))
    core.register_capability(Capability(id="network.port_scan", name="Port Scan", description="Port scanning"))

    # Create investigation
    inv = core.create_investigation("Adaptive Recon", targets=["target.corp"])
    inv.add_entity("domain", "target.corp")

    # Run adaptive investigation
    plans = core.run_adaptive_investigation(inv.id, max_cycles=3)

    assert len(plans) >= 1

    # Cycle 1 should plan certificate metadata for target.corp
    plan_c1 = plans[0]
    assert any(c.target_or_entity == "target.corp" for c in plan_c1.candidate_next_requirements)

    # After cycle 1 execution, add IP entity discovered in observation
    inv.add_entity("ip", "198.51.100.25")

    # Cycle 2 should propose port scan on discovered IP
    plans_subsequent = core.run_adaptive_investigation(inv.id, max_cycles=2)
    plan_c2 = plans_subsequent[0]
    assert any(c.target_or_entity == "198.51.100.25" for c in plan_c2.candidate_next_requirements)

    core.shutdown()


def test_future_specialist_architectural_coexistence(tmp_path):
    """Verify unknown FutureSpecialist operates seamlessly with planning without domain conditionals in Core."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    future_spec = Specialist(
        id="specialist.satellite",
        name="Satellite Recon Specialist",
        capabilities=["satellite.imagery_analysis"],
        endpoint=FutureSatelliteEndpoint(),
    )
    core.register_specialist(future_spec)
    core.register_capability(
        Capability(id="satellite.imagery_analysis", name="Satellite Analysis", description="Satellite imagery")
    )

    inv = core.create_investigation("Satellite Recon", targets=["site-alpha"])

    # Manually create requirement for future specialist capability
    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Analyze site-alpha satellite imagery",
        target_or_entity="site-alpha",
        assigned_capability_id="satellite.imagery_analysis",
    )

    # Core fulfills requirement without any specialist-specific conditional logic
    fulfilled_req = core.fulfill_information_requirement(
        investigation_id=inv.id,
        requirement_id=req.id,
        parameters={"target": "site-alpha"},
    )

    assert fulfilled_req.status.value == "SATISFIED"
    evs = inv.evidence_store.list_all()
    assert len(evs) == 1
    assert evs[0].type == "satellite.imagery"
    assert evs[0].provenance.specialist_id == "specialist.satellite"

    core.shutdown()


def test_contradiction_resolution_planning_cycle(tmp_path):
    """Verify unresolved contradiction generates targeted resolution requirement candidate."""
    from cyberclaw.correlation.models import ContradictionRecord

    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register OSINT whois capability
    class WhoisSpecialistEndpoint(SpecialistEndpoint):
        def health(self) -> SpecialistHealth:
            return SpecialistHealth.HEALTHY

        def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
            ev = Evidence(
                type="osint.whois",
                subject="conflicted.com",
                value={"registrar": "Authoritative Corp LLC"},
                source=Source(type="whois_server", name="arin"),
                confidence=0.99,
            )
            return SpecialistResponse.from_result("specialist.osint", request.request_id, ExecutionResult.success(evidence=[ev]))

    core.register_specialist(
        Specialist(
            id="specialist.osint.whois",
            name="OSINT Whois",
            capabilities=["osint.whois_lookup"],
            endpoint=WhoisSpecialistEndpoint(),
        )
    )
    core.register_capability(
        Capability(id="osint.whois_lookup", name="Whois Lookup", description="Authoritative registry query")
    )

    inv = core.create_investigation("Conflict Resolution", targets=["conflicted.com"])
    # Seed supporting evidence points referenced by contradiction
    ev1 = Evidence(
        id="ev-1",
        type="osint.dns_record",
        subject="conflicted.com",
        value={"ip": "1.2.3.4"},
        source=Source(type="mock", name="ns1"),
    )
    ev2 = Evidence(
        id="ev-2",
        type="osint.dns_record",
        subject="conflicted.com",
        value={"ip": "5.6.7.8"},
        source=Source(type="mock", name="ns2"),
    )
    inv.evidence_store.add(ev1)
    inv.evidence_store.add(ev2)

    # Record an unresolved contradiction
    inv.contradictions.append(
        ContradictionRecord(
            investigation_id=inv.id,
            conflict_type="conflicting_ownership",
            subject="conflicted.com",
            competing_evidence_ids=["ev-1", "ev-2"],
            description="Competing registrar records for conflicted.com",
            resolved=False,
        )
    )

    # Plan investigation
    plan, val_res = core.plan_investigation(inv.id, auto_convert_candidates=True)

    assert val_res.is_valid
    assert len(plan.candidate_next_requirements) >= 1
    contra_cand = next(
        c for c in plan.candidate_next_requirements
        if c.value_dimension.value == "contradiction_resolution"
    )
    assert contra_cand.target_or_entity == "conflicted.com"
    assert contra_cand.required_capability == "osint.whois_lookup"

    core.shutdown()


def test_stopping_condition_on_no_actionable_gaps(tmp_path):
    """Verify loop cleanly halts with NO_ACTIONABLE_INFORMATION_GAPS when all needs are met."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Empty Investigation", targets=[])
    plans = core.run_adaptive_investigation(inv.id, max_cycles=3)

    assert len(plans) == 1
    assert plans[0].stopping_condition == StoppingCondition.NO_ACTIONABLE_INFORMATION_GAPS

    core.shutdown()


def test_max_cycles_stopping_condition(tmp_path):
    """Verify loop halts with MAX_CYCLES_REACHED when maximum cycle limit is reached."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Cyclic Investigation", targets=["perpetual.target"])
    inv.add_entity("domain", "perpetual.target")

    # Only register a specialist that does not satisfy certificate needs so candidates remain
    plans = core.run_adaptive_investigation(inv.id, max_cycles=2)

    assert len(plans) <= 2
    last_plan = plans[-1]
    assert last_plan.stopping_condition in (
        StoppingCondition.MAX_CYCLES_REACHED,
        StoppingCondition.NO_AUTHORIZED_CAPABILITIES,
        StoppingCondition.NO_ACTIONABLE_INFORMATION_GAPS,
    )

    core.shutdown()

