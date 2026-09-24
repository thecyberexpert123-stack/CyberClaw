"""Tests for capability-based routing of Information Requirements."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.coordination.requirements import InformationRequirement
from cyberclaw.coordination.router import RequirementRouter
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.specialists.registry import SpecialistRegistry


class DummyEndpoint(SpecialistEndpoint):
    def __init__(self, health_state: SpecialistHealth = SpecialistHealth.HEALTHY) -> None:
        self._health = health_state

    def health(self) -> SpecialistHealth:
        return self._health

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        pass


def test_routing_by_evidence_types_sought():
    sr = SpecialistRegistry()
    cr = CapabilityRegistry()

    # Register OSINT specialist with dns capability
    cr.register_capability(
        Capability(id="osint.dns_lookup", name="DNS", description="Resolves DNS records")
    )
    sr.register_specialist(
        Specialist(
            id="spec_osint",
            name="OSINT",
            capabilities=["osint.dns_lookup"],
            endpoint=DummyEndpoint(),
        )
    )

    # Register Network specialist with port scan capability
    cr.register_capability(
        Capability(id="network.port_scan", name="Port Scan", description="Scans network ports")
    )
    sr.register_specialist(
        Specialist(
            id="spec_network",
            name="Network",
            capabilities=["network.port_scan"],
            endpoint=DummyEndpoint(),
        )
    )

    router = RequirementRouter(sr, cr)

    # Requirement 1: wants DNS
    req_dns = InformationRequirement(
        investigation_id="inv-1",
        description="Need DNS resolution",
        target_or_entity="example.com",
        evidence_types_sought=["osint.dns_record"],
    )
    spec, cap, err = router.resolve_specialist(req_dns)
    assert spec is not None
    assert spec.id == "spec_osint"
    assert cap == "osint.dns_lookup"
    assert err is None

    # Requirement 2: wants port scan
    req_port = InformationRequirement(
        investigation_id="inv-1",
        description="Need port scan",
        target_or_entity="10.0.0.1",
        evidence_types_sought=["network.port_scan"],
    )
    spec, cap, err = router.resolve_specialist(req_port)
    assert spec is not None
    assert spec.id == "spec_network"
    assert cap == "network.port_scan"
    assert err is None


def test_routing_skips_unhealthy_specialists():
    sr = SpecialistRegistry()
    cr = CapabilityRegistry()

    cr.register_capability(Capability(id="service.scan", name="Service Scan"))
    # Unhealthy specialist
    sr.register_specialist(
        Specialist(
            id="spec_sick",
            name="Sick Specialist",
            capabilities=["service.scan"],
            endpoint=DummyEndpoint(health_state=SpecialistHealth.UNHEALTHY),
        )
    )

    router = RequirementRouter(sr, cr)
    req = InformationRequirement(
        investigation_id="inv-1",
        description="Scan services",
        target_or_entity="10.0.0.5",
        assigned_capability_id="service.scan",
    )

    spec, cap, err = router.resolve_specialist(req)
    assert spec is None
    assert "No healthy specialist" in err


def test_routing_unmatched_requirement():
    sr = SpecialistRegistry()
    cr = CapabilityRegistry()
    router = RequirementRouter(sr, cr)

    req = InformationRequirement(
        investigation_id="inv-1",
        description="Non-existent requirement",
        target_or_entity="foo",
        evidence_types_sought=["nonexistent.type"],
    )

    spec, cap, err = router.resolve_specialist(req)
    assert spec is None
    assert "No specialists registered" in err
