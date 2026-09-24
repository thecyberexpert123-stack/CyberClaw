"""Tests for Specialist registration, contracts, health, and routing."""

import pytest
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.specialists.registry import SpecialistRegistry
from cyberclaw.types import Source


class MockSpecialistEndpoint(SpecialistEndpoint):
    """Controlled mock implementation of Specialist contract boundary."""

    def __init__(self, specialist_id: str, should_fail: bool = False, is_empty: bool = False) -> None:
        self.specialist_id = specialist_id
        self.should_fail = should_fail
        self.is_empty = is_empty
        self._health = SpecialistHealth.HEALTHY

    def health(self) -> SpecialistHealth:
        return self._health

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        if self.should_fail:
            res = ExecutionResult.failure(
                error="Specialist internal crash",
                error_code="SPECIALIST_INTERNAL_ERROR",
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)

        if self.is_empty:
            res = ExecutionResult.success_empty(
                output={"checked": request.parameters.get("target")},
                execution_id=request.context.execution_id,
            )
            return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)

        source = Source(type="specialist", name=f"Specialist-{self.specialist_id}")
        ev = Evidence(
            type="specialist_finding",
            subject=request.parameters.get("target", "domain.test"),
            value={"discovered_attribute": "value_1"},
            source=source,
        )
        res = ExecutionResult.success(
            evidence=[ev],
            output={"details": "processed"},
            execution_id=request.context.execution_id,
        )
        return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)


def test_specialist_registration_and_health():
    registry = SpecialistRegistry()
    endpoint = MockSpecialistEndpoint("osint_specialist")
    specialist = Specialist(
        id="osint_specialist",
        name="OSINT Specialist",
        version="0.1.0",
        capabilities=["recon.domain", "recon.whois"],
        endpoint=endpoint,
        permissions=["network:read"],
    )
    registry.register_specialist(specialist)

    assert registry.get_specialist("osint_specialist") is not None
    assert registry.check_health_all() == {"osint_specialist": SpecialistHealth.HEALTHY}
    assert len(registry.find_by_capability("recon.domain")) == 1


def test_specialist_request_routing():
    registry = SpecialistRegistry()
    endpoint = MockSpecialistEndpoint("net_specialist")
    specialist = Specialist(
        id="net_specialist",
        name="Network Specialist",
        capabilities=["net.scan"],
        endpoint=endpoint,
    )
    registry.register_specialist(specialist)

    req = SpecialistRequest(
        investigation_id="inv-101",
        capability_id="net.scan",
        parameters={"target": "192.168.1.1"},
        context=ExecutionContext(),
    )
    response = registry.route_request(req)

    assert response.status.value == "success"
    assert response.specialist_id == "net_specialist"
    assert len(response.result.evidence) == 1
    assert response.result.evidence[0].subject == "192.168.1.1"


def test_specialist_empty_findings_distinction():
    registry = SpecialistRegistry()
    endpoint = MockSpecialistEndpoint("forensics_specialist", is_empty=True)
    specialist = Specialist(
        id="forensics_specialist",
        name="Forensics Specialist",
        capabilities=["forensics.memory"],
        endpoint=endpoint,
    )
    registry.register_specialist(specialist)

    req = SpecialistRequest(
        investigation_id="inv-102",
        capability_id="forensics.memory",
        parameters={"target": "dump.raw"},
        context=ExecutionContext(),
    )
    response = registry.route_request(req)

    assert response.result.is_empty is True
    assert response.result.is_failure is False
    assert len(response.result.evidence) == 0


def test_specialist_failure_handling():
    registry = SpecialistRegistry()
    endpoint = MockSpecialistEndpoint("failing_specialist", should_fail=True)
    specialist = Specialist(
        id="failing_specialist",
        name="Failing Specialist",
        capabilities=["fail.action"],
        endpoint=endpoint,
    )
    registry.register_specialist(specialist)

    req = SpecialistRequest(
        investigation_id="inv-103",
        capability_id="fail.action",
        parameters={},
        context=ExecutionContext(),
    )
    response = registry.route_request(req)

    assert response.result.is_failure is True
    assert response.result.error == "Specialist internal crash"
    assert response.result.error_code == "SPECIALIST_INTERNAL_ERROR"
