"""Tests for InformationRequirement creation, lifecycle states, and dependency resolution."""

from pathlib import Path
import pytest

from cyberclaw.coordination.requirements import (
    InformationRequirement,
    RequirementStatus,
)
from cyberclaw.core import CyberClawCore
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source


class MockSpecialistForRequirements(SpecialistEndpoint):
    def __init__(self, spec_id: str) -> None:
        self.spec_id = spec_id

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        if request.parameters.get("simulate_fail"):
            res = ExecutionResult.failure(error="Operation failed", error_code="FAIL")
            return SpecialistResponse.from_result(self.spec_id, request.request_id, res)

        if request.parameters.get("simulate_empty"):
            res = ExecutionResult.success_empty()
            return SpecialistResponse.from_result(self.spec_id, request.request_id, res)

        ev = Evidence(
            type="mock.evidence",
            subject=request.parameters.get("target", "t"),
            value={"data": 123},
            source=Source(type="mock", name=self.spec_id),
        )
        res = ExecutionResult.success(evidence=[ev], output={"status": "ok"})
        return SpecialistResponse.from_result(self.spec_id, request.request_id, res)


def test_requirement_creation_and_fields(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = core.create_investigation(title="Req Test")

    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Need DNS resolution for alpha.com",
        target_or_entity="alpha.com",
        evidence_types_sought=["osint.dns_record"],
        priority=10,
    )

    assert req.id in inv.information_requirements
    assert req.status == RequirementStatus.OPEN
    assert req.priority == 10
    assert req.target_or_entity == "alpha.com"
    assert req.is_resolved is False


def test_requirement_fulfillment_success(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistForRequirements("spec_mock")
    spec = Specialist(
        id="spec_mock",
        name="Mock Specialist",
        capabilities=["intel.query"],
        endpoint=endpoint,
    )
    core.register_specialist(spec)
    inv = core.create_investigation(title="Fulfillment Test")

    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Query intelligence",
        target_or_entity="target.org",
        assigned_capability_id="intel.query",
    )

    fulfilled = core.fulfill_information_requirement(
        investigation_id=inv.id,
        requirement_id=req.id,
    )

    assert fulfilled.status == RequirementStatus.SATISFIED
    assert fulfilled.assigned_specialist_id == "spec_mock"
    assert len(fulfilled.resulting_evidence_ids) == 1
    assert inv.evidence_store.count() == 1
    assert "spec_mock" in inv.participating_specialists


def test_requirement_fulfillment_empty_distinction(tmp_path: Path):
    """Verify Section 14: SUCCESS_EMPTY marks SATISFIED_EMPTY, NOT an error!"""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistForRequirements("spec_empty")
    spec = Specialist(
        id="spec_empty",
        name="Empty Specialist",
        capabilities=["intel.empty"],
        endpoint=endpoint,
    )
    core.register_specialist(spec)
    inv = core.create_investigation(title="Empty Test")

    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Query empty intelligence",
        target_or_entity="empty.org",
        assigned_capability_id="intel.empty",
    )

    fulfilled = core.fulfill_information_requirement(
        investigation_id=inv.id,
        requirement_id=req.id,
        parameters={"simulate_empty": True},
    )

    assert fulfilled.status == RequirementStatus.SATISFIED_EMPTY
    assert fulfilled.is_resolved is True
    assert fulfilled.error is None
    assert len(fulfilled.resulting_evidence_ids) == 0


def test_requirement_fulfillment_failure_handling(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    endpoint = MockSpecialistForRequirements("spec_fail")
    spec = Specialist(
        id="spec_fail",
        name="Failing Specialist",
        capabilities=["intel.fail"],
        endpoint=endpoint,
    )
    core.register_specialist(spec)
    inv = core.create_investigation(title="Failure Test")

    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Query failing intelligence",
        target_or_entity="fail.org",
        assigned_capability_id="intel.fail",
    )

    fulfilled = core.fulfill_information_requirement(
        investigation_id=inv.id,
        requirement_id=req.id,
        parameters={"simulate_fail": True},
    )

    assert fulfilled.status == RequirementStatus.FAILED
    assert fulfilled.is_resolved is True
    assert fulfilled.error == "Operation failed"
    # Investigation state remains healthy and uncorrupted
    assert inv.current_state.value in ("READY", "INVESTIGATE")


def test_requirement_dependencies_blocking(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = core.create_investigation(title="Dep Test")

    req1 = core.create_information_requirement(
        investigation_id=inv.id,
        description="First step",
        target_or_entity="target.org",
    )
    req2 = core.create_information_requirement(
        investigation_id=inv.id,
        description="Second step",
        target_or_entity="target.org",
        dependencies=[req1.id],
    )

    # Attempt to fulfill req2 while req1 is OPEN
    res = core.fulfill_information_requirement(inv.id, req2.id)
    assert res.status == RequirementStatus.OPEN
    assert f"Blocked by dependency requirement '{req1.id}'" in res.error
