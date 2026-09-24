"""Tests for OSINTSpecialist internal state, memory, experience, and contracts."""

from pathlib import Path
import pytest
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.specialists.endpoint import (
    SpecialistHealth,
    SpecialistRequest,
)
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
)
from cyberclaw.specialists.osint.investigation import (
    OSINTTargetType,
    classify_target,
)
from cyberclaw.specialists.osint.specialist import OSINTSpecialist


def test_target_classification():
    assert classify_target("example.com") == OSINTTargetType.DOMAIN
    assert classify_target("sub.api.example.com") == OSINTTargetType.FQDN
    assert classify_target("192.168.1.100") == OSINTTargetType.IPV4
    assert classify_target("analyst@security.org") == OSINTTargetType.EMAIL
    assert classify_target("non_target_string") == OSINTTargetType.UNKNOWN


def test_specialist_health_contract(tmp_path: Path):
    specialist = OSINTSpecialist(workspace_base=tmp_path)
    assert specialist.health() == SpecialistHealth.HEALTHY

    specialist.set_health(SpecialistHealth.DEGRADED)
    assert specialist.health() == SpecialistHealth.DEGRADED


def test_specialist_invocation_and_local_state(tmp_path: Path):
    specialist = OSINTSpecialist(workspace_base=tmp_path)

    req = SpecialistRequest(
        investigation_id="inv-spec-test",
        capability_id=CAPABILITY_DNS_LOOKUP,
        parameters={"target": "company.io"},
        context=ExecutionContext(investigation_id="inv-spec-test"),
    )

    response = specialist.invoke(req)
    assert response.status.value == "success"
    assert response.specialist_id == "osint_specialist"
    assert response.metadata["local_state"] == "COMPLETE"
    assert response.metadata["target_type"] == "domain"

    # Verify local memory retained target info
    cached = specialist.memory.get_target_info("company.io")
    assert cached is not None
    assert cached["target_type"] == "domain"

    # Verify local experience was recorded
    experiences = specialist.experiences.list_all()
    assert len(experiences) >= 1
    assert experiences[0].success is True
    assert "company.io" in experiences[0].conditions["target"]


def test_specialist_workspace_persistence(tmp_path: Path):
    specialist = OSINTSpecialist(workspace_base=tmp_path)

    req = SpecialistRequest(
        investigation_id="inv-ws-persist",
        capability_id=CAPABILITY_DOMAIN_METADATA,
        parameters={"target": "persisted.com"},
        context=ExecutionContext(investigation_id="inv-ws-persist"),
    )
    specialist.invoke(req)

    # Check files inside specialist workspace
    inv_ws = specialist.workspace.get_investigation_workspace("inv-ws-persist")
    assert (inv_ws.evidence / "local_evidence.json").exists()
    assert (inv_ws.root / "investigation_state.json").exists()

    loaded_evidence = specialist.workspace.load_local_evidence("inv-ws-persist")
    assert len(loaded_evidence) == 1
    assert loaded_evidence[0].subject == "persisted.com"


def test_specialist_handles_empty_and_failure(tmp_path: Path):
    specialist = OSINTSpecialist(workspace_base=tmp_path)

    # Empty
    req_empty = SpecialistRequest(
        investigation_id="inv-empty",
        capability_id=CAPABILITY_DNS_LOOKUP,
        parameters={"target": "empty.org", "simulate_empty": True},
        context=ExecutionContext(investigation_id="inv-empty"),
    )
    resp_empty = specialist.invoke(req_empty)
    assert resp_empty.result.is_empty is True
    assert len(resp_empty.result.evidence) == 0

    # Failure
    req_fail = SpecialistRequest(
        investigation_id="inv-fail",
        capability_id=CAPABILITY_DNS_LOOKUP,
        parameters={"target": "fail.org", "simulate_failure": True},
        context=ExecutionContext(investigation_id="inv-fail"),
    )
    resp_fail = specialist.invoke(req_fail)
    assert resp_fail.result.is_failure is True
    assert resp_fail.result.error_code == "DNS_SERVFAIL"
    assert resp_fail.metadata["local_state"] == "FAILED"
