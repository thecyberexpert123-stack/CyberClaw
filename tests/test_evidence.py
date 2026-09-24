"""Tests for structured Evidence, Provenance, and ExecutionResult distinctions."""

import pytest
from cyberclaw.evidence.models import Evidence, Observation, Provenance
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.evidence.store import EvidenceStore
from cyberclaw.types import Relationship, Source


def test_evidence_provenance_preservation():
    source = Source(type="test_sensor", name="Unit Sensor", reliability=0.95)
    provenance = Provenance(
        specialist_id="specialist_mock",
        provider_id="provider_mock",
        capability_id="test.capability",
        investigation_id="inv-123",
        parameters={"target": "example.com"},
    )
    evidence = Evidence(
        type="observation",
        subject="example.com",
        value={"resolved_ip": "93.184.216.34"},
        source=source,
        provenance=provenance,
        confidence=0.9,
    )

    assert evidence.subject == "example.com"
    assert evidence.provenance.specialist_id == "specialist_mock"
    assert evidence.provenance.provider_id == "provider_mock"
    assert evidence.provenance.investigation_id == "inv-123"
    assert evidence.source.reliability == 0.95
    assert evidence.confidence == 0.9


def test_result_vs_failure_distinction():
    """Verify Section 11: System distinguishes failure, success with findings, and empty findings."""
    source = Source(type="provider", name="TestProvider")

    # Case 1: Operation completed successfully with findings
    ev = Evidence(
        type="finding",
        subject="host-1",
        value={"open_ports": [80, 443]},
        source=source,
    )
    success_res = ExecutionResult.success(evidence=[ev], output={"status": "done"})
    assert success_res.status == ExecutionStatus.SUCCESS
    assert success_res.is_success is True
    assert success_res.is_empty is False
    assert success_res.is_failure is False
    assert success_res.completed_normally is True
    assert len(success_res.evidence) == 1

    # Case 2: Operation completed successfully but produced NO findings (empty)
    empty_res = ExecutionResult.success_empty(output={"status": "scanned_nothing_found"})
    assert empty_res.status == ExecutionStatus.SUCCESS_EMPTY
    assert empty_res.is_success is False
    assert empty_res.is_empty is True
    assert empty_res.is_failure is False
    assert empty_res.completed_normally is True
    assert len(empty_res.evidence) == 0

    # Case 3: Operation failed
    failure_res = ExecutionResult.failure(error="Connection timed out", error_code="TIMEOUT")
    assert failure_res.status == ExecutionStatus.FAILURE
    assert failure_res.is_success is False
    assert failure_res.is_empty is False
    assert failure_res.is_failure is True
    assert failure_res.completed_normally is False
    assert failure_res.error == "Connection timed out"
    assert failure_res.error_code == "TIMEOUT"

    # All three states must remain strictly distinct
    assert success_res.status != empty_res.status
    assert empty_res.status != failure_res.status
    assert success_res.status != failure_res.status


def test_evidence_store_querying():
    store = EvidenceStore(investigation_id="case-101")
    source = Source(type="test", name="Mock")

    ev1 = Evidence(type="finding", subject="target-a", value="v1", source=source)
    ev2 = Evidence(type="finding", subject="target-b", value="v2", source=source)
    ev3 = Evidence(type="artifact", subject="target-a", value="v3", source=source)

    store.add_many([ev1, ev2, ev3])
    assert store.count() == 3

    # Query by subject
    results_a = store.find_by_subject("target-a")
    assert len(results_a) == 2
    assert {e.id for e in results_a} == {ev1.id, ev3.id}

    # Query by type
    findings = store.find_by_type("finding")
    assert len(findings) == 2
    assert {e.id for e in findings} == {ev1.id, ev2.id}

    # Relationships
    rel = Relationship(source_id=ev1.id, target_id=ev3.id, relation_type="corroborated_by")
    store.add_relationship(rel)
    assert len(store.list_relationships()) == 1
    assert store.list_relationships()[0].relation_type == "corroborated_by"
