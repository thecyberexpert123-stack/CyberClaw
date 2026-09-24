"""Tests for Memory vs Experience distinction and Experience Revisionability."""

import pytest
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.memory.memory import MemoryStore
from cyberclaw.memory.store import ExperienceStore
from cyberclaw.types import Source


def test_working_memory_operations():
    store = MemoryStore(investigation_id="inv-mem")
    store.set("target_domain", "corp.local", tags=["target", "network"], confidence=1.0)
    store.set("initial_vector", "phishing", tags=["hypothesis"], confidence=0.7)

    assert store.get("target_domain") == "corp.local"
    assert len(store.find_by_tag("target")) == 1

    # Update fact with new confidence
    store.set("initial_vector", "exposed_rdp", tags=["hypothesis"], confidence=0.9)
    fact = store.get_fact("initial_vector")
    assert fact is not None
    assert fact.value == "exposed_rdp"
    assert fact.confidence == 0.9


def test_experience_recording_with_condition_cause():
    store = ExperienceStore(investigation_id="inv-exp")
    res = ExecutionResult.failure(
        error="Target port unreachable",
        error_code="UNREACHABLE",
    )

    lesson = "Operations targeting internal endpoints must verify VPN readiness before scanning."
    record = store.record(
        action="execute:net.scan",
        context={"target": "10.0.0.5", "vpn": False},
        result=res,
        lesson=lesson,
        conditions={"vpn_active": False, "target_segment": "internal"},
        scope="capability:net.scan",
    )

    assert record.success is False
    assert record.failure_reason == "Target port unreachable"
    assert record.lesson == lesson
    assert record.conditions == {"vpn_active": False, "target_segment": "internal"}
    assert record.scope == "capability:net.scan"
    assert record.revision == 1
    assert record.is_active is True


def test_experience_revision_protocol():
    """Verify Section 16 4-step revision protocol:
    1. Identify the contradiction.
    2. Determine the scope of the old conclusion.
    3. Revise the lesson.
    4. Preserve the conditions under which the old lesson was valid.
    """
    store = ExperienceStore(investigation_id="inv-exp-rev")

    # Initial experience: scanner concluded target was offline because port 80 didn't reply
    initial_res = ExecutionResult.failure("Port 80 closed", error_code="CLOSED")
    old_exp = store.record(
        action="execute:service.detect",
        context={"port": 80},
        result=initial_res,
        lesson="Service is completely offline when port 80 is closed.",
        conditions={"port": 80, "protocol": "tcp"},
        scope="service.detect",
    )

    assert old_exp.revision == 1
    assert old_exp.is_active is True

    # New contradictory evidence arrives: Port 443 is open and service is active!
    new_evidence = Evidence(
        type="finding",
        subject="host-1",
        value={"port": 443, "status": "open", "tls": True},
        source=Source(type="scanner", name="TlsProbe"),
    )

    # Execute 4-step revision
    revised_exp = store.revise(
        experience_id=old_exp.id,
        contradiction_evidence_ids=[new_evidence.id],
        revised_lesson="Service was only redirecting HTTP; HTTPS (port 443) must be checked before concluding offline.",
        revised_conditions={"checked_ports": [80, 443]},
        revision_reason="Discovery of HTTPS listener refuted offline assumption.",
        new_evidence_ids=[new_evidence.id],
    )

    # 1. Contradiction was identified and recorded
    assert new_evidence.id in revised_exp.contradiction_evidence_ids
    assert revised_exp.revises_experience_id == old_exp.id

    # 2. Scope is preserved or refined
    assert revised_exp.scope == old_exp.scope

    # 3. Lesson is revised and revision incremented
    assert revised_exp.revision == 2
    assert "HTTPS (port 443) must be checked" in revised_exp.lesson

    # 4. Conditions under which old lesson was valid are preserved
    assert old_exp.is_active is False
    assert old_exp.superseded_by == revised_exp.id
    assert old_exp.conditions == {"port": 80, "protocol": "tcp"}
    assert old_exp.metadata["superseded_reason"] == "Discovery of HTTPS listener refuted offline assumption."

    # Active query should return only the revised active record
    active_records = store.find_by_scope("service.detect", include_superseded=False)
    assert len(active_records) == 1
    assert active_records[0].id == revised_exp.id
