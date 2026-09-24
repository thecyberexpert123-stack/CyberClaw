"""Tests for investigative Hypotheses model and evaluation."""

from pathlib import Path
import pytest
from cyberclaw.core import CyberClawCore
from cyberclaw.evidence.models import Evidence
from cyberclaw.types import Source


def test_hypothesis_lifecycle_and_evaluation(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = core.create_investigation(title="Hypothesis Test")

    # 1. Create Hypothesis
    hyp = core.create_hypothesis(
        investigation_id=inv.id,
        statement="Target server-alpha is an exposed web application",
        initial_confidence=0.5,
    )
    assert hyp.status == "OPEN"
    assert hyp.confidence == 0.5

    # 2. Add corroborating evidence to investigation
    source = Source(type="test", name="Scanner")
    ev1 = Evidence(type="osint.dns", subject="server-alpha", value={"ip": "1.2.3.4"}, source=source)
    ev2 = Evidence(type="network.port_scan", subject="server-alpha", value={"open_ports": [80, 443]}, source=source)
    inv.evidence_store.add_many([ev1, ev2])

    # 3. Evaluate Hypotheses
    evaluated = core.evaluate_hypotheses(investigation_id=inv.id)
    assert len(evaluated) == 1
    h = evaluated[0]
    assert h.status == "SUPPORTED"
    assert h.confidence > 0.5
    assert len(h.supporting_evidence_ids) >= 2


def test_hypothesis_contradiction_handling(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = core.create_investigation(title="Hypothesis Contradiction Test")

    hyp = core.create_hypothesis(
        investigation_id=inv.id,
        statement="Target domain-beta has a single static IP address",
        initial_confidence=0.7,
    )

    # Add competing evidence that triggers a contradiction
    source1 = Source(type="test", name="p1")
    source2 = Source(type="test", name="p2")
    ev1 = Evidence(id="e1", type="osint.dns_record", subject="domain-beta", value={"values": ["10.0.0.1"], "record_type": "A"}, source=source1)
    ev2 = Evidence(id="e2", type="osint.dns_record", subject="domain-beta", value={"values": ["10.0.0.2"], "record_type": "A"}, source=source2)
    inv.evidence_store.add_many([ev1, ev2])

    # Run correlation to detect contradiction
    core.correlate_investigation(inv.id)
    assert len(inv.contradictions) >= 1

    # Evaluate hypothesis: should transition to CONTRADICTED
    evaluated = core.evaluate_hypotheses(investigation_id=inv.id)
    h = evaluated[0]
    assert h.status == "CONTRADICTED"
    assert h.confidence < 0.7
    assert "e1" in h.refuting_evidence_ids or "e2" in h.refuting_evidence_ids
