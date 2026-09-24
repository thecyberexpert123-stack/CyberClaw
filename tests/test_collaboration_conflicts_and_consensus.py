"""Tests for evidence handoff, provenance preservation, conflict detection/lifecycle, source independence, and consensus."""

from __future__ import annotations

import pytest

from cyberclaw.collaboration.conflicts import ConflictDetector, ConflictManager
from cyberclaw.collaboration.consensus import ConsensusEngine
from cyberclaw.collaboration.evidence import EvidenceHandoffNormalizer
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    CollaborationResult,
    ConflictStatus,
    ConflictType,
    ConsensusStatus,
    FindingNature,
    SpecialistConflict,
)
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.types import Hypothesis, Source


def test_evidence_handoff_preserves_epistemic_nature():
    """Verify observations and inferences maintain distinct epistemic classifications (inferences not converted to observations)."""
    req = CollaborationRequest(
        investigation_id="inv-handoff-01",
        requesting_specialist="specialist.osint",
        objective="Assess target host",
        input_evidence_ids=["ev-root-01"],
    )

    result = CollaborationResult(
        request_id=req.request_id,
        investigation_id=req.investigation_id,
        responding_specialist="specialist.network",
        observations=[
            {"subject": "198.51.100.10", "data": {"banner": "nginx/1.18.0"}, "confidence": 1.0}
        ],
        inferences=[
            {"subject": "198.51.100.10", "conclusion": {"os_family": "Linux/Ubuntu"}, "confidence": 0.8}
        ],
    )

    evidence_items = EvidenceHandoffNormalizer.normalize_result(
        result=result,
        request=req,
        capability_id="net.banner_grab",
        capability_version="2.1.0",
        provider_id="provider.socket_scan",
        authorization_decision_id="auth-dec-999",
    )

    assert len(evidence_items) == 2

    # 1. Observation verification
    obs_ev = next(e for e in evidence_items if e.type == "observation.empirical")
    assert obs_ev.metadata["finding_nature"] == FindingNature.OBSERVATION.value
    assert obs_ev.provenance.specialist_id == "specialist.network"
    assert obs_ev.provenance.capability_id == "net.banner_grab"
    assert obs_ev.metadata["derived_from_evidence_ids"] == ["ev-root-01"]

    # 2. Inference verification (NOT converted to observation)
    inf_ev = next(e for e in evidence_items if e.type == "inference.specialist")
    assert inf_ev.metadata["finding_nature"] == FindingNature.INFERENCE.value
    assert inf_ev.metadata.get("is_inferred") is True
    assert inf_ev.value == {"os_family": "Linux/Ubuntu"}


def test_conflict_detection_and_preservation_of_competing_claims():
    """Verify conflicting evidence claims are preserved and recorded as SpecialistConflict without overwriting."""
    existing_ev = Evidence(
        id="ev-claim-1",
        type="service.status",
        subject="host.internal.corp",
        value={"status": "active", "port": 443},
        source=Source(type="probe", name="active_scanner"),
        provenance=Provenance(specialist_id="specialist.network"),
    )

    new_ev = Evidence(
        id="ev-claim-2",
        type="service.status",
        subject="host.internal.corp",
        value={"status": "revoked", "port": 443},
        source=Source(type="log", name="cert_monitor"),
        provenance=Provenance(specialist_id="specialist.osint"),
    )

    conflicts = ConflictDetector.detect_conflicts(
        new_evidence=[new_ev],
        existing_evidence=[existing_ev],
        investigation_id="inv-conflict-01",
    )

    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.subject == "host.internal.corp"
    assert conflict.specialist_a == "specialist.network"
    assert conflict.specialist_b == "specialist.osint"
    assert conflict.claim_a == {"status": "active"}
    assert conflict.claim_b == {"status": "revoked"}
    assert conflict.status == ConflictStatus.OPEN
    assert "ev-claim-1" in conflict.supporting_evidence_a
    assert "ev-claim-2" in conflict.supporting_evidence_b


def test_conflict_lifecycle_and_persistent_disagreement():
    """Verify conflict transitions from OPEN through RESOLVED or PERSISTENT."""
    manager = ConflictManager()
    from cyberclaw.collaboration.models import SpecialistConflict

    conflict = SpecialistConflict(
        investigation_id="inv-conf-02",
        subject="malicious.org",
        claim_a="benign",
        claim_b="malicious",
        specialist_a="specialist.osint",
        specialist_b="specialist.network",
    )
    manager.register_conflict(conflict)

    # 1. Transition to UNDER_REVIEW
    manager.transition_conflict(conflict.conflict_id, ConflictStatus.UNDER_REVIEW)
    assert conflict.status == ConflictStatus.UNDER_REVIEW

    # 2. Transition to PERSISTENT (persistent disagreement is legitimate state)
    manager.transition_conflict(conflict.conflict_id, ConflictStatus.PERSISTENT)
    assert conflict.status == ConflictStatus.PERSISTENT

    # 3. Transition to RESOLVED with evidence reference
    resolved = manager.resolve_conflict(
        conflict_id=conflict.conflict_id,
        resolution_evidence_id="ev-resolution-101",
        rationale="Authoritative sinkhole feed confirmed malicious disposition.",
    )
    assert resolved.status == ConflictStatus.RESOLVED
    assert resolved.resolved_at is not None
    assert resolved.resolution_reference == "ev-resolution-101"


def test_source_independence_verification():
    """Verify ConsensusEngine identifies shared underlying sources and rejects artificial corroboration."""
    # Source A and Source B share the same name/upstream origin -> NOT independent
    ev1 = Evidence(
        type="asn_record",
        subject="test.org",
        value={"asn": 12345},
        source=Source(type="feed", name="ShadowServer_Feed", id="s1"),
    )
    ev2 = Evidence(
        type="asn_record",
        subject="test.org",
        value={"asn": 12345},
        source=Source(type="feed", name="shadowserver_feed", id="s2"),  # Case insensitive match
    )
    assert ConsensusEngine.are_sources_independent(ev1, ev2) is False

    # Ev3 derived from Ev1 -> NOT independent
    ev3 = Evidence(
        type="asn_record",
        subject="test.org",
        value={"asn": 12345},
        source=Source(type="inference", name="InferenceEngine"),
        metadata={"derived_from_evidence_ids": [ev1.id]},
    )
    assert ConsensusEngine.are_sources_independent(ev1, ev3) is False

    # Ev4 from distinct provider -> Truly independent
    ev4 = Evidence(
        type="asn_record",
        subject="test.org",
        value={"asn": 12345},
        source=Source(type="whois", name="RIPE_Database", id="s4"),
    )
    assert ConsensusEngine.are_sources_independent(ev1, ev4) is True


def test_consensus_synthesis_and_hypothesis_integration():
    """Verify consensus calculation yields CORROBORATED or CONTESTED and updates hypothesis state accordingly."""
    ev_indep_1 = Evidence(
        type="threat_intel",
        subject="threat-actor.org",
        value={"status": "compromised"},
        source=Source(type="dns", name="Cloudflare_DNS"),
        confidence=0.9,
        metadata={"finding_nature": "OBSERVATION"},
    )
    ev_indep_2 = Evidence(
        type="threat_intel",
        subject="threat-actor.org",
        value={"status": "compromised"},
        source=Source(type="intel", name="CISA_Advisory"),
        confidence=0.95,
        metadata={"finding_nature": "OBSERVATION"},
    )

    hyp = Hypothesis(
        investigation_id="inv-hyp-01",
        statement="Target threat-actor.org is compromised infrastructure",
        status="OPEN",
        confidence=0.5,
    )

    # 1. Corroborated consensus without conflicts
    consensus = ConsensusEngine.evaluate_consensus(
        subject="threat-actor.org",
        evidence_items=[ev_indep_1, ev_indep_2],
        conflicts=[],
    )
    assert consensus.consensus_status == ConsensusStatus.CORROBORATED
    assert consensus.is_independently_corroborated is True
    assert consensus.independent_sources_count == 2
    assert consensus.confidence_score >= 0.9

    ConsensusEngine.update_hypothesis_from_consensus(hyp, consensus)
    assert hyp.status == "SUPPORTED"
    assert hyp.confidence >= 0.9
    assert ev_indep_1.id in hyp.supporting_evidence_ids

    # 2. Contested consensus when active conflict exists
    from cyberclaw.collaboration.models import SpecialistConflict
    active_conflict = SpecialistConflict(
        investigation_id="inv-hyp-01",
        subject="threat-actor.org",
        claim_a="compromised",
        claim_b="clean_mirror",
        specialist_a="s1",
        specialist_b="s2",
        status=ConflictStatus.OPEN,
    )
    contested_consensus = ConsensusEngine.evaluate_consensus(
        subject="threat-actor.org",
        evidence_items=[ev_indep_1, ev_indep_2],
        conflicts=[active_conflict],
    )
    assert contested_consensus.consensus_status == ConsensusStatus.CONTESTED
    assert contested_consensus.is_independently_corroborated is False

    ConsensusEngine.update_hypothesis_from_consensus(hyp, contested_consensus)
    assert hyp.confidence <= 0.45


def test_conflict_review_and_corroboration_lifecycle():
    """Verify ConflictManager guides conflicts through review, corroboration, and resolution lifecycle."""
    mgr = ConflictManager()
    c = SpecialistConflict(
        investigation_id="inv-life-01",
        subject="binary.hash.sha256",
        claim_a="malicious_trojan",
        claim_b="legitimate_updater",
        specialist_a="specialist.malware",
        specialist_b="specialist.threat_intel",
        status=ConflictStatus.OPEN,
    )
    mgr.register_conflict(c)

    # OPEN -> UNDER_REVIEW
    c = mgr.transition_conflict(c.conflict_id, ConflictStatus.UNDER_REVIEW)
    assert c.status == ConflictStatus.UNDER_REVIEW

    # UNDER_REVIEW -> CORROBORATING
    c = mgr.transition_conflict(c.conflict_id, ConflictStatus.CORROBORATING)
    assert c.status == ConflictStatus.CORROBORATING

    # CORROBORATING -> RESOLVED
    c = mgr.resolve_conflict(
        c.conflict_id,
        resolution_evidence_id="ev-gold-standard",
        rationale="Vendor code-signing certificate validated against manufacturer ledger.",
    )
    assert c.status == ConflictStatus.RESOLVED
    assert c.resolution_reference == "ev-gold-standard"


def test_consensus_under_pure_inferences_vs_empirical_observations():
    """Verify empirical observations receive full epistemic weight whereas pure inferences receive appropriate discounting."""
    obs_ev = Evidence(
        type="dns.response",
        subject="host.c2.net",
        value={"ip": "1.2.3.4"},
        source=Source(type="pcap", name="PacketCapture"),
        confidence=0.9,
        metadata={"finding_nature": "OBSERVATION"},
    )
    inf_ev = Evidence(
        type="dns.response",
        subject="host.c2.net",
        value={"ip": "1.2.3.4"},
        source=Source(type="inference", name="RuleEngine"),
        confidence=0.9,
        metadata={"finding_nature": "INFERENCE"},
    )

    obs_consensus = ConsensusEngine.evaluate_consensus("host.c2.net", [obs_ev], [])
    inf_consensus = ConsensusEngine.evaluate_consensus("host.c2.net", [inf_ev], [])

    # The inference cluster is discounted by 0.8 compared to observation
    assert obs_consensus.confidence_score == 0.9
    assert inf_consensus.confidence_score == pytest.approx(0.72, abs=0.01)


def test_consensus_explainability_and_evidence_reasons():
    """Verify ConsensusAssessment provides transparent, audit-ready reasoning explaining its verdict."""
    empty_consensus = ConsensusEngine.evaluate_consensus("unknown.subject", [], [])
    assert empty_consensus.consensus_status == ConsensusStatus.UNVERIFIED
    assert len(empty_consensus.reasons) >= 1
    assert "Zero evidence" in empty_consensus.reasons[0]
    assert "No evidence items" in empty_consensus.explanation
