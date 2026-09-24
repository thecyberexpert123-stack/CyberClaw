"""Tests for CaseState, InvestigationSnapshot, and DecisionRecord data models."""

import pytest
from cyberclaw.case.models import (
    CaseState,
    DecisionRecord,
    DecisionType,
    ExecutionHistoryRecord,
    InvestigationSnapshot,
    JournalEntry,
    JournalEntryType,
    SnapshotDelta,
    StateTransitionRecord,
)
from cyberclaw.types import Entity, Hypothesis, Relationship


def test_investigation_snapshot_digest_and_tamper_detection():
    """Verify snapshot computes deterministic SHA-256 digest and detects tampering."""
    snap = InvestigationSnapshot(
        investigation_id="inv-snap-01",
        sequence=1,
        trigger="initial_recon",
        dfa_state="READY",
        evidence_ids=["ev-101", "ev-102"],
        entities={"ent-1": Entity(type="domain", name="target.corp")},
        hypotheses={"hyp-1": Hypothesis(investigation_id="inv-snap-01", statement="Target is active", status="OPEN", confidence=0.6)},
    )
    snap.seal()

    assert snap.state_digest != ""
    assert len(snap.state_digest) == 64  # SHA-256 hex string length
    assert snap.verify_integrity() is True

    # Simulate unauthorized state tampering
    snap.dfa_state = "COMPROMISED_STATE"
    assert snap.verify_integrity() is False


def test_decision_record_structure():
    """Verify DecisionRecord preserves actor, rationale, inputs, and outcome."""
    decision = DecisionRecord(
        investigation_id="inv-01",
        sequence=1,
        decision_type=DecisionType.PLANNING_SELECTION,
        actor="core.planner",
        rationale="Selected port scan due to un-enriched IP entity",
        inputs={"entity": "192.168.1.1", "missing": "port_scan"},
        outcome={"candidate_id": "cand-001", "priority": 40},
    )
    assert decision.decision_type == DecisionType.PLANNING_SELECTION
    assert decision.actor == "core.planner"
    assert "Selected port scan" in decision.rationale
    assert decision.outcome["candidate_id"] == "cand-001"


def test_case_state_conceptual_model_separation():
    """Verify CaseState distinctly partitions current state, state history, decisions, and experiences."""
    case = CaseState(
        investigation_id="case-100",
        title="APT Incident Case",
        current_dfa_state="ACTIVE",
        state_history=[
            StateTransitionRecord(from_state="INITIALIZE", to_state="READY", event="initialized"),
            StateTransitionRecord(from_state="READY", to_state="ACTIVE", event="recon.started"),
        ],
        evidence_registry=["ev-1", "ev-2"],
        entities={"e1": Entity(type="ip", name="10.0.0.1")},
        decision_history=[
            DecisionRecord(
                investigation_id="case-100",
                sequence=1,
                decision_type=DecisionType.STATE_TRANSITION,
                actor="core.dfa",
                rationale="Authorized transition to ACTIVE",
            )
        ],
        experience_references=["exp-global-01", "exp-global-02"],
    )

    # Conceptual partitions remain strictly distinct
    assert case.current_dfa_state == "ACTIVE"
    assert len(case.state_history) == 2
    assert len(case.evidence_registry) == 2
    assert len(case.decision_history) == 1
    assert len(case.experience_references) == 2
    assert case.experience_references[0] == "exp-global-01"
