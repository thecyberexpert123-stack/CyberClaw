"""Tests for chronological CaseJournal, decision trails, and timeline queries."""

import pytest
from cyberclaw.case.models import DecisionType, JournalEntryType
from cyberclaw.investigation import Investigation


def test_chronological_case_journal_append():
    """Verify journal maintains strictly sequential, timestamped event entries."""
    inv = Investigation(id="inv-journal-test", title="Journal Test", targets=["target.com"])

    entry1 = inv.record_journal_entry(
        entry_type=JournalEntryType.STATE_TRANSITION,
        summary="Transitioned to ACTIVE",
        details={"state": "ACTIVE"},
    )
    entry2 = inv.record_journal_entry(
        entry_type=JournalEntryType.REQUIREMENT_CREATED,
        summary="Created DNS requirement",
        reference_id="req-123",
    )

    assert entry1.sequence == 1
    assert entry2.sequence == 2
    assert entry2.timestamp >= entry1.timestamp

    timeline = inv.get_timeline()
    assert len(timeline) == 2
    assert timeline[0]["type"] == JournalEntryType.STATE_TRANSITION.value
    assert timeline[1]["reference_id"] == "req-123"


def test_structured_decision_trail():
    """Verify decision records track deliberate investigative choices with structured rationale."""
    inv = Investigation(id="inv-dec-test", title="Decision Trail Test", targets=["target.com"])

    dec = inv.record_decision(
        decision_type=DecisionType.HYPOTHESIS_TRANSITION,
        actor="core.coordinator",
        rationale="Corroborated by independent TLS certificate records",
        inputs={"hypothesis_id": "hyp-01", "corroborating_evidence_count": 3},
        outcome={"previous_status": "OPEN", "new_status": "SUPPORTED", "confidence": 0.88},
    )

    assert dec.sequence == 1
    assert dec.decision_type == DecisionType.HYPOTHESIS_TRANSITION
    assert dec.actor == "core.coordinator"
    assert "Corroborated by independent" in dec.rationale
    assert dec.outcome["new_status"] == "SUPPORTED"

    # Decisions should also create an entry in the linear journal
    timeline = inv.get_timeline()
    assert len(timeline) == 1
    assert timeline[0]["type"] == JournalEntryType.DECISION_RECORDED.value
