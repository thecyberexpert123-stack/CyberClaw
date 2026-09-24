"""Tests for HistoryValidator covering journal ordering, sequence gaps, tamper detection, and corruptions."""

from datetime import datetime, timedelta, timezone
import pytest
from cyberclaw.case.models import (
    DecisionRecord,
    DecisionType,
    InvestigationSnapshot,
    JournalEntry,
    JournalEntryType,
    utc_now,
)
from cyberclaw.replay.errors import (
    CorruptedHistoryError,
    ReplayIntegrityError,
    ReplaySequenceError,
)
from cyberclaw.replay.validator import HistoryValidator


def test_journal_sequence_gap_detection():
    """Verify sequence gaps (e.g. 1 -> 3) raise ReplaySequenceError."""
    now = utc_now()
    entries = [
        JournalEntry(
            investigation_id="inv-1",
            sequence=1,
            timestamp=now,
            entry_type=JournalEntryType.STATE_TRANSITION,
            summary="Init",
            details={"to": "READY"},
        ),
        JournalEntry(
            investigation_id="inv-1",
            sequence=3,  # Gap: missing sequence 2
            timestamp=now + timedelta(seconds=1),
            entry_type=JournalEntryType.REQUIREMENT_CREATED,
            summary="Req created",
        ),
    ]

    with pytest.raises(ReplaySequenceError, match="Journal sequence gap detected"):
        HistoryValidator.validate_journal_ordering(entries)


def test_journal_duplicate_sequence_detection():
    """Verify duplicate sequence numbers raise ReplaySequenceError."""
    now = utc_now()
    entries = [
        JournalEntry(
            investigation_id="inv-1",
            sequence=1,
            timestamp=now,
            entry_type=JournalEntryType.STATE_TRANSITION,
            summary="Init",
            details={"to": "READY"},
        ),
        JournalEntry(
            investigation_id="inv-1",
            sequence=1,  # Duplicate sequence 1
            timestamp=now + timedelta(seconds=1),
            entry_type=JournalEntryType.REQUIREMENT_CREATED,
            summary="Req created",
        ),
    ]

    with pytest.raises(ReplaySequenceError, match="Duplicate journal sequence detected"):
        HistoryValidator.validate_journal_ordering(entries)


def test_snapshot_tamper_detection():
    """Verify modified snapshot state triggers ReplayIntegrityError on SHA-256 verification."""
    snap = InvestigationSnapshot(
        investigation_id="inv-tamper",
        sequence=1,
        trigger="manual",
        dfa_state="READY",
        evidence_ids=["ev-1"],
    )
    snap.seal()

    # Integrity passes originally
    assert snap.verify_integrity() is True

    # Tamper with state
    snap.dfa_state = "FAILED"

    with pytest.raises(ReplayIntegrityError, match="failed SHA-256 integrity verification"):
        HistoryValidator.validate_snapshots([snap])


def test_impossible_dfa_transition_detection():
    """Verify impossible state transitions raise CorruptedHistoryError."""
    now = utc_now()
    entries = [
        JournalEntry(
            investigation_id="inv-1",
            sequence=1,
            timestamp=now,
            entry_type=JournalEntryType.STATE_TRANSITION,
            summary="Initialize",
            details={"from": "INITIALIZE", "to": "RESOLVE"},  # Impossible direct transition!
        ),
    ]

    with pytest.raises(CorruptedHistoryError, match="Impossible DFA transition detected"):
        HistoryValidator.validate_dfa_transitions(entries)


def test_missing_decision_reference_detection():
    """Verify journal entries referencing non-existent decision IDs raise CorruptedHistoryError."""
    now = utc_now()
    entries = [
        JournalEntry(
            investigation_id="inv-1",
            sequence=1,
            timestamp=now,
            entry_type=JournalEntryType.DECISION_RECORDED,
            summary="Made a planning decision",
            reference_id="non-existent-decision-id",
        ),
    ]

    with pytest.raises(CorruptedHistoryError, match="references decision ID.*which does not exist"):
        HistoryValidator.validate_decision_references(entries, [])
