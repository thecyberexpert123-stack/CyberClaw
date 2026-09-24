"""Validation of historical journal ordering, sequence continuity, and snapshot integrity."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from cyberclaw.case.models import (
    CaseState,
    DecisionRecord,
    InvestigationSnapshot,
    JournalEntry,
    JournalEntryType,
)
from cyberclaw.dfa.states import ALLOWED_TRANSITIONS, CoreState
from cyberclaw.replay.errors import (
    CorruptedHistoryError,
    ReplayIntegrityError,
    ReplaySequenceError,
)


class ValidationReport:
    """Detailed diagnostic report of history validation."""

    def __init__(self) -> None:
        self.is_valid: bool = True
        self.errors: List[str] = []
        self.warnings: List[str] = []

    def add_error(self, message: str) -> None:
        self.is_valid = False
        self.errors.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)


class HistoryValidator:
    """Enforces strict structural, sequential, and cryptographic checks across historical records."""

    @classmethod
    def validate_journal_ordering(cls, entries: List[JournalEntry]) -> None:
        """Validate that journal sequence numbers are strictly monotonic without gaps or duplicates."""
        if not entries:
            return

        seen_sequences = set()
        expected_seq = 1

        for i, entry in enumerate(entries):
            # Check duplicates
            if entry.sequence in seen_sequences:
                raise ReplaySequenceError(
                    f"Duplicate journal sequence detected: sequence {entry.sequence} at index {i}"
                )
            seen_sequences.add(entry.sequence)

            # Check gaps
            if entry.sequence != expected_seq:
                raise ReplaySequenceError(
                    f"Journal sequence gap detected: expected {expected_seq}, but got {entry.sequence} at index {i}"
                )
            expected_seq += 1

            # Check timestamp monotonicity (soft or hard check)
            if i > 0 and entry.timestamp < entries[i - 1].timestamp:
                raise CorruptedHistoryError(
                    f"Timestamp regression in journal: entry #{entry.sequence} ({entry.timestamp}) is earlier than entry #{entries[i - 1].sequence} ({entries[i - 1].timestamp})"
                )

    @classmethod
    def validate_snapshots(cls, snapshots: List[InvestigationSnapshot]) -> None:
        """Validate snapshot ordering and cryptographic SHA-256 integrity."""
        if not snapshots:
            return

        expected_seq = 1
        seen_snapshots = set()

        for i, snap in enumerate(snapshots):
            if snap.sequence in seen_snapshots:
                raise ReplaySequenceError(
                    f"Duplicate snapshot sequence detected: sequence {snap.sequence}"
                )
            seen_snapshots.add(snap.sequence)

            if snap.sequence != expected_seq:
                raise ReplaySequenceError(
                    f"Snapshot sequence gap detected: expected {expected_seq}, but got {snap.sequence}"
                )
            expected_seq += 1

            # Cryptographic integrity verification
            if not snap.verify_integrity():
                raise ReplayIntegrityError(
                    f"Snapshot #{snap.sequence} failed SHA-256 integrity verification: state has been tampered with or corrupted"
                )

    @classmethod
    def validate_dfa_transitions(cls, entries: List[JournalEntry]) -> None:
        """Validate that all recorded DFA state transitions conform to allowed state machine rules."""
        current_state = CoreState.INITIALIZE

        for entry in entries:
            if entry.entry_type == JournalEntryType.STATE_TRANSITION:
                to_state_str = entry.details.get("to")
                from_state_str = entry.details.get("from")

                if not to_state_str:
                    raise CorruptedHistoryError(
                        f"State transition entry #{entry.sequence} missing 'to' state in details"
                    )

                try:
                    to_state = CoreState(to_state_str)
                except ValueError:
                    raise CorruptedHistoryError(
                        f"Invalid CoreState '{to_state_str}' in journal entry #{entry.sequence}"
                    )

                if from_state_str:
                    try:
                        from_state = CoreState(from_state_str)
                    except ValueError:
                        raise CorruptedHistoryError(
                            f"Invalid from CoreState '{from_state_str}' in journal entry #{entry.sequence}"
                        )
                else:
                    from_state = current_state

                # Check transition validity against ALLOWED_TRANSITIONS
                allowed = ALLOWED_TRANSITIONS.get(from_state, set())
                if to_state not in allowed and from_state != to_state:
                    raise CorruptedHistoryError(
                        f"Impossible DFA transition detected at entry #{entry.sequence}: {from_state.value} -> {to_state.value} is not permitted by Core DFA rules"
                    )

                current_state = to_state

    @classmethod
    def validate_decision_references(
        cls, entries: List[JournalEntry], decisions: List[DecisionRecord]
    ) -> None:
        """Validate that all decision references in the journal correspond to actual decision records."""
        decision_ids = {d.id for d in decisions}

        for entry in entries:
            if entry.entry_type == JournalEntryType.DECISION_RECORDED and entry.reference_id:
                if entry.reference_id not in decision_ids:
                    raise CorruptedHistoryError(
                        f"Journal entry #{entry.sequence} references decision ID '{entry.reference_id}' which does not exist in decision history"
                    )

    @classmethod
    def validate_all(
        cls,
        entries: List[JournalEntry],
        snapshots: List[InvestigationSnapshot],
        decisions: List[DecisionRecord],
    ) -> None:
        """Execute full suite of historical integrity and validation checks."""
        cls.validate_journal_ordering(entries)
        cls.validate_snapshots(snapshots)
        cls.validate_dfa_transitions(entries)
        cls.validate_decision_references(entries, decisions)
