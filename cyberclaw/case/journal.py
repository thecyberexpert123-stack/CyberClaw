"""Chronological, tamper-evident case journal and decision history tracking."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from cyberclaw.case.models import (
    DecisionRecord,
    DecisionType,
    JournalEntry,
    JournalEntryType,
    utc_now,
)


class CaseJournal:
    """Maintains an append-only linear audit trail of events, decisions, and milestones."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self._entries: List[JournalEntry] = []
        self._decisions: List[DecisionRecord] = []

    @property
    def entries(self) -> List[JournalEntry]:
        """Return all journal entries in chronological sequence."""
        return list(self._entries)

    @property
    def decisions(self) -> List[DecisionRecord]:
        """Return all decision records in chronological sequence."""
        return list(self._decisions)

    def append_entry(
        self,
        entry_type: JournalEntryType,
        summary: str,
        reference_id: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> JournalEntry:
        """Append a chronological event to the case timeline."""
        seq = len(self._entries) + 1
        entry = JournalEntry(
            investigation_id=self.investigation_id,
            sequence=seq,
            timestamp=utc_now(),
            entry_type=entry_type,
            summary=summary,
            reference_id=reference_id,
            snapshot_id=snapshot_id,
            details=details or {},
        )
        self._entries.append(entry)
        return entry

    def record_decision(
        self,
        decision_type: DecisionType,
        actor: str,
        rationale: str,
        inputs: Optional[Dict[str, Any]] = None,
        outcome: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> DecisionRecord:
        """Record an explicit investigative choice with structured rationale."""
        seq = len(self._decisions) + 1
        record = DecisionRecord(
            investigation_id=self.investigation_id,
            sequence=seq,
            timestamp=utc_now(),
            decision_type=decision_type,
            actor=actor,
            rationale=rationale,
            inputs=inputs or {},
            outcome=outcome or {},
            metadata=metadata or {},
        )
        self._decisions.append(record)

        # Also log to linear journal
        self.append_entry(
            entry_type=JournalEntryType.DECISION_RECORDED,
            summary=f"[{decision_type.value}] {rationale}",
            reference_id=record.id,
            details={"decision_type": decision_type.value, "actor": actor, "outcome": outcome},
        )
        return record

    def list_by_type(self, entry_type: JournalEntryType) -> List[JournalEntry]:
        """Filter journal entries by classification."""
        return [e for e in self._entries if e.entry_type == entry_type]

    def list_decisions_by_type(self, decision_type: DecisionType) -> List[DecisionRecord]:
        """Filter decisions by category."""
        return [d for d in self._decisions if d.decision_type == decision_type]

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Export serialized chronological timeline for audit and reporting."""
        return [
            {
                "sequence": e.sequence,
                "timestamp": e.timestamp.isoformat(),
                "type": e.entry_type.value,
                "summary": e.summary,
                "reference_id": e.reference_id,
                "snapshot_id": e.snapshot_id,
            }
            for e in self._entries
        ]
