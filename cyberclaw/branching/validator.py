"""Integrity validation for branches, sequence monotonicity, snapshot seals, and DFA legality."""

from __future__ import annotations

from typing import List, Optional, Set
from cyberclaw.branching.errors import (
    BranchIntegrityError,
    BranchSequenceError,
)
from cyberclaw.branching.models import BranchJournalEntry, InvestigationBranch
from cyberclaw.case.models import InvestigationSnapshot, JournalEntryType
from cyberclaw.dfa.states import ALLOWED_TRANSITIONS, CoreState


class BranchValidator:
    """Validates structural and cryptographic integrity of branches and their private history."""

    @classmethod
    def validate_source_snapshot(cls, snapshot: InvestigationSnapshot) -> None:
        """Validate that the source snapshot has a valid SHA-256 seal."""
        if not snapshot.verify_integrity():
            raise BranchIntegrityError(
                f"Source snapshot #{snapshot.sequence} (ID: {snapshot.snapshot_id}) "
                f"cryptographic integrity verification failed. Potential tampering detected."
            )

    @classmethod
    def validate_branch_journal(cls, entries: List[BranchJournalEntry]) -> None:
        """Enforce strict monotonic ordering, gap detection, and duplicate detection for branch journal."""
        if not entries:
            return

        # Ensure first entry starts at 1
        if entries[0].local_sequence != 1:
            raise BranchSequenceError(
                f"Branch journal sequence must start at 1, but starts at {entries[0].local_sequence}."
            )

        seen_sequences = set()
        for idx, entry in enumerate(entries):
            seq = entry.local_sequence
            expected_seq = idx + 1
            if seq in seen_sequences:
                raise BranchSequenceError(
                    f"Duplicate local sequence {seq} detected in branch journal at index {idx}."
                )
            if seq != expected_seq:
                raise BranchSequenceError(
                    f"Branch sequence gap detected: expected local sequence {expected_seq}, but found {seq}."
                )
            seen_sequences.add(seq)

    @classmethod
    def validate_dfa_transition(cls, from_state: str, to_state: str) -> None:
        """Validate that an investigative state transition within a branch is legal according to Core DFA."""
        try:
            src = CoreState(from_state)
            dst = CoreState(to_state)
        except ValueError as ve:
            raise BranchIntegrityError(f"Invalid DFA state in branch transition: {ve}")

        allowed = ALLOWED_TRANSITIONS.get(src, set())
        if dst not in allowed:
            raise BranchIntegrityError(
                f"Impossible DFA state transition in branch: '{from_state}' -> '{to_state}'. "
                f"Valid destinations: {[s.value for s in allowed]}"
            )

    @classmethod
    def validate_all(
        cls,
        branch: InvestigationBranch,
        snapshots: List[InvestigationSnapshot],
        authoritative_evidence_ids: Optional[Set[str]] = None,
    ) -> None:
        """Perform comprehensive integrity checks on an entire branch structure."""
        # 1. Source snapshot existence and integrity
        source_snap = next(
            (s for s in snapshots if s.snapshot_id == branch.source_snapshot_id or s.sequence == branch.source_snapshot_sequence),
            None,
        )
        if not source_snap:
            raise BranchIntegrityError(
                f"Source snapshot '{branch.source_snapshot_id}' (seq {branch.source_snapshot_sequence}) "
                f"not found in authoritative snapshots."
            )
        cls.validate_source_snapshot(source_snap)

        # 2. Branch journal ordering
        cls.validate_branch_journal(branch.journal)

        # 3. Decision references check
        decision_ids = {d.decision_id for d in branch.decisions}
        for entry in branch.journal:
            if entry.entry_type == JournalEntryType.DECISION_RECORDED and entry.reference_id:
                if entry.reference_id not in decision_ids:
                    raise BranchIntegrityError(
                        f"Branch journal entry {entry.local_sequence} references non-existent decision '{entry.reference_id}'."
                    )

        # 4. Evidence references check
        if authoritative_evidence_ids is not None:
            valid_ev_ids = set(authoritative_evidence_ids) | {e.id for e in branch.simulated_evidence}
            for ev_id in branch.evidence_references:
                if ev_id not in valid_ev_ids:
                    raise BranchIntegrityError(
                        f"Branch references non-existent evidence ID: '{ev_id}'."
                    )
