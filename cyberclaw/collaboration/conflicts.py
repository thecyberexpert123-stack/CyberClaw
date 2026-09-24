"""Explicit disagreement detection, conflict lifecycle management, and preservation of competing claims."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple
from cyberclaw.collaboration.errors import ConflictProcessingError
from cyberclaw.collaboration.models import (
    ConflictStatus,
    ConflictType,
    SpecialistConflict,
    utc_now,
)
from cyberclaw.evidence.models import Evidence


VALID_CONFLICT_TRANSITIONS: Dict[ConflictStatus, Set[ConflictStatus]] = {
    ConflictStatus.OPEN: {
        ConflictStatus.UNDER_REVIEW,
        ConflictStatus.CORROBORATING,
        ConflictStatus.RESOLVED,
        ConflictStatus.PERSISTENT,
        ConflictStatus.ABANDONED,
    },
    ConflictStatus.UNDER_REVIEW: {
        ConflictStatus.CORROBORATING,
        ConflictStatus.RESOLVED,
        ConflictStatus.PERSISTENT,
        ConflictStatus.ABANDONED,
    },
    ConflictStatus.CORROBORATING: {
        ConflictStatus.UNDER_REVIEW,
        ConflictStatus.RESOLVED,
        ConflictStatus.PERSISTENT,
        ConflictStatus.ABANDONED,
    },
    ConflictStatus.PERSISTENT: {
        ConflictStatus.UNDER_REVIEW,
        ConflictStatus.CORROBORATING,
        ConflictStatus.RESOLVED,
        ConflictStatus.ABANDONED,
    },
    ConflictStatus.RESOLVED: set(),
    ConflictStatus.ABANDONED: set(),
}


class ConflictDetector:
    """Discovers contradictions between newly produced collaboration evidence and existing case evidence."""

    @classmethod
    def detect_conflicts(
        cls,
        new_evidence: List[Evidence],
        existing_evidence: List[Evidence],
        investigation_id: str,
    ) -> List[SpecialistConflict]:
        """Compare incoming evidence against existing evidence to identify empirical or inferential contradictions."""
        conflicts: List[SpecialistConflict] = []

        for new_ev in new_evidence:
            new_subject = new_ev.subject
            new_specialist = new_ev.provenance.specialist_id or "unknown"

            for exist_ev in existing_evidence:
                if exist_ev.id == new_ev.id:
                    continue
                if exist_ev.subject != new_subject:
                    continue

                exist_specialist = exist_ev.provenance.specialist_id or "unknown"

                is_conflict, conflict_type, claim_a, claim_b = cls._evaluate_claims(exist_ev, new_ev)
                if is_conflict:
                    conflict = SpecialistConflict(
                        investigation_id=investigation_id,
                        subject=new_subject,
                        claim_a=claim_a,
                        claim_b=claim_b,
                        specialist_a=exist_specialist,
                        specialist_b=new_specialist,
                        supporting_evidence_a=[exist_ev.id],
                        supporting_evidence_b=[new_ev.id],
                        conflict_type=conflict_type,
                        status=ConflictStatus.OPEN,
                    )
                    conflicts.append(conflict)

        return conflicts

    @classmethod
    def _evaluate_claims(
        cls,
        ev_a: Evidence,
        ev_b: Evidence,
    ) -> Tuple[bool, ConflictType, Any, Any]:
        """Determine if two evidence items asserting findings on the same subject contradict."""
        # 1. Explicit contradiction marker in metadata
        if ev_b.metadata.get("contradicts_evidence_id") == ev_a.id or ev_a.metadata.get("contradicts_evidence_id") == ev_b.id:
            return True, ConflictType.CONTRADICTORY_OBSERVATION, ev_a.value, ev_b.value

        # 2. Both dict values comparing keys
        val_a = ev_a.value
        val_b = ev_b.value

        if isinstance(val_a, dict) and isinstance(val_b, dict):
            # Check status/verdict/attribute conflicts
            for key in ("status", "verdict", "is_malicious", "state", "ip", "asn", "identity", "owner"):
                if key in val_a and key in val_b:
                    if val_a[key] != val_b[key]:
                        c_type = ConflictType.IDENTITY_DISAGREEMENT if key in ("identity", "owner") else ConflictType.CONTRADICTORY_OBSERVATION
                        return True, c_type, {key: val_a[key]}, {key: val_b[key]}

        # 3. Direct scalar divergence
        elif val_a != val_b and type(val_a) is type(val_b):
            nature_a = ev_a.metadata.get("finding_nature")
            nature_b = ev_b.metadata.get("finding_nature")
            if nature_a == "INFERENCE" or nature_b == "INFERENCE":
                return True, ConflictType.CONTRADICTORY_INFERENCE, val_a, val_b
            return True, ConflictType.CONTRADICTORY_OBSERVATION, val_a, val_b

        return False, ConflictType.CONTRADICTORY_OBSERVATION, None, None


class ConflictManager:
    """Thread-safe manager for tracking and transitioning specialist conflicts."""

    def __init__(self) -> None:
        self._conflicts: Dict[str, SpecialistConflict] = {}

    def register_conflict(self, conflict: SpecialistConflict) -> SpecialistConflict:
        """Register a detected conflict."""
        self._conflicts[conflict.conflict_id] = conflict
        return conflict

    def get_conflict(self, conflict_id: str) -> Optional[SpecialistConflict]:
        """Fetch conflict by ID."""
        return self._conflicts.get(conflict_id)

    def list_conflicts(
        self,
        investigation_id: Optional[str] = None,
        status: Optional[ConflictStatus] = None,
    ) -> List[SpecialistConflict]:
        """List tracked conflicts with optional filtering."""
        res = list(self._conflicts.values())
        if investigation_id:
            res = [c for c in res if c.investigation_id == investigation_id]
        if status:
            res = [c for c in res if c.status == status]
        return res

    def transition_conflict(
        self,
        conflict_id: str,
        new_status: ConflictStatus,
        resolution_reference: Optional[str] = None,
        rationale: Optional[str] = None,
    ) -> SpecialistConflict:
        """Validate and apply state transition to a SpecialistConflict."""
        conflict = self.get_conflict(conflict_id)
        if not conflict:
            raise ConflictProcessingError(f"Conflict '{conflict_id}' not found.")

        current = conflict.status
        allowed = VALID_CONFLICT_TRANSITIONS.get(current, set())
        if new_status not in allowed:
            raise ConflictProcessingError(
                f"Illegal conflict transition from '{current.value}' to '{new_status.value}'. "
                f"Allowed: {[s.value for s in allowed]}"
            )

        conflict.status = new_status
        if new_status == ConflictStatus.RESOLVED:
            conflict.resolved_at = utc_now()
            conflict.resolution_reference = resolution_reference
            conflict.resolution_rationale = rationale

        return conflict

    def resolve_conflict(
        self,
        conflict_id: str,
        resolution_evidence_id: str,
        rationale: str,
    ) -> SpecialistConflict:
        """Convenience method to transition a conflict to RESOLVED."""
        return self.transition_conflict(
            conflict_id=conflict_id,
            new_status=ConflictStatus.RESOLVED,
            resolution_reference=resolution_evidence_id,
            rationale=rationale,
        )
