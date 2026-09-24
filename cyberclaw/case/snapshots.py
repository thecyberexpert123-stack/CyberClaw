"""Durable snapshot management, integrity verification, and state diffing."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from cyberclaw.case.models import (
    InvestigationSnapshot,
    SnapshotDelta,
    utc_now,
)
from cyberclaw.investigation import Investigation


class SnapshotManager:
    """Manages creation, indexing, verification, and diffing of investigation snapshots."""

    def __init__(self, investigation_id: str) -> None:
        self.investigation_id = investigation_id
        self._snapshots: List[InvestigationSnapshot] = []

    @property
    def snapshots(self) -> List[InvestigationSnapshot]:
        """Return all captured snapshots."""
        return list(self._snapshots)

    def capture(
        self,
        investigation: Investigation,
        trigger: str = "manual",
        active_plan_id: Optional[str] = None,
        stopping_condition: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InvestigationSnapshot:
        """Capture an immutable, sealed point-in-time snapshot of the investigation."""
        seq = len(self._snapshots) + 1

        # Deep copy or dictionary export of current entities, hypotheses, requirements, contradictions
        entities_copy = {k: v.model_copy(deep=True) for k, v in investigation.entities.items()}
        relationships_copy = [r.model_copy(deep=True) for r in investigation.relationships]
        hypotheses_copy = {k: v.model_copy(deep=True) for k, v in investigation.hypotheses.items()}
        reqs_copy = {k: v.model_copy(deep=True) for k, v in investigation.information_requirements.items()}
        contradictions_copy = [c.model_copy(deep=True) for c in investigation.contradictions]
        evidence_ids = [e.id for e in investigation.evidence_store.list_all()]

        snapshot = InvestigationSnapshot(
            investigation_id=investigation.id,
            sequence=seq,
            timestamp=utc_now(),
            trigger=trigger,
            dfa_state=investigation.current_state.value,
            evidence_ids=evidence_ids,
            entities=entities_copy,
            relationships=relationships_copy,
            hypotheses=hypotheses_copy,
            information_requirements=reqs_copy,
            contradictions=contradictions_copy,
            active_plan_id=active_plan_id,
            stopping_condition=stopping_condition,
            metadata=metadata or {},
        )

        snapshot.seal()
        self._snapshots.append(snapshot)
        return snapshot

    def get_by_sequence(self, sequence: int) -> Optional[InvestigationSnapshot]:
        """Retrieve snapshot by 1-based sequence index."""
        if 1 <= sequence <= len(self._snapshots):
            return self._snapshots[sequence - 1]
        return None

    def get_by_id(self, snapshot_id: str) -> Optional[InvestigationSnapshot]:
        """Retrieve snapshot by UUID string."""
        for snap in self._snapshots:
            if snap.snapshot_id == snapshot_id:
                return snap
        return None

    def get(self, sequence_or_id: Union[int, str]) -> Optional[InvestigationSnapshot]:
        """Retrieve snapshot by integer sequence or string ID."""
        if isinstance(sequence_or_id, int):
            return self.get_by_sequence(sequence_or_id)
        if isinstance(sequence_or_id, str):
            if sequence_or_id.isdigit():
                return self.get_by_sequence(int(sequence_or_id))
            return self.get_by_id(sequence_or_id)
        return None

    def compare(
        self,
        first: Union[int, str, InvestigationSnapshot],
        second: Union[int, str, InvestigationSnapshot],
    ) -> SnapshotDelta:
        """Compute an explainable delta between two snapshots."""
        snap_a = first if isinstance(first, InvestigationSnapshot) else self.get(first)
        snap_b = second if isinstance(second, InvestigationSnapshot) else self.get(second)

        if not snap_a or not snap_b:
            raise KeyError("Both snapshots must exist to compute a delta.")

        # Ensure comparison order is chronological (a <= b)
        if snap_a.sequence > snap_b.sequence:
            snap_a, snap_b = snap_b, snap_a

        # 1. State transition
        state_trans = None
        if snap_a.dfa_state != snap_b.dfa_state:
            state_trans = (snap_a.dfa_state, snap_b.dfa_state)

        # 2. Evidence added
        ev_a = set(snap_a.evidence_ids)
        ev_b = set(snap_b.evidence_ids)
        added_ev = sorted(list(ev_b - ev_a))

        # 3. Entities added
        entities_a = set(snap_a.entities.keys())
        entities_b = set(snap_b.entities.keys())
        added_entities = sorted(list(entities_b - entities_a))

        # 4. Relationships added
        rel_diff = max(0, len(snap_b.relationships) - len(snap_a.relationships))

        # 5. Hypothesis changes
        hyp_changes: Dict[str, Dict[str, Any]] = {}
        all_hyps = set(snap_a.hypotheses.keys()) | set(snap_b.hypotheses.keys())
        for hid in all_hyps:
            ha = snap_a.hypotheses.get(hid)
            hb = snap_b.hypotheses.get(hid)
            if not ha and hb:
                hyp_changes[hid] = {
                    "type": "CREATED",
                    "statement": hb.statement,
                    "new_status": hb.status,
                    "confidence": hb.confidence,
                }
            elif ha and hb:
                if ha.status != hb.status or ha.confidence != hb.confidence:
                    hyp_changes[hid] = {
                        "type": "MUTATED",
                        "statement": hb.statement,
                        "old_status": ha.status,
                        "new_status": hb.status,
                        "old_confidence": ha.confidence,
                        "new_confidence": hb.confidence,
                    }

        # 6. Requirement changes
        req_changes: Dict[str, Dict[str, Any]] = {}
        all_reqs = set(snap_a.information_requirements.keys()) | set(snap_b.information_requirements.keys())
        for rid in all_reqs:
            ra = snap_a.information_requirements.get(rid)
            rb = snap_b.information_requirements.get(rid)
            if not ra and rb:
                req_changes[rid] = {"type": "CREATED", "new_status": rb.status.value}
            elif ra and rb and ra.status != rb.status:
                req_changes[rid] = {
                    "type": "STATUS_CHANGED",
                    "old_status": ra.status.value,
                    "new_status": rb.status.value,
                }

        # 7. Contradictions
        c_a = {c.id for c in snap_a.contradictions}
        c_b = {c.id for c in snap_b.contradictions}
        new_contradictions = sorted(list(c_b - c_a))
        resolved_contradictions = [
            c.id for c in snap_b.contradictions if c.resolved and (c.id not in c_a or not snap_a.contradictions)
        ]

        # 8. Plan change
        plan_changed = snap_a.active_plan_id != snap_b.active_plan_id

        return SnapshotDelta(
            investigation_id=self.investigation_id,
            from_sequence=snap_a.sequence,
            to_sequence=snap_b.sequence,
            from_snapshot_id=snap_a.snapshot_id,
            to_snapshot_id=snap_b.snapshot_id,
            dfa_state_transition=state_trans,
            added_evidence_ids=added_ev,
            added_entities=added_entities,
            added_relationships=rel_diff,
            hypothesis_changes=hyp_changes,
            requirement_changes=req_changes,
            new_contradictions=new_contradictions,
            resolved_contradictions=resolved_contradictions,
            plan_changed=plan_changed,
        )

    def explain(self, snapshot: InvestigationSnapshot) -> Dict[str, Any]:
        """Explain the complete investigative posture at this snapshot."""
        return {
            "snapshot_id": snapshot.snapshot_id,
            "sequence": snapshot.sequence,
            "timestamp": snapshot.timestamp.isoformat(),
            "trigger": snapshot.trigger,
            "dfa_state": snapshot.dfa_state,
            "evidence_count": len(snapshot.evidence_ids),
            "entities": {
                eid: {"name": ent.name, "type": ent.type}
                for eid, ent in snapshot.entities.items()
            },
            "hypotheses": {
                hid: {"statement": hyp.statement, "status": hyp.status, "confidence": hyp.confidence}
                for hid, hyp in snapshot.hypotheses.items()
            },
            "requirements": {
                rid: {"target": req.target_or_entity, "status": req.status.value, "purpose": req.description}
                for rid, req in snapshot.information_requirements.items()
            },
            "unresolved_contradictions": len([c for c in snapshot.contradictions if not c.resolved]),
            "digest": snapshot.state_digest,
            "integrity_valid": snapshot.verify_integrity(),
        }
