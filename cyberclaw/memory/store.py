"""Persistent and revisionable Experience Store for CyberClaw Core."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.memory.experience import ExperienceRecord, utc_now


class ExperienceStore:
    """Store for operational experiences supporting auditable revisions."""

    def __init__(self, investigation_id: Optional[str] = None) -> None:
        self.investigation_id = investigation_id
        self._records: Dict[str, ExperienceRecord] = {}

    def record(
        self,
        action: str,
        context: Dict[str, Any],
        result: ExecutionResult,
        lesson: str,
        conditions: Optional[Dict[str, Any]] = None,
        scope: str = "global",
        investigation_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ExperienceRecord:
        """Create and store an experience record from an execution result."""
        evidence_ids = [ev.id for ev in result.evidence]
        failure_reason = result.error if result.is_failure else None

        record = ExperienceRecord(
            investigation_id=investigation_id or self.investigation_id,
            action=action,
            context=context,
            result_status=result.status,
            evidence_ids=evidence_ids,
            success=result.completed_normally,
            failure_reason=failure_reason,
            lesson=lesson,
            conditions=conditions or {},
            scope=scope,
            metadata=metadata or {},
        )
        self._records[record.id] = record
        return record

    def add_record(self, record: ExperienceRecord) -> ExperienceRecord:
        """Directly add an existing structured ExperienceRecord."""
        self._records[record.id] = record
        return record

    def get(self, experience_id: str) -> Optional[ExperienceRecord]:
        """Retrieve an experience record by ID."""
        return self._records.get(experience_id)

    def list_all(self, include_superseded: bool = False) -> List[ExperienceRecord]:
        """List experiences, by default only returning active (un-superseded) records."""
        if include_superseded:
            return list(self._records.values())
        return [r for r in self._records.values() if r.is_active]

    def find_by_action(self, action: str, include_superseded: bool = False) -> List[ExperienceRecord]:
        """Find experiences for a specific action."""
        records = self.list_all(include_superseded=include_superseded)
        return [r for r in records if r.action == action]

    def find_by_scope(self, scope: str, include_superseded: bool = False) -> List[ExperienceRecord]:
        """Find experiences for a given scope."""
        records = self.list_all(include_superseded=include_superseded)
        return [r for r in records if r.scope == scope]

    def revise(
        self,
        experience_id: str,
        contradiction_evidence_ids: List[str],
        revised_lesson: str,
        revised_conditions: Optional[Dict[str, Any]] = None,
        revision_reason: Optional[str] = None,
        new_evidence_ids: Optional[List[str]] = None,
    ) -> ExperienceRecord:
        """Revise an existing experience record when new evidence contradicts it.

        Follows the 4-step revision protocol:
        1. Identify the contradiction (tracked via contradiction_evidence_ids).
        2. Determine the scope of the old conclusion (inherited or refined).
        3. Revise the lesson with new conditions.
        4. Preserve the conditions under which the old lesson was valid,
           marking the old record superseded while retaining complete history.
        """
        old_record = self._records.get(experience_id)
        if old_record is None:
            raise KeyError(f"Experience record '{experience_id}' not found for revision.")

        now = utc_now()

        # Combine old evidence and new contradiction evidence
        combined_evidence = list(old_record.evidence_ids)
        if new_evidence_ids:
            for eid in new_evidence_ids:
                if eid not in combined_evidence:
                    combined_evidence.append(eid)

        merged_conditions = dict(old_record.conditions)
        if revised_conditions:
            merged_conditions.update(revised_conditions)

        # Step 3 & 4: Create revised record referencing old record
        revised_record = ExperienceRecord(
            investigation_id=old_record.investigation_id,
            action=old_record.action,
            context=old_record.context,
            result_status=old_record.result_status,
            evidence_ids=combined_evidence,
            success=old_record.success,
            failure_reason=old_record.failure_reason,
            lesson=revised_lesson,
            conditions=merged_conditions,
            scope=old_record.scope,
            revision=old_record.revision + 1,
            revises_experience_id=old_record.id,
            contradiction_evidence_ids=contradiction_evidence_ids,
            created_at=now,
            updated_at=now,
            metadata={
                **old_record.metadata,
                "revision_reason": revision_reason or "Contradicted by new evidence",
                "prior_lesson": old_record.lesson,
                "prior_conditions": old_record.conditions,
            },
        )

        # Mark old record superseded, preserving its original conditions and reason
        old_record.superseded_by = revised_record.id
        old_record.updated_at = now
        old_record.metadata["superseded_at"] = now.isoformat()
        old_record.metadata["superseded_reason"] = revision_reason or "Contradicted by new evidence"

        self._records[revised_record.id] = revised_record
        return revised_record

    def clear(self) -> None:
        """Clear store."""
        self._records.clear()
