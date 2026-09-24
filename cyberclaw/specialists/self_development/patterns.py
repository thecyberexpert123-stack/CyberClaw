"""Pattern detection over operational Experience records."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.memory.experience import ExperienceRecord


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class PatternType(str, Enum):
    """Categorization of detected operational patterns."""

    REPEATED_SUCCESS = "repeated_success"
    REPEATED_FAILURE = "repeated_failure"
    FALLBACK_SUPERIOR = "fallback_superior"
    SEQUENCE_SYNERGY = "sequence_synergy"


class PatternObservation(BaseModel):
    """Structured observation of an operational regularity or pattern."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    pattern_type: PatternType
    source_experience_ids: List[str] = Field(default_factory=list)
    description: str
    action_or_sequence: List[str] = Field(default_factory=list)
    conditions: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    revision: int = Field(default=1)
    superseded_by: Optional[str] = None
    revises_pattern_id: Optional[str] = None
    contradiction_evidence_ids: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_active(self) -> bool:
        return self.superseded_by is None


class PatternDetector:
    """Deterministic pattern detector analyzing operational experiences."""

    def __init__(self, min_occurrence_threshold: int = 2) -> None:
        self.min_occurrence_threshold = min_occurrence_threshold
        self._patterns: Dict[str, PatternObservation] = {}

    def detect_patterns(self, experiences: List[ExperienceRecord]) -> List[PatternObservation]:
        """Analyze a list of experiences and detect recurring success, failure, or synergy patterns."""
        active_exps = [e for e in experiences if e.is_active]
        if not active_exps:
            return []

        detected: List[PatternObservation] = []

        # 1. Group by action
        action_successes: Dict[str, List[ExperienceRecord]] = {}
        action_failures: Dict[str, List[ExperienceRecord]] = {}

        for exp in active_exps:
            if exp.success:
                action_successes.setdefault(exp.action, []).append(exp)
            else:
                action_failures.setdefault(exp.action, []).append(exp)

        # Detect repeated successes
        for action, exps in action_successes.items():
            if len(exps) >= self.min_occurrence_threshold:
                # Check for common condition key
                common_conditions: Dict[str, Any] = {}
                first_conds = exps[0].conditions
                for k, v in first_conds.items():
                    if all(e.conditions.get(k) == v for e in exps):
                        common_conditions[k] = v

                pat = PatternObservation(
                    pattern_type=PatternType.REPEATED_SUCCESS,
                    source_experience_ids=[e.id for e in exps],
                    description=f"Action '{action}' consistently succeeds under conditions {common_conditions}.",
                    action_or_sequence=[action],
                    conditions=common_conditions,
                    confidence=min(0.95, 0.6 + (0.1 * len(exps))),
                )
                detected.append(pat)
                self._patterns[pat.id] = pat

        # Detect repeated failures
        for action, exps in action_failures.items():
            if len(exps) >= self.min_occurrence_threshold:
                common_conditions = {}
                first_conds = exps[0].conditions
                for k, v in first_conds.items():
                    if all(e.conditions.get(k) == v for e in exps):
                        common_conditions[k] = v

                pat = PatternObservation(
                    pattern_type=PatternType.REPEATED_FAILURE,
                    source_experience_ids=[e.id for e in exps],
                    description=f"Action '{action}' consistently fails under conditions {common_conditions}.",
                    action_or_sequence=[action],
                    conditions=common_conditions,
                    confidence=min(0.95, 0.6 + (0.1 * len(exps))),
                )
                detected.append(pat)
                self._patterns[pat.id] = pat

        return detected

    def revise_pattern(
        self,
        pattern_id: str,
        contradiction_evidence_ids: List[str],
        revised_description: str,
        revised_conditions: Dict[str, Any],
        reason: str,
    ) -> PatternObservation:
        """Revise a pattern observation when new contradictory evidence arrives.

        Preserves historical version, increments revision, and marks original superseded.
        """
        old_pattern = self._patterns.get(pattern_id)
        if not old_pattern:
            raise KeyError(f"Pattern '{pattern_id}' not found for revision.")

        now = utc_now()
        revised = PatternObservation(
            pattern_type=old_pattern.pattern_type,
            source_experience_ids=list(old_pattern.source_experience_ids),
            description=revised_description,
            action_or_sequence=list(old_pattern.action_or_sequence),
            conditions=revised_conditions,
            confidence=max(0.5, old_pattern.confidence - 0.2),  # Lowered due to contradiction
            created_at=now,
            updated_at=now,
            revision=old_pattern.revision + 1,
            revises_pattern_id=old_pattern.id,
            contradiction_evidence_ids=contradiction_evidence_ids,
            metadata={
                **old_pattern.metadata,
                "revision_reason": reason,
                "prior_description": old_pattern.description,
                "prior_conditions": old_pattern.conditions,
            },
        )

        old_pattern.superseded_by = revised.id
        old_pattern.updated_at = now
        old_pattern.metadata["superseded_reason"] = reason

        self._patterns[revised.id] = revised
        return revised

    def get_pattern(self, pattern_id: str) -> Optional[PatternObservation]:
        return self._patterns.get(pattern_id)

    def list_patterns(self, include_superseded: bool = False) -> List[PatternObservation]:
        if include_superseded:
            return list(self._patterns.values())
        return [p for p in self._patterns.values() if p.is_active]
