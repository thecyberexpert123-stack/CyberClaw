"""Normalize experiences into comparable features without erasing source context."""

from __future__ import annotations

import re
from typing import Any, List

from cyberclaw.learning.models import (
    NORMALIZATION_VERSION,
    InvestigationExperience,
    NormalizedExperience,
    NormalizedFeature,
    canonical_digest,
    stable_id,
)

_STOPWORDS = {"the", "a", "an", "of", "to", "and", "or", "for", "in", "on", "with", "about"}
_WS = re.compile(r"\s+")


def normalize_text(value: str) -> str:
    return _WS.sub(" ", value.strip().lower())


def objective_tokens(text: str) -> List[str]:
    raw = "".join(ch.lower() if ch.isalnum() else " " for ch in text)
    return sorted({token for token in raw.split() if token and token not in _STOPWORDS})


def _collapse_consecutive(items: List[str]) -> List[str]:
    collapsed: List[str] = []
    for item in items:
        if not collapsed or collapsed[-1] != item:
            collapsed.append(item)
    return collapsed


class ExperienceNormalizer:
    """Produce a comparable representation. Original records remain on the experience."""

    @classmethod
    def normalize(cls, experience: InvestigationExperience) -> NormalizedExperience:
        record_ids = [ref.record_id for ref in experience.authoritative_refs]
        successful_caps = [
            action.capability_id
            for action in experience.actions_taken
            if action.capability_id and not action.error and str(action.status).upper() not in {"FAILURE", "FAILED"}
        ]
        capability_sequence = _collapse_consecutive(successful_caps)
        specialist_sequence = []
        for action in experience.actions_taken:
            if action.specialist_id and action.specialist_id not in specialist_sequence:
                specialist_sequence.append(action.specialist_id)
        for specialist in experience.specialists_involved:
            if specialist not in specialist_sequence:
                specialist_sequence.append(specialist)

        requirement_sequence = []
        for req in experience.initial_information_requirements + experience.requirements_resolved + experience.requirements_unresolved:
            types = ",".join(sorted(req.get("evidence_types_sought") or []))
            key = f"{types}|{normalize_text(req.get('description') or '')}"
            if key not in requirement_sequence:
                requirement_sequence.append(key)

        collaboration_sequence: List[str] = []
        for collab in experience.collaboration_patterns:
            details = collab.get("details") or {}
            participants = details.get("sequence") or details.get("participants") or []
            for participant in participants:
                if participant not in collaboration_sequence:
                    collaboration_sequence.append(participant)

        resolved_types = sorted(
            {
                c.get("conflict_type")
                for c in experience.contradictions
                if c.get("resolved") and c.get("conflict_type")
            }
        )
        failure_types = sorted(
            {
                (failure.get("error") or "unspecified_failure")
                for failure in experience.failures
            }
        )
        evidence_yield = len(experience.evidence_generated)
        timestamp = experience.extracted_at

        def feature(name: str, value: Any, extra_ids: List[str] | None = None) -> NormalizedFeature:
            return NormalizedFeature(
                name=name,
                value=value,
                source_investigation_id=experience.investigation_id,
                source_record_ids=sorted(set(record_ids + (extra_ids or []))),
                normalization_version=NORMALIZATION_VERSION,
                timestamp=timestamp,
            )

        features = [
            feature("action_sequence", [action.model_dump(mode="json") for action in experience.actions_taken]),
            feature("requirement_sequence", requirement_sequence),
            feature("specialist_participation", specialist_sequence),
            feature("capability_usage", capability_sequence),
            feature("evidence_yield", evidence_yield),
            feature("contradiction_frequency", len(experience.contradictions)),
            feature("planning_decisions", experience.plan_count),
            feature("collaboration_topology", collaboration_sequence),
            feature(
                "time_to_resolution_ms",
                experience.execution_duration_ms if experience.stopping_condition else None,
            ),
            feature(
                "failure_retry",
                {"failure_count": len(experience.failures), "retry_count": experience.retry_count},
            ),
        ]
        payload = {
            "experience_id": experience.experience_id,
            "normalization_version": NORMALIZATION_VERSION,
            "capability_sequence": capability_sequence,
            "specialist_sequence": specialist_sequence,
            "requirement_sequence": requirement_sequence,
            "evidence_yield": evidence_yield,
            "contradiction_count": len(experience.contradictions),
            "resolved_contradiction_types": resolved_types,
            "failure_types": failure_types,
            "collaboration_sequence": collaboration_sequence,
            "objective_tokens": objective_tokens(experience.objective),
        }
        digest = canonical_digest(payload)
        return NormalizedExperience(
            normalized_id=stable_id("norm", experience.experience_id, digest),
            experience_id=experience.experience_id,
            investigation_id=experience.investigation_id,
            timestamp=timestamp,
            features=features,
            capability_sequence=capability_sequence,
            specialist_sequence=specialist_sequence,
            requirement_sequence=requirement_sequence,
            evidence_yield=evidence_yield,
            contradiction_count=len(experience.contradictions),
            resolved_contradiction_types=resolved_types,
            failure_types=failure_types,
            collaboration_sequence=collaboration_sequence,
            objective_tokens=objective_tokens(experience.objective),
            content_digest=digest,
        )
