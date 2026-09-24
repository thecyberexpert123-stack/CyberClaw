"""Deterministic pattern detection. Patterns describe recurrence; they are not strategies."""

from __future__ import annotations

from typing import Dict, List, Sequence

from cyberclaw.learning.clustering import SourceFamilyGrouper
from cyberclaw.learning.confidence import PatternConfidenceModel
from cyberclaw.learning.models import (
    PATTERN_ALGORITHM,
    PATTERN_ALGORITHM_PARAMETERS,
    PATTERN_DETECTOR_VERSION,
    CollaborationPattern,
    ExclusionRecord,
    FailurePattern,
    InvestigationExperience,
    NormalizedExperience,
    ObservedPattern,
    OutcomeClass,
    PatternInstance,
    PatternKind,
    PatternScope,
    PromotionThresholdPolicy,
    canonical_digest,
    stable_id,
)


def _yield_bucket(evidence_yield: int, action_count: int) -> str:
    if evidence_yield <= 0:
        return "ZERO"
    if action_count <= 0 or evidence_yield < action_count:
        return "LOW"
    return "HIGH"


class PatternDetectionResult:
    def __init__(
        self,
        patterns: List[ObservedPattern],
        failure_patterns: List[FailurePattern],
        collaboration_patterns: List[CollaborationPattern],
        excluded: List[ExclusionRecord],
    ) -> None:
        self.patterns = patterns
        self.failure_patterns = failure_patterns
        self.collaboration_patterns = collaboration_patterns
        self.excluded = excluded


class PatternDetector:
    """Group exact canonical signatures. Does not conclude that a pattern always works."""

    VERSION = PATTERN_DETECTOR_VERSION
    ALGORITHM = PATTERN_ALGORITHM

    @classmethod
    def detect(
        cls,
        experiences: Sequence[InvestigationExperience],
        normalized: Dict[str, NormalizedExperience],
        policy: PromotionThresholdPolicy,
    ) -> PatternDetectionResult:
        authoritative = [exp for exp in experiences if not exp.is_counterfactual]
        excluded = [
            ExclusionRecord(
                investigation_id=exp.investigation_id,
                experience_id=exp.experience_id,
                reason="COUNTERFACTUAL_RESULT_IS_NOT_HISTORICAL_RESULT",
            )
            for exp in experiences
            if exp.is_counterfactual
        ]
        clustering = SourceFamilyGrouper.group(authoritative)
        buckets: Dict[tuple, List[InvestigationExperience]] = {}

        def add(kind: PatternKind, signature: str, experience: InvestigationExperience) -> None:
            if not signature:
                excluded.append(
                    ExclusionRecord(
                        investigation_id=experience.investigation_id,
                        experience_id=experience.experience_id,
                        reason=f"INSUFFICIENT_STRUCTURE_FOR_{kind.value}",
                    )
                )
                return
            buckets.setdefault((kind, signature), []).append(experience)

        for experience in authoritative:
            norm = normalized.get(experience.experience_id)
            if norm is None:
                excluded.append(
                    ExclusionRecord(
                        investigation_id=experience.investigation_id,
                        experience_id=experience.experience_id,
                        reason="MISSING_NORMALIZATION",
                    )
                )
                continue
            cap_sig = ">".join(norm.capability_sequence)
            if experience.outcome == OutcomeClass.FAILURE or norm.failure_types:
                fail_sig = ",".join(norm.failure_types) or "unspecified"
                preceding = cap_sig or ">".join(experience.capabilities_used) or "none"
                if experience.outcome == OutcomeClass.FAILURE:
                    add(PatternKind.REPEATED_FAILURE, f"failure:{fail_sig}:{preceding}", experience)
            if cap_sig:
                add(PatternKind.CAPABILITY_SEQUENCE_PATTERN, f"capseq:{cap_sig}", experience)
                if experience.outcome == OutcomeClass.SUCCESS:
                    add(PatternKind.REPEATED_SUCCESS, f"success:{cap_sig}", experience)
                add(
                    PatternKind.EVIDENCE_YIELD_PATTERN,
                    f"yield:{_yield_bucket(norm.evidence_yield, len(experience.actions_taken))}:{cap_sig}",
                    experience,
                )
            if len(norm.collaboration_sequence) >= 2:
                add(
                    PatternKind.SPECIALIST_COLLABORATION_PATTERN,
                    "collab:" + ">".join(norm.collaboration_sequence),
                    experience,
                )
            elif len(norm.specialist_sequence) >= 2:
                add(
                    PatternKind.SPECIALIST_COLLABORATION_PATTERN,
                    "collab:" + ">".join(norm.specialist_sequence),
                    experience,
                )
            if norm.requirement_sequence:
                add(
                    PatternKind.REPEATED_REQUIREMENT_SEQUENCE,
                    "reqseq:" + ">".join(norm.requirement_sequence),
                    experience,
                )
            if norm.resolved_contradiction_types:
                add(
                    PatternKind.REPEATED_CONTRADICTION_RESOLUTION,
                    "contradiction_resolved:" + ",".join(norm.resolved_contradiction_types),
                    experience,
                )
            if experience.plan_count >= 2 and norm.requirement_sequence:
                add(
                    PatternKind.PLANNING_ADAPTATION_PATTERN,
                    f"adapt:{experience.plan_count}:" + ">".join(norm.requirement_sequence),
                    experience,
                )
            if experience.failures and experience.outcome == OutcomeClass.SUCCESS and cap_sig:
                add(
                    PatternKind.RECOVERY_PATTERN,
                    "recovery:" + ",".join(norm.failure_types) + ">" + cap_sig,
                    experience,
                )
            if experience.stopping_condition:
                add(PatternKind.STOPPING_PATTERN, f"stop:{experience.stopping_condition}", experience)

        patterns: List[ObservedPattern] = []
        for (kind, signature), members in sorted(buckets.items(), key=lambda item: (item[0][0].value, item[0][1])):
            patterns.append(cls._materialize(kind, signature, members, clustering, excluded, policy))

        failure_patterns = cls._failure_patterns(authoritative, normalized, clustering)
        collaboration_patterns = cls._collaboration_patterns(patterns, authoritative)
        return PatternDetectionResult(patterns, failure_patterns, collaboration_patterns, excluded)

    @classmethod
    def _materialize(
        cls,
        kind: PatternKind,
        signature: str,
        members: Sequence[InvestigationExperience],
        clustering,
        global_excluded: Sequence[ExclusionRecord],
        policy: PromotionThresholdPolicy,
    ) -> ObservedPattern:
        pattern_id = stable_id("pattern", kind.value, signature)
        family_ids = sorted({clustering.experience_to_family[m.experience_id] for m in members})
        case_ids = sorted({m.investigation_id for m in members})
        success = sum(1 for m in members if m.outcome == OutcomeClass.SUCCESS)
        failure = sum(1 for m in members if m.outcome == OutcomeClass.FAILURE)
        mixed = sum(1 for m in members if m.outcome == OutcomeClass.MIXED)
        indeterminate = sum(1 for m in members if m.outcome == OutcomeClass.INDETERMINATE)
        contradiction_count = sum(len(m.contradictions) for m in members)
        confidence = PatternConfidenceModel.assess(
            sample_count=len(members),
            independent_case_count=len(case_ids),
            independent_source_family_count=len(family_ids),
            success_count=success,
            failure_count=failure,
            contradiction_count=contradiction_count,
            mixed_count=mixed,
            indeterminate_count=indeterminate,
            policy=policy,
        )
        scope = cls._scope(len(case_ids), len(family_ids), success, failure, policy)
        instances = []
        for member in sorted(members, key=lambda item: item.experience_id):
            instances.append(
                PatternInstance(
                    instance_id=stable_id("pinst", pattern_id, member.experience_id),
                    pattern_id=pattern_id,
                    experience_id=member.experience_id,
                    investigation_id=member.investigation_id,
                    source_family_id=clustering.experience_to_family[member.experience_id],
                    supporting_event_ids=sorted(ref.record_id for ref in member.authoritative_refs),
                    outcome=member.outcome,
                    observed_sequence=signature.split(":")[-1].split(">"),
                )
            )
        relevant_excluded = [
            item
            for item in global_excluded
            if item.reason.startswith("INSUFFICIENT_STRUCTURE") or item.reason.startswith("COUNTERFACTUAL")
        ]
        cap_sequence = []
        specialist_sequence = []
        if members:
            # Representative sequence is the signature payload, not a vote.
            if kind in {
                PatternKind.CAPABILITY_SEQUENCE_PATTERN,
                PatternKind.REPEATED_SUCCESS,
                PatternKind.RECOVERY_PATTERN,
                PatternKind.EVIDENCE_YIELD_PATTERN,
            }:
                cap_sequence = [part for part in signature.split(":")[-1].split(">") if part and not part.startswith("failure")]
            if kind == PatternKind.SPECIALIST_COLLABORATION_PATTERN:
                specialist_sequence = [part for part in signature.split(":")[-1].split(">") if part]
        description = (
            f"Observed regularity {kind.value} with signature '{signature}' "
            f"in {len(members)} experience(s), {len(case_ids)} investigation(s), "
            f"{len(family_ids)} independent source family(ies). "
            f"Successful in {success}, unsuccessful in {failure}. "
            "This does not mean the regularity always works."
        )
        payload = {
            "pattern_id": pattern_id,
            "kind": kind.value,
            "signature": signature,
            "scope": scope.value,
            "instance_ids": [inst.instance_id for inst in instances],
            "detector_version": cls.VERSION,
            "threshold_policy_version": policy.version,
        }
        return ObservedPattern(
            pattern_id=pattern_id,
            version="1.0.0",
            kind=kind,
            signature=signature,
            description=description,
            scope=scope,
            instances=instances,
            sample_count=len(members),
            independent_case_count=len(case_ids),
            independent_source_family_count=len(family_ids),
            success_count=success,
            failure_count=failure,
            contradiction_count=contradiction_count,
            excluded=relevant_excluded,
            confidence=confidence,
            threshold_policy_id=policy.policy_id,
            threshold_policy_version=policy.version,
            capability_sequence=cap_sequence,
            specialist_sequence=specialist_sequence,
            algorithm_parameters=dict(PATTERN_ALGORITHM_PARAMETERS),
            content_digest=canonical_digest(payload),
        )

    @staticmethod
    def _scope(
        cases: int,
        families: int,
        success: int,
        failure: int,
        policy: PromotionThresholdPolicy,
    ) -> PatternScope:
        if cases < policy.min_independent_cases or families < policy.min_independent_source_families:
            return PatternScope.CASE_LOCAL
        if (
            success >= policy.min_success_observations_for_proposal
            and success > failure
            and families >= policy.min_independent_source_families
        ):
            return PatternScope.VALIDATED
        return PatternScope.CANDIDATE_GLOBAL

    @classmethod
    def _failure_patterns(
        cls,
        experiences: Sequence[InvestigationExperience],
        normalized: Dict[str, NormalizedExperience],
        clustering,
    ) -> List[FailurePattern]:
        grouped: Dict[str, List[InvestigationExperience]] = {}
        for experience in experiences:
            if experience.outcome != OutcomeClass.FAILURE and not experience.failures:
                continue
            norm = normalized.get(experience.experience_id)
            preceding = []
            if norm and norm.capability_sequence:
                preceding = list(norm.capability_sequence)
            elif experience.capabilities_used:
                preceding = list(experience.capabilities_used)
            failure_type = ",".join(sorted({f.get("error") or "unspecified_failure" for f in experience.failures})) or "unspecified_failure"
            signature = f"{failure_type}|{' > '.join(preceding)}"
            grouped.setdefault(signature, []).append(experience)
        results = []
        for signature, members in sorted(grouped.items()):
            failure_type, _, preceding = signature.partition("|")
            results.append(
                FailurePattern(
                    failure_pattern_id=stable_id("failpat", signature),
                    failure_type=failure_type,
                    trigger_context={
                        "source_families": sorted(
                            {clustering.experience_to_family[m.experience_id] for m in members}
                        ),
                        "case_stages": sorted({m.case_stage for m in members if m.case_stage}),
                    },
                    preceding_actions=[part for part in preceding.split(" > ") if part],
                    specialists_involved=sorted({s for m in members for s in m.specialists_involved}),
                    capabilities_involved=sorted({c for m in members for c in m.capabilities_used}),
                    authorization_outcome=next(
                        (
                            outcome.get("decision")
                            for m in members
                            for outcome in m.authorization_outcomes
                            if outcome.get("decision")
                        ),
                        None,
                    ),
                    recovery_behavior="recovered" if any(m.outcome == OutcomeClass.SUCCESS for m in members) else "not_observed",
                    final_result=members[-1].outcome.value,
                    supporting_experience_ids=sorted(m.experience_id for m in members),
                    supporting_case_ids=sorted(m.investigation_id for m in members),
                    statement=(
                        "This action sequence was repeatedly observed alongside no actionable or failed outcomes "
                        "under the recorded context. This is an observed correlation, not a causal explanation."
                    ),
                )
            )
        return results

    @staticmethod
    def _collaboration_patterns(
        patterns: Sequence[ObservedPattern],
        experiences: Sequence[InvestigationExperience],
    ) -> List[CollaborationPattern]:
        by_id = {exp.experience_id: exp for exp in experiences}
        results = []
        for pattern in patterns:
            if pattern.kind != PatternKind.SPECIALIST_COLLABORATION_PATTERN:
                continue
            members = [by_id[inst.experience_id] for inst in pattern.instances if inst.experience_id in by_id]
            outcomes: Dict[str, int] = {}
            for member in members:
                outcomes[member.outcome.value] = outcomes.get(member.outcome.value, 0) + 1
            results.append(
                CollaborationPattern(
                    collaboration_pattern_id=stable_id("collabpat", pattern.signature),
                    participants=list(pattern.specialist_sequence),
                    sequence=list(pattern.specialist_sequence),
                    dependencies=[],
                    context={"signature": pattern.signature, "scope": pattern.scope.value},
                    outcomes=outcomes,
                    supporting_cases=sorted({m.investigation_id for m in members}),
                    failures=[m.investigation_id for m in members if m.outcome == OutcomeClass.FAILURE],
                )
            )
        return results


def explain_pattern(pattern: ObservedPattern) -> Dict[str, object]:
    """Answer provenance questions for a detected pattern without adding causal claims."""
    successes = [inst.investigation_id for inst in pattern.instances if inst.outcome == OutcomeClass.SUCCESS]
    failures = [inst.investigation_id for inst in pattern.instances if inst.outcome == OutcomeClass.FAILURE]
    return {
        "pattern_id": pattern.pattern_id,
        "version": pattern.version,
        "cases": sorted({inst.investigation_id for inst in pattern.instances}),
        "supporting_event_ids": sorted({eid for inst in pattern.instances for eid in inst.supporting_event_ids}),
        "successful_cases": successes,
        "unsuccessful_cases": failures,
        "excluded": [item.model_dump(mode="json") for item in pattern.excluded],
        "exclusion_reasons": sorted({item.reason for item in pattern.excluded}),
        "independent_source_families": pattern.independent_source_family_count,
        "causal_claim": "NONE",
        "statement": pattern.description,
        "detector_version": pattern.detector_version,
        "threshold_policy_version": pattern.threshold_policy_version,
    }
