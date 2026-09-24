"""Explainable evidence consensus synthesis, source independence verification, and hypothesis state integration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple
from cyberclaw.collaboration.models import (
    ConsensusAssessment,
    ConsensusStatus,
    ConflictStatus,
    SpecialistConflict,
    utc_now,
)
from cyberclaw.evidence.models import Evidence

if TYPE_CHECKING:
    from cyberclaw.types import Hypothesis


class ConsensusEngine:
    """Synthesizes structured evidence into explainable consensus without majority-rule fallacies."""

    @classmethod
    def are_sources_independent(cls, ev_a: Evidence, ev_b: Evidence) -> bool:
        """Verify whether two evidence items originate from independent upstream sources."""
        # 1. Identical source identifier or name means not independent
        if ev_a.source.id == ev_b.source.id:
            return False
        if ev_a.source.name and ev_b.source.name and ev_a.source.name.lower() == ev_b.source.name.lower():
            return False

        # 2. Check underlying source metadata (e.g. same_source marker)
        if ev_a.metadata.get("same_source_as") == ev_b.id or ev_b.metadata.get("same_source_as") == ev_a.id:
            return False

        # 3. Lineage derivation check: if ev_b is derived from ev_a and is not an independent empirical observation
        nature_a = ev_a.metadata.get("finding_nature")
        nature_b = ev_b.metadata.get("finding_nature")
        derived_b = set(ev_b.metadata.get("derived_from_evidence_ids", []))
        derived_a = set(ev_a.metadata.get("derived_from_evidence_ids", []))

        if ev_a.id in derived_b:
            if nature_b != "OBSERVATION" or ev_b.source.type == "inference":
                return False

        if ev_b.id in derived_a:
            if nature_a != "OBSERVATION" or ev_a.source.type == "inference":
                return False

        return True

    @classmethod
    def evaluate_consensus(
        cls,
        subject: str,
        evidence_items: List[Evidence],
        conflicts: List[SpecialistConflict],
    ) -> ConsensusAssessment:
        """Formulate an explainable consensus assessment for a subject based on empirical evidence and active conflicts."""
        reasons: List[str] = []
        active_conflicts = [
            c.conflict_id for c in conflicts
            if c.subject == subject and c.status in (ConflictStatus.OPEN, ConflictStatus.UNDER_REVIEW, ConflictStatus.PERSISTENT)
        ]

        relevant_evidence = [e for e in evidence_items if e.subject == subject]
        if not relevant_evidence:
            return ConsensusAssessment(
                subject=subject,
                consensus_status=ConsensusStatus.UNVERIFIED,
                confidence_score=0.0,
                independent_sources_count=0,
                total_sources_count=0,
                is_independently_corroborated=False,
                explanation="No evidence items found for this subject.",
                reasons=["Zero evidence items recorded."],
            )

        # 1. If active conflicts exist on this subject -> CONTESTED
        if active_conflicts:
            reasons.append(f"Subject has {len(active_conflicts)} active unresolved specialist conflicts.")
            return ConsensusAssessment(
                subject=subject,
                consensus_status=ConsensusStatus.CONTESTED,
                confidence_score=0.4,
                independent_sources_count=len({e.source.id for e in relevant_evidence}),
                total_sources_count=len(relevant_evidence),
                is_independently_corroborated=False,
                supporting_evidence_ids=[e.id for e in relevant_evidence],
                active_conflicts=active_conflicts,
                explanation=f"Findings on '{subject}' are contested by active disagreements.",
                reasons=reasons,
            )

        # 2. Evaluate source independence among supporting evidence
        independent_clusters: List[List[Evidence]] = []
        for ev in relevant_evidence:
            placed = False
            for cluster in independent_clusters:
                # If dependent on cluster representative, join it
                if not cls.are_sources_independent(cluster[0], ev):
                    cluster.append(ev)
                    placed = True
                    break
            if not placed:
                independent_clusters.append([ev])

        independent_count = len(independent_clusters)
        total_sources = len(relevant_evidence)

        # 3. Calculate weighted confidence considering observation vs inference
        total_weight = 0.0
        for cluster in independent_clusters:
            # Cluster weight is max confidence in cluster, discounted if purely inference
            max_conf = max(e.confidence for e in cluster)
            is_inference = any(e.metadata.get("finding_nature") == "INFERENCE" or e.metadata.get("is_inferred") for e in cluster)
            weight = (max_conf * 0.8) if is_inference else max_conf
            total_weight += weight

        normalized_confidence = min(1.0, total_weight / max(1, independent_count))

        # Check soft dependency uncertainty penalties
        for ev in relevant_evidence:
            if ev.metadata.get("has_soft_dependency_uncertainty"):
                normalized_confidence *= 0.9
                reasons.append("Uncertainty penalty applied due to unresolved soft dependency.")

        # 4. Determine consensus status
        if independent_count >= 2:
            consensus_status = ConsensusStatus.CORROBORATED
            is_corroborated = True
            reasons.append(f"Corroborated across {independent_count} independent sources.")
            explanation = f"Empirically corroborated by {independent_count} independent sources without active disputes."
        elif independent_count == 1:
            consensus_status = ConsensusStatus.UNVERIFIED
            is_corroborated = False
            reasons.append("Supported by only 1 source cluster; requires independent corroboration.")
            explanation = f"Findings from single source cluster ({relevant_evidence[0].source.name}); awaiting corroboration."
        else:
            consensus_status = ConsensusStatus.INCONCLUSIVE
            is_corroborated = False
            reasons.append("Insufficient evidence to establish corroborated state.")
            explanation = "Evidence is inconclusive."

        return ConsensusAssessment(
            subject=subject,
            consensus_status=consensus_status,
            confidence_score=round(normalized_confidence, 2),
            independent_sources_count=independent_count,
            total_sources_count=total_sources,
            is_independently_corroborated=is_corroborated,
            supporting_evidence_ids=[e.id for e in relevant_evidence],
            active_conflicts=[],
            explanation=explanation,
            reasons=reasons,
        )

    @classmethod
    def update_hypothesis_from_consensus(
        cls,
        hypothesis: Hypothesis,
        consensus: ConsensusAssessment,
    ) -> Hypothesis:
        """Update existing Hypothesis state based on consensus assessment without creating competing abstractions."""
        if consensus.consensus_status == ConsensusStatus.CORROBORATED:
            hypothesis.status = "SUPPORTED"
            hypothesis.confidence = max(hypothesis.confidence, consensus.confidence_score)
            for eid in consensus.supporting_evidence_ids:
                if eid not in hypothesis.supporting_evidence_ids:
                    hypothesis.supporting_evidence_ids.append(eid)

        elif consensus.consensus_status == ConsensusStatus.CONTESTED:
            # Leave open but mark contested and record refuting evidence
            hypothesis.confidence = min(hypothesis.confidence, 0.45)
            for eid in consensus.supporting_evidence_ids:
                if eid not in hypothesis.refuting_evidence_ids:
                    hypothesis.refuting_evidence_ids.append(eid)

        hypothesis.updated_at = utc_now()
        return hypothesis
