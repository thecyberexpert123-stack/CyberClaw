"""Transparent pattern confidence. Bands are explained; no score is treated as truth."""

from __future__ import annotations

from cyberclaw.learning.models import (
    ConfidenceBand,
    PatternConfidence,
    PromotionThresholdPolicy,
)


class PatternConfidenceModel:
    """Assign a qualitative band from explicit dimensions and the active threshold policy."""

    @classmethod
    def assess(
        cls,
        *,
        sample_count: int,
        independent_case_count: int,
        independent_source_family_count: int,
        success_count: int,
        failure_count: int,
        contradiction_count: int,
        mixed_count: int,
        indeterminate_count: int,
        policy: PromotionThresholdPolicy,
        recency_note: str = "Recency is recorded on source experiences; it is not decayed into a hidden weight.",
        context_similarity_note: str = "Pattern identity uses exact signature equality, not fuzzy similarity.",
        outcome_quality_note: str = "Success and failure counts are observations, not causal proof.",
        evidence_quality_note: str = "Evidence quality is not collapsed into this band.",
    ) -> PatternConfidence:
        reasons = [
            f"sample_count={sample_count}",
            f"independent_case_count={independent_case_count}",
            f"independent_source_family_count={independent_source_family_count}",
            f"success_count={success_count}",
            f"failure_count={failure_count}",
            f"contradiction_count={contradiction_count}",
            f"mixed_count={mixed_count}",
            f"indeterminate_count={indeterminate_count}",
            f"threshold_policy={policy.policy_id}@{policy.version}",
        ]
        if (
            independent_case_count < policy.min_independent_cases
            or independent_source_family_count < policy.min_independent_source_families
        ):
            band = ConfidenceBand.INSUFFICIENT
            reasons.append(
                "Below the architectural independence floor, so this observation cannot support a global strategy."
            )
        elif failure_count > success_count or contradiction_count > success_count:
            band = ConfidenceBand.WEAK
            reasons.append("Failures or contradictions outnumber successful observations.")
        elif (
            success_count >= policy.min_success_observations_for_proposal
            and independent_source_family_count >= policy.min_families_for_strong_band
            and failure_count == 0
            and indeterminate_count == 0
        ):
            band = ConfidenceBand.STRONG
            reasons.append(
                "Independent families and uncontradicted successes meet the explicit strong-band policy. "
                "This is still not a guarantee of future success."
            )
        elif (
            success_count >= policy.min_success_observations_for_proposal
            and independent_source_family_count >= policy.min_independent_source_families
        ):
            band = ConfidenceBand.MODERATE
            reasons.append("Repeated independent successes exist, with remaining uncertainty or limited families.")
        else:
            band = ConfidenceBand.WEAK
            reasons.append("Support is limited relative to the explicit threshold policy.")

        return PatternConfidence(
            band=band,
            explanation=" ".join(reasons),
            sample_count=sample_count,
            independent_case_count=independent_case_count,
            independent_source_family_count=independent_source_family_count,
            success_count=success_count,
            failure_count=failure_count,
            contradiction_count=contradiction_count,
            mixed_count=mixed_count,
            indeterminate_count=indeterminate_count,
            recency_note=recency_note,
            context_similarity_note=context_similarity_note,
            outcome_quality_note=outcome_quality_note,
            evidence_quality_note=evidence_quality_note,
            single_score_is_objective_truth=False,
            threshold_policy_id=policy.policy_id,
            threshold_policy_version=policy.version,
        )
