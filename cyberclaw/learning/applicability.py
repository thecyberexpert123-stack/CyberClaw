"""Explicit applicability matching. Generalization is never assumed."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence

from cyberclaw.learning.models import (
    SIMILARITY_ALGORITHM,
    ApplicabilityMatch,
    ApplicabilityProfile,
    InvestigationContext,
    InvestigationStrategy,
    PromotionThresholdPolicy,
    StrategyCandidate,
    StrategyLifecycle,
    StrategyQueryResult,
)
from cyberclaw.learning.normalization import objective_tokens


def jaccard(left: Iterable[str], right: Iterable[str]) -> float:
    a = set(left)
    b = set(right)
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class ApplicabilityEngine:
    """Structured Jaccard matching with versioned weights and hard exclusions."""

    @classmethod
    def match(
        cls,
        profile: ApplicabilityProfile,
        context: InvestigationContext,
        policy: PromotionThresholdPolicy,
    ) -> ApplicabilityMatch:
        weights = dict(policy.similarity_parameters.get("weights") or profile.similarity_parameters.get("weights") or {})
        context_tokens = objective_tokens(context.objective)
        stage_score = 1.0
        if profile.case_stages:
            stage_score = 1.0 if context.case_stage in profile.case_stages else 0.0
        cap_available = 1.0
        if profile.required_capabilities:
            present = set(context.available_capabilities)
            cap_available = len(set(profile.required_capabilities) & present) / len(set(profile.required_capabilities))
        auth_score = 1.0
        if profile.required_permissions:
            granted = set(context.actor_permissions)
            if granted:
                auth_score = len(set(profile.required_permissions) & granted) / len(set(profile.required_permissions))
            else:
                auth_score = 0.0
        scores = {
            "objective_tokens": jaccard(profile.objective_tokens or profile.investigation_objectives, context_tokens),
            "information_gap_structure": jaccard(profile.information_gap_structure, context.information_gap_structure),
            "uncertainty_characteristics": jaccard(profile.uncertainty_characteristics, context.uncertainty_characteristics),
            "evidence_characteristics": jaccard(profile.evidence_characteristics, context.evidence_characteristics),
            "case_stage": stage_score,
            "capability_availability": cap_available,
            "authorization_compatibility": auth_score,
        }
        weight_sum = sum(weights.get(name, 0.0) for name in scores) or 1.0
        similarity = sum(scores[name] * weights.get(name, 0.0) for name in scores) / weight_sum
        hard: List[str] = []
        missing_caps = [cap for cap in profile.required_capabilities if cap not in set(context.available_capabilities)]
        if missing_caps:
            hard.append("missing_required_capability:" + ",".join(sorted(missing_caps)))
        if profile.information_gap_structure and not (
            set(profile.information_gap_structure) & set(context.information_gap_structure)
        ):
            hard.append("information_gap_mismatch")
        missing_perms = [perm for perm in profile.required_permissions if perm not in set(context.actor_permissions)]
        if profile.required_permissions and missing_perms:
            hard.append("missing_required_permission:" + ",".join(sorted(missing_perms)))
        context_blob = " ".join(
            [
                context.objective,
                context.case_stage,
                *context.information_gap_structure,
                *context.uncertainty_characteristics,
                *context.environment_constraints,
            ]
        ).lower()
        for exclusion in profile.known_exclusions:
            if exclusion and exclusion.lower() in context_blob:
                hard.append(f"known_exclusion_context:{exclusion}")
        minimum = policy.applicability_minimum_similarity
        applicable = not hard and similarity >= minimum
        if hard:
            explanation = "Not applicable. Hard exclusions: " + "; ".join(hard)
        elif not applicable:
            explanation = (
                f"Not applicable. structured_jaccard_v0.1 similarity {similarity:.4f} "
                f"is below explicit minimum {minimum:.4f}. Generalization is not assumed."
            )
        else:
            explanation = (
                f"Applicable under {SIMILARITY_ALGORITHM} similarity {similarity:.4f} "
                f">= minimum {minimum:.4f}. Dimension scores: {scores}. "
                "Similarity is an explicit comparison, not objective truth."
            )
        return ApplicabilityMatch(
            is_applicable=applicable,
            similarity=round(similarity, 6),
            dimension_scores=scores,
            algorithm=policy.similarity_algorithm,
            algorithm_parameters=dict(policy.similarity_parameters),
            minimum_similarity=minimum,
            hard_exclusions=hard,
            explanation=explanation,
        )

    @classmethod
    def query_candidates(
        cls,
        strategies: Sequence[InvestigationStrategy],
        context: InvestigationContext,
        policy: PromotionThresholdPolicy,
        pattern_support: Optional[Dict[str, Dict[str, Any]]] = None,
        policy_precheck: Optional[Dict[str, str]] = None,
        policy_decision_ids: Optional[Dict[str, List[str]]] = None,
    ) -> StrategyQueryResult:
        """Return AVAILABLE strategies that fit. Order is id/version, never an opaque preference."""
        pattern_support = pattern_support or {}
        policy_precheck = policy_precheck or {}
        policy_decision_ids = policy_decision_ids or {}
        candidates: List[StrategyCandidate] = []
        excluded: List[Dict[str, Any]] = []
        ordered = sorted(strategies, key=lambda item: (item.strategy_id, item.version))
        for strategy in ordered:
            if strategy.lifecycle_state != StrategyLifecycle.AVAILABLE:
                excluded.append(
                    {
                        "strategy_id": strategy.strategy_id,
                        "version": strategy.version,
                        "reason": f"lifecycle_{strategy.lifecycle_state.value}",
                    }
                )
                continue
            match = cls.match(strategy.applicability, context, policy)
            precheck = policy_precheck.get(strategy.strategy_id, "NOT_EVALUATED")
            if not match.is_applicable:
                excluded.append(
                    {
                        "strategy_id": strategy.strategy_id,
                        "version": strategy.version,
                        "reason": "not_applicable",
                        "detail": match.explanation,
                        "hard_exclusions": match.hard_exclusions,
                    }
                )
                continue
            if precheck not in {"ALLOW", "NOT_EVALUATED"}:
                excluded.append(
                    {
                        "strategy_id": strategy.strategy_id,
                        "version": strategy.version,
                        "reason": "policy_precheck_" + precheck,
                    }
                )
                continue
            support = pattern_support.get(strategy.created_from_pattern_id, {})
            candidates.append(
                StrategyCandidate(
                    strategy_id=strategy.strategy_id,
                    strategy_version=strategy.version,
                    applicability_explanation=match.explanation,
                    supporting_pattern_ids=list(strategy.supporting_pattern_ids),
                    supporting_investigations=list(strategy.supporting_case_ids),
                    independent_case_count=int(support.get("independent_case_count", len(strategy.supporting_case_ids))),
                    known_failures=list(strategy.known_failures),
                    required_capabilities=list(strategy.required_capabilities),
                    required_permissions=list(strategy.required_permissions),
                    risk_factors=list(strategy.risk_profile.structural_factors),
                    evaluation_history=list(strategy.evaluation_history),
                    reason_for_applicability=match.explanation,
                    limitations=[
                        "HISTORICAL_PERFORMANCE_IS_NOT_A_FUTURE_GUARANTEE",
                        "STRATEGY_IS_NOT_EXECUTABLE",
                        "POLICY_AND_CAPABILITY_GOVERNANCE_REMAIN_AUTHORITATIVE",
                    ],
                    contradicting_evidence_refs=list(strategy.known_failures),
                    policy_precheck=precheck,
                    policy_decision_ids=list(policy_decision_ids.get(strategy.strategy_id, [])),
                )
            )
        return StrategyQueryResult(candidates=candidates, excluded=excluded)
