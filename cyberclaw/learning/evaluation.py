"""Multidimensional strategy evaluation and regression detection. No universal winner."""

from __future__ import annotations

from typing import List, Optional, Sequence

from cyberclaw.learning.models import (
    EVALUATION_DIMENSIONS,
    HIGHER_IS_BETTER,
    LOWER_IS_BETTER,
    AssessmentLabel,
    DimensionMeasure,
    InvestigationExperience,
    InvestigationStrategy,
    PromotionThresholdPolicy,
    RegressionSignal,
    SimulationReport,
    StrategyEvaluation,
    StrategyOutcome,
    TradeoffReport,
    canonical_digest,
    stable_id,
)


def _measure(
    name: str,
    value: Optional[float],
    unit: str,
    measured: bool,
    sample_size: int,
    explanation: str,
) -> DimensionMeasure:
    return DimensionMeasure(
        name=name,
        value=value,
        unit=unit,
        measured=measured,
        sample_size=sample_size,
        explanation=explanation,
        higher_is_better=name in HIGHER_IS_BETTER,
    )


class StrategyEvaluator:
    """Report independent dimensions and trade-offs. Never declare a best strategy."""

    @classmethod
    def evaluate(
        cls,
        strategy: InvestigationStrategy,
        simulations: Sequence[SimulationReport],
        experiences: Sequence[InvestigationExperience],
    ) -> StrategyEvaluation:
        sample = len(simulations)
        fits = [
            report
            for report in simulations
            if any(answer.question.startswith("Would this strategy have resolved") and answer.assessment == AssessmentLabel.STRUCTURAL_FIT for answer in report.answers)
        ]
        measured = sample > 0
        information_gain = (len(fits) / sample) if measured else None
        unresolved_targeted = 0
        unresolved_total = 0
        by_inv = {exp.investigation_id: exp for exp in experiences}
        for report in simulations:
            exp = by_inv.get(report.investigation_id or "")
            if exp is None:
                continue
            unresolved_total += len(exp.requirements_unresolved)
            if any(answer.assessment == AssessmentLabel.STRUCTURAL_FIT for answer in report.answers):
                unresolved_targeted += len(exp.requirements_unresolved)
        requirement_resolution = None
        if unresolved_total:
            requirement_resolution = unresolved_targeted / unresolved_total
        confidences = []
        for exp in experiences:
            for ref in exp.evidence_generated:
                confidences.append(1.0 if ref.record_id else 0.0)
        # Evidence quality is only measured when experiences recorded source independence.
        independence_values = [
            exp.source_independence_count
            for exp in experiences
            if exp.source_independence_available and exp.source_independence_count is not None
        ]
        evidence_quality = (
            sum(independence_values) / len(independence_values) if independence_values else None
        )
        contradiction_cases = [exp for exp in experiences if exp.contradictions]
        resolved_cases = [exp for exp in contradiction_cases if all(c.get("resolved") for c in exp.contradictions)]
        contradiction_resolution = (
            len(resolved_cases) / len(contradiction_cases) if contradiction_cases else None
        )
        extra_actions = []
        for report, exp in (
            (report, by_inv.get(report.investigation_id or ""))
            for report in simulations
        ):
            if exp is None:
                continue
            extra_actions.append(max(0, len(exp.actions_taken) - len(strategy.steps)))
        unnecessary = sum(extra_actions) / len(extra_actions) if extra_actions else None
        durations = [exp.execution_duration_ms for exp in experiences if exp.execution_duration_ms is not None]
        latency = sum(durations) / len(durations) if durations else None
        failure_rate = None
        if experiences:
            failure_rate = sum(1 for exp in experiences if exp.outcome.value == "FAILURE") / len(experiences)
        auth_complexity = float(len(strategy.required_permissions) + len(strategy.required_capabilities))
        specialist_dependency = float(len(strategy.applicability.specialist_roles_observed))
        recovery = None
        if experiences:
            recovery = sum(1 for exp in experiences if exp.failures and exp.outcome.value == "SUCCESS") / len(experiences)

        dimensions = {
            "information_gain": _measure(
                "information_gain",
                information_gain,
                "fraction_of_simulations_with_structural_fit",
                measured,
                sample,
                "Fraction of counterfactual simulations with structural gap fit. Not a causal success rate.",
            ),
            "requirement_resolution": _measure(
                "requirement_resolution",
                requirement_resolution,
                "fraction_of_unresolved_requirements_structurally_targeted",
                requirement_resolution is not None,
                unresolved_total,
                "Share of historically unresolved requirements whose gap structure matched the strategy.",
            ),
            "evidence_quality": _measure(
                "evidence_quality",
                evidence_quality,
                "mean_independent_source_count",
                evidence_quality is not None,
                len(independence_values),
                "Mean source-independence count from provenance. Absent when provenance was unavailable.",
            ),
            "contradiction_resolution": _measure(
                "contradiction_resolution",
                contradiction_resolution,
                "fraction_of_contradiction_cases_resolved_historically",
                contradiction_resolution is not None,
                len(contradiction_cases),
                "Historical resolution rate among supporting cases that had contradictions.",
            ),
            "unnecessary_action_count": _measure(
                "unnecessary_action_count",
                unnecessary,
                "mean_historical_actions_minus_strategy_steps",
                unnecessary is not None,
                len(extra_actions),
                "Structural surplus of historical actions over strategy intent steps.",
            ),
            "execution_cost": _measure(
                "execution_cost",
                float(len(strategy.steps)),
                "intent_step_count",
                True,
                len(strategy.steps),
                "Cost proxy is the number of intent steps, not measured provider spend.",
            ),
            "latency": _measure(
                "latency",
                latency,
                "mean_historical_duration_ms",
                latency is not None,
                len(durations),
                "Historical duration baseline. Simulated latency was not invented.",
            ),
            "failure_rate": _measure(
                "failure_rate",
                failure_rate,
                "fraction_of_experiences",
                failure_rate is not None,
                len(experiences),
                "Observed failure fraction among supplied experiences. Not a future guarantee.",
            ),
            "authorization_complexity": _measure(
                "authorization_complexity",
                auth_complexity,
                "required_permission_plus_capability_count",
                True,
                int(auth_complexity),
                "Count of required capabilities and permissions. Policy still decides authorization.",
            ),
            "specialist_dependency": _measure(
                "specialist_dependency",
                specialist_dependency,
                "distinct_specialists_observed",
                True,
                int(specialist_dependency),
                "Number of specialist roles observed in supporting cases.",
            ),
            "recovery_behavior": _measure(
                "recovery_behavior",
                recovery,
                "fraction_of_experiences_with_failure_then_success",
                recovery is not None,
                len(experiences),
                "Share of experiences that recorded a failure and still ended in success.",
            ),
        }
        tradeoffs = []
        if information_gain is not None and information_gain > 0.5 and len(strategy.steps) > 3:
            tradeoffs.append("Higher structural information-gap fit coexists with a higher intent-step cost.")
        if failure_rate and information_gain:
            tradeoffs.append("Information-gap fit and failure rate are reported separately and are not netted.")
        if not tradeoffs:
            tradeoffs.append("Dimensions are independent. No composite score was computed and no winner was declared.")
        uncertainty = []
        if sample < 2:
            uncertainty.append("Fewer than two simulations; support is thin.")
        if evidence_quality is None:
            uncertainty.append("Evidence quality was not measured because source independence was unavailable.")
        payload = {
            "strategy_id": strategy.strategy_id,
            "version": strategy.version,
            "dimensions": {name: dimensions[name].value for name in EVALUATION_DIMENSIONS},
            "simulation_ids": [report.report_id for report in simulations],
        }
        return StrategyEvaluation(
            evaluation_id=stable_id("eval", canonical_digest(payload)),
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            dimensions=dimensions,
            tradeoffs=tradeoffs,
            declares_winner=False,
            collapsed_score_used=False,
            uncertainty_notes=uncertainty,
            simulation_report_ids=[report.report_id for report in simulations],
        )

    @classmethod
    def compare(cls, first: StrategyEvaluation, second: StrategyEvaluation) -> TradeoffReport:
        first_higher: List[str] = []
        second_higher: List[str] = []
        unmeasured: List[str] = []
        for name in EVALUATION_DIMENSIONS:
            left = first.dimensions.get(name)
            right = second.dimensions.get(name)
            if left is None or right is None or not left.measured or not right.measured or left.value is None or right.value is None:
                unmeasured.append(name)
                continue
            if left.value == right.value:
                continue
            left_better = left.value > right.value if name in HIGHER_IS_BETTER or name not in LOWER_IS_BETTER else left.value < right.value
            if name in LOWER_IS_BETTER:
                left_better = left.value < right.value
            if left_better:
                first_higher.append(name)
            else:
                second_higher.append(name)
        return TradeoffReport(
            first_strategy_id=first.strategy_id,
            second_strategy_id=second.strategy_id,
            first_higher=first_higher,
            second_higher=second_higher,
            unmeasured=unmeasured,
            declares_winner=False,
        )


class StrategyRegressionDetector:
    """Detect degradation. Does not delete history and does not auto-apply lifecycle changes."""

    @classmethod
    def detect(
        cls,
        strategy: InvestigationStrategy,
        outcomes: Sequence[StrategyOutcome],
        baseline_failure_rate: float,
        policy: PromotionThresholdPolicy,
    ) -> RegressionSignal:
        authoritative = [item for item in outcomes if not item.is_counterfactual and item.strategy_version == strategy.version]
        reasons: List[str] = []
        status = "INSUFFICIENT_DATA"
        recommended = None
        observed_rate = None
        if len(authoritative) < policy.regression_min_new_observations:
            reasons.append(
                f"Only {len(authoritative)} authoritative outcome(s); policy requires {policy.regression_min_new_observations}."
            )
        else:
            observed_rate = sum(1 for item in authoritative if not item.success) / len(authoritative)
            if observed_rate - baseline_failure_rate >= policy.regression_failure_rate_increase:
                reasons.append(
                    f"Failure rate increased from {baseline_failure_rate:.3f} to {observed_rate:.3f}, "
                    f"meeting threshold {policy.regression_failure_rate_increase}."
                )
                status = "REVIEW_RECOMMENDED"
                recommended = "DEPRECATED" if observed_rate - baseline_failure_rate >= policy.regression_failure_rate_increase * 2 else "REVIEW"
            contradictions = sum(item.contradiction_count for item in authoritative)
            if contradictions >= policy.regression_contradiction_increase and any(item.contradiction_count for item in authoritative):
                reasons.append("New authoritative outcomes recorded additional contradictions.")
                status = "REVIEW_RECOMMENDED"
                recommended = recommended or "REVIEW"
            auth_failures = sum(item.authorization_failures for item in authoritative)
            if auth_failures:
                reasons.append("New authorization failures were recorded against this strategy version.")
                status = "REVIEW_RECOMMENDED"
                recommended = recommended or "DISABLED"
            yields = [item.evidence_yield for item in authoritative]
            if yields and max(yields) == 0 and baseline_failure_rate < 1:
                reasons.append("Evidence yield dropped to zero in the new authoritative outcomes.")
                status = "REVIEW_RECOMMENDED"
                recommended = recommended or "REVIEW"
            if status == "INSUFFICIENT_DATA":
                status = "NO_REGRESSION"
                reasons.append("Observed outcomes do not cross governed regression thresholds.")
        return RegressionSignal(
            signal_id=stable_id("regress", strategy.strategy_id, strategy.version, status, str(len(authoritative))),
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            status=status,
            recommended_lifecycle=recommended,
            reasons=reasons,
            baseline_failure_rate=baseline_failure_rate,
            observed_failure_rate=observed_rate,
            threshold_policy_id=policy.policy_id,
            threshold_policy_version=policy.version,
            historical_usage_deleted=False,
            auto_applied=False,
        )
