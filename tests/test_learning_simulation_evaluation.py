"""Simulation isolation, multidimensional evaluation, and regression detection."""

from __future__ import annotations

from pathlib import Path

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityTrustState
from cyberclaw.core import CyberClawCore
from cyberclaw.learning.evaluation import StrategyEvaluator, StrategyRegressionDetector
from cyberclaw.learning.models import PatternKind, StrategyLifecycle, StrategyOutcome
from cyberclaw.learning.simulation import StrategySimulator
from cyberclaw.policy.engine import PolicyEngine
from tests.learning_support import build_completed_investigation


def _ready(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    first = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    second = build_completed_investigation(core, family="fam-b", target="subject-b", source_id="src-b")
    core.ingest_investigation_experience(first.id)
    core.ingest_investigation_experience(second.id)
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION)
    strategy = core.propose_learned_strategy(pattern.pattern_id, "analyst.proposer")
    return core, first, second, strategy


def test_simulation_does_not_mutate_case_policy_or_providers(tmp_path: Path):
    core, first, _, strategy = _ready(tmp_path)
    journal_before = [entry.id for entry in first.case_manager.journal.entries]
    live_decisions = len(core.policy_engine._decisions)
    policy_count = len(core.policy_engine.registry.list_policies())
    experiences = core.learning.authoritative_experiences()
    reports = StrategySimulator.simulate(strategy, experiences, policy_engine=core.policy_engine)
    assert reports
    assert all(report.providers_executed == 0 for report in reports)
    assert all(report.authoritative_state_mutated is False for report in reports)
    assert all(report.capabilities_granted == 0 for report in reports)
    assert all(report.policy_decisions_on_live_engine == 0 for report in reports)
    assert all(report.is_counterfactual is True for report in reports)
    assert all(answer.causal_claim == "NONE" and answer.is_counterfactual for report in reports for answer in report.answers)
    assert [entry.id for entry in first.case_manager.journal.entries] == journal_before
    assert len(core.policy_engine._decisions) == live_decisions
    assert len(core.policy_engine.registry.list_policies()) == policy_count


def test_simulation_answers_gap_cost_and_authorization_questions(tmp_path: Path):
    core, _, _, strategy = _ready(tmp_path)
    reports = StrategySimulator.simulate(
        strategy,
        core.learning.authoritative_experiences(),
        policy_engine=core.policy_engine,
    )
    questions = {answer.question for answer in reports[0].answers}
    assert any(question.startswith("Would this strategy have resolved") for question in questions)
    assert any("unnecessary actions" in question for question in questions)
    assert any("contradictions" in question for question in questions)
    assert any("unavailable capabilities" in question for question in questions)
    assert any("authorization boundaries" in question for question in questions)
    assert reports[0].answers[0].assessment.value == "STRUCTURAL_FIT"


def test_branch_simulation_stays_quarantined(tmp_path: Path):
    core, first, _, strategy = _ready(tmp_path)
    snapshot = first.capture_snapshot(trigger="learning_branch")
    branch = first.create_branch(snapshot.snapshot_id, purpose="counterfactual strategy evaluation")
    authoritative_before = len(first.case_manager.journal.entries)
    candidate = StrategySimulator.simulate_on_branch(strategy, branch, source_snapshot=snapshot.snapshot_id)
    core.learning.quarantine_branch_experience(candidate, actor="lead.simulator")
    assert candidate.is_counterfactual is True
    assert candidate.promoted_to_authoritative_experience is False
    assert candidate.strategy_id == strategy.strategy_id
    assert candidate.source_snapshot == snapshot.snapshot_id
    assert branch.metadata["strategy_evaluations"][0]["is_counterfactual"] is True
    assert len(first.case_manager.journal.entries) == authoritative_before
    assert candidate.candidate_id not in {exp.experience_id for exp in core.learning.authoritative_experiences()}
    assert core.learning._quarantine[candidate.candidate_id].is_counterfactual is True


def test_simulation_does_not_change_capability_trust(tmp_path: Path):
    core, _, _, strategy = _ready(tmp_path)
    cap = Capability(id="cap.observe", name="Observe")
    core.register_capability(cap)
    before = core.capabilities.get_capability("cap.observe").trust_state
    StrategySimulator.simulate(strategy, core.learning.authoritative_experiences(), policy_engine=core.policy_engine)
    after = core.capabilities.get_capability("cap.observe").trust_state
    assert before == after == CapabilityTrustState.TRUSTED_WITH_SCOPE


def test_evaluation_preserves_independent_dimensions_and_tradeoffs(tmp_path: Path):
    core, _, _, strategy = _ready(tmp_path)
    experiences = core.learning.authoritative_experiences()
    reports = StrategySimulator.simulate(strategy, experiences, policy_engine=core.policy_engine)
    evaluation = StrategyEvaluator.evaluate(strategy, reports, experiences)
    assert evaluation.declares_winner is False
    assert evaluation.collapsed_score_used is False
    assert set(evaluation.dimensions) >= {
        "information_gain",
        "execution_cost",
        "failure_rate",
        "authorization_complexity",
        "contradiction_resolution",
    }
    assert evaluation.dimensions["information_gain"].measured is True
    assert evaluation.dimensions["execution_cost"].value == float(len(strategy.steps))
    assert evaluation.tradeoffs
    other = evaluation.model_copy(update={
        "strategy_id": "strategy-other",
        "dimensions": {
            **evaluation.dimensions,
            "information_gain": evaluation.dimensions["information_gain"].model_copy(update={"value": 0.1}),
            "execution_cost": evaluation.dimensions["execution_cost"].model_copy(update={"value": 1.0}),
        },
    })
    tradeoff = StrategyEvaluator.compare(evaluation, other)
    assert tradeoff.declares_winner is False
    assert "information_gain" in tradeoff.first_higher
    assert "execution_cost" in tradeoff.second_higher


def test_regression_recommends_review_without_deleting_history(tmp_path: Path):
    core, _, _, strategy = _ready(tmp_path)
    core.learning.record_outcome(
        StrategyOutcome(
            outcome_id="out-1",
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            investigation_id="later-1",
            success=False,
            contradiction_count=2,
            evidence_yield=0,
            authorization_failures=1,
        ),
        actor="lead.reviewer",
    )
    core.learning.record_outcome(
        StrategyOutcome(
            outcome_id="out-2",
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            investigation_id="later-2",
            success=False,
            contradiction_count=1,
            evidence_yield=0,
        ),
        actor="lead.reviewer",
    )
    signal = StrategyRegressionDetector.detect(
        strategy,
        core.learning.outcomes_for(strategy.strategy_id),
        baseline_failure_rate=0.0,
        policy=core.learning.threshold_policy,
    )
    assert signal.auto_applied is False
    assert signal.historical_usage_deleted is False
    assert signal.status == "REVIEW_RECOMMENDED"
    assert signal.recommended_lifecycle in {"REVIEW", "DEPRECATED", "DISABLED"}
    stored = core.learning.record_regression(signal, actor="learning.regression_detector")
    assert len(core.learning.outcomes_for(strategy.strategy_id)) == 2
    assert stored.historical_usage_deleted is False
    assert core.learning.get_strategy(strategy.strategy_id).lifecycle_state == StrategyLifecycle.PROPOSED


def test_counterfactual_outcomes_do_not_drive_regression(tmp_path: Path):
    core, _, _, strategy = _ready(tmp_path)
    core.learning.record_outcome(
        StrategyOutcome(
            outcome_id="cf-1",
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            investigation_id="branch-case",
            success=False,
            is_counterfactual=True,
        ),
        actor="lead.reviewer",
    )
    signal = StrategyRegressionDetector.detect(
        strategy,
        [core.learning._quarantine["cf-1"]],
        baseline_failure_rate=0.0,
        policy=core.learning.threshold_policy,
    )
    assert signal.status == "INSUFFICIENT_DATA"
    assert "out-cf" not in [item.outcome_id for item in core.learning.outcomes_for(strategy.strategy_id)]


def test_unmeasured_latency_is_not_invented_as_zero_success(tmp_path: Path):
    core, _, _, strategy = _ready(tmp_path)
    evaluation = StrategyEvaluator.evaluate(strategy, [], [])
    assert evaluation.dimensions["latency"].measured is False
    assert evaluation.dimensions["information_gain"].measured is False
    assert any("not measured" in note or "Fewer than two" in note or "unavailable" in note for note in evaluation.uncertainty_notes)
