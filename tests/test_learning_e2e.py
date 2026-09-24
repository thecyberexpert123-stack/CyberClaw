"""Mandatory cross-case learning loop, from experience through regression review."""

from __future__ import annotations

from pathlib import Path

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.coordination.requirements import RequirementStatus
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.learning.models import (
    ApprovalDecisionKind,
    PatternKind,
    PatternScope,
    StrategyLifecycle,
    StrategyOutcome,
)
from cyberclaw.learning.evaluation import StrategyRegressionDetector
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.types import Source
from tests.learning_support import build_completed_investigation


class RecordingProvider(CapabilityProvider):
    def __init__(self) -> None:
        super().__init__(id="provider.cap.observe", name="Observe provider", capability_id="cap.observe")
        self.calls = 0

    def is_ready(self, context=None):
        return True, None

    def execute(self, parameters, context: ExecutionContext) -> ExecutionResult:
        self.calls += 1
        evidence = Evidence(
            type="finding",
            subject=parameters.get("target", "subject-c"),
            value={"observed_by": "runtime", "target": parameters.get("target")},
            source=Source(type="provider", name=self.id, id="provider.cap.observe"),
        )
        return ExecutionResult.success(output={"status": "ok"}, evidence=[evidence])


def test_section_36_cross_case_strategy_learning_e2e(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    provider = RecordingProvider()
    core.register_capability(Capability(id="cap.observe", name="Observe", action_scope=ActionScope.REVERSIBLE))
    core.register_capability(Capability(id="cap.corroborate", name="Corroborate", action_scope=ActionScope.REVERSIBLE))
    core.register_provider(provider)

    investigation_a = build_completed_investigation(core, family="family-a", target="subject-a", source_id="source-a")
    journal_a = len(investigation_a.case_manager.journal.entries)
    first = core.ingest_investigation_experience(investigation_a.id)
    assert first.ok
    assert len(investigation_a.case_manager.journal.entries) == journal_a
    assert all(pattern.scope == PatternScope.CASE_LOCAL for pattern in core.learning.list_patterns())
    assert core.learning.list_strategies() == []

    investigation_b = build_completed_investigation(
        core,
        family="family-b",
        target="subject-b",
        source_id="source-b",
        with_retry=True,
    )
    assert investigation_b.id != investigation_a.id
    second = core.ingest_investigation_experience(investigation_b.id)
    assert second.ok
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION)
    assert pattern.scope == PatternScope.VALIDATED
    assert pattern.independent_case_count == 2
    assert pattern.independent_source_family_count == 2
    assert pattern.causal_claim == "NONE"
    assert {investigation_a.id, investigation_b.id} == {inst.investigation_id for inst in pattern.instances}

    strategy = core.propose_learned_strategy(pattern.pattern_id, "analyst.proposer")
    assert strategy.lifecycle_state == StrategyLifecycle.PROPOSED
    assert strategy.executable is False
    original_digest = strategy.content_digest
    reports = core.simulate_learned_strategy(strategy.strategy_id, strategy.version, actor="lead.simulator")
    assert len(reports) == 2
    assert all(report.is_counterfactual and report.providers_executed == 0 for report in reports)
    assert all(report.authoritative_state_mutated is False for report in reports)
    evaluation = core.evaluate_learned_strategy(strategy.strategy_id, strategy.version, actor="lead.evaluator")
    assert evaluation.declares_winner is False
    assert evaluation.collapsed_score_used is False
    assert evaluation.tradeoffs
    core.review_learned_strategy(strategy.strategy_id, strategy.version, "lead.reviewer")
    approved, approval = core.approve_learned_strategy(
        strategy.strategy_id,
        strategy.version,
        "lead.approver",
        ApprovalDecisionKind.APPROVE,
        "External reviewer approved the evaluated strategy.",
        evidence_refs=[investigation_a.id, investigation_b.id],
    )
    assert approval.externally_generated is True
    assert approval.actor != strategy.proposer_id
    published, precheck = core.publish_learned_strategy(
        strategy.strategy_id,
        strategy.version,
        "lead.publisher",
        actor_role="lead_investigator",
        investigation_id=investigation_a.id,
    )
    assert published.lifecycle_state == StrategyLifecycle.AVAILABLE
    assert precheck.decision == "ALLOW"
    assert published.content_digest == original_digest
    assert provider.calls == 0

    snapshot = investigation_a.capture_snapshot(trigger="strategy_counterfactual")
    branch = investigation_a.create_branch(snapshot.snapshot_id, purpose="strategy counterfactual")
    from cyberclaw.learning.simulation import StrategySimulator

    candidate = StrategySimulator.simulate_on_branch(published, branch, source_snapshot=snapshot.snapshot_id)
    core.learning.quarantine_branch_experience(candidate, actor="lead.simulator")
    assert candidate.is_counterfactual is True
    assert candidate.promoted_to_authoritative_experience is False
    assert candidate.candidate_id not in {exp.experience_id for exp in core.learning.authoritative_experiences()}

    investigation_c = core.create_investigation(
        "Resolve contradictory evidence about subject",
        description="Resolve contradictory evidence about subject",
        metadata={"source_family": "family-c", "case_id": "family-c"},
        targets=["subject-c"],
    )
    core.transition_investigation(investigation_c.id, CoreState.INVESTIGATE, event="start")
    requirement = investigation_c.create_information_requirement(
        description="Resolve contradictory evidence",
        target_or_entity="subject-c",
        evidence_types_sought=["finding"],
        assigned_capability_id="cap.observe",
    )
    requirement.metadata["uncertainty_type"] = "CONTRADICTION_RESOLUTION"
    queried = core.query_learned_strategies(
        investigation_c.id,
        available_capabilities=["cap.observe", "cap.corroborate"],
        available_specialists=["specialist.alpha", "specialist.beta"],
        actor_permissions=["investigation:view"],
    )
    assert queried.opaque_preference_used is False
    match = next(item for item in queried.candidates if item.strategy_id == published.strategy_id)
    assert match.executable is False
    assert match.policy_precheck == "ALLOW"
    assert match.strategy_version == "1.0.0"
    assert not hasattr(match, "execute")

    task = core.submit_task_to_runtime(
        investigation_c.id,
        "cap.observe",
        {"target": "subject-c"},
        requirement_id=requirement.id,
        scope=ActionScope.REVERSIBLE,
        actor="core.system",
    )
    processed = core.process_runtime_queue(investigation_c.id)
    assert provider.calls == 1
    assert processed
    assert investigation_c.evidence_store.count() >= 1
    requirement.status = RequirementStatus.SATISFIED
    requirement.resulting_evidence_ids = [item.id for item in investigation_c.evidence_store.list_all()]
    investigation_c.case_manager.stopping_history.append("OBJECTIVE_SATISFIED")
    completed = core.ingest_investigation_experience(investigation_c.id)
    assert completed.ok
    core.record_strategy_outcome(
        StrategyOutcome(
            outcome_id="outcome-c",
            strategy_id=published.strategy_id,
            strategy_version=published.version,
            investigation_id=investigation_c.id,
            experience_id=completed.experience.experience_id,
            success=True,
            evidence_yield=len(completed.experience.evidence_generated),
            contradiction_count=0,
        ),
        actor="lead.reviewer",
    )
    assert core.learning.get_strategy(published.strategy_id).content_digest == original_digest

    core.record_strategy_outcome(
        StrategyOutcome(
            outcome_id="outcome-d",
            strategy_id=published.strategy_id,
            strategy_version=published.version,
            investigation_id="later-d",
            success=False,
            contradiction_count=2,
            evidence_yield=0,
            authorization_failures=1,
        ),
        actor="lead.reviewer",
    )
    core.record_strategy_outcome(
        StrategyOutcome(
            outcome_id="outcome-e",
            strategy_id=published.strategy_id,
            strategy_version=published.version,
            investigation_id="later-e",
            success=False,
            contradiction_count=1,
            evidence_yield=0,
        ),
        actor="lead.reviewer",
    )
    signal = StrategyRegressionDetector.detect(
        core.learning.get_strategy(published.strategy_id),
        core.learning.outcomes_for(published.strategy_id),
        baseline_failure_rate=0.0,
        policy=core.learning.threshold_policy,
    )
    assert signal.status == "REVIEW_RECOMMENDED"
    assert signal.auto_applied is False
    core.learning.record_regression(signal, actor="lead.reviewer")
    reviewed = core.learning_service.apply_regression_review(
        published.strategy_id,
        published.version,
        "lead.reviewer",
        "DEPRECATED",
    )
    assert reviewed.lifecycle_state == StrategyLifecycle.DEPRECATED
    assert reviewed.content_digest == original_digest
    assert len(core.learning.outcomes_for(published.strategy_id)) == 3
    historical = ReplayEngine.replay_learning_state(
        core.learning.events,
        until_sequence=next(
            event.sequence
            for event in core.learning.events
            if event.event_type.value == "STRATEGY_APPROVAL_RECORDED"
            and event.subject_id == published.strategy_id
        ),
    )
    assert historical.strategies[published.strategy_id][published.version]["lifecycle_state"] == "APPROVED"
    assert historical.strategies[published.strategy_id][published.version]["content_digest"] == original_digest
    assert historical.detectors_executed == 0
    assert core.learning.get_strategy(published.strategy_id, "1.0.0").version == "1.0.0"
