"""Strategy immutability, lifecycle, applicability, and approval gates."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberclaw.core import CyberClawCore
from cyberclaw.learning.applicability import ApplicabilityEngine
from cyberclaw.learning.errors import (
    ExecutableStrategyRejectedError,
    InvalidStrategyTransitionError,
    LearningThresholdError,
    SelfApprovalError,
)
from cyberclaw.learning.governance import StrategyGovernance, validate_threshold_policy
from cyberclaw.learning.models import (
    ApprovalDecisionKind,
    InvestigationContext,
    PatternKind,
    PromotionThresholdPolicy,
    StrategyLifecycle,
)
from cyberclaw.learning.strategies import StrategyLifecycleMachine, assert_not_executable
from tests.learning_support import build_completed_investigation


def _validated_strategy(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    first = core.list_investigations()[0]
    second = build_completed_investigation(core, family="fam-b", target="subject-b", source_id="src-b", with_retry=True)
    core.ingest_investigation_experience(first.id)
    core.ingest_investigation_experience(second.id)
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION)
    strategy = core.propose_learned_strategy(pattern.pattern_id, "analyst.proposer")
    return core, strategy


def test_strategy_is_structured_intent_not_code(tmp_path: Path):
    _, strategy = _validated_strategy(tmp_path)
    assert strategy.executable is False
    assert strategy.execution_substrate == "runtime_only"
    assert not hasattr(strategy, "execute")
    assert strategy.steps
    assert all(step.intent for step in strategy.steps)
    assert all("import " not in step.intent for step in strategy.steps)
    blob = strategy.model_dump_json()
    assert "subprocess" not in blob
    assert "os.system" not in blob


def test_strategy_model_is_immutable(tmp_path: Path):
    _, strategy = _validated_strategy(tmp_path)
    with pytest.raises(Exception):
        strategy.lifecycle_state = StrategyLifecycle.AVAILABLE
    with pytest.raises(Exception):
        strategy.objective_intent = "rewritten"


def test_lifecycle_cannot_jump_from_proposed_to_available_or_approved(tmp_path: Path):
    _, strategy = _validated_strategy(tmp_path)
    with pytest.raises(InvalidStrategyTransitionError):
        StrategyLifecycleMachine.assert_transition(strategy.lifecycle_state, StrategyLifecycle.AVAILABLE)
    with pytest.raises(InvalidStrategyTransitionError):
        StrategyGovernance.transition(strategy, StrategyLifecycle.APPROVED, "lead.approver")
    with pytest.raises(InvalidStrategyTransitionError):
        StrategyGovernance.transition(strategy, StrategyLifecycle.AVAILABLE, "lead.publisher")


def test_content_digest_survives_lifecycle_and_old_version_remains(tmp_path: Path):
    core, strategy = _validated_strategy(tmp_path)
    original = strategy.content_digest
    simulated = core.learning_service.record_simulation(strategy.strategy_id, strategy.version, "lead.simulator")
    evaluated_strategy = StrategyGovernance.transition(simulated, StrategyLifecycle.EVALUATED, "lead.evaluator")
    core.learning.store_strategy(evaluated_strategy, actor="lead.evaluator")
    reviewed = core.review_learned_strategy(strategy.strategy_id, strategy.version, "lead.reviewer")
    approved, _ = core.approve_learned_strategy(
        strategy.strategy_id,
        strategy.version,
        "lead.approver",
        ApprovalDecisionKind.APPROVE,
        "external approval",
    )
    assert simulated.content_digest == original
    assert reviewed.content_digest == original
    assert approved.content_digest == original
    assert core.learning.get_strategy(strategy.strategy_id, "1.0.0").version == "1.0.0"
    proposal = next(event for event in core.learning.events if event.event_type.value == "STRATEGY_PROPOSED")
    assert proposal.payload["content_digest"] == original


def test_registry_orders_by_identity_not_preference(tmp_path: Path):
    core, first = _validated_strategy(tmp_path)
    other = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.CAPABILITY_SEQUENCE_PATTERN)
    second = core.propose_learned_strategy(other.pattern_id, "analyst.proposer")
    listed = core.learning.list_strategies()
    assert [item.strategy_id for item in listed] == sorted(item.strategy_id for item in listed)
    assert first.strategy_id != second.strategy_id
    assert all(item.metadata.get("opaque_preference_used", False) is False for item in listed)


def test_applicability_excludes_missing_capabilities_and_gap_mismatch(tmp_path: Path):
    core, strategy = _validated_strategy(tmp_path)
    published_like = strategy.model_copy(update={"lifecycle_state": StrategyLifecycle.AVAILABLE})
    context = InvestigationContext(
        investigation_id="inv-c",
        objective="Resolve contradictory evidence about subject",
        case_stage="INVESTIGATE",
        information_gap_structure=["CONTRADICTION_RESOLUTION", "CONTRADICTED"],
        uncertainty_characteristics=["CONTRADICTION_RESOLUTION", "CONTRADICTED"],
        available_capabilities=["cap.observe"],
        actor_permissions=["investigation:view"],
    )
    match = ApplicabilityEngine.match(published_like.applicability, context, core.learning.threshold_policy)
    assert match.is_applicable is False
    assert any(item.startswith("missing_required_capability") for item in match.hard_exclusions)
    assert match.similarity_is_objective_truth is False
    assert match.algorithm == "structured_jaccard_v0.1"

    mismatched = context.model_copy(
        update={
            "information_gap_structure": ["UNRELATED_GAP"],
            "uncertainty_characteristics": ["UNRELATED_GAP"],
            "available_capabilities": list(strategy.required_capabilities),
        }
    )
    mismatch = ApplicabilityEngine.match(strategy.applicability, mismatched, core.learning.threshold_policy)
    assert mismatch.is_applicable is False
    assert "information_gap_mismatch" in mismatch.hard_exclusions


def test_executable_payload_is_rejected():
    with pytest.raises(ExecutableStrategyRejectedError):
        assert_not_executable({"intent": "eval(payload)", "steps": []})
    with pytest.raises(ExecutableStrategyRejectedError):
        assert_not_executable({"command": "rm -rf /"})


def test_self_approval_and_non_approval_decisions(tmp_path: Path):
    core, strategy = _validated_strategy(tmp_path)
    core.learning_service.record_simulation(strategy.strategy_id, strategy.version, "lead.simulator")
    current = core.learning.get_strategy(strategy.strategy_id)
    evaluated = StrategyGovernance.transition(current, StrategyLifecycle.EVALUATED, "lead.evaluator")
    core.learning.store_strategy(evaluated, actor="lead.evaluator")
    core.review_learned_strategy(strategy.strategy_id, strategy.version, "lead.reviewer")

    with pytest.raises(SelfApprovalError):
        core.approve_learned_strategy(
            strategy.strategy_id, strategy.version, "analyst.proposer", ApprovalDecisionKind.APPROVE, "self"
        )
    with pytest.raises(SelfApprovalError):
        core.approve_learned_strategy(
            strategy.strategy_id, strategy.version, "learning.engine", ApprovalDecisionKind.APPROVE, "engine"
        )

    deferred, decision = core.approve_learned_strategy(
        strategy.strategy_id,
        strategy.version,
        "lead.approver",
        ApprovalDecisionKind.DEFER,
        "need another case",
    )
    assert decision.decision == ApprovalDecisionKind.DEFER
    assert deferred.lifecycle_state == StrategyLifecycle.REVIEWED
    requested, _ = core.approve_learned_strategy(
        strategy.strategy_id,
        strategy.version,
        "lead.approver",
        ApprovalDecisionKind.REQUEST_MORE_EVIDENCE,
        "need independent source",
    )
    assert requested.lifecycle_state == StrategyLifecycle.REVIEWED
    assert len(requested.approval_history) == 2


def test_threshold_policy_cannot_lower_architectural_floor():
    with pytest.raises(LearningThresholdError):
        validate_threshold_policy(PromotionThresholdPolicy(min_independent_cases=1))
    with pytest.raises(LearningThresholdError):
        validate_threshold_policy(PromotionThresholdPolicy(min_independent_source_families=1))


def test_required_capabilities_and_risk_profile_are_explicit(tmp_path: Path):
    _, strategy = _validated_strategy(tmp_path)
    assert "cap.observe" in strategy.required_capabilities
    assert "cap.corroborate" in strategy.required_capabilities
    assert strategy.risk_profile.policy_remains_authoritative is True
    assert strategy.risk_profile.capability_governance_remains_authoritative is True
    assert strategy.risk_profile.runtime_remains_execution_substrate is True
    assert strategy.risk_profile.single_risk_score_is_objective_truth is False
    assert strategy.applicability.known_failure_conditions == [] or isinstance(strategy.applicability.known_failure_conditions, list)
    assert strategy.applicability.version == "0.1.0"
