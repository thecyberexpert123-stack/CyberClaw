"""Governance, planner consumption, replay, persistence, and graph isolation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.knowledge.models import KnowledgeGap
from cyberclaw.learning.errors import LearningTamperError, StrategyGovernanceError
from cyberclaw.learning.models import ApprovalDecisionKind, PatternKind, StrategyLifecycle
from cyberclaw.learning.patterns import PatternDetector
from cyberclaw.planning.engine import AdaptivePlanningEngine
from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.policy.models import Policy, PolicyEffect
from cyberclaw.replay.engine import ReplayEngine
from tests.learning_support import build_completed_investigation


def _available_strategy(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    first = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    second = build_completed_investigation(core, family="fam-b", target="subject-b", source_id="src-b", with_retry=True)
    core.ingest_investigation_experience(first.id)
    core.ingest_investigation_experience(second.id)
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION)
    strategy = core.propose_learned_strategy(pattern.pattern_id, "analyst.proposer")
    core.simulate_learned_strategy(strategy.strategy_id, strategy.version, actor="lead.simulator")
    core.evaluate_learned_strategy(strategy.strategy_id, strategy.version, actor="lead.evaluator")
    core.review_learned_strategy(strategy.strategy_id, strategy.version, "lead.reviewer")
    core.approve_learned_strategy(
        strategy.strategy_id,
        strategy.version,
        "lead.approver",
        ApprovalDecisionKind.APPROVE,
        "external approval of a reviewed strategy",
        evidence_refs=[first.id, second.id],
    )
    published, precheck = core.publish_learned_strategy(
        strategy.strategy_id,
        strategy.version,
        "lead.publisher",
        actor_role="lead_investigator",
        investigation_id=first.id,
    )
    return core, first, published, precheck


def test_publish_requires_policy_allow_and_fails_closed_without_engine(tmp_path: Path):
    core, first, published, precheck = _available_strategy(tmp_path)
    assert published.lifecycle_state == StrategyLifecycle.AVAILABLE
    assert precheck.decision == "ALLOW"
    assert precheck.policy_id
    strategy = core.learning.get_strategy(published.strategy_id).model_copy(
        update={"lifecycle_state": StrategyLifecycle.APPROVED}
    )
    core.learning.store_strategy(strategy, actor="lead.publisher")
    with pytest.raises(StrategyGovernanceError):
        core.learning_service.publish(
            strategy.strategy_id,
            strategy.version,
            "lead.publisher",
            "lead_investigator",
            None,
            first.id,
        )


def test_custom_deny_policy_blocks_publication(tmp_path: Path):
    core, first, published, _ = _available_strategy(tmp_path)
    engine = PolicyEngine()
    engine.registry.register_policy(
        Policy(
            policy_id="deny-all",
            name="Deny all",
            version="9.9.9",
            rules=[],
            default_effect=PolicyEffect.DENY,
        )
    )
    engine.registry.set_default_policy("deny-all")
    strategy = published.model_copy(update={"lifecycle_state": StrategyLifecycle.APPROVED})
    core.learning.store_strategy(strategy, actor="lead.publisher")
    with pytest.raises(StrategyGovernanceError):
        core.learning_service.publish(
            strategy.strategy_id,
            strategy.version,
            "lead.publisher",
            "lead_investigator",
            engine,
            first.id,
        )
    assert core.learning.get_strategy(strategy.strategy_id).lifecycle_state == StrategyLifecycle.APPROVED


def test_planner_filters_unavailable_capabilities_and_permissions(tmp_path: Path):
    core, first, published, _ = _available_strategy(tmp_path)
    current = core.create_investigation(
        "Resolve contradictory evidence about subject",
        description="Resolve contradictory evidence about subject",
        metadata={"source_family": "fam-c"},
    )
    core.transition_investigation(current.id, CoreState.INVESTIGATE, event="start")
    req = current.create_information_requirement(
        description="Resolve contradictory evidence",
        target_or_entity="subject-c",
        evidence_types_sought=["finding"],
    )
    req.metadata["uncertainty_type"] = "CONTRADICTION_RESOLUTION"
    gap = KnowledgeGap(
        graph_location="hypothesis:none",
        uncertainty_type="CONTRADICTION_RESOLUTION",
        missing_evidence_categories=["finding"],
    )
    denied = AdaptivePlanningEngine().request_strategy_candidates(
        current,
        core.learning,
        knowledge_gaps=[gap],
        available_capabilities=["cap.observe"],
        actor_permissions=["investigation:view"],
        policy_engine=core.policy_engine,
    )
    assert published.strategy_id not in {item.strategy_id for item in denied.candidates}
    assert any("missing_required_capability" in str(item.get("detail", "")) or item.get("reason") == "not_applicable" for item in denied.excluded)

    allowed = core.query_learned_strategies(
        current.id,
        available_capabilities=["cap.observe", "cap.corroborate"],
        actor_permissions=["investigation:view"],
    )
    assert any(item.strategy_id == published.strategy_id for item in allowed.candidates)
    candidate = next(item for item in allowed.candidates if item.strategy_id == published.strategy_id)
    assert candidate.executable is False
    assert candidate.execution_substrate == "runtime_only"
    assert candidate.opaque_preference_used is False
    assert candidate.ranking_policy == "deterministic_id_order"
    assert candidate.policy_precheck == "ALLOW"
    assert candidate.required_capabilities
    assert candidate.supporting_investigations
    assert candidate.reason_for_applicability
    assert "HISTORICAL_PERFORMANCE_IS_NOT_A_FUTURE_GUARANTEE" in candidate.limitations


def test_permission_boundary_excludes_candidate(tmp_path: Path):
    core, _, published, _ = _available_strategy(tmp_path)
    restricted = published.model_copy(
        update={
            "required_permissions": ["investigation:admin"],
            "applicability": published.applicability.model_copy(update={"required_permissions": ["investigation:admin"]}),
        }
    )
    core.learning.store_strategy(restricted, actor="lead.publisher")
    current = core.create_investigation("Resolve contradictory evidence about subject", description="Resolve contradictory evidence about subject")
    core.transition_investigation(current.id, CoreState.INVESTIGATE, event="start")
    result = AdaptivePlanningEngine().request_strategy_candidates(
        current,
        core.learning,
        knowledge_gaps=[KnowledgeGap(graph_location="gap", uncertainty_type="CONTRADICTION_RESOLUTION")],
        available_capabilities=list(restricted.required_capabilities),
        actor_permissions=["investigation:view"],
        policy_engine=core.policy_engine,
    )
    assert restricted.strategy_id not in {item.strategy_id for item in result.candidates}
    assert any("missing_required_permission" in str(item) for item in result.excluded)


def test_replay_uses_recorded_events_not_todays_detector(tmp_path: Path):
    core, _, published, _ = _available_strategy(tmp_path)
    events = list(core.learning.events)

    def _boom(*args, **kwargs):
        raise AssertionError("today's detector must not run during replay")

    original = PatternDetector.detect
    PatternDetector.detect = _boom
    try:
        state = ReplayEngine.replay_learning_state(events)
        early = ReplayEngine.replay_learning_state(events, until_sequence=1)
    finally:
        PatternDetector.detect = original
    assert state.detectors_executed == 0
    assert state.evaluators_executed == 0
    assert state.providers_executed == 0
    assert published.strategy_id in state.strategies
    assert state.strategies[published.strategy_id][published.version]["lifecycle_state"] == "AVAILABLE"
    assert state.strategies[published.strategy_id][published.version]["content_digest"] == published.content_digest
    assert published.strategy_id not in early.strategies
    assert len(core.learning.events) == len(events)


def test_replay_preserves_historical_lifecycle_and_origin(tmp_path: Path):
    core, _, published, _ = _available_strategy(tmp_path)
    approval_seq = next(
        event.sequence for event in core.learning.events if event.event_type.value == "STRATEGY_APPROVAL_RECORDED"
    )
    historical = ReplayEngine.replay_learning_state(core.learning.events, until_sequence=approval_seq)
    snapshot = historical.strategies[published.strategy_id][published.version]
    assert snapshot["lifecycle_state"] == "APPROVED"
    assert snapshot["content_digest"] == published.content_digest
    origin = ReplayEngine.explain_strategy_origin(core.learning.events, published.strategy_id, published.version)
    assert origin.causal_claim == "NONE"
    assert origin.reconstructed_from_events is True
    assert len(origin.supporting_cases) == 2
    assert origin.detector_version == "0.1.0"
    history = ReplayEngine.get_strategy_history(core.learning.events, published.strategy_id)
    assert any(event.event_type.value == "STRATEGY_PROPOSED" for event in history)
    pattern_id = origin.pattern_id
    assert ReplayEngine.get_pattern_history(core.learning.events, pattern_id)


def test_persistence_roundtrip_and_tamper_detection(tmp_path: Path):
    core, _, published, _ = _available_strategy(tmp_path)
    path = core.persist_learning_state()
    assert path.exists()
    reloaded = core.load_learning_state()
    restored = reloaded.get_strategy(published.strategy_id, published.version)
    assert restored.lifecycle_state == StrategyLifecycle.AVAILABLE
    assert restored.content_digest == published.content_digest
    assert len(reloaded.events) == len(core.learning.events)

    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["payload"]["strategies"]["tampered"] = {"1.0.0": {"strategy_id": "tampered"}}
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(LearningTamperError):
        core.load_learning_state()


def test_learning_graph_does_not_alter_case_graph(tmp_path: Path):
    core, first, published, _ = _available_strategy(tmp_path)
    case_graph = core.materialize_knowledge_graph(first.id)
    before = case_graph.calculate_graph_digest()
    learning_graph = core.project_learning_knowledge_graph()
    assert case_graph.calculate_graph_digest() == before
    assert learning_graph.investigation_id == "__learning_registry__"
    assert learning_graph is not case_graph
    relations = {edge.metadata.get("learning_relation") for edge in learning_graph.get_edges()}
    assert {"SUPPORTED_BY", "OBSERVED_IN", "APPLICABLE_TO", "GENERATED"} <= relations
    assert all(edge.epistemic_nature != "OBSERVATION" for edge in learning_graph.get_edges())
    assert all(not node.is_counterfactual for node in learning_graph.get_nodes())
    assert published.strategy_id not in case_graph._nodes
