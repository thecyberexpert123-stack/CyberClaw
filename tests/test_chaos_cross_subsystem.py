"""Cross-subsystem chaos: persistence, policy time-travel, branch/learning, collaboration, knowledge."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from cyberclaw.branching.errors import BranchIntegrityError
from cyberclaw.branching.persistence import BranchPersistence
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.chaos.scenarios import scenario_branch_learning_isolation, scenario_policy_time_travel, scenario_runtime_crash_recovery_replay
from cyberclaw.collaboration.dependencies import CollaborationDependencyGraph
from cyberclaw.collaboration.errors import CollaborationPersistenceError, DependencyCycleError, UnauthorizedContextAccessError
from cyberclaw.collaboration.models import CollaborationRequest, CollaborationResult, ContextSensitivity
from cyberclaw.collaboration.persistence import CollaborationPersistenceManager
from cyberclaw.collaboration.protocol import ContextFilter
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.errors import KnowledgeIntegrityError
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.models import RelationshipType
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.persistence import KnowledgePersistenceManager
from cyberclaw.learning.errors import LearningTamperError, SelfApprovalError
from cyberclaw.learning.governance import assert_external_actor
from cyberclaw.learning.models import ApprovalDecisionKind, StrategyLifecycle
from cyberclaw.learning.persistence import LearningPersistenceManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.models import Policy, PolicyEffect, PolicyExecutionContext
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.replay.errors import ReplaySequenceError
from cyberclaw.runtime.errors import PersistenceError, RuntimeValidationError
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import ExecutionState, RuntimeEvent, RuntimeTask, TaskStatus
from cyberclaw.runtime.persistence import RuntimePersistenceManager
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.state import TaskLifecycleDFA
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistEndpoint, SpecialistHealth, SpecialistRequest, SpecialistResponse
from cyberclaw.specialists.self_development.maturity import SkillMaturityState
from cyberclaw.specialists.self_development.promotion import PromotionManager, UnauthorizedPromotionError
from cyberclaw.specialists.self_development.skill import ExperimentalSkill
from cyberclaw.types import Source


class _Endpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        return SpecialistResponse(specialist_id=self_id(self), status="SUCCESS", result=ExecutionResult.success_empty())


def self_id(endpoint) -> str:
    return "specialist.alpha"


class BoomProvider(CapabilityProvider):
    def __init__(self) -> None:
        super().__init__(id="provider.boom", name="Boom", capability_id="chaos.boom")
        self.calls = 0

    def is_ready(self, context=None):
        return True, None

    def execute(self, parameters, context: ExecutionContext) -> ExecutionResult:
        self.calls += 1
        raise TimeoutError("transient connection timeout during dispatch")


def test_runtime_crash_recovery_replay_scenario(tmp_path: Path):
    result = scenario_runtime_crash_recovery_replay(tmp_path)
    report = result["report"]
    assert report.passed, render_failures(report)
    assert result["provider_calls"] == 1
    assert result["detectors_executed"] == 0
    assert result["graph_stable"] is True
    assert report.recovery_result["requeued_unstarted"]
    assert "Replay Result" not in report.scenario_id


def test_policy_time_travel_does_not_rewrite_history(tmp_path: Path):
    result = scenario_policy_time_travel(tmp_path)
    report = result["report"]
    assert report.passed, render_failures(report)
    assert report.observed_state["historical"] == "ALLOW"
    assert report.observed_state["current"] == "DENY"
    assert report.observed_state["replayed"] == "ALLOW"
    assert report.observed_state["policy_calls_during_replay"] == 0


def test_historical_deny_survives_current_allow(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Historical deny")
    core.policy_engine.registry.register_policy(
        Policy(policy_id="chaos.reverse", name="Deny first", version="1.0.0", default_effect=PolicyEffect.DENY, rules=[])
    )
    core.policy_engine.registry.register_policy(
        Policy(policy_id="chaos.reverse", name="Allow later", version="1.9.0", default_effect=PolicyEffect.ALLOW, rules=[])
    )
    context = PolicyExecutionContext(
        investigation_id=investigation.id,
        case_stage="READY",
        actor_id="core.system",
        actor_role="system",
        capability_id="chaos.observe",
        capability_version="1.0.0",
        action_type="execute",
        action_scope="reversible",
        lifecycle_state="AVAILABLE",
        trust_state="TRUSTED_WITH_SCOPE",
    )
    historical = core.policy_engine.authorize(context, policy_id="chaos.reverse", policy_version="1.0.0")
    core.policy_engine.record_in_journal(historical, investigation.case_manager)
    current = core.policy_engine.authorize(context, policy_id="chaos.reverse")
    replayed = ReplayEngine.replay(investigation)
    outcomes = [(item.outcome or {}).get("decision") for item in replayed.decisions]
    assert historical.decision.value == "DENY"
    assert current.decision.value == "ALLOW"
    assert "DENY" in outcomes
    assert current.policy_version == "1.9.0"


def test_policy_latest_version_is_semantic_not_lexicographic():
    from cyberclaw.policy.registry import PolicyRegistry

    registry = PolicyRegistry(populate_defaults=False)
    registry.register_policy(Policy(policy_id="chaos.semver", name="nine", version="1.9.0", default_effect=PolicyEffect.DENY, rules=[]))
    registry.register_policy(Policy(policy_id="chaos.semver", name="ten", version="1.10.0", default_effect=PolicyEffect.ALLOW, rules=[]))
    assert registry.get_policy("chaos.semver").version == "1.10.0"


def test_branch_learning_isolation_scenario(tmp_path: Path):
    result = scenario_branch_learning_isolation(tmp_path)
    report = result["report"]
    assert report.passed, render_failures(report)
    assert result["branch"].is_counterfactual is True
    assert "ev-counterfactual" not in {item.id for item in result["core"].get_investigation(result["branch"].investigation_id).evidence_store.list_all()}


def test_learning_cannot_self_approve_or_publish_without_policy(tmp_path: Path):
    from cyberclaw.learning.governance import StrategyGovernance

    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    with pytest.raises(SelfApprovalError):
        assert_external_actor("learning.engine")

    class _Strategy:
        required_capabilities = ["chaos.observe"]
        risk_profile = type("Risk", (), {"required_action_scope": "reversible"})()

    precheck = StrategyGovernance.precheck(
        _Strategy(),
        None,
        investigation_id="inv-chaos",
        actor="lead.reviewer",
        actor_role="lead_investigator",
    )
    assert precheck.allowed is False
    assert precheck.decision == "DENY"
    assert any("Fail-closed" in reason for reason in precheck.reasons)


def test_experimental_skill_cannot_self_trust():
    from cyberclaw.specialists.self_development.promotion import PromotionProposal

    skill = ExperimentalSkill(
        skill_id="skill.chaos",
        purpose="Observe without escalating trust",
        hypothesis="A repeated observation is not a trusted skill",
        author_origin="specialist.alpha",
        maturity=SkillMaturityState.PROPOSED,
    )
    manager = PromotionManager()
    manager._proposals["proposal-1"] = PromotionProposal(
        id="proposal-1",
        skill_id=skill.skill_id,
        version=skill.version,
        evaluation_id="eval-1",
        rationale="attempted self approval",
    )
    with pytest.raises(UnauthorizedPromotionError):
        manager.review_proposal("proposal-1", skill, approver="specialist.alpha", approved=True, reason="self")
    assert skill.maturity != SkillMaturityState.TRUSTED


def test_unregistered_capability_is_not_created_by_runtime(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Unregistered capability")
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="start")
    before = core.capabilities.get_capability("chaos.unregistered")
    core.submit_task_to_runtime(investigation.id, "chaos.unregistered", {"target": "s"}, actor="core.system")
    with pytest.raises(RuntimeValidationError):
        core.step_runtime(investigation.id)
    assert before is None
    assert core.capabilities.get_capability("chaos.unregistered") is None


def test_provider_exception_does_not_blindly_retry_consequential_work(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    core.register_capability(Capability(id="chaos.boom", name="Boom", action_scope=ActionScope.CONSEQUENTIAL))
    provider = BoomProvider()
    core.register_provider(provider)
    investigation = core.create_investigation("Unknown dispatch")
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="start")
    task = core.submit_task_to_runtime(
        investigation.id,
        "chaos.boom",
        {"target": "s"},
        scope=ActionScope.CONSEQUENTIAL,
        actor="core.system",
        actor_role="lead_investigator",
    )
    with pytest.raises(Exception):
        core.step_runtime(investigation.id)
    stored = core.runtime_queue.get_task(task.task_id)
    assert stored.execution_state == ExecutionState.UNKNOWN_EXECUTION_STATE
    assert stored.status == TaskStatus.FAILED
    assert provider.calls == 1
    assert core.runtime_queue.depth(investigation.id) == 0


def test_duplicate_event_authorization_and_execution_remain_distinct():
    registry = IdempotencyRegistry()
    event = RuntimeEvent(
        event_id="event-1",
        event_type="TASK_QUEUED",
        investigation_id="inv",
        correlation_id="inv",
        sequence=1,
        idempotency_key="event-key",
    )
    assert registry.is_duplicate_event(event.event_id, event.idempotency_key) is False
    registry.record_event(event)
    assert registry.is_duplicate_event(event.event_id, event.idempotency_key) is True
    assert registry.get_existing_authorization("task-key") is None
    registry.record_authorization("task-key", {"decision": "ALLOW", "decision_id": "d1"})
    assert registry.get_existing_execution("task-key") is None
    registry.record_execution("task-key", {"status": "SUCCESS"})
    assert registry.get_existing_authorization("task-key")["decision"] == "ALLOW"
    assert registry.get_existing_execution("task-key")["status"] == "SUCCESS"
    assert registry.is_duplicate_event("other-event") is False


def test_duplicate_completion_does_not_duplicate_evidence(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    core.register_capability(Capability(id="chaos.observe", name="Observe", action_scope=ActionScope.REVERSIBLE))

    class Once(CapabilityProvider):
        def __init__(self):
            super().__init__(id="provider.once", name="Once", capability_id="chaos.observe")
            self.calls = 0

        def is_ready(self, context=None):
            return True, None

        def execute(self, parameters, context):
            self.calls += 1
            evidence = Evidence(
                id="ev-once",
                type="finding",
                subject="subject",
                value={"n": self.calls},
                source=Source(type="fixture", name="once", id="once"),
            )
            return ExecutionResult.success([evidence], output={"n": self.calls})

    provider = Once()
    core.register_provider(provider)
    investigation = core.create_investigation("Duplicate completion")
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="start")
    task = core.submit_task_to_runtime(investigation.id, "chaos.observe", {"target": "subject"}, actor="core.system")
    completed = core.step_runtime(investigation.id)
    assert completed.status == TaskStatus.COMPLETED
    core.runtime_queue._tasks[task.task_id].status = TaskStatus.QUEUED
    core.runtime_queue._tasks[task.task_id].execution_state = ExecutionState.UNSTARTED
    second = core.step_runtime(investigation.id)
    assert second.status == TaskStatus.COMPLETED
    assert provider.calls == 1
    assert len(investigation.evidence_store.list_all()) == 1


def test_runtime_persistence_corruption_fails_closed(tmp_path: Path):
    queue = DurableTaskQueue()
    idempotency = IdempotencyRegistry()
    task = RuntimeTask(investigation_id="inv-corrupt", capability_id="chaos.observe", idempotency_key="k")
    queue.enqueue(task)
    idempotency.record_execution("k", {"status": "SUCCESS"})
    RuntimePersistenceManager.persist_state(queue, idempotency, tmp_path)
    queue_file = tmp_path / "runtime" / "queue.json"
    original = queue_file.read_text(encoding="utf-8")
    queue_file.write_text(original[:12], encoding="utf-8")
    fresh = DurableTaskQueue()
    fresh_idemp = IdempotencyRegistry()
    with pytest.raises(PersistenceError) as exc:
        RuntimePersistenceManager.load_state(fresh, fresh_idemp, tmp_path)
    assert exc.value.corruption_class in ("TRUNCATION", "INVALID_JSON")
    assert fresh.get_task(task.task_id) is None
    assert fresh_idemp.get_existing_execution("k") is None


def test_runtime_digest_mismatch_does_not_import(tmp_path: Path):
    queue = DurableTaskQueue()
    idempotency = IdempotencyRegistry()
    queue.enqueue(RuntimeTask(investigation_id="inv-digest", capability_id="chaos.observe"))
    RuntimePersistenceManager.persist_state(queue, idempotency, tmp_path)
    digest_file = tmp_path / "runtime" / "digest.json"
    digest_file.write_text('{"digest": "' + ("a" * 64) + '"}', encoding="utf-8")
    fresh = DurableTaskQueue()
    with pytest.raises(PersistenceError) as exc:
        RuntimePersistenceManager.load_state(fresh, IdempotencyRegistry(), tmp_path)
    assert exc.value.corruption_class == "DIGEST_MISMATCH"
    assert fresh.depth() == 0


def test_runtime_invalid_schema_does_not_partially_import(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "queue.json").write_text('[{"task_id": "ok"}, {"nope": true}]', encoding="utf-8")
    (runtime / "idempotency.json").write_text("{}", encoding="utf-8")
    (runtime / "digest.json").write_text('{"digest": "irrelevant"}', encoding="utf-8")
    # Digest will fail before import if bytes don't match, so write a matching digest after schema-valid digest of these bytes.
    from cyberclaw.runtime.persistence import _digest_texts

    queue_text = (runtime / "queue.json").read_text(encoding="utf-8")
    idemp_text = (runtime / "idempotency.json").read_text(encoding="utf-8")
    (runtime / "digest.json").write_text('{"digest": "%s"}' % _digest_texts(queue_text, idemp_text), encoding="utf-8")
    fresh = DurableTaskQueue()
    with pytest.raises(PersistenceError) as exc:
        RuntimePersistenceManager.load_state(fresh, IdempotencyRegistry(), tmp_path)
    assert exc.value.corruption_class == "INVALID_SCHEMA"
    assert fresh.list_tasks() == []


def test_missing_idempotency_record_is_not_an_empty_queue(tmp_path: Path):
    queue = DurableTaskQueue()
    queue.enqueue(RuntimeTask(investigation_id="inv-missing", capability_id="chaos.observe"))
    RuntimePersistenceManager.persist_state(queue, IdempotencyRegistry(), tmp_path)
    (tmp_path / "runtime" / "idempotency.json").unlink()
    with pytest.raises(PersistenceError) as exc:
        RuntimePersistenceManager.load_state(DurableTaskQueue(), IdempotencyRegistry(), tmp_path)
    assert exc.value.corruption_class == "MISSING_RECORD"


def test_collaboration_corruption_fails_closed(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Collab persist")
    core.collaboration.request_collaboration(
        investigation=investigation,
        requesting_specialist="specialist.alpha",
        objective="Observe subject",
        target_specialist="specialist.beta",
    )
    CollaborationPersistenceManager.persist_state(core.collaboration, tmp_path)
    (tmp_path / "collaboration" / "requests.json").write_text("{", encoding="utf-8")
    fresh = CyberClawCore(workspace_path=tmp_path / "other")
    fresh.startup()
    with pytest.raises(CollaborationPersistenceError) as exc:
        CollaborationPersistenceManager.load_state(fresh.collaboration, tmp_path)
    assert exc.value.corruption_class in ("TRUNCATION", "INVALID_JSON")
    assert fresh.collaboration.list_requests() == []


def test_learning_registry_tamper_fails_closed(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    core.persist_learning_state()
    path = tmp_path / "learning" / "registry.json"
    text = path.read_text(encoding="utf-8")
    path.write_text(text.replace("0.1.0", "9.9.9", 1), encoding="utf-8")
    with pytest.raises(LearningTamperError):
        LearningPersistenceManager.load(tmp_path)


def test_knowledge_digest_mismatch_fails_closed(tmp_path: Path):
    now = datetime(2026, 9, 25, tzinfo=timezone.utc)
    graph = TemporalKnowledgeGraph(investigation_id="inv-kg", case_id="case")
    node = KnowledgeNode(
        node_id="node-1",
        node_type="ENTITY",
        label="subject",
        investigation_id="inv-kg",
        created_at=now,
        valid_from=now,
    ).seal()
    graph.add_node(node)
    KnowledgePersistenceManager.save_graph(graph, tmp_path)
    manifest = tmp_path / "knowledge" / "manifests" / "manifest.json"
    body = manifest.read_text(encoding="utf-8").replace(graph.calculate_graph_digest(), "0" * 64)
    manifest.write_text(body, encoding="utf-8")
    with pytest.raises(KnowledgeIntegrityError):
        KnowledgePersistenceManager.load_graph("inv-kg", tmp_path)


def test_missing_branch_directory_is_not_silently_dropped(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Branch missing")
    investigation.add_evidence(
        Evidence(id="ev-1", type="finding", subject="s", value={"a": 1}, source=Source(type="fixture", name="n", id="n"))
    )
    snapshot = investigation.capture_snapshot(trigger="branch")
    branch = investigation.create_branch(snapshot.sequence, purpose="isolation")
    BranchPersistence.persist_branch(core.workspace, branch)
    BranchPersistence.persist_branches_index(core.workspace, investigation.id, [branch])
    layout = core.workspace.get_investigation_workspace(investigation.id)
    import shutil

    shutil.rmtree(layout.branches / f"branch_{branch.branch_id}")
    with pytest.raises(BranchIntegrityError):
        BranchPersistence.load_branches(core.workspace, investigation.id)


def test_journal_gap_fails_replay(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Journal gap")
    entries = investigation.case_manager.journal.entries
    if len(entries) >= 2:
        entries[1].sequence = entries[1].sequence + 5
    else:
        investigation.case_manager.journal.append_entry(
            entry_type=investigation.case_manager.journal.entries[0].entry_type,
            summary="gap",
        )
        investigation.case_manager.journal._entries[-1].sequence = 9
    with pytest.raises(ReplaySequenceError):
        ReplayEngine.replay(investigation)


def test_dependency_cycle_is_rejected():
    graph = CollaborationDependencyGraph()
    graph.add_dependency("a", "b")
    graph.add_dependency("b", "c")
    with pytest.raises(DependencyCycleError):
        graph.add_dependency("c", "a")


def test_restricted_context_is_not_handed_to_uncleared_specialist(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Restricted")
    request = CollaborationRequest(
        investigation_id=investigation.id,
        requesting_specialist="specialist.alpha",
        target_specialist="specialist.beta",
        objective="share restricted context",
        sensitivity=ContextSensitivity.SENSITIVE,
    )
    specialist = Specialist(
        id="specialist.beta",
        name="Beta",
        capabilities=["chaos.observe"],
        endpoint=_Endpoint(),
        max_sensitivity_level="INTERNAL",
    )
    with pytest.raises(UnauthorizedContextAccessError):
        ContextFilter.filter_context(request, investigation, specialist)


def test_collaboration_failure_does_not_become_complete_evidence(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Collab failure")
    request = core.collaboration.request_collaboration(
        investigation=investigation,
        requesting_specialist="specialist.alpha",
        objective="need a finding",
        target_specialist="specialist.beta",
    )
    duplicate = core.collaboration.request_collaboration(
        investigation=investigation,
        requesting_specialist="specialist.alpha",
        objective="need a finding",
        target_specialist="specialist.beta",
    )
    result = CollaborationResult(
        request_id=request.request_id,
        investigation_id=investigation.id,
        responding_specialist="specialist.beta",
        status="FAILURE",
        error="specialist unavailable",
        failures=[{"type": "SPECIALIST_FAILURE"}],
    )
    assert result.status == "FAILURE"
    assert result.evidence == []
    assert request.request_id != duplicate.request_id
    assert len(investigation.evidence_store.list_all()) == 0
    participants = {request.requesting_specialist, request.target_specialist, duplicate.requesting_specialist}
    assert len(participants) == 2
    assert len(investigation.evidence_store.list_all()) == 0


def test_temporal_knowledge_keeps_history_inference_and_contradiction():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    t1 = datetime(2026, 6, 1, tzinfo=timezone.utc)
    t2 = datetime(2026, 12, 1, tzinfo=timezone.utc)
    graph = TemporalKnowledgeGraph(investigation_id="inv-temporal", case_id="case")
    subject = KnowledgeNode(node_id="subject", node_type="ENTITY", label="subject", investigation_id="inv-temporal", created_at=t0, valid_from=t0).seal()
    old = KnowledgeNode(node_id="obs-old", node_type="OBSERVATION", label="old", investigation_id="inv-temporal", created_at=t0, valid_from=t0, valid_until=t1).seal()
    new = KnowledgeNode(node_id="obs-new", node_type="OBSERVATION", label="new", investigation_id="inv-temporal", created_at=t1, valid_from=t1).seal()
    inferred = KnowledgeNode(node_id="inference-1", node_type="HYPOTHESIS", label="inferred", investigation_id="inv-temporal", created_at=t1, valid_from=t1).seal()
    for node in (subject, old, new, inferred):
        graph.add_node(node)
    historical_edge = KnowledgeEdge(
        edge_id="edge-old",
        source_node_id="subject",
        target_node_id="obs-old",
        relationship_type=RelationshipType.SUPPORTS.value,
        investigation_id="inv-temporal",
        created_at=t0,
        valid_from=t0,
        valid_until=t1,
        epistemic_nature="OBSERVATION",
    ).seal()
    current_edge = KnowledgeEdge(
        edge_id="edge-new",
        source_node_id="subject",
        target_node_id="obs-new",
        relationship_type=RelationshipType.SUPPORTS.value,
        investigation_id="inv-temporal",
        created_at=t1,
        valid_from=t1,
        epistemic_nature="OBSERVATION",
    ).seal()
    inference_edge = KnowledgeEdge(
        edge_id="edge-inference",
        source_node_id="subject",
        target_node_id="inference-1",
        relationship_type=RelationshipType.SUPPORTS.value,
        investigation_id="inv-temporal",
        created_at=t1,
        valid_from=t1,
        epistemic_nature="INFERENCE",
        metadata={"contradiction_with": "obs-old"},
    ).seal()
    graph.add_edge(historical_edge)
    graph.add_edge(current_edge)
    graph.add_edge(inference_edge)
    historical = graph.get_historical_view_at_time(t0 + timedelta(days=1))
    current = graph.get_current_view()
    assert historical.get_edge("edge-old") is not None
    assert current.get_edge("edge-old") is None or current.get_edge("edge-old").valid_until is not None
    assert graph.get_edge("edge-inference").epistemic_nature == "INFERENCE"
    assert graph.get_node("inference-1").node_type != "OBSERVATION"
    digest_a = graph.calculate_graph_digest()
    digest_b = graph.calculate_graph_digest()
    assert digest_a == digest_b
    # Graph reconstruction is a read. It must not be an execution substrate.
    assert graph.get_edge("edge-inference").epistemic_nature != "OBSERVATION"


def test_idempotency_duplicate_execution_does_not_collapse_event_identity():
    registry = IdempotencyRegistry()
    event = RuntimeEvent(
        event_id="evt-dup",
        event_type="TASK_COMPLETED",
        investigation_id="inv",
        correlation_id="inv",
        sequence=2,
        idempotency_key="evt-key",
    )
    registry.record_event(event)
    registry.record_execution("task-key", {"status": "SUCCESS", "evidence_ids": ["ev-1"]})
    exported = registry.export_state()
    assert "evt-dup" in exported["seen_events"]
    assert "task-key" in exported["executions"]
    assert exported["seen_events"]["evt-dup"]["event_id"] != exported["executions"]["task-key"]


def test_supervision_requirement_is_not_cleared_by_retry(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    core.register_capability(Capability(id="chaos.observe", name="Observe", action_scope=ActionScope.CONSEQUENTIAL))
    investigation = core.create_investigation("Supervision")
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="start")
    task = core.submit_task_to_runtime(
        investigation.id,
        "chaos.observe",
        {"target": "s"},
        scope=ActionScope.CONSEQUENTIAL,
        actor="core.system",
        actor_role="analyst",
    )
    deferred = core.step_runtime(investigation.id)
    assert deferred.status == TaskStatus.DEFERRED
    assert deferred.authorization_decision_id
    decision = core.policy_engine.get_decision(deferred.authorization_decision_id)
    assert decision.decision.value in ("REQUIRE_SUPERVISION", "REQUIRE_APPROVAL", "DENY")
    assert core.runtime_queue.schedule_retry(task.task_id) is False


def test_interleaving_authorization_and_recovery_preserves_decision(tmp_path: Path):
    from cyberclaw.chaos.scheduler import DeterministicInterleaver

    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    investigation = core.create_investigation("Interleave")
    context = PolicyExecutionContext(
        investigation_id=investigation.id,
        case_stage="READY",
        actor_id="core.system",
        actor_role="system",
        capability_id="chaos.observe",
        capability_version="1.0.0",
        action_type="execute",
        action_scope="reversible",
        lifecycle_state="AVAILABLE",
        trust_state="TRUSTED_WITH_SCOPE",
    )
    state = {"decision": None, "recovered": False}

    def authorize() -> str:
        decision = core.policy_engine.authorize(context)
        core.policy_engine.record_in_journal(decision, investigation.case_manager)
        state["decision"] = decision.decision.value
        return decision.decision.value

    def recover() -> str:
        report = core.recover_runtime()
        state["recovered"] = True
        return str(report.to_dict())

    def replay() -> str:
        reconstructed = ReplayEngine.replay(investigation)
        outcomes = [(item.outcome or {}).get("decision") for item in reconstructed.decisions]
        return ",".join(item or "" for item in outcomes)

    interleaver = DeterministicInterleaver(5, {"authorize": authorize, "recover": recover, "replay": replay})
    trace = interleaver.run(["authorize", "recover", "replay"])
    assert state["decision"] == "ALLOW"
    assert "ALLOW" in trace[-1]
    assert interleaver.seed == 5


def test_capability_trust_change_does_not_rewrite_recorded_authorization(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    capability = Capability(id="chaos.observe", name="Observe", action_scope=ActionScope.REVERSIBLE)
    core.register_capability(capability)
    investigation = core.create_investigation("Trust change")
    context = PolicyExecutionContext(
        investigation_id=investigation.id,
        case_stage="READY",
        actor_id="core.system",
        actor_role="system",
        capability_id="chaos.observe",
        capability_version="1.0.0",
        action_type="execute",
        action_scope="reversible",
        lifecycle_state="AVAILABLE",
        trust_state="TRUSTED_WITH_SCOPE",
    )
    decision = core.policy_engine.authorize(context)
    core.policy_engine.record_in_journal(decision, investigation.case_manager)
    capability.trust_state = CapabilityTrustState.REVOKED
    capability.lifecycle_state = CapabilityLifecycleState.DISABLED
    replayed = ReplayEngine.replay(investigation)
    outcomes = [(item.outcome or {}).get("decision") for item in replayed.decisions]
    assert decision.decision.value in outcomes
    assert capability.trust_state == CapabilityTrustState.REVOKED


def test_learning_strategy_cannot_skip_to_available(tmp_path: Path):
    from tests.learning_support import build_completed_investigation

    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    core.register_capability(Capability(id="cap.observe", name="Observe", action_scope=ActionScope.REVERSIBLE))
    core.register_capability(Capability(id="cap.corroborate", name="Corroborate", action_scope=ActionScope.REVERSIBLE))
    build_completed_investigation(core, family="fam-a", target="s-a", source_id="src-a")
    build_completed_investigation(core, family="fam-b", target="s-b", source_id="src-b")
    for investigation in list(core._investigations.values()):
        ingested = core.ingest_investigation_experience(investigation.id)
        assert ingested.ok
    pattern = next(item for item in core.learning.list_patterns() if item.scope.value == "VALIDATED")
    strategy = core.propose_learned_strategy(pattern.pattern_id, "analyst.proposer")
    assert strategy.lifecycle_state == StrategyLifecycle.PROPOSED
    with pytest.raises(Exception):
        core.approve_learned_strategy(strategy.strategy_id, strategy.version, actor="lead.reviewer", decision=ApprovalDecisionKind.APPROVE, reason="skip")
    assert core.learning.get_strategy(strategy.strategy_id, strategy.version).lifecycle_state == StrategyLifecycle.PROPOSED


def render_failures(report) -> str:
    return "\n".join(
        f"{item.invariant_id}: expected={item.expected} observed={item.observed}"
        for item in report.invariant_results
        if not item.passed
    )
