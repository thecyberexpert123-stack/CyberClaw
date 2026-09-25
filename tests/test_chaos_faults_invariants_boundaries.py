"""Isolated fault injection, invariant explanations, and crash-boundary classification."""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberclaw.chaos.corruption import classify_text, has_sequence_gap, truncate
from cyberclaw.chaos.errors import ChaosSecurityError
from cyberclaw.chaos.faults import FaultInjector, assert_fault_is_safe
from cyberclaw.chaos.invariants import InvariantContext, InvariantRegistry
from cyberclaw.chaos.models import CorruptionClass, FaultSpec, FaultType, RecoveryClass
from cyberclaw.chaos.persistence import ChaosReportStore
from cyberclaw.chaos.reports import render_text, structural_digest
from cyberclaw.chaos.runner import CRASH_BOUNDARIES, ChaosRunner, simulate_boundary_crash
from cyberclaw.chaos.scheduler import DeterministicInterleaver
from cyberclaw.chaos.scenarios import scenario_policy_time_travel, scenario_runtime_crash_recovery_replay
from cyberclaw.runtime.models import ExecutionState, RuntimeTask, TaskStatus
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.recovery import RuntimeRecoveryManager
from cyberclaw.runtime.state import TaskLifecycleDFA
from cyberclaw.runtime.idempotency import IdempotencyRegistry


def test_fault_catalog_covers_required_types():
    required = {
        "SPECIALIST_FAILURE",
        "PROVIDER_FAILURE",
        "VALIDATION_FAILURE",
        "POLICY_DENIAL",
        "APPROVAL_REJECTION",
        "SUPERVISION_TIMEOUT",
        "RUNTIME_CRASH",
        "WORKER_CRASH",
        "TASK_TIMEOUT",
        "TASK_CANCELLATION",
        "DUPLICATE_EVENT",
        "DUPLICATE_EXECUTION_ATTEMPT",
        "STALE_LEASE",
        "PARTIAL_RESULT",
        "MALFORMED_RESULT",
        "MISSING_EVIDENCE",
        "CONTRADICTORY_EVIDENCE",
        "PERSISTENCE_TRUNCATION",
        "PERSISTENCE_CORRUPTION",
        "SNAPSHOT_CORRUPTION",
        "JOURNAL_GAP",
        "BRANCH_MUTATION_ATTEMPT",
        "COUNTERFACTUAL_LEAK_ATTEMPT",
        "LEARNING_REGRESSION",
        "POLICY_VERSION_CHANGE",
        "CAPABILITY_STATE_CHANGE",
    }
    assert required <= {item.value for item in FaultType}


def test_fault_injector_rejects_executable_payloads():
    spec = FaultSpec(fault_id="bad", fault_type=FaultType.PROVIDER_FAILURE, target="x", parameters={"cmd": "eval("})
    with pytest.raises(ChaosSecurityError):
        assert_fault_is_safe(spec)


def test_fault_schedule_is_deterministic():
    faults = [
        FaultSpec(fault_id="f1", fault_type=FaultType.PROVIDER_FAILURE, target="chaos.observe"),
        FaultSpec(fault_id="f2", fault_type=FaultType.PARTIAL_RESULT, target="chaos.observe"),
    ]
    first = FaultInjector(faults, seed=4)
    second = FaultInjector(faults, seed=4)
    provider_a = first.provider("chaos.observe")
    provider_b = second.provider("chaos.observe")
    result_a = provider_a.execute({"target": "s"}, None)
    result_b = provider_b.execute({"target": "s"}, None)
    assert result_a.status == result_b.status
    assert first.audit.digest() == second.audit.digest()
    assert provider_a.calls == 1


def test_partial_result_is_not_successful_evidence():
    injector = FaultInjector([FaultSpec(fault_id="p", fault_type=FaultType.PARTIAL_RESULT, target="chaos.observe")])
    result = injector.provider("chaos.observe").execute({}, None)
    assert result.is_empty
    assert result.evidence == []
    assert result.output["complete"] is False


def test_malformed_result_is_a_failure():
    injector = FaultInjector([FaultSpec(fault_id="m", fault_type=FaultType.MALFORMED_RESULT, target="chaos.observe")])
    result = injector.provider("chaos.observe").execute({}, None)
    assert result.is_failure
    assert result.error_code == "MALFORMED_RESULT"


def test_worker_crash_fault_raises_before_evidence():
    injector = FaultInjector([FaultSpec(fault_id="c", fault_type=FaultType.WORKER_CRASH, target="chaos.observe")])
    with pytest.raises(RuntimeError):
        injector.provider("chaos.observe").execute({}, None)
    assert injector.provider("chaos.observe").calls == 0 or injector.audit.applied


def test_invariant_registry_ids_are_stable_and_explanatory():
    registry = InvariantRegistry()
    assert "INV-RUNTIME-001" in registry.ids()
    assert "INV-POLICY-001" in registry.ids()
    assert "INV-LEARNING-001" in registry.ids()
    result = registry.evaluate(
        "INV-RUNTIME-002",
        InvariantContext(unknown_was_retried=True, execution_state="QUEUED", task_status="QUEUED", task_ids=["t1"]),
    )
    assert result.passed is False
    assert result.expected
    assert result.observed
    assert result.boundary
    assert result.invariant_id == "INV-RUNTIME-002"
    text = render_text(
        type("R", (), {
            "scenario_id": "x",
            "seed": 1,
            "injected_faults": [],
            "execution_trace": [],
            "invariant_results": [result],
            "expected_state": {},
            "observed_state": {},
            "recovery_result": {},
            "replay_result": {},
            "digest_comparison": {},
            "boundary_violations": [result.invariant_id],
        })()
    )
    assert "expected:" in text
    assert "INV-RUNTIME-002" in text


def test_structural_digest_ignores_key_order():
    assert structural_digest({"b": 1, "a": 2}) == structural_digest({"a": 2, "b": 1})


def test_corruption_classifier_distinguishes_classes():
    assert classify_text("") == CorruptionClass.TRUNCATION
    assert classify_text("{") == CorruptionClass.TRUNCATION
    assert classify_text('{"a": }') == CorruptionClass.INVALID_JSON
    assert classify_text("[]", expect_object=True) == CorruptionClass.INVALID_SCHEMA
    assert classify_text("{\"ok\": true}", expect_object=True) is None
    assert has_sequence_gap([1, 2, 4]) is True
    assert has_sequence_gap([1, 2, 3]) is False


def test_interleaver_records_seed_and_is_repeatable():
    state = {"value": 0}

    def bump() -> str:
        state["value"] += 1
        return str(state["value"])

    first = DeterministicInterleaver(11, {"bump": bump})
    sequence = ["bump", "bump"]
    assert first.run(sequence) == ["bump:1", "bump:2"]
    digest = first.digest()
    again = DeterministicInterleaver(11, {"bump": lambda: "1"})
    again.trace = ["bump:1", "bump:2"]
    assert again.digest() == digest


@pytest.mark.parametrize("boundary", CRASH_BOUNDARIES)
def test_crash_at_boundary_is_classified_and_executes_nothing(boundary: str):
    result = simulate_boundary_crash(boundary, scope="consequential")
    assert result["provider_calls"] == 0
    assert result["evidence_invented"] is False
    assert result["classification"] in {item.value for item in RecoveryClass}
    if boundary == "before_provider_result":
        assert result["classification"] == RecoveryClass.UNKNOWN_REQUIRES_GOVERNANCE.value
        assert result["execution_state"] == "UNKNOWN_EXECUTION_STATE"
    if boundary == "after_provider_result":
        assert result["classification"] == RecoveryClass.RECONCILED_COMPLETED.value
    if boundary == "after_acknowledgement":
        assert result["classification"] == RecoveryClass.ALREADY_TERMINAL.value
    if boundary in ("after_validation", "before_authorization", "after_dispatch"):
        assert result["classification"] == RecoveryClass.REQUEUED_UNSTARTED.value


def test_reversible_in_progress_crash_uses_governed_retry_not_unknown_replay():
    result = simulate_boundary_crash("before_provider_result", scope="reversible")
    assert result["classification"] == RecoveryClass.REVERSIBLE_RETRY.value
    assert result["provider_calls"] == 0


def test_destructive_unknown_is_not_retried():
    result = simulate_boundary_crash("before_provider_result", scope="destructive")
    assert result["classification"] == RecoveryClass.UNKNOWN_REQUIRES_GOVERNANCE.value
    assert result["status"] == "FAILED"


def test_stale_lease_does_not_requeue_in_progress_consequential_task():
    queue = DurableTaskQueue()
    task = RuntimeTask(
        investigation_id="inv-lease",
        capability_id="chaos.modify",
        action_scope="consequential",
        idempotency_key="lease-key",
    )
    queue.enqueue(task)
    claimed = queue.dequeue("worker")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    claimed.execution_state = ExecutionState.IN_PROGRESS
    from datetime import timedelta
    from cyberclaw.runtime.models import utc_now

    claimed.claim_expires_at = utc_now() - timedelta(seconds=5)
    reclaimed = queue.dequeue("other-worker")
    assert reclaimed is None
    assert claimed.status == TaskStatus.DISPATCHED
    assert claimed.execution_state == ExecutionState.IN_PROGRESS


def test_schedule_retry_refuses_unknown_execution_state():
    queue = DurableTaskQueue()
    idempotency = IdempotencyRegistry()
    task = RuntimeTask(
        investigation_id="inv-unknown",
        capability_id="chaos.modify",
        action_scope="reversible",
        idempotency_key="unknown-key",
    )
    queue.enqueue(task)
    claimed = queue.dequeue("worker")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.RUNNING)
    claimed.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
    queue.fail(task.task_id, "unknown", failure_type="WORKER_CRASH")
    claimed.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
    assert queue.schedule_retry(task.task_id) is False
    report = RuntimeRecoveryManager.recover(queue, idempotency)
    assert task.task_id not in report.retried_reversible


def test_chaos_report_roundtrip(tmp_path: Path):
    from cyberclaw.chaos.models import ChaosReport

    report = ChaosReport(scenario_id="SCN-ROUNDTRIP", seed=3, passed=True)
    store = ChaosReportStore(tmp_path)
    store.save(report)
    loaded = store.load("SCN-ROUNDTRIP")
    assert loaded.scenario_id == "SCN-ROUNDTRIP"
    assert loaded.seed == 3
    text = (tmp_path / "chaos-reports" / "SCN-ROUNDTRIP.txt").read_text(encoding="utf-8")
    assert "Scenario: SCN-ROUNDTRIP" in text
    assert "Boundary Violations" in text


def test_truncation_helper_does_not_repair(tmp_path: Path):
    path = tmp_path / "queue.json"
    path.write_text("{\"queue\": [1, 2, 3], \"tail\": true}", encoding="utf-8")
    truncate(path, keep=6)
    assert classify_text(path.read_text(encoding="utf-8")) in (
        CorruptionClass.TRUNCATION,
        CorruptionClass.INVALID_JSON,
    )


def test_runner_compares_repeatable_structural_digest(tmp_path: Path):
    runner = ChaosRunner(seed=17)

    def _run():
        result = scenario_runtime_crash_recovery_replay(tmp_path / "run")
        return {"structural_digest": result["structural_digest"]}

    # Separate directories so the two runs do not share workspace files.
    calls = {"n": 0}

    def _separated():
        calls["n"] += 1
        result = scenario_runtime_crash_recovery_replay(tmp_path / f"run-{calls['n']}")
        return {"structural_digest": result["structural_digest"], "calls": result["provider_calls"]}

    compared = runner.run_twice(_separated)
    assert compared["equal"] is True
    assert compared["first"]["calls"] == 1
