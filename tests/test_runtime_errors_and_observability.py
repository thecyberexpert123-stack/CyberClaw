"""Tests for runtime error taxonomy, metrics, observability reporting, and task cancellation."""

from __future__ import annotations

import pytest

from cyberclaw.runtime.errors import (
    BranchExecutionBlockedError,
    DispatchError,
    DuplicateEventError,
    EvidenceProcessingError,
    PauseViolationError,
    PersistenceError,
    ProviderExecutionError,
    QueueError,
    RecoveryError,
    RuntimeAuthorizationError,
    RuntimeBaseError,
    RuntimeResultValidationError,
    RuntimeTimeoutError,
    RuntimeValidationError,
    StateTransitionError,
)
from cyberclaw.runtime.models import (
    CancellationStatus,
    RuntimeMetrics,
    RuntimeObservabilityReport,
    RuntimeTask,
    TaskStatus,
)
from cyberclaw.runtime.queue import DurableTaskQueue


def test_runtime_failure_taxonomy_hierarchy():
    """Verify all runtime error types properly subclass RuntimeErrorBase and retain metadata."""
    err_classes = [
        QueueError,
        RuntimeValidationError,
        RuntimeAuthorizationError,
        DispatchError,
        ProviderExecutionError,
        RuntimeTimeoutError,
        RuntimeResultValidationError,
        EvidenceProcessingError,
        StateTransitionError,
        PersistenceError,
        RecoveryError,
        DuplicateEventError,
        PauseViolationError,
        BranchExecutionBlockedError,
    ]
    for cls in err_classes:
        inst = cls("test error message", task_id="task-123", investigation_id="inv-456")
        assert isinstance(inst, RuntimeBaseError)
        assert isinstance(inst, Exception)
        assert "test error message" in str(inst)
        assert inst.task_id == "task-123"
        assert inst.investigation_id == "inv-456"


def test_runtime_metrics_tracking():
    """Verify RuntimeMetrics counters, gauges, and success rate calculation."""
    m = RuntimeMetrics()
    assert m.success_rate == 0.0

    m.queued_tasks = 10
    m.completed_tasks = 8
    m.failed_tasks = 2
    assert m.success_rate == 80.0

    report = RuntimeObservabilityReport(
        worker_id="worker-test-1",
        metrics=m,
        paused_investigations=["inv-paused-1"],
    )
    dump = report.model_dump()
    assert dump["worker_id"] == "worker-test-1"
    assert dump["metrics"]["completed_tasks"] == 8
    assert dump["paused_investigations"] == ["inv-paused-1"]


def test_task_cancellation_lifecycle_matrix():
    """Verify cancellation behaves correctly across cancellable and terminal states."""
    queue = DurableTaskQueue()

    # 1. Cancel QUEUED task
    t_queued = RuntimeTask(investigation_id="inv-cancel-01", capability_id="c.test")
    queue.enqueue(t_queued)
    assert queue.cancel(t_queued.task_id, reason="User cancelled") is True
    assert t_queued.status == TaskStatus.CANCELLED
    assert t_queued.cancellation_status == CancellationStatus.CANCELLED

    # 2. Cancel COMPLETED task (must fail)
    t_comp = RuntimeTask(investigation_id="inv-cancel-01", capability_id="c.test")
    queue.enqueue(t_comp)
    queue.dequeue("worker-1")
    from cyberclaw.runtime.state import TaskLifecycleDFA
    TaskLifecycleDFA.transition(t_comp, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(t_comp, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(t_comp, TaskStatus.RUNNING)
    queue.ack(t_comp.task_id, result={"done": True})
    assert t_comp.status == TaskStatus.COMPLETED

    assert queue.cancel(t_comp.task_id, reason="Too late") is False
    assert t_comp.status == TaskStatus.COMPLETED  # Unchanged


def test_queue_ack_nonexistent_task():
    """Verify acking an unknown task raises QueueError."""
    queue = DurableTaskQueue()
    with pytest.raises(QueueError) as exc:
        queue.ack("nonexistent-id", result={})
    assert "not found" in str(exc.value)


def test_queue_fail_nonexistent_task():
    """Verify failing an unknown task raises QueueError."""
    queue = DurableTaskQueue()
    with pytest.raises(QueueError) as exc:
        queue.fail("nonexistent-id", error="something broke")
    assert "not found" in str(exc.value)
