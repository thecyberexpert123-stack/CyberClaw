"""Tests for retry policies, timeout enforcement, crash scenarios, and process restart recovery."""

from __future__ import annotations

from datetime import timedelta
import pytest

from cyberclaw.runtime.errors import RuntimeTimeoutError
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import (
    ExecutionState,
    RetryPolicy,
    RuntimeTask,
    TaskPriority,
    TaskStatus,
    utc_now,
)
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.recovery import RuntimeRecoveryManager
from cyberclaw.runtime.state import TaskLifecycleDFA


def test_retry_policy_classification_and_destructive_prohibition():
    """Verify RetryPolicy distinguishes retryable from non-retryable failures and bars destructive retries."""
    policy = RetryPolicy(max_retries=3)

    # Retryable types on reversible actions
    assert policy.is_retryable("PROVIDER_TEMPORARY_FAILURE", action_scope="reversible") is True
    assert policy.is_retryable("TIMEOUT", action_scope="reversible") is True
    assert policy.is_retryable("TRANSIENT_UNAVAILABLE", action_scope="reversible") is True

    # Non-retryable types
    assert policy.is_retryable("POLICY_DENIAL", action_scope="reversible") is False
    assert policy.is_retryable("PERMISSION_REJECTION", action_scope="reversible") is False
    assert policy.is_retryable("INVALID_SCHEMA", action_scope="reversible") is False
    assert policy.is_retryable("REVOKED_CAPABILITY", action_scope="reversible") is False

    # DESTRUCTIVE actions are NEVER retryable regardless of failure type
    assert policy.is_retryable("PROVIDER_TEMPORARY_FAILURE", action_scope="destructive") is False
    assert policy.is_retryable("TIMEOUT", action_scope="destructive") is False


def test_queue_schedule_retry_mechanics():
    """Verify queue handles retry count limits and state transitions."""
    queue = DurableTaskQueue()
    task = RuntimeTask(
        investigation_id="inv-retry-01",
        capability_id="tool.api",
        action_scope="reversible",
        retry_policy=RetryPolicy(max_retries=2),
    )
    queue.enqueue(task)
    claimed = queue.dequeue("worker-1")

    # Fail with retryable failure
    queue.fail(claimed.task_id, "Temporary 503 from endpoint", failure_type="PROVIDER_TEMPORARY_FAILURE")
    assert claimed.status == TaskStatus.FAILED

    # First retry attempt succeeds
    can_retry1 = queue.schedule_retry(claimed.task_id)
    assert can_retry1 is True
    assert claimed.retry_count == 1
    assert claimed.status == TaskStatus.QUEUED

    # Second failure & retry
    c2 = queue.dequeue("worker-2")
    queue.fail(c2.task_id, "Temporary 503 again", failure_type="PROVIDER_TEMPORARY_FAILURE")
    can_retry2 = queue.schedule_retry(c2.task_id)
    assert can_retry2 is True
    assert c2.retry_count == 2
    assert c2.status == TaskStatus.QUEUED

    # Third failure exceeds max_retries=2
    c3 = queue.dequeue("worker-3")
    queue.fail(c3.task_id, "Temporary 503 third time", failure_type="PROVIDER_TEMPORARY_FAILURE")
    can_retry3 = queue.schedule_retry(c3.task_id)
    assert can_retry3 is False
    assert c3.status == TaskStatus.FAILED


def test_recovery_unstarted_claimed_task():
    """Verify recovery returns unstarted claimed tasks (worker crash after claim) to QUEUED."""
    queue = DurableTaskQueue()
    idemp = IdempotencyRegistry()

    task = RuntimeTask(investigation_id="inv-rec-01", capability_id="tool.whois")
    queue.enqueue(task)
    claimed = queue.dequeue("crashed-worker-1")
    assert claimed.status == TaskStatus.VALIDATING
    assert claimed.execution_state == ExecutionState.UNSTARTED

    # Simulate process restart recovery
    report = RuntimeRecoveryManager.recover(queue, idemp)
    assert task.task_id in report.requeued_unstarted
    assert task.status == TaskStatus.QUEUED
    assert task.claimed_by_worker is None


def test_recovery_completed_execution_unacknowledged():
    """Verify recovery reconciles tasks where provider finished but worker crashed before queue ack."""
    queue = DurableTaskQueue()
    idemp = IdempotencyRegistry()

    task = RuntimeTask(
        investigation_id="inv-rec-02",
        capability_id="tool.dns",
        idempotency_key="dns-key-01",
    )
    queue.enqueue(task)
    claimed = queue.dequeue("worker-x")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.RUNNING)
    claimed.execution_state = ExecutionState.IN_PROGRESS

    # Record execution in idempotency store simulating provider finished before crash
    idemp.record_execution("dns-key-01", {"result": {"ip": "1.2.3.4"}, "status": "SUCCESS"})

    report = RuntimeRecoveryManager.recover(queue, idemp)
    assert task.task_id in report.reconciled_completed
    assert task.status == TaskStatus.COMPLETED
    assert task.execution_state == ExecutionState.COMPLETED
    assert task.result == {"ip": "1.2.3.4"}


def test_recovery_consequential_in_progress_flagged_unknown():
    """Verify recovery flags interrupted consequential tasks as UNKNOWN_EXECUTION_STATE without blind retry."""
    queue = DurableTaskQueue()
    idemp = IdempotencyRegistry()

    task = RuntimeTask(
        investigation_id="inv-rec-03",
        capability_id="tool.modify_dns",
        action_scope="consequential",
        idempotency_key="mod-dns-key-01",
    )
    queue.enqueue(task)
    claimed = queue.dequeue("worker-y")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.RUNNING)
    claimed.execution_state = ExecutionState.IN_PROGRESS

    # No record in idempotency registry (crashed mid-execution)
    report = RuntimeRecoveryManager.recover(queue, idemp)
    assert task.task_id in report.flagged_unknown
    assert task.execution_state == ExecutionState.UNKNOWN_EXECUTION_STATE
    assert task.status == TaskStatus.FAILED
    assert "provider state unknown" in task.error.lower()


def test_recovery_reversible_in_progress_retried():
    """Verify recovery safely retries interrupted reversible tasks when retry policy permits."""
    queue = DurableTaskQueue()
    idemp = IdempotencyRegistry()

    task = RuntimeTask(
        investigation_id="inv-rec-04",
        capability_id="tool.query_cache",
        action_scope="reversible",
        idempotency_key="query-cache-key-01",
        retry_policy=RetryPolicy(max_retries=2),
    )
    queue.enqueue(task)
    claimed = queue.dequeue("worker-z")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.RUNNING)
    claimed.execution_state = ExecutionState.IN_PROGRESS

    report = RuntimeRecoveryManager.recover(queue, idemp)
    assert task.task_id in report.retried_reversible
    assert task.status == TaskStatus.QUEUED
    assert task.retry_count == 1
