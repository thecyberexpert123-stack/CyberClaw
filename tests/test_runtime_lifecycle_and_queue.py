"""Tests for Task Lifecycle DFA, Queue operations, Priority scheduling, and atomic persistence."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import pytest

from cyberclaw.runtime.errors import StateTransitionError
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import (
    RuntimeTask,
    TaskPriority,
    TaskStatus,
    utc_now,
)
from cyberclaw.runtime.persistence import RuntimePersistenceManager
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.state import TaskLifecycleDFA


def test_task_lifecycle_dfa_forward_path():
    """Verify valid primary lifecycle: CREATED -> QUEUED -> VALIDATING -> AUTHORIZED -> DISPATCHED -> RUNNING -> COMPLETED."""
    task = RuntimeTask(investigation_id="inv-dfa-01", capability_id="tool.scan")
    assert task.status == TaskStatus.CREATED

    TaskLifecycleDFA.transition(task, TaskStatus.QUEUED)
    assert task.status == TaskStatus.QUEUED
    assert task.queued_at is not None

    TaskLifecycleDFA.transition(task, TaskStatus.VALIDATING)
    assert task.status == TaskStatus.VALIDATING

    TaskLifecycleDFA.transition(task, TaskStatus.AUTHORIZED)
    assert task.status == TaskStatus.AUTHORIZED

    TaskLifecycleDFA.transition(task, TaskStatus.DISPATCHED)
    assert task.status == TaskStatus.DISPATCHED

    TaskLifecycleDFA.transition(task, TaskStatus.RUNNING)
    assert task.status == TaskStatus.RUNNING
    assert task.started_at is not None

    TaskLifecycleDFA.transition(task, TaskStatus.COMPLETED)
    assert task.status == TaskStatus.COMPLETED
    assert task.completed_at is not None
    assert task.status.is_terminal is True


def test_task_lifecycle_controlled_alternate_paths():
    """Verify controlled alternative paths: DEFERRED, REJECTED, CANCELLED, FAILED, TIMED_OUT, RETRY_PENDING."""
    # Alternate path 1: QUEUED -> DEFERRED -> QUEUED
    t1 = RuntimeTask(investigation_id="inv-dfa-02", capability_id="tool.scan")
    TaskLifecycleDFA.transition(t1, TaskStatus.QUEUED)
    TaskLifecycleDFA.transition(t1, TaskStatus.DEFERRED)
    assert t1.status == TaskStatus.DEFERRED
    TaskLifecycleDFA.transition(t1, TaskStatus.QUEUED)
    assert t1.status == TaskStatus.QUEUED

    # Alternate path 2: VALIDATING -> REJECTED
    t2 = RuntimeTask(investigation_id="inv-dfa-02", capability_id="tool.scan")
    TaskLifecycleDFA.transition(t2, TaskStatus.QUEUED)
    TaskLifecycleDFA.transition(t2, TaskStatus.VALIDATING)
    TaskLifecycleDFA.transition(t2, TaskStatus.REJECTED)
    assert t2.status == TaskStatus.REJECTED
    assert t2.status.is_terminal is True

    # Alternate path 3: AUTHORIZED -> CANCELLED
    t3 = RuntimeTask(investigation_id="inv-dfa-02", capability_id="tool.scan")
    TaskLifecycleDFA.transition(t3, TaskStatus.QUEUED)
    TaskLifecycleDFA.transition(t3, TaskStatus.VALIDATING)
    TaskLifecycleDFA.transition(t3, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(t3, TaskStatus.CANCELLED)
    assert t3.status == TaskStatus.CANCELLED

    # Alternate path 4: RUNNING -> FAILED -> RETRY_PENDING -> QUEUED
    t4 = RuntimeTask(investigation_id="inv-dfa-02", capability_id="tool.scan")
    TaskLifecycleDFA.transition(t4, TaskStatus.QUEUED)
    TaskLifecycleDFA.transition(t4, TaskStatus.VALIDATING)
    TaskLifecycleDFA.transition(t4, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(t4, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(t4, TaskStatus.RUNNING)
    TaskLifecycleDFA.transition(t4, TaskStatus.FAILED)
    TaskLifecycleDFA.transition(t4, TaskStatus.RETRY_PENDING)
    TaskLifecycleDFA.transition(t4, TaskStatus.QUEUED)
    assert t4.status == TaskStatus.QUEUED


def test_task_lifecycle_dfa_rejects_illegal_transitions():
    """Verify state machine rejects impossible or backward jumps."""
    task = RuntimeTask(investigation_id="inv-dfa-03", capability_id="tool.scan")

    # Cannot skip directly from CREATED to RUNNING
    with pytest.raises(StateTransitionError) as exc1:
        TaskLifecycleDFA.transition(task, TaskStatus.RUNNING)
    assert "Illegal task transition from 'CREATED' to 'RUNNING'" in str(exc1.value)

    # Cannot transition out of terminal COMPLETED
    TaskLifecycleDFA.transition(task, TaskStatus.QUEUED)
    TaskLifecycleDFA.transition(task, TaskStatus.VALIDATING)
    TaskLifecycleDFA.transition(task, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(task, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(task, TaskStatus.RUNNING)
    TaskLifecycleDFA.transition(task, TaskStatus.COMPLETED)

    with pytest.raises(StateTransitionError) as exc2:
        TaskLifecycleDFA.transition(task, TaskStatus.QUEUED)
    assert "Illegal task transition from 'COMPLETED' to 'QUEUED'" in str(exc2.value)


def test_durable_queue_priority_ordering():
    """Verify tasks are dequeued in strict priority order (CRITICAL > HIGH > NORMAL > LOW)."""
    queue = DurableTaskQueue()

    t_low = RuntimeTask(investigation_id="inv-q-01", capability_id="c.low", priority=TaskPriority.LOW)
    t_crit = RuntimeTask(investigation_id="inv-q-01", capability_id="c.crit", priority=TaskPriority.CRITICAL)
    t_norm = RuntimeTask(investigation_id="inv-q-01", capability_id="c.norm", priority=TaskPriority.NORMAL)
    t_high = RuntimeTask(investigation_id="inv-q-01", capability_id="c.high", priority=TaskPriority.HIGH)

    # Enqueue in randomized/scrambled order
    queue.enqueue(t_low)
    queue.enqueue(t_norm)
    queue.enqueue(t_crit)
    queue.enqueue(t_high)

    assert queue.depth() == 4

    # Dequeue must return CRITICAL first
    c1 = queue.dequeue(worker_id="worker-1")
    assert c1.task_id == t_crit.task_id
    assert c1.claimed_by_worker == "worker-1"

    # Next HIGH
    c2 = queue.dequeue(worker_id="worker-1")
    assert c2.task_id == t_high.task_id

    # Next NORMAL
    c3 = queue.dequeue(worker_id="worker-1")
    assert c3.task_id == t_norm.task_id

    # Finally LOW
    c4 = queue.dequeue(worker_id="worker-1")
    assert c4.task_id == t_low.task_id

    assert queue.dequeue(worker_id="worker-1") is None
    assert queue.depth() == 0


def test_durable_queue_lease_expiration_and_reclaiming():
    """Verify expired worker leases are automatically returned to the queue."""
    queue = DurableTaskQueue(default_claim_timeout_seconds=0.01)
    task = RuntimeTask(investigation_id="inv-q-02", capability_id="tool.recon")
    queue.enqueue(task)

    claimed = queue.dequeue(worker_id="crashed-worker", claim_timeout_seconds=0.01)
    assert claimed.status == TaskStatus.VALIDATING
    assert queue.depth() == 0

    # Artificially set claim expiration in the past
    claimed.claim_expires_at = utc_now() - timedelta(seconds=1)

    # Dequeue by fresh worker should trigger lease reclamation
    reclaimed = queue.dequeue(worker_id="healthy-worker")
    assert reclaimed is not None
    assert reclaimed.task_id == task.task_id
    assert reclaimed.claimed_by_worker == "healthy-worker"


def test_durable_queue_atomic_persistence_and_reload(tmp_path: Path):
    """Verify queue tasks and idempotency registry persist atomically and restore accurately."""
    queue = DurableTaskQueue()
    idemp = IdempotencyRegistry()

    t1 = RuntimeTask(investigation_id="inv-persist-01", capability_id="dns.lookup", parameters={"d": "a.org"})
    t2 = RuntimeTask(investigation_id="inv-persist-01", capability_id="whois.query", priority=TaskPriority.HIGH)
    queue.enqueue(t1)
    queue.enqueue(t2)
    idemp.record_authorization("key-persist-1", {"decision": "ALLOW"})

    # Persist to disk
    RuntimePersistenceManager.persist_state(queue, idemp, tmp_path)
    assert (tmp_path / "runtime" / "queue.json").exists()
    assert (tmp_path / "runtime" / "idempotency.json").exists()

    # Create fresh queue and reload
    new_queue = DurableTaskQueue()
    new_idemp = IdempotencyRegistry()
    loaded = RuntimePersistenceManager.load_state(new_queue, new_idemp, tmp_path)
    assert loaded is True
    assert new_queue.depth() == 2
    assert new_queue.get_task(t1.task_id) is not None
    assert new_queue.get_task(t2.task_id) is not None
    assert new_idemp.get_existing_authorization("key-persist-1") == {"decision": "ALLOW"}
