"""Durable, thread-safe, priority-aware task queue with lease and retry mechanics."""

from __future__ import annotations

from datetime import timedelta
import threading
from typing import Any, Dict, List, Optional
from cyberclaw.runtime.errors import ConcurrencyConflictError, QueueError
from cyberclaw.runtime.models import (
    ExecutionState,
    RuntimeTask,
    TaskPriority,
    TaskStatus,
    utc_now,
)
from cyberclaw.runtime.state import TaskLifecycleDFA


class DurableTaskQueue:
    """Thread-safe persistent task queue supporting priority dequeue, leases, retries, and cancellation."""

    def __init__(self, default_claim_timeout_seconds: float = 60.0) -> None:
        self._lock = threading.RLock()
        self._tasks: Dict[str, RuntimeTask] = {}
        self.default_claim_timeout = default_claim_timeout_seconds

    def enqueue(self, task: RuntimeTask) -> RuntimeTask:
        """Enqueue a new or retried task."""
        with self._lock:
            if task.task_id in self._tasks:
                existing = self._tasks[task.task_id]
                if existing.status in (TaskStatus.QUEUED, TaskStatus.RUNNING, TaskStatus.VALIDATING):
                    return existing

            TaskLifecycleDFA.transition(task, TaskStatus.QUEUED)
            self._tasks[task.task_id] = task
            return task

    def dequeue(self, worker_id: str, claim_timeout_seconds: Optional[float] = None) -> Optional[RuntimeTask]:
        """Claim the highest-priority pending task from the queue."""
        with self._lock:
            # Clean up expired claims first
            self._reclaim_expired_leases()

            # Find all eligible QUEUED tasks
            eligible = [t for t in self._tasks.values() if t.status == TaskStatus.QUEUED]
            if not eligible:
                return None

            # Sort by priority ascending (1=CRITICAL, 2=HIGH, 3=NORMAL, 4=LOW) then created_at
            eligible.sort(key=lambda t: (int(t.priority), t.created_at))
            task = eligible[0]

            # Transition task to VALIDATING (claiming)
            TaskLifecycleDFA.transition(task, TaskStatus.VALIDATING)
            task.claimed_by_worker = worker_id
            timeout_sec = claim_timeout_seconds or self.default_claim_timeout
            task.claim_expires_at = utc_now() + timedelta(seconds=timeout_sec)
            return task

    def ack(self, task_id: str, result: Optional[Dict[str, Any]] = None) -> RuntimeTask:
        """Acknowledge successful completion of a task."""
        with self._lock:
            if task_id not in self._tasks:
                raise QueueError(f"Task '{task_id}' not found in queue.")
            task = self._tasks[task_id]
            if task.status != TaskStatus.RUNNING:
                # If already completed, idempotent return
                if task.status == TaskStatus.COMPLETED:
                    return task
                raise ConcurrencyConflictError(
                    f"Cannot ack task '{task_id}' from non-running status '{task.status.value}'.",
                    task_id=task_id,
                )
            TaskLifecycleDFA.transition(task, TaskStatus.COMPLETED)
            task.result = result or {}
            task.claimed_by_worker = None
            task.claim_expires_at = None
            return task

    def reject(self, task_id: str, reason: str = "") -> RuntimeTask:
        """Mark a task as rejected during validation or policy checks."""
        with self._lock:
            if task_id not in self._tasks:
                raise QueueError(f"Task '{task_id}' not found in queue.")
            task = self._tasks[task_id]
            if task.status == TaskStatus.REJECTED:
                return task

            TaskLifecycleDFA.transition(task, TaskStatus.REJECTED, reason=reason)
            task.error = reason
            task.failure_type = "REJECTED"
            task.claimed_by_worker = None
            task.claim_expires_at = None
            return task

    def fail(self, task_id: str, error: str, failure_type: str = "PROVIDER_FAILURE") -> RuntimeTask:
        """Mark a task as failed with classification."""
        with self._lock:
            if task_id not in self._tasks:
                raise QueueError(f"Task '{task_id}' not found in queue.")
            task = self._tasks[task_id]
            if task.status == TaskStatus.FAILED:
                return task

            TaskLifecycleDFA.transition(task, TaskStatus.FAILED, reason=error)
            task.error = error
            task.failure_type = failure_type
            task.claimed_by_worker = None
            task.claim_expires_at = None
            return task

    def schedule_retry(self, task_id: str) -> bool:
        """Check retry eligibility and re-queue task if permissible."""
        with self._lock:
            if task_id not in self._tasks:
                return False
            task = self._tasks[task_id]
            if task.status != TaskStatus.FAILED and task.status != TaskStatus.TIMED_OUT:
                return False

            if task.execution_state == ExecutionState.UNKNOWN_EXECUTION_STATE:
                # Unknown provider state must not be blindly replayed, even if the
                # failure type would otherwise be retryable.
                return False
            if task.retry_count >= task.retry_policy.max_retries:
                return False
            if not task.retry_policy.is_retryable(task.failure_type, task.action_scope):
                return False

            # Valid for retry
            task.retry_count += 1
            TaskLifecycleDFA.transition(task, TaskStatus.RETRY_PENDING)
            TaskLifecycleDFA.transition(task, TaskStatus.QUEUED)
            task.error = None
            task.failure_type = None
            return True

    def cancel(self, task_id: str, reason: str = "") -> bool:
        """Cancel a pending or queued task."""
        with self._lock:
            if task_id not in self._tasks:
                return False
            task = self._tasks[task_id]
            if task.status in (TaskStatus.COMPLETED, TaskStatus.CANCELLED, TaskStatus.REJECTED):
                return False

            TaskLifecycleDFA.transition(task, TaskStatus.CANCELLED, reason=reason)
            task.error = reason or "Cancelled by user or system"
            task.claimed_by_worker = None
            task.claim_expires_at = None
            return True

    def defer(self, task_id: str, reason: str = "") -> bool:
        """Defer a task due to policy or pause."""
        with self._lock:
            if task_id not in self._tasks:
                return False
            task = self._tasks[task_id]
            if task.status not in (TaskStatus.QUEUED, TaskStatus.VALIDATING, TaskStatus.AUTHORIZED):
                return False
            TaskLifecycleDFA.transition(task, TaskStatus.DEFERRED, reason=reason)
            task.claimed_by_worker = None
            task.claim_expires_at = None
            return True

    def peek(self) -> Optional[RuntimeTask]:
        """Inspect highest priority queued task without claiming."""
        with self._lock:
            queued = [t for t in self._tasks.values() if t.status == TaskStatus.QUEUED]
            if not queued:
                return None
            queued.sort(key=lambda t: (int(t.priority), t.created_at))
            return queued[0]

    def get_task(self, task_id: str) -> Optional[RuntimeTask]:
        """Retrieve task by ID."""
        with self._lock:
            return self._tasks.get(task_id)

    def list_tasks(
        self,
        status: Optional[TaskStatus] = None,
        investigation_id: Optional[str] = None,
    ) -> List[RuntimeTask]:
        """List tasks matching filters."""
        with self._lock:
            res = list(self._tasks.values())
            if status is not None:
                res = [t for t in res if t.status == status]
            if investigation_id is not None:
                res = [t for t in res if t.investigation_id == investigation_id]
            return res

    def depth(self, investigation_id: Optional[str] = None) -> int:
        """Return count of active QUEUED tasks."""
        with self._lock:
            tasks = [t for t in self._tasks.values() if t.status == TaskStatus.QUEUED]
            if investigation_id:
                tasks = [t for t in tasks if t.investigation_id == investigation_id]
            return len(tasks)

    def _reclaim_expired_leases(self) -> None:
        """Reset claims on workers that timed out before progressing or completing."""
        now = utc_now()
        for task in self._tasks.values():
            if (
                task.status in (TaskStatus.VALIDATING, TaskStatus.AUTHORIZED, TaskStatus.DISPATCHED)
                and task.claim_expires_at
                and task.claim_expires_at < now
            ):
                # A lease expiry is not authority to replay work that may already
                # have reached a provider. Leave non-unstarted tasks for recovery.
                if task.execution_state != ExecutionState.UNSTARTED:
                    continue
                task.claimed_by_worker = None
                task.claim_expires_at = None
                task.status = TaskStatus.QUEUED

    def export_state(self) -> List[Dict[str, Any]]:
        """Export serialized tasks for atomic persistence."""
        with self._lock:
            return [t.model_dump() for t in self._tasks.values()]

    def import_state(self, items: List[Dict[str, Any]]) -> None:
        """Import tasks from persistent store."""
        with self._lock:
            for item in items:
                task = RuntimeTask(**item)
                self._tasks[task.task_id] = task
