"""Deterministic Task Lifecycle Finite State Machine (DFA)."""

from __future__ import annotations

from typing import Dict, Optional, Set
from cyberclaw.runtime.errors import StateTransitionError
from cyberclaw.runtime.models import (
    CancellationStatus,
    RuntimeTask,
    TaskStatus,
    utc_now,
)

# Deterministic transition table defining permissible next states for a RuntimeTask
VALID_TASK_TRANSITIONS: Dict[TaskStatus, Set[TaskStatus]] = {
    TaskStatus.CREATED: {TaskStatus.QUEUED, TaskStatus.CANCELLED},
    TaskStatus.QUEUED: {TaskStatus.VALIDATING, TaskStatus.DEFERRED, TaskStatus.CANCELLED},
    TaskStatus.DEFERRED: {TaskStatus.QUEUED, TaskStatus.CANCELLED},
    TaskStatus.VALIDATING: {
        TaskStatus.AUTHORIZED,
        TaskStatus.REJECTED,
        TaskStatus.DEFERRED,
        TaskStatus.CANCELLED,
        TaskStatus.FAILED,
    },
    TaskStatus.AUTHORIZED: {
        TaskStatus.DISPATCHED,
        TaskStatus.CANCELLED,
        TaskStatus.DEFERRED,
        TaskStatus.FAILED,
        TaskStatus.REJECTED,
    },
    TaskStatus.DISPATCHED: {
        TaskStatus.RUNNING,
        TaskStatus.FAILED,
        TaskStatus.TIMED_OUT,
        TaskStatus.CANCELLED,
    },
    TaskStatus.RUNNING: {
        TaskStatus.COMPLETED,
        TaskStatus.FAILED,
        TaskStatus.TIMED_OUT,
        TaskStatus.CANCELLED,
    },
    TaskStatus.FAILED: {TaskStatus.RETRY_PENDING},
    TaskStatus.TIMED_OUT: {TaskStatus.RETRY_PENDING},
    TaskStatus.RETRY_PENDING: {TaskStatus.QUEUED, TaskStatus.CANCELLED},
    TaskStatus.COMPLETED: set(),
    TaskStatus.REJECTED: set(),
    TaskStatus.CANCELLED: set(),
}


class TaskLifecycleDFA:
    """Enforces deterministic task state transitions independently of agent reasoning."""

    @classmethod
    def transition(
        cls,
        task: RuntimeTask,
        target_status: TaskStatus,
        reason: Optional[str] = None,
    ) -> TaskStatus:
        """Validate and apply a state transition to a RuntimeTask."""
        current_status = task.status
        allowed = VALID_TASK_TRANSITIONS.get(current_status, set())

        if target_status not in allowed:
            raise StateTransitionError(
                f"Illegal task transition from '{current_status.value}' to '{target_status.value}'. "
                f"Permissible targets: {[s.value for s in allowed]}",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
            )

        task.status = target_status

        # Synchronize lifecycle timestamps & flags
        now = utc_now()
        if target_status == TaskStatus.QUEUED and not task.queued_at:
            task.queued_at = now
        elif target_status == TaskStatus.RUNNING and not task.started_at:
            task.started_at = now
        elif target_status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.TIMED_OUT, TaskStatus.CANCELLED):
            task.completed_at = now

        if target_status == TaskStatus.CANCELLED:
            task.cancellation_status = CancellationStatus.CANCELLED
        elif target_status == TaskStatus.TIMED_OUT:
            if reason:
                task.timeout_reason = reason

        return task.status
