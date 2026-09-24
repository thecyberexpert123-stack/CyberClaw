"""Process restart recovery and crash reconciliation for durable investigation runtimes."""

from __future__ import annotations

from typing import Dict, List, Optional
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import (
    ExecutionState,
    RuntimeTask,
    TaskStatus,
)
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.state import TaskLifecycleDFA


class RecoveryReport:
    """Summary of actions taken during runtime recovery."""

    def __init__(self) -> None:
        self.requeued_unstarted: List[str] = []
        self.reconciled_completed: List[str] = []
        self.flagged_unknown: List[str] = []
        self.retried_reversible: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requeued_unstarted": list(self.requeued_unstarted),
            "reconciled_completed": list(self.reconciled_completed),
            "flagged_unknown": list(self.flagged_unknown),
            "retried_reversible": list(self.retried_reversible),
        }


class RuntimeRecoveryManager:
    """Reconciles in-flight and interrupted tasks upon process restart."""

    @classmethod
    def recover(
        cls,
        queue: DurableTaskQueue,
        idempotency: IdempotencyRegistry,
    ) -> RecoveryReport:
        """Inspect durable queue and idempotency state, determining safe next actions."""
        report = RecoveryReport()
        all_tasks = queue.list_tasks()

        for task in all_tasks:
            # 1. Tasks claimed but never executed (crashed before execution)
            if task.status in (TaskStatus.VALIDATING, TaskStatus.AUTHORIZED, TaskStatus.DISPATCHED):
                if task.execution_state == ExecutionState.UNSTARTED:
                    task.claimed_by_worker = None
                    task.claim_expires_at = None
                    task.status = TaskStatus.QUEUED
                    report.requeued_unstarted.append(task.task_id)
                    continue

            # 2. Tasks interrupted while RUNNING
            if task.status == TaskStatus.RUNNING:
                # Check if execution actually succeeded before worker died (crash before ack)
                existing = idempotency.get_existing_execution(task.idempotency_key)
                if existing:
                    # Reconcile completed state without re-running
                    task.execution_state = ExecutionState.COMPLETED
                    queue.ack(task.task_id, result=existing.get("result"))
                    report.reconciled_completed.append(task.task_id)
                    continue

                # Execution was in progress and result is unrecorded
                task.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
                task.claimed_by_worker = None
                task.claim_expires_at = None

                # Non-consequential (read-only / reversible) tasks may be safely retried
                is_safe_scope = task.action_scope.lower() in ("read_only", "informational", "reversible")
                if is_safe_scope and task.retry_count < task.retry_policy.max_retries:
                    queue.fail(task.task_id, "Worker crashed during in-flight execution", failure_type="WORKER_CRASH")
                    if queue.schedule_retry(task.task_id):
                        report.retried_reversible.append(task.task_id)
                        continue

                # Consequential or destructive tasks MUST NOT be blindly re-executed
                queue.fail(task.task_id, "Worker crashed during execution; provider state unknown", failure_type="UNKNOWN_EXECUTION_STATE")
                report.flagged_unknown.append(task.task_id)

        return report
