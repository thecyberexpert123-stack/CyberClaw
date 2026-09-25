"""Process restart recovery and crash reconciliation for durable investigation runtimes."""

from __future__ import annotations

from typing import Any, Dict, List
from cyberclaw.authority.models import RecoveryDisposition
from cyberclaw.authority.recovery import recovery_disposition
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import (
    ExecutionState,
    RuntimeTask,
    TaskStatus,
)
from cyberclaw.runtime.queue import DurableTaskQueue


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

    _CLAIMED = (
        TaskStatus.VALIDATING,
        TaskStatus.AUTHORIZED,
        TaskStatus.DISPATCHED,
        TaskStatus.RUNNING,
    )

    @classmethod
    def recover(
        cls,
        queue: DurableTaskQueue,
        idempotency: IdempotencyRegistry,
    ) -> RecoveryReport:
        """Inspect durable queue and idempotency state, determining safe next actions."""
        report = RecoveryReport()
        for task in queue.list_tasks():
            if task.status not in cls._CLAIMED:
                continue
            existing = idempotency.get_existing_execution(task.idempotency_key)
            disposition = recovery_disposition(
                action_scope=task.action_scope,
                execution_state=task.execution_state,
                task_status=task.status,
                has_execution_record=existing is not None,
                retries_remaining=task.retry_count < task.retry_policy.max_retries,
            )
            if disposition == RecoveryDisposition.REQUEUE_UNSTARTED:
                task.claimed_by_worker = None
                task.claim_expires_at = None
                task.status = TaskStatus.QUEUED
                report.requeued_unstarted.append(task.task_id)
                continue
            cls._reconcile_interrupted(task, queue, idempotency, report, disposition, existing)
        return report

    @classmethod
    def _reconcile_interrupted(
        cls,
        task: RuntimeTask,
        queue: DurableTaskQueue,
        idempotency: IdempotencyRegistry,
        report: RecoveryReport,
        disposition: RecoveryDisposition,
        existing,
    ) -> None:
        """Close an interrupted attempt without inventing a provider result."""
        if disposition == RecoveryDisposition.RECONCILE_COMPLETED and existing:
            task.execution_state = ExecutionState.COMPLETED
            queue.ack(task.task_id, result=existing.get("result"))
            report.reconciled_completed.append(task.task_id)
            return

        task.claimed_by_worker = None
        task.claim_expires_at = None

        if disposition == RecoveryDisposition.PRESERVE_UNKNOWN and existing:
            task.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
            queue.fail(
                task.task_id,
                "Execution record exists but the acknowledgement boundary was not reached",
                failure_type="UNKNOWN_EXECUTION_STATE",
            )
            task.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
            report.flagged_unknown.append(task.task_id)
            return

        if disposition == RecoveryDisposition.GOVERNED_REVERSIBLE_RETRY:
            queue.fail(
                task.task_id,
                "Worker crashed during in-flight execution",
                failure_type="WORKER_CRASH",
            )
            # The interrupted attempt is closed. The retry is a new unstarted attempt.
            # This is existing reversible governance, not an inference from failure timing.
            task.execution_state = ExecutionState.UNSTARTED
            if queue.schedule_retry(task.task_id):
                report.retried_reversible.append(task.task_id)
                return

        if task.status != TaskStatus.FAILED:
            queue.fail(
                task.task_id,
                "Worker crashed during execution; provider state unknown",
                failure_type="UNKNOWN_EXECUTION_STATE",
            )
        task.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
        report.flagged_unknown.append(task.task_id)
