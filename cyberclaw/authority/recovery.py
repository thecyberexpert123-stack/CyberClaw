"""Recovery and lease ownership.

Derived from existing runtime governance. Failure timing is not an input.
A reversible in-progress crash with no execution record may be closed and
retried as a new unstarted attempt. Consequential and destructive unknown
states are preserved. An execution record is not a license to call the
provider again.
"""

from __future__ import annotations

from cyberclaw.authority.models import RecoveryDisposition, WorkerOwnership


_REVERSIBLE = ("read_only", "informational", "reversible")
_UNSTARTED_CLAIM = ("VALIDATING", "AUTHORIZED", "DISPATCHED")


def recovery_disposition(
    *,
    action_scope: str,
    execution_state: ExecutionState,
    task_status: TaskStatus,
    has_execution_record: bool,
    retries_remaining: bool,
) -> RecoveryDisposition:
    """Decide recovery without looking at clocks or exception text."""
    status = task_status.value if hasattr(task_status, "value") else str(task_status)
    progress = execution_state.value if hasattr(execution_state, "value") else str(execution_state)
    if has_execution_record and status == "RUNNING":
        return RecoveryDisposition.RECONCILE_COMPLETED
    if has_execution_record:
        return RecoveryDisposition.PRESERVE_UNKNOWN
    if status in _UNSTARTED_CLAIM and progress == "UNSTARTED":
        return RecoveryDisposition.REQUEUE_UNSTARTED
    scope = (action_scope or "").lower()
    if scope in _REVERSIBLE and retries_remaining and status in ("RUNNING", "DISPATCHED", "VALIDATING", "AUTHORIZED"):
        return RecoveryDisposition.GOVERNED_REVERSIBLE_RETRY
    return RecoveryDisposition.PRESERVE_UNKNOWN


def classify_worker_ownership(task, has_execution_record: bool = False) -> WorkerOwnership:
    """Classify a claimed task. Lease expiry does not change this class."""
    status = task.status.value if hasattr(task.status, "value") else str(task.status)
    progress = task.execution_state.value if hasattr(task.execution_state, "value") else str(task.execution_state)
    if status == "COMPLETED" or progress == "COMPLETED":
        return WorkerOwnership.COMPLETED
    if has_execution_record:
        return WorkerOwnership.EXECUTION_RECORDED
    if progress == "UNKNOWN_EXECUTION_STATE":
        return WorkerOwnership.UNKNOWN
    if progress == "IN_PROGRESS" or status == "RUNNING":
        return WorkerOwnership.STARTED
    if status in _UNSTARTED_CLAIM and progress == "UNSTARTED":
        return WorkerOwnership.CLAIMED
    return WorkerOwnership.UNKNOWN
