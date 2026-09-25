"""Deterministic chaos runner. It drives existing subsystems; it does not replace them."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from cyberclaw.chaos.models import RecoveryClass, TraceEvent
from cyberclaw.chaos.reports import structural_digest
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import ExecutionState, RuntimeTask, TaskStatus
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.recovery import RuntimeRecoveryManager
from cyberclaw.runtime.state import TaskLifecycleDFA


CRASH_BOUNDARIES = (
    "before_validation",
    "after_validation",
    "before_authorization",
    "after_authorization",
    "before_dispatch",
    "after_dispatch",
    "before_provider_result",
    "after_provider_result",
    "before_evidence_persistence",
    "after_evidence_persistence",
    "before_case_journal_append",
    "after_case_journal_append",
    "before_acknowledgement",
    "after_acknowledgement",
)


def classify_recovery(report: Any, task: RuntimeTask) -> RecoveryClass:
    if task.task_id in report.requeued_unstarted:
        return RecoveryClass.REQUEUED_UNSTARTED
    if task.task_id in report.reconciled_completed:
        return RecoveryClass.RECONCILED_COMPLETED
    if task.task_id in report.retried_reversible:
        return RecoveryClass.REVERSIBLE_RETRY
    if task.task_id in report.flagged_unknown:
        return RecoveryClass.UNKNOWN_REQUIRES_GOVERNANCE
    if task.status == TaskStatus.REJECTED:
        return RecoveryClass.REJECTED_NOT_RETRIED
    if task.status == TaskStatus.QUEUED and task.execution_state == ExecutionState.UNSTARTED:
        return RecoveryClass.REQUEUED_UNSTARTED
    if task.status.is_terminal:
        return RecoveryClass.ALREADY_TERMINAL
    return RecoveryClass.NOT_RECOVERABLE


def simulate_boundary_crash(boundary: str, *, scope: str = "consequential") -> Dict[str, Any]:
    """Place a task at a crash boundary and run the existing recovery manager.

    This does not execute providers. It records the state a crash would leave
    and asks the real recovery path what is safe.
    """
    if boundary not in CRASH_BOUNDARIES:
        raise KeyError(f"Unknown crash boundary '{boundary}'")
    queue = DurableTaskQueue()
    idempotency = IdempotencyRegistry()
    task = RuntimeTask(
        task_id=f"task-{boundary}",
        investigation_id="inv-boundary",
        capability_id="chaos.observe",
        action_scope=scope,
        idempotency_key=f"key-{boundary}",
    )
    queue.enqueue(task)
    evidence_present = False
    journal_present = False

    def claim() -> None:
        queue.dequeue("chaos-worker")

    if boundary != "before_validation":
        claim()
    if boundary in (
        "after_authorization",
        "before_dispatch",
        "after_dispatch",
        "before_provider_result",
        "after_provider_result",
        "before_evidence_persistence",
        "after_evidence_persistence",
        "before_case_journal_append",
        "after_case_journal_append",
        "before_acknowledgement",
    ):
        TaskLifecycleDFA.transition(task, TaskStatus.AUTHORIZED)
    if boundary in (
        "after_dispatch",
        "before_provider_result",
        "after_provider_result",
        "before_evidence_persistence",
        "after_evidence_persistence",
        "before_case_journal_append",
        "after_case_journal_append",
        "before_acknowledgement",
    ):
        TaskLifecycleDFA.transition(task, TaskStatus.DISPATCHED)
    if boundary in (
        "before_provider_result",
        "after_provider_result",
        "before_evidence_persistence",
        "after_evidence_persistence",
        "before_case_journal_append",
        "after_case_journal_append",
        "before_acknowledgement",
    ):
        TaskLifecycleDFA.transition(task, TaskStatus.RUNNING)
        task.execution_state = ExecutionState.IN_PROGRESS
    if boundary in (
        "after_provider_result",
        "before_evidence_persistence",
        "after_evidence_persistence",
        "before_case_journal_append",
        "after_case_journal_append",
        "before_acknowledgement",
    ):
        idempotency.record_execution(task.idempotency_key, {"result": {"status": "SUCCESS"}, "status": "SUCCESS"})
    if boundary in ("after_evidence_persistence", "before_case_journal_append", "after_case_journal_append", "before_acknowledgement"):
        evidence_present = True
    if boundary in ("after_case_journal_append", "before_acknowledgement"):
        journal_present = True
    if boundary == "after_acknowledgement":
        TaskLifecycleDFA.transition(task, TaskStatus.AUTHORIZED)
        TaskLifecycleDFA.transition(task, TaskStatus.DISPATCHED)
        TaskLifecycleDFA.transition(task, TaskStatus.RUNNING)
        task.execution_state = ExecutionState.COMPLETED
        idempotency.record_execution(task.idempotency_key, {"result": {"status": "SUCCESS"}, "status": "SUCCESS"})
        queue.ack(task.task_id, result={"status": "SUCCESS"})
        evidence_present = True
        journal_present = True

    recovery = RuntimeRecoveryManager.recover(queue, idempotency)
    classification = classify_recovery(recovery, task)
    return {
        "boundary": boundary,
        "scope": scope,
        "classification": classification.value,
        "status": task.status.value,
        "execution_state": task.execution_state.value,
        "recovery": recovery.to_dict(),
        "evidence_invented": False,
        "evidence_present": evidence_present,
        "journal_present": journal_present,
        "provider_calls": 0,
    }


def trace(actions: List[str]) -> List[TraceEvent]:
    return [TraceEvent(sequence=index + 1, action=action) for index, action in enumerate(actions)]


def investigation_structure(investigation: Any) -> Dict[str, Any]:
    """Structural projection used for cross-run equality. Omits clocks and generated ids."""
    journal = [entry.entry_type.value for entry in investigation.case_manager.journal.entries]
    evidence = []
    for item in investigation.evidence_store.list_all():
        evidence.append({"type": item.type, "subject": item.subject, "value": item.value})
    evidence.sort(key=lambda item: (item["type"], item["subject"], str(item["value"])))
    decisions = []
    for decision in investigation.case_manager.journal.decisions:
        decisions.append(
            {
                "type": decision.decision_type.value,
                "outcome": (decision.outcome or {}).get("decision"),
                "policy_id": (decision.inputs or {}).get("policy_id"),
            }
        )
    return {
        "dfa": investigation.current_state.value,
        "journal_types": journal,
        "evidence": evidence,
        "decisions": decisions,
        "journal_length": len(journal),
    }


def structure_digest(investigation: Any, extra: Optional[Dict[str, Any]] = None) -> str:
    payload = investigation_structure(investigation)
    if extra:
        payload["extra"] = extra
    return structural_digest(payload)


class ChaosRunner:
    """Executes a scenario callable twice and compares structural digests."""

    def __init__(self, seed: int = 0) -> None:
        self.seed = seed

    def run_twice(self, scenario: Callable[[], Dict[str, Any]]) -> Dict[str, Any]:
        first = scenario()
        second = scenario()
        return {
            "seed": self.seed,
            "first": first,
            "second": second,
            "equal": first.get("structural_digest") == second.get("structural_digest"),
        }
