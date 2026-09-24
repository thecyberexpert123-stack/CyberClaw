"""Runtime Scheduler managing priority ordering, case-level serialization, pause/resume, and cancellation."""

from __future__ import annotations

import threading
from typing import Any, Dict, List, Optional, Set
from cyberclaw.case.models import JournalEntryType
from cyberclaw.investigation import Investigation
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.runtime.errors import PauseViolationError, QueueError
from cyberclaw.runtime.events import EventFactory, EventSequenceTracker, RuntimeEventType
from cyberclaw.runtime.executor import RuntimeExecutor
from cyberclaw.runtime.models import (
    CancellationStatus,
    RuntimeMetrics,
    RuntimeTask,
    TaskStatus,
)
from cyberclaw.runtime.queue import DurableTaskQueue


class RuntimeScheduler:
    """Coordinates task dispatch, investigation-level serialization, pause/resume, and execution loops."""

    def __init__(
        self,
        queue: DurableTaskQueue,
        executor: RuntimeExecutor,
        worker_id: str = "worker-01",
    ) -> None:
        self.queue = queue
        self.executor = executor
        self.worker_id = worker_id
        self._lock = threading.RLock()
        self._investigation_locks: Dict[str, threading.Lock] = {}
        self._paused_investigations: Set[str] = set()
        self._sequence_trackers: Dict[str, EventSequenceTracker] = {}
        self.metrics = RuntimeMetrics()

    def _get_inv_lock(self, investigation_id: str) -> threading.Lock:
        with self._lock:
            if investigation_id not in self._investigation_locks:
                self._investigation_locks[investigation_id] = threading.Lock()
            return self._investigation_locks[investigation_id]

    def _get_seq_tracker(self, investigation_id: str) -> EventSequenceTracker:
        with self._lock:
            if investigation_id not in self._sequence_trackers:
                self._sequence_trackers[investigation_id] = EventSequenceTracker(investigation_id)
            return self._sequence_trackers[investigation_id]

    def pause_investigation(self, investigation_id: str, reason: str = "") -> None:
        """Pause execution for a specific investigation case."""
        with self._lock:
            self._paused_investigations.add(investigation_id)

    def resume_investigation(self, investigation_id: str) -> None:
        """Resume execution for a paused investigation case."""
        with self._lock:
            self._paused_investigations.discard(investigation_id)

    def is_paused(self, investigation_id: str) -> bool:
        """Check if investigation is currently paused."""
        with self._lock:
            return investigation_id in self._paused_investigations

    def cancel_task(self, task_id: str, reason: str = "") -> bool:
        """Cancel a pending, queued, or running task."""
        with self._lock:
            task = self.queue.get_task(task_id)
            if not task:
                return False
            cancelled = self.queue.cancel(task_id, reason=reason)
            if cancelled:
                self.metrics.cancelled_tasks += 1
            return cancelled

    def step(
        self,
        investigation: Investigation,
        permission_manager: PermissionManager,
        custom_lesson: Optional[str] = None,
        experience_store: Optional[Any] = None,
    ) -> Optional[RuntimeTask]:
        """Claim and execute a single eligible task for this investigation adhering to serialization."""
        inv_id = investigation.id
        if self.is_paused(inv_id):
            raise PauseViolationError(
                f"Cannot process tasks; investigation '{inv_id}' is paused.",
                investigation_id=inv_id,
            )

        inv_lock = self._get_inv_lock(inv_id)
        with inv_lock:
            task = self.queue.dequeue(self.worker_id)
            if not task:
                return None

            # Verify target investigation
            if task.investigation_id != inv_id:
                # Re-queue task if not matching this investigation worker cycle
                self.queue.enqueue(task)
                return None

            self.metrics.running_tasks += 1
            seq_tracker = self._get_seq_tracker(inv_id)

            # Record Task Claimed Event in case journal
            seq = seq_tracker.next_sequence()
            investigation.case_manager.journal.append_entry(
                entry_type=JournalEntryType.TASK_CLAIMED,
                summary=f"Runtime task '{task.task_id}' claimed by {self.worker_id} for capability '{task.capability_id}'",
                reference_id=task.task_id,
                details={"sequence": seq, "capability_id": task.capability_id, "priority": int(task.priority)},
            )

            try:
                completed_task = self.executor.execute_task(
                    task=task,
                    investigation=investigation,
                    permission_manager=permission_manager,
                    custom_lesson=custom_lesson,
                    experience_store=experience_store,
                )
                if completed_task.status == TaskStatus.COMPLETED:
                    self.metrics.completed_tasks += 1
                elif completed_task.status == TaskStatus.DEFERRED:
                    self.metrics.deferred_tasks += 1
                return completed_task

            except Exception as e:
                self.metrics.failed_tasks += 1
                # Attempt retry if eligible
                if self.queue.schedule_retry(task.task_id):
                    self.metrics.retried_tasks += 1
                raise
            finally:
                self.metrics.running_tasks = max(0, self.metrics.running_tasks - 1)
                self.metrics.queue_depth = self.queue.depth(inv_id)

    def process_all(
        self,
        investigation: Investigation,
        permission_manager: PermissionManager,
        max_steps: int = 50,
        custom_lesson: Optional[str] = None,
        experience_store: Optional[Any] = None,
    ) -> List[RuntimeTask]:
        """Process all queued tasks for an investigation up to max_steps."""
        processed: List[RuntimeTask] = []
        steps = 0

        while steps < max_steps:
            if self.is_paused(investigation.id):
                break
            if self.queue.depth(investigation.id) == 0:
                break

            task = self.step(
                investigation=investigation,
                permission_manager=permission_manager,
                custom_lesson=custom_lesson,
                experience_store=experience_store,
            )
            if task:
                processed.append(task)
            steps += 1

        return processed
