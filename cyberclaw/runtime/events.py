"""Runtime event definitions, monotonic sequence tracking, and event emission."""

from __future__ import annotations

from enum import Enum
import threading
from typing import Any, Dict, List, Optional
from cyberclaw.runtime.errors import DuplicateEventError
from cyberclaw.runtime.models import RuntimeEvent, utc_now


class RuntimeEventType(str, Enum):
    """Categorization of discrete runtime events."""

    INVESTIGATION_STARTED = "INVESTIGATION_STARTED"
    REQUIREMENT_CREATED = "REQUIREMENT_CREATED"
    REQUIREMENT_READY = "REQUIREMENT_READY"
    CAPABILITY_REQUESTED = "CAPABILITY_REQUESTED"
    AUTHORIZATION_REQUESTED = "AUTHORIZATION_REQUESTED"
    AUTHORIZATION_GRANTED = "AUTHORIZATION_GRANTED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    EXECUTION_SCHEDULED = "EXECUTION_SCHEDULED"
    EXECUTION_STARTED = "EXECUTION_STARTED"
    EXECUTION_COMPLETED = "EXECUTION_COMPLETED"
    EXECUTION_FAILED = "EXECUTION_FAILED"
    EXECUTION_DEFERRED = "EXECUTION_DEFERRED"
    EVIDENCE_PRODUCED = "EVIDENCE_PRODUCED"
    EVIDENCE_NORMALIZED = "EVIDENCE_NORMALIZED"
    SPECIALIST_RESULT_RECEIVED = "SPECIALIST_RESULT_RECEIVED"
    PLAN_CREATED = "PLAN_CREATED"
    PLAN_REJECTED = "PLAN_REJECTED"
    PLAN_COMPLETED = "PLAN_COMPLETED"
    SNAPSHOT_CAPTURED = "SNAPSHOT_CAPTURED"
    RECOVERY_REQUESTED = "RECOVERY_REQUESTED"
    INVESTIGATION_PAUSED = "INVESTIGATION_PAUSED"
    INVESTIGATION_RESUMED = "INVESTIGATION_RESUMED"
    INVESTIGATION_COMPLETED = "INVESTIGATION_COMPLETED"
    INVESTIGATION_FAILED = "INVESTIGATION_FAILED"
    TASK_QUEUED = "TASK_QUEUED"
    TASK_CLAIMED = "TASK_CLAIMED"
    TASK_TIMED_OUT = "TASK_TIMED_OUT"
    TASK_CANCELLED = "TASK_CANCELLED"


class EventSequenceTracker:
    """Thread-safe monotonic sequence allocator and gap/duplicate detector per investigation."""

    def __init__(self, investigation_id: str, start_sequence: int = 0) -> None:
        self.investigation_id = investigation_id
        self._current_sequence = start_sequence
        self._seen_sequences: set[int] = set()
        self._lock = threading.Lock()

    @property
    def current_sequence(self) -> int:
        with self._lock:
            return self._current_sequence

    def next_sequence(self) -> int:
        """Allocate the next monotonically increasing sequence number."""
        with self._lock:
            self._current_sequence += 1
            self._seen_sequences.add(self._current_sequence)
            return self._current_sequence

    def register_existing_sequence(self, sequence: int) -> None:
        """Register a replayed or recovered sequence, validating strict monotonicity."""
        with self._lock:
            if sequence in self._seen_sequences:
                raise DuplicateEventError(
                    f"Duplicate sequence number {sequence} detected for investigation '{self.investigation_id}'.",
                    investigation_id=self.investigation_id,
                )
            if sequence < self._current_sequence:
                raise DuplicateEventError(
                    f"Sequence regression: received sequence {sequence} while current sequence is {self._current_sequence}.",
                    investigation_id=self.investigation_id,
                )
            self._seen_sequences.add(sequence)
            self._current_sequence = max(self._current_sequence, sequence)


class EventFactory:
    """Factory creating validated, immutable RuntimeEvent instances."""

    @staticmethod
    def create_event(
        event_type: RuntimeEventType | str,
        investigation_id: str,
        sequence: int,
        correlation_id: Optional[str] = None,
        causation_id: Optional[str] = None,
        actor: str = "core.system",
        source: str = "runtime",
        payload: Optional[Dict[str, Any]] = None,
        priority: int = 3,
        idempotency_key: str = "",
        is_counterfactual: bool = False,
    ) -> RuntimeEvent:
        """Construct an immutable, sequence-validated RuntimeEvent."""
        evt_type_val = event_type.value if isinstance(event_type, RuntimeEventType) else str(event_type)
        corr_id = correlation_id or investigation_id

        return RuntimeEvent(
            event_type=evt_type_val,
            investigation_id=investigation_id,
            sequence=sequence,
            correlation_id=corr_id,
            causation_id=causation_id,
            actor=actor,
            source=source,
            payload=payload or {},
            priority=priority,
            idempotency_key=idempotency_key,
            is_counterfactual=is_counterfactual,
            created_at=utc_now(),
        )
