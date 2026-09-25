"""Failure taxonomy and exception hierarchy for Durable Event-Driven Investigation Runtime v0.1."""

from __future__ import annotations

from typing import Optional


class RuntimeBaseError(Exception):
    """Base exception for all runtime errors."""

    def __init__(self, message: str, task_id: Optional[str] = None, investigation_id: Optional[str] = None) -> None:
        self.message = message
        self.task_id = task_id
        self.investigation_id = investigation_id
        context_str = f" [task={task_id}]" if task_id else ""
        context_str += f" [inv={investigation_id}]" if investigation_id else ""
        super().__init__(f"{message}{context_str}")


class QueueError(RuntimeBaseError):
    """Raised on queue operation failures (enqueue, dequeue, claim, empty violations)."""
    pass


class RuntimeValidationError(RuntimeBaseError):
    """Raised when request payload or task structure violates runtime validation."""
    pass


class RuntimeAuthorizationError(RuntimeBaseError):
    """Raised when policy engine denies authorization for a runtime task."""
    pass


class DispatchError(RuntimeBaseError):
    """Raised when specialist or provider resolution fails."""
    pass


class ProviderExecutionError(RuntimeBaseError):
    """Raised when provider execution encounters an error."""

    def __init__(
        self,
        message: str,
        task_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        is_retryable: bool = False,
    ) -> None:
        super().__init__(message, task_id=task_id, investigation_id=investigation_id)
        self.is_retryable = is_retryable


class RuntimeTimeoutError(RuntimeBaseError):
    """Raised when task execution exceeds its deadline."""
    pass


class RuntimeResultValidationError(RuntimeBaseError):
    """Raised when provider execution result violates structural validity."""
    pass


class EvidenceProcessingError(RuntimeBaseError):
    """Raised when normalization or evidence ingestion fails."""
    pass


class StateTransitionError(RuntimeBaseError):
    """Raised on illegal task lifecycle DFA transitions."""
    pass


class PersistenceError(RuntimeBaseError):
    """Raised on atomic persistence or serialization failures.

    corruption_class distinguishes truncation, schema failure, digest mismatch,
    and missing records. Callers must not treat this as an empty queue.
    """

    def __init__(
        self,
        message: str,
        task_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        corruption_class: str = "UNSPECIFIED",
    ) -> None:
        super().__init__(message, task_id=task_id, investigation_id=investigation_id)
        self.corruption_class = corruption_class


class RecoveryError(RuntimeBaseError):
    """Raised during process restart recovery when durable state cannot be reconciled."""
    pass


class UnknownExecutionStateError(RuntimeBaseError):
    """Raised when execution state cannot be safely determined following crash or timeout."""
    pass


class ConcurrencyConflictError(RuntimeBaseError):
    """Raised when concurrent operations attempt conflicting mutations or claims."""
    pass


class DuplicateEventError(RuntimeBaseError):
    """Raised when duplicate authoritative sequence or event delivery is detected."""
    pass


class DuplicateExecutionError(RuntimeBaseError):
    """Raised when an action is already executed and re-execution is forbidden."""
    pass


class PauseViolationError(RuntimeBaseError):
    """Raised when execution is attempted on a paused investigation."""
    pass


class BranchExecutionBlockedError(RuntimeBaseError):
    """Raised when a counterfactual branch attempts real provider execution."""
    pass
