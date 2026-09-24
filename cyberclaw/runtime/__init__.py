"""Durable Event-Driven Investigation Runtime v0.1 for CyberClaw.

Central Governance Principle:
- AN EVENT REQUESTS WORK.
- THE RUNTIME VALIDATES THE WORK.
- THE DFA AUTHORIZES THE TRANSITION.
- POLICY AUTHORIZES THE ACTION.
- A SPECIALIST PERFORMS THE WORK.
- THE RESULT BECOMES AN EVENT.
- THE CASE RECORD MAKES IT DURABLE.
"""

from __future__ import annotations

from cyberclaw.runtime.dispatcher import SpecialistDispatcher
from cyberclaw.runtime.errors import (
    BranchExecutionBlockedError,
    ConcurrencyConflictError,
    DispatchError,
    DuplicateEventError,
    DuplicateExecutionError,
    EvidenceProcessingError,
    PauseViolationError,
    PersistenceError,
    ProviderExecutionError,
    QueueError,
    RecoveryError,
    RuntimeAuthorizationError,
    RuntimeBaseError,
    RuntimeResultValidationError,
    RuntimeTimeoutError,
    RuntimeValidationError,
    StateTransitionError,
    UnknownExecutionStateError,
)
from cyberclaw.runtime.events import (
    EventFactory,
    EventSequenceTracker,
    RuntimeEventType,
)
from cyberclaw.runtime.executor import RuntimeExecutor
from cyberclaw.runtime.idempotency import (
    IdempotencyRegistry,
    compute_task_idempotency_key,
)
from cyberclaw.runtime.models import (
    CancellationStatus,
    ExecutionState,
    RetryPolicy,
    RuntimeEvent,
    RuntimeMetrics,
    RuntimeObservabilityReport,
    RuntimeTask,
    TaskPriority,
    TaskStatus,
)
from cyberclaw.runtime.persistence import RuntimePersistenceManager
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.recovery import RecoveryReport, RuntimeRecoveryManager
from cyberclaw.runtime.scheduler import RuntimeScheduler
from cyberclaw.runtime.state import (
    VALID_TASK_TRANSITIONS,
    TaskLifecycleDFA,
)

__all__ = [
    "RuntimeEvent",
    "RuntimeTask",
    "TaskStatus",
    "TaskPriority",
    "CancellationStatus",
    "ExecutionState",
    "RetryPolicy",
    "RuntimeMetrics",
    "RuntimeObservabilityReport",
    "RuntimeEventType",
    "EventSequenceTracker",
    "EventFactory",
    "DurableTaskQueue",
    "compute_task_idempotency_key",
    "IdempotencyRegistry",
    "TaskLifecycleDFA",
    "VALID_TASK_TRANSITIONS",
    "SpecialistDispatcher",
    "RuntimeExecutor",
    "RuntimeScheduler",
    "RuntimeRecoveryManager",
    "RecoveryReport",
    "RuntimePersistenceManager",
    "RuntimeBaseError",
    "QueueError",
    "RuntimeValidationError",
    "RuntimeAuthorizationError",
    "DispatchError",
    "ProviderExecutionError",
    "RuntimeTimeoutError",
    "RuntimeResultValidationError",
    "EvidenceProcessingError",
    "StateTransitionError",
    "PersistenceError",
    "RecoveryError",
    "UnknownExecutionStateError",
    "ConcurrencyConflictError",
    "DuplicateEventError",
    "DuplicateExecutionError",
    "PauseViolationError",
    "BranchExecutionBlockedError",
]
