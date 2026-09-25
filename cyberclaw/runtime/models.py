"""Domain-neutral data models and enums for Durable Event-Driven Investigation Runtime v0.1."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class TaskStatus(str, Enum):
    """Lifecycle status of a RuntimeTask."""

    CREATED = "CREATED"
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    AUTHORIZED = "AUTHORIZED"
    DISPATCHED = "DISPATCHED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    DEFERRED = "DEFERRED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    RETRY_PENDING = "RETRY_PENDING"

    @property
    def is_terminal(self) -> bool:
        """True if the state cannot transition to any active state except through explicit retry."""
        return self in (
            TaskStatus.COMPLETED,
            TaskStatus.REJECTED,
            TaskStatus.CANCELLED,
            TaskStatus.FAILED,
            TaskStatus.TIMED_OUT,
            TaskStatus.DEFERRED,
        )


class TaskPriority(int, Enum):
    """Task scheduling priority (lower integer = higher scheduling priority)."""

    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4


class CancellationStatus(str, Enum):
    """Fine-grained cancellation status distinguishing request from confirmation."""

    NOT_STARTED = "NOT_STARTED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    RUNNING = "RUNNING"
    CANCELLED = "CANCELLED"
    COMPLETED = "COMPLETED"
    UNKNOWN = "UNKNOWN"


class ExecutionState(str, Enum):
    """Execution progress tracking for crash reconciliation."""

    UNSTARTED = "UNSTARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    UNKNOWN_EXECUTION_STATE = "UNKNOWN_EXECUTION_STATE"


class RetryPolicy(BaseModel):
    """Declarative policy governing task failure retry eligibility."""

    max_retries: int = Field(default=3, ge=0)
    backoff_factor: float = Field(default=1.0, ge=0.0)
    retryable_failure_types: List[str] = Field(
        default_factory=lambda: [
            "PROVIDER_TEMPORARY_FAILURE",
            "TIMEOUT",
            "TRANSIENT_UNAVAILABLE",
            "WORKER_CRASH",
        ]
    )
    non_retryable_failure_types: List[str] = Field(
        default_factory=lambda: [
            "PERMISSION_REJECTION",
            "POLICY_DENIAL",
            "INVALID_SCHEMA",
            "RETIRED_CAPABILITY",
            "REVOKED_CAPABILITY",
            "DESTRUCTIVE_APPROVAL_MISSING",
            "UNKNOWN_EXECUTION_STATE",
        ]
    )

    def is_retryable(self, failure_type: Optional[str], action_scope: str = "reversible") -> bool:
        """Evaluate if failure can be retried. Destructive actions and policy denials are NEVER retryable."""
        if action_scope.lower() in ("destructive", "irreversible"):
            return False
        if not failure_type:
            return False
        if failure_type in self.non_retryable_failure_types:
            return False
        return failure_type in self.retryable_failure_types


class RuntimeEvent(BaseModel):
    """Immutable, versioned runtime event envelope."""

    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str = Field(description="Generic event type identifier")
    event_version: str = Field(default="1.0.0", description="Event schema version")
    investigation_id: str = Field(description="Investigation case correlation identifier")
    causation_id: Optional[str] = Field(default=None, description="Event or task ID that directly caused this event")
    correlation_id: str = Field(description="Root investigation or workflow correlation identifier")
    sequence: int = Field(description="Monotonic per-case sequence index")
    created_at: datetime = Field(default_factory=utc_now)
    actor: str = Field(default="core.system", description="Principal or subsystem originating the event")
    source: str = Field(default="runtime", description="Subsystem component originating the event")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
    payload_schema_version: str = Field(default="1.0.0")
    priority: int = Field(default=3)
    idempotency_key: str = Field(default="", description="Unique idempotency key preventing duplicate event delivery")
    is_counterfactual: bool = Field(default=False, description="Flag for events isolated inside counterfactual branches")


class RuntimeTask(BaseModel):
    """Durable runtime work item encapsulating an executable requirement or capability request."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    task_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    requirement_id: Optional[str] = None
    capability_id: str
    capability_version: str = "1.0.0"
    provider_id: Optional[str] = None
    action_scope: str = "consequential"
    parameters: Dict[str, Any] = Field(default_factory=dict)
    actor: str = "core.system"
    actor_role: str = "analyst"
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.CREATED
    cancellation_status: CancellationStatus = CancellationStatus.NOT_STARTED
    execution_state: ExecutionState = ExecutionState.UNSTARTED
    idempotency_key: str = ""
    causation_id: Optional[str] = None
    correlation_id: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    queued_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    deadline: Optional[datetime] = None
    timeout_seconds: Optional[float] = None
    timeout_reason: Optional[str] = None
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    retry_count: int = 0
    claimed_by_worker: Optional[str] = None
    claim_expires_at: Optional[datetime] = None
    authorization_decision_id: Optional[str] = None
    risk_level: Optional[str] = None
    error: Optional[str] = None
    failure_type: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    is_counterfactual: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RuntimeMetrics(BaseModel):
    """Structured runtime observability metrics."""

    queue_depth: int = 0
    queued_tasks: int = 0
    running_tasks: int = 0
    completed_tasks: int = 0
    failed_tasks: int = 0
    retried_tasks: int = 0
    deferred_tasks: int = 0
    cancelled_tasks: int = 0
    timed_out_tasks: int = 0
    authorization_denials: int = 0
    provider_failures: int = 0
    recovery_events: int = 0
    total_events_processed: int = 0

    @property
    def success_rate(self) -> float:
        total = self.completed_tasks + self.failed_tasks
        if total == 0:
            return 0.0
        return round((self.completed_tasks / total) * 100.0, 2)


class RuntimeObservabilityReport(BaseModel):
    """Observability snapshot capturing runtime health and performance."""

    worker_id: str
    timestamp: datetime = Field(default_factory=utc_now)
    metrics: RuntimeMetrics = Field(default_factory=RuntimeMetrics)
    paused_investigations: List[str] = Field(default_factory=list)
    active_leases: int = 0
