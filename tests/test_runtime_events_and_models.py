"""Tests for RuntimeEvent models, immutability, sequence tracking, and causation chains."""

from __future__ import annotations

from datetime import datetime
import pytest

from cyberclaw.runtime.errors import DuplicateEventError
from cyberclaw.runtime.events import EventFactory, EventSequenceTracker, RuntimeEventType
from cyberclaw.runtime.models import (
    CancellationStatus,
    ExecutionState,
    RetryPolicy,
    RuntimeEvent,
    RuntimeMetrics,
    RuntimeTask,
    TaskPriority,
    TaskStatus,
)


def test_runtime_event_model_fields_and_envelope():
    """Verify all mandatory fields of RuntimeEvent are populated correctly."""
    evt = EventFactory.create_event(
        event_type=RuntimeEventType.INVESTIGATION_STARTED,
        investigation_id="inv-evt-01",
        sequence=1,
        correlation_id="inv-evt-01",
        causation_id=None,
        actor="lead.analyst",
        source="core",
        payload={"title": "Test Case"},
        priority=1,
        idempotency_key="idemp-01",
    )
    assert evt.event_id is not None
    assert evt.event_type == RuntimeEventType.INVESTIGATION_STARTED.value
    assert evt.sequence == 1
    assert evt.actor == "lead.analyst"
    assert evt.source == "core"
    assert evt.payload == {"title": "Test Case"}
    assert evt.is_counterfactual is False
    assert isinstance(evt.created_at, datetime)


def test_runtime_event_immutability():
    """Verify that RuntimeEvent cannot be mutated after creation (frozen)."""
    evt = EventFactory.create_event(
        event_type=RuntimeEventType.REQUIREMENT_CREATED,
        investigation_id="inv-evt-02",
        sequence=2,
    )
    with pytest.raises(Exception):
        evt.sequence = 999  # Frozen model violation


def test_event_sequence_tracker_strict_monotonicity():
    """Verify sequence tracker allocates strict monotonically increasing sequence numbers."""
    tracker = EventSequenceTracker(investigation_id="inv-seq-01")
    s1 = tracker.next_sequence()
    s2 = tracker.next_sequence()
    s3 = tracker.next_sequence()

    assert s1 == 1
    assert s2 == 2
    assert s3 == 3
    assert tracker.current_sequence == 3


def test_event_sequence_tracker_rejects_duplicates_and_regression():
    """Verify sequence tracker rejects duplicate sequence numbers and sequence regressions."""
    tracker = EventSequenceTracker(investigation_id="inv-seq-02")
    tracker.register_existing_sequence(5)

    # Duplicate sequence must be rejected
    with pytest.raises(DuplicateEventError) as exc_dup:
        tracker.register_existing_sequence(5)
    assert "Duplicate sequence number 5 detected" in str(exc_dup.value)

    # Sequence regression must be rejected
    with pytest.raises(DuplicateEventError) as exc_reg:
        tracker.register_existing_sequence(3)
    assert "Sequence regression" in str(exc_reg.value)


def test_causation_and_correlation_chaining():
    """Verify causation_id chains accurately model the sequence of causality."""
    e1 = EventFactory.create_event(
        event_type=RuntimeEventType.PLAN_CREATED,
        investigation_id="inv-caus-01",
        sequence=1,
    )
    e2 = EventFactory.create_event(
        event_type=RuntimeEventType.REQUIREMENT_CREATED,
        investigation_id="inv-caus-01",
        sequence=2,
        causation_id=e1.event_id,
        correlation_id=e1.correlation_id,
    )
    e3 = EventFactory.create_event(
        event_type=RuntimeEventType.CAPABILITY_REQUESTED,
        investigation_id="inv-caus-01",
        sequence=3,
        causation_id=e2.event_id,
        correlation_id=e1.correlation_id,
    )

    assert e2.causation_id == e1.event_id
    assert e3.causation_id == e2.event_id
    assert e3.correlation_id == e1.correlation_id


def test_runtime_task_model_defaults_and_fields():
    """Verify RuntimeTask default values, statuses, and retry policies."""
    task = RuntimeTask(
        investigation_id="inv-task-01",
        capability_id="tool.dns",
        parameters={"domain": "example.com"},
    )
    assert task.status == TaskStatus.CREATED
    assert task.cancellation_status == CancellationStatus.NOT_STARTED
    assert task.execution_state == ExecutionState.UNSTARTED
    assert task.priority == TaskPriority.NORMAL
    assert task.retry_count == 0
    assert task.retry_policy.max_retries == 3
    assert task.is_counterfactual is False
