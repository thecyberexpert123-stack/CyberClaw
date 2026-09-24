"""Structured observability for CyberClaw Core.

Provides structured event/operation logging to enable complete auditability,
traceability, and root cause analysis across Core and Specialist operations.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ObservabilityRecord(BaseModel):
    """Structured record answering:
    - What happened? (operation, event, message)
    - Why did it happen? (reason, trigger)
    - What state was the system in? (state)
    - What component initiated it? (component)
    - What evidence was produced? (evidence_ids)
    - Why was a transition accepted or rejected? (transition_status, rejection_reason)
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    operation: str = Field(description="Name of operation, e.g., 'capability.execute', 'dfa.transition'")
    component: str = Field(description="Subsystem name, e.g., 'Core', 'DFA', 'SpecialistRegistry'")
    state: Optional[str] = Field(default=None, description="System or DFA state at the time")
    event: Optional[str] = Field(default=None, description="Triggering event")
    correlation_id: Optional[str] = Field(default=None, description="Investigation or trace correlation ID")
    result: Optional[str] = Field(default=None, description="Outcome status: 'success', 'empty', 'failure'")
    reason: Optional[str] = Field(default=None, description="Explanation or intent behind the action")
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of evidence produced or referenced")
    error: Optional[str] = Field(default=None, description="Error message if operation failed")
    duration_ms: Optional[float] = Field(default=None, description="Execution time in milliseconds")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_json(self) -> str:
        return self.model_dump_json()


class StructuredLogger:
    """In-memory and sink-dispatching structured logger for CyberClaw."""

    def __init__(self, sinks: Optional[List[Callable[[ObservabilityRecord], None]]] = None) -> None:
        self._records: List[ObservabilityRecord] = []
        self._sinks: List[Callable[[ObservabilityRecord], None]] = list(sinks or [])

    def add_sink(self, sink: Callable[[ObservabilityRecord], None]) -> None:
        self._sinks.append(sink)

    def record(
        self,
        operation: str,
        component: str,
        *,
        state: Optional[str] = None,
        event: Optional[str] = None,
        correlation_id: Optional[str] = None,
        result: Optional[str] = None,
        reason: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
        error: Optional[str] = None,
        duration_ms: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ObservabilityRecord:
        rec = ObservabilityRecord(
            operation=operation,
            component=component,
            state=state,
            event=event,
            correlation_id=correlation_id,
            result=result,
            reason=reason,
            evidence_ids=evidence_ids or [],
            error=error,
            duration_ms=duration_ms,
            metadata=metadata or {},
        )
        self._records.append(rec)
        for sink in self._sinks:
            try:
                sink(rec)
            except Exception:
                # Observability sinks must not crash the operational path
                pass
        return rec

    def get_records(
        self,
        *,
        correlation_id: Optional[str] = None,
        component: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> List[ObservabilityRecord]:
        """Query stored structured records by correlation_id, component, or operation."""
        results = self._records
        if correlation_id is not None:
            results = [r for r in results if r.correlation_id == correlation_id]
        if component is not None:
            results = [r for r in results if r.component == component]
        if operation is not None:
            results = [r for r in results if r.operation == operation]
        return results

    def clear(self) -> None:
        self._records.clear()
