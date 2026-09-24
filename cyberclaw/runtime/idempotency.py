"""Stable task identity, idempotency evaluation, and duplicate execution prevention."""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any, Dict, Optional, Tuple
from cyberclaw.runtime.models import RuntimeEvent, RuntimeTask


def compute_task_idempotency_key(
    investigation_id: str,
    capability_id: str,
    capability_version: str = "1.0.0",
    requirement_id: Optional[str] = None,
    provider_id: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> str:
    """Compute a deterministic, stable idempotency key for an executable task."""
    clean_params = parameters or {}
    serialized_params = json.dumps(clean_params, sort_keys=True, default=str)
    param_hash = hashlib.sha256(serialized_params.encode("utf-8")).hexdigest()[:16]

    parts = [
        investigation_id,
        requirement_id or "adhoc",
        capability_id,
        capability_version,
        provider_id or "unassigned",
        param_hash,
    ]
    raw_key = ":".join(parts)
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


class IdempotencyRegistry:
    """Thread-safe registry distinguishing duplicate events, authorizations, and executions."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # event_id -> event metadata
        self._seen_events: Dict[str, Dict[str, Any]] = {}
        # event idempotency_key -> event_id
        self._event_keys: Dict[str, str] = {}
        # task_idempotency_key -> authorization outcome
        self._authorizations: Dict[str, Dict[str, Any]] = {}
        # task_idempotency_key -> execution outcome
        self._executions: Dict[str, Dict[str, Any]] = {}

    def is_duplicate_event(self, event_id: str, idempotency_key: Optional[str] = None) -> bool:
        """Check if this event ID or event idempotency key has already been processed."""
        with self._lock:
            if event_id in self._seen_events:
                return True
            if idempotency_key and idempotency_key in self._event_keys:
                return True
            return False

    def record_event(self, event: RuntimeEvent) -> None:
        """Record an event to prevent duplicate processing."""
        with self._lock:
            self._seen_events[event.event_id] = {
                "event_id": event.event_id,
                "event_type": event.event_type,
                "sequence": event.sequence,
                "investigation_id": event.investigation_id,
                "created_at": event.created_at.isoformat(),
            }
            if event.idempotency_key:
                self._event_keys[event.idempotency_key] = event.event_id

    def get_existing_authorization(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve previously granted authorization for this task identity if available."""
        with self._lock:
            return self._authorizations.get(idempotency_key)

    def record_authorization(self, idempotency_key: str, decision_record: Dict[str, Any]) -> None:
        """Record an authorization decision for this task identity."""
        with self._lock:
            self._authorizations[idempotency_key] = decision_record

    def get_existing_execution(self, idempotency_key: str) -> Optional[Dict[str, Any]]:
        """Check if an execution for this task identity has already completed."""
        with self._lock:
            return self._executions.get(idempotency_key)

    def record_execution(self, idempotency_key: str, execution_result: Dict[str, Any]) -> None:
        """Record a completed execution outcome."""
        with self._lock:
            self._executions[idempotency_key] = execution_result

    def export_state(self) -> Dict[str, Any]:
        """Export serialized registry state for persistence."""
        with self._lock:
            return {
                "seen_events": dict(self._seen_events),
                "event_keys": dict(self._event_keys),
                "authorizations": dict(self._authorizations),
                "executions": dict(self._executions),
            }

    def import_state(self, data: Dict[str, Any]) -> None:
        """Import persisted state for recovery."""
        with self._lock:
            self._seen_events.update(data.get("seen_events", {}))
            self._event_keys.update(data.get("event_keys", {}))
            self._authorizations.update(data.get("authorizations", {}))
            self._executions.update(data.get("executions", {}))
