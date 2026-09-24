"""Deterministic local DFA machine for OSINT Specialist investigations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.specialists.osint.dfa.states import OSINT_ALLOWED_TRANSITIONS, OSINTState


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InvalidOSINTTransitionError(Exception):
    """Raised when an illegal local OSINT state transition is attempted."""

    def __init__(
        self,
        current_state: OSINTState,
        target_state: OSINTState,
        event: str,
        reason: str,
    ) -> None:
        self.current_state = current_state
        self.target_state = target_state
        self.event = event
        self.reason = reason
        super().__init__(
            f"Invalid OSINT local transition from '{current_state.value}' to '{target_state.value}' "
            f"via event '{event}': {reason}"
        )


class OSINTTransitionRecord(BaseModel):
    """Audit record capturing an attempted local OSINT transition."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    from_state: OSINTState
    to_state: OSINTState
    event: str
    accepted: bool
    reason: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


OSINTTransitionGuard = Callable[[OSINTState, OSINTState, Dict[str, Any]], Tuple[bool, Optional[str]]]


class OSINTDFA:
    """Local deterministic state machine governing an OSINT investigation."""

    def __init__(
        self,
        initial_state: OSINTState = OSINTState.INITIALIZE,
        allowed_transitions: Optional[Dict[OSINTState, set]] = None,
    ) -> None:
        self._current_state: OSINTState = initial_state
        self._allowed_transitions = allowed_transitions or OSINT_ALLOWED_TRANSITIONS
        self._guards: List[OSINTTransitionGuard] = []
        self._history: List[OSINTTransitionRecord] = []

    @property
    def current_state(self) -> OSINTState:
        return self._current_state

    @property
    def history(self) -> List[OSINTTransitionRecord]:
        return list(self._history)

    def add_guard(self, guard: OSINTTransitionGuard) -> None:
        self._guards.append(guard)

    def can_transition(
        self,
        target_state: OSINTState,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        if target_state not in self._allowed_transitions.get(self._current_state, set()):
            return False, f"Transition from {self._current_state.value} to {target_state.value} is not permitted in OSINT DFA."

        ctx = context or {}
        for guard in self._guards:
            allowed, reason = guard(self._current_state, target_state, ctx)
            if not allowed:
                return False, reason or "Rejected by OSINT local transition guard."

        return True, None

    def transition(
        self,
        target_state: OSINTState,
        event: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> OSINTState:
        ctx = context or {}
        allowed, reason = self.can_transition(target_state, ctx)

        record = OSINTTransitionRecord(
            from_state=self._current_state,
            to_state=target_state,
            event=event,
            accepted=allowed,
            reason=reason if not allowed else None,
            context=ctx,
        )
        self._history.append(record)

        if not allowed:
            raise InvalidOSINTTransitionError(
                current_state=self._current_state,
                target_state=target_state,
                event=event,
                reason=reason or "Transition disallowed in OSINT DFA.",
            )

        self._current_state = target_state
        return self._current_state
