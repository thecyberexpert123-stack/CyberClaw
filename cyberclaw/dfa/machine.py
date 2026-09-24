"""Deterministic Finite Automaton (DFA) engine for CyberClaw Core.

Enforces deterministic transitions, evaluates transition guards, logs transition
audit records, and strictly rejects unauthorized or invalid state mutations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.dfa.states import ALLOWED_TRANSITIONS, CoreState


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class InvalidTransitionError(Exception):
    """Raised when an illegal state transition is attempted."""

    def __init__(
        self,
        current_state: CoreState,
        target_state: CoreState,
        event: str,
        reason: str,
    ) -> None:
        self.current_state = current_state
        self.target_state = target_state
        self.event = event
        self.reason = reason
        super().__init__(
            f"Invalid transition from '{current_state.value}' to '{target_state.value}' "
            f"via event '{event}': {reason}"
        )


class TransitionRecord(BaseModel):
    """Audit record capturing every requested state transition."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=utc_now)
    from_state: CoreState
    to_state: CoreState
    event: str
    accepted: bool
    reason: Optional[str] = None
    context: Dict[str, Any] = Field(default_factory=dict)


# Guard signature: takes context dict, returns (allowed: bool, rejection_reason: Optional[str])
TransitionGuard = Callable[[CoreState, CoreState, Dict[str, Any]], Tuple[bool, Optional[str]]]


class CoreDFA:
    """Deterministic state machine governing Core and Investigation state transitions."""

    def __init__(
        self,
        initial_state: CoreState = CoreState.INITIALIZE,
        allowed_transitions: Optional[Dict[CoreState, Set[CoreState]]] = None,
    ) -> None:
        self._current_state: CoreState = initial_state
        self._allowed_transitions: Dict[CoreState, Set[CoreState]] = (
            allowed_transitions if allowed_transitions is not None else ALLOWED_TRANSITIONS
        )
        self._guards: List[TransitionGuard] = []
        self._history: List[TransitionRecord] = []

    @property
    def current_state(self) -> CoreState:
        """The current deterministic state of the machine."""
        return self._current_state

    @property
    def history(self) -> List[TransitionRecord]:
        """Complete history of transition attempts."""
        return list(self._history)

    def add_guard(self, guard: TransitionGuard) -> None:
        """Register a transition guard function."""
        self._guards.append(guard)

    def can_transition(
        self,
        target_state: CoreState,
        context: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Check whether a transition to target_state is permitted without executing it."""
        if target_state not in self._allowed_transitions.get(self._current_state, set()):
            return False, f"Transition from {self._current_state.value} to {target_state.value} is not in the allowed transition table."

        ctx = context or {}
        for guard in self._guards:
            allowed, reason = guard(self._current_state, target_state, ctx)
            if not allowed:
                return False, reason or "Rejected by transition guard policy."

        return True, None

    def transition(
        self,
        target_state: CoreState,
        event: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> CoreState:
        """Execute a state transition. Rejects invalid transitions deterministically."""
        ctx = context or {}
        allowed, reason = self.can_transition(target_state, ctx)

        record = TransitionRecord(
            from_state=self._current_state,
            to_state=target_state,
            event=event,
            accepted=allowed,
            reason=reason if not allowed else None,
            context=ctx,
        )
        self._history.append(record)

        if not allowed:
            raise InvalidTransitionError(
                current_state=self._current_state,
                target_state=target_state,
                event=event,
                reason=reason or "Transition disallowed.",
            )

        self._current_state = target_state
        return self._current_state
