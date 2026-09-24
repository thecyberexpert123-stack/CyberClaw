"""Tests for Deterministic Finite Automaton (DFA) state management."""

import pytest
from cyberclaw.dfa.machine import CoreDFA, InvalidTransitionError
from cyberclaw.dfa.states import CoreState


def test_dfa_initial_state():
    dfa = CoreDFA(initial_state=CoreState.INITIALIZE)
    assert dfa.current_state == CoreState.INITIALIZE
    assert len(dfa.history) == 0


def test_dfa_valid_transitions():
    dfa = CoreDFA(initial_state=CoreState.INITIALIZE)

    # INITIALIZE -> READY
    dfa.transition(CoreState.READY, event="core.startup")
    assert dfa.current_state == CoreState.READY

    # READY -> INVESTIGATE
    dfa.transition(CoreState.INVESTIGATE, event="action.started")
    assert dfa.current_state == CoreState.INVESTIGATE

    # INVESTIGATE -> VERIFY
    dfa.transition(CoreState.VERIFY, event="evidence.gathered")
    assert dfa.current_state == CoreState.VERIFY

    # VERIFY -> RESOLVE
    dfa.transition(CoreState.RESOLVE, event="findings.verified")
    assert dfa.current_state == CoreState.RESOLVE


def test_dfa_invalid_transition_rejected():
    dfa = CoreDFA(initial_state=CoreState.INITIALIZE)

    # INITIALIZE directly to RESOLVE is illegal
    with pytest.raises(InvalidTransitionError) as exc_info:
        dfa.transition(CoreState.RESOLVE, event="premature_resolve")

    err = exc_info.value
    assert err.current_state == CoreState.INITIALIZE
    assert err.target_state == CoreState.RESOLVE
    assert "not in the allowed transition table" in err.reason

    # State must remain unchanged
    assert dfa.current_state == CoreState.INITIALIZE
    # Transition record should reflect rejected attempt
    assert len(dfa.history) == 1
    assert not dfa.history[0].accepted


def test_dfa_loopback_for_more_evidence():
    dfa = CoreDFA(initial_state=CoreState.READY)
    dfa.transition(CoreState.INVESTIGATE, event="start")
    dfa.transition(CoreState.VERIFY, event="first_batch")

    # Verification finds inconclusive evidence -> loop back to INVESTIGATE
    dfa.transition(CoreState.INVESTIGATE, event="need_more_data")
    assert dfa.current_state == CoreState.INVESTIGATE


def test_dfa_custom_guard_rejection():
    dfa = CoreDFA(initial_state=CoreState.INVESTIGATE)

    # Guard: cannot enter VERIFY without context['evidence_count'] > 0
    def evidence_guard(from_s, to_s, ctx):
        if to_s == CoreState.VERIFY and ctx.get("evidence_count", 0) <= 0:
            return False, "Cannot verify without evidence"
        return True, None

    dfa.add_guard(evidence_guard)

    # Should fail with 0 evidence
    with pytest.raises(InvalidTransitionError) as exc_info:
        dfa.transition(CoreState.VERIFY, event="check", context={"evidence_count": 0})
    assert "Cannot verify without evidence" in str(exc_info.value)

    # Should succeed with positive evidence
    dfa.transition(CoreState.VERIFY, event="check", context={"evidence_count": 3})
    assert dfa.current_state == CoreState.VERIFY
