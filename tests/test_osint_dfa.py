"""Tests for OSINT Specialist local DFA state management."""

import pytest
from cyberclaw.specialists.osint.dfa.machine import (
    InvalidOSINTTransitionError,
    OSINTDFA,
)
from cyberclaw.specialists.osint.dfa.states import OSINTState


def test_osint_dfa_lifecycle():
    dfa = OSINTDFA(initial_state=OSINTState.INITIALIZE)
    assert dfa.current_state == OSINTState.INITIALIZE

    # INITIALIZE -> READY
    dfa.transition(OSINTState.READY, event="init.complete")
    assert dfa.current_state == OSINTState.READY

    # READY -> TARGET_RECEIVED
    dfa.transition(OSINTState.TARGET_RECEIVED, event="target.received")
    assert dfa.current_state == OSINTState.TARGET_RECEIVED

    # TARGET_RECEIVED -> CLASSIFY
    dfa.transition(OSINTState.CLASSIFY, event="target.classified")
    assert dfa.current_state == OSINTState.CLASSIFY

    # CLASSIFY -> PLAN
    dfa.transition(OSINTState.PLAN, event="plan.established")
    assert dfa.current_state == OSINTState.PLAN

    # PLAN -> COLLECT
    dfa.transition(OSINTState.COLLECT, event="collection.started")
    assert dfa.current_state == OSINTState.COLLECT

    # COLLECT -> CORRELATE
    dfa.transition(OSINTState.CORRELATE, event="correlating.findings")
    assert dfa.current_state == OSINTState.CORRELATE

    # CORRELATE -> VERIFY
    dfa.transition(OSINTState.VERIFY, event="verifying.corroboration")
    assert dfa.current_state == OSINTState.VERIFY

    # VERIFY -> COMPLETE
    dfa.transition(OSINTState.COMPLETE, event="investigation.complete")
    assert dfa.current_state == OSINTState.COMPLETE


def test_osint_dfa_invalid_transition_rejected():
    dfa = OSINTDFA(initial_state=OSINTState.READY)

    # Directly skipping TARGET_RECEIVED, CLASSIFY, PLAN to COMPLETE is illegal
    with pytest.raises(InvalidOSINTTransitionError) as exc_info:
        dfa.transition(OSINTState.COMPLETE, event="premature_completion")

    err = exc_info.value
    assert err.current_state == OSINTState.READY
    assert err.target_state == OSINTState.COMPLETE
    assert "not permitted in OSINT DFA" in err.reason
    assert dfa.current_state == OSINTState.READY


def test_osint_dfa_loopback_for_more_collection():
    dfa = OSINTDFA(initial_state=OSINTState.COLLECT)
    # Loopback from CORRELATE back to COLLECT when pivot target discovered
    dfa.transition(OSINTState.CORRELATE, event="discovered_subdomain")
    dfa.transition(OSINTState.COLLECT, event="collect_subdomain")
    assert dfa.current_state == OSINTState.COLLECT


def test_osint_dfa_guards():
    dfa = OSINTDFA(initial_state=OSINTState.CLASSIFY)

    # Custom local guard: cannot transition to PLAN without classified target type
    def target_type_guard(from_s, to_s, ctx):
        if to_s == OSINTState.PLAN and not ctx.get("target_type"):
            return False, "Target must be classified before planning"
        return True, None

    dfa.add_guard(target_type_guard)

    with pytest.raises(InvalidOSINTTransitionError) as exc:
        dfa.transition(OSINTState.PLAN, event="plan", context={})
    assert "Target must be classified before planning" in str(exc.value)

    dfa.transition(OSINTState.PLAN, event="plan", context={"target_type": "domain"})
    assert dfa.current_state == OSINTState.PLAN
