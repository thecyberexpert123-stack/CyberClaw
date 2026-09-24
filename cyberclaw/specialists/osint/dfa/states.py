"""OSINT Specialist local DFA states and transition definitions.

The local DFA models the specific investigative lifecycle of an OSINT inquiry:
target classification, capability planning, intelligence collection,
correlation of entities, and verification of findings.
The Core remains unaware of these domain-specific sub-states.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class OSINTState(str, Enum):
    """Local investigation lifecycle states for the OSINT Specialist."""

    INITIALIZE = "INITIALIZE"
    READY = "READY"
    TARGET_RECEIVED = "TARGET_RECEIVED"
    CLASSIFY = "CLASSIFY"
    PLAN = "PLAN"
    COLLECT = "COLLECT"
    CORRELATE = "CORRELATE"
    VERIFY = "VERIFY"
    COMPLETE = "COMPLETE"
    PAUSED = "PAUSED"
    FAILED = "FAILED"


# Deterministic transition table for OSINT Specialist local DFA
OSINT_ALLOWED_TRANSITIONS: Dict[OSINTState, Set[OSINTState]] = {
    OSINTState.INITIALIZE: {
        OSINTState.READY,
        OSINTState.FAILED,
    },
    OSINTState.READY: {
        OSINTState.TARGET_RECEIVED,
        OSINTState.PAUSED,
        OSINTState.FAILED,
    },
    OSINTState.TARGET_RECEIVED: {
        OSINTState.CLASSIFY,
        OSINTState.PLAN,
        OSINTState.COLLECT,
        OSINTState.PAUSED,
        OSINTState.FAILED,
    },
    OSINTState.CLASSIFY: {
        OSINTState.PLAN,
        OSINTState.COLLECT,
        OSINTState.PAUSED,
        OSINTState.FAILED,
    },
    OSINTState.PLAN: {
        OSINTState.COLLECT,
        OSINTState.PAUSED,
        OSINTState.FAILED,
    },
    OSINTState.COLLECT: {
        OSINTState.CORRELATE,
        OSINTState.COLLECT,  # Additional collection rounds
        OSINTState.VERIFY,
        OSINTState.PAUSED,
        OSINTState.FAILED,
    },
    OSINTState.CORRELATE: {
        OSINTState.VERIFY,
        OSINTState.COLLECT,  # Loopback if correlation reveals new required pivots
        OSINTState.PAUSED,
        OSINTState.FAILED,
    },
    OSINTState.VERIFY: {
        OSINTState.COMPLETE,
        OSINTState.COLLECT,  # Loopback if verification indicates insufficient corroboration
        OSINTState.PAUSED,
        OSINTState.FAILED,
    },
    OSINTState.COMPLETE: {
        OSINTState.READY,   # Re-used for new query or reset
        OSINTState.PAUSED,
    },
    OSINTState.PAUSED: {
        OSINTState.READY,
        OSINTState.TARGET_RECEIVED,
        OSINTState.CLASSIFY,
        OSINTState.PLAN,
        OSINTState.COLLECT,
        OSINTState.CORRELATE,
        OSINTState.VERIFY,
        OSINTState.COMPLETE,
        OSINTState.FAILED,
    },
    OSINTState.FAILED: {
        OSINTState.INITIALIZE,  # Full reset
        OSINTState.READY,       # Retry from ready
    },
}
