"""Core states and valid transitions for CyberClaw deterministic state machine."""

from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class CoreState(str, Enum):
    """Generic high-level lifecycle states for CyberClaw Core.

    Domain-specific sub-states belong to local Specialist DFAs, not Core.
    """

    INITIALIZE = "INITIALIZE"
    READY = "READY"
    CLASSIFY = "CLASSIFY"
    INVESTIGATE = "INVESTIGATE"
    VERIFY = "VERIFY"
    RESOLVE = "RESOLVE"
    PAUSED = "PAUSED"
    FAILED = "FAILED"


# Deterministic transition table defining permissible next states
ALLOWED_TRANSITIONS: Dict[CoreState, Set[CoreState]] = {
    CoreState.INITIALIZE: {
        CoreState.READY,
        CoreState.FAILED,
    },
    CoreState.READY: {
        CoreState.CLASSIFY,
        CoreState.INVESTIGATE,
        CoreState.PAUSED,
        CoreState.FAILED,
    },
    CoreState.CLASSIFY: {
        CoreState.INVESTIGATE,
        CoreState.READY,
        CoreState.PAUSED,
        CoreState.FAILED,
    },
    CoreState.INVESTIGATE: {
        CoreState.VERIFY,
        CoreState.CLASSIFY,
        CoreState.PAUSED,
        CoreState.FAILED,
    },
    CoreState.VERIFY: {
        CoreState.RESOLVE,
        CoreState.INVESTIGATE,  # Loop back for more evidence if verification fails
        CoreState.PAUSED,
        CoreState.FAILED,
    },
    CoreState.RESOLVE: {
        CoreState.READY,   # Reopened for further inquiry
        CoreState.PAUSED,  # Archived or held
    },
    CoreState.PAUSED: {
        CoreState.READY,
        CoreState.CLASSIFY,
        CoreState.INVESTIGATE,
        CoreState.VERIFY,
        CoreState.RESOLVE,
        CoreState.FAILED,
    },
    CoreState.FAILED: {
        CoreState.INITIALIZE,  # Full reset
        CoreState.READY,       # Retry / Recovery
    },
}
