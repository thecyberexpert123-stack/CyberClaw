"""Skill maturity lifecycle model for CyberClaw Specialist self-development.

Enforces deterministic transitions:
EXPERIMENTAL -> EVALUATED -> PROPOSED -> APPROVED -> TRUSTED

Transitions must be explicitly verified and approved; an artifact cannot
jump directly from generated to trusted.
"""

from __future__ import annotations

from enum import Enum
from typing import Dict, Set


class SkillMaturityState(str, Enum):
    """Maturity stages for experimental skills and workflows."""

    EXPERIMENTAL = "EXPERIMENTAL"  # Proposed, stored in experimental workspace, unverified
    EVALUATED = "EVALUATED"        # Tested in sandbox, measured against baseline
    PROPOSED = "PROPOSED"          # Promotion proposed with evaluation evidence
    APPROVED = "APPROVED"          # Explicitly approved by policy or human authority
    TRUSTED = "TRUSTED"            # Deployed to trusted specialist catalog
    REJECTED = "REJECTED"          # Failed evaluation or rejected by policy
    ARCHIVED = "ARCHIVED"          # Deprecated or superseded


# Deterministic transition table
ALLOWED_MATURITY_TRANSITIONS: Dict[SkillMaturityState, Set[SkillMaturityState]] = {
    SkillMaturityState.EXPERIMENTAL: {
        SkillMaturityState.EVALUATED,
        SkillMaturityState.REJECTED,
        SkillMaturityState.ARCHIVED,
    },
    SkillMaturityState.EVALUATED: {
        SkillMaturityState.PROPOSED,
        SkillMaturityState.EXPERIMENTAL,  # Additional iterations
        SkillMaturityState.REJECTED,
        SkillMaturityState.ARCHIVED,
    },
    SkillMaturityState.PROPOSED: {
        SkillMaturityState.APPROVED,
        SkillMaturityState.REJECTED,
        SkillMaturityState.ARCHIVED,
    },
    SkillMaturityState.APPROVED: {
        SkillMaturityState.TRUSTED,
        SkillMaturityState.ARCHIVED,
    },
    SkillMaturityState.TRUSTED: {
        SkillMaturityState.ARCHIVED,
    },
    SkillMaturityState.REJECTED: {
        SkillMaturityState.EXPERIMENTAL,  # Rework / retry
        SkillMaturityState.ARCHIVED,
    },
    SkillMaturityState.ARCHIVED: set(),
}


class InvalidMaturityTransitionError(Exception):
    """Raised when an illegal maturity state transition is attempted."""

    def __init__(
        self,
        current_state: SkillMaturityState,
        target_state: SkillMaturityState,
        reason: str,
    ) -> None:
        self.current_state = current_state
        self.target_state = target_state
        self.reason = reason
        super().__init__(
            f"Invalid maturity transition from '{current_state.value}' to '{target_state.value}': {reason}"
        )
