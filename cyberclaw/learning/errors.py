"""Structured exceptions for cross-case experience and strategy learning.

Learning failures are reported here. Callers must not translate a learning
failure into a mutation of authoritative case, policy, capability, or runtime
state.
"""

from __future__ import annotations

from typing import Any, Dict, Optional


class LearningError(Exception):
    """Base class for learning-subsystem failures."""

    def __init__(self, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class LearningExtractionError(LearningError):
    """Authoritative history could not be read into an experience."""


class LearningValidationError(LearningError):
    """A learned object failed structural validation."""


class ExecutableStrategyRejectedError(LearningValidationError):
    """A strategy contained executable code or a command payload."""


class PatternNotValidatedError(LearningError):
    """A pattern is not eligible to become a strategy proposal."""


class StrategyNotFoundError(LearningError):
    """Registry lookup missed a strategy id or version."""


class PatternNotFoundError(LearningError):
    """Registry lookup missed a pattern id or version."""


class InvalidStrategyTransitionError(LearningError):
    """A lifecycle transition is not permitted from the current state."""


class SelfApprovalError(LearningError):
    """The learning engine or the strategy proposer attempted to approve itself."""


class StrategyGovernanceError(LearningError):
    """A governance gate rejected a strategy operation."""


class LearningThresholdError(LearningError):
    """A threshold policy violated an architectural floor."""


class LearningPersistenceError(LearningError):
    """Learning state could not be saved or loaded."""


class LearningTamperError(LearningPersistenceError):
    """Persisted learning state failed digest verification."""


class BranchExperienceQuarantineError(LearningError):
    """A counterfactual experience was refused entry into authoritative learning."""


class LearningReplayError(LearningError):
    """Historical learning state could not be reconstructed from recorded events."""
