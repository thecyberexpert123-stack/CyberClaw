"""Structured error hierarchy for branch management, lifecycle, and counterfactual analysis."""

from __future__ import annotations


class BranchError(Exception):
    """Base exception for all branching and counterfactual analysis operations."""

    def __init__(self, message: str, branch_id: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.branch_id = branch_id


class BranchNotFoundError(BranchError):
    """Raised when a referenced investigation branch does not exist."""
    pass


class BranchIntegrityError(BranchError):
    """Raised when cryptographic, referential, or structural integrity checks fail on a branch."""
    pass


class BranchLifecycleError(BranchError):
    """Raised when an illegal transition is attempted across branch lifecycle states."""
    pass


class BranchSequenceError(BranchError):
    """Raised when branch-local journal sequences have gaps, duplicates, or non-monotonic ordering."""
    pass


class BranchExecutionBlockedError(BranchError):
    """Raised when an unauthorized real execution attempt occurs within a branch context."""
    pass


class BranchPromotionError(BranchError):
    """Raised when a branch cannot be promoted due to policy, validation, or lifecycle failure."""
    pass
