"""Validation error definitions for CyberClaw Core."""

from __future__ import annotations


class ValidationError(Exception):
    """Base class for validation failures."""
    pass


class SchemaValidationError(ValidationError):
    """Raised when parameters fail capability or data schema requirements."""
    pass


class PolicyValidationError(ValidationError):
    """Raised when request violates permission or security boundary policy."""
    pass


class StateValidationError(ValidationError):
    """Raised when request cannot execute in current DFA state."""
    pass


class ResultValidationError(ValidationError):
    """Raised when execution result fails structural integrity checks."""
    pass
