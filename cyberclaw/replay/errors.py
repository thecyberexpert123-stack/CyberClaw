"""Structured error classes for the Investigation Replay subsystem."""

from __future__ import annotations


class ReplayError(Exception):
    """Base exception for investigation replay errors."""
    pass


class ReplayIntegrityError(ReplayError):
    """Raised when historical integrity checks (e.g. SHA-256 digest verification) fail."""
    pass


class ReplaySequenceError(ReplayError):
    """Raised when sequence ordering violations (e.g. gaps, duplicates) are detected."""
    pass


class CorruptedHistoryError(ReplayError):
    """Raised when historical records contain malformed structures, impossible transitions, or missing references."""
    pass


class ReplayBoundsError(ReplayError):
    """Raised when a replay target sequence is invalid or out of chronological range."""
    pass
