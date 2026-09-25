"""Failures of the chaos framework itself. These are not case-state mutations."""

from __future__ import annotations

from typing import Any, Dict, Optional


class ChaosError(Exception):
    """Base error for controlled architectural validation."""

    def __init__(self, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class ChaosSecurityError(ChaosError):
    """The chaos framework refused an unsafe fault or payload."""


class ChaosScenarioError(ChaosError):
    """A scenario could not be executed as specified."""
