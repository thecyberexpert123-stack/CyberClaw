"""Structured error hierarchy for capability lifecycle, trust, and governance."""

from __future__ import annotations


class CapabilityError(Exception):
    """Base exception for capability operations."""

    def __init__(self, message: str, capability_id: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.capability_id = capability_id


class CapabilityNotFoundError(CapabilityError):
    """Raised when a requested capability is not registered."""
    pass


class CapabilityLifecycleError(CapabilityError):
    """Raised when an illegal transition across lifecycle states is attempted."""
    pass


class CapabilityTrustError(CapabilityError):
    """Raised when an unauthorized trust escalation or execution of untrusted capability occurs."""
    pass


class CapabilityPermissionError(CapabilityError):
    """Raised when a capability execution violates permission bounds or action scope."""
    pass


class CapabilityCompatibilityError(CapabilityError):
    """Raised when provider or caller input/output contracts violate capability schema."""
    pass


class CapabilityGovernanceError(CapabilityError):
    """Raised when an unauthorized actor attempts governance modification without required approval."""
    pass


class CapabilityUnavailableError(CapabilityError):
    """Raised when a requested capability is registered but in an unexecutable lifecycle/health state."""
    pass
