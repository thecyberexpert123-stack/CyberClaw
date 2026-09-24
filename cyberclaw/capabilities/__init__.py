"""Capabilities package providing capability definitions, providers, registry, and governance."""

from cyberclaw.capabilities.bridge import CapabilityBridge
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import (
    CapabilityCompatibilityError,
    CapabilityError,
    CapabilityGovernanceError,
    CapabilityLifecycleError,
    CapabilityNotFoundError,
    CapabilityPermissionError,
    CapabilityTrustError,
    CapabilityUnavailableError,
)
from cyberclaw.capabilities.governance import CapabilityGovernance
from cyberclaw.capabilities.lifecycle import (
    ALLOWED_LIFECYCLE_TRANSITIONS,
    transition_capability_lifecycle,
)
from cyberclaw.capabilities.models import (
    CapabilityCandidate,
    CapabilityDiscoveryResult,
    CapabilityFailureRecord,
    CapabilityFailureType,
    CapabilityGovernanceRecord,
    CapabilityHealth,
    CapabilityLifecycleState,
    CapabilityProvenance,
    CapabilityTrustState,
    CapabilityValidationRecord,
    GovernanceDecisionType,
)
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry

__all__ = [
    "Capability",
    "CapabilityProvider",
    "ExecutionContext",
    "CapabilityRegistry",
    "CapabilityLifecycleState",
    "CapabilityTrustState",
    "CapabilityHealth",
    "CapabilityProvenance",
    "CapabilityFailureType",
    "GovernanceDecisionType",
    "CapabilityValidationRecord",
    "CapabilityFailureRecord",
    "CapabilityGovernanceRecord",
    "CapabilityCandidate",
    "CapabilityDiscoveryResult",
    "CapabilityBridge",
    "CapabilityGovernance",
    "ALLOWED_LIFECYCLE_TRANSITIONS",
    "transition_capability_lifecycle",
    "CapabilityError",
    "CapabilityNotFoundError",
    "CapabilityLifecycleError",
    "CapabilityTrustError",
    "CapabilityPermissionError",
    "CapabilityCompatibilityError",
    "CapabilityGovernanceError",
    "CapabilityUnavailableError",
]
