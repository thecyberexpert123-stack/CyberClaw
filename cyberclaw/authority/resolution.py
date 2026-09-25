"""Capability resolution. Registration is not created here."""

from __future__ import annotations

from typing import Optional

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import CapabilityNotFoundError
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState


_EXECUTABLE_LIFECYCLE = (
    CapabilityLifecycleState.AVAILABLE,
    CapabilityLifecycleState.TRUSTED,
)
_UNTRUSTED = (
    CapabilityTrustState.UNTRUSTED,
    CapabilityTrustState.REVOKED,
)


def require_registered_capability(registry, capability_id: str) -> Capability:
    """Return a registered capability. Never construct one.

    A specialist advertisement, a provider object, or a queued id is not
    registration.
    """
    capability = registry.get_capability(capability_id)
    if capability is None:
        bare_id = capability_id.split("@")[0]
        raise CapabilityNotFoundError(
            f"Capability '{capability_id}' is not registered. "
            "Specialist advertisement and provider presence do not create capability authority.",
            capability_id=bare_id,
        )
    return capability


def execution_boundary(capability: Capability) -> Optional[str]:
    """Return the first failed gate, or None when lifecycle and trust allow execution.

    Order is lifecycle, then trust. Permission and policy are later gates and
    are not decided here.
    """
    if capability.lifecycle_state not in _EXECUTABLE_LIFECYCLE:
        return "NOT_EXECUTABLE"
    if capability.trust_state in _UNTRUSTED:
        return "NOT_TRUSTED"
    return None
