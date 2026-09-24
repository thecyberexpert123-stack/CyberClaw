"""Deterministic lifecycle finite state machine for CyberClaw capabilities."""

from __future__ import annotations

from typing import Dict, Optional, Set
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import CapabilityLifecycleError
from cyberclaw.capabilities.models import (
    CapabilityGovernanceRecord,
    CapabilityLifecycleState,
    GovernanceDecisionType,
    utc_now,
)
from cyberclaw.permissions.policy import ActionScope

ALLOWED_LIFECYCLE_TRANSITIONS: Dict[CapabilityLifecycleState, Set[CapabilityLifecycleState]] = {
    CapabilityLifecycleState.PROPOSED: {
        CapabilityLifecycleState.EXPERIMENTAL,
        CapabilityLifecycleState.VALIDATED,
        CapabilityLifecycleState.REJECTED,
    },
    CapabilityLifecycleState.EXPERIMENTAL: {
        CapabilityLifecycleState.VALIDATED,
        CapabilityLifecycleState.REJECTED,
        CapabilityLifecycleState.DISABLED,
    },
    CapabilityLifecycleState.VALIDATED: {
        CapabilityLifecycleState.AVAILABLE,
        CapabilityLifecycleState.TRUSTED,
        CapabilityLifecycleState.REJECTED,
    },
    CapabilityLifecycleState.AVAILABLE: {
        CapabilityLifecycleState.TRUSTED,
        CapabilityLifecycleState.DISABLED,
        CapabilityLifecycleState.DEPRECATED,
    },
    CapabilityLifecycleState.TRUSTED: {
        CapabilityLifecycleState.DISABLED,
        CapabilityLifecycleState.DEPRECATED,
        CapabilityLifecycleState.AVAILABLE,
    },
    CapabilityLifecycleState.DISABLED: {
        CapabilityLifecycleState.AVAILABLE,
        CapabilityLifecycleState.TRUSTED,
        CapabilityLifecycleState.RETIRED,
        CapabilityLifecycleState.DEPRECATED,
    },
    CapabilityLifecycleState.DEPRECATED: {
        CapabilityLifecycleState.RETIRED,
        CapabilityLifecycleState.DISABLED,
    },
    CapabilityLifecycleState.RETIRED: set(),
    CapabilityLifecycleState.REJECTED: set(),
}


def transition_capability_lifecycle(
    capability: Capability,
    target_state: CapabilityLifecycleState,
    actor: str,
    rationale: str,
    decision_type: Optional[GovernanceDecisionType] = None,
    scope: ActionScope = ActionScope.CONSEQUENTIAL,
    approval_reference: Optional[str] = None,
) -> CapabilityGovernanceRecord:
    """Enforce state machine transition and record immutable governance audit."""
    current_state = capability.lifecycle_state
    if current_state == target_state:
        # Idempotent no-op
        return capability.governance_history[-1] if capability.governance_history else CapabilityGovernanceRecord(
            capability_id=capability.id,
            capability_version=capability.version,
            decision_type=decision_type or GovernanceDecisionType.ENABLE,
            actor=actor,
            rationale=rationale,
            previous_lifecycle_state=current_state.value,
            new_lifecycle_state=target_state.value,
            previous_trust_state=capability.trust_state.value,
            new_trust_state=capability.trust_state.value,
            scope=scope,
            approval_reference=approval_reference,
        )

    allowed = ALLOWED_LIFECYCLE_TRANSITIONS.get(current_state, set())
    if target_state not in allowed:
        raise CapabilityLifecycleError(
            f"Illegal capability transition from '{current_state.value}' to '{target_state.value}'. "
            f"Allowed next states: {[s.value for s in allowed]}",
            capability_id=capability.id,
        )

    # Determine default decision type if not provided
    if decision_type is None:
        if target_state == CapabilityLifecycleState.DISABLED:
            decision_type = GovernanceDecisionType.DISABLE
        elif target_state == CapabilityLifecycleState.AVAILABLE:
            decision_type = GovernanceDecisionType.ENABLE
        elif target_state == CapabilityLifecycleState.DEPRECATED:
            decision_type = GovernanceDecisionType.DEPRECATE
        elif target_state == CapabilityLifecycleState.RETIRED:
            decision_type = GovernanceDecisionType.RETIRE
        elif target_state == CapabilityLifecycleState.REJECTED:
            decision_type = GovernanceDecisionType.REJECT
        elif target_state == CapabilityLifecycleState.TRUSTED:
            decision_type = GovernanceDecisionType.APPROVE
        elif target_state == CapabilityLifecycleState.VALIDATED:
            decision_type = GovernanceDecisionType.VALIDATE
        else:
            decision_type = GovernanceDecisionType.ENABLE

    gov_rec = CapabilityGovernanceRecord(
        capability_id=capability.id,
        capability_version=capability.version,
        decision_type=decision_type,
        actor=actor,
        rationale=rationale,
        previous_lifecycle_state=current_state.value,
        new_lifecycle_state=target_state.value,
        previous_trust_state=capability.trust_state.value,
        new_trust_state=capability.trust_state.value,
        scope=scope,
        approval_reference=approval_reference,
    )

    capability.lifecycle_state = target_state
    capability.updated_at = utc_now()
    capability.record_governance(gov_rec)
    return gov_rec
