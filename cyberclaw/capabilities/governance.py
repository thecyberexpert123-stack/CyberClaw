"""Governance workflows, validation assessment, trust assignments, and discovery."""

from __future__ import annotations

from typing import List, Optional
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import (
    CapabilityGovernanceError,
    CapabilityLifecycleError,
    CapabilityTrustError,
)
from cyberclaw.capabilities.lifecycle import transition_capability_lifecycle
from cyberclaw.capabilities.models import (
    CapabilityCandidate,
    CapabilityDiscoveryResult,
    CapabilityGovernanceRecord,
    CapabilityLifecycleState,
    CapabilityProvenance,
    CapabilityTrustState,
    CapabilityValidationRecord,
    GovernanceDecisionType,
    utc_now,
)
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import CapabilityGap


class CapabilityGovernance:
    """Manages formal validation, approval gates, trust assignments, and discovery."""

    @classmethod
    def validate_capability(
        cls,
        capability: Capability,
        validation_record: CapabilityValidationRecord,
        actor: str,
    ) -> CapabilityValidationRecord:
        """Apply a formal validation record and advance lifecycle if passed."""
        capability.record_validation(validation_record)

        if validation_record.result == "PASSED":
            if capability.lifecycle_state in (CapabilityLifecycleState.PROPOSED, CapabilityLifecycleState.EXPERIMENTAL):
                transition_capability_lifecycle(
                    capability=capability,
                    target_state=CapabilityLifecycleState.VALIDATED,
                    actor=actor,
                    rationale=f"Validation passed: {validation_record.validation_scope}",
                    decision_type=GovernanceDecisionType.VALIDATE,
                )
        elif validation_record.result == "FAILED":
            if capability.lifecycle_state in (CapabilityLifecycleState.PROPOSED, CapabilityLifecycleState.EXPERIMENTAL):
                transition_capability_lifecycle(
                    capability=capability,
                    target_state=CapabilityLifecycleState.REJECTED,
                    actor=actor,
                    rationale=f"Validation failed: {'; '.join(validation_record.failures)}",
                    decision_type=GovernanceDecisionType.REJECT,
                )
        return validation_record

    @classmethod
    def approve_capability(
        cls,
        capability: Capability,
        approver: str,
        rationale: str,
        target_state: CapabilityLifecycleState = CapabilityLifecycleState.AVAILABLE,
        trust_state: CapabilityTrustState = CapabilityTrustState.TRUSTED_WITH_SCOPE,
        scope: ActionScope = ActionScope.CONSEQUENTIAL,
        approval_reference: Optional[str] = None,
    ) -> CapabilityGovernanceRecord:
        """Formal authority gate approving a validated capability for operational availability."""
        # Enforce validation prerequisite for non-core capabilities
        if capability.provenance != CapabilityProvenance.CORE_REGISTERED:
            has_passed = any(v.result == "PASSED" for v in capability.validation_history)
            if not has_passed and capability.lifecycle_state not in (CapabilityLifecycleState.VALIDATED, CapabilityLifecycleState.AVAILABLE):
                raise CapabilityGovernanceError(
                    f"Cannot approve capability '{capability.versioned_id}' without passing validation record.",
                    capability_id=capability.id,
                )

        # Transition lifecycle
        gov_rec = transition_capability_lifecycle(
            capability=capability,
            target_state=target_state,
            actor=approver,
            rationale=rationale,
            decision_type=GovernanceDecisionType.APPROVE,
            scope=scope,
            approval_reference=approval_reference,
        )

        # Update trust state
        old_trust = capability.trust_state
        capability.trust_state = trust_state
        gov_rec.new_trust_state = trust_state.value
        gov_rec.previous_trust_state = old_trust.value
        capability.updated_at = utc_now()

        return gov_rec

    @classmethod
    def enable_capability(
        cls,
        capability: Capability,
        actor: str,
        rationale: str,
    ) -> CapabilityGovernanceRecord:
        """Re-enable a previously disabled capability."""
        return transition_capability_lifecycle(
            capability=capability,
            target_state=CapabilityLifecycleState.AVAILABLE,
            actor=actor,
            rationale=rationale,
            decision_type=GovernanceDecisionType.ENABLE,
        )

    @classmethod
    def disable_capability(
        cls,
        capability: Capability,
        actor: str,
        rationale: str,
    ) -> CapabilityGovernanceRecord:
        """Temporarily disable an active capability from selection or execution."""
        return transition_capability_lifecycle(
            capability=capability,
            target_state=CapabilityLifecycleState.DISABLED,
            actor=actor,
            rationale=rationale,
            decision_type=GovernanceDecisionType.DISABLE,
        )

    @classmethod
    def deprecate_capability(
        cls,
        capability: Capability,
        actor: str,
        rationale: str,
    ) -> CapabilityGovernanceRecord:
        """Mark a capability as deprecated; prevents new selections while allowing legacy lookups."""
        capability.deprecation_reason = rationale
        return transition_capability_lifecycle(
            capability=capability,
            target_state=CapabilityLifecycleState.DEPRECATED,
            actor=actor,
            rationale=rationale,
            decision_type=GovernanceDecisionType.DEPRECATE,
        )

    @classmethod
    def retire_capability(
        cls,
        capability: Capability,
        actor: str,
        rationale: str,
    ) -> CapabilityGovernanceRecord:
        """Permanently retire a capability from active use while preserving historical queryability."""
        return transition_capability_lifecycle(
            capability=capability,
            target_state=CapabilityLifecycleState.RETIRED,
            actor=actor,
            rationale=rationale,
            decision_type=GovernanceDecisionType.RETIRE,
        )

    @classmethod
    def grant_trust(
        cls,
        capability: Capability,
        target_trust: CapabilityTrustState,
        actor: str,
        rationale: str,
    ) -> CapabilityGovernanceRecord:
        """Explicitly elevate trust tier for a capability."""
        if target_trust == CapabilityTrustState.REVOKED:
            raise CapabilityTrustError("Use revoke_trust to revoke trust.")

        old_trust = capability.trust_state
        capability.trust_state = target_trust
        capability.updated_at = utc_now()

        gov_rec = CapabilityGovernanceRecord(
            capability_id=capability.id,
            capability_version=capability.version,
            decision_type=GovernanceDecisionType.GRANT_TRUST,
            actor=actor,
            rationale=rationale,
            previous_lifecycle_state=capability.lifecycle_state.value,
            new_lifecycle_state=capability.lifecycle_state.value,
            previous_trust_state=old_trust.value,
            new_trust_state=target_trust.value,
        )
        capability.record_governance(gov_rec)
        return gov_rec

    @classmethod
    def revoke_trust(
        cls,
        capability: Capability,
        actor: str,
        rationale: str,
    ) -> CapabilityGovernanceRecord:
        """Revoke trust from a capability, halting all execution."""
        old_trust = capability.trust_state
        capability.trust_state = CapabilityTrustState.REVOKED
        capability.updated_at = utc_now()

        gov_rec = CapabilityGovernanceRecord(
            capability_id=capability.id,
            capability_version=capability.version,
            decision_type=GovernanceDecisionType.REVOKE_TRUST,
            actor=actor,
            rationale=rationale,
            previous_lifecycle_state=capability.lifecycle_state.value,
            new_lifecycle_state=capability.lifecycle_state.value,
            previous_trust_state=old_trust.value,
            new_trust_state=CapabilityTrustState.REVOKED.value,
        )
        capability.record_governance(gov_rec)
        return gov_rec

    @classmethod
    def discover_capabilities_for_gap(
        cls,
        gap: CapabilityGap,
        capabilities: List[Capability],
    ) -> CapabilityDiscoveryResult:
        """Identify matching, disabled, deprecated, or candidate capabilities for an intelligence gap."""
        desired_ev = gap.desired_evidence_type.lower()
        target = gap.target_or_entity.lower()

        available_matches: List[str] = []
        unavailable_matches: List[str] = []
        deprecated_matches: List[str] = []

        for cap in capabilities:
            desc = cap.description.lower()
            cap_id = cap.id.lower()
            # Match heuristics based on capability metadata
            is_match = (
                desired_ev in cap_id
                or desired_ev in desc
                or any(desired_ev in str(out).lower() for out in (cap.output_schema or {}).values())
            )
            if is_match:
                if cap.lifecycle_state in (CapabilityLifecycleState.AVAILABLE, CapabilityLifecycleState.TRUSTED):
                    available_matches.append(cap.versioned_id)
                elif cap.lifecycle_state in (CapabilityLifecycleState.DISABLED, CapabilityLifecycleState.EXPERIMENTAL):
                    unavailable_matches.append(cap.versioned_id)
                elif cap.lifecycle_state == CapabilityLifecycleState.DEPRECATED:
                    deprecated_matches.append(cap.versioned_id)

        rec = "NO_MATCH"
        if available_matches:
            rec = "USE_EXISTING_CAPABILITY"
        elif unavailable_matches:
            rec = "REVALIDATE_OR_ENABLE_CAPABILITY"
        elif deprecated_matches:
            rec = "UPGRADE_DEPRECATED_CAPABILITY"
        else:
            rec = "PROPOSE_CAPABILITY_CANDIDATE"

        return CapabilityDiscoveryResult(
            gap_id=gap.gap_id,
            matching_available_capabilities=available_matches,
            matching_unavailable_capabilities=unavailable_matches,
            matching_deprecated_capabilities=deprecated_matches,
            missing_categories=[gap.desired_evidence_type],
            recommendation=rec,
        )
