"""Tests for capability identity, versioning, lifecycle transitions, trust states, and governance audit."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import (
    CapabilityError,
    CapabilityGovernanceError,
    CapabilityLifecycleError,
    CapabilityTrustError,
)
from cyberclaw.capabilities.governance import CapabilityGovernance
from cyberclaw.capabilities.lifecycle import transition_capability_lifecycle
from cyberclaw.capabilities.models import (
    CapabilityGovernanceRecord,
    CapabilityLifecycleState,
    CapabilityProvenance,
    CapabilityTrustState,
    CapabilityValidationRecord,
    GovernanceDecisionType,
)
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.permissions.policy import ActionScope


def test_capability_identity_and_versioning():
    """Verify stable capability identity, semantic versioning, and compound versioned_id."""
    cap_v1 = Capability(
        id="capability.network.service_probe",
        name="Network Service Probe",
        version="1.0.0",
        description="Probe network services for open ports",
        provenance=CapabilityProvenance.CORE_REGISTERED,
    )
    cap_v2 = Capability(
        id="capability.network.service_probe",
        name="Network Service Probe",
        version="2.0.0",
        description="Enhanced probe with banner grabbing",
        provenance=CapabilityProvenance.CORE_REGISTERED,
    )

    assert cap_v1.versioned_id == "capability.network.service_probe@1.0.0"
    assert cap_v2.versioned_id == "capability.network.service_probe@2.0.0"
    assert cap_v1.versioned_id != cap_v2.versioned_id

    reg = CapabilityRegistry()
    reg.register_capability(cap_v1)
    reg.register_capability(cap_v2)

    # Retrieval by version
    retrieved_v1 = reg.get_capability("capability.network.service_probe", version="1.0.0")
    retrieved_v2 = reg.get_capability("capability.network.service_probe", version="2.0.0")
    retrieved_compound = reg.get_capability("capability.network.service_probe@1.0.0")

    assert retrieved_v1 is not None and retrieved_v1.version == "1.0.0"
    assert retrieved_v2 is not None and retrieved_v2.version == "2.0.0"
    assert retrieved_compound == retrieved_v1


def test_duplicate_registration_and_version_conflict():
    """Verify registry rejects conflicting duplicate registrations with different configurations."""
    reg = CapabilityRegistry()
    cap_original = Capability(
        id="capability.test",
        name="Original",
        version="1.0.0",
        description="Original description",
    )
    reg.register_capability(cap_original)

    # Attempting to register different configuration under same versioned ID
    cap_conflict = Capability(
        id="capability.test",
        name="Conflicting",
        version="1.0.0",
        description="Different description",
    )

    with pytest.raises(CapabilityError) as exc_info:
        reg.register_capability(cap_conflict, allow_overwrite=False)
    assert "version conflict" in str(exc_info.value).lower()


def test_lifecycle_transitions_and_governance_audit():
    """Verify deterministic lifecycle state transitions and immutable audit recording."""
    cap = Capability.create_proposed(
        id="capability.osint.whois_lookup",
        name="Whois Lookup",
        version="0.1.0",
        provenance=CapabilityProvenance.SPECIALIST_REGISTERED,
    )

    assert cap.lifecycle_state == CapabilityLifecycleState.PROPOSED
    assert cap.trust_state == CapabilityTrustState.UNTRUSTED

    # 1. PROPOSED -> VALIDATED via successful validation
    val_rec = CapabilityValidationRecord(
        capability_id=cap.id,
        capability_version=cap.version,
        validator="ci.automated_test_runner",
        tests_performed=["schema_test", "sandbox_mock_test"],
        result="PASSED",
    )
    CapabilityGovernance.validate_capability(cap, val_rec, actor="ci.automated_test_runner")
    assert cap.lifecycle_state == CapabilityLifecycleState.VALIDATED
    assert len(cap.validation_history) == 1

    # 2. VALIDATED -> AVAILABLE via explicit approval
    gov_rec = CapabilityGovernance.approve_capability(
        capability=cap,
        approver="security.lead",
        rationale="Passed all sandbox and security compliance checks",
        target_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    assert cap.lifecycle_state == CapabilityLifecycleState.AVAILABLE
    assert cap.trust_state == CapabilityTrustState.TRUSTED_WITH_SCOPE
    assert gov_rec.decision_type == GovernanceDecisionType.APPROVE
    assert gov_rec.actor == "security.lead"

    # 3. AVAILABLE -> DISABLED
    CapabilityGovernance.disable_capability(cap, actor="security.ops", rationale="Maintenance window")
    assert cap.lifecycle_state == CapabilityLifecycleState.DISABLED

    # 4. DISABLED -> AVAILABLE
    CapabilityGovernance.enable_capability(cap, actor="security.ops", rationale="Maintenance completed")
    assert cap.lifecycle_state == CapabilityLifecycleState.AVAILABLE

    # 5. AVAILABLE -> DEPRECATED
    CapabilityGovernance.deprecate_capability(cap, actor="arch.committee", rationale="Replaced by whois_v2")
    assert cap.lifecycle_state == CapabilityLifecycleState.DEPRECATED
    assert cap.deprecation_reason == "Replaced by whois_v2"

    # 6. DEPRECATED -> RETIRED
    CapabilityGovernance.retire_capability(cap, actor="arch.committee", rationale="End of lifecycle")
    assert cap.lifecycle_state == CapabilityLifecycleState.RETIRED

    # Verify complete governance audit trail
    assert len(cap.governance_history) >= 5
    decisions = [g.decision_type for g in cap.governance_history]
    assert GovernanceDecisionType.APPROVE in decisions
    assert GovernanceDecisionType.DISABLE in decisions
    assert GovernanceDecisionType.ENABLE in decisions
    assert GovernanceDecisionType.DEPRECATE in decisions
    assert GovernanceDecisionType.RETIRE in decisions


def test_invalid_lifecycle_transitions():
    """Verify that illegal lifecycle jumps raise CapabilityLifecycleError."""
    cap = Capability.create_proposed(
        id="capability.experimental",
        name="Experimental Action",
    )

    # PROPOSED cannot jump directly to RETIRED
    with pytest.raises(CapabilityLifecycleError):
        transition_capability_lifecycle(
            capability=cap,
            target_state=CapabilityLifecycleState.RETIRED,
            actor="admin",
            rationale="Illegal jump",
        )

    # Once RETIRED, no further transitions are permissible
    cap.lifecycle_state = CapabilityLifecycleState.RETIRED
    with pytest.raises(CapabilityLifecycleError):
        transition_capability_lifecycle(
            capability=cap,
            target_state=CapabilityLifecycleState.AVAILABLE,
            actor="admin",
            rationale="Illegal resuscitation",
        )


def test_trust_state_separation_and_revocation():
    """Verify that trust state is decoupled from lifecycle state and can be independently revoked."""
    cap = Capability(
        id="capability.scoped",
        name="Scoped Capability",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.PROVISIONAL,
    )

    # Elevation to TRUSTED_WITH_SCOPE
    CapabilityGovernance.grant_trust(
        capability=cap,
        target_trust=CapabilityTrustState.TRUSTED_WITH_SCOPE,
        actor="governance.board",
        rationale="Approved after 30 days provisional operation",
    )
    assert cap.trust_state == CapabilityTrustState.TRUSTED_WITH_SCOPE

    # Revocation of trust
    CapabilityGovernance.revoke_trust(
        capability=cap,
        actor="secops.incident_response",
        rationale="Vulnerability detected in third-party library",
    )
    assert cap.trust_state == CapabilityTrustState.REVOKED
    # Lifecycle may still be AVAILABLE, but execution is blocked
    executable, reason = cap.is_executable()
    assert executable is False
    assert "revoked" in str(reason).lower()
