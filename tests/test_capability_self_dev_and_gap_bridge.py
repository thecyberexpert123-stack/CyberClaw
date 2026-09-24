"""Tests for CapabilityGap integration, capability discovery, and Self-Development bridge boundaries."""

import pytest
from cyberclaw.capabilities.bridge import CapabilityBridge
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import CapabilityGovernanceError
from cyberclaw.capabilities.governance import CapabilityGovernance
from cyberclaw.capabilities.models import (
    CapabilityLifecycleState,
    CapabilityProvenance,
    CapabilityTrustState,
    CapabilityValidationRecord,
)
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.planning.models import CapabilityGap
from cyberclaw.specialists.self_development.evaluation import SkillEvaluation
from cyberclaw.specialists.self_development.maturity import SkillMaturityState
from cyberclaw.specialists.self_development.skill import ExperimentalSkill


def test_capability_gap_discovery_recommendations():
    """Verify discovery correctly identifies matching, unavailable, deprecated, and missing capabilities for a gap."""
    gap = CapabilityGap(
        investigation_id="inv-123",
        target_or_entity="api.corp.internal",
        desired_evidence_type="tls_certificate",
        reason="Need certificate SANs for expansion",
    )

    cap_active = Capability(
        id="capability.osint.tls_certificate",
        name="TLS Cert Scanner",
        description="Inspects tls_certificate records",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
    )
    cap_disabled = Capability(
        id="capability.network.tls_certificate_probe",
        name="Network TLS Probe",
        description="Active tls_certificate probe",
        lifecycle_state=CapabilityLifecycleState.DISABLED,
    )

    # 1. Matching available capability exists
    res_avail = CapabilityGovernance.discover_capabilities_for_gap(gap, [cap_active])
    assert res_avail.recommendation == "USE_EXISTING_CAPABILITY"
    assert cap_active.versioned_id in res_avail.matching_available_capabilities

    # 2. Matching capability exists but is disabled
    res_unavail = CapabilityGovernance.discover_capabilities_for_gap(gap, [cap_disabled])
    assert res_unavail.recommendation == "REVALIDATE_OR_ENABLE_CAPABILITY"
    assert cap_disabled.versioned_id in res_unavail.matching_unavailable_capabilities

    # 3. No matching capability exists
    res_none = CapabilityGovernance.discover_capabilities_for_gap(gap, [])
    assert res_none.recommendation == "PROPOSE_CAPABILITY_CANDIDATE"


def test_self_dev_experimental_skill_to_capability_bridge():
    """Verify that ExperimentalSkill transitions through Candidate -> Validation -> Approval without self-approval."""
    # 1. Create ExperimentalSkill
    skill = ExperimentalSkill(
        skill_id="skill_domain_fingerprint",
        purpose="Fingerprint CMS from HTML metadata",
        hypothesis="Identifies target CMS in 80% of probes",
        author_origin="specialist.osint",
        maturity=SkillMaturityState.EVALUATED,
    )

    # 2. Evaluation with PROPOSE_PROMOTION
    eval_rec = SkillEvaluation(
        experiment_id="exp-001",
        skill_id=skill.skill_id,
        baseline_metrics={"latency_ms": 100},
        experimental_metrics={"latency_ms": 70},
        differences={"latency_diff_ms": -30},
        observed_benefits=["30% latency reduction"],
        recommendation="PROPOSE_PROMOTION",
    )

    # 3. Bridge generates candidate
    candidate = CapabilityBridge.candidate_from_experimental_skill(skill, eval_rec)
    assert candidate.capability_id == f"capability.skill.{skill.skill_id}"
    assert candidate.provenance == CapabilityProvenance.PROMOTED_SKILL

    # 4. Materialize into PROPOSED capability
    cap = CapabilityBridge.realize_candidate(candidate)
    assert cap.lifecycle_state == CapabilityLifecycleState.PROPOSED
    assert cap.trust_state == CapabilityTrustState.UNTRUSTED

    # 5. Direct approval without validation must be rejected
    with pytest.raises(CapabilityGovernanceError):
        CapabilityGovernance.approve_capability(
            capability=cap,
            approver="admin",
            rationale="Trying to bypass validation",
        )

    # 6. Formal validation assessment
    val_rec = CapabilityValidationRecord(
        capability_id=cap.id,
        capability_version=cap.version,
        validator="qa.specialist_auditor",
        tests_performed=["schema_validation", "sandbox_test"],
        result="PASSED",
    )
    CapabilityGovernance.validate_capability(cap, val_rec, actor="qa.specialist_auditor")
    assert cap.lifecycle_state == CapabilityLifecycleState.VALIDATED

    # 7. Explicit approval by authorized authority
    gov_rec = CapabilityGovernance.approve_capability(
        capability=cap,
        approver="chief_security_officer",
        rationale="Passed automated validation and manual review",
        target_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    assert cap.lifecycle_state == CapabilityLifecycleState.AVAILABLE
    assert cap.trust_state == CapabilityTrustState.TRUSTED_WITH_SCOPE
    assert gov_rec.actor == "chief_security_officer"


def test_unevaluated_experimental_skill_cannot_become_candidate():
    """Verify that an ExperimentalSkill that has not passed evaluation raises CapabilityGovernanceError."""
    skill = ExperimentalSkill(
        skill_id="skill_untested",
        purpose="Untested dangerous tool",
        hypothesis="Untested",
        author_origin="specialist.osint",
        maturity=SkillMaturityState.EXPERIMENTAL,  # Not EVALUATED!
    )
    eval_rec = SkillEvaluation(
        experiment_id="exp-002",
        skill_id=skill.skill_id,
        baseline_metrics={"accuracy": 0.9},
        experimental_metrics={"accuracy": 0.2},
        differences={"accuracy_diff": -0.7},
        recommendation="REJECT",
    )

    with pytest.raises(CapabilityGovernanceError):
        CapabilityBridge.candidate_from_experimental_skill(skill, eval_rec)
