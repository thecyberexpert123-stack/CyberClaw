"""Tests for PlanValidator ensuring strict structural, capability, permission, and safety gates."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.investigation import Investigation
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import (
    InformationValueDimension,
    InvestigationPlan,
    PlanStatus,
    RequirementCandidate,
    UncertaintyType,
)
from cyberclaw.planning.validator import PlanValidator
from cyberclaw.specialists.registry import SpecialistRegistry


@pytest.fixture
def test_setup():
    inv = Investigation(id="inv-test-val", title="Validation Test", targets=["example.com"])
    specialists = SpecialistRegistry()
    capabilities = CapabilityRegistry()
    permissions = PermissionManager()
    return inv, specialists, capabilities, permissions


def test_validator_structural_checks(test_setup):
    """Verify structural validation fails if target or evidence types are absent or invalid refs exist."""
    inv, specs, caps, perms = test_setup

    # Candidate with missing target
    cand_missing_target = RequirementCandidate(
        target_or_entity="",
        purpose="Missing target purpose",
        value_dimension=InformationValueDimension.MISSING_EVIDENCE,
        uncertainty_type=UncertaintyType.UNKNOWN,
    )
    res = PlanValidator.validate_candidate(cand_missing_target, inv, specs, caps, perms)
    assert not res.is_valid
    assert not res.structural_valid
    assert any("Missing target_or_entity" in r for r in res.rejection_reasons)

    # Candidate referencing non-existent supporting evidence
    cand_bad_ev = RequirementCandidate(
        target_or_entity="example.com",
        requested_evidence_types=["osint.dns_record"],
        purpose="Corroborate DNS",
        supporting_evidence_ids=["non-existent-ev-id"],
        value_dimension=InformationValueDimension.CORROBORATION,
        uncertainty_type=UncertaintyType.AMBIGUOUS,
    )
    res_ev = PlanValidator.validate_candidate(cand_bad_ev, inv, specs, caps, perms)
    assert not res_ev.is_valid
    assert not res_ev.structural_valid
    assert any("Referenced supporting evidence" in r for r in res_ev.rejection_reasons)


def test_validator_capability_checks(test_setup):
    """Verify capability validation fails if candidate requests unknown capability."""
    inv, specs, caps, perms = test_setup

    cand = RequirementCandidate(
        target_or_entity="example.com",
        requested_evidence_types=["future.quantum_decrypt"],
        required_capability="future.quantum_decrypt",
        purpose="Test capability check",
        value_dimension=InformationValueDimension.MISSING_EVIDENCE,
        uncertainty_type=UncertaintyType.UNKNOWN,
    )
    res = PlanValidator.validate_candidate(cand, inv, specs, caps, perms)
    assert not res.is_valid
    assert not res.capability_valid
    assert any("no registered provider or specialist" in r for r in res.rejection_reasons)


def test_validator_destructive_permission_checks(test_setup):
    """Verify destructive action candidates require explicit authorization."""
    inv, specs, caps, perms = test_setup

    cand = RequirementCandidate(
        target_or_entity="192.168.1.1",
        requested_evidence_types=["network.dos_exploit"],
        purpose="High risk exploit attempt",
        risk_classification=ActionScope.DESTRUCTIVE,
        value_dimension=InformationValueDimension.MISSING_EVIDENCE,
        uncertainty_type=UncertaintyType.UNKNOWN,
    )
    res = PlanValidator.validate_candidate(cand, inv, specs, caps, perms, actor="untrusted.actor")
    assert not res.is_valid
    assert not res.permission_valid
    assert any("DESTRUCTIVE authorization" in r for r in res.rejection_reasons)


def test_validator_safety_patterns(test_setup):
    """Verify candidates containing arbitrary execution strings are rejected by safety filter."""
    inv, specs, caps, perms = test_setup

    cand = RequirementCandidate(
        target_or_entity="; eval('bad code');",
        requested_evidence_types=["osint.dns_record"],
        purpose="Injection test",
        value_dimension=InformationValueDimension.MISSING_EVIDENCE,
        uncertainty_type=UncertaintyType.UNKNOWN,
    )
    res = PlanValidator.validate_candidate(cand, inv, specs, caps, perms)
    assert not res.is_valid
    assert not res.safety_valid
    assert any("forbidden command pattern" in r for r in res.rejection_reasons)
