"""Tests for SkillProposal generation and deterministic validation."""

import pytest
from cyberclaw.specialists.self_development.proposals import SkillProposal
from cyberclaw.specialists.self_development.validation import (
    SkillValidationError,
    SkillValidator,
)


def test_valid_proposal_validation():
    proposal = SkillProposal(
        originating_specialist="osint_specialist",
        intended_objective="Automate combined DNS and Certificate lookup",
        hypothesis="Executing DNS and Cert simultaneously yields 2x evidence without extra overhead",
        proposed_procedure={
            "steps": [
                {"capability_id": "osint.dns_lookup"},
                {"capability_id": "osint.cert_metadata"},
            ]
        },
        expected_benefit="Higher evidence density in initial triage",
        required_capabilities=["osint.dns_lookup", "osint.cert_metadata"],
        required_permissions=["network:read"],
    )

    res = SkillValidator.validate_proposal(
        proposal=proposal,
        specialist_permissions=["network:read"],
        known_capabilities=["osint.dns_lookup", "osint.cert_metadata", "osint.whois_lookup"],
    )
    assert res.is_valid is True
    assert res.structural_valid is True
    assert res.safety_valid is True
    assert res.architectural_valid is True


def test_proposal_missing_fields_rejected():
    proposal = SkillProposal(
        originating_specialist="osint_specialist",
        intended_objective="",  # Empty objective
        hypothesis="",           # Empty hypothesis
        proposed_procedure={},   # Empty procedure
        expected_benefit="",
    )

    res = SkillValidator.validate_proposal(
        proposal=proposal,
        specialist_permissions=["network:read"],
        known_capabilities=["osint.dns_lookup"],
    )
    assert res.is_valid is False
    assert res.structural_valid is False
    assert any("intended_objective" in r for r in res.rejection_reasons)


def test_proposal_unknown_capability_rejected():
    proposal = SkillProposal(
        originating_specialist="osint_specialist",
        intended_objective="Invoke non-existent capability",
        hypothesis="Testing unknown capability",
        proposed_procedure={"steps": [{"capability_id": "unknown.offensive_exploit"}]},
        expected_benefit="",
        required_capabilities=["unknown.offensive_exploit"],
    )

    res = SkillValidator.validate_proposal(
        proposal=proposal,
        specialist_permissions=["network:read"],
        known_capabilities=["osint.dns_lookup"],
    )
    assert res.is_valid is False
    assert any("unknown capability 'unknown.offensive_exploit'" in r for r in res.rejection_reasons)


def test_proposal_exceeding_permissions_rejected():
    proposal = SkillProposal(
        originating_specialist="osint_specialist",
        intended_objective="Privileged network reconfiguration",
        hypothesis="Testing privilege escalation",
        proposed_procedure={"steps": [{"capability_id": "osint.dns_lookup"}]},
        expected_benefit="",
        required_capabilities=["osint.dns_lookup"],
        required_permissions=["system:admin", "raw_socket:write"],  # OSINT only has network:read
    )

    res = SkillValidator.validate_proposal(
        proposal=proposal,
        specialist_permissions=["network:read"],
        known_capabilities=["osint.dns_lookup"],
    )
    assert res.is_valid is False
    assert res.safety_valid is False
    assert any("exceeds specialist authority" in r for r in res.rejection_reasons)


def test_proposal_architectural_bypass_rejected():
    proposal = SkillProposal(
        originating_specialist="osint_specialist",
        intended_objective="Bypass Core DFA",
        hypothesis="Testing architectural evasion",
        proposed_procedure={"steps": [{"capability_id": "osint.dns_lookup", "action": "eval('import os')"}]},
        expected_benefit="",
        required_capabilities=["osint.dns_lookup"],
        required_permissions=["network:read"],
    )

    res = SkillValidator.validate_proposal(
        proposal=proposal,
        specialist_permissions=["network:read"],
        known_capabilities=["osint.dns_lookup"],
    )
    assert res.is_valid is False
    assert res.architectural_valid is False
    assert any("illegally references architectural component" in r for r in res.rejection_reasons)
