"""Tests for planning models, candidate definitions, and uncertainty categories."""

import pytest
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import (
    CapabilityGap,
    InformationValueDimension,
    InvestigationPlan,
    PlanStatus,
    RequirementCandidate,
    StoppingCondition,
    UncertaintyType,
)


def test_uncertainty_and_value_dimensions():
    """Verify uncertainty types and value dimensions are well-defined enums."""
    assert UncertaintyType.UNKNOWN.value == "UNKNOWN"
    assert UncertaintyType.CONTRADICTED.value == "CONTRADICTED"
    assert UncertaintyType.INCOMPLETE.value == "INCOMPLETE"

    assert InformationValueDimension.HYPOTHESIS_SUPPORT.value == "hypothesis_support"
    assert InformationValueDimension.HYPOTHESIS_DISCONFIRMATION.value == "hypothesis_disconfirmation"
    assert InformationValueDimension.CONTRADICTION_RESOLUTION.value == "contradiction_resolution"
    assert InformationValueDimension.ENTITY_ENRICHMENT.value == "entity_enrichment"


def test_requirement_candidate_deduplication_key():
    """Verify candidate deduplication key format is deterministic."""
    cand = RequirementCandidate(
        target_or_entity="example.com",
        requested_evidence_types=["osint.dns_record", "osint.certificate"],
        required_capability="osint.cert_metadata",
        purpose="Retrieve certificate metadata",
        value_dimension=InformationValueDimension.MISSING_EVIDENCE,
        uncertainty_type=UncertaintyType.UNKNOWN,
    )
    key = cand.deduplication_key("inv-123")
    assert key == "inv-123:example.com:osint.certificate,osint.dns_record:osint.cert_metadata"


def test_capability_gap_model():
    """Verify CapabilityGap records missing intelligence needs."""
    gap = CapabilityGap(
        investigation_id="inv-999",
        target_or_entity="10.0.0.1",
        desired_evidence_type="network.port_scan",
        reason="No authorized port scanner registered",
    )
    assert gap.investigation_id == "inv-999"
    assert gap.target_or_entity == "10.0.0.1"
    assert gap.desired_evidence_type == "network.port_scan"
    assert "No authorized port scanner" in gap.reason


def test_investigation_plan_defaults_and_status():
    """Verify InvestigationPlan initialization and lifecycle status."""
    cand = RequirementCandidate(
        target_or_entity="192.168.1.1",
        purpose="Enrich IP context",
        value_dimension=InformationValueDimension.ENTITY_ENRICHMENT,
        uncertainty_type=UncertaintyType.INCOMPLETE,
    )
    plan = InvestigationPlan(
        investigation_id="inv-001",
        current_investigation_state="ACTIVE",
        candidate_next_requirements=[cand],
        reasoning_basis="Discovered IP without active port information",
        plan_status=PlanStatus.GENERATED,
    )
    assert plan.investigation_id == "inv-001"
    assert len(plan.candidate_next_requirements) == 1
    assert plan.plan_status == PlanStatus.GENERATED
    assert plan.stopping_condition is None
