"""Tests for deterministic planning rules covering enrichment, contradiction, and hypothesis testing."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.evidence.models import Evidence, Observation, Provenance
from cyberclaw.investigation import Investigation
from cyberclaw.planning.models import (
    InformationValueDimension,
    UncertaintyType,
)
from cyberclaw.planning.planner import DeterministicPlanner
from cyberclaw.planning.rules import (
    ContradictionResolutionPlanningRule,
    EntityEnrichmentPlanningRule,
    HypothesisTestingPlanningRule,
)
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.specialists.registry import SpecialistRegistry


class DummyEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        return SpecialistResponse(specialist_id="dummy", request_id=request.request_id, success=True)


def create_dummy_network_specialist() -> Specialist:
    return Specialist(
        id="specialist.network.scanner",
        name="Network Scanner",
        capabilities=["network.port_scan"],
        endpoint=DummyEndpoint(),
    )


def create_dummy_osint_specialist() -> Specialist:
    return Specialist(
        id="specialist.osint.engine",
        name="OSINT Engine",
        capabilities=["osint.dns_lookup", "osint.cert_metadata", "osint.whois_lookup"],
        endpoint=DummyEndpoint(),
    )


def test_entity_enrichment_rule_with_available_capability():
    """Verify IP entity generates port_scan candidate when network capability is registered."""
    inv = Investigation(id="inv-enrich", title="Enrich Test", targets=["example.com"])
    inv.add_entity("ip", "93.184.216.34")

    specialists = SpecialistRegistry()
    specialists.register_specialist(create_dummy_network_specialist())
    caps = CapabilityRegistry()

    rule = EntityEnrichmentPlanningRule()
    cands, gaps = rule.evaluate(inv, specialists, caps, set())

    assert len(cands) == 1
    assert cands[0].target_or_entity == "93.184.216.34"
    assert cands[0].required_capability == "network.port_scan"
    assert cands[0].value_dimension == InformationValueDimension.ENTITY_ENRICHMENT
    assert len(gaps) == 0


def test_entity_enrichment_rule_missing_capability_produces_gap():
    """Verify IP entity generates CapabilityGap when network capability is unregistered."""
    inv = Investigation(id="inv-gap", title="Gap Test", targets=["example.com"])
    inv.add_entity("ip", "10.0.0.1")

    specialists = SpecialistRegistry()  # No specialists registered
    caps = CapabilityRegistry()

    rule = EntityEnrichmentPlanningRule()
    cands, gaps = rule.evaluate(inv, specialists, caps, set())

    assert len(cands) == 0
    assert len(gaps) == 1
    assert gaps[0].target_or_entity == "10.0.0.1"
    assert gaps[0].desired_evidence_type == "network.port_scan"


def test_hypothesis_testing_rule_proposes_support_and_disconfirmation():
    """Verify hypothesis testing proposes both supporting AND refuting candidates to avoid confirmation bias."""
    inv = Investigation(id="inv-hyp", title="Hypothesis Test", targets=["target.corp"])
    hyp = inv.create_hypothesis("Infrastructure target.corp is active and owned by Corp Inc.")

    specialists = SpecialistRegistry()
    specialists.register_specialist(create_dummy_osint_specialist())
    caps = CapabilityRegistry()

    rule = HypothesisTestingPlanningRule()
    cands, gaps = rule.evaluate(inv, specialists, caps, set())

    assert len(cands) == 2
    dimensions = {c.value_dimension for c in cands}
    assert InformationValueDimension.HYPOTHESIS_SUPPORT in dimensions
    assert InformationValueDimension.HYPOTHESIS_DISCONFIRMATION in dimensions


def test_planner_deduplication():
    """Verify planner avoids re-proposing candidates that have already been executed or satisfied."""
    inv = Investigation(id="inv-dedup", title="Dedup Test", targets=["example.com"])
    inv.add_entity("ip", "1.1.1.1")

    specialists = SpecialistRegistry()
    specialists.register_specialist(create_dummy_network_specialist())
    caps = CapabilityRegistry()

    planner = DeterministicPlanner()

    # Cycle 1: should propose port_scan candidate
    plan1 = planner.generate_plan(inv, specialists, caps)
    assert len(plan1.candidate_next_requirements) == 1

    # Simulate requirement creation
    req = inv.create_information_requirement(
        description="Port scan on 1.1.1.1",
        target_or_entity="1.1.1.1",
        evidence_types_sought=["network.port_scan"],
        assigned_capability_id="network.port_scan",
    )
    req.status = req.status.__class__.SATISFIED

    # Cycle 2: should NOT propose the same requirement again
    plan2 = planner.generate_plan(inv, specialists, caps)
    assert len(plan2.candidate_next_requirements) == 0
