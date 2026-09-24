"""Tests for domain coexistence, unknown future specialists, and historical vs current separation."""

from pathlib import Path
import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.case.models import DecisionType
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source


class FutureSatelliteReplayEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        ev = Evidence(
            type="satellite.thermal_signature",
            subject="site-bravo",
            value={"hotspot_detected": True, "intensity": 0.89},
            source=Source(type="orbital_sensor", name="thermal_sat_01"),
            provenance=Provenance(specialist_id="specialist.satellite", execution_id=request.request_id),
            confidence=0.92,
        )
        return SpecialistResponse.from_result("specialist.satellite", request.request_id, ExecutionResult.success(evidence=[ev]))


def test_replay_with_unknown_future_specialist(tmp_path: Path):
    """Verify unknown FutureSatelliteSpecialist coordinates and replays seamlessly without domain logic in ReplayEngine."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register future specialist
    sat_spec = Specialist(
        id="specialist.satellite",
        name="Satellite Recon Specialist",
        capabilities=["satellite.thermal_scan"],
        endpoint=FutureSatelliteReplayEndpoint(),
    )
    core.register_specialist(sat_spec)
    core.register_capability(
        Capability(id="satellite.thermal_scan", name="Satellite Thermal Scan")
    )

    inv = core.create_investigation("Orbital Analysis", targets=["site-bravo"])
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, "start_scan")

    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Orbital scan over site-bravo",
        target_or_entity="site-bravo",
        assigned_capability_id="satellite.thermal_scan",
    )
    core.fulfill_information_requirement(inv.id, req.id)

    # Replay historical state
    recon = core.replay_investigation(inv.id)

    assert recon.dfa_state == "INVESTIGATE"
    assert len(recon.evidence) == 1
    assert recon.evidence[0].type == "satellite.thermal_signature"
    assert recon.evidence[0].provenance.specialist_id == "specialist.satellite"

    # Query historical state by type
    sat_evidence = recon.query_evidence(type="satellite.thermal_signature")
    assert len(sat_evidence) == 1
    assert sat_evidence[0].subject == "site-bravo"

    core.shutdown()


def test_experience_reference_preservation_in_replay(tmp_path: Path):
    """Verify case-linked global experience references are preserved during replay without mutating global store."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Experience Linked Case", targets=["exp-target.net"])
    inv.case_manager.link_experience("exp-global-lesson-999")
    core.capture_case_snapshot(inv.id, trigger="linked_experience")

    recon = core.replay_investigation(inv.id)

    assert "exp-global-lesson-999" in recon.experience_references
    # Global experience store is untouched
    assert core.experiences.get("exp-global-lesson-999") is None

    core.shutdown()


def test_historical_vs_current_planner_separation(tmp_path: Path):
    """Verify historical decisions are replayed from DecisionRecord without re-invoking current planning algorithms."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Planner Separation Test", targets=["historic.corp"])

    # Record historical planning decision directly
    inv.record_decision(
        decision_type=DecisionType.PLANNING_SELECTION,
        actor="core.planner.v0.1",
        rationale="Historical planner chose DNS over WHOIS based on v0.1 heuristic",
        inputs={"target": "historic.corp", "rule": "legacy_v01_rule"},
        outcome={"chosen_capability": "osint.dns_lookup"},
    )

    # Replay
    recon = core.replay_investigation(inv.id)

    assert len(recon.decisions) == 1
    historic_decision = recon.decisions[0]
    assert historic_decision.actor == "core.planner.v0.1"
    assert "legacy_v01_rule" in historic_decision.inputs["rule"]

    core.shutdown()
