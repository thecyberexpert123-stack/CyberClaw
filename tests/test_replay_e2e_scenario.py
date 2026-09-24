"""Section 20 End-to-End Investigation Replay & Time-Travel Scenario Test."""

from pathlib import Path
import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.case.models import ContradictionRecord
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source


class MockE2EOsintEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        ev = Evidence(
            type="osint.dns_record",
            subject="target.corp",
            value={"ip": "198.51.100.50"},
            source=Source(type="dns_resolver", name="primary_dns"),
            provenance=Provenance(specialist_id="specialist.osint", execution_id=request.request_id),
            confidence=0.9,
        )
        return SpecialistResponse.from_result("specialist.osint", request.request_id, ExecutionResult.success(evidence=[ev]))


class MockE2ENetworkEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        ev = Evidence(
            type="network.port_scan",
            subject="198.51.100.50",
            value={"ports": {"443": {"state": "open"}}},
            source=Source(type="port_scanner", name="scanner"),
            provenance=Provenance(specialist_id="specialist.network", execution_id=request.request_id),
            confidence=0.95,
        )
        return SpecialistResponse.from_result("specialist.network", request.request_id, ExecutionResult.success(evidence=[ev]))


class MockE2EWhoisEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        ev = Evidence(
            type="osint.whois",
            subject="target.corp",
            value={"registrar": "Authoritative Corp Registrar"},
            source=Source(type="whois", name="arin"),
            provenance=Provenance(specialist_id="specialist.osint.whois", execution_id=request.request_id),
            confidence=0.99,
        )
        return SpecialistResponse.from_result("specialist.osint.whois", request.request_id, ExecutionResult.success(evidence=[ev]))


def test_section_20_end_to_end_replay_scenario(tmp_path: Path):
    """Execute complete Section 20 end-to-end investigation lifecycle and replay deterministically."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # 1. Register Capabilities and Specialists
    core.register_specialist(
        Specialist(
            id="specialist.osint",
            name="OSINT Specialist",
            capabilities=["osint.dns_lookup"],
            endpoint=MockE2EOsintEndpoint(),
        )
    )
    core.register_specialist(
        Specialist(
            id="specialist.network",
            name="Network Specialist",
            capabilities=["network.port_scan"],
            endpoint=MockE2ENetworkEndpoint(),
        )
    )
    core.register_specialist(
        Specialist(
            id="specialist.osint.whois",
            name="Whois Specialist",
            capabilities=["osint.whois_lookup"],
            endpoint=MockE2EWhoisEndpoint(),
        )
    )

    core.register_capability(Capability(id="osint.dns_lookup", name="DNS Lookup"))
    core.register_capability(Capability(id="network.port_scan", name="Port Scan"))
    core.register_capability(Capability(id="osint.whois_lookup", name="Whois Lookup"))

    # 2. Investigation Created
    inv = core.create_investigation("E2E Replay Case", targets=["target.corp"])
    inv.add_entity("domain", "target.corp")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, "start_investigation")

    # 3. Formulate initial hypothesis
    hyp = core.create_hypothesis(inv.id, "Target infrastructure target.corp is active and resolvable")

    # 4. OSINT evidence collected
    req1 = core.create_information_requirement(
        investigation_id=inv.id,
        description="Lookup DNS for target.corp",
        target_or_entity="target.corp",
        assigned_capability_id="osint.dns_lookup",
    )
    core.fulfill_information_requirement(inv.id, req1.id)

    # 5. Entity discovered via DNS resolution
    inv.add_entity("ip", "198.51.100.50")
    snap_before_contradiction = core.capture_case_snapshot(inv.id, trigger="post_dns_enrichment")

    # 6. Planner creates requirement -> Network Specialist executes port scan
    req2 = core.create_information_requirement(
        investigation_id=inv.id,
        description="Port scan 198.51.100.50",
        target_or_entity="198.51.100.50",
        assigned_capability_id="network.port_scan",
    )
    core.fulfill_information_requirement(inv.id, req2.id)

    # 7. Correlation & Hypothesis update
    core.correlate_investigation(inv.id)
    core.evaluate_hypotheses(inv.id)

    # 8. Contradiction appears (competing records)
    ev_comp1 = Evidence(id="ev-c1", type="dns", subject="target.corp", value={"ip": "1.1.1.1"}, source=Source(type="feed", name="f1"))
    ev_comp2 = Evidence(id="ev-c2", type="dns", subject="target.corp", value={"ip": "2.2.2.2"}, source=Source(type="feed", name="f2"))
    inv.add_evidence(ev_comp1)
    inv.add_evidence(ev_comp2)

    contra = ContradictionRecord(
        investigation_id=inv.id,
        conflict_type="conflicting_resolution",
        subject="target.corp",
        competing_evidence_ids=["ev-c1", "ev-c2"],
        description="Conflicting DNS resolution from feed",
        resolved=False,
    )
    inv.contradictions.append(contra)
    inv.record_journal_entry(
        entry_type="CONTRADICTION_DETECTED",
        summary="Conflicting DNS resolution from feed",
        reference_id=contra.id,
        details={"contradiction": contra.model_dump()},
    )
    core.capture_case_snapshot(inv.id, trigger="contradiction_detected")

    # 9. Planner creates requirement to resolve contradiction
    plan, val_res = core.plan_investigation(inv.id, auto_convert_candidates=True)
    whois_reqs = [
        r for r in inv.information_requirements.values()
        if r.assigned_capability_id == "osint.whois_lookup" and r.status.value == "OPEN"
    ]
    if whois_reqs:
        core.fulfill_information_requirement(inv.id, whois_reqs[0].id)

    # Resolve contradiction
    contra.resolved = True
    snap_after_resolution = core.capture_case_snapshot(inv.id, trigger="contradiction_resolved")

    # 10. Investigation reaches stopping condition
    core.transition_investigation(inv.id, CoreState.VERIFY, "verification_phase")
    core.transition_investigation(inv.id, CoreState.RESOLVE, "case_resolved")
    snap_final = core.capture_case_snapshot(inv.id, trigger="case_stopped")

    # 11. Load persisted case and verify Replay
    # Replay 1: From sequence 0 to end
    recon_full_1 = core.replay_investigation(inv.id)
    # Replay 2: Independent replay
    recon_full_2 = core.replay_investigation(inv.id)

    # Step 6: Verify deterministic equality across two independent replays
    assert recon_full_1.state_digest == recon_full_2.state_digest
    assert recon_full_1.dfa_state == recon_full_2.dfa_state == "RESOLVE"
    assert len(recon_full_1.evidence) == len(recon_full_2.evidence)

    # Step 3: Replay to the point before the contradiction
    recon_before_contra = core.replay_investigation(
        inv.id,
        until_snapshot=snap_before_contradiction.sequence,
    )
    assert recon_before_contra.dfa_state == "INVESTIGATE"
    assert len(recon_before_contra.contradictions) == 0

    # Step 4: Replay to the point after contradiction resolution
    recon_after_contra = core.replay_investigation(
        inv.id,
        until_snapshot=snap_after_resolution.sequence,
    )
    # Contradiction should be present
    assert len(recon_after_contra.contradictions) == 1

    # Step 5: Compare reconstructed state against authoritative snapshot
    recon_final_equiv = recon_full_1.verify_against_snapshot(snap_final)
    assert recon_final_equiv is True

    # Step 7: Verify current live case remains unchanged
    assert inv.current_state.value == "RESOLVE"
    assert len(inv.evidence_store.list_all()) >= 3

    core.shutdown()
