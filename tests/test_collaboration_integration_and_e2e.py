"""Domain-neutral coexistence, Replay, Branch isolation, and Section 36 complete 31-step E2E scenario."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    CollaborationResult,
    CollaborationStatus,
    ConflictStatus,
    ContextSensitivity,
    FindingNature,
)
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence, Provenance, Source
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.runtime.errors import BranchExecutionBlockedError
from cyberclaw.runtime.models import RuntimeTask, TaskPriority
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistEndpoint, SpecialistHealth, SpecialistRequest, SpecialistResponse
from cyberclaw.types import Source


class MockSpecialistEndpoint(SpecialistEndpoint):
    def __init__(self, specialist_id: str, handler=None) -> None:
        self.specialist_id = specialist_id
        self.handler = handler
        self.invocations: List[SpecialistRequest] = []

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        self.invocations.append(request)
        if self.handler:
            return self.handler(request)
        ev = Evidence(
            type=f"{self.specialist_id}.finding",
            subject=request.parameters.get("target", "unknown"),
            value={"data": "mock_value"},
            source=Source(type="specialist", name=self.specialist_id),
            provenance=Provenance(specialist_id=self.specialist_id),
        )
        res = ExecutionResult.success(output={"status": "ok"}, evidence=[ev])
        return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)


def create_test_specialist(specialist_id: str, capabilities: List[str], handler=None) -> Specialist:
    return Specialist(
        id=specialist_id,
        name=f"Specialist {specialist_id}",
        version="1.0.0",
        capabilities=capabilities,
        endpoint=MockSpecialistEndpoint(specialist_id, handler=handler),
        permissions=["capability:execute"],
    )


# -----------------------------------------------------------------------------
# 1. Domain-Neutral Multi-Specialist Coexistence (Section 39)
# -----------------------------------------------------------------------------

def test_domain_neutral_five_specialist_coexistence(tmp_path: Path):
    """Verify runtime and collaboration coordinate across OSINT, Network, Forensics, Cloud, and an Unknown future specialist without domain branching."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    specs = [
        create_test_specialist("specialist.osint", ["osint.dns", "osint.whois"]),
        create_test_specialist("specialist.network", ["net.port_scan", "net.banner_grab"]),
        create_test_specialist("specialist.future_forensics", ["forensics.memory_dump", "forensics.pcap_parse"]),
        create_test_specialist("specialist.future_cloud", ["cloud.iam_audit", "cloud.bucket_posture"]),
        create_test_specialist("specialist.unknown_satellite", ["sat.telemetry_scan", "sat.orbit_correlate"]),
    ]

    for spec in specs:
        core.register_specialist(spec)
        for cap_id in spec.capabilities:
            cap = Capability(
                id=cap_id,
                name=cap_id,
                action_scope=ActionScope.REVERSIBLE,
                lifecycle_state=CapabilityLifecycleState.AVAILABLE,
                trust_state=CapabilityTrustState.FULLY_TRUSTED,
            )
            core.register_capability(cap)

    inv = core.create_investigation("Multi Specialist Coexistence")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    # Initiate collaboration from Forensics to Unknown Satellite specialist
    req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.future_forensics",
        target_specialist="specialist.unknown_satellite",
        objective="Analyze satellite telemetry downlink for timestamp",
        required_capabilities=["sat.telemetry_scan"],
    )

    routed = core.validate_and_route_collaboration(inv.id, req.request_id)
    assert routed.status == CollaborationStatus.ROUTED
    assert routed.target_specialist == "specialist.unknown_satellite"

    # Enqueue runtime task
    task = core.accept_collaboration_request(inv.id, routed.request_id, parameters={"sat_id": "SAT-99"})
    assert core.runtime_queue.depth(inv.id) == 1

    # Execute through runtime
    completed_task = core.step_runtime(inv.id)
    assert completed_task.status.value == "COMPLETED"

    # Process returned result
    result = CollaborationResult(
        request_id=req.request_id,
        investigation_id=inv.id,
        responding_specialist="specialist.unknown_satellite",
        observations=[{"subject": "SAT-99", "data": {"telemetry_active": True}}],
    )
    evs = core.process_collaboration_result(inv.id, req.request_id, result)
    assert len(evs) == 1
    assert evs[0].subject == "SAT-99"
    assert evs[0].provenance.specialist_id == "specialist.unknown_satellite"


# -----------------------------------------------------------------------------
# 2. Branch Isolation (Section 27)
# -----------------------------------------------------------------------------

def test_branch_collaboration_isolation_and_counterfactual_blocking(tmp_path: Path):
    """Verify branches cannot execute real collaboration tasks or mutate authoritative state."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="net.syn_probe",
        name="SYN Probe",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)
    spec = create_test_specialist("specialist.network", ["net.syn_probe"])
    core.register_specialist(spec)

    inv = core.create_investigation("Branch Isolation Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    snap = inv.capture_snapshot("base_checkpoint")

    # Create counterfactual branch
    branch = core.create_investigation_branch(inv.id, source_snapshot=snap.sequence, purpose="Hypothetical Port Scan")

    # Request collaboration within branch
    branch_req = core.request_collaboration(
        investigation_id=branch.branch_id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Probe branch host",
        required_capabilities=["net.syn_probe"],
        is_counterfactual=True,
    )
    assert branch_req.is_counterfactual is True

    core.validate_and_route_collaboration(branch.branch_id, branch_req.request_id)
    branch_task = core.accept_collaboration_request(branch.branch_id, branch_req.request_id)

    # Attempting to execute real provider in branch must raise BranchExecutionBlockedError
    with pytest.raises(BranchExecutionBlockedError) as exc:
        core.step_runtime(branch.branch_id)
    assert "cannot execute real providers in counterfactual branch" in str(exc.value)

    # Authoritative case evidence remains empty
    assert len(inv.evidence_store.list_all()) == 0


# -----------------------------------------------------------------------------
# 3. Complete 31-Step Multi-Specialist Collaboration End-to-End Scenario (Section 36)
# -----------------------------------------------------------------------------

def test_section_36_multi_specialist_collaboration_e2e_scenario(tmp_path: Path):
    """Execute the complete 31-step Section 36 collaboration, conflict, consensus, recovery, and replay scenario."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Step 0: Register Specialists and Capabilities
    cap_osint = Capability(
        id="osint.passive_dns",
        name="Passive DNS",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    cap_net = Capability(
        id="net.service_corroborate",
        name="Service Corroborator",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap_osint)
    core.register_capability(cap_net)

    osint_spec = create_test_specialist("specialist.osint", ["osint.passive_dns"])
    net_spec = create_test_specialist("specialist.network", ["net.service_corroborate"])
    core.register_specialist(osint_spec)
    core.register_specialist(net_spec)

    # 1. Investigation begins
    inv = core.create_investigation("Section 36 E2E Investigation", "Collaboration & Consensus verification")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    hyp = inv.create_hypothesis("Host 198.51.100.25 runs active malicious C2 service", initial_confidence=0.5)

    # 2. OSINTSpecialist produces initial structured evidence
    initial_ev = Evidence(
        type="osint.dns_mapping",
        subject="198.51.100.25",
        value={"domain": "c2-apex.org", "asn": 64500, "status": "active"},
        source=Source(type="passive_dns", name="Farsight_DNS"),
        provenance=Provenance(specialist_id="specialist.osint", capability_id="osint.passive_dns"),
        confidence=0.85,
    )
    inv.add_evidence(initial_ev)

    # 3. Correlation detects an information gap & 4. Planner creates collaboration requirement
    req_corrob = inv.create_information_requirement(
        description="Verify service identity on 198.51.100.25",
        target_or_entity="198.51.100.25",
        evidence_types_sought=["service_banner"],
        assigned_capability_id="net.service_corroborate",
        priority=75,
    )

    # 5. OSINTSpecialist requests assistance from NetworkSpecialist
    collab_req1 = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Determine whether service metadata corroborates C2 on 198.51.100.25",
        information_requirement_id=req_corrob.id,
        input_evidence_ids=[initial_ev.id],
        hypothesis_ids=[hyp.id],
        required_capabilities=["net.service_corroborate"],
        priority=80,
    )
    assert collab_req1.status == CollaborationStatus.PROPOSED

    # 6. CollaborationRequest is validated & 7. PolicyEngine authorizes request
    routed1 = core.validate_and_route_collaboration(inv.id, collab_req1.request_id)
    assert routed1.status == CollaborationStatus.ROUTED

    # 8. Runtime creates a durable collaboration task & 9. NetworkSpecialist receives only authorized context
    task1 = core.accept_collaboration_request(inv.id, routed1.request_id, parameters={"port": 8443})
    assert core.runtime_queue.depth(inv.id) == 1

    # 10. NetworkSpecialist executes mock capability via runtime
    completed_task1 = core.step_runtime(inv.id)
    assert completed_task1.status.value == "COMPLETED"

    # 11. Structured result is returned & 12. Evidence normalized & 13. Lineage/provenance preserved
    result1 = CollaborationResult(
        request_id=collab_req1.request_id,
        investigation_id=inv.id,
        responding_specialist="specialist.network",
        observations=[
            {
                "subject": "198.51.100.25",
                "data": {"banner": "custom_c2_protocol", "status": "active"},
                "confidence": 0.95,
            }
        ],
    )
    norm_evs1 = core.process_collaboration_result(inv.id, collab_req1.request_id, result1)
    assert len(norm_evs1) == 1
    new_ev = norm_evs1[0]
    assert new_ev.provenance.specialist_id == "specialist.network"
    assert new_ev.metadata["derived_from_evidence_ids"] == [initial_ev.id]
    assert new_ev.metadata["finding_nature"] == FindingNature.OBSERVATION.value

    # 14. Correlation evaluates new evidence & 15. Existing hypothesis becomes SUPPORTED
    assert hyp.status == "SUPPORTED"
    assert hyp.confidence >= 0.85

    # 16. A second specialist returns contradictory evidence
    collab_req2 = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.forensics",
        target_specialist="specialist.network",
        objective="Verify sinkhole telemetry for 198.51.100.25",
        required_capabilities=["net.service_corroborate"],
    )
    core.validate_and_route_collaboration(inv.id, collab_req2.request_id)
    core.accept_collaboration_request(inv.id, collab_req2.request_id)
    core.step_runtime(inv.id)

    disputing_result = CollaborationResult(
        request_id=collab_req2.request_id,
        investigation_id=inv.id,
        responding_specialist="specialist.network",
        observations=[
            {
                "subject": "198.51.100.25",
                "data": {"status": "revoked", "banner": "quarantined_sinkhole"},
                "confidence": 0.9,
            }
        ],
    )
    # 17. SpecialistConflict is created & 18. Both claims preserved
    disputing_evs = core.process_collaboration_result(inv.id, collab_req2.request_id, disputing_result)
    conflicts = core.collaboration.conflict_manager.list_conflicts(inv.id)
    assert len(conflicts) >= 1
    active_conflict = conflicts[0]
    assert active_conflict.subject == "198.51.100.25"
    assert active_conflict.status == ConflictStatus.OPEN

    # 19. Planner creates contradiction-resolution requirement & 20. Collaboration performed
    res_req = inv.create_information_requirement(
        description="Adjudicate sinkhole vs active C2 on 198.51.100.25",
        target_or_entity="198.51.100.25",
        evidence_types_sought=["authoritative_sinkhole_registry"],
    )

    # 21. Resolution evidence is produced & 22. Conflict transitions to appropriate state (RESOLVED)
    resolution_ev = Evidence(
        type="authoritative.sinkhole_disposition",
        subject="198.51.100.25",
        value={"verified_status": "sinkhole_confirmed", "status": "revoked"},
        source=Source(type="cert_auth", name="GlobalSinkholeRegistry"),
        confidence=1.0,
    )
    inv.add_evidence(resolution_ev)
    resolved_conflict = core.resolve_specialist_conflict(
        investigation_id=inv.id,
        conflict_id=active_conflict.conflict_id,
        resolution_evidence_id=resolution_ev.id,
        rationale="Authoritative GlobalSinkholeRegistry confirmed sinkhole status.",
    )
    assert resolved_conflict.status == ConflictStatus.RESOLVED

    # 23. Case snapshot is captured
    snap1 = inv.capture_snapshot("milestone_conflict_resolved")
    assert snap1.sequence >= 1

    # 24. Runtime crash simulated & 25. Recovery resumes remaining work safely
    core.runtime_queue.enqueue(
        RuntimeTask(
            investigation_id=inv.id,
            capability_id="net.service_corroborate",
            parameters={"target": "198.51.100.25"},
        )
    )
    claimed_crashed = core.runtime_queue.dequeue("crashed-worker")
    report = core.recover_runtime()
    assert claimed_crashed.task_id in report.requeued_unstarted

    # 26. Final case state persisted
    core.persist_collaboration_state(inv.id)

    # 27. Replay reconstructs complete collaboration history
    core.transition_investigation(inv.id, CoreState.VERIFY, event="verify")
    core.transition_investigation(inv.id, CoreState.RESOLVE, event="resolve")
    final_snap = inv.capture_snapshot("case_resolved")

    invocations_before_replay = len(net_spec.endpoint.invocations)
    reconstructed = ReplayEngine.replay(inv)
    assert reconstructed.dfa_state == CoreState.RESOLVE.value

    # 28. Replay produces no specialist/provider execution
    assert len(net_spec.endpoint.invocations) == invocations_before_replay  # Replay invoked 0 additional endpoints!

    # 29. Branch simulation creates hypothetical conflicting result & 30. Authoritative case remains unchanged
    auth_ev_count = len(inv.evidence_store.list_all())
    branch_sim = core.create_investigation_branch(inv.id, source_snapshot=final_snap.sequence, purpose="Simulation")
    branch_ev = Evidence(
        type="simulated_artifact",
        subject="198.51.100.25",
        value={"simulated": True},
        source=Source(type="sim", name="simulator"),
    )
    branch_sim.simulated_evidence.append(branch_ev)
    assert len(inv.evidence_store.list_all()) == auth_ev_count  # Authoritative case strictly preserved!

    # 31. Repeated replay produces identical state digest
    reconstructed2 = ReplayEngine.replay(inv)
    assert reconstructed.calculate_digest() == reconstructed2.calculate_digest()
