"""Tests for branch replay determinism, time-travel queries, counterfactual simulations, and comparative diffs."""

import pytest
from cyberclaw.branching.engine import BranchEngine
from cyberclaw.case.models import ContradictionRecord
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.investigation import Investigation
from cyberclaw.planning.models import InformationValueDimension, RequirementCandidate, UncertaintyType
from cyberclaw.types import Entity, Hypothesis, Relationship, Source


def create_scenario_investigation() -> Investigation:
    """Helper creating an investigation with structured evidence and a baseline snapshot."""
    inv = Investigation(title="Scenario Investigation", description="Replay and diff test")
    inv.dfa.transition(CoreState.READY, event="init_complete")
    inv.case_manager.record_state_transition("INITIALIZE", "READY", "init_complete")
    inv.dfa.transition(CoreState.INVESTIGATE, event="start_investigation")
    inv.case_manager.record_state_transition("READY", "INVESTIGATE", "start_investigation")

    # Ingest baseline evidence
    ev = Evidence(
        type="dns_record",
        subject="mail.example.org",
        value={"ip": "93.184.216.34"},
        source=Source(type="osint", name="DNSProvider"),
    )
    inv.add_evidence(ev)
    inv.add_entity("domain", "mail.example.org")
    inv.create_hypothesis("Server is hosted in cloud ASN", initial_confidence=0.5)

    inv.capture_snapshot(trigger="baseline_snapshot")
    return inv


def test_branch_replay_determinism():
    """Verify that repeated branch replay produces identical ReconstructedState and SHA-256 digest."""
    inv = create_scenario_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Deterministic replay test")

    # Simulate events in branch
    sim_ev = Evidence(
        type="cert_record",
        subject="mail.example.org",
        value={"issuer": "Let's Encrypt", "san": ["mail.example.org", "smtp.example.org"]},
        source=Source(type="simulated", name="CertProvider"),
    )
    BranchEngine.simulate_evidence(branch, [sim_ev])
    BranchEngine.simulate_entities(branch, [Entity(type="domain", name="smtp.example.org")])

    # Replay 1
    recon_1 = inv.replay_branch(branch.branch_id)
    # Replay 2
    recon_2 = inv.replay_branch(branch.branch_id)

    assert recon_1.state_digest == recon_2.state_digest
    assert len(recon_1.evidence) == len(recon_2.evidence) == 2  # 1 baseline + 1 simulated
    assert "smtp.example.org" in recon_1.entities
    assert "smtp.example.org" in recon_2.entities


def test_branch_time_travel():
    """Verify time-travel reconstruction inside a branch at intermediate sequence numbers."""
    inv = create_scenario_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Time travel test")

    # Sequence 1: Init
    # Sequence 2: Entity added
    BranchEngine.simulate_entities(branch, [Entity(type="host", name="server-01")])
    # Sequence 3: Evidence added
    ev = Evidence(
        type="banner",
        subject="server-01",
        value={"software": "OpenSSH 8.9"},
        source=Source(type="simulated", name="BannerScanner"),
    )
    BranchEngine.simulate_evidence(branch, [ev])

    # Query state at local sequence 2 (before evidence was ingested)
    state_seq_2 = BranchEngine.replay_branch(branch, inv, until_local_sequence=2)
    assert "server-01" in state_seq_2.entities
    assert len(state_seq_2.evidence) == 1  # Only baseline evidence

    # Query state at local sequence 3 (after evidence was ingested)
    state_seq_3 = BranchEngine.replay_branch(branch, inv, until_local_sequence=3)
    assert "server-01" in state_seq_3.entities
    assert len(state_seq_3.evidence) == 2  # Baseline + simulated evidence


def test_alternative_planning_candidate_evaluation():
    """Verify evaluation of alternative planner candidates into distinct branches."""
    inv = create_scenario_investigation()

    # Create two candidates from planner
    cand_dns = RequirementCandidate(
        target_or_entity="mail.example.org",
        requested_evidence_types=["dns_mx"],
        purpose="Enumerate mail exchange records",
        value_dimension=InformationValueDimension.MISSING_EVIDENCE,
    )
    cand_cert = RequirementCandidate(
        target_or_entity="mail.example.org",
        requested_evidence_types=["x509_cert"],
        purpose="Inspect TLS certificate transparency logs",
        value_dimension=InformationValueDimension.ENTITY_ENRICHMENT,
    )

    # Branch A follows DNS candidate
    branch_a = inv.create_branch(source_snapshot=1, purpose="Path A: MX Records")
    BranchEngine.simulate_requirement_outcome(
        branch=branch_a,
        candidate_or_req=cand_dns,
        simulated_evidence=[
            Evidence(
                type="dns_mx",
                subject="mail.example.org",
                value={"mx": ["mx1.example.org"]},
                source=Source(type="simulated", name="DNS"),
            )
        ],
    )

    # Branch B follows TLS candidate
    branch_b = inv.create_branch(source_snapshot=1, purpose="Path B: TLS Certs")
    BranchEngine.simulate_requirement_outcome(
        branch=branch_b,
        candidate_or_req=cand_cert,
        simulated_evidence=[
            Evidence(
                type="x509_cert",
                subject="mail.example.org",
                value={"san": ["admin.example.org"]},
                source=Source(type="simulated", name="CTLog"),
            )
        ],
    )

    # Compare Branches
    comparison = inv.compare_branches(branch_a.branch_id, branch_b.branch_id)

    assert len(comparison.evidence_differences["only_in_a"]) == 1
    assert len(comparison.evidence_differences["only_in_b"]) == 1
    assert len(comparison.evidence_differences["common"]) == 1  # baseline evidence
    assert "Path A: MX Records" in comparison.summary_report
    assert "Path B: TLS Certs" in comparison.summary_report


def test_branch_contradiction_handling():
    """Verify recording and resolving contradictions within a branch."""
    inv = create_scenario_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Contradiction path")

    c = ContradictionRecord(
        investigation_id=inv.id,
        subject="93.184.216.34",
        conflict_type="conflicting_resolution",
        competing_evidence_ids=["ev-1", "ev-2"],
        description="Conflicting geolocations for IP 93.184.216.34",
        resolved=False,
    )
    branch.contradictions.append(c)

    BranchEngine.apply_simulated_event(
        branch=branch,
        entry_type="CONTRADICTION_DETECTED",
        summary="Contradiction detected in geolocation",
        details={"contradiction": c.model_dump()},
    )

    recon = inv.replay_branch(branch.branch_id)
    assert len(recon.contradictions) == 1
    assert recon.contradictions[0].resolved is False
