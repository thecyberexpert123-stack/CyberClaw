"""End-to-end scenario test matching Section 23 and persistence verification."""

from pathlib import Path
import pytest
from cyberclaw.branching.engine import BranchEngine
from cyberclaw.branching.models import BranchStatus
from cyberclaw.branching.persistence import BranchPersistence
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.investigation import Investigation
from cyberclaw.planning.models import InformationValueDimension, RequirementCandidate
from cyberclaw.types import Entity, Hypothesis, Source
from cyberclaw.workspace.manager import WorkspaceManager


def test_section_23_end_to_end_branching_and_counterfactual_scenario(tmp_path: Path):
    """Execute complete Section 23 multi-branch lifecycle scenario and verify persistence and determinism."""
    ws = WorkspaceManager(tmp_path)

    # 1. Authoritative Investigation Setup
    inv = Investigation(
        title="APT Recon Investigation",
        description="Section 23 E2E test",
        workspace=ws,
    )
    inv.dfa.transition(CoreState.READY, event="init_complete")
    inv.case_manager.record_state_transition("INITIALIZE", "READY", "init_complete")
    inv.dfa.transition(CoreState.INVESTIGATE, event="start_investigation")
    inv.case_manager.record_state_transition("READY", "INVESTIGATE", "start_investigation")

    # 2. OSINT Evidence ingested & entity discovered
    ev_osint = Evidence(
        type="dns_record",
        subject="apex-defense.org",
        value={"ip": "198.51.100.22"},
        source=Source(type="osint", name="PassiveDNS"),
    )
    inv.add_evidence(ev_osint)
    inv.add_entity("domain", "apex-defense.org")
    inv.add_entity("ip", "198.51.100.22")

    hyp = inv.create_hypothesis(
        statement="Domain apex-defense.org is operated by threat actor group Raven",
        initial_confidence=0.5,
    )

    # 3. Snapshot N captured
    snap_n = inv.capture_snapshot(trigger="post_osint_recon")
    assert snap_n.sequence == 1

    # 4. Planner generates multiple valid candidate requirements
    cand_dns = RequirementCandidate(
        target_or_entity="apex-defense.org",
        requested_evidence_types=["subdomain_enum"],
        purpose="Enumerate subdomains to identify c2 infrastructure",
        value_dimension=InformationValueDimension.ENTITY_ENRICHMENT,
    )
    cand_whois = RequirementCandidate(
        target_or_entity="198.51.100.22",
        requested_evidence_types=["whois_record"],
        purpose="Inspect registrant whois data to identify attribution",
        value_dimension=InformationValueDimension.HYPOTHESIS_SUPPORT,
    )

    # 5. Branch A created: Subdomain Path
    branch_a = inv.create_branch(
        source_snapshot=snap_n.sequence,
        purpose="Branch A: Subdomain Enumeration Path",
    )
    # Simulated path A
    BranchEngine.simulate_requirement_outcome(
        branch=branch_a,
        candidate_or_req=cand_dns,
        simulated_evidence=[
            Evidence(
                type="subdomain_enum",
                subject="apex-defense.org",
                value={"subdomains": ["c2.apex-defense.org", "vpn.apex-defense.org"]},
                source=Source(type="simulated", name="SimSubdomainProvider"),
            )
        ],
        simulated_entities=[
            Entity(type="domain", name="c2.apex-defense.org"),
            Entity(type="domain", name="vpn.apex-defense.org"),
        ],
        hypothesis_shifts={
            hyp.id: ("SUPPORTED", 0.85),
        },
    )

    # 6. Branch B created: Whois Disconfirmation Path
    branch_b = inv.create_branch(
        source_snapshot=snap_n.sequence,
        purpose="Branch B: Registrant Attribution Path",
    )
    # Simulated path B
    BranchEngine.simulate_requirement_outcome(
        branch=branch_b,
        candidate_or_req=cand_whois,
        simulated_evidence=[
            Evidence(
                type="whois_record",
                subject="198.51.100.22",
                value={"org": "Legitimate Cloud Provider LLC"},
                source=Source(type="simulated", name="SimWhoisProvider"),
            )
        ],
        hypothesis_shifts={
            hyp.id: ("CONTRADICTED", 0.15),
        },
    )

    # 7. Replay Branch A
    recon_a_1 = inv.replay_branch(branch_a.branch_id)
    assert recon_a_1.hypotheses[hyp.id].status == "SUPPORTED"
    assert recon_a_1.hypotheses[hyp.id].confidence == 0.85
    assert any(entity.name == "c2.apex-defense.org" for entity in recon_a_1.entities.values())

    # 8. Replay Branch B
    recon_b_1 = inv.replay_branch(branch_b.branch_id)
    assert recon_b_1.hypotheses[hyp.id].status == "CONTRADICTED"
    assert recon_b_1.hypotheses[hyp.id].confidence == 0.15
    assert not any(entity.name == "c2.apex-defense.org" for entity in recon_b_1.entities.values())

    # 9. Compare Branch A vs Branch B
    comp_ab = inv.compare_branches(branch_a.branch_id, branch_b.branch_id)
    assert len(comp_ab.entity_differences["only_in_a"]) == 2  # c2 and vpn
    assert len(comp_ab.entity_differences["only_in_b"]) == 0
    assert hyp.id in comp_ab.hypothesis_differences["status_shifts"]
    assert comp_ab.hypothesis_differences["status_shifts"][hyp.id]["branch_a"] == "SUPPORTED"
    assert comp_ab.hypothesis_differences["status_shifts"][hyp.id]["branch_b"] == "CONTRADICTED"

    # 10. Compare both against Authoritative Snapshot N
    comp_a_snap = inv.compare_branch_with_snapshot(branch_a.branch_id, snap_n.sequence)
    assert len(comp_a_snap.evidence_differences["only_in_a"]) == 1  # simulated subdomain evidence
    assert len(comp_a_snap.evidence_differences["common"]) == 1    # baseline osint evidence

    # 11. Verify authoritative case remains unchanged
    assert inv.hypotheses[hyp.id].status == "OPEN"
    assert inv.hypotheses[hyp.id].confidence == 0.50
    assert not any(entity.name == "c2.apex-defense.org" for entity in inv.entities.values())
    assert len(inv.evidence_store.list_all()) == 1

    # 12. Persist to workspace
    ws.persist_branches(inv.id, [branch_a, branch_b])

    # 13. Reload from workspace
    loaded_branches = ws.load_branches(inv.id)
    assert len(loaded_branches) == 2
    loaded_a = next(b for b in loaded_branches if b.branch_id == branch_a.branch_id)
    loaded_b = next(b for b in loaded_branches if b.branch_id == branch_b.branch_id)

    assert loaded_a.purpose == branch_a.purpose
    assert loaded_b.purpose == branch_b.purpose
    assert len(loaded_a.journal) == len(branch_a.journal)

    # 14. Replay again from loaded structures
    recon_a_2 = BranchEngine.replay_branch(loaded_a, inv)
    assert recon_a_2.state_digest == recon_a_1.state_digest
    assert recon_a_2.hypotheses[hyp.id].status == "SUPPORTED"
