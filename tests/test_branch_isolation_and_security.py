"""Tests for branch isolation, authoritative case immutability, experience boundaries, and security limits."""

import pytest
from cyberclaw.branching.engine import BranchEngine
from cyberclaw.branching.errors import BranchExecutionBlockedError
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.investigation import Investigation
from cyberclaw.memory.store import ExperienceStore
from cyberclaw.types import Entity, Hypothesis, Source


def create_base_investigation() -> Investigation:
    """Set up an investigation with known entities, hypotheses, and a snapshot."""
    inv = Investigation(title="Isolation Baseline", description="Testing branch isolation")
    inv.dfa.transition(CoreState.READY, event="init_complete")
    inv.case_manager.record_state_transition("INITIALIZE", "READY", "init_complete")
    inv.dfa.transition(CoreState.INVESTIGATE, event="start_investigation")
    inv.case_manager.record_state_transition("READY", "INVESTIGATE", "start_investigation")
    inv.add_entity("domain", "corp.internal")
    inv.create_hypothesis("Host is compromised", initial_confidence=0.5)
    inv.capture_snapshot(trigger="snap_baseline")
    return inv


def test_branch_state_and_authoritative_isolation():
    """Verify that mutations inside a branch do not affect the authoritative investigation."""
    inv = create_base_investigation()
    initial_entities_count = len(inv.entities)
    initial_hypotheses = {h.id: h.confidence for h in inv.hypotheses.values()}
    initial_journal_len = len(inv.case_manager.journal.entries)

    branch = inv.create_branch(source_snapshot=1, purpose="Modify state inside branch")

    # 1. Add simulated entity in branch
    BranchEngine.simulate_entities(
        branch=branch,
        entities=[Entity(type="ip", name="192.168.1.100")],
    )

    # 2. Shift hypothesis in branch
    hyp_id = list(inv.hypotheses.keys())[0]
    BranchEngine.simulate_hypothesis_shift(
        branch=branch,
        hypothesis_id=hyp_id,
        new_status="SUPPORTED",
        confidence=0.95,
        reason="Counterfactual corroboration",
    )

    # Verify branch state was updated
    assert any(entity.name == "192.168.1.100" for entity in branch.entities.values())
    assert branch.hypotheses[hyp_id].status == "SUPPORTED"
    assert branch.hypotheses[hyp_id].confidence == 0.95

    # Verify authoritative case was NOT mutated
    assert len(inv.entities) == initial_entities_count
    assert not any(entity.name == "192.168.1.100" for entity in inv.entities.values())
    assert inv.hypotheses[hyp_id].status == "OPEN"
    assert inv.hypotheses[hyp_id].confidence == initial_hypotheses[hyp_id]
    assert len(inv.case_manager.journal.entries) == initial_journal_len


def test_branch_to_branch_isolation():
    """Verify that two branches derived from the same snapshot remain completely isolated."""
    inv = create_base_investigation()
    hyp_id = list(inv.hypotheses.keys())[0]

    branch_a = inv.create_branch(source_snapshot=1, purpose="Branch A: Confirming")
    branch_b = inv.create_branch(source_snapshot=1, purpose="Branch B: Disconfirming")

    # Branch A confirms hypothesis
    BranchEngine.simulate_hypothesis_shift(
        branch=branch_a,
        hypothesis_id=hyp_id,
        new_status="SUPPORTED",
        confidence=0.90,
    )

    # Branch B contradicts hypothesis
    BranchEngine.simulate_hypothesis_shift(
        branch=branch_b,
        hypothesis_id=hyp_id,
        new_status="CONTRADICTED",
        confidence=0.10,
    )

    # Branch A check
    assert branch_a.hypotheses[hyp_id].status == "SUPPORTED"
    assert branch_a.hypotheses[hyp_id].confidence == 0.90

    # Branch B check
    assert branch_b.hypotheses[hyp_id].status == "CONTRADICTED"
    assert branch_b.hypotheses[hyp_id].confidence == 0.10

    # Authoritative check remains untouched
    assert inv.hypotheses[hyp_id].status == "OPEN"
    assert inv.hypotheses[hyp_id].confidence == 0.50


def test_branch_experience_quarantine_and_promotion():
    """Verify that branch observations are quarantined and cannot contaminate global experience without explicit promotion."""
    inv = create_base_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Branch experience test")

    global_store = ExperienceStore()
    initial_exp_count = len(global_store.list_all())

    # Create candidate experience in branch
    candidate = BranchEngine.create_candidate_experience(
        branch=branch,
        action="simulate.dns.enumeration",
        lesson="Zone transfer failed under simulated hardening",
        conditions={"environment": "hardened"},
    )

    assert candidate.is_counterfactual is True
    assert candidate.validated is False
    # Global store must remain unchanged
    assert len(global_store.list_all()) == initial_exp_count

    # Explicit promotion by authorized actor
    promoted_rec = BranchEngine.promote_candidate_experience(
        candidate=candidate,
        experience_store=global_store,
        validator_actor="security.auditor",
        validation_notes="Empirically confirmed against external baseline",
    )

    assert candidate.validated is True
    assert len(global_store.list_all()) == initial_exp_count + 1
    assert promoted_rec.metadata.get("promoted_from_branch") == branch.branch_id
    assert promoted_rec.metadata.get("validated_by") == "security.auditor"


def test_security_boundary_no_executable_objects():
    """Verify that passing executable objects into simulation raises BranchExecutionBlockedError."""
    inv = create_base_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Security test")

    class MaliciousExecutableTask:
        def execute(self):
            return "executing shell command"

    with pytest.raises(BranchExecutionBlockedError):
        BranchEngine.simulate_requirement_outcome(
            branch=branch,
            candidate_or_req=MaliciousExecutableTask(),
        )
