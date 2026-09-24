"""Tests for branch creation, lifecycle state transitions, integrity checks, and sequence validation."""

import pytest
from cyberclaw.branching.engine import BranchEngine
from cyberclaw.branching.errors import (
    BranchIntegrityError,
    BranchLifecycleError,
    BranchSequenceError,
)
from cyberclaw.branching.lifecycle import transition_branch
from cyberclaw.branching.models import BranchJournalEntry, BranchStatus
from cyberclaw.branching.validator import BranchValidator
from cyberclaw.case.models import (
    DecisionRecord,
    DecisionType,
    InvestigationSnapshot,
    JournalEntryType,
)
from cyberclaw.dfa.states import CoreState
from cyberclaw.investigation import Investigation


def create_sample_investigation() -> Investigation:
    """Helper to set up an investigation with an initial sealed snapshot."""
    inv = Investigation(title="Test Branch Investigation", description="Testing branching")
    inv.dfa.transition(CoreState.READY, event="init_complete")
    inv.case_manager.record_state_transition("INITIALIZE", "READY", "init_complete")
    inv.dfa.transition(CoreState.INVESTIGATE, event="start_investigation")
    inv.case_manager.record_state_transition("READY", "INVESTIGATE", "start_investigation")
    inv.add_entity("domain", "target.com")
    inv.create_hypothesis("Target domain is active", initial_confidence=0.6)
    inv.capture_snapshot(trigger="initial_setup")
    return inv


def test_branch_creation_from_snapshot():
    """Verify branch creates properly from a valid snapshot."""
    inv = create_sample_investigation()
    snap = inv.list_snapshots()[0]

    branch = inv.create_branch(
        source_snapshot=snap.sequence,
        purpose="Explore alternative DNS lookups",
        metadata={"category": "recon"},
    )

    assert branch.branch_id is not None
    assert branch.investigation_id == inv.id
    assert branch.source_snapshot_sequence == snap.sequence
    assert branch.source_snapshot_id == snap.snapshot_id
    assert branch.status == BranchStatus.ACTIVE
    assert branch.purpose == "Explore alternative DNS lookups"
    assert branch.is_counterfactual is True
    assert len(branch.journal) == 1
    assert branch.journal[0].local_sequence == 1
    assert branch.journal[0].entry_type == JournalEntryType.INVESTIGATION_CREATED


def test_branch_source_snapshot_tamper_detection():
    """Verify that tampering with source snapshot raises BranchIntegrityError."""
    inv = create_sample_investigation()
    snap = inv.list_snapshots()[0]

    # Tamper with snapshot state
    snap.dfa_state = "COMPROMISED"

    with pytest.raises(BranchIntegrityError) as exc_info:
        inv.create_branch(source_snapshot=snap.sequence, purpose="Tampered test")
    assert "integrity verification failed" in str(exc_info.value).lower()


def test_branch_lifecycle_transitions():
    """Verify legal branch lifecycle transitions."""
    inv = create_sample_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Lifecycle test")

    assert branch.status == BranchStatus.ACTIVE

    # ACTIVE -> COMPLETED
    transition_branch(branch, BranchStatus.COMPLETED, reason="Analysis completed")
    assert branch.status == BranchStatus.COMPLETED
    assert branch.metadata.get("status_reason") == "Analysis completed"

    # COMPLETED -> PROMOTED
    transition_branch(branch, BranchStatus.PROMOTED, reason="Selected for synthesis")
    assert branch.status == BranchStatus.PROMOTED


def test_invalid_branch_lifecycle_transitions():
    """Verify that illegal transitions raise BranchLifecycleError."""
    inv = create_sample_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Illegal lifecycle test")

    # Transition to ABANDONED (terminal)
    transition_branch(branch, BranchStatus.ABANDONED)
    assert branch.status == BranchStatus.ABANDONED

    # Attempt ABANDONED -> ACTIVE (illegal)
    with pytest.raises(BranchLifecycleError):
        transition_branch(branch, BranchStatus.ACTIVE)

    # Attempt ABANDONED -> PROMOTED (illegal)
    with pytest.raises(BranchLifecycleError):
        transition_branch(branch, BranchStatus.PROMOTED)


def test_branch_journal_sequence_gap_detection():
    """Verify validator detects gaps in branch-local sequences."""
    entries = [
        BranchJournalEntry(
            branch_id="b-1",
            investigation_id="inv-1",
            local_sequence=1,
            entry_type=JournalEntryType.INVESTIGATION_CREATED,
            summary="Init",
        ),
        BranchJournalEntry(
            branch_id="b-1",
            investigation_id="inv-1",
            local_sequence=3,  # GAP! (expected 2)
            entry_type=JournalEntryType.EVIDENCE_INGESTED,
            summary="Evidence",
        ),
    ]
    with pytest.raises(BranchSequenceError) as exc_info:
        BranchValidator.validate_branch_journal(entries)
    assert "gap" in str(exc_info.value).lower()


def test_branch_journal_duplicate_sequence_detection():
    """Verify validator detects duplicate sequences in branch journal."""
    entries = [
        BranchJournalEntry(
            branch_id="b-1",
            investigation_id="inv-1",
            local_sequence=1,
            entry_type=JournalEntryType.INVESTIGATION_CREATED,
            summary="Init",
        ),
        BranchJournalEntry(
            branch_id="b-1",
            investigation_id="inv-1",
            local_sequence=1,  # Duplicate!
            entry_type=JournalEntryType.EVIDENCE_INGESTED,
            summary="Evidence",
        ),
    ]
    with pytest.raises(BranchSequenceError) as exc_info:
        BranchValidator.validate_branch_journal(entries)
    assert "duplicate" in str(exc_info.value).lower()


def test_branch_missing_decision_reference_detection():
    """Verify validator catches journal entries pointing to non-existent decisions."""
    inv = create_sample_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Missing decision ref test")

    # Manually append an entry pointing to a missing decision
    BranchEngine.apply_simulated_event(
        branch=branch,
        entry_type=JournalEntryType.DECISION_RECORDED,
        summary="Ghost decision",
        reference_id="non-existent-decision-123",
    )

    with pytest.raises(BranchIntegrityError) as exc_info:
        BranchValidator.validate_all(
            branch=branch,
            snapshots=inv.list_snapshots(),
            authoritative_evidence_ids=set(),
        )
    assert "non-existent decision" in str(exc_info.value).lower()


def test_branch_nested_lineage():
    """Verify child branch correctly preserves parent_branch_id."""
    inv = create_sample_investigation()
    parent_branch = inv.create_branch(source_snapshot=1, purpose="Parent branch")

    # Capture another snapshot or branch from parent
    child_branch = inv.create_branch(
        source_snapshot=1,
        purpose="Child branch exploring specific sub-hypothesis",
        parent_branch_id=parent_branch.branch_id,
    )

    assert child_branch.parent_branch_id == parent_branch.branch_id
    assert child_branch.branch_id != parent_branch.branch_id


def test_branch_core_api_and_promotion(tmp_path):
    """Verify CyberClawCore APIs for branch creation, validation, comparison, and promotion."""
    from cyberclaw.core import CyberClawCore
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Core Branch Test", "Testing core branching integration")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start_recon")

    # Create snapshot #2
    snap = inv.capture_snapshot(trigger="core_snap")

    # Create branches via Core API
    branch_a = core.create_investigation_branch(
        investigation_id=inv.id,
        source_snapshot=snap.sequence,
        purpose="Path Alpha",
    )
    branch_b = core.create_investigation_branch(
        investigation_id=inv.id,
        source_snapshot=snap.sequence,
        purpose="Path Beta",
    )

    assert len(core.list_investigation_branches(inv.id)) == 2
    assert core.validate_branch_history(inv.id, branch_a.branch_id) is True

    # Compare via Core
    comp = core.compare_investigation_branches(inv.id, branch_a.branch_id, branch_b.branch_id)
    assert comp.branch_a_id == branch_a.branch_id
    assert comp.branch_b_id == branch_b.branch_id

    # Compare to snapshot via Core
    comp_snap = core.compare_branch_to_snapshot(inv.id, branch_a.branch_id, snap.sequence)
    assert "Path Alpha" in comp_snap.summary_report

    # Promote branch via Core
    decision = core.promote_investigation_branch(
        investigation_id=inv.id,
        branch_id=branch_a.branch_id,
        reason="Selected Alpha as most promising hypothesis direction",
    )
    assert decision.decision_type.value == "PLANNING_SELECTION"
    assert branch_a.status == BranchStatus.PROMOTED


def test_branch_dfa_illegal_transition_detection():
    """Verify illegal DFA state transitions inside branch raise BranchIntegrityError."""
    inv = create_sample_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="DFA test")

    # Legal transition: INVESTIGATE -> VERIFY
    BranchEngine.simulate_dfa_transition(branch, CoreState.VERIFY.value, event="verify_evidence")
    assert branch.derived_state.dfa_state == CoreState.VERIFY.value

    # Illegal transition: VERIFY -> INITIALIZE (not allowed in Core DFA)
    with pytest.raises(BranchIntegrityError):
        BranchEngine.simulate_dfa_transition(branch, CoreState.INITIALIZE.value, event="restart")


def test_branch_missing_evidence_reference_validation():
    """Verify validator catches branch referencing non-existent evidence IDs."""
    inv = create_sample_investigation()
    branch = inv.create_branch(source_snapshot=1, purpose="Evidence ref test")

    # Inject ghost evidence reference
    branch.evidence_references.append("ghost-ev-999")

    with pytest.raises(BranchIntegrityError) as exc_info:
        BranchValidator.validate_all(
            branch=branch,
            snapshots=inv.list_snapshots(),
            authoritative_evidence_ids={e.id for e in inv.evidence_store.list_all()},
        )
    assert "non-existent evidence" in str(exc_info.value).lower()

