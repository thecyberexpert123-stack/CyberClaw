"""Tests for ReplayEngine deterministic reconstruction, checkpoints, and time-travel queries."""

import pytest
from cyberclaw.case.models import DecisionType, JournalEntryType
from cyberclaw.coordination.requirements import RequirementStatus
from cyberclaw.core import CyberClawCore
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.replay.errors import ReplayBoundsError
from cyberclaw.types import Source


def test_replay_from_beginning_and_determinism(tmp_path):
    """Verify replay from beginning deterministically reconstructs state and produces identical digests."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Replay Determinism Test", targets=["target.com"])
    inv.add_entity("domain", "target.com")

    # Add evidence directly
    ev = Evidence(
        id="ev-det-1",
        type="osint.dns_record",
        subject="target.com",
        value={"ip": "1.1.1.1"},
        source=Source(type="mock", name="dns"),
    )
    inv.evidence_store.add(ev)
    inv.record_journal_entry(
        entry_type=JournalEntryType.EVIDENCE_INGESTED,
        summary="Ingested DNS evidence",
        reference_id=ev.id,
        details={"evidence_ids": [ev.id]},
    )

    # Capture Snapshot
    inv.capture_snapshot(trigger="post_dns")

    # Replay 1
    recon1 = ReplayEngine.replay(inv)
    # Replay 2
    recon2 = ReplayEngine.replay(inv)

    # Assert deterministic equality
    assert recon1.state_digest == recon2.state_digest
    assert recon1.dfa_state == recon2.dfa_state
    assert len(recon1.evidence) == len(recon2.evidence) == 1
    assert recon1.evidence[0].id == "ev-det-1"
    assert "target.com" in [e.name for e in recon1.entities.values()]

    core.shutdown()


def test_replay_to_sequence_n_time_travel(tmp_path):
    """Verify time-travel state query at sequence N accurately isolates state to that sequence."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Time Travel Sequence Test", targets=["target.com"])

    # Step 1: Add entity
    inv.add_entity("domain", "target.com")
    seq1_entry = inv.case_manager.journal.entries[-1]

    # Step 2: Add hypothesis
    hyp = inv.create_hypothesis("Target domain is active", initial_confidence=0.6)
    seq2_entry = inv.case_manager.journal.entries[-1]

    # Time travel to sequence of Step 1 (before hypothesis existed)
    recon_seq1 = core.query_historical_state(inv.id, sequence=seq1_entry.sequence)
    assert len(recon_seq1.hypotheses) == 0
    assert len(recon_seq1.entities) == 1

    # Time travel to sequence of Step 2
    recon_seq2 = core.query_historical_state(inv.id, sequence=seq2_entry.sequence)
    assert len(recon_seq2.hypotheses) == 1
    assert hyp.id in recon_seq2.hypotheses

    core.shutdown()


def test_replay_from_snapshot_checkpoint(tmp_path):
    """Verify replay accelerated by snapshot checkpoint reproduces exact historical state."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Checkpoint Test", targets=["alpha.com"])
    inv.add_entity("domain", "alpha.com")

    # Capture Snapshot 1
    snap1 = inv.capture_snapshot(trigger="checkpoint_alpha")

    # Add further mutation
    inv.add_entity("ip", "2.2.2.2")

    # Replay from checkpoint 1
    recon_checkpoint = ReplayEngine.replay(inv, from_snapshot=snap1.sequence)

    assert recon_checkpoint.source_checkpoint_sequence == snap1.sequence
    assert len(recon_checkpoint.entities) == 2
    assert "alpha.com" in [e.name for e in recon_checkpoint.entities.values()]
    assert "2.2.2.2" in [e.name for e in recon_checkpoint.entities.values()]

    core.shutdown()


def test_replay_read_only_guarantee(tmp_path):
    """Verify replay does not mutate the live investigation or case state."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Read Only Guarantee Test", targets=["target.com"])
    original_target_count = len(inv.targets)
    original_entity_count = len(inv.entities)
    original_journal_count = len(inv.case_manager.journal.entries)

    # Execute replay
    recon = core.replay_investigation(inv.id)

    # Modify reconstructed object
    recon.entities["fake-entity"] = None
    recon.evidence.append("fake-evidence")

    # Verify live investigation is strictly untouched
    assert len(inv.targets) == original_target_count
    assert len(inv.entities) == original_entity_count
    assert len(inv.case_manager.journal.entries) == original_journal_count

    core.shutdown()


def test_replay_bounds_validation(tmp_path):
    """Verify replay raises ReplayBoundsError when sequence is out of range."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Bounds Test", targets=["target.com"])

    with pytest.raises(ReplayBoundsError):
        core.query_historical_state(inv.id, sequence=-1)

    with pytest.raises(ReplayBoundsError):
        core.query_historical_state(inv.id, sequence=99999)

    core.shutdown()


def test_explain_progression_between_sequences(tmp_path):
    """Verify explain_progression generates human-readable trace of events between sequences."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Progression Test", targets=["target.com"])
    inv.add_entity("domain", "target.com")

    hyp = inv.create_hypothesis("Server is operational")

    report = core.explain_case_progression(inv.id, from_sequence=1, to_sequence=len(inv.case_manager.journal.entries))

    assert report.is_valid is True
    assert len(report.explanation_steps) >= 1
    assert any("Server is operational" in step for step in report.explanation_steps)

    core.shutdown()
