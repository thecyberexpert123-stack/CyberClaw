"""Tests for SnapshotManager, point-in-time preservation, and delta calculations."""

import pytest
from cyberclaw.evidence.models import Evidence
from cyberclaw.investigation import Investigation
from cyberclaw.types import Source


def test_snapshot_point_in_time_preservation():
    """Verify modifying investigation after snapshot does NOT mutate previously captured snapshot."""
    inv = Investigation(id="inv-snap-test", title="Snapshot Preservation Test", targets=["target.com"])
    inv.add_entity("domain", "target.com")

    # Capture Snapshot 1
    snap1 = inv.capture_snapshot(trigger="initial_target")
    assert snap1.sequence == 1
    assert "target.com" in [e.name for e in snap1.entities.values()]
    assert len(snap1.entities) == 1

    # Mutate investigation state: add an IP entity and hypothesis
    inv.add_entity("ip", "1.2.3.4")
    inv.create_hypothesis("Target infrastructure resolves to 1.2.3.4")

    # Snapshot 1 remains immutable
    assert len(snap1.entities) == 1
    assert "1.2.3.4" not in [e.name for e in snap1.entities.values()]
    assert len(snap1.hypotheses) == 0

    # Capture Snapshot 2
    snap2 = inv.capture_snapshot(trigger="ip_discovered")
    assert snap2.sequence == 2
    assert len(snap2.entities) == 2
    assert len(snap2.hypotheses) == 1


def test_snapshot_comparison_and_delta():
    """Verify SnapshotDelta accurately tracks additions and state shifts across cycles."""
    inv = Investigation(id="inv-delta-test", title="Delta Test", targets=["corp.net"])
    inv.add_entity("domain", "corp.net")

    # Snapshot 1: baseline
    snap1 = inv.capture_snapshot(trigger="baseline")

    # Mutation: add evidence, new entity, and hypothesis
    ev = Evidence(
        id="ev-delta-1",
        type="osint.dns_record",
        subject="corp.net",
        value={"ip": "10.0.0.99"},
        source=Source(type="mock", name="ns"),
    )
    inv.evidence_store.add(ev)
    inv.add_entity("ip", "10.0.0.99")
    hyp = inv.create_hypothesis("Host is reachable")

    # Snapshot 2: post-enrichment
    snap2 = inv.capture_snapshot(trigger="post_dns")

    # Compute delta
    delta = inv.compare_snapshots(snap1, snap2)

    assert delta.from_sequence == 1
    assert delta.to_sequence == 2
    assert delta.added_evidence_ids == ["ev-delta-1"]
    assert len(delta.added_entities) == 1
    assert any("Host is reachable" in str(h) for h in delta.hypothesis_changes.values())


def test_explain_state_at_snapshot():
    """Verify explain_state_at provides human-readable breakdown of point-in-time posture."""
    inv = Investigation(id="inv-explain", title="Explain State Test", targets=["victim.org"])
    inv.add_entity("domain", "victim.org")
    inv.create_hypothesis("Compromised domain victim.org", initial_confidence=0.75)

    snap = inv.capture_snapshot(trigger="hypothesis_formulation")

    explanation = inv.explain_state_at(snap.sequence)

    assert explanation["sequence"] == 1
    assert explanation["trigger"] == "hypothesis_formulation"
    assert explanation["integrity_valid"] is True
    assert any("victim.org" in e["name"] for e in explanation["entities"].values())
    assert any("Compromised domain" in h["statement"] for h in explanation["hypotheses"].values())
