"""Tests for temporal interval semantics, contradiction classification, provenance, and source independence."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from cyberclaw.evidence.models import Evidence, Source
from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.models import TemporalContradictionType
from cyberclaw.knowledge.provenance import (
    KnowledgeProvenanceRecord,
    build_provenance_chain,
    calculate_source_independence,
)
from cyberclaw.knowledge.temporal import (
    classify_temporal_contradiction,
    intervals_overlap,
    is_active,
)


def test_intervals_overlap_evaluation():
    """Verify intervals_overlap detects overlapping and non-overlapping time spans."""
    t0 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 24, 11, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 24, 13, 0, 0, tzinfo=timezone.utc)

    # Disjoint intervals: [t0, t1] and [t2, t3]
    assert intervals_overlap(t0, t1, t2, t3) is False

    # Overlapping intervals: [t0, t2] and [t1, t3]
    assert intervals_overlap(t0, t2, t1, t3) is True

    # Open-ended interval: [t1, None] and [t0, t2]
    assert intervals_overlap(t1, None, t0, t2) is True

    # Contiguous abutting boundary: [t0, t1] and [t1, t2] -> False (exclusive end)
    assert intervals_overlap(t0, t1, t1, t2) is False


def test_classify_temporal_contradiction_temporal_change():
    """Verify non-overlapping intervals are classified as TEMPORAL_CHANGE rather than failure."""
    t1 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 24, 11, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    edge_past = KnowledgeEdge(
        edge_id="e-past",
        source_node_id="domain-1",
        target_node_id="ip-old",
        relationship_type="RESOLVES_TO",
        investigation_id="inv-1",
        valid_from=t1,
        valid_until=t2,
    )
    edge_present = KnowledgeEdge(
        edge_id="e-present",
        source_node_id="domain-1",
        target_node_id="ip-new",
        relationship_type="RESOLVES_TO",
        investigation_id="inv-1",
        valid_from=t2,
        valid_until=t3,
    )

    kind, explanation = classify_temporal_contradiction(edge_past, edge_present)
    assert kind == TemporalContradictionType.TEMPORAL_CHANGE
    assert "transitioned over time" in explanation


def test_classify_temporal_contradiction_simultaneous():
    """Verify overlapping intervals asserting competing claims are classified as SIMULTANEOUS_CONTRADICTION."""
    t1 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    edge_a = KnowledgeEdge(
        edge_id="e-claim-a",
        source_node_id="host-1",
        target_node_id="status-clean",
        investigation_id="inv-1",
        created_at=t1,
        valid_from=t1,
        valid_until=t2,
    )
    edge_b = KnowledgeEdge(
        edge_id="e-claim-b",
        source_node_id="host-1",
        target_node_id="status-infected",
        investigation_id="inv-1",
        created_at=t1 + timedelta(minutes=5),
        valid_from=t1,
        valid_until=t2,
    )

    kind, explanation = classify_temporal_contradiction(edge_a, edge_b)
    assert kind == TemporalContradictionType.SIMULTANEOUS_CONTRADICTION
    assert "competing assertions concurrently" in explanation


def test_classify_temporal_contradiction_stale_information():
    """Verify an old edge without update is identified as STALE_INFORMATION against a newer observation."""
    t_old = datetime(2026, 9, 20, 10, 0, 0, tzinfo=timezone.utc)
    t_new = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)

    edge_stale = KnowledgeEdge(
        edge_id="e-stale",
        source_node_id="host-1",
        target_node_id="c2",
        investigation_id="inv-1",
        created_at=t_old,
        valid_from=t_old,
    )
    edge_fresh = KnowledgeEdge(
        edge_id="e-fresh",
        source_node_id="host-1",
        target_node_id="sinkhole",
        investigation_id="inv-1",
        created_at=t_new,
        valid_from=t_new,
    )

    kind, explanation = classify_temporal_contradiction(edge_stale, edge_fresh, stale_threshold_seconds=86400)
    assert kind == TemporalContradictionType.STALE_INFORMATION
    assert "stale information" in explanation


def test_provenance_record_and_backward_chain():
    """Verify build_provenance_chain traces multi-hop causal lineage backwards accurately."""
    t0 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    p1 = KnowledgeProvenanceRecord(
        provenance_id="prov-1",
        target_id="node-raw",
        originating_specialist="specialist.osint",
        capability_id="osint.dns",
        timestamp=t0,
    )
    p2 = KnowledgeProvenanceRecord(
        provenance_id="prov-2",
        target_id="edge-assoc",
        originating_specialist="specialist.network",
        capability_id="net.probe",
        parent_provenance_ids=["prov-1"],
        timestamp=t0 + timedelta(minutes=5),
    )
    p3 = KnowledgeProvenanceRecord(
        provenance_id="prov-3",
        target_id="hyp-c2",
        originating_specialist="specialist.planner",
        capability_id="planner.reason",
        parent_provenance_ids=["prov-2"],
        timestamp=t0 + timedelta(minutes=10),
    )

    records = {"prov-1": p1, "prov-2": p2, "prov-3": p3}
    chain = build_provenance_chain(records, ["prov-3"])
    assert len(chain) == 3
    assert [p.provenance_id for p in chain] == ["prov-1", "prov-2", "prov-3"]


def test_source_independence_distinct_sources():
    """Verify calculate_source_independence correctly reports count for truly distinct sources."""
    ev1 = Evidence(
        id="ev-1",
        type="dns_record",
        subject="test.org",
        value={"ip": "1.2.3.4"},
        source=Source(type="passive_dns", name="Farsight_DNS"),
    )
    ev2 = Evidence(
        id="ev-2",
        type="scan_report",
        subject="test.org",
        value={"port": 80},
        source=Source(type="active_probe", name="Shodan_Scanner"),
    )

    count, roots = calculate_source_independence(["ev-1", "ev-2"], [ev1, ev2])
    assert count == 2
    assert "Farsight_DNS" in roots
    assert "Shodan_Scanner" in roots


def test_source_independence_shared_source_rejection():
    """Verify calculate_source_independence clusters items sharing same underlying source into 1."""
    ev1 = Evidence(
        id="ev-1",
        type="feed",
        subject="bad.org",
        value={"threat": True},
        source=Source(type="threat_intel", name="VirusTotal"),
    )
    ev2 = Evidence(
        id="ev-2",
        type="feed",
        subject="bad.org",
        value={"threat": True},
        source=Source(type="threat_intel", name="virustotal"),  # Case insensitive duplicate
    )
    ev3 = Evidence(
        id="ev-3",
        type="feed",
        subject="bad.org",
        value={"threat": True},
        source=Source(type="threat_intel", name="VT_Secondary"),
        metadata={"same_source_as": "ev-1"},  # Explicit source alias
    )

    count, roots = calculate_source_independence(["ev-1", "ev-2", "ev-3"], [ev1, ev2, ev3])
    assert count == 1
    assert len(roots) == 1


def test_source_independence_derived_inference_clustering():
    """Verify a pure inference derived from evidence is clustered with its ancestor evidence."""
    ev_obs = Evidence(
        id="ev-obs",
        type="measurement",
        subject="ip-1",
        value={"latency": 12},
        source=Source(type="telemetry", name="HostMonitor"),
        metadata={"finding_nature": "OBSERVATION"},
    )
    ev_inf = Evidence(
        id="ev-inf",
        type="derived_state",
        subject="ip-1",
        value={"status": "congested"},
        source=Source(type="inference", name="RuleEngine"),
        metadata={"finding_nature": "INFERENCE", "derived_from_evidence_ids": ["ev-obs"]},
    )

    count, roots = calculate_source_independence(["ev-obs", "ev-inf"], [ev_obs, ev_inf])
    assert count == 1
    assert "HostMonitor" in roots
