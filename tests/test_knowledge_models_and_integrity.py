"""Tests for KnowledgeNode, KnowledgeEdge, temporal fields, and deterministic integrity hashing."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.errors import KnowledgeIntegrityError
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.models import (
    EdgeStatus,
    KnowledgeNodeType,
    RelationshipType,
    utc_now,
)
from cyberclaw.knowledge.nodes import KnowledgeNode


def test_knowledge_node_creation_and_defaults():
    """Verify KnowledgeNode initializes with generic category, timestamps, and default version."""
    now = utc_now()
    node = KnowledgeNode(
        node_type=KnowledgeNodeType.ENTITY.value,
        label="Host-Alpha",
        investigation_id="inv-001",
        case_id="case-001",
        created_at=now,
        valid_from=now,
    ).seal()

    assert node.node_id is not None
    assert node.node_type == "ENTITY"
    assert node.label == "Host-Alpha"
    assert node.version == 1
    assert node.valid_until is None
    assert node.integrity_digest != ""
    assert node.verify_integrity() is True


def test_knowledge_edge_creation_and_defaults():
    """Verify KnowledgeEdge binds source and target nodes with epistemic nature and confidence."""
    now = utc_now()
    edge = KnowledgeEdge(
        source_node_id="node-1",
        target_node_id="node-2",
        relationship_type=RelationshipType.ASSOCIATED_WITH.value,
        investigation_id="inv-001",
        confidence=0.95,
        epistemic_nature="OBSERVATION",
        created_at=now,
        valid_from=now,
    ).seal()

    assert edge.edge_id is not None
    assert edge.source_node_id == "node-1"
    assert edge.target_node_id == "node-2"
    assert edge.relationship_type == "ASSOCIATED_WITH"
    assert edge.status == EdgeStatus.ACTIVE
    assert edge.confidence == 0.95
    assert edge.epistemic_nature == "OBSERVATION"
    assert edge.integrity_digest != ""
    assert edge.verify_integrity() is True


def test_node_digest_determinism_and_tamper_detection():
    """Verify calculate_node_digest is deterministic and detects field tampering."""
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    node1 = KnowledgeNode(
        node_id="n-100",
        node_type="ENTITY",
        label="Target",
        investigation_id="inv-001",
        created_at=now,
        valid_from=now,
        metadata={"os": "linux", "arch": "x86_64"},
    ).seal()

    node2 = KnowledgeNode(
        node_id="n-100",
        node_type="ENTITY",
        label="Target",
        investigation_id="inv-001",
        created_at=now,
        valid_from=now,
        metadata={"arch": "x86_64", "os": "linux"},  # Reordered dictionary keys
    ).seal()

    assert node1.integrity_digest == node2.integrity_digest

    # Tampering with metadata invalidates integrity check
    node1.metadata["compromised"] = True
    assert node1.verify_integrity() is False


def test_edge_digest_determinism_and_tamper_detection():
    """Verify calculate_edge_digest is deterministic and detects field tampering."""
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    edge1 = KnowledgeEdge(
        edge_id="e-200",
        source_node_id="n-1",
        target_node_id="n-2",
        relationship_type="SUPPORTS",
        investigation_id="inv-001",
        supporting_evidence_ids=["ev-b", "ev-a"],  # Unsorted
        created_at=now,
        valid_from=now,
    ).seal()

    edge2 = KnowledgeEdge(
        edge_id="e-200",
        source_node_id="n-1",
        target_node_id="n-2",
        relationship_type="SUPPORTS",
        investigation_id="inv-001",
        supporting_evidence_ids=["ev-a", "ev-b"],  # Sorted
        created_at=now,
        valid_from=now,
    ).seal()

    assert edge1.integrity_digest == edge2.integrity_digest

    # Tampering with confidence invalidates integrity check
    edge1.confidence = 0.5
    assert edge1.verify_integrity() is False


def test_node_temporal_validity_filtering():
    """Verify is_valid_at evaluates historical validity periods accurately."""
    t0 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    t1 = datetime(2026, 9, 24, 11, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 24, 13, 0, 0, tzinfo=timezone.utc)

    node = KnowledgeNode(
        node_id="n-temp",
        node_type="ENTITY",
        investigation_id="inv-001",
        valid_from=t1,
        valid_until=t2,
    )

    assert node.is_valid_at(t0) is False  # Before validity window
    assert node.is_valid_at(t1) is True   # Start boundary
    assert node.is_valid_at(t1 + timedelta(minutes=30)) is True
    assert node.is_valid_at(t2) is False  # End boundary (exclusive)
    assert node.is_valid_at(t3) is False  # After validity window


def test_edge_temporal_validity_filtering():
    """Verify edge is_valid_at evaluates validity periods accurately."""
    t1 = datetime(2026, 9, 24, 11, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    edge = KnowledgeEdge(
        edge_id="e-temp",
        source_node_id="n-1",
        target_node_id="n-2",
        investigation_id="inv-001",
        valid_from=t1,
        valid_until=t2,
    )

    assert edge.is_valid_at(t1 - timedelta(seconds=1)) is False
    assert edge.is_valid_at(t1) is True
    assert edge.is_valid_at(t2) is False


def test_node_supersession_lifecycle():
    """Verify superseding a node updates version, closes previous valid_until, and chains provenance."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-001")
    old_node = KnowledgeNode(
        node_id="n-target",
        node_type="ENTITY",
        label="Service-v1",
        investigation_id="inv-001",
    ).seal()
    graph.add_node(old_node)

    new_node_spec = KnowledgeNode(
        node_id="n-target-v2",
        node_type="ENTITY",
        label="Service-v2",
        investigation_id="inv-001",
    )

    ret_old, ret_new = graph.supersede_node("n-target", new_node_spec)
    assert ret_old.valid_until is not None
    assert ret_new.version == 2
    assert ret_new.provenance_references == ["n-target"]
    assert ret_new.is_valid_at(utc_now()) is True
    assert ret_old.is_valid_at(utc_now()) is False


def test_graph_digest_order_independence():
    """Verify graph digest remains identical regardless of insertion order."""
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    n_a = KnowledgeNode(node_id="node-a", node_type="ENTITY", investigation_id="inv-1", created_at=now, valid_from=now).seal()
    n_b = KnowledgeNode(node_id="node-b", node_type="ENTITY", investigation_id="inv-1", created_at=now, valid_from=now).seal()
    n_c = KnowledgeNode(node_id="node-c", node_type="ENTITY", investigation_id="inv-1", created_at=now, valid_from=now).seal()

    e_ab = KnowledgeEdge(edge_id="e-1", source_node_id="node-a", target_node_id="node-b", investigation_id="inv-1", created_at=now, valid_from=now).seal()
    e_bc = KnowledgeEdge(edge_id="e-2", source_node_id="node-b", target_node_id="node-c", investigation_id="inv-1", created_at=now, valid_from=now).seal()

    # Graph 1: Insert A, B, C, e_ab, e_bc
    g1 = TemporalKnowledgeGraph(investigation_id="inv-1")
    g1.add_node(n_a)
    g1.add_node(n_b)
    g1.add_node(n_c)
    g1.add_edge(e_ab)
    g1.add_edge(e_bc)

    # Graph 2: Insert C, B, A, e_bc, e_ab
    g2 = TemporalKnowledgeGraph(investigation_id="inv-1")
    g2.add_node(n_c)
    g2.add_node(n_b)
    g2.add_node(n_a)
    g2.add_edge(e_bc)
    g2.add_edge(e_ab)

    assert g1.calculate_graph_digest() == g2.calculate_graph_digest()
    assert g1.verify_graph_integrity() is True
    assert g2.verify_graph_integrity() is True
