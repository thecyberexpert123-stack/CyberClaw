"""Tests for Knowledge Views, neighbor queries, bounded traversal, explanation, and planning gap discovery."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import pytest

from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.models import (
    EdgeStatus,
    KnowledgeNodeType,
    RelationshipType,
    utc_now,
)
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.queries import (
    CurrentKnowledgeView,
    HistoricalKnowledgeView,
    KnowledgeQueryEngine,
)
from cyberclaw.knowledge.traversal import traverse


def test_current_vs_historical_views():
    """Verify CurrentKnowledgeView filters out invalidated edges while HistoricalKnowledgeView reconstructs them."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-views-01")
    t1 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 9, 24, 11, 0, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)

    n1 = KnowledgeNode(node_id="n1", node_type="ENTITY", investigation_id="inv-views-01", valid_from=t1).seal()
    n2 = KnowledgeNode(node_id="n2", node_type="ENTITY", investigation_id="inv-views-01", valid_from=t1).seal()
    graph.add_node(n1)
    graph.add_node(n2)

    e1 = KnowledgeEdge(
        edge_id="e1",
        source_node_id="n1",
        target_node_id="n2",
        investigation_id="inv-views-01",
        valid_from=t1,
        valid_until=t2,
        status=EdgeStatus.INVALIDATED,
    ).seal()
    graph.add_edge(e1)

    # Current view: e1 is invalidated and past its valid_until -> should NOT be active
    curr_view = graph.get_current_view()
    assert curr_view.get_edge("e1") is None
    assert len(curr_view.neighbors("n1")) == 0

    # Historical view at t1 + 30m: e1 was valid
    hist_view = graph.get_historical_view_at_time(t1 + timedelta(minutes=30))
    assert hist_view.get_edge("e1") is not None
    assert len(hist_view.neighbors("n1")) == 1


def test_neighbor_query_filtering():
    """Verify neighbors retrieves adjacent nodes with optional relationship filtering."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-01")
    n_center = KnowledgeNode(node_id="center", node_type="ENTITY", investigation_id="inv-01").seal()
    n_child1 = KnowledgeNode(node_id="child1", node_type="ENTITY", investigation_id="inv-01").seal()
    n_child2 = KnowledgeNode(node_id="child2", node_type="ENTITY", investigation_id="inv-01").seal()

    graph.add_node(n_center)
    graph.add_node(n_child1)
    graph.add_node(n_child2)

    e1 = KnowledgeEdge(
        edge_id="e-assoc",
        source_node_id="center",
        target_node_id="child1",
        relationship_type=RelationshipType.ASSOCIATED_WITH.value,
        investigation_id="inv-01",
    ).seal()
    e2 = KnowledgeEdge(
        edge_id="e-dep",
        source_node_id="center",
        target_node_id="child2",
        relationship_type=RelationshipType.DEPENDS_ON.value,
        investigation_id="inv-01",
    ).seal()

    graph.add_edge(e1)
    graph.add_edge(e2)

    all_neighbors = KnowledgeQueryEngine.neighbors(graph, "center")
    assert len(all_neighbors) == 2

    filtered_dep = KnowledgeQueryEngine.neighbors(graph, "center", relationship_type="DEPENDS_ON")
    assert len(filtered_dep) == 1
    assert filtered_dep[0].node_id == "child2"


def test_bounded_traversal_multi_hop_and_cycle_prevention():
    """Verify traverse safely explores up to specified depth and terminates on cycles."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-01")
    # Triangle cycle: A -> B -> C -> A
    na = KnowledgeNode(node_id="A", node_type="ENTITY", investigation_id="inv-01").seal()
    nb = KnowledgeNode(node_id="B", node_type="ENTITY", investigation_id="inv-01").seal()
    nc = KnowledgeNode(node_id="C", node_type="ENTITY", investigation_id="inv-01").seal()
    nd = KnowledgeNode(node_id="D", node_type="ENTITY", investigation_id="inv-01").seal()

    for n in (na, nb, nc, nd):
        graph.add_node(n)

    graph.add_edge(KnowledgeEdge(edge_id="e1", source_node_id="A", target_node_id="B", investigation_id="inv-01").seal())
    graph.add_edge(KnowledgeEdge(edge_id="e2", source_node_id="B", target_node_id="C", investigation_id="inv-01").seal())
    graph.add_edge(KnowledgeEdge(edge_id="e3", source_node_id="C", target_node_id="A", investigation_id="inv-01").seal())
    graph.add_edge(KnowledgeEdge(edge_id="e4", source_node_id="C", target_node_id="D", investigation_id="inv-01").seal())

    # Depth 1 from A (outbound)
    res_d1 = traverse(graph, "A", depth=1, direction="out")
    assert [n.node_id for n in res_d1] == ["B"]

    # Depth 2 from A (outbound) -> B, C
    res_d2 = traverse(graph, "A", depth=2, direction="out")
    assert {n.node_id for n in res_d2} == {"B", "C"}

    # Depth 3 from A (outbound) -> B, C, D (cycle back to A is gracefully prevented)
    res_d3 = traverse(graph, "A", depth=3, direction="out")
    assert {n.node_id for n in res_d3} == {"B", "C", "D"}


def test_directional_traversal_control():
    """Verify traversal direction ('out', 'in', 'both') is strictly honored."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-01")
    n1 = KnowledgeNode(node_id="n1", node_type="ENTITY", investigation_id="inv-01").seal()
    n2 = KnowledgeNode(node_id="n2", node_type="ENTITY", investigation_id="inv-01").seal()
    n3 = KnowledgeNode(node_id="n3", node_type="ENTITY", investigation_id="inv-01").seal()

    for n in (n1, n2, n3):
        graph.add_node(n)

    # n1 -> n2 and n3 -> n2
    graph.add_edge(KnowledgeEdge(edge_id="e1", source_node_id="n1", target_node_id="n2", investigation_id="inv-01").seal())
    graph.add_edge(KnowledgeEdge(edge_id="e2", source_node_id="n3", target_node_id="n2", investigation_id="inv-01").seal())

    # Traversal from n2
    out_from_n2 = traverse(graph, "n2", depth=1, direction="out")
    assert len(out_from_n2) == 0  # No outgoing edges from n2

    in_to_n2 = traverse(graph, "n2", depth=1, direction="in")
    assert {n.node_id for n in in_to_n2} == {"n1", "n3"}

    both_n2 = traverse(graph, "n2", depth=1, direction="both")
    assert {n.node_id for n in both_n2} == {"n1", "n3"}


def test_supporting_and_contradicting_evidence_queries():
    """Verify supporting_evidence and contradicting_evidence retrieve linked evidence IDs."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-01")
    hyp = KnowledgeNode(node_id="hyp-c2", node_type="HYPOTHESIS", investigation_id="inv-01").seal()
    ev_supp = KnowledgeNode(node_id="ev-pcap", node_type="EVIDENCE", investigation_id="inv-01").seal()
    ev_contra = KnowledgeNode(node_id="ev-sinkhole", node_type="EVIDENCE", investigation_id="inv-01").seal()

    for n in (hyp, ev_supp, ev_contra):
        graph.add_node(n)

    edge_supp = KnowledgeEdge(
        edge_id="e-supp",
        source_node_id="ev-pcap",
        target_node_id="hyp-c2",
        relationship_type="SUPPORTS",
        supporting_evidence_ids=["ev-pcap"],
        investigation_id="inv-01",
    ).seal()
    edge_contra = KnowledgeEdge(
        edge_id="e-contra",
        source_node_id="ev-sinkhole",
        target_node_id="hyp-c2",
        relationship_type="CONTRADICTS",
        refuting_evidence_ids=["ev-sinkhole"],
        investigation_id="inv-01",
    ).seal()

    graph.add_edge(edge_supp)
    graph.add_edge(edge_contra)

    supp = KnowledgeQueryEngine.supporting_evidence(graph, "hyp-c2")
    contra = KnowledgeQueryEngine.contradicting_evidence(graph, "hyp-c2")

    assert "ev-pcap" in supp
    assert "ev-sinkhole" in contra


def test_knowledge_node_and_edge_explanations():
    """Verify explain_node and explain_edge produce transparent factual audits without natural language hallucination."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-01")
    node = KnowledgeNode(
        node_id="node-apex",
        node_type="ENTITY",
        label="C2-Apex",
        investigation_id="inv-01",
        metadata={"confidence": 0.88},
    ).seal()
    graph.add_node(node)

    explanation = KnowledgeQueryEngine.explain_node(graph, "node-apex")
    assert explanation.target_id == "node-apex"
    assert explanation.target_type == "ENTITY"
    assert explanation.claim == "C2-Apex"
    assert explanation.confidence_score == 0.88
    assert "created_at" in explanation.temporal_validity


def test_find_knowledge_gaps_for_adaptive_planning():
    """Verify find_knowledge_gaps detects uncorroborated hypotheses, inferences, and active contradictions."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-01")

    # 1. Uncorroborated hypothesis
    hyp = KnowledgeNode(
        node_id="hyp-unsupported",
        node_type="HYPOTHESIS",
        label="Host runs trojan",
        investigation_id="inv-01",
    ).seal()
    graph.add_node(hyp)

    # 2. Contradiction edge between nodes
    na = KnowledgeNode(node_id="na", node_type="ENTITY", investigation_id="inv-01").seal()
    nb = KnowledgeNode(node_id="nb", node_type="ENTITY", investigation_id="inv-01").seal()
    graph.add_node(na)
    graph.add_node(nb)

    contra_edge = KnowledgeEdge(
        edge_id="e-unresolved",
        source_node_id="na",
        target_node_id="nb",
        relationship_type="CONTRADICTS",
        status=EdgeStatus.ACTIVE,
        investigation_id="inv-01",
    ).seal()
    graph.add_edge(contra_edge)

    gaps = KnowledgeQueryEngine.find_knowledge_gaps(graph)
    assert len(gaps) >= 2
    types = {g.uncertainty_type for g in gaps}
    assert "MISSING_SUPPORTING_EVIDENCE" in types
    assert "UNRESOLVED_CONTRADICTION" in types


def test_query_case_graph_filtering():
    """Verify query_case_graph isolates nodes by case_id."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-multi-case")
    n_c1 = KnowledgeNode(node_id="n-case1", node_type="ENTITY", investigation_id="inv-1", case_id="case-100").seal()
    n_c2 = KnowledgeNode(node_id="n-case2", node_type="ENTITY", investigation_id="inv-1", case_id="case-200").seal()
    graph.add_node(n_c1)
    graph.add_node(n_c2)

    case1_nodes = KnowledgeQueryEngine.query_case_graph(graph, "case-100")
    assert len(case1_nodes) == 1
    assert case1_nodes[0].node_id == "n-case1"


def test_explain_edge_lineage_and_authorizations():
    """Verify explain_edge extracts provenance, specialist, capability, and policy authorization IDs."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-explain")
    n1 = KnowledgeNode(node_id="src", node_type="ENTITY", investigation_id="inv-explain").seal()
    n2 = KnowledgeNode(node_id="tgt", node_type="ENTITY", investigation_id="inv-explain").seal()
    graph.add_node(n1)
    graph.add_node(n2)

    edge = KnowledgeEdge(
        edge_id="e-auth",
        source_node_id="src",
        target_node_id="tgt",
        relationship_type="ASSOCIATED_WITH",
        originating_specialist="specialist.osint",
        capability_id="osint.dns_lookup",
        capability_version="1.2.0",
        authorization_decision_id="auth-dec-999",
        supporting_evidence_ids=["ev-test"],
        investigation_id="inv-explain",
    ).seal()
    graph.add_edge(edge)

    explanation = KnowledgeQueryEngine.explain_edge(graph, "e-auth")
    assert explanation.target_id == "e-auth"
    assert "specialist.osint" in explanation.specialists_involved
    assert "osint.dns_lookup@1.2.0" in explanation.capabilities_involved
    assert "auth-dec-999" in explanation.policy_authorizations
    assert explanation.supporting_evidence_ids == ["ev-test"]
