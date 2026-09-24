"""Tests for governed graph mutations, PolicyEngine integration, branch quarantine, and consistency diagnostics."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest

from cyberclaw.case.models import JournalEntryType
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.knowledge.consistency import KnowledgeConsistencyEngine
from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.errors import (
    KnowledgeAuthorizationError,
    KnowledgeBranchLeakError,
)
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.models import (
    ConsistencySeverity,
    EdgeStatus,
    GraphMutationType,
    utc_now,
)
from cyberclaw.knowledge.mutations import (
    GraphMutationPipeline,
    GraphMutationRequest,
)
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.policy.models import (
    ActorRole,
    Policy,
    PolicyEffect,
    PolicyRule,
)


def test_mutation_add_node_governed_execution(tmp_path: Path):
    """Verify ADD_NODE executes through governance and appends a CaseJournal entry."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Mutation Test 1")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    graph = core.get_knowledge_graph(inv.id)

    node = KnowledgeNode(
        node_id="n-gov-1",
        node_type="ENTITY",
        label="Target Host",
        investigation_id=inv.id,
    ).seal()

    req = GraphMutationRequest(
        mutation_type=GraphMutationType.ADD_NODE,
        investigation_id=inv.id,
        actor_id="specialist.osint",
        node=node,
    )

    res = core.mutate_knowledge_graph(inv.id, req)
    assert res.is_successful is True
    assert "n-gov-1" in res.affected_node_ids
    assert graph.get_node("n-gov-1") is not None

    # Verify Journal Entry
    journal_types = [e.entry_type for e in inv.case_manager.journal.entries]
    assert JournalEntryType.KNOWLEDGE_NODE_ADDED in journal_types


def test_mutation_add_and_invalidate_edge(tmp_path: Path):
    """Verify ADD_EDGE and INVALIDATE_EDGE mutate the graph and update edge status without deleting historical records."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Mutation Test 2")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    graph = core.get_knowledge_graph(inv.id)

    n1 = KnowledgeNode(node_id="n1", node_type="ENTITY", investigation_id=inv.id).seal()
    n2 = KnowledgeNode(node_id="n2", node_type="ENTITY", investigation_id=inv.id).seal()
    graph.add_node(n1)
    graph.add_node(n2)

    edge = KnowledgeEdge(
        edge_id="e-gov-1",
        source_node_id="n1",
        target_node_id="n2",
        investigation_id=inv.id,
    ).seal()

    # 1. ADD_EDGE
    req_add = GraphMutationRequest(
        mutation_type=GraphMutationType.ADD_EDGE,
        investigation_id=inv.id,
        actor_id="specialist.network",
        edge=edge,
    )
    res_add = core.mutate_knowledge_graph(inv.id, req_add)
    assert res_add.is_successful is True
    assert graph.get_edge("e-gov-1").status == EdgeStatus.ACTIVE

    # 2. INVALIDATE_EDGE
    req_inv = GraphMutationRequest(
        mutation_type=GraphMutationType.INVALIDATE_EDGE,
        investigation_id=inv.id,
        actor_id="specialist.network",
        target_id="e-gov-1",
        reason="Port 80 confirmed closed upon subsequent scan",
    )
    res_inv = core.mutate_knowledge_graph(inv.id, req_inv)
    assert res_inv.is_successful is True
    edge_after = graph.get_edge("e-gov-1")
    assert edge_after.status == EdgeStatus.INVALIDATED
    assert edge_after.valid_until is not None
    assert edge_after.metadata["invalidation_reason"] == "Port 80 confirmed closed upon subsequent scan"


def test_policy_engine_mutation_denial(tmp_path: Path):
    """Verify PolicyEngine denial strictly halts graph mutation without applying state changes."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register deny rule for graph_mutation
    deny_rule = PolicyRule(
        rule_id="rule.deny_mutation",
        name="Deny Graph Mutation",
        priority=1,
        effect=PolicyEffect.DENY,
        roles=[ActorRole.SPECIALIST],
        actions=["graph_mutation"],
        conditions={"allowed_case_stages": ["INVESTIGATE"]},
    )
    default_pol = core.policy_engine.registry.get_default_policy()
    default_pol.rules.insert(0, deny_rule)

    inv = core.create_investigation("Policy Block Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    graph = core.get_knowledge_graph(inv.id)

    node = KnowledgeNode(
        node_id="n-unauthorized",
        node_type="ENTITY",
        investigation_id=inv.id,
    ).seal()

    req = GraphMutationRequest(
        mutation_type=GraphMutationType.ADD_NODE,
        investigation_id=inv.id,
        actor_id="specialist.untrusted",
        node=node,
    )

    with pytest.raises(KnowledgeAuthorizationError) as exc:
        GraphMutationPipeline.apply_mutation(
            graph=graph,
            request=req,
            policy_engine=core.policy_engine,
            investigation=inv,
        )

    assert "PolicyEngine rejected graph mutation" in str(exc.value)
    assert graph.get_node("n-unauthorized") is None


def test_branch_quarantine_blocks_counterfactual_leak_to_authoritative_graph():
    """Verify counterfactual branch nodes and edges cannot enter an authoritative graph."""
    authoritative_graph = TemporalKnowledgeGraph(investigation_id="inv-auth", is_counterfactual=False)

    branch_node = KnowledgeNode(
        node_id="n-branch-sim",
        node_type="ENTITY",
        investigation_id="inv-auth",
        is_counterfactual=True,
        branch_id="branch-sim-01",
    ).seal()

    # Attempting to add counterfactual node directly raises KnowledgeBranchLeakError
    with pytest.raises(KnowledgeBranchLeakError):
        authoritative_graph.add_node(branch_node)

    # Attempting to apply via mutation pipeline also raises KnowledgeBranchLeakError
    req = GraphMutationRequest(
        mutation_type=GraphMutationType.ADD_NODE,
        investigation_id="inv-auth",
        actor_id="specialist.simulator",
        node=branch_node,
        is_counterfactual=True,
    )
    with pytest.raises(KnowledgeBranchLeakError):
        GraphMutationPipeline.apply_mutation(
            graph=authoritative_graph,
            request=req,
        )


def test_consistency_engine_detects_missing_node_references():
    """Verify consistency engine detects dangling edges referencing non-existent nodes."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-cons")
    n1 = KnowledgeNode(node_id="n1", node_type="ENTITY", investigation_id="inv-cons").seal()
    graph._nodes["n1"] = n1

    # Insert edge referencing missing target node "n-missing"
    dangling_edge = KnowledgeEdge(
        edge_id="e-dangle",
        source_node_id="n1",
        target_node_id="n-missing",
        investigation_id="inv-cons",
    ).seal()
    graph._edges["e-dangle"] = dangling_edge

    issues = KnowledgeConsistencyEngine.check_consistency(graph)
    assert len(issues) >= 1
    critical_issues = [i for i in issues if i.severity == ConsistencySeverity.CRITICAL]
    assert any(i.issue_type == "MISSING_TARGET_NODE" for i in critical_issues)


def test_consistency_engine_detects_temporal_interval_inversion():
    """Verify consistency engine flags temporal interval inversion where valid_until < valid_from."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-cons")
    t1 = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    t0 = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)

    inverted_node = KnowledgeNode(
        node_id="n-inverted",
        node_type="ENTITY",
        investigation_id="inv-cons",
        valid_from=t1,
        valid_until=t0,  # Earlier than valid_from!
    ).seal()
    graph._nodes["n-inverted"] = inverted_node

    issues = KnowledgeConsistencyEngine.check_consistency(graph)
    assert any(i.issue_type == "TEMPORAL_INTERVAL_INVERSION" for i in issues)


def test_consistency_engine_detects_prohibited_self_reference():
    """Verify consistency engine flags invalid directional self-referential edges."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-cons")
    node = KnowledgeNode(node_id="n-self", node_type="ENTITY", investigation_id="inv-cons").seal()
    graph._nodes["n-self"] = node

    self_edge = KnowledgeEdge(
        edge_id="e-self",
        source_node_id="n-self",
        target_node_id="n-self",
        relationship_type="DERIVED_FROM",  # Prohibited directional self-reference
        investigation_id="inv-cons",
    ).seal()
    graph._edges["e-self"] = self_edge

    issues = KnowledgeConsistencyEngine.check_consistency(graph)
    assert any(i.issue_type == "PROHIBITED_SELF_REFERENCE" for i in issues)


def test_consistency_engine_detects_integrity_digest_tampering():
    """Verify consistency engine detects nodes or edges whose integrity digests fail verification."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-cons")
    node = KnowledgeNode(node_id="n-tampered", node_type="ENTITY", investigation_id="inv-cons").seal()
    graph._nodes["n-tampered"] = node

    # Tamper with node
    node.metadata["secret_tamper"] = "unauthorized_change"

    issues = KnowledgeConsistencyEngine.check_consistency(graph)
    assert any(i.issue_type == "INTEGRITY_DIGEST_MISMATCH" for i in issues)


def test_mutation_supersede_node_governed(tmp_path: Path):
    """Verify SUPERSEDE_NODE creates versioned replacement and logs KNOWLEDGE_RELATIONSHIP_SUPERSEDED."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Supersede Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    graph = core.get_knowledge_graph(inv.id)

    old_n = KnowledgeNode(node_id="n-v1", node_type="ENTITY", label="Ver1", investigation_id=inv.id).seal()
    graph.add_node(old_n)

    new_n = KnowledgeNode(node_id="n-v2", node_type="ENTITY", label="Ver2", investigation_id=inv.id)

    req = GraphMutationRequest(
        mutation_type=GraphMutationType.SUPERSEDE_NODE,
        investigation_id=inv.id,
        actor_id="specialist.forensics",
        target_id="n-v1",
        node=new_n,
    )
    res = core.mutate_knowledge_graph(inv.id, req)
    assert res.is_successful is True
    assert "n-v1" in res.affected_node_ids
    assert "n-v2" in res.affected_node_ids

    journal_types = [e.entry_type for e in inv.case_manager.journal.entries]
    assert JournalEntryType.KNOWLEDGE_RELATIONSHIP_SUPERSEDED in journal_types


def test_consistency_engine_clean_graph_reports_no_critical_errors():
    """Verify a properly constructed graph produces no CRITICAL or ERROR diagnostics."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-clean")
    n1 = KnowledgeNode(node_id="clean-1", node_type="ENTITY", investigation_id="inv-clean").seal()
    n2 = KnowledgeNode(node_id="clean-2", node_type="ENTITY", investigation_id="inv-clean").seal()
    graph.add_node(n1)
    graph.add_node(n2)

    edge = KnowledgeEdge(
        edge_id="clean-e1",
        source_node_id="clean-1",
        target_node_id="clean-2",
        relationship_type="RELATED_TO",
        investigation_id="inv-clean",
    ).seal()
    graph.add_edge(edge)

    issues = KnowledgeConsistencyEngine.check_consistency(graph)
    severe_issues = [i for i in issues if i.severity in (ConsistencySeverity.CRITICAL, ConsistencySeverity.ERROR)]
    assert len(severe_issues) == 0
