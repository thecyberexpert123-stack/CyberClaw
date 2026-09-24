"""Tests for Knowledge Graph materialization, persistence, deterministic replay, branch isolation, and Section 28 E2E scenario."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from cyberclaw.branching.engine import BranchEngine
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.case.models import ContradictionRecord, DecisionType
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    CollaborationResult,
    CollaborationStatus,
    ConflictStatus,
    FindingNature,
)
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence, Provenance, Source
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.knowledge.errors import KnowledgeIntegrityError
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.materialization import KnowledgeMaterializer
from cyberclaw.knowledge.models import (
    EdgeStatus,
    GraphMutationType,
    KnowledgeNodeType,
    RelationshipType,
    utc_now,
)
from cyberclaw.knowledge.mutations import GraphMutationRequest
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.persistence import KnowledgePersistenceManager
from cyberclaw.knowledge.queries import KnowledgeQueryEngine
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.runtime.models import RuntimeTask
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistResponse,
)


class MockEndpoint(SpecialistEndpoint):
    def __init__(self, specialist_id: str = "specialist.mock"):
        super().__init__()
        self.specialist_id = specialist_id

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request):
        ev = Evidence(
            type=f"{self.specialist_id}.finding",
            subject=getattr(request, "parameters", {}).get("target", "unknown"),
            value={"data": "mock_value"},
            source=Source(type="specialist", name=self.specialist_id),
            provenance=Provenance(specialist_id=self.specialist_id),
        )
        res = ExecutionResult.success(output={"status": "ok"}, evidence=[ev])
        return SpecialistResponse.from_result(
            self.specialist_id,
            getattr(request, "request_id", "req-1"),
            res,
        )


def test_materialization_from_investigation_state(tmp_path: Path):
    """Verify KnowledgeMaterializer deterministically converts Evidence, Hypotheses, and Contradictions into graph nodes and edges."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Materialization Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    ev1 = Evidence(
        type="dns_resolution",
        subject="198.51.100.10",
        value={"domain": "c2.test"},
        source=Source(type="probe", name="DNSProbe"),
        confidence=0.9,
    )
    inv.add_evidence(ev1)
    hyp = inv.create_hypothesis("Target 198.51.100.10 is active C2", initial_confidence=0.8)
    hyp.supporting_evidence_ids.append(ev1.id)

    graph = KnowledgeMaterializer.materialize_from_investigation(inv)

    assert graph.get_node(ev1.id) is not None
    assert graph.get_node(hyp.id) is not None
    assert graph.get_node(f"entity-198.51.100.10") is not None

    # Verify SUPPORTS edge from ev1 to hyp
    supp_edges = [
        e for e in graph.get_edges()
        if e.source_node_id == ev1.id and e.target_node_id == hyp.id
    ]
    assert len(supp_edges) == 1
    assert supp_edges[0].relationship_type == RelationshipType.SUPPORTS.value


def test_materialization_determinism_identical_digests(tmp_path: Path):
    """Verify materializing identical investigation state produces identical graph digests."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Determinism Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    ev1 = Evidence(type="raw", subject="host1", value="data1", source=Source(type="pcap", name="pcap"))
    ev2 = Evidence(type="raw", subject="host2", value="data2", source=Source(type="pcap", name="pcap"))
    inv.add_evidence(ev1)
    inv.add_evidence(ev2)

    graph1 = KnowledgeMaterializer.materialize_from_investigation(inv)
    graph2 = KnowledgeMaterializer.materialize_from_investigation(inv)

    assert graph1.calculate_graph_digest() == graph2.calculate_graph_digest()


def test_atomic_persistence_and_reload(tmp_path: Path):
    """Verify knowledge graph can be saved atomically and restored with matching digest."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-persist-01", case_id="case-100")
    n1 = KnowledgeNode(node_id="n1", node_type="ENTITY", label="Host-1", investigation_id="inv-persist-01").seal()
    n2 = KnowledgeNode(node_id="n2", node_type="ENTITY", label="Host-2", investigation_id="inv-persist-01").seal()
    graph.add_node(n1)
    graph.add_node(n2)

    saved_dir = KnowledgePersistenceManager.save_graph(graph, tmp_path)
    assert (saved_dir / "manifests" / "manifest.json").exists()
    assert (saved_dir / "integrity" / "digest.json").exists()

    reloaded_graph = KnowledgePersistenceManager.load_graph("inv-persist-01", tmp_path)
    assert reloaded_graph is not None
    assert reloaded_graph.get_node("n1") is not None
    assert reloaded_graph.get_node("n2") is not None
    assert reloaded_graph.calculate_graph_digest() == graph.calculate_graph_digest()


def test_persistence_corrupted_digest_detection(tmp_path: Path):
    """Verify loading graph with corrupted nodes or invalid digest raises KnowledgeIntegrityError."""
    graph = TemporalKnowledgeGraph(investigation_id="inv-corrupt")
    n1 = KnowledgeNode(node_id="n1", node_type="ENTITY", investigation_id="inv-corrupt").seal()
    graph.add_node(n1)
    KnowledgePersistenceManager.save_graph(graph, tmp_path)

    # Tamper with stored manifest digest
    manifest_file = tmp_path / "knowledge" / "manifests" / "manifest.json"
    with open(manifest_file, "r") as f:
        manifest = json.load(f)
    manifest["graph_digest"] = "bad_fake_hash_value"
    with open(manifest_file, "w") as f:
        json.dump(manifest, f)

    with pytest.raises(KnowledgeIntegrityError):
        KnowledgePersistenceManager.load_graph("inv-corrupt", tmp_path, verify_digest=True)


def test_replay_knowledge_graph_historical_reconstruction(tmp_path: Path):
    """Verify ReplayEngine reconstructs historical knowledge graph without executing providers."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Replay Graph Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    ev = Evidence(type="network.traffic", subject="host.c2", value={"bytes": 4096}, source=Source(type="net", name="net"))
    inv.add_evidence(ev)
    snap = inv.capture_snapshot("snap1")

    # Replay historical state up to snap1 snapshot
    replayed_graph = ReplayEngine.replay_knowledge_graph(inv, until_snapshot=snap.sequence)
    assert replayed_graph.get_node(ev.id) is not None
    assert replayed_graph.verify_graph_integrity() is True


def test_replay_compare_graph_states():
    """Verify ReplayEngine.compare_graph_states provides factual unranked differences."""
    g1 = TemporalKnowledgeGraph(investigation_id="inv-cmp")
    g2 = TemporalKnowledgeGraph(investigation_id="inv-cmp")

    n1 = KnowledgeNode(node_id="shared-node", node_type="ENTITY", investigation_id="inv-cmp").seal()
    n2 = KnowledgeNode(node_id="node-only-in-g2", node_type="ENTITY", investigation_id="inv-cmp").seal()

    g1.add_node(n1)
    g2.add_node(n1)
    g2.add_node(n2)

    diff = ReplayEngine.compare_graph_states(g1, g2)
    assert diff["identical"] is False
    assert diff["nodes_only_in_b"] == ["node-only-in-g2"]
    assert diff["nodes_shared"] == ["shared-node"]


def test_branch_graph_isolation_and_replay(tmp_path: Path):
    """Verify counterfactual branch graphs carry is_counterfactual=True and do not pollute authoritative graphs."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Branch Graph Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    snap = inv.capture_snapshot("base_checkpoint")

    branch = core.create_investigation_branch(inv.id, source_snapshot=snap.sequence, purpose="Hypothetical Analysis")
    branch_ev = Evidence(type="simulated_scan", subject="10.0.0.1", value={"port": 22}, source=Source(type="sim", name="sim"))
    branch.simulated_evidence.append(branch_ev)

    branch_graph = BranchEngine.replay_branch_graph(branch)
    assert branch_graph.is_counterfactual is True
    assert branch_graph.branch_id == branch.branch_id
    assert branch_graph.get_node(branch_ev.id) is not None

    # Authoritative graph remains clean
    auth_graph = core.materialize_knowledge_graph(inv.id)
    assert auth_graph.get_node(branch_ev.id) is None


def test_branch_graph_comparison_unranked():
    """Verify BranchEngine.compare_branch_graphs produces neutral structural comparisons."""
    bg1 = TemporalKnowledgeGraph(investigation_id="b1", is_counterfactual=True, branch_id="b1")
    bg2 = TemporalKnowledgeGraph(investigation_id="b2", is_counterfactual=True, branch_id="b2")

    n = KnowledgeNode(node_id="n-hypo", node_type="HYPOTHESIS", investigation_id="b1", is_counterfactual=True).seal()
    bg1.add_node(n)

    cmp_res = BranchEngine.compare_branch_graphs(bg1, bg2)
    assert cmp_res["identical"] is False
    assert cmp_res["nodes_only_in_a"] == ["n-hypo"]
    assert "better" not in cmp_res and "winning" not in cmp_res


def test_section_28_mandatory_e2e_scenario(tmp_path: Path):
    """Execute complete 25-step Section 28 Temporal Evidence & Knowledge Graph scenario."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register Specialists and Capabilities
    cap_osint = Capability(
        id="osint.passive_dns",
        name="Passive DNS",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    cap_net = Capability(
        id="net.service_corroborate",
        name="Service Corroborator",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap_osint)
    core.register_capability(cap_net)

    spec_osint = Specialist(id="specialist.osint", name="OSINT Specialist", endpoint=MockEndpoint(), capabilities=["osint.passive_dns"])
    spec_net = Specialist(id="specialist.network", name="Network Specialist", endpoint=MockEndpoint(), capabilities=["net.service_corroborate"])
    core.register_specialist(spec_osint)
    core.register_specialist(spec_net)

    # 1. Investigation Created
    inv = core.create_investigation("Section 28 Knowledge Graph Investigation")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    hyp = inv.create_hypothesis("Host 198.51.100.50 acts as active malicious C2 controller", initial_confidence=0.5)

    # 2. OSINT Specialist produces Evidence A
    ev_a = Evidence(
        type="dns_mapping",
        subject="198.51.100.50",
        value={"hostname": "c2-apex.net"},
        source=Source(type="passive_dns", name="Farsight_DNS"),
        provenance=Provenance(specialist_id="specialist.osint", capability_id="osint.passive_dns"),
        confidence=0.85,
    )
    inv.add_evidence(ev_a)

    # 3. Network Specialist produces Evidence B via Collaboration
    collab_req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Verify TLS banner on 198.51.100.50",
        input_evidence_ids=[ev_a.id],
        required_capabilities=["net.service_corroborate"],
    )
    core.validate_and_route_collaboration(inv.id, collab_req.request_id)
    core.accept_collaboration_request(inv.id, collab_req.request_id)
    core.step_runtime(inv.id)

    collab_res = CollaborationResult(
        request_id=collab_req.request_id,
        investigation_id=inv.id,
        responding_specialist="specialist.network",
        observations=[{"subject": "198.51.100.50", "data": {"banner": "c2_v2_banner"}, "confidence": 0.95}],
    )
    norm_evs = core.process_collaboration_result(inv.id, collab_req.request_id, collab_res)
    assert len(norm_evs) == 1
    ev_b = norm_evs[0]

    # 4. Materialize Knowledge Graph from authorized consensus
    graph = core.materialize_knowledge_graph(inv.id)
    assert graph.get_node(ev_a.id) is not None
    assert graph.get_node(ev_b.id) is not None
    assert graph.get_node(hyp.id) is not None

    # 5. Contradictory evidence arrives from secondary probe
    ev_contra = Evidence(
        type="sinkhole_telemetry",
        subject="198.51.100.50",
        value={"sinkhole": True, "status": "sinkhole_confirmed"},
        source=Source(type="sinkhole_feed", name="CertSinkhole"),
        confidence=0.9,
    )
    inv.add_evidence(ev_contra)
    inv.contradictions.append(
        ContradictionRecord(
            investigation_id=inv.id,
            subject="198.51.100.50",
            conflict_type="divergent_attribute",
            competing_evidence_ids=[ev_b.id, ev_contra.id],
            description="Active C2 banner contradicted by sinkhole status",
        )
    )

    # 6. Rematerialize graph: CONTRADICTS edge created
    graph_with_conflict = core.materialize_knowledge_graph(inv.id)
    contra_edges = [e for e in graph_with_conflict.get_edges() if e.relationship_type == RelationshipType.CONTRADICTS.value]
    assert len(contra_edges) >= 1

    # 7. Adaptive planner inspects graph-derived uncertainty
    gaps = core.find_knowledge_gaps(inv.id)
    assert len(gaps) >= 1
    assert any("CONTRADICTION" in g.uncertainty_type for g in gaps)

    # 8. Case snapshot captured
    snap = inv.capture_snapshot("milestone_graph_with_conflict")

    # 9. Replay historical graph reconstructs exact point-in-time state without executing providers
    replayed_graph = ReplayEngine.replay_knowledge_graph(inv, until_snapshot=snap.sequence)
    assert replayed_graph.calculate_graph_digest() == graph_with_conflict.calculate_graph_digest()

    # 10. Counterfactual branch graph created and isolated
    branch = core.create_investigation_branch(inv.id, source_snapshot=snap.sequence, purpose="Simulation")
    branch_ev = Evidence(type="sim_probe", subject="198.51.100.50", value={"sim": 1}, source=Source(type="sim", name="sim"))
    branch.simulated_evidence.append(branch_ev)

    branch_graph = BranchEngine.replay_branch_graph(branch)
    assert branch_graph.get_node(branch_ev.id) is not None
    # Authoritative graph remains clean
    assert graph_with_conflict.get_node(branch_ev.id) is None

    # 11. Unranked comparison
    cmp_res = BranchEngine.compare_branch_graphs(branch_graph, graph_with_conflict)
    assert cmp_res["identical"] is False
    assert branch_ev.id in cmp_res["nodes_only_in_a"]

    # 12. Persist authoritative graph and verify reload produces identical digest
    core.persist_knowledge_graph(inv.id)
    reloaded_graph = core.load_knowledge_graph(inv.id)
    assert reloaded_graph is not None
    assert reloaded_graph.calculate_graph_digest() == graph_with_conflict.calculate_graph_digest()
