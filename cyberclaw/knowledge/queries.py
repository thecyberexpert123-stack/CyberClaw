"""Knowledge views, query engine, and transparent factual explanation API."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.models import (
    EdgeStatus,
    KnowledgeExplanation,
    KnowledgeNodeType,
    RelationshipType,
    utc_now,
)
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.provenance import (
    KnowledgeProvenanceRecord,
    build_provenance_chain,
    calculate_source_independence,
)


class CurrentKnowledgeView:
    """Read-only materialized view containing only currently valid nodes and active edges."""

    def __init__(
        self,
        graph: Any,
        as_of_time: datetime,
        nodes: List[KnowledgeNode],
        edges: List[KnowledgeEdge],
    ) -> None:
        self.graph = graph
        self.as_of_time = as_of_time
        self.nodes = {n.node_id: n for n in nodes}
        self.edges = {e.edge_id: e for e in edges}

    def get_node(self, node_id: str) -> Optional[KnowledgeNode]:
        """Retrieve node if active."""
        return self.nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[KnowledgeEdge]:
        """Retrieve edge if active."""
        return self.edges.get(edge_id)

    def neighbors(
        self,
        node_id: str,
        relationship_type: Optional[str] = None,
    ) -> List[KnowledgeNode]:
        """Return adjacent nodes currently connected to node_id."""
        result: List[KnowledgeNode] = []
        for edge in self.edges.values():
            if relationship_type and edge.relationship_type != relationship_type:
                continue
            if edge.source_node_id == node_id and edge.target_node_id in self.nodes:
                result.append(self.nodes[edge.target_node_id])
            elif edge.target_node_id == node_id and edge.source_node_id in self.nodes:
                result.append(self.nodes[edge.source_node_id])
        return result


class HistoricalKnowledgeView:
    """Deterministic point-in-time graph view reconstructed as of a specific historical timestamp."""

    def __init__(
        self,
        graph: Any,
        historical_timestamp: datetime,
        nodes: List[KnowledgeNode],
        edges: List[KnowledgeEdge],
    ) -> None:
        self.graph = graph
        self.historical_timestamp = historical_timestamp
        self.nodes = {n.node_id: n for n in nodes}
        self.edges = {e.edge_id: e for e in edges}

    def get_node(self, node_id: str) -> Optional[KnowledgeNode]:
        """Retrieve node valid at historical timestamp."""
        return self.nodes.get(node_id)

    def get_edge(self, edge_id: str) -> Optional[KnowledgeEdge]:
        """Retrieve edge valid at historical timestamp."""
        return self.edges.get(edge_id)

    def neighbors(
        self,
        node_id: str,
        relationship_type: Optional[str] = None,
    ) -> List[KnowledgeNode]:
        """Return adjacent nodes valid at historical timestamp."""
        result: List[KnowledgeNode] = []
        for edge in self.edges.values():
            if relationship_type and edge.relationship_type != relationship_type:
                continue
            if edge.source_node_id == node_id and edge.target_node_id in self.nodes:
                result.append(self.nodes[edge.target_node_id])
            elif edge.target_node_id == node_id and edge.source_node_id in self.nodes:
                result.append(self.nodes[edge.source_node_id])
        return result


class KnowledgeQueryEngine:
    """Domain-neutral, secure query layer for TemporalKnowledgeGraph."""

    @classmethod
    def neighbors(
        cls,
        graph: Any,
        node_id: str,
        relationship_type: Optional[str] = None,
        current_only: bool = True,
    ) -> List[KnowledgeNode]:
        """Retrieve adjacent nodes connected by edges."""
        if current_only:
            return graph.get_current_view().neighbors(node_id, relationship_type)

        result: List[KnowledgeNode] = []
        edge_ids = graph._edges_by_source.get(node_id, set()) | graph._edges_by_target.get(node_id, set())
        for eid in edge_ids:
            edge = graph.get_edge(eid)
            if not edge:
                continue
            if relationship_type and edge.relationship_type != relationship_type:
                continue
            target_nid = edge.target_node_id if edge.source_node_id == node_id else edge.source_node_id
            n = graph.get_node(target_nid)
            if n:
                result.append(n)
        return result

    @classmethod
    def supporting_evidence(cls, graph: Any, target_id: str) -> List[str]:
        """Return all evidence IDs that support the given node or edge."""
        edge = graph.get_edge(target_id)
        if edge:
            return list(edge.supporting_evidence_ids)

        node = graph.get_node(target_id)
        if node:
            evidence_ids = set(node.evidence_references)
            # Find incoming SUPPORTS or CORROBORATES edges
            target_edges = graph._edges_by_target.get(target_id, set())
            for eid in target_edges:
                e = graph.get_edge(eid)
                if e and e.relationship_type in (RelationshipType.SUPPORTS.value, RelationshipType.CORROBORATES.value):
                    evidence_ids.update(e.supporting_evidence_ids)
                    src_node = graph.get_node(e.source_node_id)
                    if src_node and src_node.node_type == KnowledgeNodeType.EVIDENCE.value:
                        evidence_ids.add(src_node.node_id)
            return sorted(evidence_ids)
        return []

    @classmethod
    def contradicting_evidence(cls, graph: Any, target_id: str) -> List[str]:
        """Return all evidence IDs that contradict the given node or edge."""
        edge = graph.get_edge(target_id)
        if edge:
            return list(edge.refuting_evidence_ids)

        node = graph.get_node(target_id)
        if node:
            refuting_ids = set()
            target_edges = graph._edges_by_target.get(target_id, set()) | graph._edges_by_source.get(target_id, set())
            for eid in target_edges:
                e = graph.get_edge(eid)
                if e and e.relationship_type == RelationshipType.CONTRADICTS.value:
                    refuting_ids.update(e.refuting_evidence_ids)
                    other_nid = e.source_node_id if e.target_node_id == target_id else e.target_node_id
                    other_node = graph.get_node(other_nid)
                    if other_node and other_node.node_type == KnowledgeNodeType.EVIDENCE.value:
                        refuting_ids.add(other_node.node_id)
            return sorted(refuting_ids)
        return []

    @classmethod
    def provenance_chain(cls, graph: Any, target_id: str) -> List[KnowledgeProvenanceRecord]:
        """Recursively trace and return upstream provenance records."""
        prov_ids: List[str] = []
        node = graph.get_node(target_id)
        if node:
            prov_ids.extend(node.provenance_references)
        edge = graph.get_edge(target_id)
        if edge:
            prov_ids.extend(edge.provenance_ids)

        return build_provenance_chain(graph._provenance, prov_ids)

    @classmethod
    def relationships_valid_at(cls, graph: Any, timestamp: datetime) -> List[KnowledgeEdge]:
        """Return all edges that were historically valid at the given timestamp."""
        return [e for e in graph.get_edges() if e.is_valid_at(timestamp)]

    @classmethod
    def query_case_graph(cls, graph: Any, case_id: str) -> List[KnowledgeNode]:
        """Return all nodes associated with a case ID."""
        return [n for n in graph.get_nodes() if n.case_id == case_id]

    @classmethod
    def explain_node(
        cls,
        graph: Any,
        node_id: str,
        evidence_items: Optional[List[Any]] = None,
    ) -> KnowledgeExplanation:
        """Produce an explainable, audit-ready diagnostic report for a node."""
        node = graph.get_node(node_id)
        if not node:
            return KnowledgeExplanation(
                target_id=node_id,
                target_type="UNKNOWN",
                claim="Node not found in graph.",
                confidence_score=0.0,
            )

        supporting = cls.supporting_evidence(graph, node_id)
        refuting = cls.contradicting_evidence(graph, node_id)
        prov_chain = cls.provenance_chain(graph, node_id)

        specialists = sorted({p.originating_specialist for p in prov_chain if p.originating_specialist})
        capabilities = sorted({f"{p.capability_id}@{p.capability_version}" for p in prov_chain if p.capability_id})
        auth_decisions = sorted({p.authorization_decision_id for p in prov_chain if p.authorization_decision_id})

        uncertainties = []
        if not supporting and node.node_type in (KnowledgeNodeType.HYPOTHESIS.value, KnowledgeNodeType.ENTITY.value):
            uncertainties.append("Zero supporting evidence recorded for this node.")
        if refuting:
            uncertainties.append(f"Node has {len(refuting)} contradicting evidence items.")

        source_lineage: List[Dict[str, Any]] = []
        if evidence_items:
            count, sources = calculate_source_independence(supporting, evidence_items)
            source_lineage = [{"source": s, "independent": True} for s in sources]

        contradiction_details = []
        for eid in graph._edges_by_target.get(node_id, set()) | graph._edges_by_source.get(node_id, set()):
            e = graph.get_edge(eid)
            if e and e.relationship_type == RelationshipType.CONTRADICTS.value:
                contradiction_details.append({
                    "edge_id": e.edge_id,
                    "opposing_node_id": e.source_node_id if e.target_node_id == node_id else e.target_node_id,
                    "status": e.status.value,
                })

        return KnowledgeExplanation(
            target_id=node.node_id,
            target_type=node.node_type,
            claim=node.label or node.metadata.get("statement", node.node_type),
            supporting_evidence_ids=supporting,
            refuting_evidence_ids=refuting,
            source_lineage=source_lineage,
            specialists_involved=specialists,
            capabilities_involved=capabilities,
            policy_authorizations=auth_decisions,
            temporal_validity={
                "created_at": node.created_at.isoformat(),
                "valid_from": node.valid_from.isoformat(),
                "valid_until": node.valid_until.isoformat() if node.valid_until else None,
            },
            confidence_score=float(node.metadata.get("confidence", 1.0)),
            uncertainties=uncertainties,
            contradictions=contradiction_details,
        )

    @classmethod
    def explain_edge(
        cls,
        graph: Any,
        edge_id: str,
        evidence_items: Optional[List[Any]] = None,
    ) -> KnowledgeExplanation:
        """Produce an explainable diagnostic report for an edge."""
        edge = graph.get_edge(edge_id)
        if not edge:
            return KnowledgeExplanation(
                target_id=edge_id,
                target_type="UNKNOWN",
                claim="Edge not found in graph.",
                confidence_score=0.0,
            )

        supporting = list(edge.supporting_evidence_ids)
        refuting = list(edge.refuting_evidence_ids)
        prov_chain = cls.provenance_chain(graph, edge_id)

        specialists = sorted({p.originating_specialist for p in prov_chain if p.originating_specialist})
        if edge.originating_specialist:
            specialists.append(edge.originating_specialist)
            specialists = sorted(set(specialists))

        capabilities = sorted({f"{p.capability_id}@{p.capability_version}" for p in prov_chain if p.capability_id})
        if edge.capability_id:
            capabilities.append(f"{edge.capability_id}@{edge.capability_version or '1.0.0'}")
            capabilities = sorted(set(capabilities))

        auth_decisions = sorted({p.authorization_decision_id for p in prov_chain if p.authorization_decision_id})
        if edge.authorization_decision_id:
            auth_decisions.append(edge.authorization_decision_id)
            auth_decisions = sorted(set(auth_decisions))

        uncertainties = []
        if not supporting and edge.epistemic_nature == "INFERENCE":
            uncertainties.append("Pure inference without supporting empirical observations.")
        if refuting:
            uncertainties.append(f"Edge has {len(refuting)} refuting evidence items.")

        source_lineage: List[Dict[str, Any]] = []
        if evidence_items:
            count, sources = calculate_source_independence(supporting, evidence_items)
            source_lineage = [{"source": s, "independent": True} for s in sources]

        claim = f"{edge.source_node_id} --[{edge.relationship_type}]--> {edge.target_node_id}"

        return KnowledgeExplanation(
            target_id=edge.edge_id,
            target_type="EDGE",
            claim=claim,
            supporting_evidence_ids=supporting,
            refuting_evidence_ids=refuting,
            source_lineage=source_lineage,
            specialists_involved=specialists,
            capabilities_involved=capabilities,
            policy_authorizations=auth_decisions,
            temporal_validity={
                "created_at": edge.created_at.isoformat(),
                "valid_from": edge.valid_from.isoformat(),
                "valid_until": edge.valid_until.isoformat() if edge.valid_until else None,
                "status": edge.status.value,
            },
            confidence_score=edge.confidence,
            uncertainties=uncertainties,
            contradictions=[],
        )

    @classmethod
    def explain_hypothesis_graph(
        cls,
        graph: Any,
        hypothesis_id: str,
        evidence_items: Optional[List[Any]] = None,
    ) -> KnowledgeExplanation:
        """Produce diagnostic report specifically detailing a hypothesis and its corroborating/refuting graph context."""
        return cls.explain_node(graph, hypothesis_id, evidence_items=evidence_items)

    @classmethod
    def find_knowledge_gaps(cls, graph: Any) -> List[KnowledgeGap]:
        """Inspect graph for uncertainty, uncorroborated hypotheses, and active contradictions for adaptive planning."""
        from cyberclaw.knowledge.models import KnowledgeGap
        gaps: List[KnowledgeGap] = []

        # 1. Uncorroborated or low-confidence hypotheses
        for node in graph.get_nodes():
            if node.node_type == KnowledgeNodeType.HYPOTHESIS.value:
                supporting = cls.supporting_evidence(graph, node.node_id)
                refuting = cls.contradicting_evidence(graph, node.node_id)
                if not supporting:
                    gaps.append(
                        KnowledgeGap(
                            graph_location=f"hypothesis/{node.node_id}",
                            uncertainty_type="MISSING_SUPPORTING_EVIDENCE",
                            affected_hypothesis_id=node.node_id,
                            missing_evidence_categories=["empirical_observation"],
                            relevant_capabilities=["tool.probe", "osint.dns_lookup"],
                            provenance={"node_id": node.node_id, "statement": node.label},
                        )
                    )
                if refuting:
                    gaps.append(
                        KnowledgeGap(
                            graph_location=f"hypothesis/{node.node_id}",
                            uncertainty_type="CONTRADICTORY_EVIDENCE_FOUND",
                            affected_hypothesis_id=node.node_id,
                            missing_evidence_categories=["adjudication_evidence"],
                            relevant_capabilities=["authoritative.verification"],
                            provenance={"refuting_evidence_ids": refuting},
                        )
                    )

        # 2. Pure inferences without supporting empirical observation edges
        for edge in graph.get_edges():
            if edge.epistemic_nature == "INFERENCE" and not edge.supporting_evidence_ids:
                gaps.append(
                    KnowledgeGap(
                        graph_location=f"edge/{edge.edge_id}",
                        uncertainty_type="UNVERIFIED_INFERENCE",
                        missing_evidence_categories=["empirical_measurement"],
                        relevant_capabilities=[edge.capability_id or "tool.probe"],
                        provenance={"edge_id": edge.edge_id, "source": edge.source_node_id, "target": edge.target_node_id},
                    )
                )

        # 3. Active contradiction edges
        for edge in graph.get_edges():
            if edge.relationship_type == RelationshipType.CONTRADICTS.value and edge.status == EdgeStatus.ACTIVE:
                gaps.append(
                    KnowledgeGap(
                        graph_location=f"edge/{edge.edge_id}",
                        uncertainty_type="UNRESOLVED_CONTRADICTION",
                        missing_evidence_categories=["authoritative_resolution"],
                        relevant_specialists=[edge.originating_specialist] if edge.originating_specialist else [],
                        provenance={"edge_id": edge.edge_id, "refuting": edge.refuting_evidence_ids},
                    )
                )

        return gaps
