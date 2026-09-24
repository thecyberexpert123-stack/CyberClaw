"""Temporal Knowledge Graph container, indexing, and deterministic integrity hashing."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set, Tuple

from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.errors import (
    KnowledgeBranchLeakError,
    KnowledgeConsistencyError,
    KnowledgeEdgeNotFoundError,
    KnowledgeIntegrityError,
    KnowledgeNodeNotFoundError,
)
from cyberclaw.knowledge.models import EdgeStatus, RelationshipType, utc_now
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.provenance import KnowledgeProvenanceRecord

if TYPE_CHECKING:
    from cyberclaw.knowledge.queries import CurrentKnowledgeView, HistoricalKnowledgeView


class TemporalKnowledgeGraph:
    """Domain-neutral, provenance-preserving temporal knowledge graph."""

    def __init__(
        self,
        investigation_id: str,
        case_id: str = "",
        is_counterfactual: bool = False,
        branch_id: Optional[str] = None,
    ) -> None:
        self.investigation_id = investigation_id
        self.case_id = case_id
        self.is_counterfactual = is_counterfactual
        self.branch_id = branch_id

        self._nodes: Dict[str, KnowledgeNode] = {}
        self._edges: Dict[str, KnowledgeEdge] = {}
        self._provenance: Dict[str, KnowledgeProvenanceRecord] = {}

        # High-performance indexes
        self._nodes_by_type: Dict[str, Set[str]] = {}
        self._edges_by_source: Dict[str, Set[str]] = {}
        self._edges_by_target: Dict[str, Set[str]] = {}
        self._edges_by_rel: Dict[str, Set[str]] = {}
        self._edges_by_evidence: Dict[str, Set[str]] = {}
        self._edges_by_status: Dict[str, Set[str]] = {}

    # --------------------------------------------------------------------------
    # Node Management
    # --------------------------------------------------------------------------

    def add_node(self, node: KnowledgeNode, enforce_integrity: bool = True) -> KnowledgeNode:
        """Add a KnowledgeNode to the graph with isolation and integrity enforcement."""
        if not self.is_counterfactual and node.is_counterfactual:
            raise KnowledgeBranchLeakError(
                f"Cannot insert counterfactual node '{node.node_id}' into authoritative graph.",
                investigation_id=self.investigation_id,
                node_id=node.node_id,
            )

        if not node.integrity_digest:
            node.seal()
        elif enforce_integrity and not node.verify_integrity():
            raise KnowledgeIntegrityError(
                f"Integrity digest verification failed for node '{node.node_id}'.",
                investigation_id=self.investigation_id,
                node_id=node.node_id,
            )

        self._nodes[node.node_id] = node
        self._nodes_by_type.setdefault(node.node_type, set()).add(node.node_id)
        return node

    def get_node(self, node_id: str) -> Optional[KnowledgeNode]:
        """Fetch node by ID."""
        return self._nodes.get(node_id)

    def get_nodes(self) -> List[KnowledgeNode]:
        """Return all nodes in the graph."""
        return list(self._nodes.values())

    def supersede_node(self, old_node_id: str, new_node: KnowledgeNode) -> Tuple[KnowledgeNode, KnowledgeNode]:
        """Supersede an existing node with an updated version, maintaining temporal validity."""
        old_node = self._nodes.get(old_node_id)
        if not old_node:
            raise KnowledgeNodeNotFoundError(old_node_id, investigation_id=self.investigation_id)

        now = utc_now()
        old_node.valid_until = now
        old_node.seal()

        new_node.version = old_node.version + 1
        new_node.valid_from = now
        new_node.provenance_references.append(old_node.node_id)
        self.add_node(new_node)
        return old_node, new_node

    # --------------------------------------------------------------------------
    # Edge Management
    # --------------------------------------------------------------------------

    def add_edge(self, edge: KnowledgeEdge, enforce_integrity: bool = True) -> KnowledgeEdge:
        """Add a KnowledgeEdge linking two existing nodes in the graph."""
        if not self.is_counterfactual and edge.is_counterfactual:
            raise KnowledgeBranchLeakError(
                f"Cannot insert counterfactual edge '{edge.edge_id}' into authoritative graph.",
                investigation_id=self.investigation_id,
                edge_id=edge.edge_id,
            )

        if edge.source_node_id not in self._nodes:
            raise KnowledgeNodeNotFoundError(
                edge.source_node_id,
                investigation_id=self.investigation_id,
                edge_id=edge.edge_id,
                details={"role": "source_node"},
            )
        if edge.target_node_id not in self._nodes:
            raise KnowledgeNodeNotFoundError(
                edge.target_node_id,
                investigation_id=self.investigation_id,
                edge_id=edge.edge_id,
                details={"role": "target_node"},
            )

        if not edge.integrity_digest:
            edge.seal()
        elif enforce_integrity and not edge.verify_integrity():
            raise KnowledgeIntegrityError(
                f"Integrity digest verification failed for edge '{edge.edge_id}'.",
                investigation_id=self.investigation_id,
                edge_id=edge.edge_id,
            )

        self._edges[edge.edge_id] = edge
        self._edges_by_source.setdefault(edge.source_node_id, set()).add(edge.edge_id)
        self._edges_by_target.setdefault(edge.target_node_id, set()).add(edge.edge_id)
        self._edges_by_rel.setdefault(edge.relationship_type, set()).add(edge.edge_id)
        self._edges_by_status.setdefault(edge.status.value, set()).add(edge.edge_id)

        for ev_id in edge.supporting_evidence_ids + edge.refuting_evidence_ids:
            self._edges_by_evidence.setdefault(ev_id, set()).add(edge.edge_id)

        return edge

    def get_edge(self, edge_id: str) -> Optional[KnowledgeEdge]:
        """Fetch edge by ID."""
        return self._edges.get(edge_id)

    def get_edges(self) -> List[KnowledgeEdge]:
        """Return all edges in the graph."""
        return list(self._edges.values())

    def invalidate_edge(
        self,
        edge_id: str,
        invalidation_time: Optional[datetime] = None,
        reason: str = "",
    ) -> KnowledgeEdge:
        """Invalidate an active edge historically without deleting it."""
        edge = self._edges.get(edge_id)
        if not edge:
            raise KnowledgeEdgeNotFoundError(edge_id, investigation_id=self.investigation_id)

        old_status = edge.status.value
        self._edges_by_status.get(old_status, set()).discard(edge_id)

        edge.status = EdgeStatus.INVALIDATED
        edge.valid_until = invalidation_time or utc_now()
        if reason:
            edge.metadata["invalidation_reason"] = reason

        edge.seal()
        self._edges_by_status.setdefault(EdgeStatus.INVALIDATED.value, set()).add(edge_id)
        return edge

    def attach_evidence_to_edge(
        self,
        edge_id: str,
        evidence_id: str,
        supports: bool = True,
    ) -> KnowledgeEdge:
        """Attach supporting or refuting evidence ID to an existing edge."""
        edge = self._edges.get(edge_id)
        if not edge:
            raise KnowledgeEdgeNotFoundError(edge_id, investigation_id=self.investigation_id)

        if supports:
            if evidence_id not in edge.supporting_evidence_ids:
                edge.supporting_evidence_ids.append(evidence_id)
        else:
            if evidence_id not in edge.refuting_evidence_ids:
                edge.refuting_evidence_ids.append(evidence_id)

        edge.seal()
        self._edges_by_evidence.setdefault(evidence_id, set()).add(edge_id)
        return edge

    # --------------------------------------------------------------------------
    # Provenance Management
    # --------------------------------------------------------------------------

    def attach_provenance(self, record: KnowledgeProvenanceRecord) -> None:
        """Store an immutable provenance record for a graph object."""
        self._provenance[record.provenance_id] = record

    def get_provenance(self, provenance_id: str) -> Optional[KnowledgeProvenanceRecord]:
        """Retrieve a provenance record by ID."""
        return self._provenance.get(provenance_id)

    # --------------------------------------------------------------------------
    # Integrity and Canonical Digest
    # --------------------------------------------------------------------------

    def calculate_graph_digest(self) -> str:
        """Compute deterministic SHA-256 digest of the entire graph state.

        Digest is order-independent: nodes, edges, and provenance records are canonically sorted by ID.
        """
        sorted_node_digests = [
            f"{n.node_id}:{n.calculate_node_digest()}"
            for n in sorted(self._nodes.values(), key=lambda x: x.node_id)
        ]
        sorted_edge_digests = [
            f"{e.edge_id}:{e.calculate_edge_digest()}"
            for e in sorted(self._edges.values(), key=lambda x: x.edge_id)
        ]
        sorted_prov_digests = [
            f"{p.provenance_id}:{p.target_id}:{p.timestamp.isoformat()}"
            for p in sorted(self._provenance.values(), key=lambda x: x.provenance_id)
        ]

        payload = {
            "investigation_id": self.investigation_id,
            "case_id": self.case_id,
            "is_counterfactual": self.is_counterfactual,
            "branch_id": self.branch_id,
            "nodes": sorted_node_digests,
            "edges": sorted_edge_digests,
            "provenance": sorted_prov_digests,
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def verify_graph_integrity(self) -> bool:
        """Verify that all individual nodes and edges in the graph have valid digests."""
        for node in self._nodes.values():
            if not node.verify_integrity():
                return False
        for edge in self._edges.values():
            if not edge.verify_integrity():
                return False
        return True

    # --------------------------------------------------------------------------
    # Views
    # --------------------------------------------------------------------------

    def get_current_view(self) -> CurrentKnowledgeView:
        """Construct materialized view of currently active nodes and edges."""
        from cyberclaw.knowledge.queries import CurrentKnowledgeView
        now = utc_now()
        active_nodes = [n for n in self._nodes.values() if n.is_valid_at(now)]
        active_edges = [
            e for e in self._edges.values()
            if e.status == EdgeStatus.ACTIVE and e.is_valid_at(now)
        ]
        return CurrentKnowledgeView(
            graph=self,
            as_of_time=now,
            nodes=active_nodes,
            edges=active_edges,
        )

    def get_historical_view_at_time(self, timestamp: datetime) -> HistoricalKnowledgeView:
        """Reconstruct graph state as it existed at the specified point in time."""
        from cyberclaw.knowledge.queries import HistoricalKnowledgeView
        valid_nodes = [n for n in self._nodes.values() if n.is_valid_at(timestamp)]
        valid_edges = [e for e in self._edges.values() if e.is_valid_at(timestamp)]
        return HistoricalKnowledgeView(
            graph=self,
            historical_timestamp=timestamp,
            nodes=valid_nodes,
            edges=valid_edges,
        )
