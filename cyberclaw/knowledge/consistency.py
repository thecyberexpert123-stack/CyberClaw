"""Knowledge Consistency Engine identifying structural, temporal, and referential anomalies."""

from __future__ import annotations

from typing import Any, List, Optional, Set

from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.models import (
    ConsistencyIssue,
    ConsistencySeverity,
    EdgeStatus,
    RelationshipType,
)


class KnowledgeConsistencyEngine:
    """Verifies referential, temporal, and architectural integrity of a TemporalKnowledgeGraph."""

    @classmethod
    def check_consistency(
        cls,
        graph: TemporalKnowledgeGraph,
        evidence_store: Optional[Any] = None,
    ) -> List[ConsistencyIssue]:
        """Perform comprehensive deterministic consistency evaluation and return structured diagnostics."""
        issues: List[ConsistencyIssue] = []

        known_node_ids: Set[str] = set(graph._nodes.keys())
        known_evidence_ids: Set[str] = set()
        if evidence_store and hasattr(evidence_store, "list_all"):
            known_evidence_ids = {e.id for e in evidence_store.list_all()}

        # 1. Evaluate Nodes
        for node in graph._nodes.values():
            # A. Temporal interval inversion
            if node.valid_until and node.valid_until < node.valid_from:
                issues.append(
                    ConsistencyIssue(
                        issue_type="TEMPORAL_INTERVAL_INVERSION",
                        severity=ConsistencySeverity.ERROR,
                        node_id=node.node_id,
                        explanation=f"Node '{node.node_id}' has valid_until ({node.valid_until.isoformat()}) earlier than valid_from ({node.valid_from.isoformat()}).",
                        remediation_hint="Adjust valid_until to be strictly greater than or equal to valid_from.",
                    )
                )

            # B. Integrity digest verification
            if not node.verify_integrity():
                issues.append(
                    ConsistencyIssue(
                        issue_type="INTEGRITY_DIGEST_MISMATCH",
                        severity=ConsistencySeverity.CRITICAL,
                        node_id=node.node_id,
                        explanation=f"Node '{node.node_id}' failed SHA-256 integrity verification.",
                        remediation_hint="Verify if node was mutated directly without re-sealing.",
                    )
                )

            # C. Branch quarantine check
            if not graph.is_counterfactual and node.is_counterfactual:
                issues.append(
                    ConsistencyIssue(
                        issue_type="BRANCH_LEAK_IN_AUTHORITATIVE_GRAPH",
                        severity=ConsistencySeverity.CRITICAL,
                        node_id=node.node_id,
                        explanation=f"Counterfactual node '{node.node_id}' found in authoritative graph.",
                        remediation_hint="Quarantine counterfactual nodes to branch-isolated graph views.",
                    )
                )

            # D. Missing evidence references
            if evidence_store:
                for ev_ref in node.evidence_references:
                    if ev_ref not in known_evidence_ids and ev_ref not in known_node_ids:
                        issues.append(
                            ConsistencyIssue(
                                issue_type="MISSING_EVIDENCE_REFERENCE",
                                severity=ConsistencySeverity.WARNING,
                                node_id=node.node_id,
                                related_ids=[ev_ref],
                                explanation=f"Node '{node.node_id}' references unknown evidence '{ev_ref}'.",
                                remediation_hint="Ensure evidence is ingested into authoritative EvidenceStore.",
                            )
                        )

        # 2. Evaluate Edges
        for edge in graph._edges.values():
            # A. Missing source or target node
            if edge.source_node_id not in known_node_ids:
                issues.append(
                    ConsistencyIssue(
                        issue_type="MISSING_SOURCE_NODE",
                        severity=ConsistencySeverity.CRITICAL,
                        edge_id=edge.edge_id,
                        related_ids=[edge.source_node_id],
                        explanation=f"Edge '{edge.edge_id}' references non-existent source node '{edge.source_node_id}'.",
                        remediation_hint="Ensure source node is added to graph before edge creation.",
                    )
                )
            if edge.target_node_id not in known_node_ids:
                issues.append(
                    ConsistencyIssue(
                        issue_type="MISSING_TARGET_NODE",
                        severity=ConsistencySeverity.CRITICAL,
                        edge_id=edge.edge_id,
                        related_ids=[edge.target_node_id],
                        explanation=f"Edge '{edge.edge_id}' references non-existent target node '{edge.target_node_id}'.",
                        remediation_hint="Ensure target node is added to graph before edge creation.",
                    )
                )

            # B. Temporal interval inversion
            if edge.valid_until and edge.valid_until < edge.valid_from:
                issues.append(
                    ConsistencyIssue(
                        issue_type="TEMPORAL_INTERVAL_INVERSION",
                        severity=ConsistencySeverity.ERROR,
                        edge_id=edge.edge_id,
                        explanation=f"Edge '{edge.edge_id}' has valid_until earlier than valid_from.",
                        remediation_hint="Ensure edge valid_until is greater than valid_from.",
                    )
                )

            # C. Prohibited self-reference
            if edge.source_node_id == edge.target_node_id:
                if edge.relationship_type in (
                    RelationshipType.DERIVED_FROM.value,
                    RelationshipType.SUPPORTS.value,
                    RelationshipType.CONTRADICTS.value,
                ):
                    issues.append(
                        ConsistencyIssue(
                            issue_type="PROHIBITED_SELF_REFERENCE",
                            severity=ConsistencySeverity.ERROR,
                            edge_id=edge.edge_id,
                            node_id=edge.source_node_id,
                            explanation=f"Edge '{edge.edge_id}' exhibits circular self-reference on '{edge.relationship_type}'.",
                            remediation_hint="Self-referential edges are prohibited for directional derivation, support, or contradiction.",
                        )
                    )

            # D. Integrity digest verification
            if not edge.verify_integrity():
                issues.append(
                    ConsistencyIssue(
                        issue_type="INTEGRITY_DIGEST_MISMATCH",
                        severity=ConsistencySeverity.CRITICAL,
                        edge_id=edge.edge_id,
                        explanation=f"Edge '{edge.edge_id}' failed SHA-256 integrity verification.",
                        remediation_hint="Verify if edge attributes were modified without re-sealing.",
                    )
                )

            # E. Branch quarantine check
            if not graph.is_counterfactual and edge.is_counterfactual:
                issues.append(
                    ConsistencyIssue(
                        issue_type="BRANCH_LEAK_IN_AUTHORITATIVE_GRAPH",
                        severity=ConsistencySeverity.CRITICAL,
                        edge_id=edge.edge_id,
                        explanation=f"Counterfactual edge '{edge.edge_id}' found in authoritative graph.",
                        remediation_hint="Quarantine counterfactual edges to branch graphs.",
                    )
                )

            # F. Active contradiction notice
            if edge.relationship_type == RelationshipType.CONTRADICTS.value and edge.status == EdgeStatus.ACTIVE:
                issues.append(
                    ConsistencyIssue(
                        issue_type="ACTIVE_UNRESOLVED_CONTRADICTION",
                        severity=ConsistencySeverity.INFO,
                        edge_id=edge.edge_id,
                        related_ids=[edge.source_node_id, edge.target_node_id],
                        explanation=f"Active contradiction edge '{edge.edge_id}' links competing claims '{edge.source_node_id}' and '{edge.target_node_id}'.",
                        remediation_hint="Investigate and introduce authoritative resolution evidence to resolve.",
                    )
                )

        return issues
