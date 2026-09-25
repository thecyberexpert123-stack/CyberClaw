"""Deterministic knowledge graph materialization from authoritative Case State and Evidence."""

from __future__ import annotations

from typing import Any, Optional

from cyberclaw.case.models import JournalEntryType
from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.models import (
    EdgeStatus,
    KnowledgeNodeType,
    RelationshipType,
    utc_now,
)
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.provenance import KnowledgeProvenanceRecord
from cyberclaw.types import entity_storage_key


def _node_for_relationship_ref(graph: TemporalKnowledgeGraph, investigation: Any, ref: str) -> Optional[str]:
    """Resolve a case relationship endpoint without guessing among colliding names."""
    matches = []
    for entity in getattr(investigation, "entities", {}).values():
        if entity.id == ref or entity.name == ref:
            node_id = f"entity:{entity_storage_key(entity.type, entity.name)}"
            if graph.get_node(node_id):
                matches.append(node_id)
    unique = list(dict.fromkeys(matches))
    if len(unique) == 1:
        return unique[0]
    if len(unique) > 1:
        return None
    subject_id = f"entity-{ref.strip().lower()}"
    if graph.get_node(subject_id):
        return subject_id
    return None


def _materialize_case_relationships(graph: TemporalKnowledgeGraph, investigation: Any) -> None:
    """Project case relationships as knowledge edges. The relation string is preserved.

    Observed and inferred relationships stay distinct. A missing evidence reference
    is recorded; it is not invented. Ambiguous entity names are not linked.
    """
    relationships = sorted(
        getattr(investigation, "relationships", []) or [],
        key=lambda item: (item.relation_type, item.source_id, item.target_id, item.id),
    )
    evidence_by_id = {
        item.id: item for item in investigation.evidence_store.list_all()
    }
    for relationship in relationships:
        source_id = _node_for_relationship_ref(graph, investigation, relationship.source_id)
        target_id = _node_for_relationship_ref(graph, investigation, relationship.target_id)
        if not source_id or not target_id:
            continue
        support = list(relationship.supporting_evidence_ids)
        first = evidence_by_id.get(support[0]) if support else None
        metadata = {
            "case_relation_type": relationship.relation_type,
            "case_relationship_id": relationship.id,
        }
        if not support:
            metadata["supporting_evidence_missing"] = True
        edge = KnowledgeEdge(
            edge_id=f"edge-rel-{relationship.id}",
            source_node_id=source_id,
            target_node_id=target_id,
            relationship_type=relationship.relation_type,
            created_at=relationship.created_at,
            valid_from=relationship.created_at,
            status=EdgeStatus.ACTIVE,
            confidence=relationship.confidence,
            epistemic_nature="INFERENCE" if relationship.is_inferred else "OBSERVATION",
            supporting_evidence_ids=support,
            originating_specialist=getattr(getattr(first, "provenance", None), "specialist_id", None),
            capability_id=getattr(getattr(first, "provenance", None), "capability_id", None),
            capability_version=(first.metadata.get("capability_version") if first else None),
            authorization_decision_id=(first.metadata.get("authorization_decision_id") if first else None),
            investigation_id=investigation.id,
            case_id=getattr(investigation, "case_id", ""),
            is_counterfactual=graph.is_counterfactual,
            branch_id=graph.branch_id,
            metadata=metadata,
        ).seal()
        graph.add_edge(edge)


class KnowledgeMaterializer:
    """Deterministically transforms authoritative investigation state into a verified Knowledge Graph view."""

    @classmethod
    def materialize_from_investigation(
        cls,
        investigation: Any,
        target_graph: Optional[TemporalKnowledgeGraph] = None,
    ) -> TemporalKnowledgeGraph:
        """Construct deterministic temporal graph view from authoritative case records.

        Guarantees that identical investigation state always yields an identical graph digest.
        """
        graph = target_graph or TemporalKnowledgeGraph(
            investigation_id=investigation.id,
            case_id=getattr(investigation, "case_id", ""),
            is_counterfactual=getattr(investigation, "is_counterfactual", False),
            branch_id=getattr(investigation, "branch_id", None),
        )

        # 1. Materialize Entities and Evidence
        evidence_items = sorted(
            investigation.evidence_store.list_all(),
            key=lambda e: e.id,
        )

        entity_nodes = {}
        for ev in evidence_items:
            # Materialize Evidence Node
            ev_node = KnowledgeNode(
                node_id=ev.id,
                node_type=KnowledgeNodeType.EVIDENCE.value,
                label=f"{ev.type}: {ev.subject}",
                created_at=ev.timestamp,
                valid_from=ev.timestamp,
                investigation_id=investigation.id,
                case_id=getattr(investigation, "case_id", ""),
                source_references=[ev.source.id or ev.source.name] if ev.source else [],
                evidence_references=ev.metadata.get("derived_from_evidence_ids", []),
                metadata={
                    "evidence_type": ev.type,
                    "confidence": ev.confidence,
                    "finding_nature": ev.metadata.get("finding_nature", "OBSERVATION"),
                },
                is_counterfactual=graph.is_counterfactual,
                branch_id=graph.branch_id,
            ).seal()
            graph.add_node(ev_node)

            # Materialize Entity Node for Subject if not exists
            if ev.subject and ev.subject not in entity_nodes:
                ent_node_id = f"entity-{ev.subject.strip().lower()}"
                ent_node = KnowledgeNode(
                    node_id=ent_node_id,
                    node_type=KnowledgeNodeType.ENTITY.value,
                    label=ev.subject,
                    created_at=ev.timestamp,
                    valid_from=ev.timestamp,
                    investigation_id=investigation.id,
                    case_id=getattr(investigation, "case_id", ""),
                    is_counterfactual=graph.is_counterfactual,
                    branch_id=graph.branch_id,
                    metadata={"subject": ev.subject},
                ).seal()
                entity_nodes[ev.subject] = ent_node
                graph.add_node(ent_node)

            # Edge from Evidence to Entity: ASSOCIATED_WITH
            if ev.subject:
                ent_node_id = entity_nodes[ev.subject].node_id
                edge_id = f"edge-{ev.id}-{ent_node_id}"
                ev_edge = KnowledgeEdge(
                    edge_id=edge_id,
                    source_node_id=ev.id,
                    target_node_id=ent_node_id,
                    relationship_type=RelationshipType.ASSOCIATED_WITH.value,
                    created_at=ev.timestamp,
                    valid_from=ev.timestamp,
                    status=EdgeStatus.ACTIVE,
                    confidence=ev.confidence,
                    epistemic_nature=ev.metadata.get("finding_nature", "OBSERVATION"),
                    supporting_evidence_ids=[ev.id],
                    originating_specialist=getattr(ev.provenance, "specialist_id", None),
                    capability_id=getattr(ev.provenance, "capability_id", None),
                    capability_version=ev.metadata.get("capability_version"),
                    authorization_decision_id=ev.metadata.get("authorization_decision_id"),
                    investigation_id=investigation.id,
                    case_id=getattr(investigation, "case_id", ""),
                    is_counterfactual=graph.is_counterfactual,
                    branch_id=graph.branch_id,
                ).seal()
                graph.add_edge(ev_edge)

            # Record Provenance Record
            if ev.provenance:
                prov_rec = KnowledgeProvenanceRecord(
                    provenance_id=f"prov-{ev.id}",
                    target_id=ev.id,
                    originating_specialist=ev.provenance.specialist_id,
                    capability_id=ev.provenance.capability_id,
                    capability_version=ev.metadata.get("capability_version"),
                    provider_id=ev.provenance.provider_id,
                    authorization_decision_id=ev.metadata.get("authorization_decision_id"),
                    upstream_evidence_ids=ev.metadata.get("derived_from_evidence_ids", []),
                    timestamp=ev.timestamp,
                )
                graph.attach_provenance(prov_rec)

        # 1b. Materialize case entities. Identity is type plus name, so two
        # entities that share a display name remain distinct nodes.
        case_entities = sorted(
            getattr(investigation, "entities", {}).values(),
            key=lambda ent: (ent.type, ent.name, ent.id),
        )
        for ent in case_entities:
            ent_node_id = f"entity:{entity_storage_key(ent.type, ent.name)}"
            if graph.get_node(ent_node_id):
                continue
            case_ent_node = KnowledgeNode(
                node_id=ent_node_id,
                node_type=KnowledgeNodeType.ENTITY.value,
                label=ent.name,
                created_at=ent.first_seen,
                valid_from=ent.first_seen,
                investigation_id=investigation.id,
                case_id=getattr(investigation, "case_id", ""),
                is_counterfactual=graph.is_counterfactual,
                branch_id=graph.branch_id,
                metadata={"subject": ent.name, "entity_type": ent.type, "entity_id": ent.id},
            ).seal()
            graph.add_node(case_ent_node)

        _materialize_case_relationships(graph, investigation)

        # 2. Materialize Hypotheses
        hypotheses = sorted(
            investigation.hypotheses.values(),
            key=lambda h: h.id,
        )
        for hyp in hypotheses:
            hyp_node = KnowledgeNode(
                node_id=hyp.id,
                node_type=KnowledgeNodeType.HYPOTHESIS.value,
                label=hyp.statement,
                created_at=hyp.created_at,
                valid_from=hyp.created_at,
                investigation_id=investigation.id,
                case_id=getattr(investigation, "case_id", ""),
                evidence_references=list(hyp.supporting_evidence_ids),
                metadata={"status": hyp.status, "confidence": hyp.confidence},
                is_counterfactual=graph.is_counterfactual,
                branch_id=graph.branch_id,
            ).seal()
            graph.add_node(hyp_node)

            # Connect Supporting Evidence to Hypothesis: SUPPORTS
            for supp_ev_id in sorted(hyp.supporting_evidence_ids):
                if graph.get_node(supp_ev_id):
                    edge_id = f"edge-{supp_ev_id}-supports-{hyp.id}"
                    supp_edge = KnowledgeEdge(
                        edge_id=edge_id,
                        source_node_id=supp_ev_id,
                        target_node_id=hyp.id,
                        relationship_type=RelationshipType.SUPPORTS.value,
                        created_at=hyp.updated_at or hyp.created_at,
                        valid_from=hyp.updated_at or hyp.created_at,
                        status=EdgeStatus.ACTIVE,
                        confidence=hyp.confidence,
                        epistemic_nature="CORROBORATION",
                        supporting_evidence_ids=[supp_ev_id],
                        investigation_id=investigation.id,
                        case_id=getattr(investigation, "case_id", ""),
                        is_counterfactual=graph.is_counterfactual,
                        branch_id=graph.branch_id,
                    ).seal()
                    graph.add_edge(supp_edge)

        # 3. Materialize Contradictions / Conflicts: CONTRADICTS
        contradictions = sorted(
            getattr(investigation, "contradictions", []),
            key=lambda c: getattr(c, "contradiction_id", getattr(c, "id", "")),
        )
        for contra in contradictions:
            ev_a = getattr(contra, "evidence_id_a", None)
            ev_b = getattr(contra, "evidence_id_b", None)
            competing = getattr(contra, "competing_evidence_ids", [])
            if not ev_a and len(competing) >= 2:
                ev_a = competing[0]
                ev_b = competing[1]
            cid = getattr(contra, "contradiction_id", getattr(contra, "id", "contra-1"))

            # If both evidence nodes exist, connect with CONTRADICTS edge
            if ev_a and ev_b and graph.get_node(ev_a) and graph.get_node(ev_b):
                edge_id = f"edge-contradict-{cid}"
                contra_edge = KnowledgeEdge(
                    edge_id=edge_id,
                    source_node_id=ev_a,
                    target_node_id=ev_b,
                    relationship_type=RelationshipType.CONTRADICTS.value,
                    created_at=getattr(contra, "detected_at", utc_now()),
                    valid_from=getattr(contra, "detected_at", utc_now()),
                    status=EdgeStatus.ACTIVE,
                    confidence=1.0,
                    epistemic_nature="CONTRADICTION",
                    refuting_evidence_ids=[ev_a, ev_b],
                    investigation_id=investigation.id,
                    case_id=getattr(investigation, "case_id", ""),
                    is_counterfactual=graph.is_counterfactual,
                    branch_id=graph.branch_id,
                    metadata={"details": getattr(contra, "description", getattr(contra, "explanation", ""))},
                ).seal()
                graph.add_edge(contra_edge)

        # Audit materialization in journal
        if hasattr(investigation, "case_manager") and investigation.case_manager:
            investigation.case_manager.journal.append_entry(
                entry_type=JournalEntryType.KNOWLEDGE_MATERIALIZATION_COMPLETED,
                summary=f"Knowledge graph materialized: {len(graph._nodes)} nodes, {len(graph._edges)} edges",
                reference_id=investigation.id,
                details={
                    "node_count": len(graph._nodes),
                    "edge_count": len(graph._edges),
                    "graph_digest": graph.calculate_graph_digest(),
                },
            )

        return graph
