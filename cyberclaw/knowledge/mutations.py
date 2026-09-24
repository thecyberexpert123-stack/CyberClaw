"""Governed graph mutation boundary, pipeline validation, and Case Journal integration."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.case.models import JournalEntryType
from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.errors import (
    KnowledgeAuthorizationError,
    KnowledgeBranchLeakError,
    KnowledgeMutationError,
    KnowledgeValidationError,
)
from cyberclaw.knowledge.models import GraphMutationType, utc_now
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.models import ActorRole, PolicyExecutionContext


class GraphMutationRequest(BaseModel):
    """Immutable, auditable request to mutate the knowledge graph."""

    model_config = ConfigDict(frozen=False)

    mutation_id: str = Field(default_factory=lambda: str(uuid4()))
    mutation_type: GraphMutationType
    investigation_id: str
    case_id: str = ""
    actor_id: str
    node: Optional[KnowledgeNode] = None
    edge: Optional[KnowledgeEdge] = None
    target_id: Optional[str] = None
    reason: str = ""
    is_counterfactual: bool = False
    branch_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class GraphMutationResult(BaseModel):
    """Structured outcome of a governed graph mutation execution."""

    mutation_id: str
    is_successful: bool
    mutation_type: GraphMutationType
    affected_node_ids: List[str] = Field(default_factory=list)
    affected_edge_ids: List[str] = Field(default_factory=list)
    authorization_decision_id: Optional[str] = None
    error: Optional[str] = None
    execution_timestamp: datetime = Field(default_factory=utc_now)


class GraphMutationPipeline:
    """Multi-phase gatekeeper ensuring all knowledge graph mutations are validated, authorized, and audited."""

    @classmethod
    def apply_mutation(
        cls,
        graph: Any,
        request: GraphMutationRequest,
        policy_engine: Optional[Any] = None,
        investigation: Optional[Any] = None,
    ) -> GraphMutationResult:
        """Process mutation through validation, branch quarantine, policy authorization, and journaling."""
        # 1. Branch isolation enforcement
        if not graph.is_counterfactual and request.is_counterfactual:
            raise KnowledgeBranchLeakError(
                f"Cannot apply counterfactual mutation '{request.mutation_id}' to authoritative graph.",
                investigation_id=request.investigation_id,
            )

        # 2. Contextual Policy Authorization (if policy engine provided)
        auth_decision_id: Optional[str] = None
        if policy_engine and not graph.is_counterfactual:
            scope = ActionScope.REVERSIBLE
            if request.mutation_type in (GraphMutationType.INVALIDATE_EDGE, GraphMutationType.REMOVE_FROM_CURRENT_VIEW):
                scope = ActionScope.CONSEQUENTIAL

            case_stage = "INVESTIGATE"
            if investigation and hasattr(investigation, "current_state"):
                case_stage = investigation.current_state.value

            ctx = PolicyExecutionContext(
                investigation_id=request.investigation_id,
                case_stage=case_stage,
                actor_id=request.actor_id,
                actor_role=ActorRole.SPECIALIST.value,
                capability_id="knowledge.mutate",
                action_type="graph_mutation",
                action_scope=scope.value,
                parameters={
                    "mutation_type": request.mutation_type.value,
                    "target_id": request.target_id,
                    "reason": request.reason,
                },
                is_branch=request.is_counterfactual,
            )
            decision = policy_engine.authorize(ctx)
            auth_decision_id = decision.decision_id
            if hasattr(investigation, "case_manager") and investigation.case_manager:
                policy_engine.record_in_journal(decision, investigation.case_manager)

            if not decision.is_authorized:
                raise KnowledgeAuthorizationError(
                    f"PolicyEngine rejected graph mutation: {'; '.join(decision.reasons)}",
                    investigation_id=request.investigation_id,
                )

        affected_nodes: List[str] = []
        affected_edges: List[str] = []

        # 3. Apply mutation
        try:
            if request.mutation_type == GraphMutationType.ADD_NODE:
                if not request.node:
                    raise KnowledgeValidationError("ADD_NODE requires a KnowledgeNode object.")
                added = graph.add_node(request.node)
                affected_nodes.append(added.node_id)
                cls._log_journal(
                    investigation,
                    JournalEntryType.KNOWLEDGE_NODE_ADDED,
                    f"Knowledge node '{added.node_id}' ({added.node_type}) added to graph",
                    added.node_id,
                    {"node_type": added.node_type, "label": added.label},
                )

            elif request.mutation_type == GraphMutationType.ADD_EDGE:
                if not request.edge:
                    raise KnowledgeValidationError("ADD_EDGE requires a KnowledgeEdge object.")
                if auth_decision_id and not request.edge.authorization_decision_id:
                    request.edge.authorization_decision_id = auth_decision_id
                    request.edge.seal()
                added_edge = graph.add_edge(request.edge)
                affected_edges.append(added_edge.edge_id)
                cls._log_journal(
                    investigation,
                    JournalEntryType.KNOWLEDGE_EDGE_ADDED,
                    f"Knowledge edge '{added_edge.edge_id}' ({added_edge.relationship_type}) added to graph",
                    added_edge.edge_id,
                    {
                        "relationship_type": added_edge.relationship_type,
                        "source": added_edge.source_node_id,
                        "target": added_edge.target_node_id,
                    },
                )

            elif request.mutation_type == GraphMutationType.INVALIDATE_EDGE:
                if not request.target_id:
                    raise KnowledgeValidationError("INVALIDATE_EDGE requires a target edge_id.")
                inv_edge = graph.invalidate_edge(request.target_id, reason=request.reason)
                affected_edges.append(inv_edge.edge_id)
                cls._log_journal(
                    investigation,
                    JournalEntryType.KNOWLEDGE_EDGE_INVALIDATED,
                    f"Knowledge edge '{inv_edge.edge_id}' invalidated: {request.reason}",
                    inv_edge.edge_id,
                    {"reason": request.reason},
                )

            elif request.mutation_type == GraphMutationType.SUPERSEDE_NODE:
                if not request.target_id or not request.node:
                    raise KnowledgeValidationError("SUPERSEDE_NODE requires target_id and replacement node.")
                old_node, new_node = graph.supersede_node(request.target_id, request.node)
                affected_nodes.extend([old_node.node_id, new_node.node_id])
                cls._log_journal(
                    investigation,
                    JournalEntryType.KNOWLEDGE_RELATIONSHIP_SUPERSEDED,
                    f"Knowledge node '{old_node.node_id}' superseded by '{new_node.node_id}' (v{new_node.version})",
                    new_node.node_id,
                    {"old_node_id": old_node.node_id, "new_node_id": new_node.node_id},
                )

            elif request.mutation_type == GraphMutationType.ATTACH_EVIDENCE:
                if not request.target_id or "evidence_id" not in request.metadata:
                    raise KnowledgeValidationError("ATTACH_EVIDENCE requires target_id and metadata['evidence_id'].")
                ev_id = request.metadata["evidence_id"]
                supports = request.metadata.get("supports", True)
                mod_edge = graph.attach_evidence_to_edge(request.target_id, ev_id, supports=supports)
                affected_edges.append(mod_edge.edge_id)

            elif request.mutation_type == GraphMutationType.REMOVE_FROM_CURRENT_VIEW:
                if not request.target_id:
                    raise KnowledgeValidationError("REMOVE_FROM_CURRENT_VIEW requires target_id.")
                edge = graph.get_edge(request.target_id)
                if edge:
                    inv_edge = graph.invalidate_edge(request.target_id, reason="Removed from current view")
                    affected_edges.append(inv_edge.edge_id)
                else:
                    node = graph.get_node(request.target_id)
                    if node:
                        node.valid_until = utc_now()
                        node.seal()
                        affected_nodes.append(node.node_id)

            return GraphMutationResult(
                mutation_id=request.mutation_id,
                is_successful=True,
                mutation_type=request.mutation_type,
                affected_node_ids=affected_nodes,
                affected_edge_ids=affected_edges,
                authorization_decision_id=auth_decision_id,
            )

        except Exception as exc:
            return GraphMutationResult(
                mutation_id=request.mutation_id,
                is_successful=False,
                mutation_type=request.mutation_type,
                error=str(exc),
            )

    @classmethod
    def _log_journal(
        cls,
        investigation: Any,
        entry_type: Any,
        summary: str,
        reference_id: str,
        details: Dict[str, Any],
    ) -> None:
        """Audit mutation into CaseJournal if available."""
        if hasattr(investigation, "case_manager") and investigation.case_manager:
            investigation.case_manager.journal.append_entry(
                entry_type=entry_type,
                summary=summary,
                reference_id=reference_id,
                details=details,
            )
