"""Temporal Evidence & Knowledge Graph subsystem for CyberClaw.

Provides domain-neutral, provenance-preserving, temporal knowledge graph representations
of entities, observations, inferences, and relationships.
"""

from __future__ import annotations

from cyberclaw.knowledge.consistency import KnowledgeConsistencyEngine
from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.errors import (
    KnowledgeAuthorizationError,
    KnowledgeBranchLeakError,
    KnowledgeConsistencyError,
    KnowledgeEdgeNotFoundError,
    KnowledgeError,
    KnowledgeIntegrityError,
    KnowledgeMutationError,
    KnowledgeNodeNotFoundError,
    KnowledgePersistenceError,
    KnowledgeTemporalError,
    KnowledgeValidationError,
)
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.materialization import KnowledgeMaterializer
from cyberclaw.knowledge.models import (
    ConsistencyIssue,
    ConsistencySeverity,
    EdgeStatus,
    GraphMutationType,
    KnowledgeCapabilityGap,
    KnowledgeExplanation,
    KnowledgeGap,
    KnowledgeNodeType,
    RelationshipType,
    TemporalContradictionType,
    utc_now,
)
from cyberclaw.knowledge.mutations import (
    GraphMutationPipeline,
    GraphMutationRequest,
    GraphMutationResult,
)
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.persistence import KnowledgePersistenceManager
from cyberclaw.knowledge.provenance import (
    KnowledgeProvenanceRecord,
    build_provenance_chain,
    calculate_source_independence,
)
from cyberclaw.knowledge.queries import (
    CurrentKnowledgeView,
    HistoricalKnowledgeView,
    KnowledgeQueryEngine,
)
from cyberclaw.knowledge.temporal import (
    classify_temporal_contradiction,
    intervals_overlap,
    is_active,
)
from cyberclaw.knowledge.traversal import traverse

__all__ = [
    # Graph & Components
    "TemporalKnowledgeGraph",
    "KnowledgeNode",
    "KnowledgeEdge",
    "KnowledgeProvenanceRecord",
    # Models & Enums
    "KnowledgeNodeType",
    "RelationshipType",
    "EdgeStatus",
    "TemporalContradictionType",
    "GraphMutationType",
    "ConsistencySeverity",
    "ConsistencyIssue",
    "KnowledgeCapabilityGap",
    "KnowledgeGap",
    "KnowledgeExplanation",
    "utc_now",
    # Views & Queries
    "CurrentKnowledgeView",
    "HistoricalKnowledgeView",
    "KnowledgeQueryEngine",
    "traverse",
    # Pipelines & Engines
    "GraphMutationRequest",
    "GraphMutationResult",
    "GraphMutationPipeline",
    "KnowledgeMaterializer",
    "KnowledgeConsistencyEngine",
    "KnowledgePersistenceManager",
    "build_provenance_chain",
    "calculate_source_independence",
    "classify_temporal_contradiction",
    "intervals_overlap",
    "is_active",
    # Exceptions
    "KnowledgeError",
    "KnowledgeValidationError",
    "KnowledgeAuthorizationError",
    "KnowledgeNodeNotFoundError",
    "KnowledgeEdgeNotFoundError",
    "KnowledgeTemporalError",
    "KnowledgeConsistencyError",
    "KnowledgeMutationError",
    "KnowledgePersistenceError",
    "KnowledgeIntegrityError",
    "KnowledgeBranchLeakError",
]
