"""Domain-neutral data models, enums, and structures for the Knowledge Graph subsystem."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class KnowledgeNodeType(str, Enum):
    """Generic category classifications for Knowledge Nodes. Domain concepts live in metadata."""

    ENTITY = "ENTITY"
    EVIDENCE = "EVIDENCE"
    HYPOTHESIS = "HYPOTHESIS"
    INVESTIGATION = "INVESTIGATION"
    SPECIALIST = "SPECIALIST"
    CAPABILITY = "CAPABILITY"
    CASE = "CASE"
    SOURCE = "SOURCE"
    OBSERVATION = "OBSERVATION"
    ARTIFACT = "ARTIFACT"
    REQUIREMENT = "REQUIREMENT"


class RelationshipType(str, Enum):
    """Domain-neutral relationship edge types connecting knowledge nodes."""

    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    DERIVED_FROM = "DERIVED_FROM"
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"
    CORROBORATES = "CORROBORATES"
    DEPENDS_ON = "DEPENDS_ON"
    OBSERVED_BY = "OBSERVED_BY"
    GENERATED_BY = "GENERATED_BY"
    PART_OF = "PART_OF"
    SAME_AS = "SAME_AS"
    RELATED_TO = "RELATED_TO"


class EdgeStatus(str, Enum):
    """Lifecycle and validity status of a knowledge relationship edge."""

    ACTIVE = "ACTIVE"
    INVALIDATED = "INVALIDATED"
    SUPERSEDED = "SUPERSEDED"
    DISPUTED = "DISPUTED"


class TemporalContradictionType(str, Enum):
    """Classification for temporal vs simultaneous contradiction analysis."""

    SIMULTANEOUS_CONTRADICTION = "SIMULTANEOUS_CONTRADICTION"
    TEMPORAL_CHANGE = "TEMPORAL_CHANGE"
    STALE_INFORMATION = "STALE_INFORMATION"
    UNRESOLVED_CONFLICT = "UNRESOLVED_CONFLICT"


class GraphMutationType(str, Enum):
    """Governed operations that mutate the knowledge graph."""

    ADD_NODE = "ADD_NODE"
    ADD_EDGE = "ADD_EDGE"
    INVALIDATE_EDGE = "INVALIDATE_EDGE"
    SUPERSEDE_NODE = "SUPERSEDE_NODE"
    ATTACH_EVIDENCE = "ATTACH_EVIDENCE"
    ATTACH_PROVENANCE = "ATTACH_PROVENANCE"
    REMOVE_FROM_CURRENT_VIEW = "REMOVE_FROM_CURRENT_VIEW"


class ConsistencySeverity(str, Enum):
    """Severity tier for graph structural consistency diagnostics."""

    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class ConsistencyIssue(BaseModel):
    """Structured diagnostic reporting a knowledge graph inconsistency."""

    issue_type: str
    severity: ConsistencySeverity
    node_id: Optional[str] = None
    edge_id: Optional[str] = None
    related_ids: List[str] = Field(default_factory=list)
    explanation: str
    remediation_hint: str


class KnowledgeCapabilityGap(BaseModel):
    """Identified uncertainty in knowledge graph structure requiring capability execution."""

    gap_id: str = Field(default_factory=lambda: str(uuid4()))
    graph_location: str
    uncertainty_type: str
    affected_hypothesis_id: Optional[str] = None
    missing_evidence_categories: List[str] = Field(default_factory=list)
    relevant_specialists: List[str] = Field(default_factory=list)
    relevant_capabilities: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class KnowledgeGap(BaseModel):
    """Structured uncertainty identified within the knowledge graph for adaptive planning."""

    gap_id: str = Field(default_factory=lambda: str(uuid4()))
    graph_location: str
    uncertainty_type: str
    affected_hypothesis_id: Optional[str] = None
    missing_evidence_categories: List[str] = Field(default_factory=list)
    relevant_specialists: List[str] = Field(default_factory=list)
    relevant_capabilities: List[str] = Field(default_factory=list)
    provenance: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)


class KnowledgeExplanation(BaseModel):
    """Transparent, audit-ready explanation of a node, edge, or hypothesis graph."""

    target_id: str
    target_type: str
    claim: str
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    refuting_evidence_ids: List[str] = Field(default_factory=list)
    source_lineage: List[Dict[str, Any]] = Field(default_factory=list)
    specialists_involved: List[str] = Field(default_factory=list)
    capabilities_involved: List[str] = Field(default_factory=list)
    policy_authorizations: List[str] = Field(default_factory=list)
    temporal_validity: Dict[str, Any] = Field(default_factory=dict)
    confidence_score: float = 1.0
    uncertainties: List[str] = Field(default_factory=list)
    contradictions: List[Dict[str, Any]] = Field(default_factory=list)
