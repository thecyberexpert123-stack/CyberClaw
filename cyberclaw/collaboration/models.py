"""Immutable data models, schemas, and enums for Multi-Specialist Collaboration & Evidence Consensus v0.1."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.evidence.models import Evidence
from cyberclaw.types import Entity, Source


def utc_now() -> datetime:
    """Return current UTC timestamp with timezone awareness."""
    return datetime.now(timezone.utc)


class CollaborationStatus(str, Enum):
    """Deterministic lifecycle state of a CollaborationRequest."""

    PROPOSED = "PROPOSED"
    VALIDATING = "VALIDATING"
    AUTHORIZED = "AUTHORIZED"
    ROUTED = "ROUTED"
    ACCEPTED = "ACCEPTED"
    IN_PROGRESS = "IN_PROGRESS"
    RESULT_RECEIVED = "RESULT_RECEIVED"
    EVALUATED = "EVALUATED"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"
    DEFERRED = "DEFERRED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    BLOCKED = "BLOCKED"

    @property
    def is_terminal(self) -> bool:
        return self in (
            CollaborationStatus.COMPLETED,
            CollaborationStatus.REJECTED,
            CollaborationStatus.CANCELLED,
            CollaborationStatus.FAILED,
            CollaborationStatus.EXPIRED,
        )

    @property
    def is_active(self) -> bool:
        return not self.is_terminal and self != CollaborationStatus.BLOCKED


class FindingNature(str, Enum):
    """Categorical classification of findings to preserve epistemological distinction."""

    OBSERVATION = "OBSERVATION"          # Directly observed empirical fact from an external source
    INFERENCE = "INFERENCE"              # Derived logical conclusion or deduction by a specialist
    CORRELATION = "CORRELATION"          # Structural relationship identified across multiple data points
    HYPOTHESIS = "HYPOTHESIS"            # Plausible proposition requiring corroboration
    NEGATIVE_FINDING = "NEGATIVE_FINDING"# Empirical confirmation that an entity or indicator was absent
    FAILURE = "FAILURE"                  # Specialist operation failed or timed out


class ContextSensitivity(str, Enum):
    """Sensitivity tier constraining least-privilege information sharing."""

    PUBLIC = "PUBLIC"          # Freely shareable
    INTERNAL = "INTERNAL"      # Shared within standard internal investigation team
    RESTRICTED = "RESTRICTED"  # Elevated confidentiality (e.g. sensitive targets or credentials)
    SENSITIVE = "SENSITIVE"    # Highest operational classification; requires explicit clearance

    @property
    def level(self) -> int:
        levels = {
            ContextSensitivity.PUBLIC: 1,
            ContextSensitivity.INTERNAL: 2,
            ContextSensitivity.RESTRICTED: 3,
            ContextSensitivity.SENSITIVE: 4,
        }
        return levels.get(self, 2)

    def is_accessible_by(self, clearance: str) -> bool:
        try:
            target_tier = ContextSensitivity(clearance)
            return target_tier.level >= self.level
        except ValueError:
            return False


class DependencyType(str, Enum):
    """Dependency enforcement mode."""

    HARD = "HARD"  # Strict block: work cannot commence until satisfied
    SOFT = "SOFT"  # Non-blocking: work may commence with explicit uncertainty marker


class DependencyRelation(str, Enum):
    """Directional relationship between collaborative requirements or tasks."""

    DEPENDS_ON = "depends_on"
    BLOCKS = "blocks"
    UNBLOCKS = "unblocks"
    DERIVED_FROM = "derived_from"
    CORROBORATES = "corroborates"
    CONTRADICTS = "contradicts"


class ConflictType(str, Enum):
    """Taxonomy of disagreements between specialists or evidence claims."""

    CONTRADICTORY_OBSERVATION = "CONTRADICTORY_OBSERVATION"
    CONTRADICTORY_INFERENCE = "CONTRADICTORY_INFERENCE"
    IDENTITY_DISAGREEMENT = "IDENTITY_DISAGREEMENT"
    RELATIONSHIP_DISAGREEMENT = "RELATIONSHIP_DISAGREEMENT"
    TEMPORAL_DISAGREEMENT = "TEMPORAL_DISAGREEMENT"
    SOURCE_DISAGREEMENT = "SOURCE_DISAGREEMENT"
    SCOPE_DISAGREEMENT = "SCOPE_DISAGREEMENT"


class ConflictStatus(str, Enum):
    """Lifecycle status of a recorded SpecialistConflict."""

    OPEN = "OPEN"
    UNDER_REVIEW = "UNDER_REVIEW"
    CORROBORATING = "CORROBORATING"
    RESOLVED = "RESOLVED"
    PERSISTENT = "PERSISTENT"
    ABANDONED = "ABANDONED"


class ConsensusStatus(str, Enum):
    """Consensus state derived from corroborating and refuting evidence."""

    CORROBORATED = "CORROBORATED"  # Confirmed by multiple independent sources
    CONTESTED = "CONTESTED"        # Conflicting evidence exists; under dispute
    INCONCLUSIVE = "INCONCLUSIVE"  # Evidence is contradictory with insufficient weighting
    UNVERIFIED = "UNVERIFIED"      # Single source or uncorroborated inference


class CollaborationDependency(BaseModel):
    """Explicit dependency link between requirements or collaboration requests."""

    source_id: str = Field(description="ID of dependent request or requirement")
    target_id: str = Field(description="ID of required antecedent")
    dependency_type: DependencyType = DependencyType.HARD
    relation: DependencyRelation = DependencyRelation.DEPENDS_ON
    description: str = ""


class CollaborationRequest(BaseModel):
    """Immutable structured request for collaboration between Specialists."""

    model_config = ConfigDict(frozen=False)

    request_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    requesting_specialist: str
    target_specialist: Optional[str] = None
    objective: str = Field(description="Description of what information is sought")
    information_requirement_id: Optional[str] = None
    input_evidence_ids: List[str] = Field(default_factory=list)
    input_entity_ids: List[str] = Field(default_factory=list)
    hypothesis_ids: List[str] = Field(default_factory=list)
    required_capabilities: List[str] = Field(default_factory=list)
    requested_permissions: List[str] = Field(default_factory=list)
    priority: int = Field(default=50, ge=1, le=100)
    deadline: Optional[datetime] = None
    timeout_seconds: Optional[float] = None
    parent_request_id: Optional[str] = None
    correlation_id: str = ""
    causation_id: Optional[str] = None
    status: CollaborationStatus = CollaborationStatus.PROPOSED
    sensitivity: ContextSensitivity = ContextSensitivity.INTERNAL
    action_scope: str = "reversible"
    assigned_runtime_task_id: Optional[str] = None
    authorization_decision_id: Optional[str] = None
    error: Optional[str] = None
    is_counterfactual: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CollaborationContext(BaseModel):
    """Filtered, least-privilege information sharing container."""

    request_id: str
    investigation_id: str
    requesting_specialist: str
    target_specialist: str
    sensitivity: ContextSensitivity
    authorized_evidence: List[Evidence] = Field(default_factory=list)
    authorized_entities: List[Entity] = Field(default_factory=list)
    hypothesis_summaries: List[Dict[str, Any]] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)
    has_soft_dependency_uncertainty: bool = False
    uncertainty_reasons: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)


class CollaborationResult(BaseModel):
    """Structured response returned by a Specialist in response to a CollaborationRequest."""

    result_id: str = Field(default_factory=lambda: str(uuid4()))
    request_id: str
    investigation_id: str
    responding_specialist: str
    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    status: str = "SUCCESS"  # SUCCESS, FAILURE, PARTIAL
    evidence: List[Evidence] = Field(default_factory=list)
    observations: List[Dict[str, Any]] = Field(default_factory=list)
    inferences: List[Dict[str, Any]] = Field(default_factory=list)
    correlations: List[Dict[str, Any]] = Field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = Field(default_factory=list)
    hypotheses_updates: List[Dict[str, Any]] = Field(default_factory=list)
    negative_findings: List[Dict[str, Any]] = Field(default_factory=list)
    failures: List[Dict[str, Any]] = Field(default_factory=list)
    error: Optional[str] = None
    duration_ms: float = 0.0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SpecialistConflict(BaseModel):
    """Explicit, persistent record of disagreement between specialists or evidence claims."""

    conflict_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    subject: str = Field(description="Entity, target, or relationship disputed")
    claim_a: Any = Field(description="First claim value or finding")
    claim_b: Any = Field(description="Second opposing claim value or finding")
    specialist_a: str = Field(description="Specialist making claim A")
    specialist_b: str = Field(description="Specialist making claim B")
    supporting_evidence_a: List[str] = Field(default_factory=list)
    supporting_evidence_b: List[str] = Field(default_factory=list)
    conflict_type: ConflictType = ConflictType.CONTRADICTORY_OBSERVATION
    status: ConflictStatus = ConflictStatus.OPEN
    created_at: datetime = Field(default_factory=utc_now)
    resolved_at: Optional[datetime] = None
    resolution_reference: Optional[str] = None
    resolution_rationale: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ConsensusAssessment(BaseModel):
    """Explainable consensus determination for an entity or claim."""

    subject: str
    consensus_status: ConsensusStatus
    confidence_score: float = Field(default=0.5, ge=0.0, le=1.0)
    independent_sources_count: int = 0
    total_sources_count: int = 0
    is_independently_corroborated: bool = False
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    refuting_evidence_ids: List[str] = Field(default_factory=list)
    active_conflicts: List[str] = Field(default_factory=list)
    explanation: str = ""
    reasons: List[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=utc_now)


class RoutingDecision(BaseModel):
    """Explainable routing outcome connecting a collaboration request to a Specialist."""

    request_id: str
    selected_specialist_id: Optional[str] = None
    selected_capability_id: Optional[str] = None
    candidate_evaluations: List[Dict[str, Any]] = Field(default_factory=list)
    rationale: str = ""
    is_successful: bool = False
