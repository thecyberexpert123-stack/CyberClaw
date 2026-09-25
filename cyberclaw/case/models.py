"""Structured contracts for Long-Horizon Investigation Memory and Case State.

Distinguishes:
- Current State
- State History
- Evidence Registry
- Entity/Relationship Graph
- Hypothesis History
- Requirement History
- Planning History
- Execution History
- Decision History
- Contradiction History
- Stopping History
- Experience References
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.coordination.requirements import InformationRequirement, RequirementStatus
from cyberclaw.correlation.models import ContradictionRecord
from cyberclaw.planning.models import InvestigationPlan, StoppingCondition
from cyberclaw.types import Entity, Hypothesis, Relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class DecisionType(str, Enum):
    """Categorization of deliberate investigative decisions."""

    STATE_TRANSITION = "STATE_TRANSITION"
    PLANNING_SELECTION = "PLANNING_SELECTION"
    PLANNING_REJECTION = "PLANNING_REJECTION"
    HYPOTHESIS_TRANSITION = "HYPOTHESIS_TRANSITION"
    REQUIREMENT_RESOLUTION = "REQUIREMENT_RESOLUTION"
    CONTRADICTION_ADJUDICATION = "CONTRADICTION_ADJUDICATION"
    STOPPING_CRITERIA = "STOPPING_CRITERIA"
    AUTHORIZATION_DECISION = "AUTHORIZATION_DECISION"
    POLICY_EVALUATION = "POLICY_EVALUATION"


class JournalEntryType(str, Enum):
    """Event classifications for the chronological Case Journal."""

    INVESTIGATION_CREATED = "INVESTIGATION_CREATED"
    STATE_TRANSITION = "STATE_TRANSITION"
    EVIDENCE_INGESTED = "EVIDENCE_INGESTED"
    ENTITY_ADDED = "ENTITY_ADDED"
    RELATIONSHIP_ADDED = "RELATIONSHIP_ADDED"
    REQUIREMENT_CREATED = "REQUIREMENT_CREATED"
    REQUIREMENT_EXECUTED = "REQUIREMENT_EXECUTED"
    CORRELATION_COMPLETED = "CORRELATION_COMPLETED"
    CONTRADICTION_DETECTED = "CONTRADICTION_DETECTED"
    HYPOTHESIS_EVALUATED = "HYPOTHESIS_EVALUATED"
    PLAN_GENERATED = "PLAN_GENERATED"
    DECISION_RECORDED = "DECISION_RECORDED"
    STOPPING_CONDITION = "STOPPING_CONDITION"
    SNAPSHOT_CAPTURED = "SNAPSHOT_CAPTURED"
    AUTHORIZATION_REQUESTED = "AUTHORIZATION_REQUESTED"
    AUTHORIZATION_GRANTED = "AUTHORIZATION_GRANTED"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    AUTHORIZATION_DEFERRED = "AUTHORIZATION_DEFERRED"
    APPROVAL_REQUESTED = "APPROVAL_REQUESTED"
    APPROVAL_GRANTED = "APPROVAL_GRANTED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    POLICY_CONFLICT_DETECTED = "POLICY_CONFLICT_DETECTED"
    RISK_ASSESSED = "RISK_ASSESSED"
    TASK_QUEUED = "TASK_QUEUED"
    TASK_CLAIMED = "TASK_CLAIMED"
    TASK_COMPLETED = "TASK_COMPLETED"
    COLLABORATION_REQUESTED = "COLLABORATION_REQUESTED"
    COLLABORATION_AUTHORIZED = "COLLABORATION_AUTHORIZED"
    COLLABORATION_REJECTED = "COLLABORATION_REJECTED"
    COLLABORATION_ACCEPTED = "COLLABORATION_ACCEPTED"
    COLLABORATION_STARTED = "COLLABORATION_STARTED"
    COLLABORATION_RESULT_RECEIVED = "COLLABORATION_RESULT_RECEIVED"
    COLLABORATION_COMPLETED = "COLLABORATION_COMPLETED"
    COLLABORATION_FAILED = "COLLABORATION_FAILED"
    SPECIALIST_CONFLICT_DETECTED = "SPECIALIST_CONFLICT_DETECTED"
    SPECIALIST_CONFLICT_RESOLVED = "SPECIALIST_CONFLICT_RESOLVED"
    EVIDENCE_CORROBORATED = "EVIDENCE_CORROBORATED"
    EVIDENCE_CONTRADICTED = "EVIDENCE_CONTRADICTED"
    KNOWLEDGE_NODE_ADDED = "KNOWLEDGE_NODE_ADDED"
    KNOWLEDGE_EDGE_ADDED = "KNOWLEDGE_EDGE_ADDED"
    KNOWLEDGE_EDGE_INVALIDATED = "KNOWLEDGE_EDGE_INVALIDATED"
    KNOWLEDGE_RELATIONSHIP_SUPERSEDED = "KNOWLEDGE_RELATIONSHIP_SUPERSEDED"
    KNOWLEDGE_CONFLICT_DETECTED = "KNOWLEDGE_CONFLICT_DETECTED"
    KNOWLEDGE_MATERIALIZATION_COMPLETED = "KNOWLEDGE_MATERIALIZATION_COMPLETED"
    STRATEGY_SIMULATION_RECORDED = "STRATEGY_SIMULATION_RECORDED"


class DecisionRecord(BaseModel):
    """Durable record capturing why an investigative decision was made."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    sequence: int = Field(description="Monotonic case sequence number")
    timestamp: datetime = Field(default_factory=utc_now)
    decision_type: DecisionType
    actor: str = Field(description="Subsystem or actor making the decision, e.g. core.planner, core.coordinator")
    rationale: str = Field(description="Explainable reasoning basis for this decision")
    inputs: Dict[str, Any] = Field(default_factory=dict, description="Input evidence IDs, hypotheses, or candidate details")
    outcome: Dict[str, Any] = Field(default_factory=dict, description="Decision outcome, selected candidates, or state changes")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class JournalEntry(BaseModel):
    """Chronological journal event in the immutable case timeline."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    sequence: int = Field(description="Monotonic case sequence number")
    timestamp: datetime = Field(default_factory=utc_now)
    entry_type: JournalEntryType
    summary: str = Field(description="Concise human-readable description of event")
    reference_id: Optional[str] = Field(default=None, description="Optional associated ID (req, plan, evidence)")
    snapshot_id: Optional[str] = Field(default=None, description="Optional associated snapshot ID")
    details: Dict[str, Any] = Field(default_factory=dict)


class InvestigationSnapshot(BaseModel):
    """Durable point-in-time representation answering: 'What did CyberClaw know at this point?'."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    snapshot_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    sequence: int = Field(description="Monotonic sequence number of the snapshot")
    timestamp: datetime = Field(default_factory=utc_now)
    trigger: str = Field(description="Reason/milestone triggering snapshot (e.g. planning_cycle, evidence_ingestion)")
    dfa_state: str = Field(description="Core DFA state at snapshot creation")
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of all evidence present at this snapshot")
    entities: Dict[str, Entity] = Field(default_factory=dict, description="Known entities at this point")
    relationships: List[Relationship] = Field(default_factory=list, description="Active relationships at this point")
    hypotheses: Dict[str, Hypothesis] = Field(default_factory=dict, description="Hypotheses state at this point")
    information_requirements: Dict[str, InformationRequirement] = Field(
        default_factory=dict, description="Requirements state at this point"
    )
    contradictions: List[ContradictionRecord] = Field(
        default_factory=list, description="Contradictions active at this point"
    )
    active_plan_id: Optional[str] = Field(default=None, description="ID of current plan at this point")
    stopping_condition: Optional[str] = Field(default=None, description="Stopping condition if halted")
    state_digest: str = Field(default="", description="Tamper-evident SHA-256 hash of snapshot content")
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def calculate_digest(self) -> str:
        """Compute a deterministic SHA-256 hash representing the exact state at this snapshot."""
        payload = {
            "investigation_id": self.investigation_id,
            "sequence": self.sequence,
            "dfa_state": self.dfa_state,
            "evidence_ids": sorted(self.evidence_ids),
            "entity_ids": sorted(list(self.entities.keys())),
            "hypothesis_states": {
                hid: f"{h.status}:{h.confidence:.4f}"
                for hid, h in sorted(self.hypotheses.items())
            },
            "requirement_states": {
                rid: r.status.value
                for rid, r in sorted(self.information_requirements.items())
            },
            "contradiction_ids": sorted([c.id for c in self.contradictions]),
            "active_plan_id": self.active_plan_id or "",
            "stopping_condition": self.stopping_condition or "",
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def seal(self) -> None:
        """Compute and set the state_digest."""
        self.state_digest = self.calculate_digest()

    def verify_integrity(self) -> bool:
        """Verify that the state_digest matches the snapshot content."""
        if not self.state_digest:
            return False
        return self.calculate_digest() == self.state_digest


class SnapshotDelta(BaseModel):
    """Explainable diff between two investigation snapshots."""

    investigation_id: str
    from_sequence: int
    to_sequence: int
    from_snapshot_id: str
    to_snapshot_id: str
    dfa_state_transition: Optional[Tuple[str, str]] = None
    added_evidence_ids: List[str] = Field(default_factory=list)
    added_entities: List[str] = Field(default_factory=list)
    added_relationships: int = 0
    hypothesis_changes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    requirement_changes: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    new_contradictions: List[str] = Field(default_factory=list)
    resolved_contradictions: List[str] = Field(default_factory=list)
    plan_changed: bool = False


class StateTransitionRecord(BaseModel):
    """History entry for Core DFA state transitions."""

    from_state: str
    to_state: str
    event: str
    timestamp: datetime = Field(default_factory=utc_now)
    context: Dict[str, Any] = Field(default_factory=dict)
    reason: Optional[str] = None


class ExecutionHistoryRecord(BaseModel):
    """Detailed log of specialist execution for an InformationRequirement."""

    requirement_id: str
    specialist_id: str
    capability_id: str
    capability_version: str = Field(default="1.0.0", description="Version of capability executed")
    provider_id: Optional[str] = Field(default=None, description="ID of provider that executed")
    provider_version: Optional[str] = Field(default=None, description="Version of provider if available")
    lifecycle_state: str = Field(default="AVAILABLE", description="Lifecycle state at time of execution")
    trust_state: str = Field(default="TRUSTED_WITH_SCOPE", description="Trust state at time of execution")
    permission_scope: str = Field(default="reversible", description="Permission scope enforced")
    action_scope: str = Field(default="consequential", description="Action scope enforced")
    validation_reference: Optional[str] = Field(default=None, description="Reference to validation record if applicable")
    authorization_decision_id: Optional[str] = Field(default=None, description="ID of policy authorization decision")
    risk_level: Optional[str] = Field(default=None, description="Assessed risk level at execution time")
    policy_id: Optional[str] = Field(default=None, description="Policy evaluated for this execution")
    policy_version: Optional[str] = Field(default=None, description="Recorded policy version, not the current latest")
    decision: Optional[str] = Field(default=None, description="Recorded authorization decision")
    actor: Optional[str] = Field(default=None, description="Actor the authorization was evaluated for")
    task_id: Optional[str] = Field(default=None, description="Runtime task id when execution was queued")
    provider_outcome: Optional[str] = Field(default=None, description="Classified provider outcome, not exception text")
    investigation_id: Optional[str] = Field(default=None, description="Case the execution belonged to")
    status: str
    duration_ms: Optional[float] = None
    evidence_count: int = 0
    timestamp: datetime = Field(default_factory=utc_now)
    error: Optional[str] = None


class CaseState(BaseModel):
    """The complete long-horizon case container distinguishing all histories."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    investigation_id: str
    title: str
    # 1. Current State
    current_dfa_state: str
    # 2. State History
    state_history: List[StateTransitionRecord] = Field(default_factory=list)
    # 3. Evidence Registry
    evidence_registry: List[str] = Field(default_factory=list)
    # 4. Entity / Relationship Graph
    entities: Dict[str, Entity] = Field(default_factory=dict)
    relationships: List[Relationship] = Field(default_factory=list)
    # 5. Hypothesis History
    hypotheses: Dict[str, Hypothesis] = Field(default_factory=dict)
    # 6. Requirement History
    requirements: Dict[str, InformationRequirement] = Field(default_factory=dict)
    # 7. Planning History
    planning_history: List[InvestigationPlan] = Field(default_factory=list)
    # 8. Execution History
    execution_history: List[ExecutionHistoryRecord] = Field(default_factory=list)
    # 9. Decision History
    decision_history: List[DecisionRecord] = Field(default_factory=list)
    # 10. Contradiction History
    contradictions: List[ContradictionRecord] = Field(default_factory=list)
    # 11. Stopping History
    stopping_history: List[StoppingCondition] = Field(default_factory=list)
    # 12. Experience References
    experience_references: List[str] = Field(default_factory=list)
    # Snapshots
    snapshots: List[InvestigationSnapshot] = Field(default_factory=list)
    # Journal / Timeline
    journal: List[JournalEntry] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
