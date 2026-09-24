"""Structured data models for branch abstraction, counterfactual history, and comparisons."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.case.models import (
    ContradictionRecord,
    DecisionRecord,
    InvestigationSnapshot,
    JournalEntryType,
    utc_now,
)
from cyberclaw.coordination.requirements import InformationRequirement
from cyberclaw.evidence.models import Evidence
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.replay.models import ReconstructedState
from cyberclaw.types import Entity, Hypothesis, Relationship


class BranchStatus(str, Enum):
    """Lifecycle state of an InvestigationBranch."""

    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"
    REJECTED = "REJECTED"
    PROMOTED = "PROMOTED"
    EXPIRED = "EXPIRED"


class BranchJournalEntry(BaseModel):
    """Chronological event entry within a branch's private history."""

    entry_id: str = Field(default_factory=lambda: str(uuid4()))
    branch_id: str
    investigation_id: str
    originating_snapshot_id: Optional[str] = None
    originating_snapshot_sequence: int = 0
    local_sequence: int = Field(ge=1, description="Strictly monotonic branch-local sequence number starting at 1")
    entry_type: JournalEntryType
    timestamp: datetime = Field(default_factory=utc_now)
    summary: str
    reference_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    is_counterfactual: bool = Field(default=True, description="Strict flag indicating this is derived/counterfactual analysis")


class InvestigationBranch(BaseModel):
    """Derived investigative context enabling counterfactual exploration without mutating authoritative history."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    branch_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    parent_branch_id: Optional[str] = None
    source_snapshot_id: str
    source_snapshot_sequence: int
    source_sequence: int = 0
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    status: BranchStatus = BranchStatus.ACTIVE
    purpose: str
    originating_decision_id: Optional[str] = None
    derived_state: Optional[ReconstructedState] = None
    journal: List[BranchJournalEntry] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    simulated_evidence: List[Evidence] = Field(default_factory=list)
    entities: Dict[str, Entity] = Field(default_factory=dict)
    relationships: List[Relationship] = Field(default_factory=list)
    hypotheses: Dict[str, Hypothesis] = Field(default_factory=dict)
    requirements: Dict[str, InformationRequirement] = Field(default_factory=dict)
    contradictions: List[ContradictionRecord] = Field(default_factory=list)
    decisions: List[DecisionRecord] = Field(default_factory=list)
    stopping_condition: Optional[str] = None
    capability_gaps: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    is_counterfactual: bool = Field(default=True, description="Always True; branches represent counterfactual analysis, not facts")

    def get_latest_local_sequence(self) -> int:
        """Return the highest local sequence number in the branch journal."""
        return len(self.journal)

    def calculate_state_digest(self) -> str:
        """Compute deterministic SHA-256 digest of current derived branch state."""
        dfa_state = self.derived_state.dfa_state if self.derived_state else "INIT"
        payload = {
            "branch_id": self.branch_id,
            "investigation_id": self.investigation_id,
            "source_snapshot_sequence": self.source_snapshot_sequence,
            "local_sequence": self.get_latest_local_sequence(),
            "dfa_state": dfa_state,
            "evidence_ids": sorted(self.evidence_references),
            "entity_ids": sorted(list(self.entities.keys())),
            "hypothesis_states": {
                hid: f"{h.status}:{h.confidence:.4f}"
                for hid, h in sorted(self.hypotheses.items())
            },
            "requirement_states": {
                rid: r.status.value
                for rid, r in sorted(self.requirements.items())
            },
            "contradiction_ids": sorted([c.id for c in self.contradictions]),
            "stopping_condition": self.stopping_condition or "",
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


class BranchComparison(BaseModel):
    """Factual, unranked comparison between two investigative paths or a branch and authoritative state."""

    branch_a_id: str
    branch_b_id: str
    common_source_snapshot_sequence: Optional[int] = None
    evidence_differences: Dict[str, List[str]] = Field(
        default_factory=lambda: {"only_in_a": [], "only_in_b": [], "common": []}
    )
    entity_differences: Dict[str, List[str]] = Field(
        default_factory=lambda: {"only_in_a": [], "only_in_b": [], "common": []}
    )
    relationship_differences: Dict[str, List[str]] = Field(
        default_factory=lambda: {"only_in_a": [], "only_in_b": [], "common": []}
    )
    hypothesis_differences: Dict[str, Any] = Field(
        default_factory=lambda: {"status_shifts": {}, "confidence_shifts": {}}
    )
    contradiction_differences: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "unresolved_in_a": [],
            "unresolved_in_b": [],
            "resolved_in_a": [],
            "resolved_in_b": [],
        }
    )
    requirement_differences: Dict[str, List[str]] = Field(
        default_factory=lambda: {
            "satisfied_in_a": [],
            "satisfied_in_b": [],
            "open_in_a": [],
            "open_in_b": [],
        }
    )
    state_transition_differences: Dict[str, str] = Field(
        default_factory=lambda: {"dfa_state_a": "", "dfa_state_b": ""}
    )
    capability_gaps: Dict[str, List[str]] = Field(
        default_factory=lambda: {"gaps_in_a": [], "gaps_in_b": []}
    )
    summary_report: str = Field(default="", description="Factual, unranked summary of comparative differences")
    is_counterfactual_comparison: bool = True


class CandidateBranchExperience(BaseModel):
    """Candidate experience observation derived from branch analysis awaiting explicit promotion."""

    candidate_id: str = Field(default_factory=lambda: str(uuid4()))
    branch_id: str
    investigation_id: str
    experience_record: ExperienceRecord
    is_counterfactual: bool = True
    validated: bool = False
    validation_notes: Optional[str] = None
    promoted_at: Optional[datetime] = None
