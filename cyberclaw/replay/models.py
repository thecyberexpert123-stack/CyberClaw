"""Data models for deterministic investigation reconstruction and time-travel queries."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.case.models import (
    ContradictionRecord,
    DecisionRecord,
    DecisionType,
    InvestigationSnapshot,
    utc_now,
)
from cyberclaw.coordination.requirements import InformationRequirement, RequirementStatus
from cyberclaw.evidence.models import Evidence
from cyberclaw.planning.models import InvestigationPlan, StoppingCondition
from cyberclaw.types import Entity, Hypothesis, Relationship


class ReconstructedState(BaseModel):
    """Pure, immutable reconstructed state of an investigation at a specific historical point in time."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    investigation_id: str
    target_sequence: int = Field(description="Historical sequence number reconstructed")
    source_checkpoint_sequence: Optional[int] = Field(
        default=None, description="Snapshot sequence used as baseline checkpoint if any"
    )
    dfa_state: str = Field(description="Reconstructed DFA state")
    evidence: List[Evidence] = Field(default_factory=list, description="All evidence known at this sequence")
    entities: Dict[str, Entity] = Field(default_factory=dict, description="All entities known at this sequence")
    relationships: List[Relationship] = Field(default_factory=list, description="All relationships active at this sequence")
    hypotheses: Dict[str, Hypothesis] = Field(default_factory=dict, description="Hypotheses state at this sequence")
    requirements: Dict[str, InformationRequirement] = Field(
        default_factory=dict, description="Information requirements state at this sequence"
    )
    contradictions: List[ContradictionRecord] = Field(
        default_factory=list, description="Active contradictions at this sequence"
    )
    decisions: List[DecisionRecord] = Field(
        default_factory=list, description="All decisions recorded up to this sequence"
    )
    plans: List[InvestigationPlan] = Field(
        default_factory=list, description="All plans generated up to this sequence"
    )
    stopping_condition: Optional[str] = Field(
        default=None, description="Stopping condition reached if any"
    )
    experience_references: List[str] = Field(
        default_factory=list, description="Global experience IDs linked up to this sequence"
    )
    events_replayed_count: int = Field(default=0, description="Number of journal events consumed during reconstruction")
    reconstructed_at: datetime = Field(default_factory=utc_now)
    state_digest: str = Field(default="", description="Tamper-evident SHA-256 digest of reconstructed state")

    def calculate_digest(self) -> str:
        """Compute deterministic SHA-256 digest matching InvestigationSnapshot structure."""
        payload = {
            "investigation_id": self.investigation_id,
            "sequence": self.target_sequence,
            "dfa_state": self.dfa_state,
            "evidence_ids": sorted([e.id for e in self.evidence]),
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
            "active_plan_id": self.plans[-1].plan_id if self.plans else "",
            "stopping_condition": self.stopping_condition or "",
        }
        serialized = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def seal(self) -> None:
        """Calculate and set state_digest."""
        self.state_digest = self.calculate_digest()

    def verify_against_snapshot(self, snapshot: InvestigationSnapshot) -> bool:
        """Verify that the reconstructed state matches the authoritative snapshot."""
        if snapshot.investigation_id != self.investigation_id:
            return False
        if snapshot.dfa_state != self.dfa_state:
            return False
        # Evidence check
        snap_ev_ids = set(snapshot.evidence_ids)
        recon_ev_ids = {e.id for e in self.evidence}
        if snap_ev_ids != recon_ev_ids:
            return False
        # Entity check
        if set(snapshot.entities.keys()) != set(self.entities.keys()):
            return False
        # Hypothesis status check
        for hid, snap_hyp in snapshot.hypotheses.items():
            recon_hyp = self.hypotheses.get(hid)
            if not recon_hyp or recon_hyp.status != snap_hyp.status:
                return False
        # Requirements check
        for rid, snap_req in snapshot.information_requirements.items():
            recon_req = self.requirements.get(rid)
            if not recon_req or recon_req.status != snap_req.status:
                return False
        return True

    # --------------------------------------------------------------------------
    # Time-Travel Query Helpers
    # --------------------------------------------------------------------------

    def query_evidence(
        self,
        subject: Optional[str] = None,
        type: Optional[str] = None,
    ) -> List[Evidence]:
        """Query reconstructed evidence by subject or type."""
        results = self.evidence
        if subject:
            results = [e for e in results if e.subject.lower() == subject.lower()]
        if type:
            results = [e for e in results if e.type == type]
        return results

    def query_entities(self, type: Optional[str] = None) -> Dict[str, Entity]:
        """Query reconstructed entities, optionally by entity type."""
        if not type:
            return dict(self.entities)
        return {eid: ent for eid, ent in self.entities.items() if ent.type == type}

    def query_hypotheses(self, status: Optional[str] = None) -> Dict[str, Hypothesis]:
        """Query reconstructed hypotheses by status."""
        if not status:
            return dict(self.hypotheses)
        return {hid: h for hid, h in self.hypotheses.items() if h.status == status}

    def query_requirements(
        self,
        status: Optional[RequirementStatus] = None,
    ) -> Dict[str, InformationRequirement]:
        """Query reconstructed requirements by status."""
        if not status:
            return dict(self.requirements)
        return {rid: r for rid, r in self.requirements.items() if r.status == status}

    def query_decisions(
        self,
        decision_type: Optional[DecisionType] = None,
    ) -> List[DecisionRecord]:
        """Query reconstructed decisions by decision type."""
        if not decision_type:
            return list(self.decisions)
        return [d for d in self.decisions if d.decision_type == decision_type]

    def query_contradictions(self, unresolved_only: bool = True) -> List[ContradictionRecord]:
        """Query reconstructed contradictions."""
        if unresolved_only:
            return [c for c in self.contradictions if not c.resolved]
        return list(self.contradictions)

    def to_summary_dict(self) -> Dict[str, Any]:
        """Structured dictionary summary of the reconstructed posture."""
        return {
            "investigation_id": self.investigation_id,
            "sequence": self.target_sequence,
            "source_checkpoint": self.source_checkpoint_sequence,
            "dfa_state": self.dfa_state,
            "evidence_count": len(self.evidence),
            "entities_count": len(self.entities),
            "relationships_count": len(self.relationships),
            "hypotheses_count": len(self.hypotheses),
            "requirements_count": len(self.requirements),
            "contradictions_count": len(self.contradictions),
            "decisions_count": len(self.decisions),
            "plans_count": len(self.plans),
            "stopping_condition": self.stopping_condition,
            "state_digest": self.state_digest,
        }


class ReplayReport(BaseModel):
    """Detailed audit report explaining a replay execution and timeline progression."""

    investigation_id: str
    from_sequence: int
    to_sequence: int
    initial_checkpoint_sequence: Optional[int] = None
    events_replayed: int
    decisions_reconstructed: int
    final_dfa_state: str
    explanation_steps: List[str] = Field(default_factory=list)
    is_valid: bool = True
    digest: str = ""
