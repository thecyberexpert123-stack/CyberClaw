"""Investigation case container managing state, evidence, and working memory."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr

from cyberclaw.dfa.machine import CoreDFA
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.store import EvidenceStore
from cyberclaw.memory.memory import MemoryStore
from cyberclaw.types import Entity, Hypothesis, Relationship, entity_storage_key, remember_entity
from cyberclaw.coordination.requirements import InformationRequirement
from cyberclaw.correlation.models import ContradictionRecord


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(BaseModel):
    """An active investigation case within CyberClaw coordinating multiple specialists."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(description="Investigation title")
    description: str = Field(default="")
    targets: List[str] = Field(default_factory=list, description="Primary investigation targets")
    participating_specialists: List[str] = Field(
        default_factory=list, description="IDs of specialists participating in this case"
    )
    dfa: CoreDFA = Field(default_factory=lambda: CoreDFA(initial_state=CoreState.INITIALIZE))
    evidence_store: EvidenceStore = Field(default_factory=EvidenceStore)
    memory_store: MemoryStore = Field(default_factory=MemoryStore)
    entities: Dict[str, Entity] = Field(default_factory=dict, description="Extracted entities graph")
    relationships: List[Relationship] = Field(default_factory=list, description="Correlated relationships")
    hypotheses: Dict[str, Hypothesis] = Field(default_factory=dict, description="Working hypotheses")
    information_requirements: Dict[str, InformationRequirement] = Field(
        default_factory=dict, description="Outstanding and satisfied information requirements"
    )
    contradictions: List[ContradictionRecord] = Field(
        default_factory=list, description="Recorded conflicting evidence points"
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    _case_manager: Optional[Any] = PrivateAttr(default=None)
    _branches: Dict[str, Any] = PrivateAttr(default_factory=dict)

    @property
    def branches(self) -> Dict[str, Any]:
        """Dictionary of derived branches indexed by branch_id."""
        return self._branches

    @property
    def case_manager(self) -> Any:
        """Internal CaseManager instance coordinating long-horizon memory."""
        if self._case_manager is None:
            from cyberclaw.case.manager import CaseManager
            self._case_manager = CaseManager(self.id)
        return self._case_manager

    @property
    def current_state(self) -> CoreState:
        """Convenience property for DFA state."""
        return self.dfa.current_state

    def add_entity(self, type: str, name: str, attributes: Optional[Dict[str, Any]] = None) -> Entity:
        """Add or update an Entity in the investigation.

        Identity is `(type, name)`. A second type with the same name is a
        different entity. The same type and name updates the existing record.
        """
        key = entity_storage_key(type, name)
        existing = self.entities.get(key)
        if existing is None or existing.type != type or existing.name != name:
            existing = next(
                (
                    stored
                    for stored in self.entities.values()
                    if stored is not None and stored.type == type and stored.name == name
                ),
                None,
            )
        if existing is not None:
            if attributes:
                existing.attributes.update(attributes)
            existing.last_seen = utc_now()
            remember_entity(self.entities, existing)
            return existing

        entity = Entity(type=type, name=name, attributes=attributes or {})
        remember_entity(self.entities, entity)
        self.record_journal_entry(
            entry_type="CORRELATION_COMPLETED",
            summary=f"Entity added: {name} ({type})",
            reference_id=entity.id,
            details={"entities": [{"id": entity.id, "type": type, "name": name, "attributes": attributes or {}}]},
        )
        return entity

    def create_hypothesis(self, statement: str, initial_confidence: float = 0.5) -> Hypothesis:
        """Formulate a working hypothesis for the investigation."""
        hyp = Hypothesis(
            investigation_id=self.id,
            statement=statement,
            status="OPEN",
            confidence=initial_confidence,
        )
        self.hypotheses[hyp.id] = hyp
        self.record_journal_entry(
            entry_type="HYPOTHESIS_EVALUATED",
            summary=f"Hypothesis formulated: '{statement}'",
            reference_id=hyp.id,
            details={"hypothesis_id": hyp.id, "statement": statement, "status": "OPEN", "confidence": initial_confidence},
        )
        return hyp

    def create_information_requirement(
        self,
        description: str,
        target_or_entity: str,
        evidence_types_sought: Optional[List[str]] = None,
        assigned_capability_id: Optional[str] = None,
        priority: int = 50,
        dependencies: Optional[List[str]] = None,
    ) -> InformationRequirement:
        """Create and track an information requirement within this investigation."""
        req = InformationRequirement(
            investigation_id=self.id,
            description=description,
            target_or_entity=target_or_entity,
            evidence_types_sought=evidence_types_sought or [],
            assigned_capability_id=assigned_capability_id,
            priority=priority,
            dependencies=dependencies or [],
        )
        self.information_requirements[req.id] = req
        self.record_journal_entry(
            entry_type="REQUIREMENT_CREATED",
            summary=f"Requirement created for {target_or_entity}: {description}",
            reference_id=req.id,
            details={"target": target_or_entity, "capability": assigned_capability_id, "evidence_types": req.evidence_types_sought},
        )
        return req

    def add_evidence(self, evidence: Any) -> None:
        """Add structured evidence to the evidence store and journal the event."""
        self.evidence_store.add(evidence)
        self.record_journal_entry(
            entry_type="EVIDENCE_INGESTED",
            summary=f"Ingested evidence: {evidence.subject} ({evidence.type})",
            reference_id=evidence.id,
            details={"evidence_ids": [evidence.id]},
        )

    # --------------------------------------------------------------------------
    # Long-Horizon Case State, Snapshots & Decisions
    # --------------------------------------------------------------------------

    def capture_snapshot(
        self,
        trigger: str = "manual",
        active_plan_id: Optional[str] = None,
        stopping_condition: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Capture an immutable, sealed point-in-time snapshot of the investigation."""
        return self.case_manager.capture_snapshot(
            investigation=self,
            trigger=trigger,
            active_plan_id=active_plan_id,
            stopping_condition=stopping_condition,
            metadata=metadata,
        )

    def get_snapshot(self, sequence_or_id: Union[int, str]):
        """Retrieve a snapshot by sequence index or UUID."""
        return self.case_manager.snapshots.get(sequence_or_id)

    def list_snapshots(self):
        """List all captured snapshots chronologically."""
        return self.case_manager.snapshots.snapshots

    def compare_snapshots(self, first: Union[int, str, Any], second: Union[int, str, Any]):
        """Compute an explainable delta between two snapshots."""
        return self.case_manager.snapshots.compare(first, second)

    def record_decision(
        self,
        decision_type: Any,
        actor: str,
        rationale: str,
        inputs: Optional[Dict[str, Any]] = None,
        outcome: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Record an explicit investigative choice with structured rationale."""
        return self.case_manager.journal.record_decision(
            decision_type=decision_type,
            actor=actor,
            rationale=rationale,
            inputs=inputs,
            outcome=outcome,
            metadata=metadata,
        )

    def record_journal_entry(
        self,
        entry_type: Any,
        summary: str,
        reference_id: Optional[str] = None,
        snapshot_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """Append an event to the chronological case journal."""
        return self.case_manager.journal.append_entry(
            entry_type=entry_type,
            summary=summary,
            reference_id=reference_id,
            snapshot_id=snapshot_id,
            details=details,
        )

    def get_timeline(self) -> List[Dict[str, Any]]:
        """Return serialized chronological timeline."""
        return self.case_manager.journal.get_timeline()

    def explain_state_at(self, sequence_or_id: Union[int, str]) -> Dict[str, Any]:
        """Explain the investigative posture at a specific snapshot."""
        snap = self.get_snapshot(sequence_or_id)
        if not snap:
            raise KeyError(f"Snapshot '{sequence_or_id}' not found.")
        return self.case_manager.snapshots.explain(snap)

    def replay(
        self,
        until_sequence: Optional[int] = None,
        from_snapshot: Optional[Union[int, str]] = None,
        until_snapshot: Optional[Union[int, str]] = None,
    ):
        """Deterministically reconstruct historical state without executing live tools."""
        from cyberclaw.replay.engine import ReplayEngine
        return ReplayEngine.replay(
            self,
            until_sequence=until_sequence,
            from_snapshot=from_snapshot,
            until_snapshot=until_snapshot,
        )

    def query_historical_state(self, sequence: Optional[int] = None):
        """Perform a time-travel state query at a specific sequence index."""
        from cyberclaw.replay.engine import ReplayEngine
        return ReplayEngine.replay(self, until_sequence=sequence)

    def explain_progression(self, from_sequence: int = 1, to_sequence: Optional[int] = None):
        """Explain state progression and historical delta between two sequences."""
        from cyberclaw.replay.engine import ReplayEngine
        max_seq = len(self.case_manager.journal.entries)
        return ReplayEngine.explain_progression(
            self, from_sequence=from_sequence, to_sequence=to_sequence or max_seq
        )

    def get_case_state(self):
        """Assemble the complete CaseState object adhering to the conceptual model."""
        return self.case_manager.assemble_case_state(self)

    # --------------------------------------------------------------------------
    # Investigation Branching & Counterfactual Analysis
    # --------------------------------------------------------------------------

    def create_branch(
        self,
        source_snapshot: Union[int, str],
        purpose: str,
        originating_decision_id: Optional[str] = None,
        parent_branch_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Create an isolated investigation branch rooted at a cryptographically verified snapshot."""
        from cyberclaw.branching.engine import BranchEngine
        branch = BranchEngine.create_branch(
            investigation=self,
            source_snapshot=source_snapshot,
            purpose=purpose,
            originating_decision_id=originating_decision_id,
            parent_branch_id=parent_branch_id,
            metadata=metadata,
        )
        self._branches[branch.branch_id] = branch
        return branch

    def get_branch(self, branch_id: str):
        """Retrieve a branch by ID."""
        return self._branches.get(branch_id)

    def list_branches(self):
        """List all branches created under this investigation."""
        return list(self._branches.values())

    def replay_branch(self, branch_id: str, until_local_sequence: Optional[int] = None):
        """Deterministically reconstruct historical state of a branch."""
        from cyberclaw.branching.engine import BranchEngine
        from cyberclaw.branching.errors import BranchNotFoundError
        branch = self.get_branch(branch_id)
        if not branch:
            raise BranchNotFoundError(f"Branch '{branch_id}' not found in investigation '{self.id}'.")
        return BranchEngine.replay_branch(branch, self, until_local_sequence=until_local_sequence)

    def compare_branches(self, branch_a_id: str, branch_b_id: str):
        """Factually compare two investigation branches."""
        from cyberclaw.branching.engine import BranchEngine
        from cyberclaw.branching.errors import BranchNotFoundError
        ba = self.get_branch(branch_a_id)
        bb = self.get_branch(branch_b_id)
        if not ba:
            raise BranchNotFoundError(f"Branch '{branch_a_id}' not found.")
        if not bb:
            raise BranchNotFoundError(f"Branch '{branch_b_id}' not found.")
        return BranchEngine.compare_branches(ba, bb)

    def compare_branch_with_snapshot(self, branch_id: str, snapshot_seq_or_id: Union[int, str]):
        """Factually compare a branch with an authoritative snapshot."""
        from cyberclaw.branching.engine import BranchEngine
        from cyberclaw.branching.errors import BranchNotFoundError
        branch = self.get_branch(branch_id)
        if not branch:
            raise BranchNotFoundError(f"Branch '{branch_id}' not found.")
        snap = self.get_snapshot(snapshot_seq_or_id)
        if not snap:
            raise KeyError(f"Snapshot '{snapshot_seq_or_id}' not found.")
        return BranchEngine.compare_branch_with_snapshot(branch, snap)

    def promote_branch(self, branch_id: str, reason: str, actor: str = "core.system"):
        """Promote a branch for authoritative consideration without mutating facts."""
        from cyberclaw.branching.engine import BranchEngine
        from cyberclaw.branching.errors import BranchNotFoundError
        branch = self.get_branch(branch_id)
        if not branch:
            raise BranchNotFoundError(f"Branch '{branch_id}' not found.")
        return BranchEngine.promote_branch(branch, self, reason=reason, actor=actor)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize metadata and state to dictionary for persistence."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "targets": self.targets,
            "participating_specialists": self.participating_specialists,
            "current_state": self.current_state.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
            "evidence_count": self.evidence_store.count(),
            "entities_count": len(self.entities),
            "relationships_count": len(self.relationships),
            "hypotheses_count": len(self.hypotheses),
            "requirements_count": len(self.information_requirements),
            "contradictions_count": len(self.contradictions),
            "history_count": len(self.dfa.history),
            "snapshots_count": len(self.case_manager.snapshots.snapshots),
            "decisions_count": len(self.case_manager.journal.decisions),
            "journal_count": len(self.case_manager.journal.entries),
            "branches_count": len(self._branches),
        }
