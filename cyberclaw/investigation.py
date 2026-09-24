"""Investigation case container managing state, evidence, and working memory."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.dfa.machine import CoreDFA
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.store import EvidenceStore
from cyberclaw.memory.memory import MemoryStore
from cyberclaw.types import Entity, Hypothesis, Relationship
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

    @property
    def current_state(self) -> CoreState:
        """Convenience property for DFA state."""
        return self.dfa.current_state

    def add_entity(self, type: str, name: str, attributes: Optional[Dict[str, Any]] = None) -> Entity:
        """Add or update an Entity in the investigation."""
        for existing in self.entities.values():
            if existing.type == type and existing.name == name:
                if attributes:
                    existing.attributes.update(attributes)
                existing.last_seen = utc_now()
                return existing

        entity = Entity(type=type, name=name, attributes=attributes or {})
        self.entities[entity.id] = entity
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
        return req

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
        }
