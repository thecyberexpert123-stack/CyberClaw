"""Evidence store for organizing and querying investigation findings."""

from __future__ import annotations

from typing import Dict, List, Optional
from cyberclaw.evidence.models import Evidence
from cyberclaw.types import Relationship


class EvidenceStore:
    """Thread-safe and auditable evidence repository scoped to an investigation."""

    def __init__(self, investigation_id: Optional[str] = None) -> None:
        self.investigation_id = investigation_id
        self._evidence_by_id: Dict[str, Evidence] = {}
        self._relationships: List[Relationship] = []

    def add(self, evidence: Evidence) -> Evidence:
        """Add structured evidence to the store."""
        self._evidence_by_id[evidence.id] = evidence
        return evidence

    def add_many(self, evidence_list: List[Evidence]) -> List[Evidence]:
        """Add multiple structured evidence objects."""
        for ev in evidence_list:
            self.add(ev)
        return evidence_list

    def get(self, evidence_id: str) -> Optional[Evidence]:
        """Retrieve evidence by its unique ID."""
        return self._evidence_by_id.get(evidence_id)

    def list_all(self) -> List[Evidence]:
        """Return all evidence items currently in the store."""
        return list(self._evidence_by_id.values())

    def find_by_subject(self, subject: str) -> List[Evidence]:
        """Find all evidence matching a given subject."""
        return [ev for ev in self._evidence_by_id.values() if ev.subject == subject]

    def find_by_type(self, evidence_type: str) -> List[Evidence]:
        """Find all evidence matching a given type."""
        return [ev for ev in self._evidence_by_id.values() if ev.type == evidence_type]

    def add_relationship(self, relationship: Relationship) -> Relationship:
        """Add a relationship connecting evidence or entities."""
        self._relationships.append(relationship)
        return relationship

    def list_relationships(self) -> List[Relationship]:
        """Return all relationships in the store."""
        return list(self._relationships)

    def count(self) -> int:
        """Total count of evidence items."""
        return len(self._evidence_by_id)

    def clear(self) -> None:
        """Clear store."""
        self._evidence_by_id.clear()
        self._relationships.clear()
