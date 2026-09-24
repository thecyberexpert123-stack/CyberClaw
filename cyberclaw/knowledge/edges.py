"""First-class immutable KnowledgeEdge data model with integrity hashing and lineage."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.knowledge.models import EdgeStatus, RelationshipType, utc_now


class KnowledgeEdge(BaseModel):
    """First-class knowledge relationship edge linking knowledge nodes with provenance and evidence."""

    model_config = ConfigDict(frozen=False)

    edge_id: str = Field(default_factory=lambda: str(uuid4()))
    source_node_id: str
    target_node_id: str
    relationship_type: str = Field(default=RelationshipType.ASSOCIATED_WITH.value)
    created_at: datetime = Field(default_factory=utc_now)
    valid_from: datetime = Field(default_factory=utc_now)
    valid_until: Optional[datetime] = None
    status: EdgeStatus = EdgeStatus.ACTIVE
    confidence: float = 1.0
    epistemic_nature: str = "OBSERVATION"
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    refuting_evidence_ids: List[str] = Field(default_factory=list)
    provenance_ids: List[str] = Field(default_factory=list)
    originating_specialist: Optional[str] = None
    capability_id: Optional[str] = None
    capability_version: Optional[str] = None
    authorization_decision_id: Optional[str] = None
    investigation_id: str
    case_id: str = ""
    branch_id: Optional[str] = None
    is_counterfactual: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
    integrity_digest: str = ""

    def calculate_edge_digest(self) -> str:
        """Compute deterministic SHA-256 hash of canonical edge fields."""
        payload = {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relationship_type": self.relationship_type,
            "created_at": self.created_at.isoformat(),
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "status": self.status.value,
            "confidence": self.confidence,
            "epistemic_nature": self.epistemic_nature,
            "supporting_evidence_ids": sorted(self.supporting_evidence_ids),
            "refuting_evidence_ids": sorted(self.refuting_evidence_ids),
            "provenance_ids": sorted(self.provenance_ids),
            "originating_specialist": self.originating_specialist,
            "capability_id": self.capability_id,
            "capability_version": self.capability_version,
            "authorization_decision_id": self.authorization_decision_id,
            "investigation_id": self.investigation_id,
            "case_id": self.case_id,
            "branch_id": self.branch_id,
            "is_counterfactual": self.is_counterfactual,
            "metadata": self.metadata,
        }
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def seal(self) -> KnowledgeEdge:
        """Calculate and store integrity_digest."""
        self.integrity_digest = self.calculate_edge_digest()
        return self

    def verify_integrity(self) -> bool:
        """Verify that stored integrity digest matches calculated digest."""
        if not self.integrity_digest:
            return False
        return self.integrity_digest == self.calculate_edge_digest()

    def is_valid_at(self, timestamp: datetime) -> bool:
        """Check if edge was historically valid at the given timestamp."""
        if timestamp < self.valid_from:
            return False
        if self.valid_until and timestamp >= self.valid_until:
            return False
        return True
