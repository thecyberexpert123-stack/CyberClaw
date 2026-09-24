"""Immutable and versioned KnowledgeNode data model with integrity hashing."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.knowledge.models import KnowledgeNodeType, utc_now


class KnowledgeNode(BaseModel):
    """Domain-neutral knowledge node representing a discrete entity, finding, hypothesis, or artifact."""

    model_config = ConfigDict(frozen=False)

    node_id: str = Field(default_factory=lambda: str(uuid4()))
    node_type: str = Field(description="Generic node type (e.g. ENTITY, EVIDENCE, HYPOTHESIS, etc.)")
    label: str = Field(default="", description="Human-readable label or identifier")
    created_at: datetime = Field(default_factory=utc_now)
    valid_from: datetime = Field(default_factory=utc_now)
    valid_until: Optional[datetime] = None
    investigation_id: str
    case_id: str = ""
    provenance_references: List[str] = Field(default_factory=list)
    source_references: List[str] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    version: int = 1
    metadata: Dict[str, Any] = Field(default_factory=dict)
    integrity_digest: str = ""
    is_counterfactual: bool = False
    branch_id: Optional[str] = None

    def calculate_node_digest(self) -> str:
        """Compute deterministic SHA-256 hash of canonical node fields."""
        payload = {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "label": self.label,
            "created_at": self.created_at.isoformat(),
            "valid_from": self.valid_from.isoformat(),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "investigation_id": self.investigation_id,
            "case_id": self.case_id,
            "provenance_references": sorted(self.provenance_references),
            "source_references": sorted(self.source_references),
            "evidence_references": sorted(self.evidence_references),
            "version": self.version,
            "metadata": self.metadata,
            "is_counterfactual": self.is_counterfactual,
            "branch_id": self.branch_id,
        }
        encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def seal(self) -> KnowledgeNode:
        """Calculate and store integrity_digest."""
        self.integrity_digest = self.calculate_node_digest()
        return self

    def verify_integrity(self) -> bool:
        """Verify that stored integrity digest matches calculated digest."""
        if not self.integrity_digest:
            return False
        return self.integrity_digest == self.calculate_node_digest()

    def is_valid_at(self, timestamp: datetime) -> bool:
        """Check if node is historically valid at the given timestamp."""
        if timestamp < self.valid_from:
            return False
        if self.valid_until and timestamp >= self.valid_until:
            return False
        return True
