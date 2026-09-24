"""Correlation and Contradiction models for CyberClaw Core evidence graph."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CorrelationProvenance(BaseModel):
    """Lineage tracking how a relationship was derived by the Correlation Engine."""

    rule_name: str
    specialists_involved: List[str] = Field(default_factory=list)
    capabilities_involved: List[str] = Field(default_factory=list)
    investigation_id: Optional[str] = None
    derived_at: datetime = Field(default_factory=utc_now)
    context: Dict[str, Any] = Field(default_factory=dict)


class ContradictionRecord(BaseModel):
    """Explicit representation of conflicting evidence or competing relationships."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    subject: str
    conflict_type: str = Field(description="Descriptor of conflict, e.g. 'conflicting_resolution', 'divergent_attribute'")
    competing_evidence_ids: List[str] = Field(default_factory=list)
    description: str
    detected_at: datetime = Field(default_factory=utc_now)
    resolved: bool = False
    resolution_notes: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
