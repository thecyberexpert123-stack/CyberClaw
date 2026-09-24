"""Domain-agnostic foundational types for CyberClaw Core.

The Core understands generic concepts such as Entity, Source, Relationship,
and Hypothesis. Domain-specific entities (IPs, malware hashes, DNS records)
are represented as typed Entities or Evidence without embedding domain logic
into the Core itself.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    """Return current UTC datetime with timezone awareness."""
    return datetime.now(timezone.utc)


class Source(BaseModel):
    """Source provenance tracking where an observation or evidence originated."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str = Field(description="Generic source type, e.g., 'provider', 'specialist', 'feed', 'user'")
    name: str = Field(description="Human-readable name of the source")
    location: Optional[str] = Field(default=None, description="Optional URI, endpoint, or system path")
    reliability: float = Field(default=1.0, ge=0.0, le=1.0, description="Source reliability score (0.0 to 1.0)")
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Entity(BaseModel):
    """A generic domain-agnostic entity identified during an investigation."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str = Field(description="Generic entity category, e.g., 'host', 'artifact', 'identity'")
    name: str = Field(description="Identifier or name of the entity")
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Relationship(BaseModel):
    """Relationship between entities or evidence in the investigation graph."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    source_id: str = Field(description="ID of source entity or evidence")
    target_id: str = Field(description="ID of target entity or evidence")
    relation_type: str = Field(description="Descriptor of relationship, e.g., 'associated_with', 'resolves_to'")
    is_inferred: bool = Field(default=False, description="True if inferred by correlation; False if explicitly observed in evidence")
    supporting_evidence_ids: List[str] = Field(default_factory=list, description="IDs of evidence directly supporting this relationship")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    status: str = Field(default="active", description="'active', 'contradicted', 'superseded'")
    created_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Hypothesis(BaseModel):
    """An investigative hypothesis reasoned about during an investigation."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str
    statement: str = Field(description="Clear hypothesis proposition")
    status: str = Field(default="proposed", description="'proposed', 'supported', 'refuted', 'inconclusive'")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    supporting_evidence_ids: List[str] = Field(default_factory=list)
    refuting_evidence_ids: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)
