"""Domain-agnostic foundational types for CyberClaw Core.

The Core understands generic concepts such as Entity, Source, Relationship,
and Hypothesis. Domain-specific entities (IPs, malware hashes, DNS records)
are represented as typed Entities or Evidence without embedding domain logic
into the Core itself.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional
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


# Unit separator keeps type and name from colliding when either contains ':'.
_ENTITY_KEY_SEPARATOR = "\x1f"


class EntityIdentityError(ValueError):
    """Raised when an entity index cannot be migrated without collapsing two identities."""


def entity_storage_key(entity_type: str, name: str) -> str:
    """Canonical storage identity for an entity: type plus name, not name alone."""

    def _escape(value: str) -> str:
        return str(value).replace("\\", "\\\\").replace(_ENTITY_KEY_SEPARATOR, "\\x1f")

    return f"{_escape(entity_type)}{_ENTITY_KEY_SEPARATOR}{_escape(name)}"


def remember_entity(entities: Dict[str, Entity], entity: Entity) -> str:
    """Store `entity` under its canonical identity and drop a stale alias of the same id.

    A later record with the same type and name replaces that identity. A different
    type with the same name occupies a different key and is left in place.
    """
    key = entity_storage_key(entity.type, entity.name)
    entities[key] = entity
    for stale in [k for k, stored in entities.items() if k != key and stored is not None and stored.id == entity.id]:
        del entities[stale]
    return key


def has_entity(
    entities: Mapping[str, Entity],
    name: str,
    entity_type: Optional[str] = None,
) -> bool:
    """Return whether the index already contains this name, optionally of this type."""
    if entity_type is not None:
        key = entity_storage_key(entity_type, name)
        stored = entities.get(key)
        if stored is not None and stored.type == entity_type and stored.name == name:
            return True
    for stored in entities.values():
        if stored is None:
            continue
        if stored.name == name and (entity_type is None or stored.type == entity_type):
            return True
    return False


def normalize_entity_index(entities: Mapping[str, Entity]) -> Dict[str, Entity]:
    """Rekey an entity index to `(type, name)`.

    Name-only historical keys are migrated from each entity's own type and name.
    This does not invent an entity that a name-only index already overwrote.
    Two different entities that would share one canonical key raise
    `EntityIdentityError` instead of dropping one. Already-canonical indexes
    are returned unchanged in content.
    """
    migrated: Dict[str, Entity] = {}
    origin: Dict[str, str] = {}
    ordered = sorted(entities.items(), key=lambda item: str(item[0]))
    for old_key, stored in ordered:
        if stored is None:
            continue
        new_key = entity_storage_key(stored.type, stored.name)
        previous = migrated.get(new_key)
        if previous is not None and previous.id != stored.id:
            raise EntityIdentityError(
                f"Entity index migration would collapse '{origin[new_key]}' and '{old_key}' into '{new_key}'."
            )
        migrated[new_key] = stored
        origin[new_key] = str(old_key)
    return migrated


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
