"""Working Memory system for retained case facts and investigation state."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class MemoryFact(BaseModel):
    """An individual retained fact in working memory."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    key: str = Field(description="Identifying key or topic for this memory")
    value: Any = Field(description="Retained fact content")
    tags: List[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class MemoryStore:
    """Thread-safe working memory store for retained knowledge."""

    def __init__(self, investigation_id: Optional[str] = None) -> None:
        self.investigation_id = investigation_id
        self._facts: Dict[str, MemoryFact] = {}

    def set(
        self,
        key: str,
        value: Any,
        tags: Optional[List[str]] = None,
        confidence: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryFact:
        """Store or update a retained fact in working memory."""
        fact = self._facts.get(key)
        now = utc_now()
        if fact is None:
            fact = MemoryFact(
                key=key,
                value=value,
                tags=tags or [],
                confidence=confidence,
                created_at=now,
                updated_at=now,
                metadata=metadata or {},
            )
        else:
            fact.value = value
            fact.confidence = confidence
            if tags:
                fact.tags = list(set(fact.tags + tags))
            if metadata:
                fact.metadata.update(metadata)
            fact.updated_at = now
        self._facts[key] = fact
        return fact

    def get(self, key: str) -> Optional[Any]:
        """Retrieve the value of a memory fact by key."""
        fact = self._facts.get(key)
        return fact.value if fact else None

    def get_fact(self, key: str) -> Optional[MemoryFact]:
        """Retrieve the full MemoryFact metadata by key."""
        return self._facts.get(key)

    def find_by_tag(self, tag: str) -> List[MemoryFact]:
        """Find facts tagged with a specific tag."""
        return [f for f in self._facts.values() if tag in f.tags]

    def list_all(self) -> List[MemoryFact]:
        """List all retained facts."""
        return list(self._facts.values())

    def clear(self) -> None:
        """Clear memory."""
        self._facts.clear()
