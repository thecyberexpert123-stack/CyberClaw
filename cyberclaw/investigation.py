"""Investigation case container managing state, evidence, and working memory."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.dfa.machine import CoreDFA
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.store import EvidenceStore
from cyberclaw.memory.memory import MemoryStore


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Investigation(BaseModel):
    """An active investigation case within CyberClaw."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    title: str = Field(description="Investigation title")
    description: str = Field(default="")
    dfa: CoreDFA = Field(default_factory=lambda: CoreDFA(initial_state=CoreState.INITIALIZE))
    evidence_store: EvidenceStore = Field(default_factory=EvidenceStore)
    memory_store: MemoryStore = Field(default_factory=MemoryStore)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def current_state(self) -> CoreState:
        """Convenience property for DFA state."""
        return self.dfa.current_state

    def to_dict(self) -> Dict[str, Any]:
        """Serialize metadata and state to dictionary for persistence."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "current_state": self.current_state.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
            "evidence_count": self.evidence_store.count(),
            "history_count": len(self.dfa.history),
        }
