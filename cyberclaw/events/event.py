"""Structured event models for CyberClaw Core event communication."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Event(BaseModel):
    """A structured event dispatched through the CyberClaw Event Bus."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str = Field(description="Structured event topic, e.g. 'evidence.created', 'dfa.transition'")
    timestamp: datetime = Field(default_factory=utc_now)
    source: str = Field(description="Emitter identifier, e.g. 'core', 'specialist.osint'")
    correlation_id: Optional[str] = Field(default=None, description="Investigation or trace correlation ID")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
    metadata: Dict[str, Any] = Field(default_factory=dict)
