"""Structured Evidence models and Provenance tracking for CyberClaw Core.

Evidence is the primary currency of investigations in CyberClaw.
Every piece of evidence preserves provenance, subject attribution, confidence,
and originating source information.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.types import Source


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Provenance(BaseModel):
    """Tracks full lineage of how an evidence item was produced."""

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    specialist_id: Optional[str] = Field(default=None, description="Specialist that coordinated production")
    provider_id: Optional[str] = Field(default=None, description="Specific capability provider executed")
    capability_id: Optional[str] = Field(default=None, description="Capability invoked")
    investigation_id: Optional[str] = Field(default=None, description="Investigation scope")
    timestamp: datetime = Field(default_factory=utc_now)
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Redacted/safe input parameters")
    environment: Dict[str, Any] = Field(default_factory=dict, description="Runtime execution metadata")


class Observation(BaseModel):
    """An atomic observation recorded before synthesis into higher-order evidence."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    subject: str = Field(description="Target or entity observed")
    raw_data: Any = Field(description="Raw observation content")
    timestamp: datetime = Field(default_factory=utc_now)
    source: Source
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    """Structured evidence object adhering to CyberClaw Core contract."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    type: str = Field(description="Evidence type, e.g. 'observation', 'artifact', 'finding', 'correlation'")
    subject: str = Field(description="Entity, target, or domain subject of the evidence")
    value: Any = Field(description="Normalized structured finding content")
    source: Source = Field(description="Source originating this evidence")
    timestamp: datetime = Field(default_factory=utc_now)
    provenance: Provenance = Field(default_factory=Provenance)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence level between 0.0 and 1.0")
    metadata: Dict[str, Any] = Field(default_factory=dict)
