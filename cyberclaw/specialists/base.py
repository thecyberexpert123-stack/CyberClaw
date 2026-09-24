"""Specialist model representing semi-autonomous subsystems."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.specialists.endpoint import SpecialistEndpoint, SpecialistHealth


class Specialist(BaseModel):
    """A registered semi-autonomous Specialist in CyberClaw.

    The Core interacts exclusively through this contract without depending on
    the Specialist's internal reasoning, local DFA, or tools.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(description="Unique specialist identifier, e.g. 'osint', 'network'")
    name: str = Field(description="Human-readable specialist name")
    version: str = Field(default="0.1.0")
    capabilities: List[str] = Field(
        default_factory=list, description="IDs of capabilities provided or managed by this specialist"
    )
    endpoint: SpecialistEndpoint = Field(description="Contract boundary endpoint")
    permissions: List[str] = Field(
        default_factory=list, description="Explicit permissions granted to this specialist"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def get_health(self) -> SpecialistHealth:
        """Query the specialist endpoint for its current health."""
        return self.endpoint.health()
