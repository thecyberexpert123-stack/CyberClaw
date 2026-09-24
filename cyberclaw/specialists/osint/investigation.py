"""Local investigation container for the OSINT Specialist."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.evidence.models import Evidence
from cyberclaw.specialists.osint.dfa.machine import OSINTDFA
from cyberclaw.specialists.osint.dfa.states import OSINTState
from cyberclaw.types import Relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class OSINTTargetType(str, Enum):
    """Categorization of OSINT investigation targets."""

    DOMAIN = "domain"
    FQDN = "fqdn"
    IPV4 = "ipv4"
    EMAIL = "email"
    ORGANIZATION = "organization"
    UNKNOWN = "unknown"


def classify_target(target: str) -> OSINTTargetType:
    """Classify an OSINT target string deterministically."""
    clean = target.strip().lower()
    # Check IPv4
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ipv4_pattern, clean):
        return OSINTTargetType.IPV4

    # Check Email
    if "@" in clean and "." in clean.split("@")[-1]:
        return OSINTTargetType.EMAIL

    # Check Domain / FQDN
    domain_pattern = r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$"
    if re.match(domain_pattern, clean):
        parts = clean.split(".")
        if len(parts) > 2:
            return OSINTTargetType.FQDN
        return OSINTTargetType.DOMAIN

    return OSINTTargetType.UNKNOWN


class OSINTInvestigation(BaseModel):
    """Internal investigation state managed exclusively by the OSINT Specialist."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: str = Field(description="Global Core investigation correlation ID")
    target: str
    target_type: OSINTTargetType = OSINTTargetType.UNKNOWN
    dfa: OSINTDFA = Field(default_factory=lambda: OSINTDFA(initial_state=OSINTState.INITIALIZE))
    evidence: List[Evidence] = Field(default_factory=list)
    relationships: List[Relationship] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def current_state(self) -> OSINTState:
        return self.dfa.current_state

    def add_evidence(self, ev: Evidence) -> None:
        self.evidence.append(ev)
        self.updated_at = utc_now()

    def add_relationship(self, rel: Relationship) -> None:
        self.relationships.append(rel)
        self.updated_at = utc_now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "investigation_id": self.investigation_id,
            "target": self.target,
            "target_type": self.target_type.value,
            "current_state": self.current_state.value,
            "evidence_count": len(self.evidence),
            "relationships_count": len(self.relationships),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata,
        }
