"""Base contracts for OSINT Specialist skills and composite workflows."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from pydantic import BaseModel, Field

from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.result import ExecutionResult


class OSINTSkill(BaseModel):
    """Declarative specification of a repeatable OSINT capability pattern or skill."""

    id: str = Field(description="Unique skill identifier, e.g. 'skill.domain_profile'")
    name: str
    description: str
    required_capabilities: List[str] = Field(default_factory=list)
    version: str = "0.1.0"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class OSINTWorkflow(ABC):
    """Abstract base workflow orchestrating multi-capability investigative procedures."""

    def __init__(self, id: str, name: str, description: str = "") -> None:
        self.id = id
        self.name = name
        self.description = description

    @abstractmethod
    def execute(
        self,
        parameters: Dict[str, Any],
        context: ExecutionContext,
        capability_invoker: Any,
    ) -> ExecutionResult:
        """Execute the composite workflow steps deterministically."""
        pass
