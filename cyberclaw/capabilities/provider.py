"""Capability provider contracts and execution contexts for CyberClaw Core."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.evidence.result import ExecutionResult


class ExecutionContext(BaseModel):
    """Contextual metadata passed to capability providers and specialists."""

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    investigation_id: Optional[str] = Field(default=None)
    correlation_id: Optional[str] = Field(default=None)
    actor: str = Field(default="core.system")
    granted_permissions: List[str] = Field(default_factory=list)
    environment: Dict[str, Any] = Field(default_factory=dict)


class CapabilityProvider(ABC):
    """Abstract base provider backing a capability.

    A provider may wrap a mock, an internal algorithm, a CLI tool, a library,
    or an external API without the Core knowing provider-specific details.
    """

    def __init__(
        self,
        id: str,
        name: str,
        capability_id: str,
        priority: int = 100,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.id = id
        self.name = name
        self.capability_id = capability_id
        self.priority = priority
        self.metadata = metadata or {}

    @abstractmethod
    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        """Check whether the provider is currently ready to execute.

        Returns (ready: bool, reason_if_not_ready: Optional[str]).
        Allows capturing structured reasons such as missing dependency or unconfigured credentials.
        """
        pass

    @abstractmethod
    def execute(
        self,
        parameters: Dict[str, Any],
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Execute the capability against given parameters and context.

        Must return a structured ExecutionResult distinguishing SUCCESS,
        SUCCESS_EMPTY, or FAILURE.
        """
        pass
