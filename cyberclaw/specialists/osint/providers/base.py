"""Base provider abstraction for OSINT Specialist."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any, Dict, Optional, Tuple
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.evidence.result import ExecutionResult


class OSINTProvider(CapabilityProvider):
    """Abstract provider backing an OSINT capability.

    Handles provider readiness, priority sorting, failure diagnostics,
    and returns standard ExecutionResults.
    """

    def __init__(
        self,
        id: str,
        name: str,
        capability_id: str,
        priority: int = 100,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(id=id, name=name, capability_id=capability_id, priority=priority, metadata=metadata)

    @abstractmethod
    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        """Check provider readiness (e.g. rate limits, dependencies, credentials)."""
        pass

    @abstractmethod
    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        """Execute intelligence collection deterministically."""
        pass
