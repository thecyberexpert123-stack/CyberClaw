"""Registry for managing Specialist registration, discovery, health, and routing."""

from __future__ import annotations

from typing import Dict, List, Optional
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)


class SpecialistRegistryError(Exception):
    """Raised on specialist registry errors."""
    pass


class SpecialistRegistry:
    """Core registry managing semi-autonomous specialist instances."""

    def __init__(self) -> None:
        self._specialists: Dict[str, Specialist] = {}

    def register_specialist(self, specialist: Specialist) -> None:
        """Register a specialist subsystem."""
        self._specialists[specialist.id] = specialist

    def unregister_specialist(self, specialist_id: str) -> Optional[Specialist]:
        """Unregister a specialist by ID."""
        return self._specialists.pop(specialist_id, None)

    def get_specialist(self, specialist_id: str) -> Optional[Specialist]:
        """Retrieve specialist by ID."""
        return self._specialists.get(specialist_id)

    def list_specialists(self) -> List[Specialist]:
        """List all currently registered specialists."""
        return list(self._specialists.values())

    def find_by_capability(self, capability_id: str) -> List[Specialist]:
        """Find all specialists that advertise the specified capability."""
        return [
            s for s in self._specialists.values()
            if capability_id in s.capabilities
        ]

    def check_health_all(self) -> Dict[str, SpecialistHealth]:
        """Query health state across all registered specialists."""
        return {s.id: s.get_health() for s in self._specialists.values()}

    def route_request(
        self,
        request: SpecialistRequest,
        target_specialist_id: Optional[str] = None,
    ) -> SpecialistResponse:
        """Route a structured request to an appropriate specialist endpoint."""
        specialist: Optional[Specialist] = None

        if target_specialist_id:
            specialist = self.get_specialist(target_specialist_id)
            if not specialist:
                err_result = ExecutionResult.failure(
                    error=f"Specialist '{target_specialist_id}' not found",
                    error_code="SPECIALIST_NOT_FOUND",
                    execution_id=request.context.execution_id,
                )
                return SpecialistResponse.from_result(
                    specialist_id=target_specialist_id,
                    request_id=request.request_id,
                    result=err_result,
                )
        else:
            candidates = self.find_by_capability(request.capability_id)
            if not candidates:
                err_result = ExecutionResult.failure(
                    error=f"No specialist found providing capability '{request.capability_id}'",
                    error_code="SPECIALIST_CAPABILITY_NOT_FOUND",
                    execution_id=request.context.execution_id,
                )
                return SpecialistResponse.from_result(
                    specialist_id="unknown",
                    request_id=request.request_id,
                    result=err_result,
                )
            # Pick first healthy specialist, or first candidate if none explicitly marked healthy
            healthy_candidates = [s for s in candidates if s.get_health() == SpecialistHealth.HEALTHY]
            specialist = healthy_candidates[0] if healthy_candidates else candidates[0]

        # Dispatch request to specialist endpoint contract boundary
        try:
            return specialist.endpoint.invoke(request)
        except Exception as exc:
            err_result = ExecutionResult.failure(
                error=f"Specialist '{specialist.id}' raised unhandled exception: {exc}",
                error_code="SPECIALIST_INVOCATION_EXCEPTION",
                execution_id=request.context.execution_id,
                metadata={"specialist_id": specialist.id, "exception": str(exc)},
            )
            return SpecialistResponse.from_result(
                specialist_id=specialist.id,
                request_id=request.request_id,
                result=err_result,
            )
