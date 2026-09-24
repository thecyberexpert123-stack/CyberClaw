"""Domain-neutral dispatcher routing runtime tasks through capability and specialist contracts."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.runtime.errors import DispatchError, ProviderExecutionError
from cyberclaw.runtime.models import RuntimeTask
from cyberclaw.specialists.endpoint import SpecialistRequest
from cyberclaw.specialists.registry import SpecialistRegistry


class SpecialistDispatcher:
    """Dispatches executable tasks to registered specialists or direct capability providers.

    Operates purely via structural contracts without domain-specific conditionals.
    """

    def __init__(
        self,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
    ) -> None:
        self.specialists = specialists
        self.capabilities = capabilities

    def dispatch(
        self,
        task: RuntimeTask,
        exec_ctx: ExecutionContext,
        target_specialist_id: Optional[str] = None,
    ) -> Tuple[ExecutionResult, str]:
        """Dispatch task to appropriate specialist or capability provider.

        Returns (ExecutionResult, resolved_subsystem_id).
        """
        capability_id = task.capability_id
        candidate_specialists = self.specialists.find_by_capability(capability_id)

        try:
            if target_specialist_id or candidate_specialists:
                req = SpecialistRequest(
                    investigation_id=task.investigation_id,
                    capability_id=capability_id,
                    action="execute",
                    parameters=task.parameters,
                    context=exec_ctx,
                )
                spec_resp = self.specialists.route_request(req, target_specialist_id=target_specialist_id)
                resolved_id = spec_resp.specialist_id
                result = spec_resp.result
            else:
                # Direct provider execution through registry
                result = self.capabilities.execute_capability(capability_id, task.parameters, exec_ctx)
                resolved_id = "core.registry"

            return result, resolved_id

        except Exception as e:
            is_transient = "timeout" in str(e).lower() or "connection" in str(e).lower() or "transient" in str(e).lower()
            raise ProviderExecutionError(
                f"Execution failed on capability '{capability_id}': {e}",
                task_id=task.task_id,
                investigation_id=task.investigation_id,
                is_retryable=is_transient,
            ) from e
