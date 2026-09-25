"""Registry for capabilities and their backing providers."""

from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import (
    CapabilityCompatibilityError,
    CapabilityError,
    CapabilityNotFoundError,
    CapabilityTrustError,
    CapabilityUnavailableError,
)
from cyberclaw.capabilities.models import (
    CapabilityFailureType,
    CapabilityHealth,
    CapabilityLifecycleState,
    CapabilityTrustState,
)
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.evidence.result import ExecutionResult


class CapabilityRegistry:
    """Manages capability declarations, versioning, lifecycle states, and provider resolution."""

    def __init__(self) -> None:
        self._capabilities: Dict[str, Capability] = {}
        self._versioned_capabilities: Dict[str, Capability] = {}
        # Maps capability_id to list of registered providers
        self._providers: Dict[str, List[CapabilityProvider]] = {}

    def register_capability(
        self,
        capability: Capability,
        allow_overwrite: bool = False,
    ) -> None:
        """Register a new capability in the system enforcing version uniqueness."""
        vid = capability.versioned_id
        if vid in self._versioned_capabilities and not allow_overwrite:
            existing = self._versioned_capabilities[vid]
            if existing.id == capability.id and existing.version == capability.version and existing != capability:
                raise CapabilityError(
                    f"Version conflict: Capability '{vid}' is already registered with different configuration.",
                    capability_id=capability.id,
                )

        self._versioned_capabilities[vid] = capability
        self._capabilities[capability.id] = capability

        if capability.id not in self._providers:
            self._providers[capability.id] = []

    def get_capability(
        self,
        capability_id: str,
        version: Optional[str] = None,
    ) -> Optional[Capability]:
        """Retrieve capability definition by ID or versioned ID."""
        if version is not None:
            return self._versioned_capabilities.get(f"{capability_id}@{version}")
        if "@" in capability_id:
            return self._versioned_capabilities.get(capability_id)
        return self._capabilities.get(capability_id)

    def list_capabilities(
        self,
        category: Optional[str] = None,
        include_retired: bool = False,
        include_disabled: bool = False,
    ) -> List[Capability]:
        """List all registered capabilities, optionally filtered by category and lifecycle state."""
        caps = list(self._capabilities.values())
        if category is not None:
            caps = [c for c in caps if c.category == category]
        if not include_retired:
            caps = [c for c in caps if c.lifecycle_state != CapabilityLifecycleState.RETIRED]
        if not include_disabled:
            caps = [c for c in caps if c.lifecycle_state != CapabilityLifecycleState.DISABLED]
        return caps

    def register_provider(self, provider: CapabilityProvider) -> None:
        """Register a provider backing a specific capability.

        Multiple providers can back the same capability with different priorities.
        """
        if self.get_capability(provider.capability_id) is None:
            raise CapabilityNotFoundError(
                f"Provider '{provider.id}' cannot create capability '{provider.capability_id}'. "
                "Register the capability through governance before attaching a provider.",
                capability_id=provider.capability_id,
            )

        providers = self._providers.setdefault(provider.capability_id, [])
        # Avoid duplicate registration
        providers = [p for p in providers if p.id != provider.id]
        providers.append(provider)
        # Keep providers sorted descending by priority
        providers.sort(key=lambda p: p.priority, reverse=True)
        self._providers[provider.capability_id] = providers

    def get_providers(self, capability_id: str) -> List[CapabilityProvider]:
        """Return all providers registered for a capability."""
        # Strip version tag if present
        bare_id = capability_id.split("@")[0]
        return list(self._providers.get(bare_id, []))

    def resolve_provider(
        self,
        capability_id: str,
        context: ExecutionContext,
    ) -> Tuple[Optional[CapabilityProvider], Optional[str]]:
        """Resolve the highest-priority provider that reports is_ready()."""
        bare_id = capability_id.split("@")[0]
        providers = self._providers.get(bare_id, [])
        if not providers:
            return None, f"No provider registered for capability '{capability_id}'"

        unready_reasons: List[str] = []
        for provider in providers:
            ready, reason = provider.is_ready(context)
            if ready:
                return provider, None
            unready_reasons.append(f"Provider '{provider.id}' not ready: {reason}")

        return None, "; ".join(unready_reasons)

    def get_capability_health(
        self,
        capability_id: str,
        context: Optional[ExecutionContext] = None,
    ) -> CapabilityHealth:
        """Assess capability health considering lifecycle status and provider readiness."""
        cap = self.get_capability(capability_id)
        if not cap:
            return CapabilityHealth.UNAVAILABLE

        if cap.lifecycle_state in (CapabilityLifecycleState.DISABLED, CapabilityLifecycleState.RETIRED, CapabilityLifecycleState.REJECTED):
            return CapabilityHealth.UNAVAILABLE

        providers = self.get_providers(cap.id)
        if not providers:
            return CapabilityHealth.UNAVAILABLE

        ctx = context or ExecutionContext()
        ready_count = 0
        for p in providers:
            ready, _ = p.is_ready(ctx)
            if ready:
                ready_count += 1

        if ready_count == len(providers):
            return CapabilityHealth.HEALTHY
        elif ready_count > 0:
            return CapabilityHealth.DEGRADED
        else:
            return CapabilityHealth.UNAVAILABLE

    def execute_capability(
        self,
        capability_id: str,
        parameters: Dict[str, Any],
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Resolve and execute the capability with lifecycle, trust, and schema validation."""
        cap = self.get_capability(capability_id)
        if not cap:
            return ExecutionResult.failure(
                error=f"Capability '{capability_id}' not found",
                error_code="CAPABILITY_NOT_FOUND",
                execution_id=context.execution_id,
            )

        # 1. Lifecycle verification
        executable, reason = cap.is_executable()
        if not executable:
            cap.record_failure(
                failure_type=CapabilityFailureType.CAPABILITY_UNAVAILABLE,
                error_message=reason or "Capability unexecutable",
                context={"parameters": parameters},
            )
            return ExecutionResult.failure(
                error=reason or f"Capability '{cap.versioned_id}' cannot be executed.",
                error_code="CAPABILITY_UNAVAILABLE",
                execution_id=context.execution_id,
            )

        # 2. Schema / Contract compatibility check
        if cap.input_schema and "required" in cap.input_schema:
            required_keys = set(cap.input_schema.get("required", []))
            provided_keys = set(parameters.keys())
            missing = required_keys - provided_keys
            if missing:
                err_msg = f"Contract mismatch: Missing required parameters {sorted(list(missing))}"
                cap.record_failure(
                    failure_type=CapabilityFailureType.CONTRACT_VIOLATION,
                    error_message=err_msg,
                    context={"parameters": parameters},
                )
                return ExecutionResult.failure(
                    error=err_msg,
                    error_code="CONTRACT_MISMATCH",
                    execution_id=context.execution_id,
                )

        # 3. Provider resolution
        provider, not_ready_reason = self.resolve_provider(cap.id, context)
        if provider is None:
            err_msg = not_ready_reason or f"No ready provider for '{cap.versioned_id}'"
            cap.record_failure(
                failure_type=CapabilityFailureType.PROVIDER_FAILURE,
                error_message=err_msg,
                context={"parameters": parameters},
            )
            return ExecutionResult.failure(
                error=err_msg,
                error_code="PROVIDER_NOT_READY",
                execution_id=context.execution_id,
            )

        # 4. Provider execution
        start_time = time.perf_counter()
        try:
            result = provider.execute(parameters, context)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            if result.duration_ms == 0.0:
                result.duration_ms = duration_ms

            # Check for malformed result
            if result.output is None and not result.evidence and result.is_success:
                cap.record_failure(
                    failure_type=CapabilityFailureType.MALFORMED_RESULT,
                    error_message="Provider returned SUCCESS with neither output nor evidence.",
                    provider_id=provider.id,
                )

            # Record failure history if execution failed
            if result.is_failure:
                cap.record_failure(
                    failure_type=CapabilityFailureType.PROVIDER_FAILURE,
                    error_message=result.error or "Provider execution failed",
                    provider_id=provider.id,
                )

            return result

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            cap.record_failure(
                failure_type=CapabilityFailureType.PROVIDER_FAILURE,
                error_message=str(exc),
                provider_id=provider.id,
                context={"exception": type(exc).__name__},
            )
            return ExecutionResult.failure(
                error=str(exc),
                error_code="PROVIDER_EXECUTION_EXCEPTION",
                duration_ms=duration_ms,
                execution_id=context.execution_id,
                metadata={"provider_id": provider.id, "exception_type": type(exc).__name__},
            )
