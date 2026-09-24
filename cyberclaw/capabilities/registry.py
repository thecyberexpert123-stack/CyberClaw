"""Registry for capabilities and their backing providers."""

from __future__ import annotations

import time
from typing import Dict, List, Optional, Tuple
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.evidence.result import ExecutionResult


class CapabilityNotFoundError(Exception):
    """Raised when a requested capability is not registered."""
    pass


class CapabilityRegistry:
    """Manages capability declarations and provider resolution."""

    def __init__(self) -> None:
        self._capabilities: Dict[str, Capability] = {}
        # Maps capability_id to list of registered providers
        self._providers: Dict[str, List[CapabilityProvider]] = {}

    def register_capability(self, capability: Capability) -> None:
        """Register a new capability in the system."""
        self._capabilities[capability.id] = capability
        if capability.id not in self._providers:
            self._providers[capability.id] = []

    def get_capability(self, capability_id: str) -> Optional[Capability]:
        """Retrieve capability definition by ID."""
        return self._capabilities.get(capability_id)

    def list_capabilities(self, category: Optional[str] = None) -> List[Capability]:
        """List all registered capabilities, optionally filtered by category."""
        caps = list(self._capabilities.values())
        if category is not None:
            caps = [c for c in caps if c.category == category]
        return caps

    def register_provider(self, provider: CapabilityProvider) -> None:
        """Register a provider backing a specific capability.

        Multiple providers can back the same capability with different priorities.
        """
        if provider.capability_id not in self._capabilities:
            # Auto-register a minimal capability stub if not explicitly declared
            self.register_capability(
                Capability(
                    id=provider.capability_id,
                    name=provider.name,
                    description=f"Auto-registered capability for provider {provider.id}",
                )
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
        return list(self._providers.get(capability_id, []))

    def resolve_provider(
        self, capability_id: str, context: ExecutionContext
    ) -> Tuple[Optional[CapabilityProvider], Optional[str]]:
        """Resolve the highest-priority provider that reports is_ready()."""
        providers = self._providers.get(capability_id, [])
        if not providers:
            return None, f"No provider registered for capability '{capability_id}'"

        unready_reasons: List[str] = []
        for provider in providers:
            ready, reason = provider.is_ready(context)
            if ready:
                return provider, None
            unready_reasons.append(f"Provider '{provider.id}' not ready: {reason}")

        return None, "; ".join(unready_reasons)

    def execute_capability(
        self,
        capability_id: str,
        parameters: Dict[str, Any],
        context: ExecutionContext,
    ) -> ExecutionResult:
        """Resolve and execute the capability with full error handling and timing."""
        if capability_id not in self._capabilities:
            return ExecutionResult.failure(
                error=f"Capability '{capability_id}' not found",
                error_code="CAPABILITY_NOT_FOUND",
                execution_id=context.execution_id,
            )

        provider, not_ready_reason = self.resolve_provider(capability_id, context)
        if provider is None:
            return ExecutionResult.failure(
                error=not_ready_reason or f"No ready provider for '{capability_id}'",
                error_code="PROVIDER_NOT_READY",
                execution_id=context.execution_id,
            )

        start_time = time.perf_counter()
        try:
            result = provider.execute(parameters, context)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            if result.duration_ms == 0.0:
                result.duration_ms = duration_ms
            return result
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            return ExecutionResult.failure(
                error=str(exc),
                error_code="PROVIDER_EXECUTION_EXCEPTION",
                duration_ms=duration_ms,
                execution_id=context.execution_id,
                metadata={"provider_id": provider.id, "exception_type": type(exc).__name__},
            )
