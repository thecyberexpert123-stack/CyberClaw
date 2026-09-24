"""Tests for Capabilities, Providers, and CapabilityRegistry."""

from typing import Any, Dict, Tuple
import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.types import Source


class MockReadyProvider(CapabilityProvider):
    """Controlled mock provider that returns structured evidence."""

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, str | None]:
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        source = Source(type="provider", name=self.name)
        ev = Evidence(
            type="mock_finding",
            subject=parameters.get("target", "unknown"),
            value={"data": "found"},
            source=source,
        )
        return ExecutionResult.success(evidence=[ev], output={"executed": True})


class MockUnreadyProvider(CapabilityProvider):
    """Mock provider simulating an unready state (e.g. missing dependency)."""

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, str | None]:
        return False, "Missing required external dependency 'libdummy'"

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        return ExecutionResult.failure("Should not execute", error_code="UNREADY")


def test_capability_registration():
    registry = CapabilityRegistry()
    cap = Capability(
        id="discovery.entity",
        name="Entity Discovery",
        description="Discovers entities given a seed",
        category="discovery",
        input_schema={"required": ["seed"]},
    )
    registry.register_capability(cap)

    fetched = registry.get_capability("discovery.entity")
    assert fetched is not None
    assert fetched.name == "Entity Discovery"
    assert fetched.category == "discovery"
    assert len(registry.list_capabilities(category="discovery")) == 1


def test_provider_registration_and_execution():
    registry = CapabilityRegistry()
    cap = Capability(id="test.cap", name="Test Cap")
    registry.register_capability(cap)

    provider = MockReadyProvider(id="p1", name="Ready Provider", capability_id="test.cap")
    registry.register_provider(provider)

    ctx = ExecutionContext(actor="test.user")
    res = registry.execute_capability("test.cap", {"target": "victim.org"}, ctx)

    assert res.is_success is True
    assert len(res.evidence) == 1
    assert res.evidence[0].subject == "victim.org"
    assert res.output == {"executed": True}


def test_provider_readiness_failure():
    registry = CapabilityRegistry()
    provider = MockUnreadyProvider(id="p_unready", name="Unready Provider", capability_id="test.unready")
    registry.register_provider(provider)

    ctx = ExecutionContext(actor="test.user")
    res = registry.execute_capability("test.unready", {}, ctx)

    assert res.is_failure is True
    assert res.error_code == "PROVIDER_NOT_READY"
    assert "Missing required external dependency 'libdummy'" in res.error


def test_provider_priority_fallback():
    registry = CapabilityRegistry()
    # High priority provider is unready
    unready_p = MockUnreadyProvider(id="p_high", name="High Unready", capability_id="test.fallback", priority=200)
    # Lower priority provider is ready
    ready_p = MockReadyProvider(id="p_low", name="Low Ready", capability_id="test.fallback", priority=100)

    registry.register_provider(unready_p)
    registry.register_provider(ready_p)

    ctx = ExecutionContext(actor="test.user")
    res = registry.execute_capability("test.fallback", {"target": "fallback.org"}, ctx)

    assert res.is_success is True
    assert res.evidence[0].subject == "fallback.org"
