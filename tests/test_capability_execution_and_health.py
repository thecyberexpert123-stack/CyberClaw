"""Tests for provider multi-tenancy, health evaluation, failure history, and schema contract validation."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import (
    CapabilityFailureType,
    CapabilityHealth,
    CapabilityLifecycleState,
    CapabilityTrustState,
)
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.types import Source


class MockReadyProvider(CapabilityProvider):
    def __init__(self, id: str, capability_id: str, priority: int = 100):
        super().__init__(id=id, name=f"Mock {id}", capability_id=capability_id, priority=priority)

    def is_ready(self, context: ExecutionContext):
        return True, None

    def execute(self, parameters, context):
        ev = Evidence(
            type="mock_finding",
            subject=parameters.get("target", "unknown"),
            value={"data": "test_output"},
            source=Source(type="mock", name=self.id),
        )
        return ExecutionResult.success(output={"status": "ok"}, evidence=[ev])


class MockUnreadyProvider(CapabilityProvider):
    def __init__(self, id: str, capability_id: str, priority: int = 200, unready_reason: str = "Down for maintenance"):
        super().__init__(id=id, name=f"Mock {id}", capability_id=capability_id, priority=priority)
        self.unready_reason = unready_reason

    def is_ready(self, context: ExecutionContext):
        return False, self.unready_reason

    def execute(self, parameters, context):
        return ExecutionResult.failure(error=self.unready_reason)


class MockFailingProvider(CapabilityProvider):
    def __init__(self, id: str, capability_id: str):
        super().__init__(id=id, name="Failing", capability_id=capability_id)

    def is_ready(self, context: ExecutionContext):
        return True, None

    def execute(self, parameters, context):
        raise RuntimeError("Low-level connection timeout")


class MockMalformedProvider(CapabilityProvider):
    def __init__(self, id: str, capability_id: str):
        super().__init__(id=id, name="Malformed", capability_id=capability_id)

    def is_ready(self, context: ExecutionContext):
        return True, None

    def execute(self, parameters, context):
        # Returns SUCCESS with neither output nor evidence
        return ExecutionResult(status=ExecutionStatus.SUCCESS, output=None, evidence=[])


def test_multiple_providers_and_priority_fallback():
    """Verify registry resolves highest priority provider that is ready, falling back gracefully."""
    reg = CapabilityRegistry()
    cap = Capability(
        id="capability.network.dns",
        name="DNS Resolver",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    reg.register_capability(cap)

    p_primary = MockUnreadyProvider("provider.primary", "capability.network.dns", priority=200, unready_reason="API key expired")
    p_secondary = MockReadyProvider("provider.secondary", "capability.network.dns", priority=100)

    reg.register_provider(p_primary)
    reg.register_provider(p_secondary)

    ctx = ExecutionContext()
    # Should resolve secondary because primary is unready
    resolved, reason = reg.resolve_provider(cap.id, ctx)
    assert resolved is not None
    assert resolved.id == "provider.secondary"

    # Execution should succeed via secondary
    res = reg.execute_capability(cap.id, {"target": "example.com"}, ctx)
    assert res.is_success is True


def test_distinguish_capability_unavailable_vs_provider_not_ready():
    """Verify distinct error codes for disabled capability vs ready provider unavailability."""
    reg = CapabilityRegistry()
    cap_disabled = Capability(
        id="capability.disabled.test",
        name="Disabled Cap",
        lifecycle_state=CapabilityLifecycleState.DISABLED,
    )
    reg.register_capability(cap_disabled)

    ctx = ExecutionContext()
    res_disabled = reg.execute_capability(cap_disabled.id, {}, ctx)
    assert res_disabled.is_failure is True
    assert res_disabled.error_code == "CAPABILITY_UNAVAILABLE"

    cap_active = Capability(
        id="capability.active.test",
        name="Active Cap",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    reg.register_capability(cap_active)
    # Register only unready provider
    reg.register_provider(MockUnreadyProvider("unready.p1", cap_active.id, priority=100))

    res_unready = reg.execute_capability(cap_active.id, {}, ctx)
    assert res_unready.is_failure is True
    assert res_unready.error_code == "PROVIDER_NOT_READY"


def test_capability_health_states():
    """Verify HEALTHY, DEGRADED, and UNAVAILABLE health calculations."""
    reg = CapabilityRegistry()
    cap = Capability(
        id="capability.health.test",
        name="Health Cap",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    reg.register_capability(cap)

    # 1. No providers registered -> UNAVAILABLE
    assert reg.get_capability_health(cap.id) == CapabilityHealth.UNAVAILABLE

    # 2. One unready provider -> UNAVAILABLE
    p_unready = MockUnreadyProvider("p.unready", cap.id)
    reg.register_provider(p_unready)
    assert reg.get_capability_health(cap.id) == CapabilityHealth.UNAVAILABLE

    # 3. One ready + one unready -> DEGRADED
    p_ready = MockReadyProvider("p.ready", cap.id)
    reg.register_provider(p_ready)
    assert reg.get_capability_health(cap.id) == CapabilityHealth.DEGRADED

    # 4. Capability disabled -> UNAVAILABLE regardless of ready providers
    cap.lifecycle_state = CapabilityLifecycleState.DISABLED
    assert reg.get_capability_health(cap.id) == CapabilityHealth.UNAVAILABLE


def test_schema_contract_validation_and_failure_recording():
    """Verify input schema contract mismatch returns CONTRACT_MISMATCH and appends failure record."""
    reg = CapabilityRegistry()
    cap = Capability(
        id="capability.schema.test",
        name="Schema Test",
        input_schema={"required": ["target_ip", "port"]},
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    reg.register_capability(cap)
    reg.register_provider(MockReadyProvider("mock.p", cap.id))

    ctx = ExecutionContext()
    # Missing 'port'
    res = reg.execute_capability(cap.id, {"target_ip": "10.0.0.1"}, ctx)
    assert res.is_failure is True
    assert res.error_code == "CONTRACT_MISMATCH"

    # Verify failure record was captured
    assert len(cap.failure_history) == 1
    assert cap.failure_history[0].failure_type == CapabilityFailureType.CONTRACT_VIOLATION


def test_provider_exception_and_malformed_result_handling():
    """Verify unhandled provider exceptions and malformed results are captured in failure history."""
    reg = CapabilityRegistry()
    cap_fail = Capability(
        id="capability.fail.test",
        name="Fail Test",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    reg.register_capability(cap_fail)
    reg.register_provider(MockFailingProvider("failing.p", cap_fail.id))

    ctx = ExecutionContext()
    res_fail = reg.execute_capability(cap_fail.id, {}, ctx)
    assert res_fail.is_failure is True
    assert res_fail.error_code == "PROVIDER_EXECUTION_EXCEPTION"
    assert len(cap_fail.failure_history) == 1
    assert cap_fail.failure_history[0].failure_type == CapabilityFailureType.PROVIDER_FAILURE

    # Test malformed provider result
    cap_malformed = Capability(
        id="capability.malformed.test",
        name="Malformed Test",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    reg.register_capability(cap_malformed)
    reg.register_provider(MockMalformedProvider("malformed.p", cap_malformed.id))

    res_malformed = reg.execute_capability(cap_malformed.id, {}, ctx)
    assert len(cap_malformed.failure_history) == 1
    assert cap_malformed.failure_history[0].failure_type == CapabilityFailureType.MALFORMED_RESULT
