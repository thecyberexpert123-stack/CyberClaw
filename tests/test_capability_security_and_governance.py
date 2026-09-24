"""Security boundaries: untrusted rejection, permission enforcement, action scopes, and immutability."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import (
    CapabilityLifecycleState,
    CapabilityTrustState,
)
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.permissions.policy import ActionScope, Permission
from cyberclaw.validation.errors import PolicyValidationError
from cyberclaw.validation.pipeline import ValidationPipeline


class DummyProvider(CapabilityProvider):
    def __init__(self, capability_id: str):
        super().__init__(id="dummy.p", name="Dummy", capability_id=capability_id)

    def is_ready(self, context: ExecutionContext):
        return True, None

    def execute(self, parameters, context):
        return ExecutionResult.success(output={"status": "ok"}, evidence=[])


def test_untrusted_and_retired_capabilities_cannot_execute():
    """Verify that capabilities in UNTRUSTED state or RETIRED lifecycle cannot be executed."""
    reg = CapabilityRegistry()

    # 1. Untrusted capability
    cap_untrusted = Capability(
        id="capability.untrusted.sample",
        name="Untrusted Sample",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.UNTRUSTED,
    )
    reg.register_capability(cap_untrusted)
    reg.register_provider(DummyProvider(cap_untrusted.id))

    res_untrusted = reg.execute_capability(cap_untrusted.id, {}, ExecutionContext())
    assert res_untrusted.is_failure is True
    assert res_untrusted.error_code == "CAPABILITY_UNAVAILABLE"

    # 2. Retired capability
    cap_retired = Capability(
        id="capability.retired.sample",
        name="Retired Sample",
        lifecycle_state=CapabilityLifecycleState.RETIRED,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    reg.register_capability(cap_retired)
    reg.register_provider(DummyProvider(cap_retired.id))

    res_retired = reg.execute_capability(cap_retired.id, {}, ExecutionContext())
    assert res_retired.is_failure is True
    assert res_retired.error_code == "CAPABILITY_UNAVAILABLE"


def test_trusted_capabilities_still_enforce_permissions_and_scope(tmp_path):
    """Verify that even a FULLY_TRUSTED capability is rejected if the actor lacks required permissions."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register capability requiring high permission
    cap = Capability(
        id="capability.admin.wipe_cache",
        name="Wipe Cache",
        required_permissions=["admin:cache_wipe"],
        action_scope=ActionScope.DESTRUCTIVE,
        lifecycle_state=CapabilityLifecycleState.TRUSTED,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)
    core.register_provider(DummyProvider(cap.id))

    inv = core.create_investigation("Security Scope Test", "Permission test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start_recon")

    # Give analyst standard view/update permissions, but NOT admin:cache_wipe
    core.permissions.grant_permission("unprivileged.analyst", "investigation:view")
    core.permissions.grant_permission("unprivileged.analyst", "investigation:update")

    # Unprivileged actor attempts execution
    with pytest.raises(PolicyValidationError) as exc_info:
        core.execute_action(
            investigation_id=inv.id,
            capability_id=cap.id,
            parameters={},
            actor="unprivileged.analyst",
            scope=ActionScope.DESTRUCTIVE,
            approval_granted=True,
        )
    assert "rejected for capability" in str(exc_info.value).lower()
    assert "admin:cache_wipe" in str(exc_info.value)


def test_destructive_action_requires_explicit_approval(tmp_path):
    """Verify that DESTRUCTIVE scoped actions fail unless explicit approval_granted=True is provided."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="capability.destructive.delete_resource",
        name="Delete Resource",
        required_permissions=["resource:delete"],
        action_scope=ActionScope.DESTRUCTIVE,
        lifecycle_state=CapabilityLifecycleState.TRUSTED,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)
    core.register_provider(DummyProvider(cap.id))

    # Grant permission to actor
    core.permissions.grant_permission("operator.alice", "investigation:view")
    core.permissions.grant_permission("operator.alice", "investigation:update")
    core.permissions.grant_permission("operator.alice", "resource:delete")

    inv = core.create_investigation("Destructive Approval Test", "Testing approval gate")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start_recon")

    # Attempting destructive action without explicit approval_granted=True must be rejected
    with pytest.raises(PolicyValidationError) as exc_info:
        core.execute_action(
            investigation_id=inv.id,
            capability_id=cap.id,
            parameters={},
            actor="operator.alice",
            scope=ActionScope.DESTRUCTIVE,
            approval_granted=False,  # Lacks approval!
        )
    assert "destructive scope requires explicit approval" in str(exc_info.value).lower()


def test_branches_cannot_silently_register_capabilities(tmp_path):
    """Verify that branches cannot alter authoritative Core capability registry."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Branch Reg Test", "Branch isolation test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start_recon")
    snap = inv.capture_snapshot(trigger="base_snap")

    branch = core.create_investigation_branch(
        investigation_id=inv.id,
        source_snapshot=snap.sequence,
        purpose="Explore fictitious capability",
    )

    initial_caps_count = len(core.capabilities.list_capabilities(include_retired=True, include_disabled=True))

    # Branch records a capability reference in its metadata
    branch.metadata["hypothetical_capability"] = "capability.satellite.telemetry"

    # Core registry must remain completely unchanged
    assert len(core.capabilities.list_capabilities(include_retired=True, include_disabled=True)) == initial_caps_count
    assert core.capabilities.get_capability("capability.satellite.telemetry") is None
