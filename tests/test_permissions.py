"""Tests for Permission boundaries, Action scopes, and Approval requirements."""

import pytest
from cyberclaw.permissions.manager import (
    ApprovalRequiredError,
    PermissionDeniedError,
    PermissionManager,
)
from cyberclaw.permissions.policy import (
    ActionScope,
    PERM_CAPABILITY_EXECUTE,
    PERM_INVESTIGATION_CREATE,
    Role,
)


def test_permission_granted_and_denied():
    pm = PermissionManager()

    # Analyst role has PERM_INVESTIGATION_CREATE but not system admin
    pm.assign_role("analyst_bob", "analyst")

    # Bob can create investigation
    allowed, reason = pm.check_permission(
        actor="analyst_bob",
        action="investigation.create",
        required_permission=PERM_INVESTIGATION_CREATE,
        scope=ActionScope.CONSEQUENTIAL,
    )
    assert allowed is True

    # Bob cannot execute ungranted arbitrary permission
    allowed, reason = pm.check_permission(
        actor="analyst_bob",
        action="restricted.action",
        required_permission="privileged:kernel",
        scope=ActionScope.CONSEQUENTIAL,
    )
    assert allowed is False
    assert "lacks permission 'privileged:kernel'" in reason

    with pytest.raises(PermissionDeniedError) as exc_info:
        pm.enforce_permission(
            actor="analyst_bob",
            action="restricted.action",
            required_permission="privileged:kernel",
        )
    assert exc_info.value.permission == "privileged:kernel"


def test_destructive_scope_requires_explicit_approval():
    """Verify Section 18: Destructive/irreversible operations require explicit approval."""
    pm = PermissionManager()
    pm.grant_permission("operator_alice", PERM_CAPABILITY_EXECUTE)

    # Reversible execution works
    pm.enforce_permission(
        actor="operator_alice",
        action="safe_scan",
        required_permission=PERM_CAPABILITY_EXECUTE,
        scope=ActionScope.REVERSIBLE,
    )

    # Destructive action without approval raises ApprovalRequiredError
    with pytest.raises(ApprovalRequiredError) as exc_info:
        pm.enforce_permission(
            actor="operator_alice",
            action="destroy_artifacts",
            required_permission=PERM_CAPABILITY_EXECUTE,
            scope=ActionScope.DESTRUCTIVE,
            approval_granted=False,
        )
    assert exc_info.value.scope == ActionScope.DESTRUCTIVE

    # When approval is granted, it passes
    pm.enforce_permission(
        actor="operator_alice",
        action="destroy_artifacts",
        required_permission=PERM_CAPABILITY_EXECUTE,
        scope=ActionScope.DESTRUCTIVE,
        approval_granted=True,
    )


def test_permission_audit_trail():
    pm = PermissionManager()
    pm.check_permission("actor_1", "action_1", "perm_1", ActionScope.REVERSIBLE)
    pm.check_permission("core.system", "action_2", "perm_2", ActionScope.CONSEQUENTIAL)

    audit = pm.get_audit_log()
    assert len(audit) == 2
    assert audit[0].actor == "actor_1"
    assert audit[0].granted is False
    assert audit[1].actor == "core.system"
    assert audit[1].granted is True
