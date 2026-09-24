"""Permission enforcement and audit logging for CyberClaw Core."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
from cyberclaw.permissions.policy import (
    ActionScope,
    PERM_CAPABILITY_EXECUTE,
    PERM_INVESTIGATION_CREATE,
    PERM_INVESTIGATION_UPDATE,
    PERM_INVESTIGATION_VIEW,
    PERM_SPECIALIST_INVOKE,
    PERM_SYSTEM_ADMIN,
    PERM_WORKSPACE_WRITE,
    Role,
)


class PermissionDeniedError(Exception):
    """Raised when an actor lacks authority for an action."""

    def __init__(self, actor: str, action: str, permission: str, reason: str) -> None:
        self.actor = actor
        self.action = action
        self.permission = permission
        self.reason = reason
        super().__init__(
            f"Permission denied for actor '{actor}' attempting '{action}': "
            f"missing '{permission}' ({reason})"
        )


class ApprovalRequiredError(Exception):
    """Raised when a consequential or destructive action requires human or explicit approval."""

    def __init__(self, actor: str, action: str, scope: ActionScope) -> None:
        self.actor = actor
        self.action = action
        self.scope = scope
        super().__init__(
            f"Action '{action}' with scope '{scope.value}' requires explicit approval before execution."
        )


class PermissionAuditRecord:
    """Record of a permission validation check."""

    def __init__(
        self,
        actor: str,
        action: str,
        permission: str,
        scope: ActionScope,
        granted: bool,
        reason: Optional[str] = None,
    ) -> None:
        self.actor = actor
        self.action = action
        self.permission = permission
        self.scope = scope
        self.granted = granted
        self.reason = reason


class PermissionManager:
    """Manages authorization rules, actor grants, and explicit approval gates."""

    def __init__(self) -> None:
        self._actor_permissions: Dict[str, Set[str]] = {}
        self._actor_roles: Dict[str, Set[str]] = {}
        self._roles: Dict[str, Role] = {}
        self._audit_log: List[PermissionAuditRecord] = []

        # Setup standard system roles
        self.register_role(
            Role(
                name="admin",
                permissions={
                    PERM_SYSTEM_ADMIN,
                    PERM_INVESTIGATION_CREATE,
                    PERM_INVESTIGATION_VIEW,
                    PERM_INVESTIGATION_UPDATE,
                    PERM_CAPABILITY_EXECUTE,
                    PERM_SPECIALIST_INVOKE,
                    PERM_WORKSPACE_WRITE,
                },
                description="Unrestricted administrative access",
            )
        )
        self.register_role(
            Role(
                name="specialist",
                permissions={
                    PERM_INVESTIGATION_VIEW,
                    PERM_CAPABILITY_EXECUTE,
                    PERM_WORKSPACE_WRITE,
                },
                description="Specialist operational role",
            )
        )
        self.register_role(
            Role(
                name="analyst",
                permissions={
                    PERM_INVESTIGATION_CREATE,
                    PERM_INVESTIGATION_VIEW,
                    PERM_INVESTIGATION_UPDATE,
                    PERM_CAPABILITY_EXECUTE,
                    PERM_SPECIALIST_INVOKE,
                },
                description="Investigative analyst role",
            )
        )

        # Grant core system administrator role by default
        self.assign_role("core.system", "admin")

    def register_role(self, role: Role) -> None:
        """Register a new role."""
        self._roles[role.name] = role

    def assign_role(self, actor: str, role_name: str) -> None:
        """Assign a defined role to an actor."""
        self._actor_roles.setdefault(actor, set()).add(role_name)

    def grant_permission(self, actor: str, permission: str) -> None:
        """Grant a specific granular permission to an actor."""
        self._actor_permissions.setdefault(actor, set()).add(permission)

    def get_effective_permissions(self, actor: str) -> Set[str]:
        """Compute the union of directly granted and role-based permissions for an actor."""
        perms = set(self._actor_permissions.get(actor, set()))
        for role_name in self._actor_roles.get(actor, set()):
            role = self._roles.get(role_name)
            if role:
                perms.update(role.permissions)
        return perms

    def check_permission(
        self,
        actor: str,
        action: str,
        required_permission: Optional[str] = None,
        scope: ActionScope = ActionScope.REVERSIBLE,
        approval_granted: bool = False,
    ) -> Tuple[bool, Optional[str]]:
        """Validate whether an actor is authorized to perform an action under a given scope."""
        # Destructive actions require explicit approval unless system admin
        effective_perms = self.get_effective_permissions(actor)
        is_admin = PERM_SYSTEM_ADMIN in effective_perms

        if scope == ActionScope.DESTRUCTIVE and not approval_granted and not is_admin:
            self._log_audit(actor, action, required_permission or "", scope, False, "Explicit approval required")
            return False, "DESTRUCTIVE scope requires explicit approval"

        # Check permission grant if required
        if required_permission:
            if not is_admin and required_permission not in effective_perms:
                self._log_audit(
                    actor, action, required_permission, scope, False, f"Missing {required_permission}"
                )
                return False, f"Actor '{actor}' lacks permission '{required_permission}'"

        self._log_audit(actor, action, required_permission or "", scope, True, "Authorized")
        return True, None

    def enforce_permission(
        self,
        actor: str,
        action: str,
        required_permission: Optional[str] = None,
        scope: ActionScope = ActionScope.REVERSIBLE,
        approval_granted: bool = False,
    ) -> None:
        """Enforce permission, raising PermissionDeniedError or ApprovalRequiredError on failure."""
        allowed, reason = self.check_permission(actor, action, required_permission, scope, approval_granted)
        if not allowed:
            if "approval" in (reason or "").lower():
                raise ApprovalRequiredError(actor, action, scope)
            raise PermissionDeniedError(
                actor=actor,
                action=action,
                permission=required_permission or "unspecified",
                reason=reason or "Unauthorized",
            )

    def _log_audit(
        self,
        actor: str,
        action: str,
        permission: str,
        scope: ActionScope,
        granted: bool,
        reason: Optional[str] = None,
    ) -> None:
        self._audit_log.append(
            PermissionAuditRecord(actor, action, permission, scope, granted, reason)
        )

    def get_audit_log(self) -> List[PermissionAuditRecord]:
        return list(self._audit_log)
