"""Permission policies, scopes, and authority boundaries for CyberClaw Core."""

from __future__ import annotations

from enum import Enum
from typing import Set
from pydantic import BaseModel, Field


class ActionScope(str, Enum):
    """Scope categorization for operational actions.

    Differentiates ordinary reversible operations from consequential or destructive ones.
    """

    REVERSIBLE = "reversible"          # Read-only or safe local operations
    CONSEQUENTIAL = "consequential"    # External queries, state modifications, provider calls
    DESTRUCTIVE = "destructive"        # Irreversible deletion, elevated actions, privileged tools


class Permission(BaseModel):
    """A granular permission grantable within CyberClaw."""

    name: str = Field(description="Permission identifier, e.g. 'capability.execute'")
    scope: ActionScope = Field(default=ActionScope.REVERSIBLE)
    description: str = Field(default="")


class Role(BaseModel):
    """Named collection of permissions."""

    name: str
    permissions: Set[str] = Field(default_factory=set)
    description: str = Field(default="")


# Predefined baseline permissions
PERM_INVESTIGATION_CREATE = "investigation:create"
PERM_INVESTIGATION_VIEW = "investigation:view"
PERM_INVESTIGATION_UPDATE = "investigation:update"
PERM_CAPABILITY_EXECUTE = "capability:execute"
PERM_SPECIALIST_INVOKE = "specialist:invoke"
PERM_WORKSPACE_WRITE = "workspace:write"
PERM_SYSTEM_ADMIN = "system:admin"
