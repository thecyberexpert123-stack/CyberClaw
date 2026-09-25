"""Governed dispatch marker.

The executor copies an authorization it has already issued onto the execution
context. This module does not authorize, execute, persist, or replay.
"""

from __future__ import annotations

from typing import Any, Optional


GOVERNED_DISPATCH_KEY = "governed_dispatch"
_REQUIRED = (
    "authorization_decision_id",
    "policy_id",
    "policy_version",
    "capability_id",
    "capability_version",
    "actor",
)


def governed_dispatch(context: Any) -> Optional[dict]:
    """Return the executor marker, or None when the call did not come from one."""
    environment = getattr(context, "environment", None) or {}
    stamp = environment.get(GOVERNED_DISPATCH_KEY)
    if not isinstance(stamp, dict):
        return None
    if any(not stamp.get(field) for field in _REQUIRED):
        return None
    return stamp


def stamp_governed_dispatch(
    context: Any,
    *,
    authorization_decision_id: str,
    policy_id: str,
    policy_version: str,
    capability_id: str,
    capability_version: str,
    actor: str,
    requirement_id: Optional[str] = None,
    task_id: Optional[str] = None,
) -> Any:
    """Attach an already-issued authorization to an execution context.

    Missing fields are a caller error. This function does not create an
    authorization and does not consult the policy engine.
    """
    fields = {
        "authorization_decision_id": authorization_decision_id,
        "policy_id": policy_id,
        "policy_version": policy_version,
        "capability_id": capability_id,
        "capability_version": capability_version,
        "actor": actor,
    }
    if any(not value for value in fields.values()):
        raise ValueError(
            "Governed dispatch requires an issued authorization, policy reference, "
            "capability version, and actor. It does not create them."
        )
    environment = dict(getattr(context, "environment", None) or {})
    environment[GOVERNED_DISPATCH_KEY] = {
        **fields,
        "requirement_id": requirement_id,
        "task_id": task_id,
    }
    if hasattr(context, "model_copy"):
        return context.model_copy(update={"environment": environment})
    context.environment = environment
    return context
