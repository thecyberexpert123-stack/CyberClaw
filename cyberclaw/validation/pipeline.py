"""Deterministic validation pipeline for CyberClaw Core requests and results.

Enforces schema validation, permission boundaries, DFA state rules,
and result integrity before state updates or experience recordings.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from cyberclaw.capabilities.capability import Capability
from cyberclaw.dfa.machine import CoreDFA
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.validation.errors import (
    PolicyValidationError,
    ResultValidationError,
    SchemaValidationError,
    StateValidationError,
)


class ValidationPipeline:
    """Orchestrates multi-phase validation independently of agent reasoning."""

    @staticmethod
    def validate_schema(capability: Capability, parameters: Dict[str, Any]) -> None:
        """Validate input parameters against capability schema if defined."""
        if not capability.input_schema:
            return

        required_keys = capability.input_schema.get("required", [])
        for req in required_keys:
            if req not in parameters:
                raise SchemaValidationError(
                    f"Missing required parameter '{req}' for capability '{capability.id}'"
                )

        expected_properties = capability.input_schema.get("properties", {})
        for param_name, param_val in parameters.items():
            if param_name in expected_properties:
                expected_type = expected_properties[param_name].get("type")
                if expected_type == "string" and not isinstance(param_val, str):
                    raise SchemaValidationError(
                        f"Parameter '{param_name}' must be a string, got {type(param_val).__name__}"
                    )
                elif expected_type == "integer" and not isinstance(param_val, int):
                    raise SchemaValidationError(
                        f"Parameter '{param_name}' must be an integer, got {type(param_val).__name__}"
                    )
                elif expected_type == "boolean" and not isinstance(param_val, bool):
                    raise SchemaValidationError(
                        f"Parameter '{param_name}' must be a boolean, got {type(param_val).__name__}"
                    )
                elif expected_type == "array" and not isinstance(param_val, list):
                    raise SchemaValidationError(
                        f"Parameter '{param_name}' must be a list/array, got {type(param_val).__name__}"
                    )
                elif expected_type == "object" and not isinstance(param_val, dict):
                    raise SchemaValidationError(
                        f"Parameter '{param_name}' must be an object/dict, got {type(param_val).__name__}"
                    )

    @staticmethod
    def validate_permissions(
        capability: Capability,
        actor: str,
        permission_manager: PermissionManager,
        scope: ActionScope = ActionScope.REVERSIBLE,
        approval_granted: bool = False,
    ) -> None:
        """Validate that actor has all required permissions for this capability."""
        for perm in capability.required_permissions:
            allowed, reason = permission_manager.check_permission(
                actor=actor,
                action=f"execute:{capability.id}",
                required_permission=perm,
                scope=scope,
                approval_granted=approval_granted,
            )
            if not allowed:
                raise PolicyValidationError(
                    f"Actor '{actor}' rejected for capability '{capability.id}': {reason}"
                )

    @staticmethod
    def validate_dfa_state(
        current_state: CoreState,
        allowed_states: List[CoreState],
        action_name: str,
    ) -> None:
        """Verify that current state permits this action."""
        if current_state not in allowed_states:
            raise StateValidationError(
                f"Action '{action_name}' cannot be executed in state '{current_state.value}'. "
                f"Allowed states: {[s.value for s in allowed_states]}"
            )

    @staticmethod
    def validate_result(result: ExecutionResult) -> None:
        """Verify the structural integrity of the returned ExecutionResult."""
        if not isinstance(result, ExecutionResult):
            raise ResultValidationError(
                f"Expected ExecutionResult instance, got {type(result).__name__}"
            )

        if result.is_failure and not result.error:
            raise ResultValidationError(
                "ExecutionResult with status FAILURE must contain an error explanation."
            )

        if result.is_success and len(result.evidence) == 0:
            raise ResultValidationError(
                "ExecutionResult with status SUCCESS must contain at least one evidence item. "
                "Use SUCCESS_EMPTY if no findings were discovered."
            )

        if result.is_empty and len(result.evidence) > 0:
            raise ResultValidationError(
                "ExecutionResult with status SUCCESS_EMPTY must not contain evidence items."
            )

    @classmethod
    def validate_request(
        cls,
        capability: Capability,
        parameters: Dict[str, Any],
        actor: str,
        permission_manager: PermissionManager,
        current_state: CoreState,
        allowed_states: List[CoreState],
        scope: ActionScope = ActionScope.REVERSIBLE,
        approval_granted: bool = False,
    ) -> None:
        """Execute the full pre-execution validation pipeline."""
        # 1. State Validation
        cls.validate_dfa_state(current_state, allowed_states, capability.id)
        # 2. Schema Validation
        cls.validate_schema(capability, parameters)
        # 3. Permission Validation
        cls.validate_permissions(capability, actor, permission_manager, scope, approval_granted)
