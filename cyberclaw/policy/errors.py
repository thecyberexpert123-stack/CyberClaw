"""Exception hierarchy for the Policy Engine and Authorization subsystem."""

from __future__ import annotations

from typing import Optional
from cyberclaw.validation.errors import PolicyValidationError as CorePolicyValidationError


class PolicyError(Exception):
    """Base exception for policy engine and authorization failures."""

    def __init__(self, message: str, policy_id: Optional[str] = None) -> None:
        self.message = message
        self.policy_id = policy_id
        super().__init__(f"Policy failure [{policy_id or 'unknown'}]: {message}" if policy_id else f"Policy failure: {message}")


class PolicyNotFoundError(PolicyError):
    """Raised when a requested policy or policy version is not found in the registry."""
    pass


class PolicyValidationError(CorePolicyValidationError, PolicyError):
    """Raised when a policy definition is structurally invalid or violates integrity constraints."""

    def __init__(self, message: str, policy_id: Optional[str] = None) -> None:
        self.message = message
        self.policy_id = policy_id
        super().__init__(message)


class AuthorizationDeniedError(PolicyValidationError):
    """Raised when policy evaluation results in a hard DENY."""

    def __init__(self, message: str, decision_id: Optional[str] = None, policy_id: Optional[str] = None) -> None:
        self.decision_id = decision_id
        super().__init__(message, policy_id=policy_id)


class ApprovalRequiredError(PolicyValidationError):
    """Raised when action cannot proceed without explicit approval (REQUIRE_APPROVAL)."""

    def __init__(self, message: str, decision_id: Optional[str] = None, policy_id: Optional[str] = None) -> None:
        self.decision_id = decision_id
        super().__init__(message, policy_id=policy_id)


class SupervisionRequiredError(PolicyValidationError):
    """Raised when action cannot proceed without supervision acknowledgment (REQUIRE_SUPERVISION)."""

    def __init__(self, message: str, decision_id: Optional[str] = None, policy_id: Optional[str] = None) -> None:
        self.decision_id = decision_id
        super().__init__(message, policy_id=policy_id)


class PolicyConflictError(PolicyError):
    """Raised when irreconcilable or illegal policy rule conflicts are encountered."""
    pass


class InvalidPolicyContextError(PolicyError):
    """Raised when the provided execution context is malformed or missing required parameters."""
    pass
