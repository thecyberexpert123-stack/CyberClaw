"""CyberClaw Policy Engine & Risk-Aware Authorization subsystem.

Enforces deterministic, contextual, risk-aware authorization independently of capability
trust or existence.

Governance Axioms:
- CAPABILITY EXISTENCE != CAPABILITY AUTHORITY
- CAPABILITY TRUST != EXECUTION AUTHORIZATION
- TRUST != UNLIMITED PERMISSION
- PERMISSION != POLICY AUTHORIZATION
- POLICY AUTHORIZATION != EXECUTION GUARANTEE
- EXECUTION != SUCCESS
"""

from __future__ import annotations

from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.policy.errors import (
    ApprovalRequiredError,
    AuthorizationDeniedError,
    InvalidPolicyContextError,
    PolicyConflictError,
    PolicyError,
    PolicyNotFoundError,
    PolicyValidationError,
    SupervisionRequiredError,
)
from cyberclaw.policy.evaluator import PolicyEvaluator
from cyberclaw.policy.models import (
    ActorRole,
    AuthorizationDecision,
    AuthorizationDecisionType,
    Policy,
    PolicyEffect,
    PolicyExecutionContext,
    PolicyRule,
    PolicyValidationRecord,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
)
from cyberclaw.policy.registry import (
    DEFAULT_POLICY_ID,
    DEFAULT_POLICY_VERSION,
    PolicyRegistry,
)
from cyberclaw.policy.risk import RiskEvaluator
from cyberclaw.policy.rules import create_standard_rules, match_rule_conditions

__all__ = [
    "PolicyEngine",
    "PolicyEvaluator",
    "RiskEvaluator",
    "PolicyRegistry",
    "Policy",
    "PolicyRule",
    "PolicyEffect",
    "PolicyExecutionContext",
    "AuthorizationDecision",
    "AuthorizationDecisionType",
    "RiskAssessment",
    "RiskFactor",
    "RiskLevel",
    "ActorRole",
    "PolicyValidationRecord",
    "PolicyError",
    "PolicyNotFoundError",
    "PolicyValidationError",
    "AuthorizationDeniedError",
    "ApprovalRequiredError",
    "SupervisionRequiredError",
    "PolicyConflictError",
    "InvalidPolicyContextError",
    "DEFAULT_POLICY_ID",
    "DEFAULT_POLICY_VERSION",
    "create_standard_rules",
    "match_rule_conditions",
]
