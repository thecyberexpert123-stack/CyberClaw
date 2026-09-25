"""Data models and enums for the Policy Engine & Risk-Aware Authorization subsystem.

Enforces fail-closed, contextual, risk-aware authorization decisions decoupled from
capability existence or raw trust declarations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class RiskLevel(str, Enum):
    """Calculated risk tier for a proposed execution."""

    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"

    @property
    def severity_rank(self) -> int:
        """Numerical ranking for comparison (higher = more severe)."""
        ranks = {
            RiskLevel.LOW: 1,
            RiskLevel.MODERATE: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
            RiskLevel.UNKNOWN: 5,  # Unknown is treated with highest severity (fail-closed)
        }
        return ranks.get(self, 5)


class AuthorizationDecisionType(str, Enum):
    """Categorical authorization outcome."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REQUIRE_SUPERVISION = "REQUIRE_SUPERVISION"
    DEFER = "DEFER"

    @property
    def precedence(self) -> int:
        """Precedence ranking for conflict resolution.

        DENY > REQUIRE_APPROVAL > REQUIRE_SUPERVISION > DEFER > ALLOW.
        Higher value = higher precedence.
        """
        ranks = {
            AuthorizationDecisionType.DENY: 50,
            AuthorizationDecisionType.REQUIRE_APPROVAL: 40,
            AuthorizationDecisionType.REQUIRE_SUPERVISION: 30,
            AuthorizationDecisionType.DEFER: 20,
            AuthorizationDecisionType.ALLOW: 10,
        }
        return ranks.get(self, 50)


class PolicyEffect(str, Enum):
    """Effect resulting from a policy rule evaluation."""

    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REQUIRE_SUPERVISION = "REQUIRE_SUPERVISION"
    DEFER = "DEFER"

    def to_decision_type(self) -> AuthorizationDecisionType:
        return AuthorizationDecisionType(self.value)


class ActorRole(str, Enum):
    """Principal role initiating the action."""

    ANALYST = "analyst"
    LEAD_INVESTIGATOR = "lead_investigator"
    OPERATOR = "operator"
    AUDITOR = "auditor"
    SYSTEM = "system"
    SPECIALIST = "specialist"


class RiskFactor(BaseModel):
    """Explainable component contributing to the overall risk assessment."""

    name: str = Field(description="Identifier or category of the risk factor")
    score: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized factor score [0.0 - 1.0]")
    weight: float = Field(default=1.0, ge=0.0, description="Relative weight in assessment")
    level: RiskLevel = Field(default=RiskLevel.LOW, description="Severity tier of this individual factor")
    description: str = Field(default="", description="Human-readable explanation of why this risk was assessed")


class RiskAssessment(BaseModel):
    """Deterministic, explainable risk assessment for a proposed action context."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    assessment_id: str = Field(default_factory=lambda: str(uuid4()))
    overall_risk: RiskLevel = Field(description="Aggregated risk tier")
    score: float = Field(ge=0.0, le=1.0, description="Aggregated normalized risk score [0.0 - 1.0]")
    factors: List[RiskFactor] = Field(default_factory=list, description="Constituent risk factors")
    assessed_at: datetime = Field(default_factory=utc_now)
    rationale: str = Field(default="", description="Summary rationale for assessed risk")


class PolicyExecutionContext(BaseModel):
    """Contextual execution parameter bundle presented to the Policy Engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    investigation_id: str
    case_stage: str = Field(description="Current DFA state of the investigation")
    actor_id: str = Field(description="Identifier of requesting actor")
    actor_role: str = Field(default=ActorRole.ANALYST.value, description="Role of requesting actor")
    capability_id: str = Field(description="Target capability identifier")
    capability_version: str = Field(default="1.0.0", description="Target capability version")
    provider_id: Optional[str] = Field(default=None, description="Target provider identifier if known")
    action_type: str = Field(default="execute", description="Type of action (e.g. 'execute', 'read')")
    action_scope: str = Field(default="reversible", description="Scope of the action (reversible, consequential, destructive)")
    lifecycle_state: str = Field(default="AVAILABLE", description="Capability lifecycle state")
    trust_state: str = Field(default="TRUSTED_WITH_SCOPE", description="Capability trust state")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Input parameters for the action")
    environment: Dict[str, Any] = Field(default_factory=dict, description="Environmental attributes")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary execution context metadata")
    is_branch: bool = Field(default=False, description="Whether execution is inside a counterfactual branch")
    branch_id: Optional[str] = Field(default=None, description="Branch identifier if applicable")
    approval_token: Optional[str] = Field(default=None, description="Approval token if pre-approved")
    approver_id: Optional[str] = Field(default=None, description="Approver actor ID if approved")
    requires_supervision_acknowledged: bool = Field(default=False, description="Whether supervision has been acknowledged")
    supervisor_id: Optional[str] = Field(default=None, description="Supervisor actor ID if acknowledged")


class ApprovalGrant(BaseModel):
    """Authoritative approval record. A token string is only a lookup key.

    The record is issued by PolicyEngine.request_approval. Callers cannot mint
    one by setting a boolean or choosing a token value.
    """

    token: str
    decision_id: str
    investigation_id: str
    capability_id: str
    capability_version: str
    action_scope: str
    actor_id: str
    approver_id: str
    approver_role: str
    issued_at: datetime = Field(default_factory=utc_now)
    expires_at: Optional[datetime] = None


class PolicyRule(BaseModel):
    """A deterministic declarative rule within a Policy."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    rule_id: str = Field(description="Unique rule identifier")
    name: str = Field(description="Human-readable rule name")
    description: str = Field(default="", description="Explanation of rule's intent")
    effect: PolicyEffect = Field(description="Resulting effect if rule condition matches")
    priority: int = Field(default=100, description="Evaluation priority (lower value = higher priority)")
    conditions: Dict[str, Any] = Field(
        default_factory=dict,
        description="Conditions that must all match for this rule to trigger",
    )


class Policy(BaseModel):
    """An immutable, versioned authorization policy containing ordered rules."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    policy_id: str = Field(description="Unique policy identifier")
    name: str = Field(description="Human-readable policy name")
    version: str = Field(default="1.0.0", description="Semantic version of policy")
    description: str = Field(default="")
    rules: List[PolicyRule] = Field(default_factory=list, description="Ordered rules")
    default_effect: PolicyEffect = Field(
        default=PolicyEffect.DENY,
        description="Fail-closed default effect when no rules match",
    )
    created_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class AuthorizationDecision(BaseModel):
    """Immutable audit record produced by the Policy Engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    decision_id: str = Field(default_factory=lambda: str(uuid4()))
    decision: AuthorizationDecisionType = Field(description="Outcome of authorization")
    policy_id: str = Field(description="Identifier of policy evaluated")
    policy_version: str = Field(default="1.0.0", description="Version of policy evaluated")
    risk_assessment: RiskAssessment = Field(description="Associated risk assessment")
    matched_rules: List[str] = Field(default_factory=list, description="Rule IDs that matched")
    reasons: List[str] = Field(default_factory=list, description="Explanations for the decision")
    obligations: List[str] = Field(default_factory=list, description="Required runtime obligations/constraints")
    timestamp: datetime = Field(default_factory=utc_now)
    context_snapshot: Dict[str, Any] = Field(default_factory=dict, description="Snapshot of execution context")

    @property
    def is_authorized(self) -> bool:
        """True only if decision permits immediate execution."""
        return self.decision == AuthorizationDecisionType.ALLOW


class PolicyValidationRecord(BaseModel):
    """Validation audit record for Policy structure and rules."""

    record_id: str = Field(default_factory=lambda: str(uuid4()))
    policy_id: str
    passed: bool
    violations: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)
