"""Models and enums for capability lifecycle, trust, provenance, and governance."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.permissions.policy import ActionScope


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class CapabilityLifecycleState(str, Enum):
    """Lifecycle state of a capability."""

    PROPOSED = "PROPOSED"
    EXPERIMENTAL = "EXPERIMENTAL"
    VALIDATED = "VALIDATED"
    AVAILABLE = "AVAILABLE"
    TRUSTED = "TRUSTED"
    DEPRECATED = "DEPRECATED"
    DISABLED = "DISABLED"
    RETIRED = "RETIRED"
    REJECTED = "REJECTED"


class CapabilityTrustState(str, Enum):
    """Trust tier of a capability, decoupled from lifecycle availability."""

    UNTRUSTED = "UNTRUSTED"
    PROVISIONAL = "PROVISIONAL"
    TRUSTED_WITH_SCOPE = "TRUSTED_WITH_SCOPE"
    FULLY_TRUSTED = "FULLY_TRUSTED"
    REVOKED = "REVOKED"


class CapabilityHealth(str, Enum):
    """Operational health status of a capability."""

    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"


class CapabilityProvenance(str, Enum):
    """Origin tracking for auditability and governance."""

    CORE_REGISTERED = "CORE_REGISTERED"
    SPECIALIST_REGISTERED = "SPECIALIST_REGISTERED"
    EXPERIMENTAL_SKILL = "EXPERIMENTAL_SKILL"
    PROMOTED_SKILL = "PROMOTED_SKILL"
    ADMIN_REGISTERED = "ADMIN_REGISTERED"
    FUTURE_EXTERNAL_SOURCE = "FUTURE_EXTERNAL_SOURCE"


class CapabilityFailureType(str, Enum):
    """Structured categorization of capability failures."""

    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    PERMISSION_REJECTION = "PERMISSION_REJECTION"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    TIMEOUT = "TIMEOUT"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    EVIDENCE_NORMALIZATION_FAILURE = "EVIDENCE_NORMALIZATION_FAILURE"
    CONTRACT_VIOLATION = "CONTRACT_VIOLATION"
    CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
    POLICY_REJECTION = "POLICY_REJECTION"


class GovernanceDecisionType(str, Enum):
    """Types of formal lifecycle and governance decisions."""

    PROPOSE = "PROPOSE"
    VALIDATE = "VALIDATE"
    APPROVE = "APPROVE"
    ENABLE = "ENABLE"
    DISABLE = "DISABLE"
    DEPRECATE = "DEPRECATE"
    RETIRE = "RETIRE"
    REJECT = "REJECT"
    GRANT_TRUST = "GRANT_TRUST"
    REVOKE_TRUST = "REVOKE_TRUST"


class CapabilityValidationRecord(BaseModel):
    """Durable record of a formal validation assessment for a capability version."""

    validation_id: str = Field(default_factory=lambda: str(uuid4()))
    capability_id: str
    capability_version: str
    validator: str = Field(description="Actor, automated gate, or analyst performing validation")
    validated_at: datetime = Field(default_factory=utc_now)
    validation_scope: str = Field(default="standard", description="e.g. 'sandbox_tests', 'schema_verification'")
    tests_performed: List[str] = Field(default_factory=list)
    evidence_produced: List[str] = Field(default_factory=list)
    failures: List[str] = Field(default_factory=list)
    restrictions: List[str] = Field(default_factory=list)
    result: str = Field(default="PASSED", description="'PASSED', 'FAILED', or 'CONDITIONAL'")
    experiment_references: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CapabilityFailureRecord(BaseModel):
    """Historical record of an operational failure or policy rejection."""

    failure_id: str = Field(default_factory=lambda: str(uuid4()))
    capability_id: str
    capability_version: str
    failure_type: CapabilityFailureType
    timestamp: datetime = Field(default_factory=utc_now)
    provider_id: Optional[str] = None
    error_message: str
    context: Dict[str, Any] = Field(default_factory=dict)


class CapabilityGovernanceRecord(BaseModel):
    """Immutable audit record of a lifecycle or trust modification."""

    record_id: str = Field(default_factory=lambda: str(uuid4()))
    capability_id: str
    capability_version: str
    decision_type: GovernanceDecisionType
    actor: str = Field(description="Actor or authority executing the governance action")
    timestamp: datetime = Field(default_factory=utc_now)
    rationale: str
    previous_lifecycle_state: str
    new_lifecycle_state: str
    previous_trust_state: str
    new_trust_state: str
    scope: ActionScope = ActionScope.CONSEQUENTIAL
    evidence_references: List[str] = Field(default_factory=list)
    validation_references: List[str] = Field(default_factory=list)
    approval_reference: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CapabilityCandidate(BaseModel):
    """Structured proposal for a new capability prior to formal registration."""

    candidate_id: str = Field(default_factory=lambda: str(uuid4()))
    capability_id: str
    name: str
    version: str = "0.1.0"
    description: str
    category: str = "general"
    specialist_id: Optional[str] = None
    originating_gap_id: Optional[str] = None
    originating_skill_id: Optional[str] = None
    provenance: CapabilityProvenance = CapabilityProvenance.CORE_REGISTERED
    input_schema: Optional[Dict[str, Any]] = None
    output_schema: Optional[Dict[str, Any]] = None
    required_permissions: List[str] = Field(default_factory=list)
    action_scope: ActionScope = ActionScope.REVERSIBLE
    rationale: str
    proposed_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CapabilityDiscoveryResult(BaseModel):
    """Structured result of discovering capabilities for an unmet intelligence requirement."""

    gap_id: str
    matching_available_capabilities: List[str] = Field(default_factory=list)
    matching_unavailable_capabilities: List[str] = Field(default_factory=list)
    matching_deprecated_capabilities: List[str] = Field(default_factory=list)
    candidate_capabilities: List[CapabilityCandidate] = Field(default_factory=list)
    missing_categories: List[str] = Field(default_factory=list)
    recommendation: str = "NONE"
