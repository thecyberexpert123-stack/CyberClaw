"""Capability definitions representing domain-agnostic or specialist actions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pydantic import BaseModel, Field

from cyberclaw.capabilities.models import (
    CapabilityFailureRecord,
    CapabilityFailureType,
    CapabilityGovernanceRecord,
    CapabilityLifecycleState,
    CapabilityProvenance,
    CapabilityTrustState,
    CapabilityValidationRecord,
    utc_now,
)
from cyberclaw.permissions.policy import ActionScope


class Capability(BaseModel):
    """A defined functional ability within CyberClaw.

    Capabilities represent WHAT can be done, abstracted away from HOW
    a specific tool or provider executes it.
    """

    id: str = Field(description="Unique capability identifier, e.g. 'discovery.entity'")
    name: str = Field(description="Human-readable capability name")
    version: str = Field(default="1.0.0", description="Semantic version string, e.g. '1.0.0'")
    specialist_id: Optional[str] = Field(default=None, description="Owning specialist ID if specialized")
    description: str = Field(default="")
    category: str = Field(default="general", description="Functional category or ecosystem name")
    input_schema: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional parameter validation schema"
    )
    output_schema: Optional[Dict[str, Any]] = Field(
        default=None, description="Optional expected output schema"
    )
    required_permissions: List[str] = Field(
        default_factory=list, description="Permissions required to invoke this capability"
    )
    action_scope: ActionScope = Field(
        default=ActionScope.REVERSIBLE, description="Scope classification (REVERSIBLE, CONSEQUENTIAL, DESTRUCTIVE)"
    )
    lifecycle_state: CapabilityLifecycleState = Field(
        default=CapabilityLifecycleState.AVAILABLE,
        description="Current lifecycle state (PROPOSED, EXPERIMENTAL, VALIDATED, AVAILABLE, TRUSTED, DEPRECATED, DISABLED, RETIRED, REJECTED)",
    )
    trust_state: CapabilityTrustState = Field(
        default=CapabilityTrustState.TRUSTED_WITH_SCOPE,
        description="Decoupled trust tier (UNTRUSTED, PROVISIONAL, TRUSTED_WITH_SCOPE, FULLY_TRUSTED, REVOKED)",
    )
    provenance: CapabilityProvenance = Field(
        default=CapabilityProvenance.CORE_REGISTERED,
        description="Origin provenance of the capability",
    )
    validation_history: List[CapabilityValidationRecord] = Field(
        default_factory=list, description="Audit trail of formal validations"
    )
    failure_history: List[CapabilityFailureRecord] = Field(
        default_factory=list, description="Audit trail of recorded operational/policy failures"
    )
    governance_history: List[CapabilityGovernanceRecord] = Field(
        default_factory=list, description="Immutable record of lifecycle and trust decisions"
    )
    deprecation_reason: Optional[str] = Field(
        default=None, description="Reason for deprecation if applicable"
    )
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def versioned_id(self) -> str:
        """Stable compound identifier including version."""
        return f"{self.id}@{self.version}"

    def is_executable(self) -> Tuple[bool, Optional[str]]:
        """Determine whether capability can currently be executed based on lifecycle and trust."""
        # 1. Lifecycle check
        if self.lifecycle_state not in (CapabilityLifecycleState.AVAILABLE, CapabilityLifecycleState.TRUSTED):
            return False, f"Capability '{self.versioned_id}' is in lifecycle state '{self.lifecycle_state.value}' and cannot be executed."

        # 2. Trust check
        if self.trust_state in (CapabilityTrustState.UNTRUSTED, CapabilityTrustState.REVOKED):
            return False, f"Capability '{self.versioned_id}' has trust state '{self.trust_state.value}' and cannot execute in production."

        return True, None

    def is_routable(self) -> bool:
        """Determine whether the capability can be selected by planners or routing coordinators."""
        return self.lifecycle_state in (
            CapabilityLifecycleState.AVAILABLE,
            CapabilityLifecycleState.TRUSTED,
        )

    def record_failure(
        self,
        failure_type: CapabilityFailureType,
        error_message: str,
        provider_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> CapabilityFailureRecord:
        """Append a structured failure record."""
        rec = CapabilityFailureRecord(
            capability_id=self.id,
            capability_version=self.version,
            failure_type=failure_type,
            error_message=error_message,
            provider_id=provider_id,
            context=context or {},
        )
        self.failure_history.append(rec)
        self.updated_at = utc_now()
        return rec

    def record_validation(self, validation_record: CapabilityValidationRecord) -> None:
        """Append a validation record to history."""
        self.validation_history.append(validation_record)
        self.updated_at = utc_now()

    def record_governance(self, governance_record: CapabilityGovernanceRecord) -> None:
        """Append an immutable governance decision to history."""
        self.governance_history.append(governance_record)
        self.updated_at = utc_now()

    @classmethod
    def create_proposed(
        cls,
        id: str,
        name: str,
        version: str = "0.1.0",
        description: str = "",
        category: str = "general",
        specialist_id: Optional[str] = None,
        action_scope: ActionScope = ActionScope.REVERSIBLE,
        required_permissions: Optional[List[str]] = None,
        provenance: CapabilityProvenance = CapabilityProvenance.CORE_REGISTERED,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Capability:
        """Factory for a newly proposed, untrusted capability."""
        return cls(
            id=id,
            name=name,
            version=version,
            description=description,
            category=category,
            specialist_id=specialist_id,
            action_scope=action_scope,
            required_permissions=required_permissions or [],
            lifecycle_state=CapabilityLifecycleState.PROPOSED,
            trust_state=CapabilityTrustState.UNTRUSTED,
            provenance=provenance,
            metadata=metadata or {},
        )
