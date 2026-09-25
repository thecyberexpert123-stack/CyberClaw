"""Explicit authority records. These models do not grant authority."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class AuthorityLayer(str, Enum):
    """Who may do what. A later layer must not skip an earlier one."""

    SPECIALIST_PROPOSAL = "SPECIALIST_PROPOSAL"
    PLANNER_INTENT = "PLANNER_INTENT"
    COLLABORATION_ROUTE = "COLLABORATION_ROUTE"
    CAPABILITY_REGISTRATION = "CAPABILITY_REGISTRATION"
    LIFECYCLE = "LIFECYCLE"
    TRUST = "TRUST"
    PERMISSION = "PERMISSION"
    POLICY = "POLICY"
    RUNTIME_DISPATCH = "RUNTIME_DISPATCH"
    PROVIDER = "PROVIDER"
    CASE_RECORD = "CASE_RECORD"
    REPLAY = "REPLAY"
    BRANCH_SIMULATION = "BRANCH_SIMULATION"
    LEARNING_PROPOSAL = "LEARNING_PROPOSAL"


class PersistenceDocumentState(str, Enum):
    """Persisted-document classes. These must not collapse into each other."""

    MISSING = "MISSING"
    EMPTY_VALID = "EMPTY_VALID"
    POPULATED_VALID = "POPULATED_VALID"
    PARTIAL = "PARTIAL"
    CORRUPT = "CORRUPT"


class ProviderOutcome(str, Enum):
    """Provider result classes. Exception text is not one of these."""

    SUCCESS = "SUCCESS"
    SUCCESS_EMPTY = "SUCCESS_EMPTY"
    KNOWN_FAILURE = "KNOWN_FAILURE"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    PROVIDER_REJECTION = "PROVIDER_REJECTION"
    PROVIDER_EXECUTION_EXCEPTION = "PROVIDER_EXECUTION_EXCEPTION"
    TIMEOUT_BEFORE_EXECUTION = "TIMEOUT_BEFORE_EXECUTION"
    TIMEOUT_WITH_UNKNOWN_EXECUTION = "TIMEOUT_WITH_UNKNOWN_EXECUTION"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    UNKNOWN_EXECUTION_STATE = "UNKNOWN_EXECUTION_STATE"


class RecoveryDisposition(str, Enum):
    """What recovery may do. Failure timing is not an input."""

    REQUEUE_UNSTARTED = "REQUEUE_UNSTARTED"
    RECONCILE_COMPLETED = "RECONCILE_COMPLETED"
    GOVERNED_REVERSIBLE_RETRY = "GOVERNED_REVERSIBLE_RETRY"
    PRESERVE_UNKNOWN = "PRESERVE_UNKNOWN"


class WorkerOwnership(str, Enum):
    """Lease ownership. Expiry is not permission to execute again."""

    CLAIMED = "CLAIMED"
    STARTED = "STARTED"
    EXECUTION_RECORDED = "EXECUTION_RECORDED"
    COMPLETED = "COMPLETED"
    UNKNOWN = "UNKNOWN"


class ExecutionAuthorityRecord(BaseModel):
    """What an authoritative execution was allowed to do.

    Secrets are not stored here. A replay reader must be able to explain the
    execution from this record and the recorded policy reference, without
    calling the current policy engine.
    """

    capability_id: str
    capability_version: str = "1.0.0"
    provider_id: Optional[str] = None
    lifecycle_state: str = "AVAILABLE"
    trust_state: str = "TRUSTED_WITH_SCOPE"
    permission_scope: str = "reversible"
    action_scope: str = "consequential"
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    decision: Optional[str] = None
    decision_id: Optional[str] = None
    actor: str = "core.system"
    investigation_id: Optional[str] = None
    task_id: Optional[str] = None
    provider_outcome: Optional[str] = None
    required_permissions: list[str] = Field(default_factory=list)
