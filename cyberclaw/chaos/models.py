"""Explicit models for deterministic fault injection and invariant validation.

Chaos reports are diagnostic records. They are not authoritative case state,
policy, capability trust, or learned strategy.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


CHAOS_SCHEMA_VERSION = "0.1.0"


class FaultType(str, Enum):
    SPECIALIST_FAILURE = "SPECIALIST_FAILURE"
    PROVIDER_FAILURE = "PROVIDER_FAILURE"
    VALIDATION_FAILURE = "VALIDATION_FAILURE"
    POLICY_DENIAL = "POLICY_DENIAL"
    APPROVAL_REJECTION = "APPROVAL_REJECTION"
    SUPERVISION_TIMEOUT = "SUPERVISION_TIMEOUT"
    RUNTIME_CRASH = "RUNTIME_CRASH"
    WORKER_CRASH = "WORKER_CRASH"
    TASK_TIMEOUT = "TASK_TIMEOUT"
    TASK_CANCELLATION = "TASK_CANCELLATION"
    DUPLICATE_EVENT = "DUPLICATE_EVENT"
    DUPLICATE_EXECUTION_ATTEMPT = "DUPLICATE_EXECUTION_ATTEMPT"
    STALE_LEASE = "STALE_LEASE"
    PARTIAL_RESULT = "PARTIAL_RESULT"
    MALFORMED_RESULT = "MALFORMED_RESULT"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"
    PERSISTENCE_TRUNCATION = "PERSISTENCE_TRUNCATION"
    PERSISTENCE_CORRUPTION = "PERSISTENCE_CORRUPTION"
    SNAPSHOT_CORRUPTION = "SNAPSHOT_CORRUPTION"
    JOURNAL_GAP = "JOURNAL_GAP"
    BRANCH_MUTATION_ATTEMPT = "BRANCH_MUTATION_ATTEMPT"
    COUNTERFACTUAL_LEAK_ATTEMPT = "COUNTERFACTUAL_LEAK_ATTEMPT"
    LEARNING_REGRESSION = "LEARNING_REGRESSION"
    POLICY_VERSION_CHANGE = "POLICY_VERSION_CHANGE"
    CAPABILITY_STATE_CHANGE = "CAPABILITY_STATE_CHANGE"


class CorruptionClass(str, Enum):
    TRUNCATION = "TRUNCATION"
    MISSING_RECORD = "MISSING_RECORD"
    MODIFIED_RECORD = "MODIFIED_RECORD"
    INVALID_JSON = "INVALID_JSON"
    INVALID_SCHEMA = "INVALID_SCHEMA"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    SEQUENCE_GAP = "SEQUENCE_GAP"
    INVALID_REFERENCE = "INVALID_REFERENCE"


class RecoveryClass(str, Enum):
    REQUEUED_UNSTARTED = "REQUEUED_UNSTARTED"
    RECONCILED_COMPLETED = "RECONCILED_COMPLETED"
    REVERSIBLE_RETRY = "REVERSIBLE_RETRY"
    UNKNOWN_REQUIRES_GOVERNANCE = "UNKNOWN_REQUIRES_GOVERNANCE"
    NOT_RECOVERABLE = "NOT_RECOVERABLE"
    ALREADY_TERMINAL = "ALREADY_TERMINAL"
    REJECTED_NOT_RETRIED = "REJECTED_NOT_RETRIED"


class InvariantSeverity(str, Enum):
    AUTHORITY = "AUTHORITY"
    RUNTIME = "RUNTIME"
    KNOWLEDGE = "KNOWLEDGE"
    LEARNING = "LEARNING"
    BRANCHING = "BRANCHING"
    POLICY = "POLICY"
    COLLABORATION = "COLLABORATION"
    PERSISTENCE = "PERSISTENCE"


class FaultSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    fault_id: str
    fault_type: FaultType
    target: str
    schedule_index: int = 0
    parameters: Dict[str, Any] = Field(default_factory=dict)
    note: str = ""


class InvariantResult(BaseModel):
    """A failed or passed invariant with an explanation, not a lone boolean."""

    invariant_id: str
    description: str
    subsystem: str
    severity: InvariantSeverity
    passed: bool
    what_happened: str
    expected: str
    observed: str
    boundary: str
    references: List[str] = Field(default_factory=list)
    digest: str = ""
    version: str = CHAOS_SCHEMA_VERSION


class TraceEvent(BaseModel):
    sequence: int
    action: str
    detail: str = ""
    fault_type: Optional[str] = None


class DigestBundle(BaseModel):
    case_state: str = ""
    journal: str = ""
    snapshots: str = ""
    runtime: str = ""
    knowledge_graph: str = ""
    branch: str = ""
    learning: str = ""
    structural: str = ""


class ChaosReport(BaseModel):
    model_config = ConfigDict(frozen=False)

    scenario_id: str
    seed: int
    schema_version: str = CHAOS_SCHEMA_VERSION
    injected_faults: List[FaultSpec] = Field(default_factory=list)
    execution_trace: List[TraceEvent] = Field(default_factory=list)
    invariant_results: List[InvariantResult] = Field(default_factory=list)
    expected_state: Dict[str, Any] = Field(default_factory=dict)
    observed_state: Dict[str, Any] = Field(default_factory=dict)
    recovery_result: Dict[str, Any] = Field(default_factory=dict)
    replay_result: Dict[str, Any] = Field(default_factory=dict)
    digest_comparison: Dict[str, Any] = Field(default_factory=dict)
    boundary_violations: List[str] = Field(default_factory=list)
    final_digest: DigestBundle = Field(default_factory=DigestBundle)
    replay_digest: DigestBundle = Field(default_factory=DigestBundle)
    recovery_digest: DigestBundle = Field(default_factory=DigestBundle)
    branch_digest: str = ""
    passed: bool = False

    def violations(self) -> List[InvariantResult]:
        return [item for item in self.invariant_results if not item.passed]
