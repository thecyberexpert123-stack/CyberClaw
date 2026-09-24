"""Domain-neutral models for cross-case experience and strategy learning.

Learned objects are structured data. They are not executable code, not policy,
and not authority. Every object carries the schema version that produced it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


EXPERIENCE_SCHEMA_VERSION = "0.1.0"
NORMALIZATION_VERSION = "0.1.0"
PATTERN_SCHEMA_VERSION = "0.1.0"
PATTERN_DETECTOR_VERSION = "0.1.0"
PATTERN_ALGORITHM = "signature_equality_v0.1"
STRATEGY_SCHEMA_VERSION = "0.1.0"
EVALUATION_VERSION = "0.1.0"
APPLICABILITY_VERSION = "0.1.0"
SIMILARITY_ALGORITHM = "structured_jaccard_v0.1"
LEARNING_LEDGER_VERSION = "0.1.0"
SIMULATION_VERSION = "0.1.0"

# Justified by axioms: a single case, and a single source family, must not
# become global knowledge. Threshold policy may only raise these floors.
ARCHITECTURAL_MIN_INDEPENDENT_CASES = 2
ARCHITECTURAL_MIN_INDEPENDENT_SOURCE_FAMILIES = 2

LEARNING_ENGINE_ACTORS = frozenset(
    {
        "learning.engine",
        "learning.pattern_detector",
        "learning.strategy_proposer",
        "learning.simulator",
        "learning.evaluator",
        "learning.regression_detector",
    }
)

FORBIDDEN_EXECUTABLE_FRAGMENTS = (
    "eval(",
    "exec(",
    "compile(",
    "__import__",
    "subprocess",
    "os.system",
    "os.popen",
    "pty.spawn",
    "socket.socket",
    "shutil.rmtree",
    "import ",
    "#!",
    "bash -c",
    "powershell",
)

PATTERN_ALGORITHM_PARAMETERS: Dict[str, Any] = {
    "algorithm": PATTERN_ALGORITHM,
    "version": "0.1.0",
    "identity": "exact string equality of a canonical signature",
    "fuzzy_matching": False,
    "capability_sequence": "ordered successful capability ids; consecutive duplicates collapsed",
    "collaboration_sequence": "ordered first-seen specialist ids",
    "requirement_sequence": "ordered sorted evidence-type sets",
    "contradiction_resolution": "sorted resolved conflict types",
    "causal_claims": False,
}

DEFAULT_SIMILARITY_PARAMETERS: Dict[str, Any] = {
    "algorithm": SIMILARITY_ALGORITHM,
    "version": "0.1.0",
    "weights": {
        "objective_tokens": 0.15,
        "information_gap_structure": 0.25,
        "uncertainty_characteristics": 0.15,
        "evidence_characteristics": 0.10,
        "case_stage": 0.10,
        "capability_availability": 0.15,
        "authorization_compatibility": 0.10,
    },
    "hard_exclusions": [
        "missing_required_capability",
        "known_exclusion_context",
        "missing_required_permission",
    ],
}

HIGHER_IS_BETTER = frozenset(
    {
        "information_gain",
        "requirement_resolution",
        "evidence_quality",
        "contradiction_resolution",
        "recovery_behavior",
    }
)
LOWER_IS_BETTER = frozenset(
    {
        "unnecessary_action_count",
        "execution_cost",
        "latency",
        "failure_rate",
        "authorization_complexity",
        "specialist_dependency",
    }
)
EVALUATION_DIMENSIONS = (
    "information_gain",
    "requirement_resolution",
    "evidence_quality",
    "contradiction_resolution",
    "unnecessary_action_count",
    "execution_cost",
    "latency",
    "failure_rate",
    "authorization_complexity",
    "specialist_dependency",
    "recovery_behavior",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def canonical_digest(payload: Dict[str, Any]) -> str:
    """Order-independent SHA-256 of a JSON-serializable payload."""
    encoded = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def stable_id(prefix: str, *parts: str) -> str:
    raw = "|".join(parts)
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:20]}"


def semver_key(version: str) -> tuple:
    parts = []
    for piece in version.split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def bump_minor(version: str) -> str:
    bits = (version.split(".") + ["0", "0"])[:3]
    return f"{int(bits[0])}.{int(bits[1]) + 1}.{int(bits[2])}"


class PatternKind(str, Enum):
    REPEATED_SUCCESS = "REPEATED_SUCCESS"
    REPEATED_FAILURE = "REPEATED_FAILURE"
    REPEATED_CONTRADICTION_RESOLUTION = "REPEATED_CONTRADICTION_RESOLUTION"
    REPEATED_REQUIREMENT_SEQUENCE = "REPEATED_REQUIREMENT_SEQUENCE"
    SPECIALIST_COLLABORATION_PATTERN = "SPECIALIST_COLLABORATION_PATTERN"
    CAPABILITY_SEQUENCE_PATTERN = "CAPABILITY_SEQUENCE_PATTERN"
    EVIDENCE_YIELD_PATTERN = "EVIDENCE_YIELD_PATTERN"
    PLANNING_ADAPTATION_PATTERN = "PLANNING_ADAPTATION_PATTERN"
    RECOVERY_PATTERN = "RECOVERY_PATTERN"
    STOPPING_PATTERN = "STOPPING_PATTERN"


class PatternScope(str, Enum):
    """Promotion scope. CASE_LOCAL is never global authority."""

    CASE_LOCAL = "CASE_LOCAL"
    CANDIDATE_GLOBAL = "CANDIDATE_GLOBAL"
    VALIDATED = "VALIDATED"


class ConfidenceBand(str, Enum):
    INSUFFICIENT = "INSUFFICIENT"
    WEAK = "WEAK"
    MODERATE = "MODERATE"
    STRONG = "STRONG"


class StrategyLifecycle(str, Enum):
    PROPOSED = "PROPOSED"
    SIMULATED = "SIMULATED"
    EVALUATED = "EVALUATED"
    REVIEWED = "REVIEWED"
    APPROVED = "APPROVED"
    AVAILABLE = "AVAILABLE"
    DEPRECATED = "DEPRECATED"
    RETIRED = "RETIRED"
    REJECTED = "REJECTED"
    DISABLED = "DISABLED"
    QUARANTINED = "QUARANTINED"


ALLOWED_LIFECYCLE_TRANSITIONS = {
    StrategyLifecycle.PROPOSED: {
        StrategyLifecycle.SIMULATED,
        StrategyLifecycle.REJECTED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.SIMULATED: {
        StrategyLifecycle.EVALUATED,
        StrategyLifecycle.REJECTED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.EVALUATED: {
        StrategyLifecycle.REVIEWED,
        StrategyLifecycle.REJECTED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.REVIEWED: {
        StrategyLifecycle.APPROVED,
        StrategyLifecycle.REJECTED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.APPROVED: {
        StrategyLifecycle.AVAILABLE,
        StrategyLifecycle.DISABLED,
        StrategyLifecycle.REJECTED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.AVAILABLE: {
        StrategyLifecycle.DEPRECATED,
        StrategyLifecycle.DISABLED,
        StrategyLifecycle.RETIRED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.DEPRECATED: {
        StrategyLifecycle.RETIRED,
        StrategyLifecycle.DISABLED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.DISABLED: {
        StrategyLifecycle.RETIRED,
        StrategyLifecycle.QUARANTINED,
    },
    StrategyLifecycle.QUARANTINED: {
        StrategyLifecycle.REJECTED,
        StrategyLifecycle.REVIEWED,
    },
    StrategyLifecycle.REJECTED: set(),
    StrategyLifecycle.RETIRED: set(),
}


class ApprovalDecisionKind(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REQUEST_MORE_EVIDENCE = "REQUEST_MORE_EVIDENCE"
    DEFER = "DEFER"


class OutcomeClass(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    MIXED = "MIXED"
    INDETERMINATE = "INDETERMINATE"


class AssessmentLabel(str, Enum):
    """Counterfactual structural assessment. Never a causal guarantee."""

    STRUCTURAL_FIT = "STRUCTURAL_FIT"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    INDETERMINATE = "INDETERMINATE"
    BOUNDARY_CROSSED = "BOUNDARY_CROSSED"
    FEWER_STEPS = "FEWER_STEPS"
    MORE_STEPS = "MORE_STEPS"
    EQUAL_STEPS = "EQUAL_STEPS"
    NO_HISTORICAL_CORRELATION = "NO_HISTORICAL_CORRELATION"
    CORRELATED_NOT_CAUSAL = "CORRELATED_NOT_CAUSAL"
    UNAVAILABLE = "UNAVAILABLE"


class LearningEventType(str, Enum):
    THRESHOLD_POLICY_REGISTERED = "THRESHOLD_POLICY_REGISTERED"
    EXPERIENCE_EXTRACTED = "EXPERIENCE_EXTRACTED"
    EXPERIENCE_NORMALIZED = "EXPERIENCE_NORMALIZED"
    EXPERIENCE_QUARANTINED = "EXPERIENCE_QUARANTINED"
    PATTERN_OBSERVED = "PATTERN_OBSERVED"
    PATTERN_VERSION_RECORDED = "PATTERN_VERSION_RECORDED"
    STRATEGY_PROPOSED = "STRATEGY_PROPOSED"
    STRATEGY_SIMULATED = "STRATEGY_SIMULATED"
    STRATEGY_EVALUATED = "STRATEGY_EVALUATED"
    STRATEGY_REVIEWED = "STRATEGY_REVIEWED"
    STRATEGY_APPROVAL_RECORDED = "STRATEGY_APPROVAL_RECORDED"
    STRATEGY_LIFECYCLE_TRANSITION = "STRATEGY_LIFECYCLE_TRANSITION"
    STRATEGY_OUTCOME_RECORDED = "STRATEGY_OUTCOME_RECORDED"
    REGRESSION_DETECTED = "REGRESSION_DETECTED"
    REGRESSION_REVIEWED = "REGRESSION_REVIEWED"
    LEARNING_FAILURE = "LEARNING_FAILURE"
    BRANCH_EXPERIENCE_QUARANTINED = "BRANCH_EXPERIENCE_QUARANTINED"


class StepKind(str, Enum):
    IDENTIFY_INFORMATION_GAP = "IDENTIFY_INFORMATION_GAP"
    IDENTIFY_CONFLICTING_CLAIMS = "IDENTIFY_CONFLICTING_CLAIMS"
    CLASSIFY_TEMPORAL_DISAGREEMENT = "CLASSIFY_TEMPORAL_DISAGREEMENT"
    REQUEST_INDEPENDENT_EVIDENCE = "REQUEST_INDEPENDENT_EVIDENCE"
    REQUEST_AUTHORIZED_CAPABILITY = "REQUEST_AUTHORIZED_CAPABILITY"
    HANDOFF_THROUGH_COLLABORATION = "HANDOFF_THROUGH_COLLABORATION"
    REEVALUATE_CONSENSUS = "REEVALUATE_CONSENSUS"
    REPLAN_IF_UNRESOLVED = "REPLAN_IF_UNRESOLVED"
    RECORD_FAILURE_CONTEXT = "RECORD_FAILURE_CONTEXT"
    STOP_WHEN_CONDITION_MET = "STOP_WHEN_CONDITION_MET"


class AuthoritativeRef(BaseModel):
    """Pointer to an authoritative record. The learning layer does not copy the record as truth."""

    model_config = ConfigDict(frozen=True)

    record_type: str
    record_id: str
    investigation_id: str
    sequence: Optional[int] = None


class SourceFamily(BaseModel):
    model_config = ConfigDict(frozen=True)

    family_id: str
    family_key: str
    member_investigation_ids: List[str] = Field(default_factory=list)
    member_experience_ids: List[str] = Field(default_factory=list)
    shared_source_ids: List[str] = Field(default_factory=list)
    rationale: str


class SourceFamilyClustering(BaseModel):
    model_config = ConfigDict(frozen=True)

    families: List[SourceFamily] = Field(default_factory=list)
    experience_to_family: Dict[str, str] = Field(default_factory=dict)
    algorithm: str = "source_lineage_union_find_v0.1"
    integrates_with: str = "cyberclaw.knowledge.provenance.calculate_source_independence"


class PromotionThresholdPolicy(BaseModel):
    """Auditable promotion and regression thresholds.

    Values below the architectural floor are rejected by the registry.
    """

    model_config = ConfigDict(frozen=True)

    policy_id: str = "default-learning-thresholds"
    version: str = "0.1.0"
    min_independent_cases: int = ARCHITECTURAL_MIN_INDEPENDENT_CASES
    min_independent_source_families: int = ARCHITECTURAL_MIN_INDEPENDENT_SOURCE_FAMILIES
    min_success_observations_for_proposal: int = 2
    min_families_for_strong_band: int = 3
    regression_failure_rate_increase: float = 0.25
    regression_contradiction_increase: int = 1
    regression_evidence_yield_drop: float = 0.5
    regression_min_new_observations: int = 2
    applicability_minimum_similarity: float = 0.5
    similarity_algorithm: str = SIMILARITY_ALGORITHM
    similarity_parameters: Dict[str, Any] = Field(default_factory=lambda: json.loads(json.dumps(DEFAULT_SIMILARITY_PARAMETERS)))
    justification: str = (
        "Architectural floor of 2 independent cases and 2 independent source families "
        "enforces CASE-SPECIFIC EXPERIENCE MUST NOT AUTOMATICALLY BECOME GLOBAL KNOWLEDGE. "
        "This policy may raise the floor; it may not lower it."
    )


class ActionTrace(BaseModel):
    model_config = ConfigDict(frozen=True)

    requirement_id: Optional[str] = None
    specialist_id: Optional[str] = None
    capability_id: Optional[str] = None
    capability_version: Optional[str] = None
    status: Optional[str] = None
    authorization_decision_id: Optional[str] = None
    policy_id: Optional[str] = None
    evidence_count: int = 0
    error: Optional[str] = None
    source_record_ids: List[str] = Field(default_factory=list)


class InvestigationExperience(BaseModel):
    """Structured reconstruction of what an investigation's authoritative history contains.

    Absent fields stay absent. Nothing is invented to fill gaps.
    """

    model_config = ConfigDict(frozen=True)

    experience_id: str
    schema_version: str = EXPERIENCE_SCHEMA_VERSION
    investigation_id: str
    case_id: str
    objective: str = ""
    initial_information_requirements: List[Dict[str, Any]] = Field(default_factory=list)
    initial_uncertainties: List[Dict[str, Any]] = Field(default_factory=list)
    actions_taken: List[ActionTrace] = Field(default_factory=list)
    capabilities_used: List[str] = Field(default_factory=list)
    specialists_involved: List[str] = Field(default_factory=list)
    collaboration_patterns: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_generated: List[AuthoritativeRef] = Field(default_factory=list)
    hypothesis_transitions: List[Dict[str, Any]] = Field(default_factory=list)
    contradictions: List[Dict[str, Any]] = Field(default_factory=list)
    knowledge_graph_changes: List[AuthoritativeRef] = Field(default_factory=list)
    requirements_resolved: List[Dict[str, Any]] = Field(default_factory=list)
    requirements_unresolved: List[Dict[str, Any]] = Field(default_factory=list)
    stopping_condition: Optional[str] = None
    execution_duration_ms: Optional[float] = None
    retry_count: int = 0
    failures: List[Dict[str, Any]] = Field(default_factory=list)
    policy_decisions: List[Dict[str, Any]] = Field(default_factory=list)
    authorization_outcomes: List[Dict[str, Any]] = Field(default_factory=list)
    final_investigation_state: Optional[str] = None
    source_family_key: str
    upstream_source_ids: List[str] = Field(default_factory=list)
    source_independence_count: Optional[int] = None
    source_independence_roots: List[str] = Field(default_factory=list)
    source_independence_available: bool = False
    uncertainty_types: List[str] = Field(default_factory=list)
    evidence_types: List[str] = Field(default_factory=list)
    case_stage: Optional[str] = None
    plan_count: int = 0
    outcome: OutcomeClass = OutcomeClass.INDETERMINATE
    is_counterfactual: bool = False
    branch_id: Optional[str] = None
    extracted_at: datetime
    extractor_version: str = EXPERIENCE_SCHEMA_VERSION
    authoritative_refs: List[AuthoritativeRef] = Field(default_factory=list)
    absent_fields: List[str] = Field(default_factory=list)
    content_digest: str


class NormalizedFeature(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    value: Any
    source_investigation_id: str
    source_record_ids: List[str] = Field(default_factory=list)
    normalization_version: str = NORMALIZATION_VERSION
    timestamp: datetime


class NormalizedExperience(BaseModel):
    model_config = ConfigDict(frozen=True)

    normalized_id: str
    experience_id: str
    investigation_id: str
    normalization_version: str = NORMALIZATION_VERSION
    timestamp: datetime
    features: List[NormalizedFeature] = Field(default_factory=list)
    capability_sequence: List[str] = Field(default_factory=list)
    specialist_sequence: List[str] = Field(default_factory=list)
    requirement_sequence: List[str] = Field(default_factory=list)
    evidence_yield: int = 0
    contradiction_count: int = 0
    resolved_contradiction_types: List[str] = Field(default_factory=list)
    failure_types: List[str] = Field(default_factory=list)
    collaboration_sequence: List[str] = Field(default_factory=list)
    objective_tokens: List[str] = Field(default_factory=list)
    content_digest: str


class ExclusionRecord(BaseModel):
    model_config = ConfigDict(frozen=True)

    investigation_id: str
    experience_id: str
    reason: str


class PatternInstance(BaseModel):
    model_config = ConfigDict(frozen=True)

    instance_id: str
    pattern_id: str
    experience_id: str
    investigation_id: str
    source_family_id: str
    supporting_event_ids: List[str] = Field(default_factory=list)
    outcome: OutcomeClass
    observed_sequence: List[str] = Field(default_factory=list)


class PatternConfidence(BaseModel):
    """Transparent, multi-dimensional support statement. Not an objective truth score."""

    model_config = ConfigDict(frozen=True)

    band: ConfidenceBand
    explanation: str
    sample_count: int
    independent_case_count: int
    independent_source_family_count: int
    success_count: int
    failure_count: int
    contradiction_count: int
    mixed_count: int
    indeterminate_count: int
    recency_note: str
    context_similarity_note: str
    outcome_quality_note: str
    evidence_quality_note: str
    single_score_is_objective_truth: bool = False
    threshold_policy_id: str
    threshold_policy_version: str


class ObservedPattern(BaseModel):
    model_config = ConfigDict(frozen=True)

    pattern_id: str
    version: str
    schema_version: str = PATTERN_SCHEMA_VERSION
    kind: PatternKind
    signature: str
    description: str
    causal_claim: str = "NONE"
    scope: PatternScope
    instances: List[PatternInstance] = Field(default_factory=list)
    sample_count: int = 0
    independent_case_count: int = 0
    independent_source_family_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    contradiction_count: int = 0
    excluded: List[ExclusionRecord] = Field(default_factory=list)
    confidence: PatternConfidence
    detector_version: str = PATTERN_DETECTOR_VERSION
    algorithm: str = PATTERN_ALGORITHM
    algorithm_parameters: Dict[str, Any] = Field(default_factory=lambda: json.loads(json.dumps(PATTERN_ALGORITHM_PARAMETERS)))
    threshold_policy_id: str
    threshold_policy_version: str
    capability_sequence: List[str] = Field(default_factory=list)
    specialist_sequence: List[str] = Field(default_factory=list)
    content_digest: str


class FailurePattern(BaseModel):
    model_config = ConfigDict(frozen=True)

    failure_pattern_id: str
    version: str = "1.0.0"
    failure_type: str
    trigger_context: Dict[str, Any] = Field(default_factory=dict)
    preceding_actions: List[str] = Field(default_factory=list)
    specialists_involved: List[str] = Field(default_factory=list)
    capabilities_involved: List[str] = Field(default_factory=list)
    authorization_outcome: Optional[str] = None
    recovery_behavior: Optional[str] = None
    final_result: str
    supporting_experience_ids: List[str] = Field(default_factory=list)
    supporting_case_ids: List[str] = Field(default_factory=list)
    causal_claim: str = "NONE"
    statement: str
    detector_version: str = PATTERN_DETECTOR_VERSION


class CollaborationPattern(BaseModel):
    """Observed collaboration structure. Not a hidden communication channel."""

    model_config = ConfigDict(frozen=True)

    collaboration_pattern_id: str
    version: str = "1.0.0"
    participants: List[str] = Field(default_factory=list)
    sequence: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    context: Dict[str, Any] = Field(default_factory=dict)
    outcomes: Dict[str, int] = Field(default_factory=dict)
    supporting_cases: List[str] = Field(default_factory=list)
    failures: List[str] = Field(default_factory=list)
    execution_path: str = "Collaboration+Runtime+PolicyEngine+CapabilityGovernance"
    hidden_channel: bool = False
    causal_claim: str = "NONE"


class ApplicabilityProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    version: str = APPLICABILITY_VERSION
    investigation_objectives: List[str] = Field(default_factory=list)
    objective_tokens: List[str] = Field(default_factory=list)
    information_gap_structure: List[str] = Field(default_factory=list)
    available_capabilities_observed: List[str] = Field(default_factory=list)
    specialist_roles_observed: List[str] = Field(default_factory=list)
    authorization_requirements: List[str] = Field(default_factory=list)
    case_stages: List[str] = Field(default_factory=list)
    evidence_characteristics: List[str] = Field(default_factory=list)
    uncertainty_characteristics: List[str] = Field(default_factory=list)
    environment_constraints: List[str] = Field(default_factory=list)
    applicable_contexts: List[str] = Field(default_factory=list)
    known_exclusions: List[str] = Field(default_factory=list)
    required_capabilities: List[str] = Field(default_factory=list)
    required_permissions: List[str] = Field(default_factory=list)
    known_failure_conditions: List[str] = Field(default_factory=list)
    similarity_algorithm: str = SIMILARITY_ALGORITHM
    similarity_parameters: Dict[str, Any] = Field(default_factory=lambda: json.loads(json.dumps(DEFAULT_SIMILARITY_PARAMETERS)))


class StrategyStep(BaseModel):
    """Intent step. Not code, not a shell command, not a provider invocation."""

    model_config = ConfigDict(frozen=True)

    order: int
    step_kind: StepKind
    intent: str
    requested_capability_id: Optional[str] = None
    expected_evidence_characteristics: List[str] = Field(default_factory=list)
    required_capability_classes: List[str] = Field(default_factory=list)
    notes: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StrategyRiskProfile(BaseModel):
    model_config = ConfigDict(frozen=True)

    required_action_scope: str = "reversible"
    structural_factors: List[str] = Field(default_factory=list)
    does_not_grant_authority: bool = True
    policy_remains_authoritative: bool = True
    capability_governance_remains_authoritative: bool = True
    runtime_remains_execution_substrate: bool = True
    single_risk_score_is_objective_truth: bool = False


class StrategyApprovalDecision(BaseModel):
    model_config = ConfigDict(frozen=True)

    decision_id: str
    strategy_id: str
    version: str
    decision: ApprovalDecisionKind
    actor: str
    reason: str
    timestamp: datetime
    evidence_refs: List[str] = Field(default_factory=list)
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    externally_generated: bool = True


class InvestigationStrategy(BaseModel):
    model_config = ConfigDict(frozen=True)

    strategy_id: str
    version: str
    schema_version: str = STRATEGY_SCHEMA_VERSION
    lifecycle_state: StrategyLifecycle = StrategyLifecycle.PROPOSED
    objective_intent: str
    steps: List[StrategyStep] = Field(default_factory=list)
    proposer_id: str
    provenance: Dict[str, Any] = Field(default_factory=dict)
    applicability: ApplicabilityProfile
    required_capabilities: List[str] = Field(default_factory=list)
    required_permissions: List[str] = Field(default_factory=list)
    risk_profile: StrategyRiskProfile
    supporting_pattern_ids: List[str] = Field(default_factory=list)
    supporting_pattern_versions: Dict[str, str] = Field(default_factory=dict)
    supporting_case_ids: List[str] = Field(default_factory=list)
    known_failures: List[str] = Field(default_factory=list)
    evaluation_history: List[str] = Field(default_factory=list)
    approval_history: List[str] = Field(default_factory=list)
    created_from_pattern_id: str
    created_from_pattern_version: str
    executable: bool = False
    execution_substrate: str = "runtime_only"
    content_digest: str
    regression_status: str = "NONE"
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SimulationAnswer(BaseModel):
    model_config = ConfigDict(frozen=True)

    question: str
    assessment: AssessmentLabel
    rationale: str
    is_counterfactual: bool = True
    causal_claim: str = "NONE"


class SimulationReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    report_id: str
    strategy_id: str
    strategy_version: str
    experience_id: Optional[str] = None
    investigation_id: Optional[str] = None
    simulation_version: str = SIMULATION_VERSION
    is_counterfactual: bool = True
    answers: List[SimulationAnswer] = Field(default_factory=list)
    missing_capabilities: List[str] = Field(default_factory=list)
    authorization_boundaries: List[str] = Field(default_factory=list)
    providers_executed: int = 0
    authoritative_state_mutated: bool = False
    policy_decisions_on_live_engine: int = 0
    capabilities_granted: int = 0


class CandidateBranchExperience(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidate_id: str
    strategy_id: str
    strategy_version: str
    is_counterfactual: bool = True
    branch_id: str
    investigation_id: str
    source_snapshot: str
    evaluation_context: Dict[str, Any] = Field(default_factory=dict)
    report: SimulationReport
    promoted_to_authoritative_experience: bool = False
    quarantine_reason: str = "COUNTERFACTUAL_RESULT_IS_NOT_HISTORICAL_RESULT"


class DimensionMeasure(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    value: Optional[float] = None
    unit: str
    measured: bool
    sample_size: int
    explanation: str
    higher_is_better: bool


class StrategyEvaluation(BaseModel):
    model_config = ConfigDict(frozen=True)

    evaluation_id: str
    strategy_id: str
    strategy_version: str
    evaluation_version: str = EVALUATION_VERSION
    dimensions: Dict[str, DimensionMeasure] = Field(default_factory=dict)
    tradeoffs: List[str] = Field(default_factory=list)
    declares_winner: bool = False
    collapsed_score_used: bool = False
    uncertainty_notes: List[str] = Field(default_factory=list)
    simulation_report_ids: List[str] = Field(default_factory=list)


class TradeoffReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    first_strategy_id: str
    second_strategy_id: str
    first_higher: List[str] = Field(default_factory=list)
    second_higher: List[str] = Field(default_factory=list)
    unmeasured: List[str] = Field(default_factory=list)
    declares_winner: bool = False
    note: str = "No winner is declared. Trade-offs are reported independently."


class StrategyOutcome(BaseModel):
    model_config = ConfigDict(frozen=True)

    outcome_id: str
    strategy_id: str
    strategy_version: str
    investigation_id: str
    experience_id: Optional[str] = None
    success: bool
    contradiction_count: int = 0
    evidence_yield: int = 0
    authorization_failures: int = 0
    capability_failures: int = 0
    context_signature: str = ""
    is_counterfactual: bool = False
    recorded_at: datetime = Field(default_factory=utc_now)


class RegressionSignal(BaseModel):
    model_config = ConfigDict(frozen=True)

    signal_id: str
    strategy_id: str
    strategy_version: str
    status: str
    recommended_lifecycle: Optional[str] = None
    reasons: List[str] = Field(default_factory=list)
    baseline_failure_rate: Optional[float] = None
    observed_failure_rate: Optional[float] = None
    threshold_policy_id: str
    threshold_policy_version: str
    historical_usage_deleted: bool = False
    auto_applied: bool = False


class ApplicabilityMatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    is_applicable: bool
    similarity: float
    dimension_scores: Dict[str, float] = Field(default_factory=dict)
    algorithm: str = SIMILARITY_ALGORITHM
    algorithm_parameters: Dict[str, Any] = Field(default_factory=dict)
    minimum_similarity: float
    hard_exclusions: List[str] = Field(default_factory=list)
    explanation: str
    similarity_is_objective_truth: bool = False


class StrategyCandidate(BaseModel):
    model_config = ConfigDict(frozen=True)

    strategy_id: str
    strategy_version: str
    applicability_explanation: str
    supporting_pattern_ids: List[str] = Field(default_factory=list)
    supporting_investigations: List[str] = Field(default_factory=list)
    independent_case_count: int = 0
    known_failures: List[str] = Field(default_factory=list)
    required_capabilities: List[str] = Field(default_factory=list)
    required_permissions: List[str] = Field(default_factory=list)
    risk_factors: List[str] = Field(default_factory=list)
    evaluation_history: List[str] = Field(default_factory=list)
    reason_for_applicability: str
    limitations: List[str] = Field(default_factory=list)
    contradicting_evidence_refs: List[str] = Field(default_factory=list)
    policy_precheck: str = "NOT_EVALUATED"
    policy_decision_ids: List[str] = Field(default_factory=list)
    executable: bool = False
    execution_substrate: str = "runtime_only"
    ranking_policy: str = "deterministic_id_order"
    opaque_preference_used: bool = False


class StrategyQueryResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    candidates: List[StrategyCandidate] = Field(default_factory=list)
    excluded: List[Dict[str, Any]] = Field(default_factory=list)
    ranking_policy: str = "deterministic_id_order"
    opaque_preference_used: bool = False


class LearningEvent(BaseModel):
    """Immutable ledger event. Replay reconstructs state from these payloads only."""

    model_config = ConfigDict(frozen=True)

    event_id: str
    sequence: int
    event_type: LearningEventType
    timestamp: datetime
    actor: str
    subject_id: str
    subject_version: Optional[str] = None
    schema_version: str = LEARNING_LEDGER_VERSION
    detector_version: Optional[str] = None
    evaluator_version: Optional[str] = None
    normalization_version: Optional[str] = None
    applicability_version: Optional[str] = None
    threshold_policy_id: Optional[str] = None
    threshold_policy_version: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    payload: Dict[str, Any] = Field(default_factory=dict)
    is_counterfactual: bool = False


class InvestigationContext(BaseModel):
    model_config = ConfigDict(frozen=True)

    investigation_id: str
    objective: str = ""
    case_stage: str = ""
    information_gap_structure: List[str] = Field(default_factory=list)
    uncertainty_characteristics: List[str] = Field(default_factory=list)
    evidence_characteristics: List[str] = Field(default_factory=list)
    available_capabilities: List[str] = Field(default_factory=list)
    available_specialists: List[str] = Field(default_factory=list)
    actor_permissions: List[str] = Field(default_factory=list)
    environment_constraints: List[str] = Field(default_factory=list)


class ReconstructedLearningState(BaseModel):
    """Point-in-time learning state folded from recorded events. Detectors were not re-run."""

    model_config = ConfigDict(frozen=True)

    until_sequence: int
    experiences: Dict[str, Any] = Field(default_factory=dict)
    patterns: Dict[str, Any] = Field(default_factory=dict)
    pattern_versions: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    strategies: Dict[str, Dict[str, Any]] = Field(default_factory=dict)
    approvals: List[Dict[str, Any]] = Field(default_factory=list)
    evaluations: List[Dict[str, Any]] = Field(default_factory=list)
    threshold_policies: Dict[str, Any] = Field(default_factory=dict)
    detector_versions_seen: List[str] = Field(default_factory=list)
    evaluator_versions_seen: List[str] = Field(default_factory=list)
    detectors_executed: int = 0
    evaluators_executed: int = 0
    providers_executed: int = 0
    note: str = "Reconstructed from recorded events and decisions. Today's detector, evaluator, thresholds, and policy were not applied."


class StrategyOriginExplanation(BaseModel):
    model_config = ConfigDict(frozen=True)

    strategy_id: str
    strategy_version: str
    pattern_id: Optional[str] = None
    pattern_version: Optional[str] = None
    supporting_cases: List[str] = Field(default_factory=list)
    supporting_event_ids: List[str] = Field(default_factory=list)
    successful_cases: List[str] = Field(default_factory=list)
    contradicting_cases: List[str] = Field(default_factory=list)
    excluded: List[Dict[str, Any]] = Field(default_factory=list)
    exclusion_reasons: List[str] = Field(default_factory=list)
    causal_claim: str = "NONE"
    detector_version: Optional[str] = None
    threshold_policy_id: Optional[str] = None
    threshold_policy_version: Optional[str] = None
    reconstructed_from_events: bool = True
