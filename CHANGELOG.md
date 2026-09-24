# Changelog

All notable changes to CyberClaw are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-09-24

### Added - Cross-Case Experience & Investigation Strategy Learning v0.1
- **`cyberclaw/learning/`**: Domain-neutral learning package. Experience is extracted from authoritative history, normalized with source lineage, clustered by source family, and grouped by exact versioned signatures. Patterns do not become strategies, strategies do not execute, and the learning engine cannot approve itself.
- **Experience and provenance**: `InvestigationExperience` retains journal, evidence, requirement, hypothesis, contradiction, execution, and authorization references. Missing knowledge-graph history is recorded as absent rather than invented. Extraction does not append to the case journal.
- **Pattern detection**: `signature_equality_v0.1` detects repeated success, failure, contradiction resolution, requirement sequence, collaboration, capability sequence, evidence yield, planning adaptation, recovery, and stopping patterns. Confidence is a explained qualitative band, not an objective score.
- **Source independence**: declared templates/feeds/experiments and shared upstream sources collapse into one source family. A single case or a single family cannot become global knowledge. The floor of 2 independent cases and 2 families is architectural and cannot be lowered by threshold policy.
- **Strategies**: immutable, versioned structured intents with explicit applicability, required capabilities, required permissions, known failures, and a deterministic lifecycle (`PROPOSED` through `AVAILABLE`, plus `REJECTED`, `DISABLED`, `QUARANTINED`). Executable payloads are rejected.
- **Simulation and evaluation**: counterfactual simulation uses historical experiences and branches without provider execution, case mutation, capability grants, or live policy-store writes. Evaluation reports independent dimensions and trade-offs and does not declare a winner. Regression detection recommends review without deleting history.
- **Governance and planner integration**: external `StrategyApprovalDecision`, isolated PolicyEngine precheck before publication, and planner candidate queries that return non-executable data. Runtime remains the only execution substrate.
- **Replay, branching, persistence, and knowledge projection**: ledger replay reconstructs historical strategy and pattern versions without re-running today's detector. Branch results stay quarantined. `learning/registry.json` is atomic and digest-verified. Learned relations are projected onto a separate learning graph.
- **Tests**: 46 new deterministic tests, including the mandatory cross-case E2E scenario. Full suite is 387 passed.

### Added - Temporal Evidence & Knowledge Graph v0.1
- **`cyberclaw/knowledge/models.py`**: Immutable domain-neutral models and enums including `NodeType` (11 generic node types), `RelationshipType` (11 generic relationship types), `EdgeStatus`, `KnowledgeGap`, `KnowledgeExplanation`, and `ConsistencyIssue`.
- **`cyberclaw/knowledge/nodes.py`**: Deterministic `KnowledgeNode` container with temporal validity boundaries (`valid_from`, `valid_until`), provenance references, source references, counterfactual tagging, and deterministic SHA-256 node integrity digests.
- **`cyberclaw/knowledge/edges.py`**: Directed, typed `KnowledgeEdge` capturing relationships between nodes with confidence scores (0.0 to 1.0), epistemic classification (`OBSERVATION`, `INFERENCE`, `HYPOTHESIS`, `CONTRADICTION`), supporting/refuting evidence references, and deterministic SHA-256 edge integrity digests.
- **`cyberclaw/knowledge/temporal.py`**: `TemporalInterval` semantics for computing interval overlap, containment, and validity at arbitrary historical timestamps; conflict classifier distinguishing `DIRECT_CONTRADICTION`, `TEMPORAL_SUPERSEDENCE`, `SOURCE_DISAGREEMENT`, and `PROBABILISTIC_TENSION`.
- **`cyberclaw/knowledge/provenance.py`**: Lineage and derivation engine providing recursive backward lineage tracing to extract root evidence and source references, and source independence verification rejecting circular or shared-source corroboration.
- **`cyberclaw/knowledge/graph.py`**: Multi-indexed `TemporalKnowledgeGraph` managing nodes, edges, adjacency indices, temporal lookup, branch isolation, and order-independent cryptographic graph digest computation.
- **`cyberclaw/knowledge/queries.py`**: Dual-view abstraction (`CurrentKnowledgeView` and `HistoricalKnowledgeView`), query engine, planning gap discovery (`find_knowledge_gaps`), and explanation generation (`explain_node`, `explain_edge`, `explain_hypothesis_graph`).
- **`cyberclaw/knowledge/traversal.py`**: `GraphTraversalEngine` providing BFS/DFS path traversal with depth limits, node/edge type constraints, and strict cycle protection.
- **`cyberclaw/knowledge/mutations.py`**: Governed `GraphMutationPipeline` enforcing 3-phase mutation lifecycle (`Validation -> PolicyEngine Authorization -> CaseJournal Auditing -> Execution`) for additions, edge assertions, and edge revocations.
- **`cyberclaw/knowledge/materialization.py`**: Deterministic `KnowledgeMaterializer` synthesizing complete temporal knowledge graphs from authoritative `CaseState` and `Investigation` stores without invoking specialists or providers.
- **`cyberclaw/knowledge/consistency.py`**: `KnowledgeConsistencyEngine` verifying graph integrity, detecting contradictions, cycle violations, dangling references, and uncorroborated inferences.
- **`cyberclaw/knowledge/persistence.py`**: `KnowledgePersistenceManager` providing atomic workspace serialization in `knowledge/graph.json` with cryptographic digest verification on reload.
- **`cyberclaw/knowledge/errors.py`**: Structured exception taxonomy (`KnowledgeGraphError`, `NodeNotFoundError`, `EdgeNotFoundError`, `CyclicDependencyError`, `TemporalConsistencyError`, `GraphMutationValidationError`, `GraphAuthorizationDeniedError`, `GraphTamperDetectedError`, `BranchIsolationError`, `KnowledgePersistenceError`).
- **Core Integration**:
  - `CyberClawCore.materialize_knowledge_graph(...)`: Materializes deterministic graph from case state.
  - `CyberClawCore.propose_graph_mutation(...)`: Processes governed graph mutations through validation and policy.
  - `CyberClawCore.query_current_graph(...)` & `query_historical_graph(...)`: Current vs. historical time-slice queries.
  - `CyberClawCore.explain_graph_hypothesis(...)`: Generates explainability report for hypotheses.
  - `CyberClawCore.discover_knowledge_gaps(...)`: Surfaces knowledge gaps for adaptive planning.
  - `CyberClawCore.persist_knowledge_graph(...)` & `load_knowledge_graph(...)`: Atomic persistence and reload verification.
- **Replay & Branch Integration**:
  - `ReplayEngine.replay_knowledge_graph(...)`: Reconstructs historical graph states without provider or planner execution.
  - `ReplayEngine.compare_graph_states(...)`: Computes state diffs across live and replayed knowledge graphs.
  - Strict branch isolation quarantine ensuring branch mutations do not contaminate authoritative graphs.
- **Comprehensive Testing**:
  - Added 44 deterministic tests across 5 new test files:
    - `tests/test_knowledge_models_and_integrity.py` (8 tests)
    - `tests/test_knowledge_temporal_and_provenance.py` (8 tests)
    - `tests/test_knowledge_traversal_and_queries.py` (9 tests)
    - `tests/test_knowledge_governance_and_consistency.py` (10 tests)
    - `tests/test_knowledge_persistence_replay_e2e.py` (9 tests, including complete Section 28 E2E scenario)
  - Total passing tests increased from 297 to 341 with zero regressions across all 65 test suites.

### Added - Multi-Specialist Collaboration & Evidence Consensus v0.1
- **`cyberclaw/collaboration/models.py`**: Immutable, versioned data models including `CollaborationRequest`, `CollaborationResult`, `CollaborationContext`, `SpecialistConflict`, `ConsensusAssessment`, `CollaborationDependency`, `CollaborationStatus`, `ConflictStatus`, `ConsensusStatus`, `ContextSensitivity`, `DependencyType`, `DependencyRelation`, and `FindingNature`.
- **`cyberclaw/collaboration/protocol.py`**: Deterministic `CollaborationLifecycleDFA` defining formal state machine (`PROPOSED -> VALIDATING -> AUTHORIZED -> ROUTED -> ACCEPTED -> IN_PROGRESS -> RESULT_RECEIVED -> EVALUATED -> COMPLETED` and alternate paths `REJECTED`, `DEFERRED`, `CANCELLED`, `FAILED`, `EXPIRED`, `BLOCKED`) and least-privilege `ContextFilter` enforcing 4 clearance tiers (`PUBLIC`, `INTERNAL`, `RESTRICTED`, `SENSITIVE`).
- **`cyberclaw/collaboration/dependencies.py`**: `CollaborationDependencyGraph` modeling explicit dependency DAG relationships (`depends_on`, `blocks`, `unblocks`, `derived_from`, `corroborates`, `contradicts`), DFS multi-hop cycle detection, and hard vs. soft dependency readiness gating.
- **`cyberclaw/collaboration/routing.py`**: Domain-neutral `CollaborationRouter` evaluating specialist health (`HEALTHY`, `DEGRADED`, `UNHEALTHY`), workload capacity, capability registration, and requirement constraints with transparent candidate scoring.
- **`cyberclaw/collaboration/evidence.py`**: Structured `EvidenceHandoffNormalizer` classifying specialist findings into 6 distinct epistemic categories (`OBSERVATION`, `INFERENCE`, `CORRELATION`, `HYPOTHESIS`, `NEGATIVE_FINDING`, `FAILURE`) while preserving complete derivation and provenance lineage (`derived_from_evidence_ids`, `authorization_decision_id`, `capability_version`).
- **`cyberclaw/collaboration/conflicts.py`**: `ConflictDetector` and `ConflictManager` identifying contradictory findings across specialists, maintaining explicit `SpecialistConflict` records without overwriting findings, and tracking conflict resolution lifecycle (`OPEN`, `UNDER_REVIEW`, `CORROBORATING`, `RESOLVED`, `PERSISTENT`, `ABANDONED`).
- **`cyberclaw/collaboration/consensus.py`**: Explainable `ConsensusEngine` computing confidence based on source independence, corroboration, refutation, and uncertainty; rejects artificial consensus from shared upstream sources or derivative inferences.
- **`cyberclaw/collaboration/coordinator.py`**: `CollaborationCoordinator` integrating Multi-Specialist Collaboration with Runtime, PolicyEngine, Case Journal, and Evidence Stores.
- **`cyberclaw/collaboration/persistence.py`**: `CollaborationPersistenceManager` providing atomic workspace serialization in `collaboration/state.json`.
- **`cyberclaw/collaboration/errors.py`**: Structured exception hierarchy (`CollaborationError`, `CollaborationStateTransitionError`, `CollaborationValidationError`, `CollaborationAuthorizationError`, `SpecialistUnavailableError`, `DependencyUnresolvedError`, `DependencyCycleError`, `CollaborationTimeoutError`, `EvidenceNormalizationError`, `ConflictProcessingError`, `ConsensusEvaluationError`, `UnauthorizedContextAccessError`, `CollaborationPersistenceError`).
- **Core Integration**:
  - `CyberClawCore.request_collaboration(...)`: Submits structured collaboration requests across specialists.
  - `CyberClawCore.validate_and_route_collaboration(...)`: Validates dependencies, policy authorization, and capability routing.
  - `CyberClawCore.accept_collaboration_request(...)`: Enqueues governed durable runtime tasks.
  - `CyberClawCore.process_collaboration_result(...)`: Normalizes findings, detects conflicts, and synthesizes consensus.
  - `CyberClawCore.resolve_specialist_conflict(...)`: Formally resolves specialist conflicts with authoritative evidence and rationale.
  - `CyberClawCore.persist_collaboration_state(...)` & `load_collaboration_state(...)`: Atomic persistence and restore.
- **Case Journal**:
  - Added collaboration journal entries: `COLLABORATION_REQUESTED`, `COLLABORATION_AUTHORIZED`, `COLLABORATION_ACCEPTED`, `COLLABORATION_RESULT_RECEIVED`, `SPECIALIST_CONFLICT_DETECTED`, `COLLABORATION_COMPLETED`.
- **Comprehensive Testing**:
  - Added 36 unit and integration tests across 5 new test files:
    - `tests/test_collaboration_models_and_lifecycle.py` (9 tests)
    - `tests/test_collaboration_dependencies_and_routing.py` (8 tests)
    - `tests/test_collaboration_conflicts_and_consensus.py` (8 tests)
    - `tests/test_collaboration_runtime_and_governance.py` (8 tests)
    - `tests/test_collaboration_integration_and_e2e.py` (3 tests, including complete 31-step Section 36 E2E scenario)
  - Total passing tests increased from 261 to 297 with zero regressions across all 60 test suites.

### Added - Durable Event-Driven Investigation Runtime v0.1
- **`cyberclaw/runtime/models.py`**: Immutable, versioned data models including `RuntimeEvent`, `RuntimeTask`, `TaskStatus`, `TaskPriority`, `CancellationStatus`, `ExecutionState`, `RetryPolicy`, `RuntimeMetrics`, and `RuntimeObservabilityReport`.
- **`cyberclaw/runtime/events.py`**: Explicit event typing (`RuntimeEventType` with 23 operational lifecycle event types), monotonic per-investigation `EventSequenceTracker` rejecting regressions and duplicates, and `EventFactory` maintaining causation and correlation graphs.
- **`cyberclaw/runtime/state.py`**: Deterministic `TaskLifecycleDFA` defining formal task transition rules (`CREATED -> QUEUED -> VALIDATING -> AUTHORIZED -> DISPATCHED -> RUNNING -> COMPLETED`) and governed alternate paths (`DEFERRED`, `REJECTED`, `CANCELLED`, `FAILED`, `TIMED_OUT`, `RETRY_PENDING`).
- **`cyberclaw/runtime/idempotency.py`**: Deterministic `compute_task_idempotency_key` and thread-safe `IdempotencyRegistry` maintaining strict ontological separation: duplicate event ≠ duplicate authorization ≠ duplicate execution.
- **`cyberclaw/runtime/queue.py`**: `DurableTaskQueue` providing multi-priority dequeuing (`CRITICAL > HIGH > NORMAL > LOW`), time-bounded worker leases, automatic lease expiration and reclaim, thread-safe double-claim protection, retry scheduling, task cancellation, and atomic workspace persistence.
- **`cyberclaw/runtime/dispatcher.py`**: Contract-based `SpecialistDispatcher` resolving capability requests to specialist endpoints or registered providers without domain-specific conditionals.
- **`cyberclaw/runtime/executor.py`**: Governed `RuntimeExecutor` orchestrating the end-to-end execution pipeline: branch check, idempotency check, timeout evaluation, capability trust & lifecycle verification, contextual policy authorization, multi-phase validation pipeline (schema, permissions, DFA), specialist dispatch, result validation, structured evidence ingestion, case journal logging, and experience store recording.
- **`cyberclaw/runtime/scheduler.py`**: `RuntimeScheduler` enforcing case-level serialization locks, priority dispatching, monotonic sequence assignment, pause/resume gating, and worker metrics tracking.
- **`cyberclaw/runtime/recovery.py`**: `RuntimeRecoveryManager` performing deterministic crash recovery across worker claim, execution, and unacknowledged stages without blind retries or destructive double-executions.
- **`cyberclaw/runtime/persistence.py`**: `RuntimePersistenceManager` implementing atomic state export and import to `runtime/queue.json` and `runtime/idempotency.json`.
- **`cyberclaw/runtime/errors.py`**: Structured failure taxonomy and exception hierarchy (`QueueError`, `RuntimeValidationError`, `RuntimeAuthorizationError`, `DispatchError`, `ProviderExecutionError`, `RuntimeTimeoutError`, `RuntimeResultValidationError`, `EvidenceProcessingError`, `StateTransitionError`, `PersistenceError`, `RecoveryError`, `DuplicateEventError`, `PauseViolationError`, `BranchExecutionBlockedError`, `ConcurrencyConflictError`, `UnknownExecutionStateError`).
- **Core Integration**:
  - `CyberClawCore.submit_task_to_runtime(...)`: Submits executable tasks with priority, scope, actor, and timeout into the durable queue.
  - `CyberClawCore.submit_requirement_to_runtime(...)`: Bridges planning `InformationRequirement` into durable runtime tasks.
  - `CyberClawCore.step_runtime(...)` & `process_runtime_queue(...)`: Step-by-step and batch queue execution with case persistence.
  - `CyberClawCore.pause_investigation_runtime(...)` & `resume_investigation_runtime(...)`: Controlled runtime pause/resume flow control.
  - `CyberClawCore.recover_runtime(...)`: Process-restart recovery reconciliation.
- **Case Journal**:
  - Added `TASK_QUEUED`, `TASK_CLAIMED`, `TASK_COMPLETED` to `JournalEntryType`.
- **Comprehensive Test Suite**:
  - Added 35 unit and integration tests across 6 new test files:
    - `tests/test_runtime_events_and_models.py`
    - `tests/test_runtime_lifecycle_and_queue.py`
    - `tests/test_runtime_idempotency_and_concurrency.py`
    - `tests/test_runtime_retry_timeout_recovery.py`
    - `tests/test_runtime_governance_and_integration.py` (including full 34-step Section 37 E2E scenario)
    - `tests/test_runtime_errors_and_observability.py`
  - Total passing tests increased from 226 to 261.

### Added - Policy Engine & Risk-Aware Authorization v0.1
- **`cyberclaw/policy/models.py`**: Domain-agnostic models including `Policy`, `PolicyRule`, `PolicyEffect`, `PolicyExecutionContext`, `AuthorizationDecision`, `AuthorizationDecisionType`, `RiskLevel`, `RiskAssessment`, `RiskFactor`, `ActorRole`, and `PolicyValidationRecord`.
- **`cyberclaw/policy/errors.py`**: Structured error hierarchy (`PolicyError`, `PolicyNotFoundError`, `PolicyValidationError`, `AuthorizationDeniedError`, `ApprovalRequiredError`, `SupervisionRequiredError`, `PolicyConflictError`, `InvalidPolicyContextError`).
- **`cyberclaw/policy/risk.py`**: Deterministic, explainable `RiskEvaluator` assessing action scope, lifecycle state, trust state, investigation DFA state, actor role, branch isolation, and dangerous parameter flags.
- **`cyberclaw/policy/rules.py`**: Declarative condition matching engine (`match_rule_conditions`) and baseline system rules (`create_standard_rules`).
- **`cyberclaw/policy/evaluator.py`**: Fail-closed `PolicyEvaluator` implementing categorical conflict resolution: `DENY > REQUIRE_APPROVAL > REQUIRE_SUPERVISION > DEFER > ALLOW`.
- **`cyberclaw/policy/registry.py`**: Version-aware, thread-safe `PolicyRegistry` enforcing policy immutability, default policy management, and read-only isolated snapshots for counterfactual branches.
- **`cyberclaw/policy/engine.py`**: Central `PolicyEngine` coordinating contextual authorization, lead/human approval workflows (`request_approval`, `reject_approval`), supervision acknowledgment (`acknowledge_supervision`), and Case Journal auditing.
- **`cyberclaw/case/models.py` & `cyberclaw/case/manager.py`**: Added authorization journal entry types (`AUTHORIZATION_REQUESTED`, `AUTHORIZATION_GRANTED`, `AUTHORIZATION_DENIED`, `AUTHORIZATION_DEFERRED`, `APPROVAL_REQUESTED`, `APPROVAL_GRANTED`, `APPROVAL_REJECTED`, `POLICY_CONFLICT_DETECTED`, `RISK_ASSESSED`) and enhanced `ExecutionHistoryRecord` with `authorization_decision_id`, `risk_level`, and `policy_id`.
- **Validation & Core Integration**:
  - `ValidationPipeline.validate_authorization(...)`: Phase enforcing policy decisions during request pre-validation.
  - `CyberClawCore.execute_action(...)`: Contextual authorization pipeline evaluating risk, enforcing approval/supervision gates, and logging authorization records into case history.
  - `PlanValidator.validate_candidate(...)`: Speculative policy authorization pre-check for planning candidates.
- **Comprehensive Test Suite**:
  - `tests/test_policy_engine.py`: 30 unit and integration tests covering models, risk evaluation, rule matching, fail-closed precedence, versioning, approval workflows, supervision acknowledgment, journal recording, Core dispatch, branch isolation, self-development quarantine, and replay preservation.

### Added - Capability Lifecycle & Governance v0.1
- **`cyberclaw/capabilities/models.py`**: Introduced `CapabilityLifecycleState`, `CapabilityTrustState`, `CapabilityHealth`, `CapabilityProvenance`, `CapabilityFailureType`, `CapabilityValidationRecord`, `CapabilityFailureRecord`, `CapabilityGovernanceRecord`, `CapabilityCandidate`, and `CapabilityDiscoveryResult`.
- **`cyberclaw/capabilities/lifecycle.py`**: State machine enforcing permissible lifecycle transitions (`PROPOSED` -> `EXPERIMENTAL` -> `VALIDATED` -> `AVAILABLE` -> `TRUSTED` -> `DEPRECATED` -> `RETIRED`, with operational control `DISABLED` and rejection `REJECTED`).
- **`cyberclaw/capabilities/governance.py`**: Formal validation assessments, explicit authority approval gates, trust assignments, trust revocation, deprecation, retirement, and intelligence gap capability discovery.
- **`cyberclaw/capabilities/bridge.py`**: Mediates between Self-Development framework (`ExperimentalSkill` -> candidate -> validation -> approval) and Adaptive Planning (`CapabilityGap` -> candidate/discovery), strictly enforcing that experimental skills cannot self-approve or self-promote.
- **`cyberclaw/capabilities/registry.py`**: Version-aware registry (`capability@version`), multiple provider prioritization, health assessment, schema contract validation, and execution failure history tracking.
- **`cyberclaw/capabilities/errors.py`**: Structured error hierarchy (`CapabilityLifecycleError`, `CapabilityTrustError`, `CapabilityPermissionError`, `CapabilityCompatibilityError`, `CapabilityGovernanceError`, `CapabilityUnavailableError`).
- **`cyberclaw/case/models.py`**: Enhanced `ExecutionHistoryRecord` with version, provider, lifecycle state, trust state, permission scope, and validation references.
- **Core Governance APIs**:
  - `core.validate_capability(...)`
  - `core.approve_capability(...)`
  - `core.enable_capability(...)`
  - `core.disable_capability(...)`
  - `core.deprecate_capability(...)`
  - `core.retire_capability(...)`
  - `core.grant_capability_trust(...)`
  - `core.revoke_capability_trust(...)`
  - `core.get_capability_health(...)`
  - `core.discover_capabilities_for_gap(...)`
- **Comprehensive Test Suite**:
  - `tests/test_capability_lifecycle.py`: Identity, versioning, transitions, illegal transitions, trust separation, revocation, and governance audit trails.
  - `tests/test_capability_execution_and_health.py`: Multi-provider fallback, provider failure vs capability unavailable, health computation, schema mismatch, and malformed provider results.
  - `tests/test_capability_security_and_governance.py`: Untrusted execution rejection, permission enforcement on trusted capabilities, destructive scope approval gates, and branch registry isolation.
  - `tests/test_capability_self_dev_and_gap_bridge.py`: CapabilityGap discovery recommendations, experimental skill bridge, and rejection of unevaluated or self-approved promotions.
  - `tests/test_capability_e2e_scenario.py`: Section 27 full lifecycle scenario (Gap -> Candidate -> Experiment -> Validation -> Approval -> Registration -> Health -> Execution -> Failure -> Degradation -> Disable -> Revalidation -> Re-enable -> Deprecate -> Retire -> Replay verification).

### Added - Investigation Branching & Counterfactual Analysis v0.1
- **`cyberclaw/branching/models.py`**: `InvestigationBranch`, `BranchStatus`, `BranchJournalEntry`, `BranchComparison`, and `CandidateBranchExperience` models supporting counterfactual exploration without mutating authoritative history.
- **`cyberclaw/branching/engine.py`**: Deterministic `BranchEngine` managing branch creation from verified snapshots, simulated requirements, hypothesis shifts, branch replay, unranked factual branch comparisons, and candidate experience handling.
- **`cyberclaw/branching/lifecycle.py`**: Strict state machine enforcing permissible branch lifecycle transitions (`ACTIVE` -> `COMPLETED`, `ABANDONED`, `REJECTED`, `PROMOTED`, `EXPIRED`).
- **`cyberclaw/branching/validator.py`**: `BranchValidator` enforcing source snapshot cryptographic integrity, branch sequence continuity, legal DFA transitions, and referential validity.
- **`cyberclaw/branching/persistence.py`**: Isolated, atomic directory persistence under `branches/branch_<id>/` and `branches_index.json`.
- **`cyberclaw/branching/errors.py`**: Structured error hierarchy (`BranchError`, `BranchNotFoundError`, `BranchIntegrityError`, `BranchLifecycleError`, `BranchSequenceError`, `BranchExecutionBlockedError`, `BranchPromotionError`).
- **Core Branching APIs**:
  - `core.create_investigation_branch(...)`
  - `core.get_investigation_branch(...)`
  - `core.list_investigation_branches(...)`
  - `core.replay_investigation_branch(...)`
  - `core.compare_investigation_branches(...)`
  - `core.compare_branch_to_snapshot(...)`
  - `core.promote_investigation_branch(...)`
  - `core.validate_branch_history(...)`
- **Comprehensive Test Suite**:
  - `tests/test_branch_lifecycle_and_validation.py`: Snapshot creation, tamper detection, lifecycle enforcement, sequence monotonicity, decision/evidence reference checks, nested lineage, and Core APIs.
  - `tests/test_branch_isolation_and_security.py`: State and authoritative immutability, branch-to-branch isolation, experience quarantine, and execution blocking.
  - `tests/test_branch_replay_and_counterfactuals.py`: Deterministic branch replay, intermediate time-travel, alternative candidate evaluation, and contradiction handling.
  - `tests/test_branch_persistence_and_e2e.py`: Section 23 end-to-end multi-branch lifecycle scenario and atomic persistence/reload verification.
  - `tests/test_branch_coexistence.py`: Domain-agnostic operation across OSINT, Network, and unknown `FutureSatelliteSpecialist`.

### Added - Investigation Replay & Deterministic Time-Travel v0.1
- **`cyberclaw/replay/engine.py`**: Deterministic `ReplayEngine` capable of reconstructing historical state from sequence 0 or from snapshot checkpoints up to sequence $N$ or snapshot $M$.
- **`cyberclaw/replay/models.py`**: `ReconstructedState` and `ReplayReport` models supporting point-in-time entity, evidence, hypothesis, requirement, and decision queries with deterministic SHA-256 state hashing.
- **`cyberclaw/replay/validator.py`**: `HistoryValidator` enforcing strict monotonic journal ordering, snapshot SHA-256 integrity, DFA transition legality, and decision reference consistency.
- **`cyberclaw/replay/errors.py`**: Structured error hierarchy (`ReplayError`, `ReplayIntegrityError`, `ReplaySequenceError`, `CorruptedHistoryError`, `ReplayBoundsError`).
- **Core Time-Travel APIs**:
  - `core.replay_investigation(...)`
  - `core.query_historical_state(...)`
  - `core.explain_case_progression(...)`
  - `core.validate_case_history(...)`
- **Comprehensive Test Suite**:
  - `tests/test_replay_validation.py`: Sequence gap detection, duplicate sequence detection, snapshot tamper detection, impossible transition detection, and missing reference detection.
  - `tests/test_replay_engine.py`: Replay from beginning, replay to sequence N, checkpoint replay, read-only guarantees, bounds validation, and explainable progression.
  - `tests/test_replay_e2e_scenario.py`: Section 20 end-to-end multi-specialist lifecycle replay, contradiction resolution replay, snapshot equivalence, and independent replay determinism.
  - `tests/test_replay_coexistence.py`: Domain-agnostic replay with OSINT, Network, unknown future specialists (`FutureSatelliteSpecialist`), and experience references.

### Added - Long-Horizon Investigation Memory & Case State v0.1
- **`cyberclaw/case/models.py`**: Conceptual separation of Current State, State History, Evidence Registry, Entity Graph, Hypothesis History, Requirement History, Planning History, Execution History, Decision History, Contradiction History, Stopping History, and Experience References.
- **`cyberclaw/case/snapshots.py`**: Tamper-evident point-in-time `InvestigationSnapshot` with SHA-256 digests and `SnapshotDelta` calculation.
- **`cyberclaw/case/journal.py`**: Chronological append-only `CaseJournal` and structured `DecisionRecord` tracking.
- **`cyberclaw/case/manager.py`**: High-level `CaseManager` coordinating snapshots, journals, executions, and workspace persistence.

### Added - Adaptive Investigation Planning v0.1
- **`cyberclaw/planning/models.py`**: `InvestigationPlan`, `RequirementCandidate`, `UncertaintyType`, `InformationValueDimension`, `StoppingCondition`, and `CapabilityGap`.
- **`cyberclaw/planning/rules.py`**: Deterministic rules for entity enrichment, contradiction resolution, and balanced hypothesis testing (support and disconfirmation).
- **`cyberclaw/planning/validator.py`**: `PlanValidator` multi-phase gates (structural, capability, permission, safety).
- **`cyberclaw/planning/engine.py`**: Multi-cycle adaptive planning loop.

### Added - Global Specialist Coordination & Evidence Correlation v0.1
- **`cyberclaw/coordination/`**: Information requirements, capability-based routing, multi-specialist coordination, and failure isolation.
- **`cyberclaw/correlation/`**: Pluggable correlation engine, entity graph derivation, relationship correlation, contradiction detection, and hypothesis evaluation.

### Added - Specialist Self-Development Framework v0.1
- Pattern detection, skill proposals, validation, sandbox experiments, baseline comparison, and human/policy promotion gates.

### Added - CyberClaw Core & OSINT Specialist v0.1
- Deterministic DFA, structured evidence, permissions policy, and workspace isolation.
