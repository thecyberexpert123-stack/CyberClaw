# Changelog

All notable changes to CyberClaw are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-09-24

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
