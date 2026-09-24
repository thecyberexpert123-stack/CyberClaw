# CyberClaw Core

> **Local autonomy, global coordination.**

CyberClaw is an extensible autonomous cybersecurity investigation platform. **CyberClaw Core** is the domain-agnostic foundation that orchestrates semi-autonomous specialist systems (OSINT, Network, Forensics, Malware Analysis, Threat Intelligence, etc.) through deterministic control, stable contracts, and structured evidence.

---

## 1. Architectural Philosophy

* **Domain-Agnostic Core**: The Core does not contain domain-specific logic, hardcoded tools, or offensive exploit payloads. It understands generic abstractions: `Entity`, `Evidence`, `Source`, `Observation`, `Event`, `Relationship`, `Hypothesis`, `Capability`, `Specialist`, `Workspace`, and `Experience`.
* **Deterministic State Machine (DFA)**: The agent/LLM may reason about intent, but the DFA strictly validates and enforces valid system transitions.
* **Capabilities over Tools**: The Core reasons about capabilities (`Capability`), not raw tools. Capabilities are backed by one or more `CapabilityProvider` implementations.
* **Specialist Boundary**: Specialists are semi-autonomous subsystems interacting with the Core through a contract endpoint (`SpecialistEndpoint`).
* **Evidence-First**: Tools are not the product; structured `Evidence` with full lineage/provenance is.
* **Result vs. Failure Distinction**: `SUCCESS` (with findings), `SUCCESS_EMPTY` (successful execution with zero findings), and `FAILURE` (execution error/dependency failure) are distinct states.
* **Memory vs. Experience**: Working memory stores retained facts; experience records operational actions, conditions, causes, and revisionable lessons.
* **Explicit Authority Boundaries**: Operations are scoped (`REVERSIBLE`, `CONSEQUENTIAL`, `DESTRUCTIVE`) with authorization and approval gates.
* **Persistent Workspace**: Isolated persistent workspaces with atomic writes protect trusted Core code from arbitrary modifications.

---

## 2. Directory Layout

```
CyberClaw/
├── cyberclaw/
│   ├── __init__.py
│   ├── types.py                # Generic models: Entity, Source, Relationship, Hypothesis
│   ├── core.py                 # CyberClawCore orchestrator
│   ├── investigation.py        # Investigation case container
│   ├── coordination/           # Global Multi-Specialist Coordination Layer
│   │   ├── requirements.py     # InformationRequirement (OPEN, ASSIGNED, SATISFIED, SATISFIED_EMPTY, FAILED)
│   │   ├── router.py           # Capability-based RequirementRouter
│   │   └── coordinator.py      # InvestigationCoordinator & orchestration loop
│   ├── correlation/            # Global Evidence Correlation & Graph Engine
│   │   ├── engine.py           # CorrelationEngine
│   │   ├── models.py           # CorrelationProvenance, ContradictionRecord
│   │   └── rules.py            # Generic rules (DNS, Cert, Network Service, Shared Infrastructure)
│   ├── dfa/                    # Deterministic Finite Automaton
│   │   ├── states.py           # CoreState (INITIALIZE, READY, CLASSIFY, INVESTIGATE, VERIFY, RESOLVE, PAUSED, FAILED)
│   │   └── machine.py          # CoreDFA engine with guard validation and rejection
│   ├── capabilities/           # Capabilities and Providers
│   │   ├── capability.py       # Capability model
│   │   ├── provider.py         # CapabilityProvider interface & ExecutionContext
│   │   └── registry.py         # CapabilityRegistry
│   ├── specialists/            # Specialist registration & endpoint contracts
│   │   ├── base.py             # Specialist model
│   │   ├── endpoint.py         # SpecialistEndpoint, SpecialistRequest, SpecialistResponse
│   │   ├── registry.py         # SpecialistRegistry
│   │   ├── network/            # Minimal Network Specialist (interoperability & failure isolation)
│   │   │   └── specialist.py   # NetworkSpecialist (port scan, service probe)
│   │   ├── self_development/  # Self-Development Framework v0.1 (controlled autonomous growth)
│   │   │   ├── maturity.py     # SkillMaturityState (EXPERIMENTAL -> EVALUATED -> PROPOSED -> APPROVED -> TRUSTED)
│   │   │   ├── patterns.py     # PatternDetector & PatternObservation
│   │   │   ├── proposals.py    # SkillProposal
│   │   │   ├── skill.py        # ExperimentalSkill
│   │   │   ├── validation.py   # SkillValidator (structural, safety, architectural)
│   │   │   ├── experiment.py   # ExperimentSandbox & SkillExperiment
│   │   │   ├── evaluation.py   # SkillEvaluator & SkillEvaluation
│   │   │   ├── promotion.py    # PromotionManager, PromotionProposal, ApprovalDecision
│   │   │   └── engine.py       # SpecialistSelfDevelopmentEngine
│   │   └── osint/              # OSINT Specialist v0.1 (autonomous passive intelligence)
│   │       ├── specialist.py   # OSINTSpecialist implementing SpecialistEndpoint & self-development
│   │       ├── investigation.py# OSINTInvestigation & target classification
│   │       ├── dfa/            # Local OSINT DFA (READY -> TARGET_RECEIVED -> CLASSIFY -> PLAN -> COLLECT -> CORRELATE -> VERIFY -> COMPLETE)
│   │       ├── capabilities/   # Domain metadata, DNS, Cert metadata, WHOIS
│   │       ├── providers/      # OSINTProvider & deterministic offline mock providers
│   │       ├── normalizers/    # OSINTNormalizer into structured Evidence
│   │       ├── workflows/      # Repeatable workflows (e.g. DomainTriageWorkflow)
│   │       ├── memory/         # Specialist-local memory and experience store
│   │       └── workspace/      # Specialist-local isolated persistent workspace
│   ├── evidence/               # Structured Evidence
│   │   ├── models.py           # Evidence, Observation, Provenance
│   │   ├── result.py           # ExecutionResult & ExecutionStatus (SUCCESS, SUCCESS_EMPTY, FAILURE)
│   │   └── store.py            # EvidenceStore repository
│   ├── events/                 # Event & Evidence Bus
│   │   ├── event.py            # Event model
│   │   └── bus.py              # EventBus with topic and wildcard routing
│   ├── memory/                 # Memory & Experience
│   │   ├── memory.py           # MemoryStore & MemoryFact
│   │   ├── experience.py       # ExperienceRecord
│   │   └── store.py            # ExperienceStore with 4-step revision protocol
│   ├── permissions/            # Permissions & Policies
│   │   ├── policy.py           # ActionScope, Permission, Role
│   │   └── manager.py          # PermissionManager & audit logging
│   ├── workspace/              # Persistent Workspace
│   │   ├── layout.py           # Standard directory structure (skills, workflows, memory, etc.)
│   │   └── manager.py          # WorkspaceManager (atomic writes & isolation)
│   ├── policy/                 # Policy Engine & Risk-Aware Authorization v0.1
│   │   ├── models.py           # Policy, PolicyRule, PolicyExecutionContext, RiskAssessment, AuthorizationDecision
│   │   ├── errors.py           # PolicyError, AuthorizationDeniedError, ApprovalRequiredError, SupervisionRequiredError
│   │   ├── risk.py             # Deterministic explainable RiskEvaluator & RiskFactor decomposition
│   │   ├── rules.py            # Declarative rule condition matcher & standard baseline rules
│   │   ├── evaluator.py        # Fail-closed PolicyEvaluator with explicit precedence resolution
│   │   ├── registry.py         # Thread-safe versioned PolicyRegistry with branch isolation
│   │   ├── engine.py           # Central PolicyEngine & Case Journal audit coordinator
│   │   └── authorization.py    # Facade interface & re-exports
│   ├── runtime/                # Durable Event-Driven Investigation Runtime v0.1
│   │   ├── models.py           # RuntimeEvent, RuntimeTask, TaskStatus, TaskPriority, RetryPolicy, ExecutionState
│   │   ├── events.py           # RuntimeEventType, EventSequenceTracker, EventFactory
│   │   ├── state.py            # TaskLifecycleDFA (deterministic task state machine)
│   │   ├── idempotency.py      # IdempotencyRegistry & stable task identity hashing
│   │   ├── queue.py            # DurableTaskQueue (priority scheduling, leases, atomic persistence)
│   │   ├── dispatcher.py       # SpecialistDispatcher (domain-neutral contract-based routing)
│   │   ├── executor.py         # RuntimeExecutor (governed execution pipeline)
│   │   ├── scheduler.py        # RuntimeScheduler (case serialization locks, pause/resume gating)
│   │   ├── recovery.py         # RuntimeRecoveryManager (crash reconciliation across claim & execution stages)
│   │   ├── persistence.py      # RuntimePersistenceManager (atomic state serialization)
│   │   └── errors.py           # Explicit failure taxonomy & exception hierarchy
│   ├── collaboration/          # Multi-Specialist Collaboration & Evidence Consensus v0.1
│   │   ├── models.py           # CollaborationRequest, CollaborationResult, ConflictStatus, ConsensusStatus, Sensitivity
│   │   ├── protocol.py         # CollaborationLifecycleDFA & least-privilege ContextFilter
│   │   ├── dependencies.py     # CollaborationDependencyGraph, cycle detection, hard/soft readiness gating
│   │   ├── routing.py          # CollaborationRouter evaluating health, workload, capabilities, and requirements
│   │   ├── evidence.py         # EvidenceHandoffNormalizer, epistemic classification (6 finding natures), provenance lineage
│   │   ├── conflicts.py        # ConflictDetector, ConflictManager, and SpecialistConflict lifecycle
│   │   ├── consensus.py        # Explainable ConsensusEngine, source independence, and hypothesis synthesis
│   │   ├── coordinator.py      # Central CollaborationCoordinator integrating Runtime, Policy, and Case state
│   │   ├── persistence.py      # CollaborationPersistenceManager (atomic workspace persistence)
│   │   └── errors.py           # Structured failure taxonomy & exception hierarchy
│   ├── knowledge/              # Temporal Evidence & Knowledge Graph v0.1
│   │   ├── models.py           # Diagnostic models, NodeType, RelationshipType, KnowledgeGap
│   │   ├── nodes.py            # KnowledgeNode immutable container and deterministic SHA-256 digest
│   │   ├── edges.py            # KnowledgeEdge immutable relationship, epistemic nature, confidence, status
│   │   ├── temporal.py         # TemporalInterval, temporal validity window, contradiction classification
│   │   ├── provenance.py       # ProvenanceRecord, recursive backward lineage tracing, source independence
│   │   ├── graph.py            # TemporalKnowledgeGraph multi-index, SHA-256 graph digest, integrity verification
│   │   ├── queries.py          # Current/Historical views, query filtering, planning gaps, explanations
│   │   ├── traversal.py        # GraphTraversalEngine bounded multi-hop traversal with cycle protection
│   │   ├── mutations.py        # Governed GraphMutationRequest/Pipeline with PolicyEngine authorization
│   │   ├── materialization.py  # Deterministic state materialization from authoritative CaseState/Investigation
│   │   ├── consistency.py      # KnowledgeConsistencyEngine (contradictions, gaps, dangling refs, cycles)
│   │   ├── persistence.py      # KnowledgePersistenceManager atomic serialization & integrity reload
│   │   └── errors.py           # Structured Knowledge Graph exception taxonomy
│   ├── learning/               # Cross-Case Experience & Investigation Strategy Learning v0.1
│   │   ├── models.py           # Experience, pattern, strategy, evaluation, and ledger models
│   │   ├── extraction.py       # Read-only InvestigationExperience extraction
│   │   ├── normalization.py    # Comparable features that retain source record IDs
│   │   ├── clustering.py       # Source-family union-find; prevents sample inflation
│   │   ├── patterns.py         # Exact-signature PatternDetector; correlation, not causation
│   │   ├── confidence.py       # Qualitative confidence bands with explicit dimensions
│   │   ├── strategies.py       # Structured InvestigationStrategy intents and lifecycle
│   │   ├── applicability.py    # Versioned structured-Jaccard applicability matching
│   │   ├── simulation.py       # Counterfactual simulation without provider execution
│   │   ├── evaluation.py       # Multidimensional evaluation and regression detection
│   │   ├── proposals.py        # Ingest/propose loop; never self-approves
│   │   ├── governance.py       # External approval, policy precheck, publication gates
│   │   ├── registry.py         # Versioned registry, ledger, and event-sourced replay
│   │   ├── persistence.py      # Atomic learning/registry.json with digest verification
│   │   └── errors.py           # Learning exception taxonomy
│   ├── validation/             # Multi-phase Validation Pipeline
│   │   ├── errors.py           # Schema, Policy, State, and Result validation errors
│   │   └── pipeline.py         # ValidationPipeline
│   └── observability/          # Structured Observability
│       └── logger.py           # StructuredLogger & ObservabilityRecord
├── tests/                      # 387 unit & integration tests covering all requirements
└── pyproject.toml
```

---

## 3. Core Lifecycle (Definition of Done)

CyberClaw Core v0.1 implements and verifies the complete lifecycle:

```
Core Startup
    ↓
Investigation Created
    ↓
DFA State Established (INITIALIZE -> READY)
    ↓
Specialist Registered
    ↓
Capability Available
    ↓
Request Validated (State, Schema, Permissions)
    ↓
Specialist Invoked
    ↓
Result Produced (Distinguishing Findings, Empty, Failure)
    ↓
Evidence Structured (Provenance preserved)
    ↓
Event / Evidence Propagated (EventBus)
    ↓
DFA Updated (INVESTIGATE -> VERIFY -> RESOLVE)
    ↓
Experience Recorded (Condition-Cause lessons)
    ↓
State Persisted (Atomic workspace persistence)
    ↓
Tests Pass
```

---

## 4. OSINT Specialist v0.1

The OSINT Specialist is the first semi-autonomous specialist operating behind the `SpecialistEndpoint` contract:

* **Local Autonomy**: Maintains its own local DFA (`OSINTDFA`), local investigation state, target classifier (`classify_target`), local memory, and isolated workspace (`workspace/specialists/osint/`).
* **Safe, Non-Offensive Capabilities**:
  * `osint.domain_metadata`: Registrar, status, nameservers, registration dates.
  * `osint.dns_lookup`: A, AAAA, MX, TXT, and NS resource records.
  * `osint.cert_metadata`: Subject alternative names (SANs), issuer, certificate validity.
  * `osint.whois_lookup`: Registrant country, organization, admin contact.
* **Workflows & Skills**:
  * `DomainTriageWorkflow` (`osint.workflow:domain_triage`): Multi-step passive reconnaissance correlating domain targets into relationships (`resolves_to_ip`, `delegated_to_nameserver`).
* **Deterministic Providers**:
  * Prioritized provider resolution with readiness evaluation (`is_ready`) and automatic operational fallback.
  * Strict distinction between `SUCCESS`, `SUCCESS_EMPTY`, and `FAILURE`.
* **Zero Core Pollution**: Core contains zero OSINT-specific imports or conditionals, validated by multi-specialist coexistence tests with Network Specialist.

---

## 5. Specialist Self-Development Framework v0.1

The Specialist Self-Development Framework provides controlled, auditable, and safe self-evolution for semi-autonomous specialists:

* **Principle**: *Freedom of creation ≠ freedom of deployment.* AI proposes, validation verifies, policy decides.
* **Maturity Lifecycle**:
  ```text
  EXPERIMENTAL ──→ EVALUATED ──→ PROPOSED ──→ APPROVED ──→ TRUSTED
  ```
  * Direct transitions from generated to trusted are strictly prohibited.
  * Attempting to self-promote without explicit external approval raises `UnauthorizedPromotionError`.
* **Controlled Pipeline**:
  1. **Pattern Detection**: `PatternDetector` identifies recurring successes or failures across experiences (`PatternObservation`).
  2. **Proposal**: `SkillProposal` generated with expected benefits, assumptions, and required capabilities.
  3. **Validation**: `SkillValidator` enforces structural integrity, authority boundary checks, and architectural non-bypass.
  4. **Sandbox Experimentation**: `ExperimentSandbox` runs candidate skills alongside baselines without mutating trusted state.
  5. **Baseline Comparison**: `SkillEvaluator` calculates deltas (evidence yield, duration, failure rates) and produces formal `SkillEvaluation`.
  6. **Promotion & Approval**: `PromotionManager` requires explicit external policy/human `ApprovalDecision` before moving to `APPROVED`.
  7. **Deployment**: Approved skills are promoted to `TRUSTED` in the specialist's catalog and registered with Core.
* **Security Boundaries**:
  * Candidate skills cannot modify Core source code, DFA transition authority, or permission policies.
  * Candidate skills cannot escalate permissions or self-promote.
  * Isolated workspace trees protect production assets from experimental artifacts.

---

## 6. Global Coordination & Evidence Correlation v0.1

The Global Coordination and Evidence Correlation layer enables multiple autonomous specialists (OSINT, Network, Forensics, etc.) to investigate jointly while keeping Core completely domain-agnostic:

* **Information Requirements (`InformationRequirement`)**:
  * Represents *what information is needed* rather than raw tool commands (e.g. `Need DNS info for target X`, `Need network context for IP Y`).
  * Lifecycle: `OPEN` ──→ `ASSIGNED` ──→ `SATISFIED` | `SATISFIED_EMPTY` | `FAILED`.
  * `SATISFIED_EMPTY` indicates normal completion with zero findings (strictly distinct from `FAILED`).
* **Capability-Based Routing (`RequirementRouter`)**:
  * Resolves information requirements against registered healthy specialists and capability declarations deterministically without hardcoded specialist names in Core.
* **Correlation Engine (`CorrelationEngine`)**:
  * **Entity Extraction**: Automatically identifies and tracks entities (`domain`, `ip`, `certificate`, `service`).
  * **Observed vs. Inferred Distinction**:
    * **Observed** (`is_inferred = False`): Direct findings from evidence (e.g. Domain ──`resolves_to`──> IP, IP ──`exposes_service`──> Port).
    * **Inferred** (`is_inferred = True`): Synergies derived across disparate evidence (e.g. distinct domains co-hosted on shared infrastructure).
  * **Correlation Provenance**: Every derived relationship references its supporting evidence IDs, generating rule, and timestamps.
* **Contradiction Management**:
  * Conflicting evidence (e.g. divergent resolutions from competing sources) is captured as `ContradictionRecord` without deleting historical observations.
* **Hypotheses (`Hypothesis`)**:
  * Working propositions evaluated against accumulated evidence (`OPEN` ──→ `SUPPORTED` | `CONTRADICTED`).
* **Failure Isolation**:
  * A specialist failure (e.g. Network host unreachable) does not corrupt global investigation state or affect other specialists.

---

## 7. Adaptive Investigation Planning v0.1

The Adaptive Investigation Planning subsystem enables CyberClaw to autonomously reason about *"What information should be sought next?"* via deterministic, auditable planning cycles without becoming an uncontrolled agent:

* **Separation of Architectural Roles**:
  * **Planner**: *"What information might be useful next?"* (Proposes structured `InvestigationPlan` containing `RequirementCandidate`s).
  * **Coordinator / Validator**: *"Is that request valid and authorized?"* (Validates candidates structurally, against capabilities, and permissions).
  * **Router**: *"Which Specialist can satisfy it?"* (Matches requirement to eligible specialists).
  * **Specialist**: *"How do I accomplish it?"* (Executes workflows, coordinates providers).
  * **Provider**: *"How do I technically execute this capability?"* (Executes low-level tool/API calls).
* **The Planning Loop**:
  ```text
  Evidence ──→ Correlation ──→ State ──→ Uncertainty/Gaps ──→ Planning ──→ Validation ──→ Execution ──→ Replanning
  ```
* **Structured Uncertainty & Value Models**:
  * **`UncertaintyType`**: `UNKNOWN`, `AMBIGUOUS`, `UNCONFIRMED`, `CONTRADICTED`, `INCOMPLETE`, `STALE`.
  * **`InformationValueDimension`**: `HYPOTHESIS_SUPPORT`, `HYPOTHESIS_DISCONFIRMATION`, `CONTRADICTION_RESOLUTION`, `ENTITY_ENRICHMENT`, `MISSING_EVIDENCE`, `CORROBORATION`.
  * **Balanced Hypothesis Testing**: Proposes both confirming *and* disconfirming candidates to prevent confirmation bias.
* **Deterministic Planning Rules (`PlanningRule`)**:
  * **`EntityEnrichmentPlanningRule`**: Proposes network and context enrichment for newly discovered IPs and domains.
  * **`ContradictionResolutionPlanningRule`**: Proposes targeted verification (e.g., authoritative registry lookups) to adjudicate contradictory observations.
  * **`HypothesisTestingPlanningRule`**: Formulates balanced verification needs for open investigative hypotheses.
  * **Deduplication & Failure Awareness**: Prevents re-planning already satisfied or failed requirements.
* **Multi-Stage Plan Validation (`PlanValidator`)**:
  * Enforces structural integrity, checks capability existence, validates permission boundaries (e.g. destructive actions blocked), and rejects forbidden command injection patterns.
* **Controlled Stopping Conditions**:
  * Halts cleanly on `OBJECTIVE_SATISFIED`, `NO_ACTIONABLE_INFORMATION_GAPS`, `NO_AUTHORIZED_CAPABILITIES`, `UNRESOLVED_CRITICAL_CONTRADICTION`, or `MAX_CYCLES_REACHED`.
* **`CapabilityGap`**:
  * Formally records unmet intelligence needs when no capable specialist is registered, creating a direct architectural bridge to Specialist Self-Development.

---

## 8. Long-Horizon Investigation Memory & Case State v0.1

The Long-Horizon Investigation Memory & Case State layer enables CyberClaw to maintain an explainable, auditable, and reproducible investigation across multiple planning and execution cycles:

* **Distinct Conceptual Partitions**:
  CyberClaw strictly distinguishes case-local state, sequential histories, and cross-case global experiences:
  ```text
  Case
  ├── Current Investigation State   (DFA state, current active graph, hypotheses)
  ├── State History                 (Chronological DFA transitions with context)
  ├── Evidence Registry             (Catalog of all ingested structured findings)
  ├── Entity / Relationship Graph   (Observed and inferred topological entities)
  ├── Hypothesis History            (Lifecycle of hypothesis status & confidence)
  ├── Requirement History           (Requirements lifecycle and execution linkage)
  ├── Planning History              (Formal InvestigationPlan artifacts)
  ├── Execution History             (Specialist execution logs, durations, status)
  ├── Decision History              (Explicit rationale for all deliberate choices)
  ├── Contradiction History         (Recorded and resolved conflicting evidence)
  ├── Stopping History              (Encountered halting criteria)
  └── Experience References         (Links to global cross-case ExperienceRecords)
  ```
* **Durable Sealed Snapshots (`InvestigationSnapshot`)**:
  * Frozen point-in-time state answering: *"What did CyberClaw know at this point?"*
  * Monotonically sequenced (`sequence: 1, 2, 3...`) with trigger labels.
  * Tamper-evident: Every snapshot computes a deterministic SHA-256 state digest (`seal()` and `verify_integrity()`). Any external file modification breaks cryptographic verification.
  * Deep copy preservation guarantees that subsequent mutations in the live investigation do not alter historic snapshots.
* **Explainable Delta Comparison (`SnapshotDelta`)**:
  * `compare_snapshots(seq_a, seq_b)` computes precise deltas:
    * Newly added evidence IDs.
    * Newly discovered entities and relationships.
    * Shift in hypothesis confidence and status (`OPEN` ──→ `SUPPORTED`).
    * Requirement transitions (`OPEN` ──→ `SATISFIED`).
    * Discovery or adjudication of contradictions.
    * DFA state transitions.
* **Structured Decision Trail (`DecisionRecord`)**:
  * Explicitly preserves the *why*:
    * `PLANNING_SELECTION` / `PLANNING_REJECTION`
    * `HYPOTHESIS_TRANSITION`
    * `REQUIREMENT_RESOLUTION`
    * `STATE_TRANSITION`
    * `STOPPING_CRITERIA`
* **Chronological Case Journal (`CaseJournal`)**:
  * Linear append-only audit timeline of all events, decisions, and milestones.
* **Workspace Persistence**:
  * Automatically persisted by `WorkspaceManager` into isolated directories:
    * `snapshots/`: individual JSON snapshots (`snapshot_0001.json`, ...) and index.
    * `journal/`: `journal.json` and `decisions.json`.
    * `case_state.json`: full assembled case structure.

---

## 9. Investigation Replay & Deterministic Time-Travel v0.1

The Investigation Replay and Deterministic Time-Travel subsystem enables CyberClaw to audit, reconstruct, and analyze past investigation state with mathematical determinism without re-executing tools or altering live investigation posture:

* **Snapshot vs. Replay Distinction**:
  * **`InvestigationSnapshot`**: A static, persisted point-in-time state artifact.
  * **`ReplayEngine`**: A dynamic, deterministic reconstruction process. Replay consumes ordered historical records (`JournalEntry`, `DecisionRecord`, `Evidence`) and applies state transitions sequentially from sequence 0 or fast-forwards from a validated snapshot checkpoint.
* **Deterministic Reconstruction**:
  * Pure data transformation: Independent repeated replays over identical historical records produce logically identical reconstructed states with identical cryptographic SHA-256 digests (`state_digest`).
  * Free from wall-clock dependencies, live network calls, active provider readiness, or live tool execution.
* **Historical Immutability & Read-Only Guarantees**:
  * Replay operates on deep copies and NEVER mutates the live `Investigation`, `CaseState`, snapshots, journal, or global `ExperienceStore`.
  * Security boundary: Replay is strictly data processing; historical commands/strings are never executed.
* **Decision Replay Semantics**:
  * Decisions are reconstructed as historical facts directly from `DecisionRecord` objects. The system never re-invokes contemporary planning or evaluation rules to guess what occurred historically.
  * Version isolation: Cases generated under planner version X remain replayable even after planner version Y is released.
* **Journal Validation & Corruption Handling**:
  * `HistoryValidator` validates sequence continuity prior to reconstruction:
    * Sequence gaps or duplicate sequence numbers raise `ReplaySequenceError`.
    * Tampered snapshots (SHA-256 hash mismatch) raise `ReplayIntegrityError`.
    * Impossible state transitions or broken references raise `CorruptedHistoryError`.
    * Out-of-bounds target sequence requests raise `ReplayBoundsError`.
    * Corrupted history is rejected immediately; it is never silently repaired or fabricated.
* **Time-Travel Query APIs**:
  * `core.replay_investigation(investigation_id, until_sequence=N, from_snapshot=K, until_snapshot=M)`
  * `core.query_historical_state(investigation_id, sequence=N)`: Inspects exact state (DFA, evidence, entities, hypotheses, requirements, decisions, contradictions) at sequence $N$.
  * `core.explain_case_progression(investigation_id, from_sequence=A, to_sequence=B)`: Provides human-readable chronological trace of events and state deltas between two sequence milestones.

---

## 10. Investigation Branching & Counterfactual Analysis v0.1

The Investigation Branching and Counterfactual Analysis subsystem allows CyberClaw to explore alternative investigative paths, simulate requirement outcomes, and perform comparative "what-if" analyses **without altering authoritative case history**:

> **CORE PRINCIPLE: COUNTERFACTUAL RESULTS ARE NOT HISTORICAL FACTS.**
> The authoritative case records what actually happened. A branch represents a derived investigative context. A counterfactual is an analytical exploration, not fact. No branch may silently become reality.

* **Authoritative vs. Derived State**:
  * **Authoritative History**: Strictly immutable. Authoritative snapshots, case journals, decision records, empirical evidence, requirements, hypotheses, and global `ExperienceStore` cannot be rewritten or modified by branch exploration.
  * **InvestigationBranch (`cyberclaw/branching/models.py`)**: An isolated derived context originating from a cryptographically sealed historical snapshot (`source_snapshot_sequence`). Contains branch-local private journals (`BranchJournalEntry`), simulated evidence, hypotheses, and requirements.
* **Branch Lineage**:
  * Rooted at a verified snapshot checkpoint (`source_snapshot_id`). Supports child/nested branch lineages (`parent_branch_id`).
* **Counterfactual Semantics & No Unauthorized Execution**:
  * Exploration operates purely over data structures, historical records, and deterministic simulation.
  * Security boundary: Branches **never execute real tools, network operations, shell commands, or external APIs**. Actions are evaluated as hypothetical state shifts.
* **Deterministic Branch Replay**:
  * Branch histories can be replayed from the source snapshot through branch journal events up to local sequence $N$.
  * Determinism guarantee: Repeated replay of a branch yields an identical `ReconstructedState` with matching cryptographic digest.
* **Factual, Unranked Branch Comparison (`BranchComparison`)**:
  * `compare_branches(branch_a, branch_b)` computes precise set differences: evidence gained/lost, entities discovered, relationships mapped, hypothesis shifts, contradictions resolved, requirements satisfied, and capability gaps.
  * Zero subjective scoring or ranking: branches are presented with factual differences without declaring a universal "winner".
* **Promotion Boundary (Explicit Promotion vs Merging)**:
  * Unrestricted automatic branch merging is prohibited.
  * A branch can be marked `PROMOTED` via explicit validation, recording an authoritative `DecisionRecord` (e.g. `PLANNING_SELECTION`) for human or executive consideration, without directly mutating authoritative case evidence or DFA state.
* **Experience & Self-Development Boundaries**:
  * Branch observations are quarantined as `CandidateBranchExperience` (`is_counterfactual=True`).
  * Branch experiences can never enter the global `ExperienceStore` or trigger autonomous self-development/capability promotion without explicit audit and validation.
* **Workspace Persistence**:
  * Persisted safely in workspace subdirectories: `branches/branch_<id>/{metadata.json, journal.json, state.json, decisions.json}` with atomic writes and a global `branches/branches_index.json`.

---

## 11. Capability Lifecycle & Governance v0.1

The Capability Lifecycle & Governance layer formalizes the operational lifecycle, decoupled trust tiers, provenance, and authority boundaries of capabilities across CyberClaw:

> **CORE PRINCIPLES OF CAPABILITY GOVERNANCE:**  
> 1. **CAPABILITY EXISTENCE ≠ CAPABILITY AUTHORITY**: A capability being registered does NOT mean it is authorized to execute.  
> 2. **EXPERIMENTAL SUCCESS ≠ TRUST**: A skill succeeding in an experiment does NOT grant it production trust.  
> 3. **REGISTRATION ≠ EXECUTION AUTHORIZATION**: Execution requires passing DFA state checks, schema validation, actor permissions, and action scopes.  
> 4. **TRUST ≠ UNLIMITED PERMISSION**: Even a `FULLY_TRUSTED` capability must strictly adhere to permission policy and action scopes (`REVERSIBLE`, `CONSEQUENTIAL`, `DESTRUCTIVE`).

* **Stable Identity & Versioning**:
  * Capabilities possess explicit semantic versioning (`capability.network.service_probe@1.0.0` vs `@2.0.0`).
  * Historical case records preserve the exact capability version invoked, ensuring deterministic historical replay remains unaffected by future capability updates.
* **Deterministic Lifecycle States**:
  * `PROPOSED` ──► `EXPERIMENTAL` ──► `VALIDATED` ──► `AVAILABLE` ──► `TRUSTED` ──► `DEPRECATED` ──► `RETIRED`.
  * Operational control transitions: `AVAILABLE` ◄──► `DISABLED`, `DISABLED` ──► `RETIRED`.
  * Terminal failure states: `REJECTED`, `RETIRED`. Illegal lifecycle jumps raise `CapabilityLifecycleError`.
* **Decoupled Trust Model**:
  * Trust is distinct from availability: `UNTRUSTED`, `PROVISIONAL`, `TRUSTED_WITH_SCOPE`, `FULLY_TRUSTED`, `REVOKED`.
  * Capabilities in `UNTRUSTED` or `REVOKED` state cannot be executed in production.
* **Capability Provenance**:
  * Explicit origin tracking: `CORE_REGISTERED`, `SPECIALIST_REGISTERED`, `EXPERIMENTAL_SKILL`, `PROMOTED_SKILL`, `ADMIN_REGISTERED`, `FUTURE_EXTERNAL_SOURCE`.
* **Validation & Governance Records**:
  * `CapabilityValidationRecord`: Durable audit of formal test assessments, verification scopes, and results (`PASSED`, `FAILED`, `CONDITIONAL`).
  * `CapabilityGovernanceRecord`: Immutable audit trail of every lifecycle transition, trust assignment, and administrative rationale.
* **Provider Multi-Tenancy & Health Assessment**:
  * A single capability can be backed by multiple providers with descending priorities.
  * Health states: `HEALTHY`, `DEGRADED`, `UNAVAILABLE`, `UNKNOWN`. Provider outages degrade health without destroying capability trust.
* **Self-Development & Planning Gap Bridge**:
  * `CapabilityBridge`:
    * Translates `CapabilityGap` into `CapabilityCandidate` for discovery and planning.
    * Converts evaluated `ExperimentalSkill` into `CapabilityCandidate`.
    * **No Self-Approval**: Experimental skills CANNOT self-promote or self-approve directly into trusted capabilities. Validation verifies; explicit human or policy authority decides.

---

## 12. Policy Engine & Risk-Aware Authorization v0.1

The Policy Engine formalizes contextual authorization as an independent subsystem, completely decoupled from capability existence or raw trust declarations:

> **CORE GOVERNANCE PRINCIPLES:**
> 1. **CAPABILITY EXISTENCE ≠ CAPABILITY AUTHORITY**: A capability declaring what it can do does NOT mean it is authorized to execute in this context.
> 2. **CAPABILITY TRUST ≠ EXECUTION AUTHORIZATION**: Trust is an origin tier; authorization is an operational decision.
> 3. **TRUST ≠ UNLIMITED PERMISSION**: Even fully trusted capabilities are bound by strict action scopes and actor roles.
> 4. **PERMISSION ≠ POLICY AUTHORIZATION**: Having a permission grant is necessary but not sufficient; policy evaluates real-time investigation risk and stage constraints.
> 5. **POLICY AUTHORIZATION ≠ EXECUTION GUARANTEE**: An approved action must still pass DFA transition gates, schema checks, and provider health checks.
> 6. **EXECUTION ≠ SUCCESS**: An authorized, dispatched execution may still produce an empty or failed outcome.

> *"The capability declares what it can do. The policy engine decides whether it may do it here. The validation pipeline verifies that decision. The DFA controls whether execution is legally possible. The case journal records why it happened."*

### Contextual Authorization Pipeline
Execution requests proceed through a strict unidirectional sequence:
```
Investigation Context
    ↓
Requested Action
    ↓
Capability + Version + Provider
    ↓
Capability Lifecycle / Trust Check (is_executable)
    ↓
Contextual Policy Evaluation (PolicyEngine)
    ↓
Deterministic Risk Assessment (RiskEvaluator)
    ↓
Actor / Role Authorization Check
    ↓
Action Scope Authorization Gate
    ↓
DFA / Schema / Permission Validation Pipeline
    ↓
Execution Decision & Journal Audit Trail
```

### Key Subsystems & Semantics
* **Fail-Closed Semantics**:
  * Unknown policies, missing context, unrecognized roles, unverified providers, or unhandled risk dimensions evaluate to `DENY` or `DEFER`.
* **Explicit Precedence & Conflict Resolution**:
  * Rules evaluate strictly deterministically by priority. Conflicting outcomes are reconciled via categorical precedence:
    $$\text{DENY} > \text{REQUIRE\_APPROVAL} > \text{REQUIRE\_SUPERVISION} > \text{DEFER} > \text{ALLOW}$$
* **Explainable Risk Decomposition (`RiskEvaluator`)**:
  * Zero opaque scoring or stochastic LLM evaluation.
  * Evaluates action scope, capability lifecycle state, trust tier, investigation DFA state, principal role, branch isolation, and parameter risk.
  * Yields categorical `RiskLevel` (`LOW`, `MODERATE`, `HIGH`, `CRITICAL`, `UNKNOWN`), a normalized weighted score $[0.0 - 1.0]$, and human-readable constituent `RiskFactor` explanations.
* **Versioned Policy Registry (`PolicyRegistry`)**:
  * Policies are immutable once registered. Supports explicit version targeting (`policy_id@version`).
  * Isolated, read-only policy snapshots protect counterfactual branches from modifying authoritative root governance.
* **Human / Lead Approval & Supervision Workflows**:
  * `REQUIRE_APPROVAL`: High-risk or destructive actions halt until an authorized human or lead investigator submits an explicit approval token (`request_approval`).
  * `REQUIRE_SUPERVISION`: Consequential actions by analysts require operational supervision acknowledgment (`acknowledge_supervision`).
* **Tamper-Evident Audit Trail**:
  * Every authorization request, risk assessment, and decision outcome is recorded in the immutable Case Journal (`AUTHORIZATION_REQUESTED`, `RISK_ASSESSED`, `AUTHORIZATION_GRANTED`, `AUTHORIZATION_DENIED`, `APPROVAL_REQUESTED`, `AUTHORIZATION_DEFERRED`) and execution history records.

---

## 13. Durable Event-Driven Investigation Runtime v0.1

CyberClaw's investigation workflows execute as resumable, observable, event-driven state transitions rather than relying primarily on synchronous orchestration loops.

### Runtime Axioms
1. **`EVENT ≠ EXECUTION`**: An event signifies that something occurred or is requested; it never grants permission or implies execution.
2. **`QUEUED ≠ AUTHORIZED`**: Putting work in a durable queue does not mean the work is approved.
3. **`AUTHORIZED ≠ EXECUTED`**: Policy and validation approval does not imply specialist or provider execution took place.
4. **`EXECUTED ≠ SUCCEEDED`**: A specialist returning an outcome does not mean it produced valid evidence or succeeded.
5. **`RETRY ≠ RE-EXECUTE UNSAFELY`**: Retries must re-enter the validation and authorization pipeline; destructive actions are strictly barred from automatic retry.
6. **`REPLAY ≠ RE-RUN`**: Time-travel replay reads historical facts to reconstruct state; it never creates tasks, invokes providers, or requests authorization.
7. **`DURABILITY ≠ PERMISSION`**: Persisting a task or queue state does not elevate trust or bypass security checks.
8. **`CONCURRENCY ≠ AUTHORITY`**: Parallel workers cannot race past serialization locks or mutate authoritative case sequences out-of-order.

> *"AN EVENT REQUESTS WORK. THE RUNTIME VALIDATES THE WORK. THE DFA AUTHORIZES THE TRANSITION. POLICY AUTHORIZES THE ACTION. A SPECIALIST PERFORMS THE WORK. THE RESULT BECOMES AN EVENT. THE CASE RECORD MAKES IT DURABLE."*

### Key Subsystems & Guarantees
* **Deterministic Task Lifecycle DFA (`TaskLifecycleDFA`)**:
  * Enforces state progression: `CREATED -> QUEUED -> VALIDATING -> AUTHORIZED -> DISPATCHED -> RUNNING -> COMPLETED`.
  * Governed alternate branches: `DEFERRED`, `REJECTED`, `CANCELLED`, `FAILED`, `TIMED_OUT`, `RETRY_PENDING`.
  * Arbitrary or backward state jumps are strictly rejected with `StateTransitionError`.
* **Durable Priority Task Queue (`DurableTaskQueue`)**:
  * Monotonically ordered multi-priority dequeue (`CRITICAL > HIGH > NORMAL > LOW`).
  * Time-bounded worker leases with automatic lease expiration and reclaim.
  * Thread-safe double-claim protection.
  * Atomic persistence to workspace layout (`runtime/queue.json`).
* **Idempotency & Duplicate Protection (`IdempotencyRegistry`)**:
  * Stable deterministic hashing of investigation ID, capability identity, version, requirement ID, and canonical parameters.
  * Separates event deduplication from authorization deduplication and execution deduplication.
  * Completed executions reconcile directly without re-invoking providers.
* **Governed Execution Pipeline (`RuntimeExecutor`)**:
  * Verifies capability lifecycle state (`AVAILABLE`, `TRUSTED`) and trust state (`TRUSTED_WITH_SCOPE`, `FULLY_TRUSTED`).
  * Evaluates contextual policy rules via `PolicyEngine` (`DENY`, `REQUIRE_APPROVAL`, `REQUIRE_SUPERVISION`, `DEFER`, `ALLOW`).
  * Validates request through `ValidationPipeline` (schema, permissions, case DFA state).
  * Dispatches to specialist endpoint or capability provider without domain-specific conditionals (`if osint`, `if network`).
  * Enforces strict result schema validation, ingests evidence, logs case journal entries, and registers lessons into `ExperienceStore`.
* **Process-Restart Crash Recovery (`RuntimeRecoveryManager`)**:
  * Unstarted claimed tasks return to `QUEUED` (`requeued_unstarted`).
  * Finished tasks unacknowledged before crash are reconciled via idempotency records and acknowledged (`reconciled_completed`).
  * Interrupted consequential tasks are flagged `UNKNOWN_EXECUTION_STATE` to prevent dangerous duplicate executions (`flagged_unknown`).
  * Interrupted reversible tasks are safely retried according to policy (`retried_reversible`).
* **Case-Level Serialization & Flow Control (`RuntimeScheduler`)**:
  * Investigation-level locks prevent concurrent state mutation race conditions.
  * Explicit investigation pause/resume controls halt queue processing during human triage or maintenance (`PauseViolationError`).
  * Counterfactual branches strictly block real provider execution (`BranchExecutionBlockedError`).

---

## 14. Multi-Specialist Collaboration & Evidence Consensus v0.1

CyberClaw supports structured, peer-to-peer and coordinated collaboration between semi-autonomous Specialist Brains without bypassing Core governance, mutating authoritative state directly, granting self-permissions, silently overwriting findings, or treating disagreement as failure.

### Core Collaboration Axioms
1. **`SPECIALIST AUTONOMY ≠ SPECIALIST AUTHORITY`**: Specialists reason and propose independently; only the Core authorizes and records mutations.
2. **`MESSAGE ≠ EXECUTION`**: Passing a structured collaboration message does not constitute permission or capability execution.
3. **`REQUEST ≠ PERMISSION`**: Asking assistance from another specialist never bypasses the PolicyEngine or capability trust tier.
4. **`EVIDENCE ≠ TRUTH`**: Evidence represents captured or inferred facts; corroboration is required before hypotheses become supported.
5. **`CORROBORATION ≠ PROOF`**: Independent corroboration increases epistemic confidence; it does not eliminate uncertainty.
6. **`DISAGREEMENT ≠ FAILURE`**: Competing specialist claims are preserved as explicit conflicts rather than silently discarded or overwritten.
7. **`CORRELATION ≠ FACT`**: Correlated indicators suggest relationships requiring targeted empirical observation.
8. **`INFERENCE ≠ OBSERVATION`**: Inferences receive epistemic discounting and can never be disguised as empirical observations.
9. **`SPECIALIST RESULT ≠ AUTHORITATIVE CASE MUTATION`**: Specialist findings must be normalized, evaluated for conflicts, and reviewed before case hypothesis updates.

> *"THE SPECIALIST PROPOSES. THE COORDINATOR VALIDATES. THE GRAPH GATES READINESS. THE POLICY ENGINE AUTHORIZES. THE RUNTIME ORCHESTRATES. THE SPECIALIST EXECUTES. THE NORMALIZER CLASSIFIES. THE CONFLICT DETECTOR PRESERVES DIVERGENCE. THE CONSENSUS ENGINE WEIGHS INDEPENDENCE. THE CASE JOURNAL MAKES IT IMMUTABLE."*

### Key Subsystems & Architectural Guarantees
* **Deterministic Collaboration Lifecycle DFA (`CollaborationLifecycleDFA`)**:
  * Formal lifecycle progression: `PROPOSED -> VALIDATING -> AUTHORIZED -> ROUTED -> ACCEPTED -> IN_PROGRESS -> RESULT_RECEIVED -> EVALUATED -> COMPLETED`.
  * Governed alternate terminal/gating states: `REJECTED`, `DEFERRED`, `CANCELLED`, `FAILED`, `EXPIRED`, `BLOCKED`.
  * Arbitrary or illegal state transitions raise `CollaborationStateTransitionError`.
* **Explicit Dependency DAG & Cycle Detection (`CollaborationDependencyGraph`)**:
  * Models explicit dependency edges: `depends_on`, `blocks`, `unblocks`, `derived_from`, `corroborates`, `contradicts`.
  * Self-referential and multi-hop cycles are detected via DFS and rejected with `DependencyCycleError`.
  * Hard dependencies enforce strict readiness gating (`is_blocked`); soft dependencies allow execution to proceed under an explicit uncertainty marker.
* **Domain-Neutral Collaboration Routing (`CollaborationRouter`)**:
  * Evaluates health status (`HEALTHY`, `DEGRADED`, `UNHEALTHY`), capability availability, workload capacity, and requirement specifications.
  * Disqualifies unhealthy, overloaded, or missing-capability specialists with auditable explanations.
* **Epistemic Classification & Lineage Preservation (`EvidenceHandoffNormalizer`)**:
  * Strictly categorizes findings into 6 epistemic natures: `OBSERVATION`, `INFERENCE`, `CORRELATION`, `HYPOTHESIS`, `NEGATIVE_FINDING`, and `FAILURE`.
  * Inferences are never converted into observations; direct empirical observations are distinguished from deductive conclusions.
  * Full provenance metadata is preserved: `specialist_id`, `capability_id`, `capability_version`, `authorization_decision_id`, `derived_from_evidence_ids`, and originating request links.
* **Specialist Conflict Detection & Lifecycle (`ConflictDetector`, `ConflictManager`)**:
  * Automatically detects contradictory claims on shared investigative subjects.
  * Preserves both competing claims without overwriting (Evidence Immutability strictly enforced).
  * Conflict lifecycle: `OPEN -> UNDER_REVIEW -> CORROBORATING -> RESOLVED` or `PERSISTENT` / `ABANDONED`.
* **Explainable Consensus Engine (`ConsensusEngine`)**:
  * Evaluates evidence corroboration, contradiction, temporal relevance, and source independence.
  * Identifies shared upstream feeds or derivative inference chains and rejects artificial consensus.
  * Generates explainable, auditable consensus assessments (`ConsensusAssessment`) with human-readable rationale and status (`CORROBORATED`, `CONTESTED`, `INCONCLUSIVE`, `UNVERIFIED`).
* **Specialist Isolation & Context Filtering (`ContextFilter`)**:
  * Least-privilege information sharing container (`CollaborationContext`) partitioned across 4 sensitivity tiers (`PUBLIC`, `INTERNAL`, `RESTRICTED`, `SENSITIVE`).
  * Unauthorized context access is blocked with `UnauthorizedContextAccessError`.
* **Workspace Persistence & Deterministic Recovery (`CollaborationPersistenceManager`)**:
  * Atomic state serialization to `collaboration/state.json`.
  * Automatic state restoration on core restart.
* **Replay & Counterfactual Branch Quarantine**:
  * Time-travel replay reconstructs collaboration history without re-invoking specialists or providers.
  * Counterfactual branches represent simulation hypotheses and are strictly blocked from real provider dispatch or authoritative state pollution (`BranchExecutionBlockedError`).

---

## 15. Temporal Evidence & Knowledge Graph v0.1

CyberClaw integrates a domain-neutral, provenance-preserving, temporal knowledge graph that sits between raw evidence production and investigation reasoning. The graph maintains an immutable history of entities, empirical evidence, analytical hypotheses, and governed relationships across investigative time.

### Core Architectural Axioms
1. **`ENTITY ≠ EVIDENCE`**: An entity (e.g. host, domain, account) is a conceptual subject; evidence is a captured artifact or observation about that subject.
2. **`RELATIONSHIP ≠ EVIDENCE`**: A relationship is an asserted connection between nodes; evidence is the factual basis that supports or refutes that connection.
3. **`OBSERVATION ≠ INFERENCE`**: Direct sensor readings and observations must never be conflated with derived inferences or hypotheses.
4. **`INFERENCE ≠ FACT`**: Analytical conclusions retain lower epistemic confidence and carry mandatory premise lineage.
5. **`CORRELATION ≠ CAUSATION`**: Statistical co-occurrence or temporal proximity does not establish a causal dependency.
6. **`CURRENT STATE ≠ HISTORICAL STATE`**: Queries can inspect the graph as it currently exists or as it existed at any historical point in time or event sequence.
7. **`GRAPH EDGE ≠ PROOF`**: Graph edges represent probabilistic or evidentiary links, not undeniable factual proof.
8. **`GRAPH STRUCTURE ≠ AUTHORITY`**: The graph reflects knowledge state; authoritative case decisions reside in the Case Journal.
9. **`DERIVED KNOWLEDGE MUST RETAIN LINEAGE`**: Any node or edge produced from upstream premises must maintain backward lineage to root evidence.
10. **`REMOVING EVIDENCE MUST NOT SILENTLY ERASE HISTORY`**: Superseded or refuted evidence marks edges as revoked, superseded, or refuting without destroying historical records.
11. **`AUTHORITATIVE CASE STATE REMAINS THE SOURCE OF CASE TRUTH`**: The graph materializes deterministically from authoritative case history.
12. **`REPLAY MUST RECONSTRUCT THE GRAPH AS IT EXISTED AT THAT POINT IN TIME`**: Historical replay produces bit-for-bit identical cryptographic digests.
13. **`BRANCH GRAPH STATE MUST NEVER LEAK INTO AUTHORITATIVE GRAPH STATE`**: Counterfactual branch nodes and edges (`is_counterfactual=True`) are isolated.
14. **`SPECIALISTS MAY PROPOSE GRAPH CHANGES; CORE GOVERNANCE AUTHORIZES THEM`**: Specialist mutations flow through the governed mutation pipeline.
15. **`NO GRAPH INFERENCE MAY BE TREATED AS AN OBSERVATION`**: Epistemic classifications are preserved without upward elevation.

### Architectural Subsystems
* **Domain-Neutral Node & Edge Ontology (`models.py`, `nodes.py`, `edges.py`)**:
  * Generic `NodeType` taxonomy: `ENTITY`, `EVIDENCE`, `HYPOTHESIS`, `INVESTIGATION`, `SPECIALIST`, `CAPABILITY`, `CASE`, `SOURCE`, `OBSERVATION`, `ARTIFACT`, `REQUIREMENT`.
  * Generic `RelationshipType` taxonomy: `ASSOCIATED_WITH`, `DERIVED_FROM`, `SUPPORTS`, `CONTRADICTS`, `CORROBORATES`, `DEPENDS_ON`, `OBSERVED_BY`, `GENERATED_BY`, `PART_OF`, `SAME_AS`, `RELATED_TO`.
  * Deterministic SHA-256 integrity digest for all nodes and edges.
* **Temporal Semantics & Contradictions (`temporal.py`)**:
  * Temporal validity windows (`valid_from`, `valid_until`) with interval overlap and containment tests.
  * Explicit conflict classification: `DIRECT_CONTRADICTION`, `TEMPORAL_SUPERSEDENCE`, `SOURCE_DISAGREEMENT`, `PROBABILISTIC_TENSION`.
* **Lineage & Source Independence (`provenance.py`)**:
  * Backward lineage tracing across multi-hop derivation chains to extract root evidence and source references.
  * Source independence verification detecting shared upstream sources and preventing circular corroboration.
* **Governed Mutations & Integrity (`mutations.py`, `graph.py`)**:
  * `GraphMutationPipeline` evaluating schema validity, PolicyEngine authorization, and journal auditing before mutation application.
  * Graph-level SHA-256 digest calculated deterministically independent of node/edge insertion order.
* **Current vs. Historical Views (`queries.py`)**:
  * `CurrentKnowledgeView` querying active elements at the current time horizon.
  * `HistoricalKnowledgeView` filtering elements valid at specific historical timestamps or sequence points.
* **Bounded Traversal & Explanation API (`traversal.py`, `queries.py`)**:
  * BFS/DFS path traversal with depth bounds, node type filtering, and strict cycle protection.
  * Structured explanations (`explain_node`, `explain_edge`, `explain_hypothesis_graph`) exposing supporting vs. refuting evidence, confidence, and source independence.
* **Adaptive Planning & Consistency Engine (`consistency.py`, `queries.py`)**:
  * Automated detection of `KnowledgeGap` records (unsupported hypotheses, uncorroborated inferences, conflicting findings, isolated entities).
  * Knowledge consistency checks flagging cycles, dangling references, and unresolved contradictions.
* **Workspace Persistence & Replay Determinism (`persistence.py`, `replay/engine.py`)**:
  * Atomic serialization to `knowledge/graph.json` with hash verification on reload.
  * Full replay reconstruction matching live graph digests exactly.

---

## 16. Cross-Case Experience & Investigation Strategy Learning v0.1

CyberClaw can learn structured investigative patterns from completed investigations and propose improved strategies without becoming an uncontrolled self-modifying agent. Learning remembers what happened. It does not become authority by itself.

```text
Completed Cases
      ↓
Experience Extraction
      ↓
Normalization
      ↓
Pattern Detection
      ↓
Pattern Validation
      ↓
Strategy Proposal
      ↓
Counterfactual Simulation
      ↓
Evaluation
      ↓
Approval
      ↓
Strategy Registry
      ↓
Adaptive Planner
      ↓
Runtime
      ↓
New Investigation
      ↓
Experience
```

### Learning Axioms
Experience is not truth. Correlation is not causation. Repeated success is not a guarantee. A pattern is not a strategy. A strategy is not execution. A proposal is not approval. Approval is not trust. Trust is not unlimited authority. Simulation is not real execution. A counterfactual result is not a historical result. Specialist or case-local experience does not automatically become global knowledge. A learning failure must not mutate authoritative case state. No learned pattern may bypass policy, capability governance, or runtime. No learned strategy may execute itself.

### Experience, Patterns, and Strategies
* **Extraction (`extraction.py`)**: `InvestigationExperience` is reconstructed from CaseState, the Case Journal, execution history, evidence, requirements, hypotheses, contradictions, and knowledge-journal references. Absent facts stay absent. Every experience keeps authoritative record IDs rather than replacing them with an untraceable copy.
* **Normalization (`normalization.py`)**: action, requirement, specialist, capability, evidence-yield, contradiction, planning, collaboration, duration, and failure/retry features are comparable, but each feature retains the source investigation, source record IDs, normalization version `0.1.0`, and source timestamp.
* **Source independence (`clustering.py`)**: experiences that share a declared template, feed, experiment, or upstream source are one `SourceFamily`. Sample count and independent-family count are reported separately. This uses the same source-lineage idea as knowledge provenance.
* **Pattern detection (`patterns.py`)**: algorithm `signature_equality_v0.1` groups exact canonical signatures. Supported kinds include repeated success, repeated failure, contradiction resolution, requirement sequence, collaboration, capability sequence, evidence yield, planning adaptation, recovery, and stopping. The detector reports counts. It does not conclude that a strategy always works.
* **Confidence (`confidence.py`)**: support is a qualitative band (`INSUFFICIENT`, `WEAK`, `MODERATE`, `STRONG`) explained from sample count, independent cases, independent source families, successes, failures, contradictions, and the active threshold policy. There is no single score treated as objective truth, and registry order is never an opaque preference.
* **Strategy (`strategies.py`)**: an `InvestigationStrategy` is versioned structured intent. Steps name what to try, including contradiction-resolution and authorized capability requests. They are not Python, shell, or provider invocations. `executable` is always false.

### Lifecycle, Applicability, and Governance
```text
PROPOSED → SIMULATED → EVALUATED → REVIEWED → APPROVED → AVAILABLE → DEPRECATED → RETIRED
```
Alternative terminal or holding states are `REJECTED`, `DISABLED`, and `QUARANTINED`. `PROPOSED` cannot jump to `APPROVED` or `AVAILABLE`.

Promotion is explicit:
```text
single case                         → case-local experience
below independence floor            → not a global pattern
independent validated pattern       → strategy proposal
external approval                   → APPROVED
policy-prechecked publication       → AVAILABLE
```
The architectural floor is 2 independent investigations and 2 independent source families. Threshold policy may raise that floor. It may not lower it. The active policy id and version are stored on every pattern and regression signal.

`ApplicabilityProfile` states applicable contexts, exclusions, required capabilities, required permissions, and known failure conditions. Matching uses `structured_jaccard_v0.1` with published weights. Missing capabilities, missing permissions, and information-gap mismatch are hard exclusions. Similarity is not assumed generalization and is not objective truth.

`StrategyApprovalDecision` is externally generated. The learning engine and the proposer cannot approve the strategy. Decisions are `APPROVE`, `REJECT`, `REQUEST_MORE_EVIDENCE`, and `DEFER`. Publication additionally requires an isolated PolicyEngine precheck. Learning does not modify policies, permissions, capability trust, DFA definitions, or Core code.

### Simulation, Evaluation, and Regression
`StrategySimulator` compares a strategy with historical experiences and counterfactual branches. It answers whether the structural preconditions for a gap, fewer steps, extra contradictions, missing capabilities, or an authorization boundary were present. Answers are labeled counterfactual and carry `causal_claim=NONE`. The simulator does not execute providers, grant capabilities, mutate CaseState, or write decisions into the live PolicyEngine.

`StrategyEvaluation` reports information gain, requirement resolution, evidence quality, contradiction resolution, unnecessary actions, execution cost, latency, failure rate, authorization complexity, specialist dependency, and recovery independently. Comparisons list trade-offs and do not declare a winner.

`StrategyRegressionDetector` can recommend review, deprecation, or disabling when governed thresholds are crossed. It does not delete historical usage and does not apply the lifecycle change itself. An external actor must review it. Deprecated strategies remain queryable as historical versions.

### Planner, Runtime, Replay, Branching, and Knowledge
The Adaptive Planner can request candidates through `request_strategy_candidates`. Candidates include strategy id and version, applicability explanation, supporting cases, independent case count, known failures, required capabilities and permissions, risk factors, evaluation history, and policy precheck. The planner does not execute them. Runtime remains the only execution substrate.

Replay reconstructs learning state from the learning ledger. `replay_learning_state`, `get_strategy_history`, `get_pattern_history`, and `explain_strategy_origin` do not re-run today's detector, today's evaluator, or today's thresholds, and they do not execute anything.

Branch strategy evaluations are `CandidateBranchExperience` records with `is_counterfactual=True`. They are quarantined and do not become authoritative experience.

Learned relationships are projected onto a separate learning knowledge graph, not into a case graph. Mapping uses existing edge types plus `metadata.learning_relation`: `SUPPORTED_BY`, `OBSERVED_IN`, `GENERATED`, `FAILED_IN`, and `APPLICABLE_TO`. Those edges are inferences, not observations.

Persistence writes `learning/registry.json` atomically and refuses to load a digest mismatch.

### Security Boundaries
A learned strategy is structured data. The package rejects `eval`, `exec`, imports, shell commands, and similar executable fragments. It does not generate code, deploy code, escalate privilege, change policy, change capability trust, open hidden specialist channels, or call providers.

### Known Limitations
v0.1 does not implement reinforcement learning, model fine-tuning, neural strategy generation, embeddings, online training, external ML services, automatic approval, automatic trust escalation, automatic policy or capability changes, or cross-installation learning. Pattern identity is exact and versioned. Similar workflows corroborate only when their canonical signature matches; a recovered retry collapses consecutive duplicate capability calls but does not fuzzy-match unrelated sequences.

---

## 17. Running the Tests

Install dependencies and run the test suite:

```bash
python3 -m pip install -e ".[dev]" --break-system-packages
python3 -m pytest tests/ -v
```
