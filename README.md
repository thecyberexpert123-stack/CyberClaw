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
│   ├── validation/             # Multi-phase Validation Pipeline
│   │   ├── errors.py           # Schema, Policy, State, and Result validation errors
│   │   └── pipeline.py         # ValidationPipeline
│   └── observability/          # Structured Observability
│       └── logger.py           # StructuredLogger & ObservabilityRecord
├── tests/                      # 116 unit & integration tests covering all requirements
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

## 12. Running the Tests

Install dependencies and run the test suite:

```bash
python3 -m pip install -e ".[dev]" --break-system-packages
python3 -m pytest tests/ -v
```
