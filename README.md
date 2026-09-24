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
├── tests/                      # 99 unit & integration tests covering all requirements
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

## 6. Running the Tests

Install dependencies and run the test suite:

```bash
python3 -m pip install -e ".[dev]" --break-system-packages
python3 -m pytest tests/ -v
```
