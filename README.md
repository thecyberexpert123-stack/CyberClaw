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
│   │   └── registry.py         # SpecialistRegistry
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
├── tests/                      # 52 unit & integration tests covering all requirements
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

## 4. Running the Tests

Install dependencies and run the test suite:

```bash
python3 -m pip install -e ".[dev]" --break-system-packages
python3 -m pytest tests/ -v
```
