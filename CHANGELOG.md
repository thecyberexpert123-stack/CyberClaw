# Changelog

All notable changes to CyberClaw are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.0] - 2026-09-24

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
