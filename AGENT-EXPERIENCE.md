# Agent Engineering Experience Log

This document records verified engineering experiences, architectural lessons, and operational findings accumulated across milestones in the CyberClaw greenfield implementation.

## Milestone: Investigation Replay & Deterministic Time-Travel v0.1

### Lesson 1: Replay as Pure Reconstruction vs. Speculative Execution
- **Observation**: During replay, there is a risk of re-running original decision logic (e.g. calling planner rules or hypothesis evaluators) rather than reconstructing what historically happened.
- **Consequence**: Re-running contemporary decision logic during replay creates non-deterministic drift when algorithms or rules evolve across versions (e.g. planner version X vs version Y).
- **Resolution**: Replay was implemented strictly as a pure data reconstruction process. It consumes historical `DecisionRecord` and `JournalEntry` artifacts as immutable facts, ensuring exact historical reproduction regardless of future algorithm changes.

### Lesson 2: Entity Keying Uniformity Across Core Subsystems
- **Observation**: When entities were correlated by `CorrelationEngine`, they were originally indexed in `Investigation.entities` by `ent.name` (e.g. `'target.corp'`), whereas `Investigation.add_entity` had used `ent.id`.
- **Consequence**: Divergent dictionary keys created split views in live investigation states and caused snapshot comparisons to fail during replay verification.
- **Resolution**: Standardized entity dictionary keys on `ent.name` across `Investigation.add_entity`, `CorrelationEngine`, and `ReplayEngine`. Deduplication updates existing attributes while preserving canonical identity.

### Lesson 3: Journal Granularity for Checkpoint-Independent Reconstruction
- **Observation**: When an investigation creates requirements or detects contradictions via coordinator methods, failing to immediately append corresponding journal entries prevents sequence 0 replay from reconstructing those elements.
- **Consequence**: Snapshots could store state, but replaying from sequence 0 missed the un-journaled requirement or contradiction.
- **Resolution**: Every state-affecting action (`add_entity`, `add_evidence`, `create_hypothesis`, `create_information_requirement`, `CONTRADICTION_DETECTED`) emits a synchronous `JournalEntry`. This guarantees that replay from sequence 0 and replay from a snapshot checkpoint produce identical reconstructed states.

### Lesson 4: Cryptographic Snapshot Checkpoint Verification
- **Observation**: Using snapshots as checkpoints accelerates replay, but relying on unverified snapshots risks compounding silent corruption.
- **Consequence**: If a snapshot JSON file is modified externally or corrupted on disk, resuming replay from it yields invalid state.
- **Resolution**: `ReplayEngine` cryptographically verifies the SHA-256 state digest (`verify_integrity()`) of the snapshot before seeding the reconstruction. Tampered checkpoints immediately halt replay with `ReplayIntegrityError`.
