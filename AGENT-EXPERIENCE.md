# Agent Engineering Experience Log

This document records verified engineering experiences, architectural lessons, and operational findings accumulated across milestones in the CyberClaw greenfield implementation.

## Milestone: Investigation Branching & Counterfactual Analysis v0.1

### Lesson 5: Clear Separation of Authoritative Truth vs. Counterfactual Hypothesis
- **Observation**: When branches simulate prospective outcomes, there is a temptation to store simulated evidence directly in the authoritative evidence store with a flag, or to allow branch hypotheses to directly update case-level hypothesis confidence.
- **Consequence**: This risks contaminating the authoritative truth baseline, causing downstream correlation, replay, or global experience generation to treat hypothetical possibilities as real historical facts.
- **Resolution**: Implemented strict data quarantine. Investigation branches maintain completely isolated, deep-copied working graphs, private branch journals (`BranchJournalEntry`), and simulated evidence lists. Every branch object is explicitly tagged with `is_counterfactual=True`. Authoritative investigation state remains strictly immutable throughout branch exploration.

### Lesson 6: Deterministic Branch Replay via Composite Journal Sequences
- **Observation**: A branch consists of an authoritative history segment up to a source snapshot, followed by branch-local counterfactual events. Reconstructing a branch at local sequence $N$ requires replaying both layers in sequence.
- **Consequence**: Reconstructing the base state from sequence 0 on every branch operation would be inefficient, while replaying from an unverified branch state could propagate tampered state.
- **Resolution**: `BranchEngine.replay_branch` fast-forwards to the cryptographically verified source snapshot using the existing `ReplayEngine.replay`, creates a deep-copy of the resulting `ReconstructedState`, and applies only branch-local journal entries up to `until_local_sequence`. This achieves microsecond-speed reconstruction while preserving deterministic SHA-256 seal guarantees.

### Lesson 7: Objective Comparison Without Artificial Scoring
- **Observation**: When evaluating alternative branches, there is an urge to implement a heuristic "winning branch" or "intelligence utility" score.
- **Consequence**: Universal scalar scores obscure domain trade-offs (e.g. confirming high-risk hypotheses vs resolving contradictions vs reducing uncertainty) and create biased agent decision paths.
- **Resolution**: `BranchComparison` was architected to produce strictly factual set and state differences: evidence gained/lost, entities discovered, relationship changes, hypothesis confidence shifts, unresolved contradictions, and capability gaps. No universal score or ranking is computed; human or executive policies receive neutral, objective deltas.

### Lesson 8: Workspace Directory Pattern in Gitignore
- **Observation**: An unanchored `workspace/` pattern in `.gitignore` silently ignored the python packages `cyberclaw/workspace/` and `cyberclaw/specialists/osint/workspace/`.
- **Consequence**: Python source files responsible for disk layout and atomic writes were omitted from git tracking.
- **Resolution**: Anchored the ignore pattern to the root directory `/workspace/` so repository code under `cyberclaw/workspace/` is properly captured and version controlled.

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
