# Agent Engineering Experience Log

This document records verified engineering experiences, architectural lessons, and operational findings accumulated across milestones in the CyberClaw greenfield implementation.

## Milestone: Temporal Evidence & Knowledge Graph v0.1

### Lesson 21: Ontological Disaggregation of Knowledge: Entity ≠ Evidence ≠ Inference
- **Observation**: Graph systems often collapse entities, empirical findings, and analytical assertions into generic nodes with undirected edges or uniform weightings.
- **Consequence**: An inference (e.g., "host is infected with malware") is treated as equivalent in certainty to an empirical observation (e.g., "DNS query logged to domain X"), causing automated planners to treat unverified hypotheses as established ground truth.
- **Resolution**: Enforced strict architectural axioms: `ENTITY ≠ EVIDENCE`, `RELATIONSHIP ≠ EVIDENCE`, `OBSERVATION ≠ INFERENCE`, and `INFERENCE ≠ FACT`. The knowledge graph categorizes nodes into distinct, typed ontological roles (`ENTITY`, `EVIDENCE`, `HYPOTHESIS`, `OBSERVATION`, etc.) and requires all edges to carry an explicit `epistemic_nature` and confidence rating. Inferences require explicit supporting evidence linkages and cannot be elevated into observations without new empirical data collection.

### Lesson 22: Temporal Validity Windows and the Principle of Contradiction Preservation
- **Observation**: Traditional graph databases treat conflicting updates as overwrite operations or merge conflicts, erasing historical facts when an indicator changes (e.g., an IP reassignment or certificate renewal).
- **Consequence**: Reconstructing what the investigation knew at sequence step $N$ becomes impossible because superseded states were overwritten, destroying auditability and time-travel replay.
- **Resolution**: Implemented bi-temporal intervals (`valid_from`, `valid_until`) across all nodes and edges alongside non-destructive contradiction edges (`RelationshipType.CONTRADICTS`). Conflicting findings do not mutate or delete existing edges; instead, an explicit contradiction record is introduced with competing evidence references. Historical queries evaluate validity intervals as of that point in time, enabling both the past state and current dispute to be inspected independently.

### Lesson 23: Cryptographic State Determinism and Journal Replay Sourcing
- **Observation**: Knowledge graphs constructed incrementally across disparate specialist turns can suffer from non-deterministic hash digests due to dictionary ordering, floating-point timestamp drift, or container identity mismatches.
- **Consequence**: Live graphs and replayed graphs generated from the same underlying case history diverge cryptographically, failing deterministic verification during case closeout or peer review.
- **Resolution**: Implemented canonical, sorted JSON stringification for node, edge, and whole-graph SHA-256 digests. Sourced investigation container attributes strictly from replayed state (matching `investigation.id`) and ensured that journal events or snapshot state capture all contradictions and evidence uniformly, achieving identical bit-for-bit digest parity between live materialization and replay reconstruction.

## Milestone: Multi-Specialist Collaboration & Evidence Consensus v0.1

### Lesson 18: Disagreement Preservation Over Winner-Takes-All Overwriting
- **Observation**: Autonomous agent systems often handle conflicting findings between specialist agents by letting the last writer win, choosing the agent with higher static rank, or treating contradiction as a fatal exception.
- **Consequence**: Critical signals (e.g. an endpoint reporting active C2 while another reports a legitimate sinkhole) are lost, resulting in misleading investigations and unexplainable conclusions.
- **Resolution**: Enforced strict collaboration axioms: `DISAGREEMENT ≠ FAILURE` and `SPECIALIST AUTONOMY ≠ SPECIALIST AUTHORITY`. Introduced `SpecialistConflict` records and a formal conflict lifecycle (`OPEN -> UNDER_REVIEW -> CORROBORATING -> RESOLVED`). Competing claims are both retained in the immutable Case Journal, and consensus status defaults to `CONTESTED` until explicit, verifiable resolution evidence is introduced.

### Lesson 19: Source Independence and Rejection of Artificial Consensus
- **Observation**: Multiple agents querying the same upstream data provider or performing derivative inferences on each other's outputs are often counted as "multiple independent corroborations".
- **Consequence**: Artificial consensus emerges where one unverified upstream record is echoed across multiple specialists, falsely inflating hypothesis confidence.
- **Resolution**: Enforced strict source relationship tracking in `ConsensusEngine`. Evidence items sharing identical upstream provider identifiers, marked with `same_source_as`, or formed through derivative inference chains are clustered into a single source dependency group. Only genuinely distinct empirical observations from independent collection methods contribute to corroborated consensus.

### Lesson 20: Epistemic Nature Distinction (Observation vs. Inference)
- **Observation**: Systems routinely flatten deductive conclusions, hypotheses, and empirical probe measurements into generic "evidence" or "findings".
- **Consequence**: Deductive inferences get treated as ground truth facts, causing subsequent planning loops to compound unproven assumptions.
- **Resolution**: Implemented `EvidenceHandoffNormalizer` categorizing findings into 6 explicit epistemic natures: `OBSERVATION`, `INFERENCE`, `CORRELATION`, `HYPOTHESIS`, `NEGATIVE_FINDING`, and `FAILURE`. Inferences receive explicit confidence discounting (weighted at 0.8 relative to empirical observations) and retain upstream premise lineage (`derived_from_evidence_ids`), preventing unverified leaps from masquerading as factual observations.

## Milestone: Durable Event-Driven Investigation Runtime v0.1

### Lesson 15: Ontological Separation of Event, Queue, Authorization, and Execution
- **Observation**: Systems frequently treat event ingestion, work queueing, policy authorization, and specialist execution as a single blurred lifecycle step.
- **Consequence**: Tasks pulled from a queue bypass security checks under the assumption that "if it's in the queue, it's authorized", or duplicate delivery results in dangerous duplicate side-effects.
- **Resolution**: Enforced strict runtime axioms: `EVENT ≠ EXECUTION`, `QUEUED ≠ AUTHORIZED`, `AUTHORIZED ≠ EXECUTED`, and `EXECUTED ≠ SUCCEEDED`. Enqueuing a task merely registers intent; the claimed task must pass formal capability trust verification, PolicyEngine evaluation, and multi-phase schema/permission validation before dispatch. Duplicate events, duplicate authorizations, and duplicate executions are segregated into distinct idempotency registries.

### Lesson 16: Crash Recovery Reconciles Rather Than Blindly Re-Executing
- **Observation**: When worker processes crash mid-investigation, naive queue recovery simply resets all in-flight tasks to `QUEUED` and re-runs them upon restart.
- **Consequence**: Consequential or destructive actions (such as credential revocation, network isolation, or API writes) get executed multiple times, while completed executions whose acknowledgments were lost re-execute needlessly.
- **Resolution**: Implemented `RuntimeRecoveryManager` with stage-aware reconciliation. Unstarted claimed tasks return safely to `QUEUED`. Executions already completed in the idempotency store are acknowledged immediately without provider dispatch. Interrupted consequential operations without confirmed results are flagged `UNKNOWN_EXECUTION_STATE` to prevent dangerous duplicate executions and require human/operator intervention.

### Lesson 17: Case-Level Mutation Serialization Under Asynchronous Work Queues
- **Observation**: While work queues support multi-worker concurrent dequeuing across different investigations, executing multiple tasks concurrently on the same investigation leads to journal sequence interleaving, out-of-order state transitions, and broken cryptographic replay seals.
- **Consequence**: Time-travel replay validator rejects the investigation history because events or DFA transitions appear out of sequence.
- **Resolution**: `RuntimeScheduler` maintains per-investigation serialization locks. Workers can process different investigations concurrently with high throughput, but all mutations within a single investigation case record are strictly serialized, preserving monotonic event sequences, consistent DFA state progressions, and deterministic replay digests.

## Milestone: Policy Engine & Risk-Aware Authorization v0.1

### Lesson 12: Contextual Authorization Independent of Static Trust
- **Observation**: Systems often conflate capability registration and trust tiers with runtime execution permission.
- **Consequence**: A capability that is fully trusted (e.g. system backup cleanup) could be invoked in an inappropriate investigative stage (e.g. while case is closed or reporting) or by an unprivileged role (e.g. read-only auditor).
- **Resolution**: Separated capability trust from contextual authorization. The capability declares what it can do; the Policy Engine contextually decides whether it may execute given the current investigation DFA state, actor role, action scope, parameters, and evaluated risk.

### Lesson 13: Deterministic Explainable Risk Decomposition
- **Observation**: Using opaque LLM-based risk scores or single composite heuristic numbers creates unpredictable authorization decisions that cannot be audited or explained.
- **Consequence**: Security teams cannot deterministically verify why an action was approved or denied, and edge cases fail silently or inconsistently.
- **Resolution**: Implemented `RiskEvaluator` using explicit, weighted, deterministic risk factors across orthogonal dimensions (scope, lifecycle, trust, stage, role, branch containment, parameters). Each factor provides an explicit severity level and human-readable explanation, ensuring fail-closed gates when any critical factor triggers.

### Lesson 14: Categorical Precedence in Conflict Resolution
- **Observation**: When multiple policy rules match an execution context, resolving conflicts via numerical priority alone can lead to accidental overrides where an allow rule unintentionally bypasses safety blocks.
- **Consequence**: Safety invariants (e.g. "never execute destructive actions in branches" or "never allow auditors to mutate") could be bypassed if an allow rule was assigned a lower numerical priority index.
- **Resolution**: Enforced strict categorical precedence: `DENY > REQUIRE_APPROVAL > REQUIRE_SUPERVISION > DEFER > ALLOW`. Regardless of rule evaluation order, a hard denial or approval gate will always override an allow verdict.

## Milestone: Capability Lifecycle & Governance v0.1

### Lesson 9: Decoupling Lifecycle Availability from Trust Tiers
- **Observation**: Systems often treat "registered and enabled" as synonymous with "trusted to execute".
- **Consequence**: An experimental capability under sandbox evaluation or a recently re-enabled tool could be prematurely scheduled for autonomous execution, bypassing organizational trust gates.
- **Resolution**: Separated `CapabilityLifecycleState` (`PROPOSED`, `EXPERIMENTAL`, `VALIDATED`, `AVAILABLE`, `TRUSTED`, `DEPRECATED`, `DISABLED`, `RETIRED`) from `CapabilityTrustState` (`UNTRUSTED`, `PROVISIONAL`, `TRUSTED_WITH_SCOPE`, `FULLY_TRUSTED`, `REVOKED`). Execution strictly requires both an active lifecycle state (`AVAILABLE` or `TRUSTED`) and an approved trust tier (`TRUSTED_WITH_SCOPE` or `FULLY_TRUSTED`).

### Lesson 10: Provider Fault Isolation vs. Capability Operational Status
- **Observation**: Temporary upstream provider outages (e.g. third-party rate limits, network blips) frequently lead to capabilities being permanently marked as broken or invalid.
- **Consequence**: Transient provider unavailability causes unnecessary capability churn and destroys historical provenance.
- **Resolution**: Separated the logical capability definition from its backing providers. Multi-provider priority fallbacks and a distinct `CapabilityHealth` model (`HEALTHY`, `DEGRADED`, `UNAVAILABLE`) ensure that provider outages transition health without altering registered trust or mutating immutable capability governance records.

### Lesson 11: Immutable Version References in Case History
- **Observation**: When capabilities evolve across versions (e.g. `v1.0.0` to `v2.0.0`), subsequent changes to schemas or provider implementations can alter the meaning of historical executions.
- **Consequence**: Deterministic time-travel replay breaks or misinterprets historical findings if execution records only store unversioned capability slugs.
- **Resolution**: `ExecutionHistoryRecord` explicitly stores `capability_id`, `capability_version`, `provider_id`, `lifecycle_state`, `trust_state`, and `action_scope`. Replay consumes these records as immutable historical facts rather than consulting current live registry configurations.

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
