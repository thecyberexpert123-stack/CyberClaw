"""Deterministic Replay Engine reconstructing historical investigation states without execution."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Union
from cyberclaw.case.models import (
    CaseState,
    DecisionRecord,
    DecisionType,
    InvestigationSnapshot,
    JournalEntry,
    JournalEntryType,
    SnapshotDelta,
    utc_now,
)
from cyberclaw.coordination.requirements import InformationRequirement, RequirementStatus
from cyberclaw.correlation.models import ContradictionRecord
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.investigation import Investigation
from cyberclaw.planning.models import InvestigationPlan, StoppingCondition
from cyberclaw.replay.errors import (
    CorruptedHistoryError,
    ReplayBoundsError,
    ReplayIntegrityError,
    ReplaySequenceError,
)
from cyberclaw.replay.models import ReconstructedState, ReplayReport
from cyberclaw.replay.validator import HistoryValidator
from cyberclaw.types import Entity, Hypothesis, Relationship, normalize_entity_index, remember_entity


class ReplayEngine:
    """Pure, deterministic state reconstruction engine operating strictly on historical records."""

    @classmethod
    def validate_case_history(
        cls,
        entries: List[JournalEntry],
        snapshots: List[InvestigationSnapshot],
        decisions: List[DecisionRecord],
    ) -> None:
        """Run all structural, sequence, and cryptographic integrity checks on case history."""
        HistoryValidator.validate_all(entries, snapshots, decisions)

    @classmethod
    def replay(
        cls,
        case_data: Union[CaseState, Investigation],
        until_sequence: Optional[int] = None,
        from_snapshot: Optional[Union[int, str]] = None,
        until_snapshot: Optional[Union[int, str]] = None,
    ) -> ReconstructedState:
        """Deterministically reconstruct historical state up to a specified journal sequence or snapshot."""
        # Extract collections
        if isinstance(case_data, Investigation):
            cs = case_data.get_case_state()
            all_evidence = case_data.evidence_store.list_all()
        else:
            cs = case_data
            all_evidence = []

        investigation_id = cs.investigation_id
        journal = sorted(cs.journal, key=lambda e: e.sequence)
        snapshots = sorted(cs.snapshots, key=lambda s: s.sequence)
        decisions = sorted(cs.decision_history, key=lambda d: d.sequence)
        all_plans = list(cs.planning_history)
        all_requirements = list(cs.requirements.values())
        all_hypotheses = list(cs.hypotheses.values())
        all_entities = list(cs.entities.values())
        all_contradictions = list(cs.contradictions)

        # 1. Validate History
        cls.validate_case_history(journal, snapshots, decisions)

        total_journal_entries = len(journal)
        max_seq = total_journal_entries

        # Determine target sequence
        if until_snapshot is not None:
            target_snap = None
            if isinstance(until_snapshot, int):
                target_snap = next((s for s in snapshots if s.sequence == until_snapshot), None)
            else:
                target_snap = next((s for s in snapshots if s.snapshot_id == until_snapshot), None)

            if not target_snap:
                raise CorruptedHistoryError(f"Target snapshot '{until_snapshot}' not found.")

            match_entry = next((e for e in journal if e.snapshot_id == target_snap.snapshot_id), None)
            if match_entry:
                target_seq = match_entry.sequence
            else:
                entries_before = [e for e in journal if e.timestamp <= target_snap.timestamp]
                target_seq = entries_before[-1].sequence if entries_before else 0

        elif until_sequence is not None:
            if until_sequence < 0:
                raise ReplayBoundsError(f"Target sequence cannot be negative: {until_sequence}")
            if until_sequence > max_seq:
                raise ReplayBoundsError(
                    f"Requested sequence {until_sequence} exceeds max journal sequence {max_seq}"
                )
            target_seq = until_sequence
        else:
            target_seq = max_seq

        # 2. Checkpoint Selection (Snapshot vs Sequence 0)
        start_journal_idx = 0
        source_checkpoint_seq = None

        if from_snapshot is not None:
            # Locate snapshot
            snap_match = None
            if isinstance(from_snapshot, int):
                snap_match = next((s for s in snapshots if s.sequence == from_snapshot), None)
            else:
                snap_match = next((s for s in snapshots if s.snapshot_id == from_snapshot), None)

            if not snap_match:
                raise CorruptedHistoryError(f"Snapshot checkpoint '{from_snapshot}' not found.")

            # Cryptographic verification
            if not snap_match.verify_integrity():
                raise ReplayIntegrityError(
                    f"Snapshot #{snap_match.sequence} failed SHA-256 integrity verification: cannot use as checkpoint"
                )

            source_checkpoint_seq = snap_match.sequence

            # Seed state directly from validated checkpoint
            dfa_state = snap_match.dfa_state
            evidence = [
                e.model_copy(deep=True)
                for e in all_evidence
                if e.id in snap_match.evidence_ids
            ]
            entities = normalize_entity_index(
                {k: v.model_copy(deep=True) for k, v in snap_match.entities.items()}
            )
            relationships = [r.model_copy(deep=True) for r in snap_match.relationships]
            hypotheses = {k: v.model_copy(deep=True) for k, v in snap_match.hypotheses.items()}
            requirements = {k: v.model_copy(deep=True) for k, v in snap_match.information_requirements.items()}
            contradictions = [c.model_copy(deep=True) for c in snap_match.contradictions]
            stopping_cond = snap_match.stopping_condition
            plans = [p.model_copy(deep=True) for p in all_plans if p.plan_id == snap_match.active_plan_id]
            reconstructed_decisions = [
                d.model_copy(deep=True) for d in decisions if d.timestamp <= snap_match.timestamp
            ]

            # Find corresponding journal index
            snap_journal_entry = next(
                (e for e in journal if e.snapshot_id == snap_match.snapshot_id), None
            )
            if snap_journal_entry:
                start_journal_idx = snap_journal_entry.sequence  # Next index to replay
            else:
                # Search by timestamp
                start_journal_idx = len([e for e in journal if e.timestamp <= snap_match.timestamp])
        else:
            # Baseline from sequence 0
            dfa_state = CoreState.INITIALIZE.value
            evidence = []
            entities = {}
            relationships = []
            hypotheses = {}
            requirements = {}
            contradictions = []
            reconstructed_decisions = []
            plans = []
            stopping_cond = None

        # 3. Sequential Journal Replay
        events_replayed = 0

        for entry in journal[start_journal_idx:]:
            if entry.sequence > target_seq:
                break

            events_replayed += 1
            etype = entry.entry_type

            if etype == JournalEntryType.STATE_TRANSITION:
                to_state = entry.details.get("to")
                if to_state:
                    dfa_state = to_state

            elif etype == JournalEntryType.EVIDENCE_INGESTED:
                eids = entry.details.get("evidence_ids", [])
                if entry.reference_id and entry.reference_id not in eids:
                    eids.append(entry.reference_id)
                for eid in eids:
                    match_ev = next((e for e in all_evidence if e.id == eid), None)
                    if match_ev and not any(e.id == eid for e in evidence):
                        evidence.append(match_ev.model_copy(deep=True))

            elif etype == JournalEntryType.REQUIREMENT_CREATED:
                rid = entry.reference_id
                match_req = next((r for r in all_requirements if r.id == rid), None)
                if match_req:
                    req_copy = match_req.model_copy(deep=True)
                    req_copy.status = RequirementStatus.OPEN
                    requirements[match_req.id] = req_copy

            elif etype == JournalEntryType.REQUIREMENT_EXECUTED:
                rid = entry.reference_id or entry.details.get("requirement_id")
                stat = entry.details.get("status")
                if rid and rid in requirements and stat:
                    try:
                        requirements[rid].status = RequirementStatus(stat)
                    except ValueError:
                        pass
                # Add resulting evidence if present
                for eid in entry.details.get("evidence_ids", []):
                    match_ev = next((e for e in all_evidence if e.id == eid), None)
                    if match_ev and not any(e.id == eid for e in evidence):
                        evidence.append(match_ev.model_copy(deep=True))

            elif etype == JournalEntryType.HYPOTHESIS_EVALUATED:
                hid = entry.reference_id or entry.details.get("hypothesis_id")
                stat = entry.details.get("status")
                conf = entry.details.get("confidence")
                if hid and hid in hypotheses:
                    if stat:
                        hypotheses[hid].status = stat
                    if conf is not None:
                        hypotheses[hid].confidence = float(conf)
                elif hid:
                    match_hyp = next((h for h in all_hypotheses if h.id == hid), None)
                    if match_hyp:
                        hc = match_hyp.model_copy(deep=True)
                        if stat:
                            hc.status = stat
                        if conf is not None:
                            hc.confidence = float(conf)
                        hypotheses[hc.id] = hc

            elif etype == JournalEntryType.CORRELATION_COMPLETED:
                for ent_data in entry.details.get("entities", []):
                    ent = Entity(**ent_data) if isinstance(ent_data, dict) else ent_data
                    remember_entity(entities, ent.model_copy(deep=True))
                for rel_data in entry.details.get("relationships", []):
                    rel = Relationship(**rel_data) if isinstance(rel_data, dict) else rel_data
                    if not any(r.id == rel.id for r in relationships):
                        relationships.append(rel.model_copy(deep=True))

            elif etype == JournalEntryType.ENTITY_ADDED:
                ent_data = entry.details.get("entity")
                if ent_data:
                    ent = Entity(**ent_data) if isinstance(ent_data, dict) else ent_data
                    remember_entity(entities, ent.model_copy(deep=True))

            elif etype == JournalEntryType.RELATIONSHIP_ADDED:
                rel_data = entry.details.get("relationship")
                if rel_data:
                    rel = Relationship(**rel_data) if isinstance(rel_data, dict) else rel_data
                    if not any(r.id == rel.id for r in relationships):
                        relationships.append(rel.model_copy(deep=True))

            elif etype == JournalEntryType.CONTRADICTION_DETECTED:
                c_data = entry.details.get("contradiction")
                if c_data:
                    c = ContradictionRecord(**c_data) if isinstance(c_data, dict) else c_data
                    if not any(x.id == c.id for x in contradictions):
                        contradictions.append(c.model_copy(deep=True))
                elif entry.reference_id:
                    match_c = next((c for c in all_contradictions if c.id == entry.reference_id), None)
                    if match_c and not any(x.id == match_c.id for x in contradictions):
                        contradictions.append(match_c.model_copy(deep=True))

            elif etype == JournalEntryType.DECISION_RECORDED:
                did = entry.reference_id
                match_dec = next((d for d in decisions if d.id == did), None)
                if match_dec and not any(d.id == did for d in reconstructed_decisions):
                    reconstructed_decisions.append(match_dec.model_copy(deep=True))

            elif etype == JournalEntryType.PLAN_GENERATED:
                pid = entry.reference_id
                match_plan = next((p for p in all_plans if p.plan_id == pid), None)
                if match_plan and not any(p.plan_id == pid for p in plans):
                    plans.append(match_plan.model_copy(deep=True))

            elif etype == JournalEntryType.STOPPING_CONDITION:
                stopping_cond = entry.details.get("stopping_condition")

            elif etype == JournalEntryType.SNAPSHOT_CAPTURED:
                # Snapshots are checkpoints; if entities were discovered, ensure they are retained
                pass

        # 4. Synthesize Reconstructed State
        reconstructed = ReconstructedState(
            investigation_id=investigation_id,
            target_sequence=target_seq,
            source_checkpoint_sequence=source_checkpoint_seq,
            dfa_state=dfa_state,
            evidence=evidence,
            entities=entities,
            relationships=relationships,
            hypotheses=hypotheses,
            requirements=requirements,
            contradictions=contradictions,
            decisions=reconstructed_decisions,
            plans=plans,
            stopping_condition=stopping_cond,
            experience_references=list(cs.experience_references),
            events_replayed_count=events_replayed,
        )

        reconstructed.seal()
        return reconstructed

    @classmethod
    def explain_progression(
        cls,
        case_data: Union[CaseState, Investigation],
        from_sequence: int,
        to_sequence: int,
    ) -> ReplayReport:
        """Provide a human-readable explanation tracing the progression from sequence A to sequence B."""
        if from_sequence > to_sequence:
            from_sequence, to_sequence = to_sequence, from_sequence

        recon_start = cls.replay(case_data, until_sequence=from_sequence)
        recon_end = cls.replay(case_data, until_sequence=to_sequence)

        explanation_steps: List[str] = []

        # DFA change
        if recon_start.dfa_state != recon_end.dfa_state:
            explanation_steps.append(
                f"State transitioned from {recon_start.dfa_state} to {recon_end.dfa_state}"
            )

        # Evidence added
        added_ev = len(recon_end.evidence) - len(recon_start.evidence)
        if added_ev > 0:
            explanation_steps.append(f"Ingested {added_ev} new evidence item(s)")

        # Entities added
        added_ent = len(recon_end.entities) - len(recon_start.entities)
        if added_ent > 0:
            explanation_steps.append(f"Discovered {added_ent} new entity/entities")

        # Hypotheses evaluated
        for hid, hend in recon_end.hypotheses.items():
            hstart = recon_start.hypotheses.get(hid)
            if not hstart:
                explanation_steps.append(f"Formulated hypothesis '{hend.statement}' ({hend.status})")
            elif hstart.status != hend.status:
                explanation_steps.append(
                    f"Hypothesis '{hend.statement}' shifted from {hstart.status} to {hend.status} (confidence {hend.confidence:.2f})"
                )

        # Requirements resolved
        for rid, rend in recon_end.requirements.items():
            rstart = recon_start.requirements.get(rid)
            if not rstart:
                explanation_steps.append(f"Created requirement: {rend.description}")
            elif rstart.status != rend.status:
                explanation_steps.append(
                    f"Requirement '{rend.description}' resolved: {rstart.status.value} -> {rend.status.value}"
                )

        # Decisions made
        new_decisions = len(recon_end.decisions) - len(recon_start.decisions)
        if new_decisions > 0:
            explanation_steps.append(f"Recorded {new_decisions} deliberate investigative decision(s)")

        if recon_end.stopping_condition:
            explanation_steps.append(f"Reached stopping condition: {recon_end.stopping_condition}")

        return ReplayReport(
            investigation_id=recon_end.investigation_id,
            from_sequence=from_sequence,
            to_sequence=to_sequence,
            events_replayed=recon_end.events_replayed_count,
            decisions_reconstructed=len(recon_end.decisions),
            final_dfa_state=recon_end.dfa_state,
            explanation_steps=explanation_steps,
            is_valid=True,
            digest=recon_end.state_digest,
        )

    @classmethod
    def replay_knowledge_graph(
        cls,
        case_data: Union[CaseState, Investigation],
        until_sequence: Optional[int] = None,
        until_snapshot: Optional[Union[int, str]] = None,
        until_timestamp: Optional[Any] = None,
    ) -> Any:
        """Deterministically reconstruct historical knowledge graph without executing providers, planners, or policies."""
        import copy
        from cyberclaw.knowledge.materialization import KnowledgeMaterializer
        recon_state = cls.replay(
            case_data,
            until_sequence=until_sequence,
            from_snapshot=until_snapshot,
            until_snapshot=until_snapshot,
        )

        # Build lightweight investigation container holding strictly replayed state
        from cyberclaw.investigation import Investigation
        inv_wrapper = Investigation(
            id=recon_state.investigation_id,
            title=f"Replay Investigation {recon_state.investigation_id}",
        )
        inv_wrapper.hypotheses = copy.deepcopy(recon_state.hypotheses)
        inv_wrapper.contradictions = copy.deepcopy(recon_state.contradictions)
        for ev in recon_state.evidence:
            inv_wrapper.evidence_store.add(ev)

        graph = KnowledgeMaterializer.materialize_from_investigation(inv_wrapper)
        return graph

    @classmethod
    def query_historical_graph(
        cls,
        case_data: Union[CaseState, Investigation],
        timestamp: Any,
        until_sequence: Optional[int] = None,
    ) -> Any:
        """Query historical point-in-time view of knowledge graph."""
        graph = cls.replay_knowledge_graph(case_data, until_sequence=until_sequence)
        return graph.get_historical_view_at_time(timestamp)

    @classmethod
    def compare_graph_states(
        cls,
        graph_a: Any,
        graph_b: Any,
    ) -> Dict[str, Any]:
        """Factual, unranked comparison between two knowledge graph states."""
        nodes_a = set(graph_a._nodes.keys())
        nodes_b = set(graph_b._nodes.keys())
        edges_a = set(graph_a._edges.keys())
        edges_b = set(graph_b._edges.keys())

        return {
            "digest_a": graph_a.calculate_graph_digest(),
            "digest_b": graph_b.calculate_graph_digest(),
            "identical": graph_a.calculate_graph_digest() == graph_b.calculate_graph_digest(),
            "nodes_only_in_a": sorted(nodes_a - nodes_b),
            "nodes_only_in_b": sorted(nodes_b - nodes_a),
            "nodes_shared": sorted(nodes_a & nodes_b),
            "edges_only_in_a": sorted(edges_a - edges_b),
            "edges_only_in_b": sorted(edges_b - edges_a),
            "edges_shared": sorted(edges_a & edges_b),
        }

    @classmethod
    def validate_graph_history(
        cls,
        graph: Any,
        entries: List[JournalEntry],
    ) -> bool:
        """Verify that all nodes and edges in graph maintain cryptographic integrity."""
        return graph.verify_graph_integrity()

    @classmethod
    def replay_learning_state(
        cls,
        events: List[Any],
        until_sequence: Optional[int] = None,
    ) -> Any:
        """Reconstruct historical learning state from recorded events only.

        Does not rediscover patterns, reevaluate strategies, apply today's
        thresholds, consult today's policy, or execute anything.
        """
        from cyberclaw.learning.registry import LearningReplay

        return LearningReplay.replay_learning_state(events, until_sequence=until_sequence)

    @classmethod
    def get_strategy_history(cls, events: List[Any], strategy_id: str) -> List[Any]:
        from cyberclaw.learning.registry import LearningReplay

        return LearningReplay.get_strategy_history(events, strategy_id)

    @classmethod
    def get_pattern_history(cls, events: List[Any], pattern_id: str) -> List[Any]:
        from cyberclaw.learning.registry import LearningReplay

        return LearningReplay.get_pattern_history(events, pattern_id)

    @classmethod
    def explain_strategy_origin(
        cls,
        events: List[Any],
        strategy_id: str,
        version: Optional[str] = None,
    ) -> Any:
        from cyberclaw.learning.registry import LearningReplay

        return LearningReplay.explain_strategy_origin(events, strategy_id, version=version)
