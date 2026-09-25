"""Deterministic branch engine for creating, simulating, replaying, and comparing investigative branches."""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from uuid import uuid4

from cyberclaw.branching.errors import (
    BranchExecutionBlockedError,
    BranchIntegrityError,
    BranchLifecycleError,
    BranchNotFoundError,
    BranchPromotionError,
    BranchSequenceError,
)
from cyberclaw.branching.lifecycle import transition_branch
from cyberclaw.branching.models import (
    BranchComparison,
    BranchJournalEntry,
    BranchStatus,
    CandidateBranchExperience,
    InvestigationBranch,
)
from cyberclaw.branching.validator import BranchValidator
from cyberclaw.case.models import (
    CaseState,
    ContradictionRecord,
    DecisionRecord,
    DecisionType,
    InvestigationSnapshot,
    JournalEntryType,
    utc_now,
)
from cyberclaw.coordination.requirements import (
    InformationRequirement,
    RequirementStatus,
)
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionStatus
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.planning.models import RequirementCandidate
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.replay.models import ReconstructedState
from cyberclaw.types import Entity, Hypothesis, Relationship, remember_entity


class BranchEngine:
    """Core engine for managing isolated investigation branches and counterfactual state transformations."""

    @classmethod
    def create_branch(
        cls,
        investigation: Union[CaseState, Any],
        source_snapshot: Union[int, str],
        purpose: str,
        originating_decision_id: Optional[str] = None,
        parent_branch_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InvestigationBranch:
        """Create an isolated investigation branch rooted at a cryptographically verified snapshot."""
        # 1. Retrieve snapshots from investigation or CaseState
        if hasattr(investigation, "case_manager"):
            snapshots = investigation.case_manager.snapshots.snapshots
            inv_id = investigation.id
        elif isinstance(investigation, CaseState):
            snapshots = investigation.snapshots
            inv_id = investigation.investigation_id
        else:
            raise TypeError("investigation must be an Investigation instance or CaseState")

        # 2. Locate and validate source snapshot
        target_snap: Optional[InvestigationSnapshot] = None
        if isinstance(source_snapshot, int):
            target_snap = next((s for s in snapshots if s.sequence == source_snapshot), None)
        else:
            target_snap = next((s for s in snapshots if s.snapshot_id == source_snapshot), None)

        if not target_snap:
            raise BranchIntegrityError(
                f"Source snapshot '{source_snapshot}' not found in investigation '{inv_id}'."
            )

        # Cryptographic integrity check
        BranchValidator.validate_source_snapshot(target_snap)

        # 3. Deterministically reconstruct state at source snapshot
        reconstructed = ReplayEngine.replay(
            investigation,
            until_snapshot=target_snap.sequence,
        )

        # 4. Construct isolated branch with deep-copied state
        branch_id = str(uuid4())
        branch = InvestigationBranch(
            branch_id=branch_id,
            investigation_id=inv_id,
            parent_branch_id=parent_branch_id,
            source_snapshot_id=target_snap.snapshot_id,
            source_snapshot_sequence=target_snap.sequence,
            source_sequence=reconstructed.target_sequence,
            purpose=purpose,
            originating_decision_id=originating_decision_id,
            derived_state=reconstructed.model_copy(deep=True),
            entities={k: v.model_copy(deep=True) for k, v in reconstructed.entities.items()},
            relationships=[r.model_copy(deep=True) for r in reconstructed.relationships],
            hypotheses={k: v.model_copy(deep=True) for k, v in reconstructed.hypotheses.items()},
            requirements={k: v.model_copy(deep=True) for k, v in reconstructed.requirements.items()},
            contradictions=[c.model_copy(deep=True) for c in reconstructed.contradictions],
            decisions=[d.model_copy(deep=True) for d in reconstructed.decisions],
            evidence_references=[e.id for e in reconstructed.evidence],
            stopping_condition=reconstructed.stopping_condition,
            metadata=dict(metadata or {}),
            is_counterfactual=True,
        )

        # 5. Initialize branch-local journal with sequence 1
        init_entry = BranchJournalEntry(
            branch_id=branch.branch_id,
            investigation_id=branch.investigation_id,
            originating_snapshot_id=branch.source_snapshot_id,
            originating_snapshot_sequence=branch.source_snapshot_sequence,
            local_sequence=1,
            entry_type=JournalEntryType.INVESTIGATION_CREATED,
            summary=f"Branch '{branch.branch_id}' initialized from Snapshot #{target_snap.sequence} for: {purpose}",
            details={
                "source_snapshot_id": target_snap.snapshot_id,
                "source_snapshot_sequence": target_snap.sequence,
                "purpose": purpose,
                "originating_decision_id": originating_decision_id,
            },
            is_counterfactual=True,
        )
        branch.journal.append(init_entry)

        return branch

    @classmethod
    def apply_simulated_event(
        cls,
        branch: InvestigationBranch,
        entry_type: JournalEntryType,
        summary: str,
        details: Optional[Dict[str, Any]] = None,
        reference_id: Optional[str] = None,
    ) -> BranchJournalEntry:
        """Append a chronological event to the branch's private journal."""
        if branch.status != BranchStatus.ACTIVE:
            raise BranchLifecycleError(
                f"Cannot record events in branch '{branch.branch_id}' with status '{branch.status.value}'.",
                branch_id=branch.branch_id,
            )

        next_seq = len(branch.journal) + 1
        entry = BranchJournalEntry(
            branch_id=branch.branch_id,
            investigation_id=branch.investigation_id,
            originating_snapshot_id=branch.source_snapshot_id,
            originating_snapshot_sequence=branch.source_snapshot_sequence,
            local_sequence=next_seq,
            entry_type=entry_type,
            summary=summary,
            reference_id=reference_id,
            details=details or {},
            is_counterfactual=True,
        )
        branch.journal.append(entry)
        branch.updated_at = utc_now()
        return entry

    @classmethod
    def simulate_dfa_transition(
        cls,
        branch: InvestigationBranch,
        target_state: str,
        event: str,
        reason: str = "",
    ) -> None:
        """Simulate a valid DFA state transition within a branch context."""
        current_state = branch.derived_state.dfa_state if branch.derived_state else "INIT"
        BranchValidator.validate_dfa_transition(current_state, target_state)

        if branch.derived_state:
            branch.derived_state.dfa_state = target_state

        cls.apply_simulated_event(
            branch=branch,
            entry_type=JournalEntryType.STATE_TRANSITION,
            summary=f"Simulated DFA transition: {current_state} -> {target_state} via '{event}'",
            details={"from": current_state, "to": target_state, "event": event, "reason": reason},
        )

    @classmethod
    def simulate_evidence(
        cls,
        branch: InvestigationBranch,
        evidence_items: List[Evidence],
    ) -> None:
        """Incorporate simulated/counterfactual evidence strictly within the branch."""
        for ev in evidence_items:
            # Tag metadata to guarantee provenance
            ev.metadata["counterfactual"] = True
            ev.metadata["branch_id"] = branch.branch_id

            branch.simulated_evidence.append(ev.model_copy(deep=True))
            if ev.id not in branch.evidence_references:
                branch.evidence_references.append(ev.id)

            if branch.derived_state and not any(e.id == ev.id for e in branch.derived_state.evidence):
                branch.derived_state.evidence.append(ev.model_copy(deep=True))

            cls.apply_simulated_event(
                branch=branch,
                entry_type=JournalEntryType.EVIDENCE_INGESTED,
                summary=f"Simulated evidence ingested: {ev.type} on '{ev.subject}'",
                reference_id=ev.id,
                details={"evidence": ev.model_dump(), "is_counterfactual": True},
            )

    @classmethod
    def simulate_entities(
        cls,
        branch: InvestigationBranch,
        entities: List[Entity],
        relationships: Optional[List[Relationship]] = None,
    ) -> None:
        """Incorporate simulated entities and relationships into branch topology."""
        for ent in entities:
            copied = ent.model_copy(deep=True)
            remember_entity(branch.entities, copied)
            if branch.derived_state:
                remember_entity(branch.derived_state.entities, copied.model_copy(deep=True))

            cls.apply_simulated_event(
                branch=branch,
                entry_type=JournalEntryType.ENTITY_ADDED,
                summary=f"Simulated entity added: {ent.type} '{ent.name}'",
                details={"entity": ent.model_dump()},
            )

        if relationships:
            for rel in relationships:
                branch.relationships.append(rel.model_copy(deep=True))
                if branch.derived_state:
                    branch.derived_state.relationships.append(rel.model_copy(deep=True))

                cls.apply_simulated_event(
                    branch=branch,
                    entry_type=JournalEntryType.RELATIONSHIP_ADDED,
                    summary=f"Simulated relationship added: {rel.source_id} -[{rel.type}]-> {rel.target_id}",
                    details={"relationship": rel.model_dump()},
                )

    @classmethod
    def simulate_hypothesis_shift(
        cls,
        branch: InvestigationBranch,
        hypothesis_id: str,
        new_status: str,
        confidence: float,
        reason: str = "",
    ) -> None:
        """Simulate an evaluative update to a hypothesis within the branch."""
        hyp = branch.hypotheses.get(hypothesis_id)
        if not hyp and branch.derived_state:
            hyp = branch.derived_state.hypotheses.get(hypothesis_id)

        if not hyp:
            raise BranchIntegrityError(
                f"Hypothesis '{hypothesis_id}' not found in branch '{branch.branch_id}'.",
                branch_id=branch.branch_id,
            )

        old_status = hyp.status
        old_conf = hyp.confidence
        hyp.status = new_status
        hyp.confidence = max(0.0, min(1.0, confidence))
        branch.hypotheses[hypothesis_id] = hyp

        if branch.derived_state:
            branch.derived_state.hypotheses[hypothesis_id] = hyp.model_copy(deep=True)

        cls.apply_simulated_event(
            branch=branch,
            entry_type=JournalEntryType.HYPOTHESIS_EVALUATED,
            summary=f"Simulated hypothesis '{hypothesis_id}' shift: {old_status} ({old_conf:.2f}) -> {new_status} ({confidence:.2f})",
            reference_id=hypothesis_id,
            details={
                "hypothesis_id": hypothesis_id,
                "old_status": old_status,
                "new_status": new_status,
                "old_confidence": old_conf,
                "new_confidence": confidence,
                "reason": reason,
            },
        )

    @classmethod
    def simulate_requirement_outcome(
        cls,
        branch: InvestigationBranch,
        candidate_or_req: Union[RequirementCandidate, InformationRequirement],
        simulated_evidence: Optional[List[Evidence]] = None,
        simulated_entities: Optional[List[Entity]] = None,
        simulated_relationships: Optional[List[Relationship]] = None,
        hypothesis_shifts: Optional[Dict[str, Tuple[str, float]]] = None,
        status: RequirementStatus = RequirementStatus.SATISFIED,
        error: Optional[str] = None,
    ) -> InformationRequirement:
        """Simulate the resolution of an InformationRequirement without live execution."""
        # Check security boundary: reject real execution invocation
        if hasattr(candidate_or_req, "execute") or hasattr(candidate_or_req, "run"):
            raise BranchExecutionBlockedError(
                "Execution objects are not permitted in counterfactual simulation.",
                branch_id=branch.branch_id,
            )

        # Convert candidate to InformationRequirement if needed
        if isinstance(candidate_or_req, RequirementCandidate):
            req_id = str(uuid4())
            req = InformationRequirement(
                id=req_id,
                investigation_id=branch.investigation_id,
                description=candidate_or_req.purpose,
                evidence_types_sought=candidate_or_req.requested_evidence_types,
                target_or_entity=candidate_or_req.target_or_entity,
                assigned_capability_id=candidate_or_req.required_capability,
                priority=candidate_or_req.priority,
                dependencies=candidate_or_req.dependencies,
                status=RequirementStatus.OPEN,
                metadata={
                    "candidate_id": candidate_or_req.candidate_id,
                    "counterfactual": True,
                },
            )
        else:
            req = candidate_or_req.model_copy(deep=True)

        branch.requirements[req.id] = req
        if branch.derived_state:
            branch.derived_state.requirements[req.id] = req.model_copy(deep=True)

        cls.apply_simulated_event(
            branch=branch,
            entry_type=JournalEntryType.REQUIREMENT_CREATED,
            summary=f"Simulated requirement created: '{req.description}'",
            reference_id=req.id,
            details={"requirement": req.model_dump()},
        )

        # Ingest simulated evidence
        if simulated_evidence:
            cls.simulate_evidence(branch, simulated_evidence)

        # Ingest simulated entities and relationships
        if simulated_entities or simulated_relationships:
            cls.simulate_entities(branch, simulated_entities or [], simulated_relationships or [])

        # Apply hypothesis shifts
        if hypothesis_shifts:
            for hid, (new_stat, new_conf) in hypothesis_shifts.items():
                cls.simulate_hypothesis_shift(branch, hid, new_stat, new_conf, reason=f"Outcome of requirement {req.id}")

        # Update requirement status
        req.status = status
        req.error = error
        branch.requirements[req.id] = req
        if branch.derived_state:
            branch.derived_state.requirements[req.id] = req.model_copy(deep=True)

        cls.apply_simulated_event(
            branch=branch,
            entry_type=JournalEntryType.REQUIREMENT_EXECUTED,
            summary=f"Simulated requirement '{req.id}' resolved: {status.value}",
            reference_id=req.id,
            details={
                "status": status.value,
                "evidence_count": len(simulated_evidence or []),
                "error": error,
            },
        )

        return req

    @classmethod
    def replay_branch(
        cls,
        branch: InvestigationBranch,
        authoritative_case: Union[CaseState, Any],
        until_local_sequence: Optional[int] = None,
    ) -> ReconstructedState:
        """Deterministically reconstruct historical state of a branch up to a local sequence index."""
        # 1. Validate branch private history
        BranchValidator.validate_branch_journal(branch.journal)

        max_seq = len(branch.journal)
        if until_local_sequence is not None:
            if until_local_sequence < 1:
                raise BranchSequenceError(
                    f"Target branch sequence cannot be less than 1: {until_local_sequence}",
                    branch_id=branch.branch_id,
                )
            if until_local_sequence > max_seq:
                raise BranchSequenceError(
                    f"Target branch sequence {until_local_sequence} exceeds max sequence {max_seq}",
                    branch_id=branch.branch_id,
                )
            target_seq = until_local_sequence
        else:
            target_seq = max_seq

        # 2. Reconstruct base state from authoritative source snapshot
        base_state = ReplayEngine.replay(
            authoritative_case,
            until_snapshot=branch.source_snapshot_sequence,
        )

        # 3. Create independent copy to replay branch events
        recon = base_state.model_copy(deep=True)

        # 4. Sequentially process branch journal entries up to target_seq
        active_entries = [e for e in branch.journal if e.local_sequence <= target_seq]
        for entry in active_entries:
            etype = entry.entry_type

            if etype == JournalEntryType.STATE_TRANSITION:
                recon.dfa_state = entry.details.get("to", recon.dfa_state)

            elif etype == JournalEntryType.EVIDENCE_INGESTED:
                ev_data = entry.details.get("evidence")
                if ev_data:
                    ev = Evidence(**ev_data) if isinstance(ev_data, dict) else ev_data
                    if not any(e.id == ev.id for e in recon.evidence):
                        recon.evidence.append(ev.model_copy(deep=True))

            elif etype == JournalEntryType.ENTITY_ADDED:
                ent_data = entry.details.get("entity")
                if ent_data:
                    ent = Entity(**ent_data) if isinstance(ent_data, dict) else ent_data
                    remember_entity(recon.entities, ent.model_copy(deep=True))

            elif etype == JournalEntryType.RELATIONSHIP_ADDED:
                rel_data = entry.details.get("relationship")
                if rel_data:
                    rel = Relationship(**rel_data) if isinstance(rel_data, dict) else rel_data
                    if not any(r.id == rel.id for r in recon.relationships):
                        recon.relationships.append(rel.model_copy(deep=True))

            elif etype == JournalEntryType.CORRELATION_COMPLETED:
                for ent_data in entry.details.get("entities", []):
                    ent = Entity(**ent_data) if isinstance(ent_data, dict) else ent_data
                    remember_entity(recon.entities, ent.model_copy(deep=True))
                for rel_data in entry.details.get("relationships", []):
                    rel = Relationship(**rel_data) if isinstance(rel_data, dict) else rel_data
                    if not any(r.id == rel.id for r in recon.relationships):
                        recon.relationships.append(rel.model_copy(deep=True))

            elif etype == JournalEntryType.HYPOTHESIS_EVALUATED:
                hid = entry.details.get("hypothesis_id")
                new_status = entry.details.get("new_status")
                new_conf = entry.details.get("new_confidence")
                if hid and hid in recon.hypotheses:
                    h = recon.hypotheses[hid]
                    if new_status:
                        h.status = new_status
                    if new_conf is not None:
                        h.confidence = float(new_conf)

            elif etype == JournalEntryType.REQUIREMENT_CREATED:
                req_data = entry.details.get("requirement")
                if req_data:
                    req = InformationRequirement(**req_data) if isinstance(req_data, dict) else req_data
                    recon.requirements[req.id] = req.model_copy(deep=True)

            elif etype == JournalEntryType.REQUIREMENT_EXECUTED:
                rid = entry.reference_id
                if rid and rid in recon.requirements:
                    stat_val = entry.details.get("status")
                    if stat_val:
                        recon.requirements[rid].status = RequirementStatus(stat_val)

            elif etype == JournalEntryType.CONTRADICTION_DETECTED:
                c_data = entry.details.get("contradiction")
                if c_data:
                    c = ContradictionRecord(**c_data) if isinstance(c_data, dict) else c_data
                    if not any(item.id == c.id for item in recon.contradictions):
                        recon.contradictions.append(c.model_copy(deep=True))

            elif etype == JournalEntryType.STOPPING_CONDITION:
                recon.stopping_condition = entry.details.get("stopping_condition")

        # 5. Seal reconstructed state with SHA-256 digest
        recon.events_replayed_count += len(active_entries)
        recon.seal()
        return recon

    @classmethod
    def compare_branches(
        cls,
        branch_a: InvestigationBranch,
        branch_b: InvestigationBranch,
    ) -> BranchComparison:
        """Perform a structured, factual comparison between two branches without scoring or ranking."""
        # Evidence differences
        ev_a = set(branch_a.evidence_references)
        ev_b = set(branch_b.evidence_references)
        ev_diff = {
            "only_in_a": sorted(list(ev_a - ev_b)),
            "only_in_b": sorted(list(ev_b - ev_a)),
            "common": sorted(list(ev_a & ev_b)),
        }

        # Entity differences
        ent_a = set(branch_a.entities.keys())
        ent_b = set(branch_b.entities.keys())
        ent_diff = {
            "only_in_a": sorted(list(ent_a - ent_b)),
            "only_in_b": sorted(list(ent_b - ent_a)),
            "common": sorted(list(ent_a & ent_b)),
        }

        # Relationship differences
        rel_a = {f"{r.source_id}->{r.target_id}:{r.type}" for r in branch_a.relationships}
        rel_b = {f"{r.source_id}->{r.target_id}:{r.type}" for r in branch_b.relationships}
        rel_diff = {
            "only_in_a": sorted(list(rel_a - rel_b)),
            "only_in_b": sorted(list(rel_b - rel_a)),
            "common": sorted(list(rel_a & rel_b)),
        }

        # Hypothesis differences
        all_hyp_ids = sorted(list(set(branch_a.hypotheses.keys()) | set(branch_b.hypotheses.keys())))
        hyp_status_shifts = {}
        hyp_conf_shifts = {}
        for hid in all_hyp_ids:
            ha = branch_a.hypotheses.get(hid)
            hb = branch_b.hypotheses.get(hid)
            st_a = ha.status if ha else "ABSENT"
            st_b = hb.status if hb else "ABSENT"
            cf_a = ha.confidence if ha else 0.0
            cf_b = hb.confidence if hb else 0.0

            if st_a != st_b or abs(cf_a - cf_b) > 1e-4:
                hyp_status_shifts[hid] = {"branch_a": st_a, "branch_b": st_b}
                hyp_conf_shifts[hid] = {"branch_a": cf_a, "branch_b": cf_b}

        # Contradiction differences
        unres_a = [c.id for c in branch_a.contradictions if not c.resolved]
        unres_b = [c.id for c in branch_b.contradictions if not c.resolved]
        res_a = [c.id for c in branch_a.contradictions if c.resolved]
        res_b = [c.id for c in branch_b.contradictions if c.resolved]
        c_diff = {
            "unresolved_in_a": unres_a,
            "unresolved_in_b": unres_b,
            "resolved_in_a": res_a,
            "resolved_in_b": res_b,
        }

        # Requirement differences
        sat_a = [r.id for r in branch_a.requirements.values() if r.status == RequirementStatus.SATISFIED]
        sat_b = [r.id for r in branch_b.requirements.values() if r.status == RequirementStatus.SATISFIED]
        open_a = [r.id for r in branch_a.requirements.values() if r.status == RequirementStatus.OPEN]
        open_b = [r.id for r in branch_b.requirements.values() if r.status == RequirementStatus.OPEN]
        req_diff = {
            "satisfied_in_a": sat_a,
            "satisfied_in_b": sat_b,
            "open_in_a": open_a,
            "open_in_b": open_b,
        }

        # DFA state differences
        dfa_a = branch_a.derived_state.dfa_state if branch_a.derived_state else "UNKNOWN"
        dfa_b = branch_b.derived_state.dfa_state if branch_b.derived_state else "UNKNOWN"
        state_diff = {"dfa_state_a": dfa_a, "dfa_state_b": dfa_b}

        # Capability gaps
        cap_diff = {
            "gaps_in_a": list(branch_a.capability_gaps),
            "gaps_in_b": list(branch_b.capability_gaps),
        }

        # Factual summary report
        lines = [
            f"=== Branch Comparison: {branch_a.branch_id[:8]} vs {branch_b.branch_id[:8]} ===",
            f"Purpose A: {branch_a.purpose}",
            f"Purpose B: {branch_b.purpose}",
            f"DFA States: A='{dfa_a}', B='{dfa_b}'",
            f"Evidence: Only in A ({len(ev_diff['only_in_a'])}), Only in B ({len(ev_diff['only_in_b'])}), Common ({len(ev_diff['common'])})",
            f"Entities: Only in A ({len(ent_diff['only_in_a'])}), Only in B ({len(ent_diff['only_in_b'])}), Common ({len(ent_diff['common'])})",
            f"Hypothesis Shifts ({len(hyp_status_shifts)} altered):",
        ]
        for hid, shift in hyp_status_shifts.items():
            conf = hyp_conf_shifts.get(hid, {})
            lines.append(
                f"  - {hid}: A=[{shift['branch_a']} ({conf.get('branch_a', 0.0):.2f})] | B=[{shift['branch_b']} ({conf.get('branch_b', 0.0):.2f})]"
            )
        lines.append(f"Contradictions: Unresolved in A ({len(unres_a)}), Unresolved in B ({len(unres_b)})")
        lines.append(f"Requirements: Satisfied A ({len(sat_a)}), Satisfied B ({len(sat_b)})")

        return BranchComparison(
            branch_a_id=branch_a.branch_id,
            branch_b_id=branch_b.branch_id,
            common_source_snapshot_sequence=branch_a.source_snapshot_sequence
            if branch_a.source_snapshot_sequence == branch_b.source_snapshot_sequence
            else None,
            evidence_differences=ev_diff,
            entity_differences=ent_diff,
            relationship_differences=rel_diff,
            hypothesis_differences={"status_shifts": hyp_status_shifts, "confidence_shifts": hyp_conf_shifts},
            contradiction_differences=c_diff,
            requirement_differences=req_diff,
            state_transition_differences=state_diff,
            capability_gaps=cap_diff,
            summary_report="\n".join(lines),
            is_counterfactual_comparison=True,
        )

    @classmethod
    def compare_branch_with_snapshot(
        cls,
        branch: InvestigationBranch,
        snapshot: InvestigationSnapshot,
    ) -> BranchComparison:
        """Compare branch derived state against an authoritative snapshot factually."""
        ev_branch = set(branch.evidence_references)
        ev_snap = set(snapshot.evidence_ids)
        ev_diff = {
            "only_in_a": sorted(list(ev_branch - ev_snap)),
            "only_in_b": sorted(list(ev_snap - ev_branch)),
            "common": sorted(list(ev_branch & ev_snap)),
        }

        ent_branch = set(branch.entities.keys())
        ent_snap = set(snapshot.entities.keys())
        ent_diff = {
            "only_in_a": sorted(list(ent_branch - ent_snap)),
            "only_in_b": sorted(list(ent_snap - ent_branch)),
            "common": sorted(list(ent_branch & ent_snap)),
        }

        all_hyp = sorted(list(set(branch.hypotheses.keys()) | set(snapshot.hypotheses.keys())))
        hyp_status_shifts = {}
        hyp_conf_shifts = {}
        for hid in all_hyp:
            hb = branch.hypotheses.get(hid)
            hs = snapshot.hypotheses.get(hid)
            st_b = hb.status if hb else "ABSENT"
            st_s = hs.status if hs else "ABSENT"
            cf_b = hb.confidence if hb else 0.0
            cf_s = hs.confidence if hs else 0.0

            if st_b != st_s or abs(cf_b - cf_s) > 1e-4:
                hyp_status_shifts[hid] = {"branch": st_b, "snapshot": st_s}
                hyp_conf_shifts[hid] = {"branch": cf_b, "snapshot": cf_s}

        dfa_b = branch.derived_state.dfa_state if branch.derived_state else "UNKNOWN"
        dfa_s = snapshot.dfa_state
        state_diff = {"dfa_state_a": dfa_b, "dfa_state_b": dfa_s}

        lines = [
            f"=== Branch vs Authoritative Snapshot #{snapshot.sequence} ===",
            f"Branch: {branch.branch_id[:8]} ({branch.purpose})",
            f"DFA: Branch='{dfa_b}', Snapshot='{dfa_s}'",
            f"Evidence: Only in Branch ({len(ev_diff['only_in_a'])}), Only in Snapshot ({len(ev_diff['only_in_b'])})",
            f"Entities: Only in Branch ({len(ent_diff['only_in_a'])}), Only in Snapshot ({len(ent_diff['only_in_b'])})",
        ]

        return BranchComparison(
            branch_a_id=branch.branch_id,
            branch_b_id=f"authoritative:snapshot_{snapshot.sequence}",
            common_source_snapshot_sequence=branch.source_snapshot_sequence,
            evidence_differences=ev_diff,
            entity_differences=ent_diff,
            relationship_differences={"only_in_a": [], "only_in_b": [], "common": []},
            hypothesis_differences={"status_shifts": hyp_status_shifts, "confidence_shifts": hyp_conf_shifts},
            contradiction_differences={"unresolved_in_a": [], "unresolved_in_b": [], "resolved_in_a": [], "resolved_in_b": []},
            requirement_differences={"satisfied_in_a": [], "satisfied_in_b": [], "open_in_a": [], "open_in_b": []},
            state_transition_differences=state_diff,
            capability_gaps={"gaps_in_a": list(branch.capability_gaps), "gaps_in_b": []},
            summary_report="\n".join(lines),
            is_counterfactual_comparison=True,
        )

    @classmethod
    def promote_branch(
        cls,
        branch: InvestigationBranch,
        investigation: Any,
        reason: str,
        actor: str = "core.system",
    ) -> DecisionRecord:
        """Mark branch as PROMOTED and record an authoritative decision for potential incorporation.

        Crucially: does NOT automatically mutate authoritative evidence or entities.
        """
        # Validate branch lifecycle transition
        transition_branch(branch, BranchStatus.PROMOTED, reason=reason)

        # Record structured decision in authoritative case
        decision = investigation.record_decision(
            decision_type=DecisionType.PLANNING_SELECTION,
            actor=actor,
            rationale=f"Promoted investigation branch '{branch.branch_id}' ({branch.purpose}): {reason}",
            inputs={"branch_id": branch.branch_id, "source_snapshot": branch.source_snapshot_sequence},
            outcome={"promoted_branch_id": branch.branch_id, "status": BranchStatus.PROMOTED.value},
            metadata={"is_counterfactual_promotion": True, "reason": reason},
        )
        return decision

    @classmethod
    def create_candidate_experience(
        cls,
        branch: InvestigationBranch,
        action: str,
        lesson: str,
        conditions: Dict[str, Any],
        result_status: ExecutionStatus = ExecutionStatus.SUCCESS,
    ) -> CandidateBranchExperience:
        """Record an operational lesson as a CandidateBranchExperience clearly quarantined from global memory."""
        rec = ExperienceRecord(
            investigation_id=branch.investigation_id,
            action=action,
            context={"branch_id": branch.branch_id, "is_counterfactual": True},
            result_status=result_status,
            evidence_ids=list(branch.evidence_references),
            success=(result_status == ExecutionStatus.SUCCESS),
            lesson=lesson,
            conditions=conditions,
            scope="branch.candidate",
            metadata={"counterfactual": True, "branch_id": branch.branch_id},
        )
        return CandidateBranchExperience(
            branch_id=branch.branch_id,
            investigation_id=branch.investigation_id,
            experience_record=rec,
            is_counterfactual=True,
            validated=False,
        )

    @classmethod
    def promote_candidate_experience(
        cls,
        candidate: CandidateBranchExperience,
        experience_store: Any,
        validator_actor: str,
        validation_notes: str,
    ) -> ExperienceRecord:
        """Explicit promotion gate transferring a validated branch lesson into global ExperienceStore."""
        if candidate.validated:
            raise BranchPromotionError("Candidate experience has already been promoted.")

        candidate.validated = True
        candidate.validation_notes = validation_notes
        candidate.promoted_at = utc_now()

        rec = candidate.experience_record
        rec.scope = "global"
        rec.metadata["promoted_from_branch"] = candidate.branch_id
        rec.metadata["validated_by"] = validator_actor
        rec.metadata["validation_notes"] = validation_notes

        if hasattr(experience_store, "add_record"):
            experience_store.add_record(rec)
        elif hasattr(experience_store, "record_experience"):
            experience_store.record_experience(rec)
        else:
            experience_store._records[rec.id] = rec
        return rec

    @classmethod
    def replay_branch_graph(
        cls,
        branch: InvestigationBranch,
    ) -> Any:
        """Deterministically reconstruct counterfactual branch knowledge graph from branch state."""
        import copy
        from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
        from cyberclaw.knowledge.materialization import KnowledgeMaterializer
        from cyberclaw.investigation import Investigation

        inv_wrapper = Investigation(
            title=f"Branch Graph {branch.branch_id}",
            investigation_id=branch.branch_id,
        )
        inv_wrapper.hypotheses = copy.deepcopy(branch.hypotheses)
        for ev in branch.simulated_evidence:
            inv_wrapper.add_evidence(ev)

        target_graph = TemporalKnowledgeGraph(
            investigation_id=branch.branch_id,
            case_id=branch.investigation_id,
            is_counterfactual=True,
            branch_id=branch.branch_id,
        )
        return KnowledgeMaterializer.materialize_from_investigation(inv_wrapper, target_graph=target_graph)

    @classmethod
    def compare_branch_graphs(
        cls,
        graph_a: Any,
        graph_b: Any,
    ) -> Dict[str, Any]:
        """Factual, unranked comparison between two branch knowledge graphs."""
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
    def compare_graph_to_snapshot(
        cls,
        branch_graph: Any,
        snapshot_graph: Any,
    ) -> Dict[str, Any]:
        """Factual, unranked comparison between branch graph and source snapshot graph."""
        return cls.compare_branch_graphs(branch_graph, snapshot_graph)
