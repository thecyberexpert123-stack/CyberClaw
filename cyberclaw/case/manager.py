"""CaseManager: High-level orchestrator for Long-Horizon Case State and Memory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from cyberclaw.case.journal import CaseJournal
from cyberclaw.case.models import (
    CaseState,
    DecisionRecord,
    DecisionType,
    ExecutionHistoryRecord,
    InvestigationSnapshot,
    JournalEntry,
    JournalEntryType,
    SnapshotDelta,
    StateTransitionRecord,
    utc_now,
)
from cyberclaw.case.snapshots import SnapshotManager
from cyberclaw.investigation import Investigation
from cyberclaw.planning.models import InvestigationPlan, StoppingCondition
from cyberclaw.workspace.manager import WorkspaceManager


class CaseManager:
    """Manages the lifecycle, snapshots, decisions, and durable state of an investigation case."""

    def __init__(self, investigation_id: str, workspace: Optional[WorkspaceManager] = None) -> None:
        self.investigation_id = investigation_id
        self.workspace = workspace
        self.snapshots = SnapshotManager(investigation_id)
        self.journal = CaseJournal(investigation_id)
        self.state_history: List[StateTransitionRecord] = []
        self.execution_history: List[ExecutionHistoryRecord] = []
        self.planning_history: List[InvestigationPlan] = []
        self.stopping_history: List[StoppingCondition] = []
        self.experience_references: List[str] = []

    @property
    def decision_history(self) -> List[DecisionRecord]:
        """Return all decisions from the case journal."""
        return self.journal.decisions

    def record_decision(
        self,
        decision_type: DecisionType,
        actor: str = "core.system",
        rationale: str = "",
        inputs: Optional[Dict[str, Any]] = None,
        outcome: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> DecisionRecord:
        """Record an explicit investigative choice in the journal."""
        combined_meta = dict(metadata or {})
        combined_meta.update(kwargs)
        return self.journal.record_decision(
            decision_type=decision_type,
            actor=actor,
            rationale=rationale,
            inputs=inputs or {},
            outcome=outcome or {},
            metadata=combined_meta,
        )

    def record_state_transition(
        self,
        from_state: str,
        to_state: str,
        event: str,
        reason: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> StateTransitionRecord:
        """Record an explicit DFA state transition in the state history and journal."""
        rec = StateTransitionRecord(
            from_state=from_state,
            to_state=to_state,
            event=event,
            timestamp=utc_now(),
            reason=reason,
            context=context or {},
        )
        self.state_history.append(rec)
        self.journal.append_entry(
            entry_type=JournalEntryType.STATE_TRANSITION,
            summary=f"DFA Transition: {from_state} -> {to_state} via event '{event}'",
            details={"from": from_state, "to": to_state, "event": event, "reason": reason},
        )
        return rec

    def record_execution(
        self,
        requirement_id: str,
        specialist_id: str,
        capability_id: str,
        status: str,
        duration_ms: Optional[float] = None,
        evidence_count: int = 0,
        evidence_ids: Optional[List[str]] = None,
        error: Optional[str] = None,
        capability_version: str = "1.0.0",
        provider_id: Optional[str] = None,
        provider_version: Optional[str] = None,
        lifecycle_state: str = "AVAILABLE",
        trust_state: str = "TRUSTED_WITH_SCOPE",
        permission_scope: str = "reversible",
        action_scope: str = "consequential",
        validation_reference: Optional[str] = None,
        authorization_decision_id: Optional[str] = None,
        risk_level: Optional[str] = None,
        policy_id: Optional[str] = None,
    ) -> ExecutionHistoryRecord:
        """Log specialist execution details."""
        rec = ExecutionHistoryRecord(
            requirement_id=requirement_id,
            specialist_id=specialist_id,
            capability_id=capability_id,
            capability_version=capability_version,
            provider_id=provider_id,
            provider_version=provider_version,
            lifecycle_state=lifecycle_state,
            trust_state=trust_state,
            permission_scope=permission_scope,
            action_scope=action_scope,
            validation_reference=validation_reference,
            authorization_decision_id=authorization_decision_id,
            risk_level=risk_level,
            policy_id=policy_id,
            status=status,
            duration_ms=duration_ms,
            evidence_count=evidence_count,
            timestamp=utc_now(),
            error=error,
        )
        self.execution_history.append(rec)
        self.journal.append_entry(
            entry_type=JournalEntryType.REQUIREMENT_EXECUTED,
            summary=f"Specialist '{specialist_id}' executed capability '{capability_id}' (v{capability_version}) for requirement '{requirement_id}': {status}",
            reference_id=requirement_id,
            details={
                "specialist": specialist_id,
                "capability": capability_id,
                "capability_version": capability_version,
                "provider_id": provider_id,
                "lifecycle_state": lifecycle_state,
                "trust_state": trust_state,
                "status": status,
                "evidence_count": evidence_count,
                "evidence_ids": evidence_ids or [],
            },
        )
        return rec

    def record_plan(self, plan: InvestigationPlan) -> None:
        """Track planning cycles in history."""
        self.planning_history.append(plan)
        if plan.stopping_condition:
            self.stopping_history.append(plan.stopping_condition)
            self.journal.append_entry(
                entry_type=JournalEntryType.STOPPING_CONDITION,
                summary=f"Investigation reached stopping condition: {plan.stopping_condition.value}",
                reference_id=plan.plan_id,
                details={"stopping_condition": plan.stopping_condition.value, "reason": plan.reasoning_basis},
            )

        self.journal.append_entry(
            entry_type=JournalEntryType.PLAN_GENERATED,
            summary=f"Plan generated with {len(plan.candidate_next_requirements)} candidates. Status: {plan.plan_status.value}",
            reference_id=plan.plan_id,
            details={"candidates": len(plan.candidate_next_requirements), "gaps": len(plan.capability_gaps)},
        )

    def link_experience(self, experience_id: str) -> None:
        """Reference a global experience record learned during or applied to this case."""
        if experience_id not in self.experience_references:
            self.experience_references.append(experience_id)

    def capture_snapshot(
        self,
        investigation: Investigation,
        trigger: str = "manual",
        active_plan_id: Optional[str] = None,
        stopping_condition: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> InvestigationSnapshot:
        """Capture and journal a new point-in-time snapshot."""
        snapshot = self.snapshots.capture(
            investigation=investigation,
            trigger=trigger,
            active_plan_id=active_plan_id,
            stopping_condition=stopping_condition,
            metadata=metadata,
        )
        self.journal.append_entry(
            entry_type=JournalEntryType.SNAPSHOT_CAPTURED,
            summary=f"Captured Snapshot #{snapshot.sequence} [{trigger}] (SHA256: {snapshot.state_digest[:12]}...)",
            snapshot_id=snapshot.snapshot_id,
            details={"sequence": snapshot.sequence, "digest": snapshot.state_digest, "trigger": trigger},
        )
        return snapshot

    def assemble_case_state(self, investigation: Investigation) -> CaseState:
        """Assemble the complete CaseState object adhering to the conceptual model."""
        return CaseState(
            investigation_id=self.investigation_id,
            title=investigation.title,
            current_dfa_state=investigation.current_state.value,
            state_history=list(self.state_history),
            evidence_registry=[e.id for e in investigation.evidence_store.list_all()],
            entities=dict(investigation.entities),
            relationships=list(investigation.relationships),
            hypotheses=dict(investigation.hypotheses),
            requirements=dict(investigation.information_requirements),
            planning_history=list(self.planning_history),
            execution_history=list(self.execution_history),
            decision_history=list(self.journal.decisions),
            contradictions=list(investigation.contradictions),
            stopping_history=list(self.stopping_history),
            experience_references=list(self.experience_references),
            snapshots=list(self.snapshots.snapshots),
            journal=list(self.journal.entries),
            created_at=investigation.created_at,
            updated_at=utc_now(),
        )

    def persist(self, investigation: Investigation) -> None:
        """Persist full case state, snapshots, and journal to investigation workspace if available."""
        if not self.workspace:
            return

        layout = self.workspace.get_investigation_workspace(self.investigation_id)

        # 1. Persist CaseState summary
        case_state = self.assemble_case_state(investigation)
        case_file = layout.root / "case_state.json"
        self.workspace.atomic_write(
            case_file,
            json.dumps(json.loads(case_state.model_dump_json()), indent=2),
        )

        # 2. Persist Snapshots
        snapshots_dir = layout.root / "snapshots"
        snapshots_dir.mkdir(parents=True, exist_ok=True)
        for snap in self.snapshots.snapshots:
            snap_file = snapshots_dir / f"snapshot_{snap.sequence:04d}.json"
            self.workspace.atomic_write(
                snap_file,
                json.dumps(json.loads(snap.model_dump_json()), indent=2),
            )

        # 3. Persist Journal
        journal_file = layout.root / "journal.json"
        journal_data = [json.loads(e.model_dump_json()) for e in self.journal.entries]
        self.workspace.atomic_write(journal_file, json.dumps(journal_data, indent=2))

        # 4. Persist Decisions
        decisions_file = layout.root / "decisions.json"
        decisions_data = [json.loads(d.model_dump_json()) for d in self.journal.decisions]
        self.workspace.atomic_write(decisions_file, json.dumps(decisions_data, indent=2))
