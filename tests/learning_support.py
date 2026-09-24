"""Shared builders for learning tests. Not collected as tests."""

from __future__ import annotations

from cyberclaw.case.models import JournalEntryType
from cyberclaw.coordination.requirements import RequirementStatus
from cyberclaw.core import CyberClawCore
from cyberclaw.correlation.models import ContradictionRecord
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.planning.models import StoppingCondition
from cyberclaw.types import Source


def build_completed_investigation(
    core: CyberClawCore,
    *,
    family: str,
    target: str,
    source_id: str,
    title: str = "Resolve contradictory evidence about subject",
    with_retry: bool = False,
    failing: bool = False,
    conflict_type: str = "competing_claims",
):
    inv = core.create_investigation(
        title,
        description="Resolve contradictory evidence about subject",
        metadata={"source_family": family, "case_id": family},
        targets=[target],
    )
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    inv.participating_specialists = ["specialist.alpha", "specialist.beta"]
    req = inv.create_information_requirement(
        description="Need independent evidence",
        target_or_entity=target,
        evidence_types_sought=["finding"],
        assigned_capability_id="cap.observe",
    )
    req.assigned_specialist_id = "specialist.alpha"
    ev = Evidence(
        type="finding",
        subject=target,
        value={"observed": target, "family": family},
        source=Source(type="feed", name=source_id, id=source_id),
    )
    inv.add_evidence(ev)
    if failing:
        req.status = RequirementStatus.FAILED
        req.error = "no_actionable_information"
        inv.case_manager.record_execution(
            requirement_id=req.id,
            specialist_id="specialist.alpha",
            capability_id="cap.observe",
            status="FAILURE",
            evidence_count=0,
            error="no_actionable_information",
        )
        inv.case_manager.stopping_history.append(StoppingCondition.REQUIREMENT_FAILURE_LIMIT)
    else:
        req.status = RequirementStatus.SATISFIED
        req.resulting_evidence_ids = [ev.id]
        if with_retry:
            inv.case_manager.record_execution(
                requirement_id=req.id,
                specialist_id="specialist.alpha",
                capability_id="cap.observe",
                status="FAILURE",
                evidence_count=0,
                error="temporary_unavailable",
            )
        inv.case_manager.record_execution(
            requirement_id=req.id,
            specialist_id="specialist.alpha",
            capability_id="cap.observe",
            status="SUCCESS",
            evidence_count=1,
            evidence_ids=[ev.id],
        )
        inv.case_manager.record_execution(
            requirement_id=req.id,
            specialist_id="specialist.beta",
            capability_id="cap.corroborate",
            status="SUCCESS",
            evidence_count=1,
            evidence_ids=[ev.id],
        )
        inv.contradictions.append(
            ContradictionRecord(
                investigation_id=inv.id,
                subject=target,
                conflict_type=conflict_type,
                competing_evidence_ids=[ev.id],
                description=f"Competing claims about {target}",
                resolved=True,
                resolution_notes="Independent source corroborated the claim.",
            )
        )
        inv.case_manager.stopping_history.append(StoppingCondition.OBJECTIVE_SATISFIED)
    inv.record_journal_entry(
        JournalEntryType.COLLABORATION_COMPLETED,
        summary=f"specialist.alpha handed findings to specialist.beta for {target}",
        details={"sequence": ["specialist.alpha", "specialist.beta"], "participants": ["specialist.alpha", "specialist.beta"]},
    )
    inv.record_journal_entry(
        JournalEntryType.AUTHORIZATION_GRANTED,
        summary="Policy allowed capability consultation",
        details={
            "decision": "ALLOW",
            "capability_id": "cap.observe",
            "policy_id": "default-system-policy",
            "policy_version": "1.0.0",
            "permission": "investigation:view",
        },
    )
    return inv
