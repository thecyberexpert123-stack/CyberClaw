"""Deterministic state machine and least-privilege information sharing protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Dict, List, Optional, Set
from cyberclaw.collaboration.errors import (
    CollaborationStateTransitionError,
    UnauthorizedContextAccessError,
)
from cyberclaw.collaboration.models import (
    CollaborationContext,
    CollaborationRequest,
    CollaborationStatus,
    ContextSensitivity,
    utc_now,
)

if TYPE_CHECKING:
    from cyberclaw.investigation import Investigation
    from cyberclaw.specialists.base import Specialist


VALID_COLLABORATION_TRANSITIONS: Dict[CollaborationStatus, Set[CollaborationStatus]] = {
    CollaborationStatus.PROPOSED: {
        CollaborationStatus.VALIDATING,
        CollaborationStatus.REJECTED,
        CollaborationStatus.CANCELLED,
    },
    CollaborationStatus.VALIDATING: {
        CollaborationStatus.AUTHORIZED,
        CollaborationStatus.REJECTED,
        CollaborationStatus.DEFERRED,
        CollaborationStatus.CANCELLED,
        CollaborationStatus.BLOCKED,
        CollaborationStatus.FAILED,
    },
    CollaborationStatus.AUTHORIZED: {
        CollaborationStatus.ROUTED,
        CollaborationStatus.ACCEPTED,
        CollaborationStatus.DEFERRED,
        CollaborationStatus.CANCELLED,
        CollaborationStatus.FAILED,
        CollaborationStatus.BLOCKED,
        CollaborationStatus.REJECTED,
    },
    CollaborationStatus.ROUTED: {
        CollaborationStatus.ACCEPTED,
        CollaborationStatus.REJECTED,
        CollaborationStatus.DEFERRED,
        CollaborationStatus.CANCELLED,
        CollaborationStatus.FAILED,
        CollaborationStatus.BLOCKED,
    },
    CollaborationStatus.ACCEPTED: {
        CollaborationStatus.IN_PROGRESS,
        CollaborationStatus.CANCELLED,
        CollaborationStatus.FAILED,
        CollaborationStatus.EXPIRED,
        CollaborationStatus.BLOCKED,
    },
    CollaborationStatus.IN_PROGRESS: {
        CollaborationStatus.RESULT_RECEIVED,
        CollaborationStatus.FAILED,
        CollaborationStatus.EXPIRED,
        CollaborationStatus.CANCELLED,
    },
    CollaborationStatus.RESULT_RECEIVED: {
        CollaborationStatus.EVALUATED,
        CollaborationStatus.FAILED,
    },
    CollaborationStatus.EVALUATED: {
        CollaborationStatus.COMPLETED,
        CollaborationStatus.FAILED,
    },
    CollaborationStatus.BLOCKED: {
        CollaborationStatus.AUTHORIZED,
        CollaborationStatus.ROUTED,
        CollaborationStatus.ACCEPTED,
        CollaborationStatus.CANCELLED,
        CollaborationStatus.FAILED,
    },
    CollaborationStatus.DEFERRED: {
        CollaborationStatus.VALIDATING,
        CollaborationStatus.AUTHORIZED,
        CollaborationStatus.ROUTED,
        CollaborationStatus.CANCELLED,
    },
    CollaborationStatus.COMPLETED: set(),
    CollaborationStatus.REJECTED: set(),
    CollaborationStatus.CANCELLED: set(),
    CollaborationStatus.FAILED: set(),
    CollaborationStatus.EXPIRED: set(),
}


class CollaborationLifecycleDFA:
    """Deterministic finite state machine controlling collaboration request lifecycle."""

    @classmethod
    def transition(
        cls,
        request: CollaborationRequest,
        target_status: CollaborationStatus,
        reason: Optional[str] = None,
    ) -> CollaborationStatus:
        """Validate and apply a deterministic lifecycle state transition to a CollaborationRequest."""
        current_status = request.status
        allowed = VALID_COLLABORATION_TRANSITIONS.get(current_status, set())

        if target_status not in allowed:
            raise CollaborationStateTransitionError(
                f"Illegal collaboration transition from '{current_status.value}' to '{target_status.value}'. "
                f"Permissible targets: {[s.value for s in sorted(allowed, key=lambda x: x.value)]}",
                request_id=request.request_id,
                investigation_id=request.investigation_id,
            )

        request.status = target_status
        request.updated_at = utc_now()
        if reason:
            request.metadata["status_reason"] = reason

        return target_status


class ContextFilter:
    """Enforces least-privilege information sharing boundaries between specialists."""

    @classmethod
    def filter_context(
        cls,
        request: CollaborationRequest,
        investigation: Investigation,
        target_specialist: Specialist,
        has_soft_uncertainty: bool = False,
        uncertainty_reasons: Optional[List[str]] = None,
    ) -> CollaborationContext:
        """Construct a minimal, filtered context container for the target specialist."""
        # 1. Enforce Sensitivity Clearance
        clearance = getattr(target_specialist, "max_sensitivity_level", "SENSITIVE")
        if not request.sensitivity.is_accessible_by(clearance):
            raise UnauthorizedContextAccessError(
                f"Specialist '{target_specialist.id}' clearance '{clearance}' insufficient for "
                f"collaboration context sensitivity '{request.sensitivity.value}'.",
                request_id=request.request_id,
                investigation_id=request.investigation_id,
                specialist_id=target_specialist.id,
            )

        # 2. Extract only explicitly authorized input evidence
        authorized_evidence = []
        for ev_id in request.input_evidence_ids:
            ev = investigation.evidence_store.get(ev_id)
            if ev:
                authorized_evidence.append(ev)

        # 3. Extract only explicitly authorized input entities
        authorized_entities = []
        for ent_id in request.input_entity_ids:
            # Check by id or name
            matched = None
            for ent in investigation.entities.values():
                if ent.id == ent_id or ent.name == ent_id:
                    matched = ent
                    break
            if matched:
                authorized_entities.append(matched)

        # 4. Extract only relevant hypothesis statements (not entire case deliberations)
        hyp_summaries = []
        for hid in request.hypothesis_ids:
            hyp = investigation.hypotheses.get(hid)
            if hyp:
                hyp_summaries.append({
                    "id": hyp.id,
                    "statement": hyp.statement,
                    "status": hyp.status,
                    "confidence": hyp.confidence,
                })

        return CollaborationContext(
            request_id=request.request_id,
            investigation_id=request.investigation_id,
            requesting_specialist=request.requesting_specialist,
            target_specialist=target_specialist.id,
            sensitivity=request.sensitivity,
            authorized_evidence=authorized_evidence,
            authorized_entities=authorized_entities,
            hypothesis_summaries=hyp_summaries,
            parameters=dict(request.metadata.get("parameters", {})),
            has_soft_dependency_uncertainty=has_soft_uncertainty,
            uncertainty_reasons=uncertainty_reasons or [],
        )
