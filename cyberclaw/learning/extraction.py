"""Extract InvestigationExperience from authoritative history without inventing facts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Sequence

from cyberclaw.learning.errors import LearningExtractionError
from cyberclaw.learning.models import (
    EXPERIENCE_SCHEMA_VERSION,
    ActionTrace,
    AuthoritativeRef,
    InvestigationExperience,
    OutcomeClass,
    canonical_digest,
    stable_id,
)


_RESOLVED_REQUIREMENT_STATUSES = {"SATISFIED", "SATISFIED_EMPTY", "FAILED", "CANCELLED"}
_SUCCESS_STOPS = {"OBJECTIVE_SATISFIED", "NO_ACTIONABLE_INFORMATION_GAPS"}
_FAILURE_STOPS = {"REQUIREMENT_FAILURE_LIMIT"}
_KNOWLEDGE_ENTRY_PREFIX = "KNOWLEDGE_"
_AUTH_ENTRY_TYPES = {
    "AUTHORIZATION_REQUESTED",
    "AUTHORIZATION_GRANTED",
    "AUTHORIZATION_DENIED",
    "AUTHORIZATION_DEFERRED",
    "APPROVAL_REQUESTED",
    "APPROVAL_GRANTED",
    "APPROVAL_REJECTED",
    "POLICY_CONFLICT_DETECTED",
    "RISK_ASSESSED",
}


def _enum_value(value: Any) -> str:
    if value is None:
        return ""
    return value.value if hasattr(value, "value") else str(value)


def _ref(record_type: str, record_id: str, investigation_id: str, sequence: Optional[int] = None) -> AuthoritativeRef:
    return AuthoritativeRef(
        record_type=record_type,
        record_id=record_id,
        investigation_id=investigation_id,
        sequence=sequence,
    )


class ExperienceExtractor:
    """Read-only extractor. Does not append journal entries or mutate the investigation."""

    @classmethod
    def extract(cls, investigation: Any) -> InvestigationExperience:
        investigation_id = getattr(investigation, "id", None) or getattr(investigation, "investigation_id", None)
        if not investigation_id:
            raise LearningExtractionError("Investigation has no id; refusing to invent an experience identity.")

        case_manager = getattr(investigation, "case_manager", None)
        journal = list(case_manager.journal.entries) if case_manager is not None else []
        decisions = list(case_manager.journal.decisions) if case_manager is not None else []
        executions = list(getattr(case_manager, "execution_history", []) or [])
        plans = list(getattr(case_manager, "planning_history", []) or [])
        stopping_history = list(getattr(case_manager, "stopping_history", []) or [])

        metadata = dict(getattr(investigation, "metadata", {}) or {})
        title = getattr(investigation, "title", "") or ""
        description = getattr(investigation, "description", "") or ""
        objective = " ".join(part for part in (title, description) if part).strip()

        source_family_key = (
            metadata.get("source_family")
            or metadata.get("experiment_id")
            or metadata.get("template_id")
            or metadata.get("feed_id")
            or f"investigation:{investigation_id}"
        )
        branch_id = metadata.get("branch_id") or getattr(investigation, "branch_id", None)
        is_counterfactual = bool(
            metadata.get("is_counterfactual")
            or getattr(investigation, "is_counterfactual", False)
            or branch_id
        )

        requirements = list(getattr(investigation, "information_requirements", {}).values())
        requirements_sorted = sorted(requirements, key=lambda r: (getattr(r, "created_at", datetime.min), r.id))
        earliest = requirements_sorted[0].created_at if requirements_sorted else None
        initial_reqs = []
        resolved = []
        unresolved = []
        for req in requirements_sorted:
            status = _enum_value(req.status)
            summary = {
                "requirement_id": req.id,
                "description": req.description,
                "target_or_entity": req.target_or_entity,
                "evidence_types_sought": list(req.evidence_types_sought),
                "assigned_capability_id": req.assigned_capability_id,
                "assigned_specialist_id": req.assigned_specialist_id,
                "status": status,
                "resulting_evidence_ids": list(req.resulting_evidence_ids),
            }
            if earliest is not None and req.created_at == earliest:
                initial_reqs.append(summary)
            if status in _RESOLVED_REQUIREMENT_STATUSES and status != "FAILED":
                resolved.append(summary)
            elif status == "FAILED":
                resolved.append(summary)
            else:
                unresolved.append(summary)

        evidence_items = []
        store = getattr(investigation, "evidence_store", None)
        if store is not None and hasattr(store, "list_all"):
            evidence_items = list(store.list_all())

        evidence_refs = [
            _ref("evidence", ev.id, investigation_id) for ev in evidence_items if getattr(ev, "id", None)
        ]
        evidence_types = sorted({ev.type for ev in evidence_items if getattr(ev, "type", None)})
        upstream_source_ids = sorted(
            {
                getattr(getattr(ev, "source", None), "id", None)
                or getattr(getattr(ev, "source", None), "name", None)
                for ev in evidence_items
                if getattr(ev, "source", None) is not None
            }
            - {None, ""}
        )

        source_independence_count = None
        source_independence_roots: List[str] = []
        source_independence_available = False
        if evidence_items:
            try:
                from cyberclaw.knowledge.provenance import calculate_source_independence

                count, roots = calculate_source_independence([ev.id for ev in evidence_items], evidence_items)
                source_independence_count = count
                source_independence_roots = list(roots)
                source_independence_available = True
            except Exception:
                source_independence_available = False

        hypotheses = list(getattr(investigation, "hypotheses", {}).values())
        hypothesis_transitions = []
        uncertainties = []
        for hyp in hypotheses:
            record = {
                "hypothesis_id": hyp.id,
                "statement": hyp.statement,
                "status": hyp.status,
                "confidence": hyp.confidence,
                "supporting_evidence_ids": list(hyp.supporting_evidence_ids),
                "refuting_evidence_ids": list(hyp.refuting_evidence_ids),
            }
            hypothesis_transitions.append(record)
            if str(hyp.status).lower() not in {"supported", "refuted", "satisfied"}:
                uncertainties.append({"kind": "hypothesis", "hypothesis_id": hyp.id, "status": hyp.status})

        contradictions_raw = list(getattr(investigation, "contradictions", []) or [])
        contradictions = []
        for contra in contradictions_raw:
            contradictions.append(
                {
                    "contradiction_id": contra.id,
                    "subject": contra.subject,
                    "conflict_type": contra.conflict_type,
                    "competing_evidence_ids": list(contra.competing_evidence_ids),
                    "resolved": bool(contra.resolved),
                    "resolution_notes": contra.resolution_notes,
                }
            )
            if not contra.resolved:
                uncertainties.append(
                    {
                        "kind": "contradiction",
                        "contradiction_id": contra.id,
                        "conflict_type": contra.conflict_type,
                    }
                )

        actions: List[ActionTrace] = []
        for rec in executions:
            actions.append(
                ActionTrace(
                    requirement_id=rec.requirement_id,
                    specialist_id=rec.specialist_id,
                    capability_id=rec.capability_id,
                    capability_version=rec.capability_version,
                    status=rec.status,
                    authorization_decision_id=rec.authorization_decision_id,
                    policy_id=rec.policy_id,
                    evidence_count=rec.evidence_count,
                    error=rec.error,
                    source_record_ids=[rec.requirement_id] if rec.requirement_id else [],
                )
            )

        capabilities_used = sorted({a.capability_id for a in actions if a.capability_id})
        specialists = set(getattr(investigation, "participating_specialists", []) or [])
        for action in actions:
            if action.specialist_id:
                specialists.add(action.specialist_id)
        for req in requirements:
            if req.assigned_specialist_id:
                specialists.add(req.assigned_specialist_id)
        specialists_involved = sorted(specialists)

        collaboration_patterns = []
        knowledge_refs: List[AuthoritativeRef] = []
        policy_decisions = []
        authorization_outcomes = []
        authoritative_refs: List[AuthoritativeRef] = []

        for entry in journal:
            etype = _enum_value(entry.entry_type)
            authoritative_refs.append(
                _ref("journal", entry.id, investigation_id, entry.sequence)
            )
            if etype.startswith("COLLABORATION_"):
                collaboration_patterns.append(
                    {
                        "journal_entry_id": entry.id,
                        "sequence": entry.sequence,
                        "entry_type": etype,
                        "summary": entry.summary,
                        "details": dict(entry.details or {}),
                    }
                )
            if etype.startswith(_KNOWLEDGE_ENTRY_PREFIX):
                knowledge_refs.append(
                    _ref("knowledge_journal", entry.id, investigation_id, entry.sequence)
                )
            if etype in _AUTH_ENTRY_TYPES:
                outcome = {
                    "journal_entry_id": entry.id,
                    "entry_type": etype,
                    "reference_id": entry.reference_id,
                    "details": dict(entry.details or {}),
                }
                policy_decisions.append(outcome)
                decision = (entry.details or {}).get("decision")
                if decision or etype.startswith("AUTHORIZATION_"):
                    authorization_outcomes.append(
                        {
                            "journal_entry_id": entry.id,
                            "decision": decision or etype.removeprefix("AUTHORIZATION_"),
                            "capability_id": (entry.details or {}).get("capability_id"),
                            "policy_id": (entry.details or {}).get("policy_id"),
                            "policy_version": (entry.details or {}).get("policy_version"),
                            "permission": (entry.details or {}).get("permission"),
                        }
                    )

        for decision in decisions:
            authoritative_refs.append(_ref("decision", decision.id, investigation_id, decision.sequence))
            dtype = _enum_value(decision.decision_type)
            if dtype in {"AUTHORIZATION_DECISION", "POLICY_EVALUATION"}:
                policy_decisions.append(
                    {
                        "decision_id": decision.id,
                        "decision_type": dtype,
                        "actor": decision.actor,
                        "rationale": decision.rationale,
                        "outcome": dict(decision.outcome or {}),
                    }
                )

        for ev in evidence_items:
            authoritative_refs.append(_ref("evidence", ev.id, investigation_id))
        for req in requirements:
            authoritative_refs.append(_ref("requirement", req.id, investigation_id))
        for hyp in hypotheses:
            authoritative_refs.append(_ref("hypothesis", hyp.id, investigation_id))
        for contra in contradictions_raw:
            authoritative_refs.append(_ref("contradiction", contra.id, investigation_id))

        stopping_condition = None
        if stopping_history:
            stopping_condition = _enum_value(stopping_history[-1])
        else:
            for entry in reversed(journal):
                if _enum_value(entry.entry_type) == "STOPPING_CONDITION":
                    stopping_condition = (entry.details or {}).get("condition") or entry.summary
                    break

        created_at = getattr(investigation, "created_at", None)
        updated_at = getattr(investigation, "updated_at", None)
        duration_ms = None
        absent = []
        if created_at is None or updated_at is None:
            absent.append("execution_duration_ms")
        else:
            duration_ms = (updated_at - created_at).total_seconds() * 1000.0

        retry_count = 0
        seen_req_cap = {}
        failures = []
        for action in actions:
            key = (action.requirement_id, action.capability_id)
            seen_req_cap[key] = seen_req_cap.get(key, 0) + 1
            if action.error:
                failures.append(
                    {
                        "requirement_id": action.requirement_id,
                        "capability_id": action.capability_id,
                        "specialist_id": action.specialist_id,
                        "error": action.error,
                        "authorization_decision_id": action.authorization_decision_id,
                    }
                )
        retry_count = sum(count - 1 for count in seen_req_cap.values() if count > 1)
        for req_summary in resolved:
            if req_summary["status"] == "FAILED":
                failures.append(
                    {
                        "requirement_id": req_summary["requirement_id"],
                        "capability_id": req_summary["assigned_capability_id"],
                        "error": "requirement_failed",
                    }
                )

        if not executions and not journal:
            absent.append("actions_taken")
        if not policy_decisions:
            absent.append("policy_decisions")
        if not knowledge_refs:
            absent.append("knowledge_graph_changes")

        final_state = None
        current = getattr(investigation, "current_state", None)
        if current is not None:
            final_state = _enum_value(current)
        case_stage = final_state

        uncertainty_types = sorted(
            {
                item.get("conflict_type") or item.get("status") or item.get("kind")
                for item in uncertainties
                if item.get("conflict_type") or item.get("status") or item.get("kind")
            }
        )
        if any(not c["resolved"] for c in contradictions):
            if "CONTRADICTED" not in uncertainty_types:
                uncertainty_types = sorted(set(uncertainty_types) | {"CONTRADICTED"})
        if any(c["resolved"] for c in contradictions):
            uncertainty_types = sorted(set(uncertainty_types) | {"CONTRADICTION_RESOLUTION"})

        outcome = cls._classify_outcome(stopping_condition, unresolved, failures, contradictions)

        extracted_at = updated_at or created_at
        if extracted_at is None:
            raise LearningExtractionError(
                "Investigation has no created_at/updated_at timestamp; refusing to invent an extraction time.",
                details={"investigation_id": investigation_id},
            )

        content_payload = {
            "schema_version": EXPERIENCE_SCHEMA_VERSION,
            "investigation_id": investigation_id,
            "case_id": metadata.get("case_id") or investigation_id,
            "objective": objective,
            "initial_information_requirements": initial_reqs,
            "requirements_resolved": resolved,
            "requirements_unresolved": unresolved,
            "capabilities_used": capabilities_used,
            "specialists_involved": specialists_involved,
            "contradictions": contradictions,
            "hypothesis_transitions": hypothesis_transitions,
            "stopping_condition": stopping_condition,
            "retry_count": retry_count,
            "failures": failures,
            "authorization_outcomes": authorization_outcomes,
            "final_investigation_state": final_state,
            "source_family_key": source_family_key,
            "upstream_source_ids": upstream_source_ids,
            "evidence_ids": [ref.record_id for ref in evidence_refs],
            "is_counterfactual": is_counterfactual,
            "branch_id": branch_id,
            "outcome": outcome.value,
            "journal_ids": [ref.record_id for ref in authoritative_refs if ref.record_type == "journal"],
        }
        digest = canonical_digest(content_payload)
        experience_id = stable_id("exp", investigation_id, digest)

        return InvestigationExperience(
            experience_id=experience_id,
            investigation_id=investigation_id,
            case_id=metadata.get("case_id") or investigation_id,
            objective=objective,
            initial_information_requirements=initial_reqs,
            initial_uncertainties=uncertainties,
            actions_taken=actions,
            capabilities_used=capabilities_used,
            specialists_involved=specialists_involved,
            collaboration_patterns=collaboration_patterns,
            evidence_generated=evidence_refs,
            hypothesis_transitions=hypothesis_transitions,
            contradictions=contradictions,
            knowledge_graph_changes=knowledge_refs,
            requirements_resolved=resolved,
            requirements_unresolved=unresolved,
            stopping_condition=stopping_condition,
            execution_duration_ms=duration_ms,
            retry_count=retry_count,
            failures=failures,
            policy_decisions=policy_decisions,
            authorization_outcomes=authorization_outcomes,
            final_investigation_state=final_state,
            source_family_key=str(source_family_key),
            upstream_source_ids=upstream_source_ids,
            source_independence_count=source_independence_count,
            source_independence_roots=source_independence_roots,
            source_independence_available=source_independence_available,
            uncertainty_types=uncertainty_types,
            evidence_types=evidence_types,
            case_stage=case_stage,
            plan_count=len(plans),
            outcome=outcome,
            is_counterfactual=is_counterfactual,
            branch_id=branch_id,
            extracted_at=extracted_at,
            authoritative_refs=authoritative_refs,
            absent_fields=sorted(set(absent)),
            content_digest=digest,
        )

    @staticmethod
    def _classify_outcome(
        stopping_condition: Optional[str],
        unresolved: Sequence[Dict[str, Any]],
        failures: Sequence[Dict[str, Any]],
        contradictions: Sequence[Dict[str, Any]],
    ) -> OutcomeClass:
        if stopping_condition in _SUCCESS_STOPS and not unresolved:
            # A recovered investigation is still a success. Failures stay on the record.
            return OutcomeClass.SUCCESS
        if failures or (stopping_condition in _FAILURE_STOPS):
            return OutcomeClass.FAILURE
        if contradictions and all(c.get("resolved") for c in contradictions) and not unresolved and not failures:
            return OutcomeClass.SUCCESS
        if unresolved and not failures:
            return OutcomeClass.MIXED
        return OutcomeClass.INDETERMINATE
