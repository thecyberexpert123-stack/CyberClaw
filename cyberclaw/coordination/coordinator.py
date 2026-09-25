"""Investigation Coordinator managing multi-specialist coordination, requirements, and evidence flows."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional
from uuid import uuid4

if TYPE_CHECKING:
    from cyberclaw.investigation import Investigation

from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.coordination.requirements import (
    InformationRequirement,
    RequirementStatus,
    utc_now,
)
from cyberclaw.coordination.router import RequirementRouter
from cyberclaw.correlation.engine import CorrelationEngine, CorrelationResult
from cyberclaw.events.bus import EventBus
from cyberclaw.events.event import Event
from cyberclaw.evidence.result import ExecutionStatus
from cyberclaw.specialists.registry import SpecialistRegistry
from cyberclaw.types import Hypothesis


class InvestigationCoordinator:
    """Coordinates multi-specialist investigations without domain-specific hardcoding."""

    def __init__(
        self,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        event_bus: EventBus,
        correlation_engine: Optional[CorrelationEngine] = None,
    ) -> None:
        self.specialists = specialists
        self.capabilities = capabilities
        self.event_bus = event_bus
        self.governed_executor: Optional[Callable[..., Any]] = None
        self.correlation_engine = correlation_engine or CorrelationEngine()
        self.router = RequirementRouter(specialists, capabilities)

    def create_requirement(
        self,
        investigation: Investigation,
        description: str,
        target_or_entity: str,
        evidence_types_sought: Optional[List[str]] = None,
        assigned_capability_id: Optional[str] = None,
        priority: int = 50,
        dependencies: Optional[List[str]] = None,
        completion_criteria: Optional[Dict[str, Any]] = None,
    ) -> InformationRequirement:
        """Create and register an InformationRequirement in the global investigation."""
        req = InformationRequirement(
            investigation_id=investigation.id,
            description=description,
            evidence_types_sought=evidence_types_sought or [],
            target_or_entity=target_or_entity,
            assigned_capability_id=assigned_capability_id,
            priority=priority,
            dependencies=dependencies or [],
            completion_criteria=completion_criteria or {},
        )
        investigation.information_requirements[req.id] = req
        investigation.record_journal_entry(
            entry_type="REQUIREMENT_CREATED",
            summary=f"Requirement created for {target_or_entity}: {description}",
            reference_id=req.id,
            details={
                "requirement_id": req.id,
                "target": target_or_entity,
                "capability": assigned_capability_id,
                "evidence_types": req.evidence_types_sought,
            },
        )

        self.event_bus.publish(
            Event(
                type="requirement.created",
                source="core.coordinator",
                correlation_id=investigation.id,
                payload={
                    "requirement_id": req.id,
                    "description": req.description,
                    "target": req.target_or_entity,
                    "evidence_types_sought": req.evidence_types_sought,
                },
            )
        )
        return req

    def fulfill_requirement(
        self,
        investigation: Investigation,
        requirement_id: str,
        parameters: Optional[Dict[str, Any]] = None,
        actor: str = "core.system",
    ) -> InformationRequirement:
        """Resolve, dispatch, and fulfill an InformationRequirement via an eligible Specialist."""
        req = investigation.information_requirements.get(requirement_id)
        if not req:
            raise KeyError(f"Requirement '{requirement_id}' not found in investigation.")

        # Check dependencies
        for dep_id in req.dependencies:
            dep = investigation.information_requirements.get(dep_id)
            if dep and not dep.is_resolved:
                req.status = RequirementStatus.OPEN
                req.error = f"Blocked by dependency requirement '{dep_id}'"
                return req

        # 1. Resolve eligible specialist and capability
        specialist, cap_id, failure_reason = self.router.resolve_specialist(req)
        if not specialist or not cap_id:
            req.status = RequirementStatus.FAILED
            req.error = failure_reason or "No eligible specialist found."
            req.updated_at = utc_now()
            return req

        req.assigned_specialist_id = specialist.id
        req.assigned_capability_id = cap_id
        req.status = RequirementStatus.ASSIGNED
        req.updated_at = utc_now()

        # Track specialist participation in investigation
        if specialist.id not in investigation.participating_specialists:
            investigation.participating_specialists.append(specialist.id)

        self.event_bus.publish(
            Event(
                type="requirement.assigned",
                source="core.coordinator",
                correlation_id=investigation.id,
                payload={"requirement_id": req.id, "specialist_id": specialist.id, "capability_id": cap_id},
            )
        )

        # 2. Route into the governed executor. Coordination does not invoke
        # the specialist endpoint itself: registration, lifecycle, trust,
        # permission, and policy are not optional because a specialist exists.
        if self.governed_executor is None:
            raise RuntimeError(
                "Requirement fulfillment has no governed executor. "
                "Coordination must not invoke a specialist directly."
            )
        req_params = dict(parameters or {})
        if "target" not in req_params:
            req_params["target"] = req.target_or_entity
        if "target_ip" not in req_params and "." in req.target_or_entity:
            req_params["target_ip"] = req.target_or_entity

        result = self.governed_executor(
            investigation_id=investigation.id,
            capability_id=cap_id,
            parameters=req_params,
            actor=actor,
            target_specialist_id=specialist.id,
            requirement_id=req.id,
        )
        self.event_bus.publish(
            Event(
                type="specialist.invoked",
                source="core.coordinator",
                correlation_id=investigation.id,
                payload={"specialist_id": specialist.id, "capability_id": cap_id},
            )
        )

        # 3. Process Execution Result. Evidence ingestion belongs to the executor.
        if result.status == ExecutionStatus.SUCCESS:
            req.status = RequirementStatus.SATISFIED
            ev_ids = [ev.id for ev in result.evidence]
            req.resulting_evidence_ids = ev_ids
            req.updated_at = utc_now()

            self.event_bus.publish(
                Event(
                    type="evidence.created",
                    source=f"specialist.{specialist.id}",
                    correlation_id=investigation.id,
                    payload={"count": len(ev_ids), "evidence_ids": ev_ids},
                )
            )
            self.event_bus.publish(
                Event(
                    type="requirement.completed",
                    source="core.coordinator",
                    correlation_id=investigation.id,
                    payload={"requirement_id": req.id, "status": "SATISFIED", "evidence_count": len(ev_ids)},
                )
            )

        elif result.status == ExecutionStatus.SUCCESS_EMPTY:
            req.status = RequirementStatus.SATISFIED_EMPTY
            req.updated_at = utc_now()
            self.event_bus.publish(
                Event(
                    type="requirement.completed",
                    source="core.coordinator",
                    correlation_id=investigation.id,
                    payload={"requirement_id": req.id, "status": "SATISFIED_EMPTY"},
                )
            )

        else:
            # FAILURE
            req.status = RequirementStatus.FAILED
            req.error = result.error or "Specialist reported failure"
            req.updated_at = utc_now()
            # Do NOT corrupt investigation; simply record requirement failure
            self.event_bus.publish(
                Event(
                    type="requirement.failed",
                    source="core.coordinator",
                    correlation_id=investigation.id,
                    payload={"requirement_id": req.id, "error": req.error},
                )
            )

        return req

    def correlate(self, investigation: Investigation) -> CorrelationResult:
        """Run CorrelationEngine across investigation evidence and update graph."""
        res = self.correlation_engine.correlate(
            evidence_list=investigation.evidence_store.list_all(),
            existing_entities=investigation.entities,
            investigation_id=investigation.id,
        )

        # Update entities
        new_ents = []
        for ent in res.new_entities:
            created_ent = investigation.add_entity(ent.type, ent.name, ent.attributes)
            new_ents.append(created_ent.model_dump())

        # Update relationships
        new_rels = []
        existing_rel_keys = {(r.source_id, r.target_id, r.relation_type) for r in investigation.relationships}
        for rel in res.new_relationships:
            key = (rel.source_id, rel.target_id, rel.relation_type)
            if key not in existing_rel_keys:
                investigation.relationships.append(rel)
                existing_rel_keys.add(key)
                new_rels.append(rel.model_dump())
                self.event_bus.publish(
                    Event(
                        type="relationship.created",
                        source="core.correlation",
                        correlation_id=investigation.id,
                        payload={
                            "relationship_id": rel.id,
                            "source": rel.source_id,
                            "target": rel.target_id,
                            "type": rel.relation_type,
                            "is_inferred": rel.is_inferred,
                        },
                    )
                )

        if new_ents or new_rels:
            investigation.record_journal_entry(
                entry_type="CORRELATION_COMPLETED",
                summary=f"Correlation discovered {len(new_ents)} entity/entities and {len(new_rels)} relationship(s)",
                details={"entities": new_ents, "relationships": new_rels},
            )

        # Update contradictions
        for contra in res.contradictions:
            if not any(c.description == contra.description for c in investigation.contradictions):
                investigation.contradictions.append(contra)
                investigation.record_journal_entry(
                    entry_type="CONTRADICTION_DETECTED",
                    summary=f"Contradiction detected: {contra.description}",
                    reference_id=contra.id,
                    details={"contradiction": contra.model_dump()},
                )
                self.event_bus.publish(
                    Event(
                        type="relationship.contradicted",
                        source="core.correlation",
                        correlation_id=investigation.id,
                        payload={"contradiction_id": contra.id, "subject": contra.subject, "description": contra.description},
                    )
                )

        self.event_bus.publish(
            Event(
                type="investigation.updated",
                source="core.coordinator",
                correlation_id=investigation.id,
                payload={
                    "entities_count": len(investigation.entities),
                    "relationships_count": len(investigation.relationships),
                    "contradictions_count": len(investigation.contradictions),
                },
            )
        )
        return res

    def create_hypothesis(
        self,
        investigation: Investigation,
        statement: str,
        initial_confidence: float = 0.5,
    ) -> Hypothesis:
        """Register an investigative hypothesis."""
        hyp = Hypothesis(
            investigation_id=investigation.id,
            statement=statement,
            confidence=initial_confidence,
            status="OPEN",
        )
        investigation.hypotheses[hyp.id] = hyp
        return hyp

    def evaluate_hypotheses(self, investigation: Investigation) -> List[Hypothesis]:
        """Evaluate open hypotheses based on evidence and contradictions."""
        evaluated = []
        for hyp in investigation.hypotheses.values():
            if hyp.status in ("RESOLVED", "ABANDONED"):
                continue

            # Check if any contradiction touches the hypothesis
            related_contradictions = [c for c in investigation.contradictions if c.subject.lower() in hyp.statement.lower()]
            if related_contradictions:
                hyp.status = "CONTRADICTED"
                hyp.confidence = max(0.1, hyp.confidence - 0.3)
                for c in related_contradictions:
                    for eid in c.competing_evidence_ids:
                        if eid not in hyp.refuting_evidence_ids:
                            hyp.refuting_evidence_ids.append(eid)
            else:
                # Check for corroborating evidence
                corroborating = [e for e in investigation.evidence_store.list_all() if e.subject.lower() in hyp.statement.lower()]
                if len(corroborating) >= 2:
                    hyp.status = "SUPPORTED"
                    hyp.confidence = min(0.95, hyp.confidence + 0.3)
                    for e in corroborating:
                        if e.id not in hyp.supporting_evidence_ids:
                            hyp.supporting_evidence_ids.append(e.id)

            hyp.updated_at = utc_now()
            evaluated.append(hyp)

            investigation.record_journal_entry(
                entry_type="HYPOTHESIS_EVALUATED",
                summary=f"Hypothesis '{hyp.id}' status updated to {hyp.status} (confidence: {hyp.confidence:.2f})",
                reference_id=hyp.id,
                details={"hypothesis_id": hyp.id, "status": hyp.status, "confidence": hyp.confidence},
            )

            self.event_bus.publish(
                Event(
                    type="hypothesis.updated",
                    source="core.coordinator",
                    correlation_id=investigation.id,
                    payload={"hypothesis_id": hyp.id, "status": hyp.status, "confidence": hyp.confidence},
                )
            )

        return evaluated
