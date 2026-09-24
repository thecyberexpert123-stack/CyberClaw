"""Structured evidence handoff, provenance tracking, and epistemological classification."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional
from uuid import uuid4
from cyberclaw.collaboration.errors import EvidenceNormalizationError
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    CollaborationResult,
    FindingNature,
    utc_now,
)
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.types import Source

if TYPE_CHECKING:
    from cyberclaw.investigation import Investigation


class EvidenceHandoffNormalizer:
    """Normalizes specialist collaboration findings into structured evidence while strictly preserving provenance and epistemic nature."""

    @classmethod
    def normalize_result(
        cls,
        result: CollaborationResult,
        request: CollaborationRequest,
        capability_id: str,
        capability_version: str = "1.0.0",
        provider_id: Optional[str] = None,
        authorization_decision_id: Optional[str] = None,
    ) -> List[Evidence]:
        """Convert collaboration result items into immutable Evidence instances with complete lineage."""
        normalized_evidence: List[Evidence] = []

        # 1. Process explicit Evidence items in result
        for ev in result.evidence:
            cls._ensure_lineage(
                ev=ev,
                request=request,
                responding_specialist=result.responding_specialist,
                capability_id=capability_id,
                capability_version=capability_version,
                provider_id=provider_id,
                authorization_decision_id=authorization_decision_id,
                finding_nature=FindingNature.OBSERVATION,
            )
            normalized_evidence.append(ev)

        # 2. Process observations (direct empirical observations)
        for obs in result.observations:
            ev = Evidence(
                type="observation.empirical",
                subject=obs.get("subject", request.objective),
                value=obs.get("data", obs),
                source=Source(
                    type="specialist_observation",
                    name=result.responding_specialist,
                    reliability=float(obs.get("reliability", 1.0)),
                ),
                confidence=float(obs.get("confidence", 1.0)),
            )
            cls._ensure_lineage(
                ev=ev,
                request=request,
                responding_specialist=result.responding_specialist,
                capability_id=capability_id,
                capability_version=capability_version,
                provider_id=provider_id,
                authorization_decision_id=authorization_decision_id,
                finding_nature=FindingNature.OBSERVATION,
            )
            normalized_evidence.append(ev)

        # 3. Process inferences (deductive conclusions - NEVER converted to observations)
        for inf in result.inferences:
            ev = Evidence(
                type="inference.specialist",
                subject=inf.get("subject", request.objective),
                value=inf.get("conclusion", inf),
                source=Source(
                    type="specialist_inference",
                    name=result.responding_specialist,
                    reliability=float(inf.get("reliability", 0.8)),
                ),
                confidence=float(inf.get("confidence", 0.75)),
            )
            cls._ensure_lineage(
                ev=ev,
                request=request,
                responding_specialist=result.responding_specialist,
                capability_id=capability_id,
                capability_version=capability_version,
                provider_id=provider_id,
                authorization_decision_id=authorization_decision_id,
                finding_nature=FindingNature.INFERENCE,
            )
            ev.metadata["is_inferred"] = True
            ev.metadata["premises"] = inf.get("premises", [])
            normalized_evidence.append(ev)

        # 4. Process correlations
        for corr in result.correlations:
            ev = Evidence(
                type="correlation.finding",
                subject=corr.get("subject", request.objective),
                value=corr.get("relationship", corr),
                source=Source(
                    type="specialist_correlation",
                    name=result.responding_specialist,
                    reliability=float(corr.get("reliability", 0.85)),
                ),
                confidence=float(corr.get("confidence", 0.8)),
            )
            cls._ensure_lineage(
                ev=ev,
                request=request,
                responding_specialist=result.responding_specialist,
                capability_id=capability_id,
                capability_version=capability_version,
                provider_id=provider_id,
                authorization_decision_id=authorization_decision_id,
                finding_nature=FindingNature.CORRELATION,
            )
            normalized_evidence.append(ev)

        # 5. Process hypotheses
        for hyp in result.hypotheses:
            ev = Evidence(
                type="hypothesis.specialist",
                subject=hyp.get("subject", request.objective),
                value=hyp.get("claim", hyp),
                source=Source(
                    type="specialist_hypothesis",
                    name=result.responding_specialist,
                    reliability=float(hyp.get("reliability", 0.6)),
                ),
                confidence=float(hyp.get("confidence", 0.5)),
            )
            cls._ensure_lineage(
                ev=ev,
                request=request,
                responding_specialist=result.responding_specialist,
                capability_id=capability_id,
                capability_version=capability_version,
                provider_id=provider_id,
                authorization_decision_id=authorization_decision_id,
                finding_nature=FindingNature.HYPOTHESIS,
            )
            normalized_evidence.append(ev)

        # 6. Process negative findings
        for neg in result.negative_findings:
            ev = Evidence(
                type="negative_finding.specialist",
                subject=neg.get("subject", request.objective),
                value=neg.get("details", neg),
                source=Source(
                    type="specialist_negative_finding",
                    name=result.responding_specialist,
                    reliability=float(neg.get("reliability", 0.9)),
                ),
                confidence=float(neg.get("confidence", 0.9)),
            )
            cls._ensure_lineage(
                ev=ev,
                request=request,
                responding_specialist=result.responding_specialist,
                capability_id=capability_id,
                capability_version=capability_version,
                provider_id=provider_id,
                authorization_decision_id=authorization_decision_id,
                finding_nature=FindingNature.NEGATIVE_FINDING,
            )
            normalized_evidence.append(ev)

        # 7. Process failures
        for fail in result.failures:
            ev = Evidence(
                type="failure.specialist",
                subject=fail.get("subject", request.objective),
                value=fail.get("error", fail),
                source=Source(
                    type="specialist_failure",
                    name=result.responding_specialist,
                    reliability=0.0,
                ),
                confidence=0.0,
            )
            cls._ensure_lineage(
                ev=ev,
                request=request,
                responding_specialist=result.responding_specialist,
                capability_id=capability_id,
                capability_version=capability_version,
                provider_id=provider_id,
                authorization_decision_id=authorization_decision_id,
                finding_nature=FindingNature.FAILURE,
            )
            normalized_evidence.append(ev)

        return normalized_evidence

    @classmethod
    def _ensure_lineage(
        cls,
        ev: Evidence,
        request: CollaborationRequest,
        responding_specialist: str,
        capability_id: str,
        capability_version: str,
        provider_id: Optional[str],
        authorization_decision_id: Optional[str],
        finding_nature: FindingNature,
    ) -> None:
        """Inject full provenance metadata and causal links."""
        if not ev.provenance:
            ev.provenance = Provenance()

        ev.provenance.investigation_id = request.investigation_id
        ev.provenance.specialist_id = responding_specialist
        ev.provenance.capability_id = capability_id
        ev.provenance.provider_id = provider_id

        # Collaboration specific provenance in metadata
        ev.metadata.update({
            "finding_nature": finding_nature.value,
            "collaboration_request_id": request.request_id,
            "originating_request_id": request.request_id,
            "requesting_specialist": request.requesting_specialist,
            "responding_specialist": responding_specialist,
            "capability_version": capability_version,
            "authorization_decision_id": authorization_decision_id or request.authorization_decision_id,
            "derived_from_evidence_ids": list(request.input_evidence_ids),
            "information_requirement_id": request.information_requirement_id,
        })
