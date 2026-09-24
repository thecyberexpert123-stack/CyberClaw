"""Deterministic planning rules identifying information gaps, contradictions, and hypothesis tests."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Set, Tuple
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.coordination.requirements import RequirementStatus
from cyberclaw.investigation import Investigation
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import (
    CapabilityGap,
    InformationValueDimension,
    RequirementCandidate,
    UncertaintyType,
)
from cyberclaw.specialists.registry import SpecialistRegistry


class PlanningRule(ABC):
    """Abstract base class for deterministic planning rules."""

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description

    @abstractmethod
    def evaluate(
        self,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        satisfied_keys: Set[str],
    ) -> Tuple[List[RequirementCandidate], List[CapabilityGap]]:
        """Evaluate investigation state and produce candidate requirements and capability gaps."""
        pass


class EntityEnrichmentPlanningRule(PlanningRule):
    """Identifies newly discovered entities lacking baseline intelligence coverage."""

    def __init__(self) -> None:
        super().__init__(
            name="entity_enrichment",
            description="Proposes information gathering for entities with missing operational context.",
        )

    def evaluate(
        self,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        satisfied_keys: Set[str],
    ) -> Tuple[List[RequirementCandidate], List[CapabilityGap]]:
        candidates: List[RequirementCandidate] = []
        gaps: List[CapabilityGap] = []

        # Available capabilities across registered specialists
        available_caps: Set[str] = set()
        for s in specialists.list_specialists():
            available_caps.update(s.capabilities)

        # 1. IP Entities: Check for network service / port information
        for entity in investigation.entities.values():
            if entity.type == "ip":
                ip = entity.name
                dedup_key = f"{investigation.id}:{ip}:network.port_scan:"

                # Check if port scan already exists or has been executed
                has_port_ev = any(
                    e.subject == ip and ("port" in e.type or "service" in e.type or "network" in e.type)
                    for e in investigation.evidence_store.list_all()
                )

                if not has_port_ev and dedup_key not in satisfied_keys:
                    # Check if capability is available
                    if "network.port_scan" in available_caps:
                        candidates.append(
                            RequirementCandidate(
                                target_or_entity=ip,
                                requested_evidence_types=["network.port_scan"],
                                required_capability="network.port_scan",
                                purpose=f"Obtain network port and service exposure for IP {ip}",
                                value_dimension=InformationValueDimension.ENTITY_ENRICHMENT,
                                uncertainty_type=UncertaintyType.INCOMPLETE,
                                priority=40,
                                expected_information_value="Identifies active listener services and perimeter attack surface.",
                                permission_requirements=["network:read"],
                                risk_classification=ActionScope.REVERSIBLE,
                            )
                        )
                    else:
                        gaps.append(
                            CapabilityGap(
                                investigation_id=investigation.id,
                                target_or_entity=ip,
                                desired_evidence_type="network.port_scan",
                                reason="IP entity discovered but no authorized network port scanning capability is available.",
                            )
                        )

            # 2. Domain Entities: Check for TLS certificate metadata
            elif entity.type in ("domain", "fqdn"):
                domain = entity.name
                dedup_key = f"{investigation.id}:{domain}:osint.cert_metadata:"

                has_cert_ev = any(
                    e.subject == domain and "cert" in e.type
                    for e in investigation.evidence_store.list_all()
                )

                if not has_cert_ev and dedup_key not in satisfied_keys:
                    if "osint.cert_metadata" in available_caps:
                        candidates.append(
                            RequirementCandidate(
                                target_or_entity=domain,
                                requested_evidence_types=["osint.certificate"],
                                required_capability="osint.cert_metadata",
                                purpose=f"Retrieve TLS certificate identity and SANs for domain {domain}",
                                value_dimension=InformationValueDimension.MISSING_EVIDENCE,
                                uncertainty_type=UncertaintyType.UNKNOWN,
                                priority=50,
                                expected_information_value="Identifies certificate authority, validity, and co-associated SAN domains.",
                                permission_requirements=["network:read"],
                                risk_classification=ActionScope.REVERSIBLE,
                            )
                        )
                    else:
                        gaps.append(
                            CapabilityGap(
                                investigation_id=investigation.id,
                                target_or_entity=domain,
                                desired_evidence_type="osint.cert_metadata",
                                reason="Domain discovered but no certificate lookup capability is registered.",
                            )
                        )

        return candidates, gaps


class ContradictionResolutionPlanningRule(PlanningRule):
    """Proposes corroborating requirements when conflicting evidence is detected."""

    def __init__(self) -> None:
        super().__init__(
            name="contradiction_resolution",
            description="Proposes targeted verification requirements when conflicting observations exist.",
        )

    def evaluate(
        self,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        satisfied_keys: Set[str],
    ) -> Tuple[List[RequirementCandidate], List[CapabilityGap]]:
        candidates: List[RequirementCandidate] = []
        gaps: List[CapabilityGap] = []

        for contra in investigation.contradictions:
            if contra.resolved:
                continue

            target = contra.subject
            dedup_key = f"{investigation.id}:{target}:corroboration:whois"

            if dedup_key not in satisfied_keys:
                # Propose authoritative WHOIS or certificate check to help resolve the ambiguity
                available_caps = {cap for s in specialists.list_specialists() for cap in s.capabilities}
                if "osint.whois_lookup" in available_caps:
                    candidates.append(
                        RequirementCandidate(
                            target_or_entity=target,
                            requested_evidence_types=["osint.whois"],
                            required_capability="osint.whois_lookup",
                            purpose=f"Resolve contradiction '{contra.conflict_type}' on {target} via independent registrar records",
                            value_dimension=InformationValueDimension.CONTRADICTION_RESOLUTION,
                            uncertainty_type=UncertaintyType.CONTRADICTED,
                            supporting_evidence_ids=contra.competing_evidence_ids,
                            priority=20,  # High priority to resolve conflict
                            expected_information_value="Provides authoritative registration ownership to adjudicate contradictory observations.",
                            permission_requirements=["network:read"],
                        )
                    )
                else:
                    gaps.append(
                        CapabilityGap(
                            investigation_id=investigation.id,
                            target_or_entity=target,
                            desired_evidence_type="osint.whois",
                            reason=f"Unresolved contradiction on '{target}' but no WHOIS capability exists to adjudicate.",
                        )
                    )

        return candidates, gaps


class HypothesisTestingPlanningRule(PlanningRule):
    """Proposes both supporting and disconfirming requirements for open hypotheses."""

    def __init__(self) -> None:
        super().__init__(
            name="hypothesis_testing",
            description="Generates balanced confirmatory and disconfirmatory information needs for hypotheses.",
        )

    def evaluate(
        self,
        investigation: Investigation,
        specialists: SpecialistRegistry,
        capabilities: CapabilityRegistry,
        satisfied_keys: Set[str],
    ) -> Tuple[List[RequirementCandidate], List[CapabilityGap]]:
        candidates: List[RequirementCandidate] = []
        gaps: List[CapabilityGap] = []

        available_caps = {cap for s in specialists.list_specialists() for cap in s.capabilities}

        for hyp in investigation.hypotheses.values():
            if hyp.status != "OPEN":
                continue

            # Check if hypothesis references targets
            for target in investigation.targets:
                if target.lower() in hyp.statement.lower():
                    # 1. Propose supporting evidence candidate (e.g. DNS)
                    sup_key = f"{investigation.id}:{target}:dns_support:"
                    if sup_key not in satisfied_keys and "osint.dns_lookup" in available_caps:
                        candidates.append(
                            RequirementCandidate(
                                target_or_entity=target,
                                requested_evidence_types=["osint.dns_record"],
                                required_capability="osint.dns_lookup",
                                purpose=f"Seek supporting corroboration for hypothesis '{hyp.id}' on {target}",
                                value_dimension=InformationValueDimension.HYPOTHESIS_SUPPORT,
                                uncertainty_type=UncertaintyType.UNCONFIRMED,
                                supporting_hypothesis_ids=[hyp.id],
                                priority=30,
                                expected_information_value="Verifies whether target actively resolves on internet routing.",
                                permission_requirements=["network:read"],
                            )
                        )

                    # 2. Propose disconfirming evidence candidate (avoiding confirmation bias!)
                    dis_key = f"{investigation.id}:{target}:whois_disconfirm:"
                    if dis_key not in satisfied_keys and "osint.whois_lookup" in available_caps:
                        candidates.append(
                            RequirementCandidate(
                                target_or_entity=target,
                                requested_evidence_types=["osint.whois"],
                                required_capability="osint.whois_lookup",
                                purpose=f"Seek potentially refuting registration evidence for hypothesis '{hyp.id}' on {target}",
                                value_dimension=InformationValueDimension.HYPOTHESIS_DISCONFIRMATION,
                                uncertainty_type=UncertaintyType.AMBIGUOUS,
                                supporting_hypothesis_ids=[hyp.id],
                                priority=35,
                                expected_information_value="Tests whether entity ownership refutes assumed infrastructure control.",
                                permission_requirements=["network:read"],
                            )
                        )

        return candidates, gaps
