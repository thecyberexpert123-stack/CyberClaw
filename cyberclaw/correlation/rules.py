"""Generic and deterministic correlation rules for the Correlation Engine."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Tuple
from cyberclaw.correlation.models import ContradictionRecord, CorrelationProvenance
from cyberclaw.evidence.models import Evidence
from cyberclaw.types import Entity, Relationship


class CorrelationRule(ABC):
    """Abstract base class for pluggable correlation rules."""

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description

    @abstractmethod
    def evaluate(
        self,
        evidence_list: List[Evidence],
        existing_entities: Dict[str, Entity],
        investigation_id: str,
    ) -> Tuple[List[Entity], List[Relationship], List[ContradictionRecord]]:
        """Evaluate evidence list and yield new entities, relationships, and contradictions."""
        pass


class DnsResolutionCorrelationRule(CorrelationRule):
    """Correlates DNS evidence into Domain and IP entities and observed 'resolves_to' relationships."""

    def __init__(self) -> None:
        super().__init__(
            name="dns_resolution_correlation",
            description="Extracts IP entities and observed resolves_to links from DNS evidence.",
        )

    def evaluate(
        self,
        evidence_list: List[Evidence],
        existing_entities: Dict[str, Entity],
        investigation_id: str,
    ) -> Tuple[List[Entity], List[Relationship], List[ContradictionRecord]]:
        new_entities: List[Entity] = []
        new_relationships: List[Relationship] = []
        contradictions: List[ContradictionRecord] = []

        # Filter DNS record evidence
        dns_evidence = [e for e in evidence_list if "dns" in e.type.lower()]

        # Track domain and record_type to IPs to check for contradictory resolutions (e.g. conflicting A records)
        domain_rtype_ip_map: Dict[Tuple[str, str], List[Tuple[str, str]]] = {}  # (domain, rtype) -> list of (ip, evidence_id)

        for ev in dns_evidence:
            domain = ev.subject
            records: Dict[str, List[str]] = {}
            if isinstance(ev.value, dict):
                if "values" in ev.value and ev.value.get("record_type") in ("A", "AAAA"):
                    records[ev.value["record_type"]] = ev.value["values"]
                elif "records" in ev.value:
                    records = ev.value["records"]

            # Add domain entity if not existing
            if domain not in existing_entities and not any(e.name == domain for e in new_entities):
                new_entities.append(
                    Entity(type="domain", name=domain, attributes={"source": "dns_evidence"})
                )

            for rtype in ("A", "AAAA"):
                ip_list = records.get(rtype, [])
                for ip in ip_list:
                    # Add IP entity
                    if ip not in existing_entities and not any(e.name == ip for e in new_entities):
                        new_entities.append(Entity(type="ip", name=ip, attributes={"address": ip}))

                    domain_rtype_ip_map.setdefault((domain, rtype), []).append((ip, ev.id))

                    # Observed relationship
                    prov = CorrelationProvenance(
                        rule_name=self.name,
                        specialists_involved=[ev.provenance.specialist_id] if ev.provenance.specialist_id else [],
                        capabilities_involved=[ev.provenance.capability_id] if ev.provenance.capability_id else [],
                        investigation_id=investigation_id,
                    )
                    rel = Relationship(
                        source_id=domain,
                        target_id=ip,
                        relation_type="resolves_to",
                        is_inferred=False,  # Directly observed in DNS record
                        supporting_evidence_ids=[ev.id],
                        confidence=ev.confidence,
                        metadata={"record_type": rtype, "provenance": prov.model_dump()},
                    )
                    new_relationships.append(rel)

        # Check for genuine contradictions: multiple divergent IPs for the SAME record type from competing evidence
        for (domain, rtype), ip_tuples in domain_rtype_ip_map.items():
            unique_ips = list({t[0] for t in ip_tuples})
            ev_ids = list({t[1] for t in ip_tuples})
            if len(unique_ips) > 1 and len(ev_ids) > 1:
                contradictions.append(
                    ContradictionRecord(
                        investigation_id=investigation_id,
                        subject=domain,
                        conflict_type=f"conflicting_{rtype}_resolution",
                        competing_evidence_ids=ev_ids,
                        description=f"Domain '{domain}' resolved to conflicting {rtype} addresses {unique_ips} across evidence sources.",
                    )
                )

        return new_entities, new_relationships, contradictions


class CertificateIdentityCorrelationRule(CorrelationRule):
    """Correlates TLS certificate evidence into Certificate entities and observed domain associations."""

    def __init__(self) -> None:
        super().__init__(
            name="certificate_identity_correlation",
            description="Extracts Certificate entities and authenticates_identity relationships.",
        )

    def evaluate(
        self,
        evidence_list: List[Evidence],
        existing_entities: Dict[str, Entity],
        investigation_id: str,
    ) -> Tuple[List[Entity], List[Relationship], List[ContradictionRecord]]:
        new_entities: List[Entity] = []
        new_relationships: List[Relationship] = []
        cert_evidence = [e for e in evidence_list if "cert" in e.type.lower()]

        for ev in cert_evidence:
            val = ev.value if isinstance(ev.value, dict) else {}
            cert_name = val.get("serial_number") or f"cert:{ev.subject}"

            if cert_name not in existing_entities and not any(e.name == cert_name for e in new_entities):
                new_entities.append(
                    Entity(
                        type="certificate",
                        name=cert_name,
                        attributes={
                            "issuer": val.get("issuer"),
                            "valid_until": val.get("valid_until"),
                        },
                    )
                )

            # Link certificate to subject and all SANs
            sans = val.get("sans", [ev.subject])
            for san in sans:
                if san not in existing_entities and not any(e.name == san for e in new_entities):
                    new_entities.append(Entity(type="domain", name=san, attributes={"discovered_via": "cert_san"}))

                prov = CorrelationProvenance(
                    rule_name=self.name,
                    specialists_involved=[ev.provenance.specialist_id] if ev.provenance.specialist_id else [],
                    capabilities_involved=[ev.provenance.capability_id] if ev.provenance.capability_id else [],
                    investigation_id=investigation_id,
                )
                rel = Relationship(
                    source_id=cert_name,
                    target_id=san,
                    relation_type="authenticates_identity",
                    is_inferred=False,  # Observed in certificate definition
                    supporting_evidence_ids=[ev.id],
                    confidence=ev.confidence,
                    metadata={"provenance": prov.model_dump()},
                )
                new_relationships.append(rel)

        return new_entities, new_relationships, []


class NetworkServiceCorrelationRule(CorrelationRule):
    """Correlates network scanning evidence into Service/Port entities and exposes_service links."""

    def __init__(self) -> None:
        super().__init__(
            name="network_service_correlation",
            description="Extracts port/service entities from network scan evidence.",
        )

    def evaluate(
        self,
        evidence_list: List[Evidence],
        existing_entities: Dict[str, Entity],
        investigation_id: str,
    ) -> Tuple[List[Entity], List[Relationship], List[ContradictionRecord]]:
        new_entities: List[Entity] = []
        new_relationships: List[Relationship] = []
        net_evidence = [e for e in evidence_list if "network" in e.type.lower() or "port" in e.type.lower()]

        for ev in net_evidence:
            ip = ev.subject
            val = ev.value if isinstance(ev.value, dict) else {}

            ports = val.get("open_ports", [])
            for port in ports:
                service_entity_name = f"{ip}:{port}"
                if service_entity_name not in existing_entities and not any(e.name == service_entity_name for e in new_entities):
                    new_entities.append(
                        Entity(
                            type="service",
                            name=service_entity_name,
                            attributes={"port": port, "ip": ip},
                        )
                    )

                prov = CorrelationProvenance(
                    rule_name=self.name,
                    specialists_involved=[ev.provenance.specialist_id] if ev.provenance.specialist_id else [],
                    capabilities_involved=[ev.provenance.capability_id] if ev.provenance.capability_id else [],
                    investigation_id=investigation_id,
                )
                rel = Relationship(
                    source_id=ip,
                    target_id=service_entity_name,
                    relation_type="exposes_service",
                    is_inferred=False,  # Directly observed by probe
                    supporting_evidence_ids=[ev.id],
                    confidence=ev.confidence,
                    metadata={"provenance": prov.model_dump()},
                )
                new_relationships.append(rel)

        return new_entities, new_relationships, []


class SharedInfrastructureCorrelationRule(CorrelationRule):
    """Infers co-location or infrastructure sharing between multiple targets sharing the same IP."""

    def __init__(self) -> None:
        super().__init__(
            name="shared_infrastructure_inference",
            description="Infers shared_infrastructure relationships when distinct domains resolve to the same IP.",
        )

    def evaluate(
        self,
        evidence_list: List[Evidence],
        existing_entities: Dict[str, Entity],
        investigation_id: str,
    ) -> Tuple[List[Entity], List[Relationship], List[ContradictionRecord]]:
        new_relationships: List[Relationship] = []

        # Find all domain -> IP mappings
        ip_to_domains: Dict[str, List[Tuple[str, str]]] = {}  # ip -> list of (domain, evidence_id)

        dns_evidence = [e for e in evidence_list if "dns" in e.type.lower()]
        for ev in dns_evidence:
            domain = ev.subject
            val = ev.value if isinstance(ev.value, dict) else {}
            ips = []
            if "records" in val and isinstance(val["records"], dict):
                ips = val["records"].get("A", []) + val["records"].get("AAAA", [])
            elif "values" in val and isinstance(val["values"], list):
                ips = val["values"]

            for ip in ips:
                ip_to_domains.setdefault(ip, []).append((domain, ev.id))

        # Where 2+ distinct domains share an IP, produce an INFERRED relationship
        for ip, domain_tuples in ip_to_domains.items():
            unique_domains = list({t[0] for t in domain_tuples})
            if len(unique_domains) >= 2:
                # Pairwise relationships
                for i in range(len(unique_domains)):
                    for j in range(i + 1, len(unique_domains)):
                        d1 = unique_domains[i]
                        d2 = unique_domains[j]
                        all_ev_ids = [t[1] for t in domain_tuples if t[0] in (d1, d2)]

                        prov = CorrelationProvenance(
                            rule_name=self.name,
                            investigation_id=investigation_id,
                            context={"shared_ip": ip},
                        )

                        # INFERRED relationship
                        rel = Relationship(
                            source_id=d1,
                            target_id=d2,
                            relation_type="inferred_shared_infrastructure",
                            is_inferred=True,  # Mandatory distinction!
                            supporting_evidence_ids=all_ev_ids,
                            confidence=0.75,  # Inferred confidence lower than direct observation
                            metadata={"shared_ip": ip, "provenance": prov.model_dump()},
                        )
                        new_relationships.append(rel)

        return [], new_relationships, []
