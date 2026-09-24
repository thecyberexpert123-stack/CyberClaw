"""Result normalization for OSINT Specialist raw outputs into structured Evidence.

Translates heterogeneous provider formats into consistent, typed Evidence
preserving full provenance and source confidence.
"""

from __future__ import annotations

from typing import Any, Dict, List
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
    CAPABILITY_WHOIS_LOOKUP,
)
from cyberclaw.types import Source


class OSINTNormalizer:
    """Normalizes raw provider outputs into standardized Evidence objects."""

    @staticmethod
    def normalize_domain_metadata(
        raw_data: Dict[str, Any],
        target: str,
        provider_id: str,
        specialist_id: str = "osint_specialist",
        context: ExecutionContext | None = None,
    ) -> List[Evidence]:
        """Normalize domain metadata raw result into structured evidence."""
        if not raw_data:
            return []

        source = Source(type="osint_provider", name=provider_id, reliability=0.95)
        prov = Provenance(
            execution_id=context.execution_id if context else "",
            investigation_id=context.investigation_id if context else None,
            specialist_id=specialist_id,
            provider_id=provider_id,
            capability_id=CAPABILITY_DOMAIN_METADATA,
            parameters={"target": target},
        )

        ev = Evidence(
            type="osint.domain_metadata",
            subject=target,
            value={
                "domain": target,
                "registrar": raw_data.get("registrar", "Unknown"),
                "status": raw_data.get("status", []),
                "nameservers": raw_data.get("nameservers", []),
                "creation_date": raw_data.get("creation_date"),
                "expiration_date": raw_data.get("expiration_date"),
            },
            source=source,
            provenance=prov,
            confidence=0.95,
        )
        return [ev]

    @staticmethod
    def normalize_dns_records(
        raw_data: Dict[str, Any],
        target: str,
        provider_id: str,
        specialist_id: str = "osint_specialist",
        context: ExecutionContext | None = None,
    ) -> List[Evidence]:
        """Normalize DNS records into structured evidence."""
        records = raw_data.get("records", {})
        if not records:
            return []

        source = Source(type="osint_provider", name=provider_id, reliability=0.98)
        prov = Provenance(
            execution_id=context.execution_id if context else "",
            investigation_id=context.investigation_id if context else None,
            specialist_id=specialist_id,
            provider_id=provider_id,
            capability_id=CAPABILITY_DNS_LOOKUP,
            parameters={"target": target},
        )

        evidence_items: List[Evidence] = []
        for rtype, values in records.items():
            if values:
                evidence_items.append(
                    Evidence(
                        type="osint.dns_record",
                        subject=target,
                        value={"record_type": rtype, "values": values},
                        source=source,
                        provenance=prov,
                        confidence=0.98,
                    )
                )
        return evidence_items

    @staticmethod
    def normalize_cert_metadata(
        raw_data: Dict[str, Any],
        target: str,
        provider_id: str,
        specialist_id: str = "osint_specialist",
        context: ExecutionContext | None = None,
    ) -> List[Evidence]:
        """Normalize certificate metadata into structured evidence."""
        if not raw_data:
            return []

        source = Source(type="osint_provider", name=provider_id, reliability=0.99)
        prov = Provenance(
            execution_id=context.execution_id if context else "",
            investigation_id=context.investigation_id if context else None,
            specialist_id=specialist_id,
            provider_id=provider_id,
            capability_id=CAPABILITY_CERT_METADATA,
            parameters={"target": target},
        )

        ev = Evidence(
            type="osint.certificate",
            subject=target,
            value={
                "subject": raw_data.get("subject", target),
                "issuer": raw_data.get("issuer", "Unknown"),
                "sans": raw_data.get("sans", []),
                "valid_from": raw_data.get("valid_from"),
                "valid_until": raw_data.get("valid_until"),
                "serial_number": raw_data.get("serial_number"),
            },
            source=source,
            provenance=prov,
            confidence=0.99,
        )
        return [ev]

    @staticmethod
    def normalize_whois_data(
        raw_data: Dict[str, Any],
        target: str,
        provider_id: str,
        specialist_id: str = "osint_specialist",
        context: ExecutionContext | None = None,
    ) -> List[Evidence]:
        """Normalize WHOIS lookup output into structured evidence."""
        if not raw_data:
            return []

        source = Source(type="osint_provider", name=provider_id, reliability=0.90)
        prov = Provenance(
            execution_id=context.execution_id if context else "",
            investigation_id=context.investigation_id if context else None,
            specialist_id=specialist_id,
            provider_id=provider_id,
            capability_id=CAPABILITY_WHOIS_LOOKUP,
            parameters={"target": target},
        )

        ev = Evidence(
            type="osint.whois",
            subject=target,
            value={
                "registrant_org": raw_data.get("registrant_org", "REDACTED"),
                "registrant_country": raw_data.get("registrant_country", "Unknown"),
                "admin_email": raw_data.get("admin_email"),
                "raw_whois": raw_data.get("raw_whois", ""),
            },
            source=source,
            provenance=prov,
            confidence=0.90,
        )
        return [ev]
