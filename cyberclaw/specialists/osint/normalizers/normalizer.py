"""Result normalization for OSINT Specialist raw outputs into structured Evidence.

Provider output becomes observations. Missing fields stay missing. This module
does not infer relationships or invent provenance.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional, Tuple

from cyberclaw.authority.dispatch import governed_dispatch
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
    CAPABILITY_WHOIS_LOOKUP,
)
from cyberclaw.types import Source


def _present(raw_data: Dict[str, Any], field: str) -> bool:
    value = raw_data.get(field)
    return value is not None and value != "" and value != []


def _copy_present(raw_data: Dict[str, Any], fields: List[str]) -> Tuple[Dict[str, Any], List[str]]:
    value: Dict[str, Any] = {}
    missing: List[str] = []
    for field in fields:
        if _present(raw_data, field):
            value[field] = raw_data[field]
        else:
            missing.append(field)
    return value, missing


class OSINTNormalizer:
    """Normalizes raw provider outputs into standardized observation evidence."""

    @staticmethod
    def normalize(
        capability_id: str,
        raw_data: Dict[str, Any],
        target: str,
        provider_id: str,
        context: ExecutionContext | None = None,
        specialist_id: str = "osint_specialist",
        provider_version: Optional[str] = None,
        source_reference: Optional[str] = None,
        collected_at: Optional[str] = None,
    ) -> List[Evidence]:
        """Dispatch to the capability normalizer. Unknown capabilities fail closed."""
        if capability_id == CAPABILITY_DOMAIN_METADATA:
            evidence = OSINTNormalizer.normalize_domain_metadata(
                raw_data, target, provider_id, specialist_id, context
            )
        elif capability_id == CAPABILITY_DNS_LOOKUP:
            evidence = OSINTNormalizer.normalize_dns_records(
                raw_data, target, provider_id, specialist_id, context
            )
        elif capability_id == CAPABILITY_CERT_METADATA:
            evidence = OSINTNormalizer.normalize_cert_metadata(
                raw_data, target, provider_id, specialist_id, context
            )
        elif capability_id == CAPABILITY_WHOIS_LOOKUP:
            evidence = OSINTNormalizer.normalize_whois_data(
                raw_data, target, provider_id, specialist_id, context
            )
        else:
            raise ValueError(f"No OSINT normalizer for capability '{capability_id}'.")
        return [
            OSINTNormalizer.enrich(
                item,
                context,
                provider_version=provider_version,
                source_reference=source_reference,
                collected_at=collected_at,
            )
            for item in evidence
        ]

    @staticmethod
    def enrich(
        evidence: Evidence,
        context: ExecutionContext | None,
        *,
        provider_version: Optional[str] = None,
        source_reference: Optional[str] = None,
        collected_at: Optional[str] = None,
    ) -> Evidence:
        """Attach collection facts that were actually supplied. Do not invent them."""
        stamp = governed_dispatch(context) if context is not None else None
        encoded = json.dumps(evidence.value, sort_keys=True, default=str, separators=(",", ":"))
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        metadata = dict(evidence.metadata)
        metadata["finding_nature"] = "OBSERVATION"
        metadata["integrity_digest"] = digest
        if provider_version:
            metadata["provider_version"] = provider_version
        else:
            metadata["provider_version_missing"] = True
        if source_reference:
            metadata["source_reference"] = source_reference
            evidence.source.location = source_reference
        else:
            metadata["source_reference_missing"] = True
        if collected_at:
            metadata["collection_timestamp"] = collected_at
        else:
            metadata["collection_timestamp_missing"] = True
        if stamp:
            metadata["authorization_decision_id"] = stamp["authorization_decision_id"]
            metadata["policy_id"] = stamp["policy_id"]
            metadata["policy_version"] = stamp["policy_version"]
            metadata["capability_version"] = stamp["capability_version"]
            metadata["requirement_id"] = stamp.get("requirement_id")
            metadata["task_id"] = stamp.get("task_id")
            metadata["actor"] = stamp["actor"]
        else:
            metadata["authorization_decision_id_missing"] = True
        evidence.metadata = metadata
        provenance = evidence.provenance.model_copy(deep=True)
        environment = dict(provenance.environment)
        environment["finding_nature"] = "OBSERVATION"
        if stamp:
            environment["authorization_decision_id"] = stamp["authorization_decision_id"]
            environment["policy_id"] = stamp["policy_id"]
            environment["policy_version"] = stamp["policy_version"]
        provenance.environment = environment
        evidence.provenance = provenance
        return evidence

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

        value, missing = _copy_present(
            raw_data,
            ["registrar", "status", "nameservers", "creation_date", "expiration_date"],
        )
        value["domain"] = target
        source = Source(type="osint_provider", name=provider_id, reliability=0.95)
        evidence = Evidence(
            type="osint.domain_metadata",
            subject=target,
            value=value,
            source=source,
            provenance=_provenance(context, specialist_id, provider_id, CAPABILITY_DOMAIN_METADATA, target),
            confidence=0.95,
            metadata={"missing_fields": missing} if missing else {},
        )
        return [evidence]

    @staticmethod
    def normalize_dns_records(
        raw_data: Dict[str, Any],
        target: str,
        provider_id: str,
        specialist_id: str = "osint_specialist",
        context: ExecutionContext | None = None,
    ) -> List[Evidence]:
        """Normalize DNS records into one observation per record type."""
        records = raw_data.get("records", {})
        if not isinstance(records, dict):
            raise ValueError("DNS records payload must be an object.")
        if not records:
            return []

        source = Source(type="osint_provider", name=provider_id, reliability=0.98)
        evidence_items: List[Evidence] = []
        for rtype, values in records.items():
            if values:
                evidence_items.append(
                    Evidence(
                        type="osint.dns_record",
                        subject=target,
                        value={"record_type": rtype, "values": values},
                        source=source.model_copy(deep=True),
                        provenance=_provenance(context, specialist_id, provider_id, CAPABILITY_DNS_LOOKUP, target),
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
        """Normalize certificate metadata into an observation. Missing fields stay missing."""
        if not raw_data:
            return []

        value, missing = _copy_present(
            raw_data,
            ["subject", "issuer", "sans", "valid_from", "valid_until", "serial_number"],
        )
        if "subject" not in value:
            value["subject"] = target
            missing = [field for field in missing if field != "subject"]
        source = Source(type="osint_provider", name=provider_id, reliability=0.99)
        evidence = Evidence(
            type="osint.certificate",
            subject=target,
            value=value,
            source=source,
            provenance=_provenance(context, specialist_id, provider_id, CAPABILITY_CERT_METADATA, target),
            confidence=0.99,
            metadata={"missing_fields": missing} if missing else {},
        )
        return [evidence]

    @staticmethod
    def normalize_whois_data(
        raw_data: Dict[str, Any],
        target: str,
        provider_id: str,
        specialist_id: str = "osint_specialist",
        context: ExecutionContext | None = None,
    ) -> List[Evidence]:
        """Normalize registration data. Absent registrant fields are not filled in."""
        if not raw_data:
            return []

        value, missing = _copy_present(
            raw_data,
            ["registrant_org", "registrant_country", "admin_email", "raw_whois"],
        )
        if not value:
            return []
        source = Source(type="osint_provider", name=provider_id, reliability=0.90)
        evidence = Evidence(
            type="osint.whois",
            subject=target,
            value=value,
            source=source,
            provenance=_provenance(context, specialist_id, provider_id, CAPABILITY_WHOIS_LOOKUP, target),
            confidence=0.90,
            metadata={"missing_fields": missing} if missing else {},
        )
        return [evidence]


def _provenance(
    context: ExecutionContext | None,
    specialist_id: str,
    provider_id: str,
    capability_id: str,
    target: str,
) -> Provenance:
    return Provenance(
        execution_id=context.execution_id if context else "",
        investigation_id=context.investigation_id if context else None,
        specialist_id=specialist_id,
        provider_id=provider_id,
        capability_id=capability_id,
        parameters={"target": target},
    )
