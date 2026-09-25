"""Deterministic OSINT fixture provider.

The fixture catalog is the offline source for the governed investigation.
It does not open a network connection. A missing fixture is a provider
failure, not an empty observation.
"""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from cyberclaw.authority.dispatch import governed_dispatch
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
    CAPABILITY_WHOIS_LOOKUP,
)
from cyberclaw.specialists.osint.normalizers.normalizer import OSINTNormalizer
from cyberclaw.specialists.osint.providers.base import OSINTProvider


PROVIDER_VERSION = "1.0.0"
APEX_DOMAIN = "apex.example"
APEX_IP = "203.0.113.10"
APEX_ORG = "Apex Example Org"
APEX_CERT_SERIAL = "CERT-APEX-1"
COLLECTION_TIME = "2026-01-15T12:00:00+00:00"

_APEX_DNS = {
    "outcome": "success",
    "source_reference": "fixture:osint-v1:dns:apex.example",
    "collected_at": COLLECTION_TIME,
    "payload": {
        "records": {
            "A": [APEX_IP],
            "NS": ["ns1.example.net"],
        }
    },
}
_APEX_CERT = {
    "outcome": "success",
    "source_reference": "fixture:osint-v1:cert:apex.example",
    "collected_at": COLLECTION_TIME,
    "payload": {
        "subject": APEX_DOMAIN,
        "issuer": "Example CA",
        "sans": [APEX_DOMAIN, "www.apex.example"],
        "valid_from": "2025-01-01T00:00:00Z",
        "valid_until": "2026-12-31T23:59:59Z",
        "serial_number": APEX_CERT_SERIAL,
    },
}

# Keys are (capability_id, target). Outcomes stay explicit.
FIXTURE_CATALOG: Dict[Tuple[str, str], Dict[str, Any]] = {
    (CAPABILITY_DNS_LOOKUP, APEX_DOMAIN): _APEX_DNS,
    (CAPABILITY_CERT_METADATA, APEX_DOMAIN): _APEX_CERT,
    (CAPABILITY_CERT_METADATA, "www.apex.example"): {
        **_APEX_CERT,
        "source_reference": "fixture:osint-v1:cert:www.apex.example",
        "payload": {**_APEX_CERT["payload"], "subject": "www.apex.example"},
    },
    (CAPABILITY_WHOIS_LOOKUP, APEX_DOMAIN): {
        "outcome": "success",
        "source_reference": "fixture:osint-v1:whois:apex.example",
        "collected_at": COLLECTION_TIME,
        "payload": {
            "registrant_org": APEX_ORG,
            "registrant_country": "US",
        },
    },
    (CAPABILITY_DOMAIN_METADATA, APEX_DOMAIN): {
        "outcome": "success",
        "source_reference": "fixture:osint-v1:domain:apex.example",
        "collected_at": COLLECTION_TIME,
        "payload": {
            "registrar": "Example Registrar, LLC",
            "status": ["clientTransferProhibited"],
            "nameservers": ["ns1.example.net"],
            "creation_date": "2018-04-01T00:00:00Z",
            "expiration_date": "2028-04-01T00:00:00Z",
        },
    },
    (CAPABILITY_DNS_LOOKUP, "empty.example"): {
        "outcome": "empty",
        "source_reference": "fixture:osint-v1:dns:empty.example",
        "collected_at": COLLECTION_TIME,
        "payload": {"records": {}},
    },
    (CAPABILITY_DNS_LOOKUP, "fail.example"): {
        "outcome": "failure",
        "error": "DNS lookup timeout at the resolver",
        "error_code": "DNS_LOOKUP_FAILED",
    },
    (CAPABILITY_DNS_LOOKUP, "malformed.example"): {
        "outcome": "malformed",
    },
    (CAPABILITY_DNS_LOOKUP, "noprov.example"): {
        "outcome": "success",
        "payload": {"records": {"A": ["203.0.113.20"]}},
    },
}


class FixtureOSINTProvider(OSINTProvider):
    """Offline provider. Collection runs only after governed dispatch."""

    def __init__(
        self,
        capability_id: str,
        catalog: Optional[Dict[Tuple[str, str], Dict[str, Any]]] = None,
        priority: int = 0,
    ) -> None:
        super().__init__(
            id=f"fixture.osint.{capability_id}",
            name=f"Fixture OSINT provider for {capability_id}",
            capability_id=capability_id,
            priority=priority,
            metadata={"version": PROVIDER_VERSION, "mode": "fixture"},
        )
        self.catalog = catalog if catalog is not None else FIXTURE_CATALOG
        self.calls = 0
        self.version = PROVIDER_VERSION

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        if governed_dispatch(context) is None:
            return ExecutionResult.failure(
                error=(
                    "OSINT fixture provider refused an ungoverned invocation. "
                    "Collection requires the governed executor."
                ),
                error_code="UNGOVERNED_PROVIDER_INVOCATION",
                execution_id=context.execution_id,
            )

        self.calls += 1
        target = parameters.get("target")
        if not target:
            return ExecutionResult.failure(
                error="OSINT fixture provider requires an explicit target.",
                error_code="VALIDATION_FAILURE",
                execution_id=context.execution_id,
            )

        record = self.catalog.get((self.capability_id, target))
        if record is None:
            return ExecutionResult.failure(
                error=f"No fixture for {self.capability_id} target '{target}'. Absence is not an empty observation.",
                error_code="TARGET_NOT_IN_FIXTURE",
                execution_id=context.execution_id,
            )

        outcome = record.get("outcome")
        if outcome == "empty":
            return ExecutionResult.success_empty(
                output={"target": target, "provider_version": self.version},
                execution_id=context.execution_id,
                metadata={"provider_version": self.version, "mode": "fixture"},
            )
        if outcome == "failure":
            return ExecutionResult.failure(
                error=record.get("error") or "Fixture provider failed.",
                error_code=record.get("error_code") or "DNS_LOOKUP_FAILED",
                execution_id=context.execution_id,
            )
        if outcome == "malformed":
            return ExecutionResult.failure(
                error="Fixture payload did not match the OSINT evidence contract.",
                error_code="MALFORMED_RESULT",
                execution_id=context.execution_id,
            )
        if outcome != "success":
            return ExecutionResult.failure(
                error=f"Fixture outcome '{outcome}' is not a known provider result.",
                error_code="MALFORMED_RESULT",
                execution_id=context.execution_id,
            )

        payload = record.get("payload")
        if not isinstance(payload, dict):
            return ExecutionResult.failure(
                error="Fixture success payload was not a structured object.",
                error_code="MALFORMED_RESULT",
                execution_id=context.execution_id,
            )

        try:
            evidence = OSINTNormalizer.normalize(
                capability_id=self.capability_id,
                raw_data=payload,
                target=target,
                provider_id=self.id,
                context=context,
                provider_version=self.version,
                source_reference=record.get("source_reference"),
                collected_at=record.get("collected_at"),
            )
        except (TypeError, ValueError) as exc:
            return ExecutionResult.failure(
                error=f"OSINT normalization rejected the fixture payload: {exc}",
                error_code="MALFORMED_RESULT",
                execution_id=context.execution_id,
            )

        if not evidence:
            return ExecutionResult.failure(
                error="Fixture was marked success but normalization produced no observation.",
                error_code="MALFORMED_RESULT",
                execution_id=context.execution_id,
            )
        return ExecutionResult.success(
            evidence=evidence,
            output={"target": target, "provider_version": self.version},
            execution_id=context.execution_id,
            metadata={"provider_version": self.version, "mode": "fixture"},
        )


def fixture_providers() -> list:
    """One fixture provider for each passive OSINT capability."""
    return [
        FixtureOSINTProvider(CAPABILITY_DOMAIN_METADATA),
        FixtureOSINTProvider(CAPABILITY_DNS_LOOKUP),
        FixtureOSINTProvider(CAPABILITY_CERT_METADATA),
        FixtureOSINTProvider(CAPABILITY_WHOIS_LOOKUP),
    ]
