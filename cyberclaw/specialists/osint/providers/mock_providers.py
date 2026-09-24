"""Deterministic mock providers for offline testing of OSINT capabilities."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
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


class MockDomainMetadataProvider(OSINTProvider):
    """Deterministic mock provider for domain metadata."""

    def __init__(
        self,
        id: str = "mock.osint.domain_metadata",
        name: str = "Mock Domain Metadata Provider",
        priority: int = 100,
        is_ready_override: bool = True,
        unready_reason: Optional[str] = None,
    ) -> None:
        super().__init__(
            id=id,
            name=name,
            capability_id=CAPABILITY_DOMAIN_METADATA,
            priority=priority,
        )
        self._is_ready_override = is_ready_override
        self._unready_reason = unready_reason

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        if not self._is_ready_override:
            return False, self._unready_reason or "Provider is disabled or unconfigured."
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        target = parameters.get("target", "example.com")

        # Test control flags
        if parameters.get("simulate_failure"):
            return ExecutionResult.failure(
                error=f"Domain metadata lookup failed for '{target}': API timeout",
                error_code="PROVIDER_API_TIMEOUT",
                execution_id=context.execution_id,
            )

        if parameters.get("simulate_empty"):
            return ExecutionResult.success_empty(
                output={"domain": target, "status": "not_registered"},
                execution_id=context.execution_id,
            )

        # Deterministic domain metadata
        raw = {
            "registrar": "Example Registrar, LLC",
            "status": ["clientTransferProhibited", "clientUpdateProhibited"],
            "nameservers": ["ns1.exampledns.net", "ns2.exampledns.net"],
            "creation_date": "2015-08-14T00:00:00Z",
            "expiration_date": "2027-08-14T00:00:00Z",
        }
        evidence_list = OSINTNormalizer.normalize_domain_metadata(
            raw, target, provider_id=self.id, context=context
        )
        return ExecutionResult.success(
            evidence=evidence_list,
            output=raw,
            execution_id=context.execution_id,
        )


class MockDnsLookupProvider(OSINTProvider):
    """Deterministic mock provider for DNS records lookup."""

    def __init__(
        self,
        id: str = "mock.osint.dns_lookup",
        name: str = "Mock DNS Provider",
        priority: int = 100,
        is_ready_override: bool = True,
        unready_reason: Optional[str] = None,
    ) -> None:
        super().__init__(
            id=id,
            name=name,
            capability_id=CAPABILITY_DNS_LOOKUP,
            priority=priority,
        )
        self._is_ready_override = is_ready_override
        self._unready_reason = unready_reason

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        if not self._is_ready_override:
            return False, self._unready_reason or "DNS resolver not responding."
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        target = parameters.get("target", "example.com")

        if parameters.get("simulate_failure"):
            return ExecutionResult.failure(
                error=f"DNS lookup failed for '{target}': SERVFAIL",
                error_code="DNS_SERVFAIL",
                execution_id=context.execution_id,
            )

        if parameters.get("simulate_empty"):
            return ExecutionResult.success_empty(
                output={"target": target, "records": {}},
                execution_id=context.execution_id,
            )

        # Realistic records derived deterministically
        raw = {
            "records": {
                "A": ["93.184.216.34"],
                "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
                "MX": ["10 mail.example.com"],
                "TXT": ["v=spf1 -all"],
                "NS": ["ns1.exampledns.net", "ns2.exampledns.net"],
            }
        }
        evidence_list = OSINTNormalizer.normalize_dns_records(
            raw, target, provider_id=self.id, context=context
        )
        return ExecutionResult.success(
            evidence=evidence_list,
            output=raw,
            execution_id=context.execution_id,
        )


class MockCertMetadataProvider(OSINTProvider):
    """Deterministic mock provider for TLS certificate metadata."""

    def __init__(
        self,
        id: str = "mock.osint.cert_metadata",
        name: str = "Mock Certificate Metadata Provider",
        priority: int = 100,
        is_ready_override: bool = True,
        unready_reason: Optional[str] = None,
    ) -> None:
        super().__init__(
            id=id,
            name=name,
            capability_id=CAPABILITY_CERT_METADATA,
            priority=priority,
        )
        self._is_ready_override = is_ready_override
        self._unready_reason = unready_reason

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        if not self._is_ready_override:
            return False, self._unready_reason or "TLS connection failed."
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        target = parameters.get("target", "example.com")

        if parameters.get("simulate_failure"):
            return ExecutionResult.failure(
                error=f"TLS handshake failed with '{target}': Connection reset by peer",
                error_code="TLS_HANDSHAKE_ERROR",
                execution_id=context.execution_id,
            )

        if parameters.get("simulate_empty"):
            return ExecutionResult.success_empty(
                output={"target": target, "certificate": None},
                execution_id=context.execution_id,
            )

        raw = {
            "subject": f"CN={target}",
            "issuer": "Let's Encrypt Authority X3",
            "sans": [target, f"www.{target}", f"api.{target}"],
            "valid_from": "2024-01-01T00:00:00Z",
            "valid_until": "2027-01-01T23:59:59Z",
            "serial_number": "03A4B892F1",
        }
        evidence_list = OSINTNormalizer.normalize_cert_metadata(
            raw, target, provider_id=self.id, context=context
        )
        return ExecutionResult.success(
            evidence=evidence_list,
            output=raw,
            execution_id=context.execution_id,
        )


class MockWhoisLookupProvider(OSINTProvider):
    """Deterministic mock provider for WHOIS lookups."""

    def __init__(
        self,
        id: str = "mock.osint.whois_lookup",
        name: str = "Mock WHOIS Lookup Provider",
        priority: int = 100,
        is_ready_override: bool = True,
        unready_reason: Optional[str] = None,
    ) -> None:
        super().__init__(
            id=id,
            name=name,
            capability_id=CAPABILITY_WHOIS_LOOKUP,
            priority=priority,
        )
        self._is_ready_override = is_ready_override
        self._unready_reason = unready_reason

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        if not self._is_ready_override:
            return False, self._unready_reason or "WHOIS server rate limited."
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        target = parameters.get("target", "example.com")

        if parameters.get("simulate_failure"):
            return ExecutionResult.failure(
                error=f"WHOIS lookup failed for '{target}': Rate limit exceeded",
                error_code="WHOIS_RATE_LIMITED",
                execution_id=context.execution_id,
            )

        if parameters.get("simulate_empty"):
            return ExecutionResult.success_empty(
                output={"target": target, "whois": None},
                execution_id=context.execution_id,
            )

        raw = {
            "registrant_org": "Example Technologies Inc",
            "registrant_country": "US",
            "admin_email": "admin@example.com",
            "raw_whois": f"Domain Name: {target.upper()}\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN",
        }
        evidence_list = OSINTNormalizer.normalize_whois_data(
            raw, target, provider_id=self.id, context=context
        )
        return ExecutionResult.success(
            evidence=evidence_list,
            output=raw,
            execution_id=context.execution_id,
        )
