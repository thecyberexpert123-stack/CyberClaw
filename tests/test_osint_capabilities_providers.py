"""Tests for OSINT Capabilities, Providers, Readiness, and Normalization."""

from pathlib import Path
import pytest
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionStatus
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
    CAPABILITY_WHOIS_LOOKUP,
    get_osint_capabilities,
)
from cyberclaw.specialists.osint.normalizers.normalizer import OSINTNormalizer
from cyberclaw.specialists.osint.providers.mock_providers import (
    MockCertMetadataProvider,
    MockDnsLookupProvider,
    MockDomainMetadataProvider,
    MockWhoisLookupProvider,
)
from cyberclaw.specialists.osint.specialist import OSINTSpecialist


def test_osint_capabilities_definitions():
    caps = get_osint_capabilities()
    cap_ids = [c.id for c in caps]
    assert CAPABILITY_DOMAIN_METADATA in cap_ids
    assert CAPABILITY_DNS_LOOKUP in cap_ids
    assert CAPABILITY_CERT_METADATA in cap_ids
    assert CAPABILITY_WHOIS_LOOKUP in cap_ids
    for c in caps:
        assert c.category == "osint"
        assert "network:read" in c.required_permissions


def test_domain_metadata_provider_lifecycle():
    ctx = ExecutionContext(execution_id="exec-dm-1")
    prov = MockDomainMetadataProvider()

    ready, reason = prov.is_ready(ctx)
    assert ready is True
    assert reason is None

    # Success execution with findings
    res = prov.execute({"target": "cyberclaw.io"}, ctx)
    assert res.is_success is True
    assert len(res.evidence) == 1
    ev = res.evidence[0]
    assert ev.type == "osint.domain_metadata"
    assert ev.subject == "cyberclaw.io"
    assert ev.value["registrar"] == "Example Registrar, LLC"
    assert "ns1.exampledns.net" in ev.value["nameservers"]
    assert ev.provenance.provider_id == prov.id
    assert ev.provenance.capability_id == CAPABILITY_DOMAIN_METADATA

    # Empty result execution
    empty_res = prov.execute({"target": "unregistered.xyz", "simulate_empty": True}, ctx)
    assert empty_res.status == ExecutionStatus.SUCCESS_EMPTY
    assert empty_res.is_empty is True
    assert len(empty_res.evidence) == 0

    # Failure execution
    fail_res = prov.execute({"target": "timeout.io", "simulate_failure": True}, ctx)
    assert fail_res.status == ExecutionStatus.FAILURE
    assert fail_res.is_failure is True
    assert fail_res.error_code == "PROVIDER_API_TIMEOUT"


def test_dns_lookup_provider():
    ctx = ExecutionContext(execution_id="exec-dns-1")
    prov = MockDnsLookupProvider()

    res = prov.execute({"target": "target.org"}, ctx)
    assert res.is_success is True
    # Multiple DNS record types normalized as distinct evidence items
    types = {e.value["record_type"] for e in res.evidence}
    assert "A" in types
    assert "MX" in types
    assert "NS" in types


def test_cert_metadata_provider():
    ctx = ExecutionContext(execution_id="exec-cert-1")
    prov = MockCertMetadataProvider()

    res = prov.execute({"target": "secure.org"}, ctx)
    assert res.is_success is True
    assert len(res.evidence) == 1
    cert_ev = res.evidence[0]
    assert cert_ev.type == "osint.certificate"
    assert "www.secure.org" in cert_ev.value["sans"]


def test_whois_lookup_provider():
    ctx = ExecutionContext(execution_id="exec-whois-1")
    prov = MockWhoisLookupProvider()

    res = prov.execute({"target": "corp.net"}, ctx)
    assert res.is_success is True
    assert len(res.evidence) == 1
    whois_ev = res.evidence[0]
    assert whois_ev.type == "osint.whois"
    assert whois_ev.value["registrant_country"] == "US"


def test_provider_readiness_rejection():
    ctx = ExecutionContext()
    unready_prov = MockDomainMetadataProvider(
        id="mock.unready",
        is_ready_override=False,
        unready_reason="API key expired",
    )
    ready, reason = unready_prov.is_ready(ctx)
    assert ready is False
    assert reason == "API key expired"


def test_specialist_provider_fallback(tmp_path: Path):
    specialist = OSINTSpecialist(workspace_base=tmp_path, use_default_mock_providers=False)

    # Register primary provider (higher priority) that simulates failure
    primary = MockDnsLookupProvider(id="dns.primary", priority=200)
    # Register secondary fallback provider (lower priority)
    secondary = MockDnsLookupProvider(id="dns.secondary", priority=100)

    specialist.register_provider(primary)
    specialist.register_provider(secondary)

    ctx = ExecutionContext(execution_id="exec-fallback")
    # Primary fails when simulate_failure is passed, but secondary should execute as fallback
    res = specialist.execute_local_capability(
        CAPABILITY_DNS_LOOKUP,
        {"target": "fallback.org", "simulate_failure": False},
        ctx,
    )
    assert res.is_success is True
