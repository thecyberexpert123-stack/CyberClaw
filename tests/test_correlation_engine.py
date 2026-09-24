"""Tests for CorrelationEngine, Observed vs Inferred relationships, and Contradictions."""

import pytest
from cyberclaw.correlation.engine import CorrelationEngine
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.types import Source


def test_observed_dns_and_cert_correlation():
    engine = CorrelationEngine()

    source = Source(type="test", name="MockScanner")
    prov_dns = Provenance(specialist_id="osint_specialist", capability_id="osint.dns_lookup")
    prov_cert = Provenance(specialist_id="osint_specialist", capability_id="osint.cert_metadata")

    ev_dns = Evidence(
        type="osint.dns_record",
        subject="target-alpha.com",
        value={"values": ["192.168.1.50"], "record_type": "A"},
        source=source,
        provenance=prov_dns,
    )
    ev_cert = Evidence(
        type="osint.certificate",
        subject="target-alpha.com",
        value={"issuer": "DigiCert", "sans": ["target-alpha.com", "mail.target-alpha.com"], "serial_number": "CERT-999"},
        source=source,
        provenance=prov_cert,
    )

    res = engine.correlate([ev_dns, ev_cert])

    # 1. Extracted Entities
    entity_names = {e.name for e in res.new_entities}
    assert "target-alpha.com" in entity_names
    assert "192.168.1.50" in entity_names
    assert "CERT-999" in entity_names

    # 2. Observed relationships
    rels = res.new_relationships
    assert len(rels) >= 2
    for r in rels:
        assert r.is_inferred is False  # Directly observed
        assert len(r.supporting_evidence_ids) >= 1
        assert "provenance" in r.metadata

    # 3. Check specific observed link
    resolves_rel = [r for r in rels if r.relation_type == "resolves_to"][0]
    assert resolves_rel.source_id == "target-alpha.com"
    assert resolves_rel.target_id == "192.168.1.50"
    assert resolves_rel.supporting_evidence_ids == [ev_dns.id]


def test_inferred_shared_infrastructure_relationship():
    """Verify Section 9: Inferred relationships are explicitly marked is_inferred=True."""
    engine = CorrelationEngine()

    source = Source(type="test", name="MockScanner")
    ev1 = Evidence(
        type="osint.dns_record",
        subject="site-one.com",
        value={"values": ["10.20.30.40"], "record_type": "A"},
        source=source,
    )
    ev2 = Evidence(
        type="osint.dns_record",
        subject="site-two.com",
        value={"values": ["10.20.30.40"], "record_type": "A"},
        source=source,
    )

    res = engine.correlate([ev1, ev2])

    # Check observed relationships
    observed_rels = [r for r in res.new_relationships if not r.is_inferred]
    assert len(observed_rels) == 2  # site-one -> IP, site-two -> IP

    # Check inferred relationships
    inferred_rels = [r for r in res.new_relationships if r.is_inferred]
    assert len(inferred_rels) == 1
    inf_rel = inferred_rels[0]
    assert inf_rel.relation_type == "inferred_shared_infrastructure"
    assert inf_rel.is_inferred is True
    assert set([inf_rel.source_id, inf_rel.target_id]) == {"site-one.com", "site-two.com"}
    assert set(inf_rel.supporting_evidence_ids) == {ev1.id, ev2.id}
    assert inf_rel.confidence < 1.0  # Inferred confidence is conservative


def test_contradiction_detection_without_deleting_history():
    """Verify Section 11: Contradictions are explicitly detected and recorded without deletion."""
    engine = CorrelationEngine()

    source1 = Source(type="test", name="Provider1")
    source2 = Source(type="test", name="Provider2")

    ev_early = Evidence(
        id="ev-early",
        type="osint.dns_record",
        subject="flipping-domain.org",
        value={"values": ["1.1.1.1"], "record_type": "A"},
        source=source1,
    )
    ev_late = Evidence(
        id="ev-late",
        type="osint.dns_record",
        subject="flipping-domain.org",
        value={"values": ["2.2.2.2"], "record_type": "A"},
        source=source2,
    )

    res = engine.correlate([ev_early, ev_late])

    # Verify both relationships still exist in graph (history preserved)
    ip_targets = {r.target_id for r in res.new_relationships if r.relation_type == "resolves_to"}
    assert "1.1.1.1" in ip_targets
    assert "2.2.2.2" in ip_targets

    # Contradiction explicitly flagged
    assert len(res.contradictions) == 1
    contra = res.contradictions[0]
    assert contra.conflict_type in ("conflicting_A_resolution", "multiple_divergent_resolutions")
    assert contra.subject == "flipping-domain.org"
    assert set(contra.competing_evidence_ids) == {"ev-early", "ev-late"}
    assert contra.resolved is False
