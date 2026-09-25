"""Governed OSINT investigation vertical.

The scenario uses a fixture catalog. It does not contact a live domain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cyberclaw.capabilities.errors import (
    CapabilityNotFoundError,
    CapabilityTrustError,
    CapabilityUnavailableError,
)
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.coordination.requirements import RequirementStatus
from cyberclaw.evidence.models import Evidence
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import StoppingCondition
from cyberclaw.policy.errors import AuthorizationDeniedError
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.runtime.errors import ProviderExecutionError
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_WHOIS_LOOKUP,
    get_osint_capabilities,
)
from cyberclaw.specialists.osint.governance import configure_governed_osint
from cyberclaw.specialists.osint.providers.fixtures import (
    APEX_CERT_SERIAL,
    APEX_DOMAIN,
    APEX_IP,
    APEX_ORG,
    PROVIDER_VERSION,
)
from cyberclaw.specialists.osint.providers.live import LiveOSINTProvider
from cyberclaw.types import Source
from cyberclaw.validation.errors import PolicyValidationError

from cyberclaw.core import CyberClawCore


def _calls(specialist) -> dict:
    return {
        capability_id: sum(provider.calls for provider in providers)
        for capability_id, providers in specialist._providers.items()
    }


def _total_calls(specialist) -> int:
    return sum(_calls(specialist).values())


def _build(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path / "core")
    core.startup()
    specialist = configure_governed_osint(tmp_path / "osint")
    for capability in get_osint_capabilities():
        core.register_capability(capability)
    core.register_specialist(specialist.as_specialist())
    core.permissions.grant_permission(specialist.SPECIALIST_ID, "network:read")
    return core, specialist


def test_fixture_investigation_follows_information_gaps(tmp_path: Path):
    """DNS and registration are requested. Certificate follow-up comes from the planner."""
    core, specialist = _build(tmp_path)
    investigation = core.create_investigation(
        title="Apex Example infrastructure",
        description="What infrastructure is publicly associated with apex.example?",
        targets=[APEX_DOMAIN],
    )

    dns_requirement = core.create_information_requirement(
        investigation.id,
        description="Resolve the domain before treating any address as observed.",
        target_or_entity=APEX_DOMAIN,
        evidence_types_sought=["osint.dns_record"],
        assigned_capability_id=CAPABILITY_DNS_LOOKUP,
    )
    whois_requirement = core.create_information_requirement(
        investigation.id,
        description="Record the registrant organization if the registration source returns one.",
        target_or_entity=APEX_DOMAIN,
        evidence_types_sought=["osint.whois"],
        assigned_capability_id=CAPABILITY_WHOIS_LOOKUP,
    )
    core.fulfill_information_requirement(investigation.id, dns_requirement.id)
    core.fulfill_information_requirement(investigation.id, whois_requirement.id)
    core.correlate_investigation(investigation.id)

    assert dns_requirement.status == RequirementStatus.SATISFIED
    assert whois_requirement.status == RequirementStatus.SATISFIED
    assert _calls(specialist)[CAPABILITY_DNS_LOOKUP] == 1
    assert _calls(specialist)[CAPABILITY_WHOIS_LOOKUP] == 1

    followed = []
    stopping = None
    for _ in range(4):
        plan, validation = core.plan_investigation(
            investigation.id,
            auto_convert_candidates=True,
        )
        assert validation.is_valid
        if plan.stopping_condition:
            stopping = plan.stopping_condition
            break
        open_requirements = [
            item
            for item in investigation.information_requirements.values()
            if item.status == RequirementStatus.OPEN and item.id not in {dns_requirement.id, whois_requirement.id}
        ]
        assert open_requirements, "Planner reported a gap but created no requirement."
        for requirement in open_requirements:
            assert requirement.assigned_capability_id == CAPABILITY_CERT_METADATA
            assert requirement.metadata.get("value_dimension") == "missing_evidence"
            core.fulfill_information_requirement(investigation.id, requirement.id)
            followed.append(requirement)
        core.correlate_investigation(investigation.id)

    assert followed, "Certificate follow-up was not proposed from the missing-evidence gap."
    assert stopping == StoppingCondition.NO_AUTHORIZED_CAPABILITIES
    assert all(item.status == RequirementStatus.SATISFIED for item in followed)

    evidence = investigation.evidence_store.list_all()
    dns = next(item for item in evidence if item.type == "osint.dns_record" and item.value["record_type"] == "A")
    whois = next(item for item in evidence if item.type == "osint.whois")
    certificate = next(item for item in evidence if item.type == "osint.certificate" and item.subject == APEX_DOMAIN)
    assert dns.value["values"] == [APEX_IP]
    assert whois.value["registrant_org"] == APEX_ORG
    assert "REDACTED" not in whois.value.values()
    assert certificate.value["serial_number"] == APEX_CERT_SERIAL
    for item in (dns, whois, certificate):
        assert item.metadata["finding_nature"] == "OBSERVATION"
        assert item.metadata["provider_version"] == PROVIDER_VERSION
        assert item.metadata["source_reference"].startswith("fixture:osint-v1:")
        assert item.metadata["collection_timestamp"] == "2026-01-15T12:00:00+00:00"
        assert item.metadata["integrity_digest"]
        assert item.metadata["authorization_decision_id"]
        assert item.metadata["policy_version"]
        assert item.provenance.provider_id.startswith("fixture.osint.")
        assert item.provenance.specialist_id == "osint_specialist"
        assert item.provenance.investigation_id == investigation.id

    execution = next(
        record for record in investigation.case_manager.execution_history
        if record.capability_id == CAPABILITY_DNS_LOOKUP and record.status == "success"
    )
    assert dns.metadata["authorization_decision_id"] == execution.authorization_decision_id
    assert dns.metadata["policy_id"] == execution.policy_id
    assert dns.metadata["requirement_id"] == dns_requirement.id

    entities = {(entity.type, entity.name) for entity in investigation.entities.values()}
    assert ("domain", APEX_DOMAIN) in entities
    assert ("ip", APEX_IP) in entities
    assert ("organization", APEX_ORG) in entities
    assert ("certificate", APEX_CERT_SERIAL) in entities

    observed = {
        (item.relation_type, item.source_id, item.target_id, item.is_inferred)
        for item in investigation.relationships
    }
    assert ("resolves_to", APEX_DOMAIN, APEX_IP, False) in observed
    assert ("registered_by", APEX_DOMAIN, APEX_ORG, False) in observed
    assert ("authenticates_identity", APEX_CERT_SERIAL, APEX_DOMAIN, False) in observed
    assert not any(item.is_inferred for item in investigation.relationships)

    graph = core.materialize_knowledge_graph(investigation.id)
    projected = {
        (edge.relationship_type, edge.epistemic_nature, tuple(edge.supporting_evidence_ids))
        for edge in graph.get_edges()
        if edge.relationship_type in {"resolves_to", "registered_by", "authenticates_identity"}
    }
    assert ("resolves_to", "OBSERVATION", (dns.id,)) in projected
    assert ("registered_by", "OBSERVATION", (whois.id,)) in projected
    assert any(
        kind == "authenticates_identity" and nature == "OBSERVATION" and certificate.id in support
        for kind, nature, support in projected
    )

    calls_before_replay = _total_calls(specialist)
    journal_before = len(investigation.case_manager.journal.entries)
    executions_before = len(investigation.case_manager.execution_history)
    evidence_before = [item.id for item in investigation.evidence_store.list_all()]
    strategies_before = len(core.learning.list_strategies())
    reconstructed = ReplayEngine.replay(investigation)
    assert _total_calls(specialist) == calls_before_replay
    assert len(investigation.case_manager.journal.entries) == journal_before
    assert len(investigation.case_manager.execution_history) == executions_before
    assert [item.id for item in investigation.evidence_store.list_all()] == evidence_before
    assert len(core.learning.list_strategies()) == strategies_before
    assert any(item.id == dns.id for item in reconstructed.evidence)

    original_ip = dns.value["values"][0]
    dns.value["values"][0] = "198.51.100.50"
    replayed = ReplayEngine.replay(investigation)
    historical = next(item for item in replayed.evidence if item.id == dns.id)
    assert historical.value["values"][0] == original_ip
    assert _total_calls(specialist) == calls_before_replay

    trust_before = {
        capability.id: capability.trust_state
        for capability in core.capabilities.list_capabilities()
    }
    core.ingest_investigation_experience(investigation.id)
    assert _total_calls(specialist) == calls_before_replay
    assert len(core.learning.list_strategies()) == strategies_before
    assert {
        capability.id: capability.trust_state
        for capability in core.capabilities.list_capabilities()
    } == trust_before
    with pytest.raises(CapabilityNotFoundError):
        core.execute_action(investigation.id, "learned.osint.follow_dns", {"target": APEX_DOMAIN})
    assert _total_calls(specialist) == calls_before_replay

    snapshot = investigation.list_snapshots()[-1]
    branch = investigation.create_branch(snapshot.sequence, purpose="Counterfactual certificate identity")
    BranchEvidence = Evidence(
        type="osint.certificate",
        subject=APEX_DOMAIN,
        value={"serial_number": "COUNTERFACTUAL"},
        source=Source(type="simulation", name="branch"),
    )
    from cyberclaw.branching.engine import BranchEngine

    BranchEngine.simulate_evidence(branch, [BranchEvidence])
    assert branch.status.value == "ACTIVE"
    assert [item.id for item in investigation.evidence_store.list_all()] == evidence_before
    assert _total_calls(specialist) == calls_before_replay
    assert investigation.get_branch(branch.branch_id) is branch


def test_success_empty_failure_and_malformed_stay_distinct(tmp_path: Path):
    core, specialist = _build(tmp_path)
    investigation = core.create_investigation("Outcome distinction")
    before = investigation.evidence_store.count()

    empty = core.execute_action(
        investigation.id,
        CAPABILITY_DNS_LOOKUP,
        {"target": "empty.example"},
    )
    assert empty.is_empty
    assert empty.evidence == []
    assert investigation.evidence_store.count() == before

    failed = core.execute_action(
        investigation.id,
        CAPABILITY_DNS_LOOKUP,
        {"target": "fail.example"},
    )
    assert failed.is_failure
    assert failed.error_code == "DNS_LOOKUP_FAILED"
    assert "timeout" in failed.error
    assert failed.evidence == []
    assert investigation.evidence_store.count() == before
    from cyberclaw.authority.outcomes import explicit_temporary_failure

    assert explicit_temporary_failure(failed) is False

    malformed = core.execute_action(
        investigation.id,
        CAPABILITY_DNS_LOOKUP,
        {"target": "malformed.example"},
    )
    assert malformed.is_failure
    assert malformed.error_code == "MALFORMED_RESULT"
    assert malformed.evidence == []
    assert investigation.evidence_store.count() == before

    missing_provenance = core.execute_action(
        investigation.id,
        CAPABILITY_DNS_LOOKUP,
        {"target": "noprov.example"},
    )
    assert missing_provenance.is_success
    assert missing_provenance.evidence[0].metadata["source_reference_missing"] is True
    assert missing_provenance.evidence[0].metadata["collection_timestamp_missing"] is True
    assert "source_reference" not in missing_provenance.evidence[0].metadata


def test_timeout_text_does_not_retry_the_provider(tmp_path: Path):
    core, specialist = _build(tmp_path)
    investigation = core.create_investigation("Timeout text")
    core.submit_task_to_runtime(
        investigation.id,
        CAPABILITY_DNS_LOOKUP,
        {"target": "fail.example"},
    )
    with pytest.raises(ProviderExecutionError) as caught:
        core.step_runtime(investigation.id)
    assert caught.value.is_retryable is False
    assert _calls(specialist)[CAPABILITY_DNS_LOOKUP] == 1
    assert core.runtime_queue.depth(investigation.id) == 0


def test_collaboration_handoff_does_not_mutate_the_case_directly(tmp_path: Path):
    core, specialist = _build(tmp_path)
    investigation = core.create_investigation("Collaboration handoff")
    before = investigation.evidence_store.count()
    request = core.request_collaboration(
        investigation_id=investigation.id,
        requesting_specialist="analyst.osint",
        target_specialist=specialist.SPECIALIST_ID,
        objective="Certificate identity for apex.example",
        required_capabilities=[CAPABILITY_CERT_METADATA],
        requested_permissions=["network:read"],
    )
    routed = core.validate_and_route_collaboration(investigation.id, request.request_id)
    core.accept_collaboration_request(
        investigation.id,
        routed.request_id,
        parameters={"target": APEX_DOMAIN},
    )
    assert investigation.evidence_store.count() == before
    assert _total_calls(specialist) == 0
    core.step_runtime(investigation.id)
    assert _calls(specialist)[CAPABILITY_CERT_METADATA] == 1
    assert investigation.evidence_store.count() == before + 1
    evidence = investigation.evidence_store.list_all()[0]
    assert evidence.metadata["finding_nature"] == "OBSERVATION"
    assert evidence.metadata["task_id"]
    assert evidence.metadata["authorization_decision_id"]


def test_live_provider_does_not_collect_unless_explicitly_enabled():
    provider = LiveOSINTProvider(CAPABILITY_DNS_LOOKUP)
    ready, reason = provider.is_ready(None)
    assert ready is False
    assert "disabled" in reason
    from cyberclaw.capabilities.provider import ExecutionContext

    result = provider.execute({"target": APEX_DOMAIN}, ExecutionContext())
    assert result.is_failure
    assert result.error_code == "UNGOVERNED_PROVIDER_INVOCATION"
    assert provider.network_attempts == 0
    assert provider.calls == 0
