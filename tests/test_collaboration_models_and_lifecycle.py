"""Tests for Collaboration models, lifecycle DFA, specialist isolation, and sensitivity enforcement."""

from __future__ import annotations

from datetime import datetime
import pytest

from cyberclaw.collaboration.errors import (
    CollaborationStateTransitionError,
    UnauthorizedContextAccessError,
)
from cyberclaw.collaboration.models import (
    CollaborationContext,
    CollaborationRequest,
    CollaborationResult,
    CollaborationStatus,
    ContextSensitivity,
    FindingNature,
)
from cyberclaw.collaboration.protocol import CollaborationLifecycleDFA, ContextFilter
from cyberclaw.evidence.models import Evidence
from cyberclaw.investigation import Investigation
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistEndpoint
from cyberclaw.types import Source


class DummyEndpoint(SpecialistEndpoint):
    def health(self):
        from cyberclaw.specialists.endpoint import SpecialistHealth
        return SpecialistHealth.HEALTHY

    def invoke(self, request):
        from cyberclaw.evidence.result import ExecutionResult
        from cyberclaw.specialists.endpoint import SpecialistResponse
        return SpecialistResponse.from_result("dummy", getattr(request, "request_id", "req-1"), ExecutionResult.success())


def test_collaboration_request_model_fields_and_defaults():
    """Verify CollaborationRequest initializes with expected defaults and metadata."""
    req = CollaborationRequest(
        investigation_id="inv-req-01",
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Probe open service ports",
        priority=75,
        sensitivity=ContextSensitivity.INTERNAL,
    )
    assert req.request_id is not None
    assert req.status == CollaborationStatus.PROPOSED
    assert req.priority == 75
    assert req.sensitivity == ContextSensitivity.INTERNAL
    assert req.action_scope == "reversible"
    assert req.is_counterfactual is False
    assert isinstance(req.created_at, datetime)


def test_collaboration_lifecycle_primary_path():
    """Verify primary valid lifecycle: PROPOSED -> VALIDATING -> AUTHORIZED -> ROUTED -> ACCEPTED -> IN_PROGRESS -> RESULT_RECEIVED -> EVALUATED -> COMPLETED."""
    req = CollaborationRequest(
        investigation_id="inv-dfa-01",
        requesting_specialist="specialist.osint",
        objective="Analyze host infrastructure",
    )
    assert req.status == CollaborationStatus.PROPOSED

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.VALIDATING)
    assert req.status == CollaborationStatus.VALIDATING

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.AUTHORIZED)
    assert req.status == CollaborationStatus.AUTHORIZED

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.ROUTED)
    assert req.status == CollaborationStatus.ROUTED

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.ACCEPTED)
    assert req.status == CollaborationStatus.ACCEPTED

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.IN_PROGRESS)
    assert req.status == CollaborationStatus.IN_PROGRESS

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.RESULT_RECEIVED)
    assert req.status == CollaborationStatus.RESULT_RECEIVED

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.EVALUATED)
    assert req.status == CollaborationStatus.EVALUATED

    CollaborationLifecycleDFA.transition(req, CollaborationStatus.COMPLETED)
    assert req.status == CollaborationStatus.COMPLETED
    assert req.status.is_terminal is True


def test_collaboration_lifecycle_controlled_alternates():
    """Verify governed alternate transitions: DEFERRED, REJECTED, CANCELLED, BLOCKED, EXPIRED, FAILED."""
    # Alternate path 1: VALIDATING -> DEFERRED -> VALIDATING -> REJECTED
    r1 = CollaborationRequest(investigation_id="inv-alt-01", requesting_specialist="s1", objective="o1")
    CollaborationLifecycleDFA.transition(r1, CollaborationStatus.VALIDATING)
    CollaborationLifecycleDFA.transition(r1, CollaborationStatus.DEFERRED)
    assert r1.status == CollaborationStatus.DEFERRED
    CollaborationLifecycleDFA.transition(r1, CollaborationStatus.VALIDATING)
    CollaborationLifecycleDFA.transition(r1, CollaborationStatus.REJECTED)
    assert r1.status == CollaborationStatus.REJECTED
    assert r1.status.is_terminal is True

    # Alternate path 2: AUTHORIZED -> BLOCKED -> ROUTED
    r2 = CollaborationRequest(investigation_id="inv-alt-01", requesting_specialist="s1", objective="o2")
    CollaborationLifecycleDFA.transition(r2, CollaborationStatus.VALIDATING)
    CollaborationLifecycleDFA.transition(r2, CollaborationStatus.AUTHORIZED)
    CollaborationLifecycleDFA.transition(r2, CollaborationStatus.BLOCKED)
    assert r2.status == CollaborationStatus.BLOCKED
    CollaborationLifecycleDFA.transition(r2, CollaborationStatus.ROUTED)
    assert r2.status == CollaborationStatus.ROUTED

    # Alternate path 3: IN_PROGRESS -> EXPIRED
    r3 = CollaborationRequest(investigation_id="inv-alt-01", requesting_specialist="s1", objective="o3")
    CollaborationLifecycleDFA.transition(r3, CollaborationStatus.VALIDATING)
    CollaborationLifecycleDFA.transition(r3, CollaborationStatus.AUTHORIZED)
    CollaborationLifecycleDFA.transition(r3, CollaborationStatus.ROUTED)
    CollaborationLifecycleDFA.transition(r3, CollaborationStatus.ACCEPTED)
    CollaborationLifecycleDFA.transition(r3, CollaborationStatus.IN_PROGRESS)
    CollaborationLifecycleDFA.transition(r3, CollaborationStatus.EXPIRED)
    assert r3.status == CollaborationStatus.EXPIRED


def test_collaboration_lifecycle_rejects_illegal_transitions():
    """Verify state machine rejects impossible transitions and terminal violations."""
    req = CollaborationRequest(investigation_id="inv-illegal-01", requesting_specialist="s1", objective="o1")

    # Cannot skip directly from PROPOSED to IN_PROGRESS
    with pytest.raises(CollaborationStateTransitionError) as exc1:
        CollaborationLifecycleDFA.transition(req, CollaborationStatus.IN_PROGRESS)
    assert "Illegal collaboration transition from 'PROPOSED' to 'IN_PROGRESS'" in str(exc1.value)

    # Cannot transition out of terminal COMPLETED
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.VALIDATING)
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.AUTHORIZED)
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.ROUTED)
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.ACCEPTED)
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.IN_PROGRESS)
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.RESULT_RECEIVED)
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.EVALUATED)
    CollaborationLifecycleDFA.transition(req, CollaborationStatus.COMPLETED)

    with pytest.raises(CollaborationStateTransitionError) as exc2:
        CollaborationLifecycleDFA.transition(req, CollaborationStatus.VALIDATING)
    assert "Illegal collaboration transition from 'COMPLETED'" in str(exc2.value)


def test_specialist_isolation_least_privilege_context():
    """Verify ContextFilter only transfers authorized evidence and entities, not full case workspace."""
    inv = Investigation(title="Isolation Test")
    ev1 = Evidence(
        type="dns_record",
        subject="apex.org",
        value={"ip": "1.2.3.4"},
        source=Source(type="dns", name="resolver"),
    )
    ev2 = Evidence(
        type="secret_token",
        subject="internal_vault",
        value={"secret": "super_classified"},
        source=Source(type="vault", name="keyring"),
    )
    inv.add_evidence(ev1)
    inv.add_evidence(ev2)
    inv.add_entity("host", "apex.org", {"environment": "prod"})
    inv.add_entity("database", "secret_db", {"unrelated": True})

    target_specialist = Specialist(
        id="specialist.network",
        name="Network Specialist",
        endpoint=DummyEndpoint(),
        max_sensitivity_level="INTERNAL",
    )

    req = CollaborationRequest(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Probe ports for apex.org",
        input_evidence_ids=[ev1.id],      # Only ev1 is authorized
        input_entity_ids=["apex.org"],    # Only apex.org entity is authorized
        sensitivity=ContextSensitivity.INTERNAL,
    )

    context = ContextFilter.filter_context(req, inv, target_specialist)

    # Verify least-privilege boundary
    assert len(context.authorized_evidence) == 1
    assert context.authorized_evidence[0].id == ev1.id
    assert ev2.id not in [e.id for e in context.authorized_evidence]

    assert len(context.authorized_entities) == 1
    assert context.authorized_entities[0].name == "apex.org"
    assert "secret_db" not in [e.name for e in context.authorized_entities]


def test_sensitivity_clearance_enforcement():
    """Verify accessing a sensitive request without adequate clearance raises UnauthorizedContextAccessError."""
    inv = Investigation(title="Sensitivity Test")
    target_spec_low = Specialist(
        id="specialist.untrusted_worker",
        name="Low Clearance Worker",
        endpoint=DummyEndpoint(),
        max_sensitivity_level="INTERNAL",  # Level 2
    )

    req_restricted = CollaborationRequest(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.untrusted_worker",
        objective="Inspect restricted artifacts",
        sensitivity=ContextSensitivity.RESTRICTED,  # Level 3 > Level 2
    )

    with pytest.raises(UnauthorizedContextAccessError) as exc:
        ContextFilter.filter_context(req_restricted, inv, target_spec_low)

    assert "clearance 'INTERNAL' insufficient" in str(exc.value)


def test_evidence_normalization_and_all_finding_natures():
    """Verify normalization classifies all 6 finding natures properly."""
    from cyberclaw.collaboration.evidence import EvidenceHandoffNormalizer

    req = CollaborationRequest(
        investigation_id="inv-123",
        requesting_specialist="specialist.osint",
        target_specialist="specialist.forensics",
        objective="Classify memory artifacts",
    )

    result = CollaborationResult(
        request_id=req.request_id,
        investigation_id="inv-123",
        responding_specialist="specialist.forensics",
        observations=[{"subject": "kernel", "data": "clean"}],
        inferences=[{"subject": "process_injection", "claim": "unlikely", "confidence": 0.7}],
        correlations=[{"subject": "mutex_to_ip", "claim": "correlated with c2"}],
        hypotheses=[{"subject": "persistence", "claim": "registry run key"}],
        negative_findings=[{"subject": "rootkit", "details": "no hidden modules found"}],
        failures=[{"subject": "raw_dump", "error": "access denied"}],
    )

    normalized = EvidenceHandoffNormalizer.normalize_result(
        result=result,
        request=req,
        capability_id="mem.inspect",
        capability_version="2.0.0",
        authorization_decision_id="auth-dec-99",
    )

    assert len(normalized) == 6
    natures = {e.metadata.get("finding_nature") for e in normalized}
    assert natures == {
        FindingNature.OBSERVATION.value,
        FindingNature.INFERENCE.value,
        FindingNature.CORRELATION.value,
        FindingNature.HYPOTHESIS.value,
        FindingNature.NEGATIVE_FINDING.value,
        FindingNature.FAILURE.value,
    }


def test_provenance_and_derivation_lineage_preservation():
    """Verify evidence normalization strictly preserves specialist, capability, and upstream evidence lineage."""
    from cyberclaw.collaboration.evidence import EvidenceHandoffNormalizer

    req = CollaborationRequest(
        investigation_id="inv-456",
        requesting_specialist="specialist.planner",
        target_specialist="specialist.network",
        objective="Analyze TLS cipher suites",
        input_evidence_ids=["ev-parent-1", "ev-parent-2"],
    )

    result = CollaborationResult(
        request_id=req.request_id,
        investigation_id="inv-456",
        responding_specialist="specialist.network",
        observations=[{"subject": "tls.port.443", "data": {"cipher": "TLS_AES_256_GCM_SHA384"}}],
    )

    ev_list = EvidenceHandoffNormalizer.normalize_result(
        result=result,
        request=req,
        capability_id="tls.handshake_audit",
        capability_version="1.4.2",
        authorization_decision_id="auth-777",
    )

    assert len(ev_list) == 1
    ev = ev_list[0]
    assert ev.provenance.specialist_id == "specialist.network"
    assert ev.provenance.capability_id == "tls.handshake_audit"
    assert ev.metadata["capability_version"] == "1.4.2"
    assert ev.metadata["authorization_decision_id"] == "auth-777"
    assert ev.metadata["derived_from_evidence_ids"] == ["ev-parent-1", "ev-parent-2"]
    assert ev.metadata["originating_request_id"] == req.request_id


def test_collaboration_timeout_expiration():
    """Verify check_and_expire_timeouts identifies stale active requests and transitions them to EXPIRED."""
    from datetime import timedelta
    from cyberclaw.case.models import utc_now
    from cyberclaw.capabilities.registry import CapabilityRegistry
    from cyberclaw.collaboration.coordinator import CollaborationCoordinator
    from cyberclaw.collaboration.routing import CollaborationRouter
    from cyberclaw.policy.engine import PolicyEngine
    from cyberclaw.policy.risk import RiskEvaluator
    from cyberclaw.policy.registry import PolicyRegistry
    from cyberclaw.runtime.queue import DurableTaskQueue
    from cyberclaw.specialists.registry import SpecialistRegistry

    queue = DurableTaskQueue()
    caps = CapabilityRegistry()
    specs = SpecialistRegistry()
    policies = PolicyRegistry()
    policy_engine = PolicyEngine(policies)

    coordinator = CollaborationCoordinator(specs, caps, policy_engine, queue)
    inv = Investigation(title="Timeout Expire Test")

    req = coordinator.request_collaboration(
        investigation=inv,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Slow network port scan",
        timeout_seconds=5,
    )
    # Artificially age the request created_at beyond 5 seconds
    req.created_at = utc_now() - timedelta(seconds=10)

    expired = coordinator.check_and_expire_timeouts(inv.id)
    assert len(expired) == 1
    assert expired[0] == req.request_id
    assert req.status == CollaborationStatus.EXPIRED

