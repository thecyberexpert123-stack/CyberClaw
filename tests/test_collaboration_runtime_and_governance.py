"""Tests for collaboration runtime queue integration, policy authorization, capability trust, and timeout handling."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.collaboration.errors import (
    CollaborationAuthorizationError,
    CollaborationValidationError,
)
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    CollaborationStatus,
    ContextSensitivity,
    utc_now,
)
from cyberclaw.collaboration.persistence import CollaborationPersistenceManager
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistEndpoint, SpecialistHealth


class MockEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request):
        from cyberclaw.evidence.result import ExecutionResult
        from cyberclaw.specialists.endpoint import SpecialistResponse
        return SpecialistResponse.from_result("mock", getattr(request, "request_id", "req-1"), ExecutionResult.success())


def test_collaboration_enqueues_durable_runtime_task(tmp_path: Path):
    """Verify an accepted collaboration request is enqueued into Core's durable runtime queue."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register specialist and capability
    cap = Capability(
        id="net.port_scan",
        name="Port Scanner",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)

    spec = Specialist(
        id="specialist.network",
        name="Network Specialist",
        capabilities=["net.port_scan"],
        endpoint=MockEndpoint(),
    )
    core.register_specialist(spec)

    inv = core.create_investigation("Runtime Collab Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    # 1. Propose request
    collab_req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Scan port 443",
        required_capabilities=["net.port_scan"],
        priority=80,
    )
    assert collab_req.status == CollaborationStatus.PROPOSED

    # 2. Validate and Route
    routed_req = core.validate_and_route_collaboration(inv.id, collab_req.request_id)
    assert routed_req.status == CollaborationStatus.ROUTED

    # 3. Accept and Enqueue
    task = core.accept_collaboration_request(inv.id, routed_req.request_id, parameters={"port": 443})
    assert routed_req.status == CollaborationStatus.ACCEPTED
    assert routed_req.assigned_runtime_task_id == task.task_id

    # Verify task in durable runtime queue
    assert core.runtime_queue.depth(inv.id) == 1
    queued_task = core.runtime_queue.get_task(task.task_id)
    assert queued_task is not None
    assert queued_task.capability_id == "net.port_scan"
    assert queued_task.actor == "specialist.network"


def test_collaboration_cannot_bypass_policy_engine(tmp_path: Path):
    """Verify collaboration request targeting a disallowed operation is rejected or deferred by PolicyEngine."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Destructive capability in terminal stage
    cap = Capability(
        id="sys.force_reboot",
        name="Force Reboot",
        action_scope=ActionScope.DESTRUCTIVE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)

    spec = Specialist(
        id="specialist.remediator",
        name="Remediation Specialist",
        capabilities=["sys.force_reboot"],
        endpoint=MockEndpoint(),
    )
    core.register_specialist(spec)

    inv = core.create_investigation("Policy Block Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    # 1. Destructive scope requires lead approval -> DEFERRED
    req_defer = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.analyst",
        target_specialist="specialist.remediator",
        objective="Reboot machine immediately",
        required_capabilities=["sys.force_reboot"],
        action_scope="destructive",
    )
    res_defer = core.validate_and_route_collaboration(inv.id, req_defer.request_id)
    assert res_defer.status == CollaborationStatus.DEFERRED

    # 2. Hard denial: Mutating action in terminal stage (RESOLVE)
    core.transition_investigation(inv.id, CoreState.VERIFY, event="verify")
    core.transition_investigation(inv.id, CoreState.RESOLVE, event="resolve")

    req_deny = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.analyst",
        target_specialist="specialist.remediator",
        objective="Mutate terminal case",
        required_capabilities=["sys.force_reboot"],
        action_scope="destructive",
    )

    with pytest.raises(CollaborationAuthorizationError) as exc:
        core.validate_and_route_collaboration(inv.id, req_deny.request_id)
    assert "Policy denied" in str(exc.value)
    assert req_deny.status == CollaborationStatus.REJECTED


def test_collaboration_cannot_bypass_capability_trust(tmp_path: Path):
    """Verify collaboration request targeting an UNTRUSTED capability is rejected."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="tool.untrusted_script",
        name="Untrusted Script",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.UNTRUSTED,
    )
    core.register_capability(cap)

    spec = Specialist(
        id="specialist.scripting",
        name="Scripting Specialist",
        capabilities=["tool.untrusted_script"],
        endpoint=MockEndpoint(),
    )
    core.register_specialist(spec)

    inv = core.create_investigation("Trust Block Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.scripting",
        objective="Execute arbitrary script",
        required_capabilities=["tool.untrusted_script"],
    )

    with pytest.raises(CollaborationValidationError) as exc:
        core.validate_and_route_collaboration(inv.id, req.request_id)
    assert "cannot be executed" in str(exc.value).lower() or "not executable" in str(exc.value).lower()
    assert req.status == CollaborationStatus.REJECTED


def test_collaboration_atomic_persistence_and_restore(tmp_path: Path):
    """Verify collaboration requests and conflicts persist atomically and reload cleanly."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Persistence Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="s1",
        target_specialist="s2",
        objective="Analyze sample",
        sensitivity=ContextSensitivity.RESTRICTED,
    )

    core.persist_collaboration_state(inv.id)

    # Check files exist
    layout = core.workspace.get_investigation_workspace(inv.id)
    assert (layout.root / "collaboration" / "requests.json").exists()

    # Create fresh core instance and reload
    core2 = CyberClawCore(workspace_path=tmp_path)
    core2.startup()
    loaded = core2.load_collaboration_state(inv.id)
    assert loaded is True

    restored_req = core2.collaboration.get_request(req.request_id)
    assert restored_req is not None
    assert restored_req.objective == "Analyze sample"
    assert restored_req.sensitivity == ContextSensitivity.RESTRICTED


def test_collaboration_timeout_creates_explicit_expired_status(tmp_path: Path):
    """Verify exceeding collaboration deadline sets EXPIRED without treating missing response as negative finding."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Timeout Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    # Request with deadline in the past
    req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Analyze slow target",
        deadline=utc_now() - timedelta(seconds=10),
    )

    expired = core.collaboration.check_and_expire_timeouts(inv.id)
    assert req.request_id in expired
    assert req.status == CollaborationStatus.EXPIRED
    assert req.status.is_terminal is True
    # Crucial: no evidence or negative findings were added
    assert len(inv.evidence_store.list_all()) == 0


def test_collaboration_deferred_state_on_supervisor_approval_requirement(tmp_path: Path):
    """Verify that when policy requires approval, collaboration request transitions to DEFERRED."""
    from cyberclaw.policy.models import Policy, PolicyRule, PolicyEffect, ActorRole

    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="net.controlled_probe",
        name="Controlled Probe",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)

    spec = Specialist(
        id="specialist.controlled",
        name="Controlled Specialist",
        endpoint=MockEndpoint(),
        capabilities=["net.controlled_probe"],
        max_sensitivity_level="RESTRICTED",
    )
    core.register_specialist(spec)

    # Add approval rule to default policy
    approval_rule = PolicyRule(
        rule_id="rule.approval_probe",
        name="Require Approval for Controlled Probe",
        priority=1,
        effect=PolicyEffect.REQUIRE_APPROVAL,
        roles=[ActorRole.SPECIALIST],
        actions=["collaboration_execute"],
        conditions={"allowed_case_stages": ["INVESTIGATE"]},
    )
    default_pol = core.policy_engine.registry.get_default_policy()
    default_pol.rules.insert(0, approval_rule)

    inv = core.create_investigation("Approval Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.controlled",
        objective="Perform controlled probe",
        required_capabilities=["net.controlled_probe"],
    )

    deferred_req = core.validate_and_route_collaboration(inv.id, req.request_id)
    assert deferred_req.status == CollaborationStatus.DEFERRED
    assert "Awaiting authorization approval" in deferred_req.metadata.get("status_reason", "")


def test_collaboration_runtime_worker_crash_and_task_recovery(tmp_path: Path):
    """Verify task queue recovery safely requeues unstarted collaboration tasks after a simulated worker crash."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="dns.query",
        name="DNS Query",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)
    spec = Specialist(
        id="specialist.dns",
        name="DNS Specialist",
        endpoint=MockEndpoint(),
        capabilities=["dns.query"],
    )
    core.register_specialist(spec)

    inv = core.create_investigation("Crash Recovery Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="specialist.dns",
        objective="Resolve target domain",
        required_capabilities=["dns.query"],
    )
    core.validate_and_route_collaboration(inv.id, req.request_id)
    task = core.accept_collaboration_request(inv.id, req.request_id)

    # Worker-1 claims the task then crashes
    claimed = core.runtime_queue.dequeue("worker-crash-1")
    assert claimed.task_id == task.task_id

    # Recovery runs
    recovery_report = core.recover_runtime()
    assert task.task_id in recovery_report.requeued_unstarted

    # Worker-2 claims the recovered task and completes it
    claimed_recovered = core.runtime_queue.dequeue("worker-healthy-2")
    assert claimed_recovered.task_id == task.task_id


def test_collaboration_specialist_isolation_sanitization_in_runtime_task(tmp_path: Path):
    """Verify context filtering sanitizes input evidence and entities according to least-privilege context."""
    from cyberclaw.collaboration.protocol import ContextFilter
    from cyberclaw.evidence.models import Evidence, Source
    from cyberclaw.types import Entity

    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    inv = core.create_investigation("Sanitization Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    # Authoritative store has items of varying sensitivities
    ev_public = Evidence(type="raw", subject="pub", value="public_data", source=Source(type="test", name="test"))
    ev_restricted = Evidence(type="raw", subject="priv", value="classified", source=Source(type="test", name="test"))
    inv.add_evidence(ev_public)
    inv.add_evidence(ev_restricted)

    spec_internal = Specialist(
        id="spec.internal",
        name="Internal Specialist",
        endpoint=MockEndpoint(),
        max_sensitivity_level="INTERNAL",  # Clearance: INTERNAL
    )

    req = core.request_collaboration(
        investigation_id=inv.id,
        requesting_specialist="specialist.osint",
        target_specialist="spec.internal",
        objective="Analyze sanitized subset",
        input_evidence_ids=[ev_public.id],
        sensitivity=ContextSensitivity.INTERNAL,
    )

    context = ContextFilter.filter_context(req, inv, spec_internal)
    authorized_ids = [e.id for e in context.authorized_evidence]
    assert ev_public.id in authorized_ids
    assert ev_restricted.id not in authorized_ids
