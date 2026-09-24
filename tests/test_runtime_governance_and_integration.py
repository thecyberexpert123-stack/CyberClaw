"""Comprehensive governance boundaries, security verification, specialist coexistence, and Section 37 E2E scenario."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import InformationValueDimension, RequirementCandidate, UncertaintyType
from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.policy.models import ActorRole
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.runtime.errors import (
    BranchExecutionBlockedError,
    PauseViolationError,
    ProviderExecutionError,
    RuntimeAuthorizationError,
    RuntimeValidationError,
)
from cyberclaw.runtime.models import (
    ExecutionState,
    RetryPolicy,
    RuntimeTask,
    TaskPriority,
    TaskStatus,
)
from cyberclaw.runtime.recovery import RuntimeRecoveryManager
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistEndpoint, SpecialistHealth, SpecialistRequest, SpecialistResponse
from cyberclaw.types import Source


class FlakyRetryProvider(CapabilityProvider):
    """Simulates a provider that temporarily fails on first attempt and succeeds on retry."""

    def __init__(self, capability_id: str) -> None:
        super().__init__(id=f"provider.{capability_id}", capability_id=capability_id, name="Flaky Provider")
        self.attempts = 0

    def is_ready(self, context: Any = None):
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        self.attempts += 1
        if self.attempts == 1:
            return ExecutionResult.failure(
                error="Upstream API temporary 503 unavailable",
                error_code="PROVIDER_TEMPORARY_FAILURE",
            )
        ev = Evidence(
            type="flaky_recovery_finding",
            subject=parameters.get("target", "target.org"),
            value={"attempt": self.attempts, "status": "resolved"},
            source=Source(type="mock", name=self.id),
        )
        return ExecutionResult.success(output={"attempts": self.attempts}, evidence=[ev])


class GenericSpecialistEndpoint(SpecialistEndpoint):
    def __init__(self, specialist_id: str) -> None:
        self.specialist_id = specialist_id

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        ev = Evidence(
            type=f"{self.specialist_id}_artifact",
            subject=request.parameters.get("target", "unknown"),
            value={"handled_by": self.specialist_id, "capability": request.capability_id},
            source=Source(type="specialist", name=self.specialist_id),
        )
        res = ExecutionResult.success(output={"status": "ok"}, evidence=[ev])
        return SpecialistResponse.from_result(self.specialist_id, request.request_id, res)


def make_generic_specialist(specialist_id: str, capabilities: List[str]) -> Specialist:
    return Specialist(
        id=specialist_id,
        name=f"Specialist {specialist_id}",
        version="1.0.0",
        capabilities=capabilities,
        endpoint=GenericSpecialistEndpoint(specialist_id),
        permissions=["capability:execute"],
    )


# -----------------------------------------------------------------------------
# 1. Security & Governance Boundaries (Section 34)
# -----------------------------------------------------------------------------

def test_queued_task_cannot_bypass_policy(tmp_path: Path):
    """Verify queued tasks cannot bypass policy (auditor role attempting mutation is rejected)."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="tool.sensitive_wipe",
        name="Sensitive Wipe",
        action_scope=ActionScope.CONSEQUENTIAL,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)

    # Assign auditor role (which policy restricts from mutating actions)
    core.permissions.assign_role("auditor.dave", "auditor")
    core.permissions.grant_permission("auditor.dave", "investigation:view")
    core.permissions.grant_permission("auditor.dave", "investigation:update")

    inv = core.create_investigation("Policy Bypass Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    task = core.submit_task_to_runtime(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={"target": "target.org"},
        actor="auditor.dave",
        actor_role=ActorRole.AUDITOR.value,
        scope=ActionScope.CONSEQUENTIAL,
    )

    with pytest.raises(RuntimeAuthorizationError) as exc_info:
        core.step_runtime(inv.id)
    assert "Policy denied task execution" in str(exc_info.value)
    assert task.status == TaskStatus.REJECTED


def test_queued_task_cannot_bypass_capability_trust(tmp_path: Path):
    """Verify queued task targeting an UNTRUSTED capability is rejected before execution."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="tool.untrusted_binary",
        name="Untrusted Binary",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.UNTRUSTED,
    )
    core.register_capability(cap)

    inv = core.create_investigation("Trust Bypass Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    task = core.submit_task_to_runtime(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={"target": "victim.org"},
        actor="core.system",
    )

    with pytest.raises(RuntimeValidationError) as exc:
        core.step_runtime(inv.id)
    assert "cannot be executed" in str(exc.value)
    assert task.status == TaskStatus.REJECTED


def test_queued_task_cannot_bypass_permissions(tmp_path: Path):
    """Verify queued task submitted with actor lacking required permission is rejected."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="tool.privileged_op",
        name="Privileged Operation",
        required_permissions=["privileged:root"],
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)

    core.permissions.assign_role("unprivileged.user", "analyst")
    core.permissions.grant_permission("unprivileged.user", "investigation:view")
    core.permissions.grant_permission("unprivileged.user", "investigation:update")

    inv = core.create_investigation("Permission Bypass Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    task = core.submit_task_to_runtime(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={},
        actor="unprivileged.user",
    )

    with pytest.raises(RuntimeValidationError) as exc:
        core.step_runtime(inv.id)
    assert "lacks permission" in str(exc.value).lower()
    assert task.status == TaskStatus.REJECTED


def test_branch_task_cannot_execute_providers(tmp_path: Path):
    """Verify tasks inside counterfactual branches are barred from real provider execution."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="tool.network_probe",
        name="Network Probe",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)

    inv = core.create_investigation("Branch Security Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    branch = core.create_investigation_branch(inv.id, source_snapshot=1, purpose="Simulation Only")

    # Attempting to submit and run task with is_counterfactual=True must raise BranchExecutionBlockedError
    task = core.submit_task_to_runtime(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={"target": "apex.org"},
        is_counterfactual=True,
    )

    with pytest.raises(BranchExecutionBlockedError) as exc:
        core.step_runtime(inv.id)
    assert "cannot execute real providers in counterfactual branch" in str(exc.value)


def test_investigation_pause_and_resume_controls(tmp_path: Path):
    """Verify pause blocks execution and resume restores queue processing."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="tool.paused_test",
        name="Paused Test",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)

    inv = core.create_investigation("Pause Test Case")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    task = core.submit_task_to_runtime(inv.id, cap.id, parameters={"a": "b"})
    assert core.runtime_queue.depth(inv.id) == 1

    # Pause investigation
    core.pause_investigation_runtime(inv.id, reason="Operator maintenance")
    assert core.runtime_scheduler.is_paused(inv.id) is True

    # Processing must be blocked
    with pytest.raises(PauseViolationError) as exc:
        core.step_runtime(inv.id)
    assert "is paused" in str(exc.value)
    assert task.status == TaskStatus.QUEUED  # Still queued, not executed

    # Resume investigation
    core.resume_investigation_runtime(inv.id)
    assert core.runtime_scheduler.is_paused(inv.id) is False

    # Process all succeeds
    spec = make_generic_specialist("spec.general", [cap.id])
    core.register_specialist(spec)
    processed = core.process_runtime_queue(inv.id)
    assert len(processed) == 1
    assert processed[0].status == TaskStatus.COMPLETED


# -----------------------------------------------------------------------------
# 2. Domain-Neutral Multi-Specialist Coexistence (Section 38)
# -----------------------------------------------------------------------------

def test_domain_neutral_specialist_coexistence(tmp_path: Path):
    """Verify runtime coordinates OSINT, Network, and unknown FutureCloudSpecialist without domain-specific if-branches."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register 3 distinct domain specialists
    spec_osint = make_generic_specialist("specialist.osint", ["osint.dns_enum", "osint.whois"])
    spec_net = make_generic_specialist("specialist.network", ["network.port_scan", "network.service_probe"])
    spec_cloud = make_generic_specialist("specialist.future_cloud", ["cloud.s3_audit", "cloud.iam_posture"])

    core.register_specialist(spec_osint)
    core.register_specialist(spec_net)
    core.register_specialist(spec_cloud)

    # Register corresponding capabilities
    for spec in (spec_osint, spec_net, spec_cloud):
        for cid in spec.capabilities:
            cap = Capability(
                id=cid,
                name=cid,
                action_scope=ActionScope.REVERSIBLE,
                lifecycle_state=CapabilityLifecycleState.AVAILABLE,
                trust_state=CapabilityTrustState.FULLY_TRUSTED,
            )
            core.register_capability(cap)

    inv = core.create_investigation("Multi Specialist Coexistence")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    # Queue tasks across all 3 domains
    t1 = core.submit_task_to_runtime(inv.id, "osint.dns_enum", parameters={"target": "apex.org"})
    t2 = core.submit_task_to_runtime(inv.id, "network.port_scan", parameters={"target": "10.0.0.1"})
    t3 = core.submit_task_to_runtime(inv.id, "cloud.s3_audit", parameters={"target": "corp-bucket"})

    assert core.runtime_queue.depth(inv.id) == 3

    processed = core.process_runtime_queue(inv.id)
    assert len(processed) == 3
    for p in processed:
        assert p.status == TaskStatus.COMPLETED

    # Verify structured evidence ingested from all three specialists
    evidences = inv.evidence_store.list_all()
    assert len(evidences) == 3
    sources = {e.source.name for e in evidences}
    assert sources == {"specialist.osint", "specialist.network", "specialist.future_cloud"}


# -----------------------------------------------------------------------------
# 3. Complete End-to-End Investigation Lifecycle (Section 37)
# -----------------------------------------------------------------------------

def test_section_37_complete_durable_runtime_e2e_scenario(tmp_path: Path):
    """Execute complete 34-step Section 37 lifecycle scenario.

    Covers:
    Investigation start -> Planning requirement -> Runtime task queueing -> Policy & DFA gates ->
    Specialist dispatch -> Provider execution -> Result normalization -> Evidence ingestion ->
    Crash before ack simulation -> Runtime restart & recovery -> Duplicate execution prevention ->
    Second requirement -> Transient provider failure & classification -> Normal authorization on retry ->
    Stopping condition -> Final snapshot -> Replay proving ZERO provider executions & deterministic state digest.
    """
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Step 0: Setup capability and flaky provider
    cap_id = "recon.cert_scan"
    cap = Capability(
        id=cap_id,
        name="Certificate Scanner",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
        required_permissions=["investigation:view", "investigation:update"],
    )
    core.register_capability(cap)
    flaky_provider = FlakyRetryProvider(cap_id)
    core.register_provider(flaky_provider)

    # 1. Investigation starts
    inv = core.create_investigation("Section 37 E2E Case", "Testing full durable runtime cycle")
    assert inv.current_state == CoreState.READY

    # 2. Planner creates an information requirement
    req1 = inv.create_information_requirement(
        description="Map root domain certificate transparency",
        target_or_entity="apex-security.org",
        evidence_types_sought=["cert_transparency_log"],
        assigned_capability_id=cap_id,
        priority=80,
    )

    # 3. Requirement becomes a runtime task & 4. Task is durably queued
    task1 = core.submit_requirement_to_runtime(inv.id, req1.id, priority=TaskPriority.HIGH)
    assert task1.status == TaskStatus.QUEUED
    assert core.runtime_queue.depth(inv.id) == 1

    # 5. Runtime claims task, 6. verifies lifecycle/trust, 7. evaluates policy, 8. authorization granted,
    # 9. DFA validates transition, 10. dispatches, 11-16. executes, ingests evidence, persists completion
    # Note: flaky_provider will fail on attempt 1, triggering retry
    with pytest.raises(ProviderExecutionError):
        core.step_runtime(inv.id)

    # 25-28: Runtime classified failure as retryable, scheduled retry through normal authorization path
    assert task1.retry_count == 1
    assert task1.status == TaskStatus.QUEUED

    # 29: Retry execution succeeds on attempt 2 through normal authorization path
    step_res = core.step_runtime(inv.id)
    assert step_res.status == TaskStatus.COMPLETED
    assert flaky_provider.attempts == 2

    # 14. Evidence is added to authoritative case state
    evs = inv.evidence_store.list_all()
    assert len(evs) == 1
    assert evs[0].type == "flaky_recovery_finding"

    # 17. Snapshot captured
    snap1 = inv.capture_snapshot("milestone_1")
    assert snap1.sequence >= 1

    # 18. Simulate worker crash before acknowledgement of duplicate event
    # We record an unacknowledged task in the queue to test restart recovery
    dup_task = RuntimeTask(
        investigation_id=inv.id,
        capability_id=cap_id,
        action_scope="reversible",
        parameters={"target": "apex-security.org"},
        idempotency_key=task1.idempotency_key,
    )
    core.runtime_queue.enqueue(dup_task)
    # Claim it as crashed worker
    claimed_crashed = core.runtime_queue.dequeue("worker-crashed")
    claimed_crashed.status = TaskStatus.RUNNING
    claimed_crashed.execution_state = ExecutionState.IN_PROGRESS

    # 19. Runtime restarts -> 20. Recovery detects existing execution identity
    report = core.recover_runtime()
    # 21. Duplicate execution prevented; reconciled as completed without invoking provider!
    assert dup_task.task_id in report.reconciled_completed
    assert flaky_provider.attempts == 2  # Provider was NOT invoked again!

    # 22. Investigation continues -> 23. Planner identifies new information gap
    req2 = inv.create_information_requirement(
        description="Verify secondary subdomains",
        target_or_entity="api.apex-security.org",
        evidence_types_sought=["subdomain_records"],
        assigned_capability_id=cap_id,
        priority=60,
    )

    # 24. Second task is queued
    task2 = core.submit_requirement_to_runtime(inv.id, req2.id, priority=TaskPriority.NORMAL)
    assert core.runtime_queue.depth(inv.id) == 1

    # Execute second task
    step_res2 = core.step_runtime(inv.id)
    assert step_res2.status == TaskStatus.COMPLETED
    assert flaky_provider.attempts == 3

    # 30. Investigation reaches stopping condition
    core.transition_investigation(inv.id, CoreState.VERIFY, event="verify_findings")
    core.transition_investigation(inv.id, CoreState.RESOLVE, event="resolve_case")

    # 31. Final snapshot is captured
    final_snap = inv.capture_snapshot("investigation_resolved")
    assert final_snap.dfa_state == CoreState.RESOLVE.value

    # 32. Replay reconstructs the entire investigation
    reconstructed = ReplayEngine.replay(inv)
    assert reconstructed.dfa_state == CoreState.RESOLVE.value
    assert len(reconstructed.evidence) == 2

    # 33. Replay produces ZERO provider executions
    assert flaky_provider.attempts == 3  # No additional provider executions!

    # 34. Repeated replay produces identical state digest
    reconstructed2 = ReplayEngine.replay(inv)
    assert reconstructed.calculate_digest() == reconstructed2.calculate_digest()
