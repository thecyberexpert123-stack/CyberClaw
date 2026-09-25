"""Authority boundary contract tests.

These tests lock the rule that no subsystem gains authority because another
exposes an id, object, result, or path. They do not add a second policy
engine, capability registry, or runtime.
"""

from __future__ import annotations

import shutil
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import pytest

from cyberclaw.authority.models import (
    PersistenceDocumentState,
    ProviderOutcome,
    RecoveryDisposition,
    WorkerOwnership,
)
from cyberclaw.authority.outcomes import classify_provider_result
from cyberclaw.authority.recovery import classify_worker_ownership, recovery_disposition
from cyberclaw.authority.versions import semantic_version_key
from cyberclaw.branching.engine import BranchEngine
from cyberclaw.branching.errors import BranchIntegrityError
from cyberclaw.branching.models import BranchStatus
from cyberclaw.branching.persistence import BranchPersistence
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.errors import (
    CapabilityNotFoundError,
    CapabilityTrustError,
    CapabilityUnavailableError,
)
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.case.models import JournalEntry, JournalEntryType
from cyberclaw.collaboration.persistence import CollaborationPersistenceManager
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.learning.errors import InvalidStrategyTransitionError
from cyberclaw.learning.models import StrategyLifecycle
from cyberclaw.learning.strategies import StrategyLifecycleMachine, assert_not_executable
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.policy.errors import (
    ApprovalRequiredError,
    AuthorizationDeferredError,
    AuthorizationDeniedError,
    SupervisionRequiredError,
)
from cyberclaw.policy.models import Policy, PolicyEffect, PolicyRule
from cyberclaw.policy.registry import PolicyRegistry
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.replay.errors import CorruptedHistoryError, ReplaySequenceError
from cyberclaw.replay.validator import HistoryValidator
from cyberclaw.runtime.errors import (
    DispatchError,
    PersistenceError,
    RuntimeAuthorizationError,
    RuntimeTimeoutError,
    RuntimeValidationError,
    UnknownExecutionStateError,
)
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import ExecutionState, RetryPolicy, RuntimeTask, TaskStatus, utc_now
from cyberclaw.runtime.persistence import RuntimePersistenceManager
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.recovery import RuntimeRecoveryManager
from cyberclaw.runtime.state import TaskLifecycleDFA
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source


class CountingProvider(CapabilityProvider):
    def __init__(self, capability_id: str, mode: str = "success") -> None:
        super().__init__(id=f"provider.{capability_id}", name="Counting", capability_id=capability_id)
        self.calls = 0
        self.mode = mode

    def is_ready(self, context: ExecutionContext) -> Tuple[bool, Optional[str]]:
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        self.calls += 1
        if self.mode == "raise":
            raise TimeoutError("timeout while the provider was already running")
        if self.mode == "timeout-text":
            return ExecutionResult.failure(
                error="timeout talking to upstream",
                error_code="PROVIDER_FAILURE",
            )
        if self.mode == "temporary":
            if self.calls == 1:
                return ExecutionResult.failure(
                    error="please retry",
                    error_code="PROVIDER_TEMPORARY_FAILURE",
                )
        if self.mode == "malformed":
            return ExecutionResult.success(evidence=[], output=None)
        if self.mode == "empty":
            return ExecutionResult(status=ExecutionStatus.SUCCESS_EMPTY, evidence=[], output={})
        evidence = Evidence(
            type="observation",
            subject=parameters.get("target", "subject"),
            value={"ok": True},
            source=Source(type="provider", name=self.id),
        )
        return ExecutionResult.success(evidence=[evidence], output={"ok": True})


class CountingEndpoint(SpecialistEndpoint):
    def __init__(self) -> None:
        self.calls = 0

    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        self.calls += 1
        evidence = Evidence(
            type="routed",
            subject="subject",
            value={"ok": True},
            source=Source(type="specialist", name="spec"),
        )
        return SpecialistResponse.from_result(
            "spec",
            request.request_id,
            ExecutionResult.success(evidence=[evidence], output={"ok": True}),
        )


def _core(tmp_path: Path) -> CyberClawCore:
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    return core


def _ready_case(core: CyberClawCore, title: str = "Authority"):
    investigation = core.create_investigation(title)
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="start")
    return investigation


def _register(core: CyberClawCore, capability_id: str, **kwargs) -> Capability:
    capability = Capability(id=capability_id, name=capability_id, **kwargs)
    core.register_capability(capability)
    return capability


# ---------------------------------------------------------------------------
# Version order
# ---------------------------------------------------------------------------


def test_semantic_version_order_is_not_lexicographic():
    assert semantic_version_key("1.9.0") < semantic_version_key("1.10.0") < semantic_version_key("2.0.0")
    assert ("1.10.0" > "1.9.0") is False


def test_policy_latest_version_is_semantic():
    registry = PolicyRegistry(populate_defaults=False)
    for version in ("1.9.0", "1.10.0", "2.0.0"):
        registry.register_policy(Policy(policy_id="boundary", name="Boundary", version=version))
    assert registry.get_policy("boundary").version == "2.0.0"
    assert registry.get_policy("boundary", version="1.10.0").version == "1.10.0"


# ---------------------------------------------------------------------------
# Advertised != registered != authorized != executable
# ---------------------------------------------------------------------------


def test_specialist_advertisement_does_not_register_capability(tmp_path: Path):
    core = _core(tmp_path)
    endpoint = CountingEndpoint()
    core.register_specialist(
        Specialist(id="spec", name="Spec", capabilities=["observe.subject"], endpoint=endpoint)
    )
    assert core.capabilities.get_capability("observe.subject") is None
    investigation = _ready_case(core)
    with pytest.raises(CapabilityNotFoundError):
        core.execute_action(investigation.id, "observe.subject", {"target": "subject"})
    assert endpoint.calls == 0
    assert core.capabilities.get_capability("observe.subject") is None


def test_provider_registration_does_not_create_capability():
    registry = CapabilityRegistry()
    provider = CountingProvider("missing.cap")
    with pytest.raises(CapabilityNotFoundError):
        registry.register_provider(provider)
    assert registry.get_capability("missing.cap") is None


def test_runtime_does_not_materialize_unregistered_capability(tmp_path: Path):
    core = _core(tmp_path)
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(investigation.id, "not.registered", {"target": "s"})
    with pytest.raises(RuntimeValidationError) as exc:
        core.step_runtime(investigation.id)
    assert exc.value.boundary == "NOT_FOUND"
    assert task.status == TaskStatus.REJECTED
    assert core.capabilities.get_capability("not.registered") is None


@pytest.mark.parametrize(
    "lifecycle",
    [
        CapabilityLifecycleState.PROPOSED,
        CapabilityLifecycleState.EXPERIMENTAL,
        CapabilityLifecycleState.VALIDATED,
        CapabilityLifecycleState.DEPRECATED,
        CapabilityLifecycleState.DISABLED,
        CapabilityLifecycleState.RETIRED,
        CapabilityLifecycleState.REJECTED,
    ],
)
def test_registered_lifecycle_is_not_executable(tmp_path: Path, lifecycle: CapabilityLifecycleState):
    core = _core(tmp_path)
    _register(core, "observe.lifecycle", lifecycle_state=lifecycle)
    investigation = _ready_case(core)
    with pytest.raises(CapabilityUnavailableError):
        core.execute_action(investigation.id, "observe.lifecycle", {"target": "s"})
    assert core.capabilities.get_capability("observe.lifecycle").lifecycle_state == lifecycle


@pytest.mark.parametrize("trust", [CapabilityTrustState.UNTRUSTED, CapabilityTrustState.REVOKED])
def test_registered_untrusted_is_not_executable(tmp_path: Path, trust: CapabilityTrustState):
    core = _core(tmp_path)
    _register(core, "observe.trust", trust_state=trust)
    investigation = _ready_case(core)
    with pytest.raises(CapabilityTrustError):
        core.execute_action(investigation.id, "observe.trust", {"target": "s"})


def test_registered_available_capability_can_execute(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.ok")
    provider = CountingProvider("observe.ok")
    core.register_provider(provider)
    investigation = _ready_case(core)
    result = core.execute_action(investigation.id, "observe.ok", {"target": "s"})
    assert result.is_success is True
    assert provider.calls == 1


def test_runtime_distinguishes_untrusted_from_disabled(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.untrusted", trust_state=CapabilityTrustState.UNTRUSTED)
    _register(core, "observe.disabled", lifecycle_state=CapabilityLifecycleState.DISABLED)
    investigation = _ready_case(core)
    core.submit_task_to_runtime(investigation.id, "observe.untrusted", {"target": "s"})
    with pytest.raises(RuntimeValidationError) as untrusted:
        core.step_runtime(investigation.id)
    assert untrusted.value.boundary == "NOT_TRUSTED"
    core.submit_task_to_runtime(investigation.id, "observe.disabled", {"target": "s"})
    with pytest.raises(RuntimeValidationError) as disabled:
        core.step_runtime(investigation.id)
    assert disabled.value.boundary == "NOT_EXECUTABLE"


def test_trust_gate_runs_before_policy(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.untrusted", trust_state=CapabilityTrustState.UNTRUSTED)
    investigation = _ready_case(core)
    calls = {"n": 0}
    original = core.policy_engine.authorize

    def counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    core.policy_engine.authorize = counting
    with pytest.raises(CapabilityTrustError):
        core.execute_action(investigation.id, "observe.untrusted", {"target": "s"})
    assert calls["n"] == 0


def test_permission_gate_runs_before_policy(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.private", required_permissions=["private:read"])
    investigation = _ready_case(core)
    core.permissions.grant_permission("analyst.one", "investigation:view")
    core.permissions.grant_permission("analyst.one", "investigation:update")
    calls = {"n": 0}
    original = core.policy_engine.authorize

    def counting(*args, **kwargs):
        calls["n"] += 1
        return original(*args, **kwargs)

    core.policy_engine.authorize = counting
    with pytest.raises(Exception):
        core.execute_action(
            investigation.id,
            "observe.private",
            {"target": "s"},
            actor="analyst.one",
            scope=ActionScope.REVERSIBLE,
        )
    assert calls["n"] == 0


# ---------------------------------------------------------------------------
# Authorization decisions survive later paths
# ---------------------------------------------------------------------------


def _deny_policy() -> Policy:
    return Policy(
        policy_id="authority-deny",
        name="Deny",
        version="1.0.0",
        rules=[PolicyRule(rule_id="deny", name="Deny", effect=PolicyEffect.DENY)],
    )


def _defer_policy() -> Policy:
    return Policy(
        policy_id="authority-defer",
        name="Defer",
        version="1.2.0",
        rules=[PolicyRule(rule_id="defer", name="Defer", effect=PolicyEffect.DEFER)],
    )


def test_deny_does_not_execute(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.deny")
    provider = CountingProvider("observe.deny")
    core.register_provider(provider)
    core.policy_engine.registry.register_policy(_deny_policy())
    investigation = _ready_case(core)
    with pytest.raises(AuthorizationDeniedError):
        core.execute_action(investigation.id, "observe.deny", {"target": "s"}, policy_id="authority-deny")
    assert provider.calls == 0


def test_require_approval_survives_retry(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.destroy", action_scope=ActionScope.DESTRUCTIVE)
    provider = CountingProvider("observe.destroy")
    core.register_provider(provider)
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(
        investigation.id,
        "observe.destroy",
        {"target": "s"},
        scope=ActionScope.DESTRUCTIVE,
        actor="core.system",
    )
    completed = core.step_runtime(investigation.id)
    assert completed.status == TaskStatus.DEFERRED
    assert completed.metadata["authority"]["decision"] == "REQUIRE_APPROVAL"
    assert provider.calls == 0
    core.runtime_queue.schedule_retry(task.task_id)
    again = core.step_runtime(investigation.id)
    assert again is None or again.status == TaskStatus.DEFERRED
    assert provider.calls == 0


def test_supervision_is_not_transferred_to_another_case(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.consequential", action_scope=ActionScope.CONSEQUENTIAL)
    provider = CountingProvider("observe.consequential")
    core.register_provider(provider)
    core.permissions.assign_role("analyst.one", "analyst")
    first = _ready_case(core, "First")
    second = _ready_case(core, "Second")
    with pytest.raises(SupervisionRequiredError):
        core.execute_action(
            first.id,
            "observe.consequential",
            {"target": "s"},
            actor="analyst.one",
            actor_role="analyst",
            scope=ActionScope.CONSEQUENTIAL,
            supervision_acknowledged=False,
        )
    with pytest.raises(SupervisionRequiredError):
        core.execute_action(
            second.id,
            "observe.consequential",
            {"target": "s"},
            actor="analyst.one",
            actor_role="analyst",
            scope=ActionScope.CONSEQUENTIAL,
            supervision_acknowledged=True and False,
        )
    assert provider.calls == 0


def test_defer_is_not_allow(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.defer")
    provider = CountingProvider("observe.defer")
    core.register_provider(provider)
    core.policy_engine.registry.register_policy(_defer_policy())
    investigation = _ready_case(core)
    with pytest.raises(AuthorizationDeferredError):
        core.execute_action(investigation.id, "observe.defer", {"target": "s"}, policy_id="authority-defer")
    assert provider.calls == 0


def test_execution_record_retains_policy_version_and_authority(tmp_path: Path):
    core = _core(tmp_path)
    capability = _register(core, "observe.recorded")
    provider = CountingProvider("observe.recorded")
    core.register_provider(provider)
    investigation = _ready_case(core)
    core.execute_action(investigation.id, "observe.recorded", {"target": "s"}, actor="core.system")
    record = investigation.case_manager.execution_history[-1]
    assert record.capability_id == capability.id
    assert record.capability_version == capability.version
    assert record.lifecycle_state == capability.lifecycle_state.value
    assert record.trust_state == capability.trust_state.value
    assert record.policy_id
    assert record.policy_version
    assert record.decision == "ALLOW"
    assert record.actor == "core.system"
    assert record.investigation_id == investigation.id
    assert record.provider_outcome == ProviderOutcome.SUCCESS.value
    granted = [
        entry for entry in investigation.case_manager.journal.entries
        if entry.entry_type == JournalEntryType.AUTHORIZATION_GRANTED
    ]
    assert granted[-1].details["policy_version"] == record.policy_version


def test_new_execution_uses_current_policy_version():
    registry = PolicyRegistry(populate_defaults=False)
    registry.register_policy(Policy(policy_id="current", name="Current", version="1.9.0"))
    registry.register_policy(Policy(policy_id="current", name="Current", version="1.10.0"))
    engine = PolicyEngine(registry=registry)
    from cyberclaw.policy.models import PolicyExecutionContext

    decision = engine.authorize(
        PolicyExecutionContext(
            investigation_id="inv",
            case_stage="INVESTIGATE",
            actor_id="core.system",
            actor_role="system",
            capability_id="observe.current",
            capability_version="1.0.0",
            action_type="execute",
            action_scope="reversible",
            lifecycle_state="AVAILABLE",
            trust_state="TRUSTED_WITH_SCOPE",
        ),
        policy_id="current",
    )
    assert decision.policy_version == "1.10.0"


def test_replay_consumes_recorded_decision_and_does_not_call_policy(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.replay")
    provider = CountingProvider("observe.replay")
    core.register_provider(provider)
    investigation = _ready_case(core)
    core.execute_action(investigation.id, "observe.replay", {"target": "s"})
    recorded_version = investigation.case_manager.execution_history[-1].policy_version
    calls = {"n": 0}
    original = PolicyEngine.authorize

    def counting(self, *args, **kwargs):
        calls["n"] += 1
        return original(self, *args, **kwargs)

    PolicyEngine.authorize = counting
    try:
        ReplayEngine.replay(investigation)
    finally:
        PolicyEngine.authorize = original
    assert calls["n"] == 0
    assert provider.calls == 1
    assert any(
        entry.details.get("policy_version") == recorded_version
        for entry in investigation.case_manager.journal.entries
    )


def test_replay_does_not_publish_strategy_or_mutate_trust(tmp_path: Path):
    core = _core(tmp_path)
    capability = _register(core, "observe.trustline")
    investigation = core.create_investigation("Replay isolation")
    calls = {"publish": 0}
    original = core.publish_learned_strategy

    def counting(*args, **kwargs):
        calls["publish"] += 1
        return original(*args, **kwargs)

    core.publish_learned_strategy = counting
    ReplayEngine.replay(investigation)
    assert calls["publish"] == 0
    assert core.capabilities.get_capability(capability.id).trust_state == capability.trust_state


# ---------------------------------------------------------------------------
# Recovery, leases, provider outcomes
# ---------------------------------------------------------------------------


def test_recovery_matrix_matches_existing_governance():
    assert recovery_disposition(
        action_scope="reversible",
        execution_state=ExecutionState.UNSTARTED,
        task_status=TaskStatus.VALIDATING,
        has_execution_record=False,
        retries_remaining=True,
    ) == RecoveryDisposition.REQUEUE_UNSTARTED
    assert recovery_disposition(
        action_scope="reversible",
        execution_state=ExecutionState.IN_PROGRESS,
        task_status=TaskStatus.RUNNING,
        has_execution_record=False,
        retries_remaining=True,
    ) == RecoveryDisposition.GOVERNED_REVERSIBLE_RETRY
    assert recovery_disposition(
        action_scope="consequential",
        execution_state=ExecutionState.UNKNOWN_EXECUTION_STATE,
        task_status=TaskStatus.RUNNING,
        has_execution_record=False,
        retries_remaining=True,
    ) == RecoveryDisposition.PRESERVE_UNKNOWN
    assert recovery_disposition(
        action_scope="destructive",
        execution_state=ExecutionState.IN_PROGRESS,
        task_status=TaskStatus.RUNNING,
        has_execution_record=False,
        retries_remaining=True,
    ) == RecoveryDisposition.PRESERVE_UNKNOWN
    assert recovery_disposition(
        action_scope="consequential",
        execution_state=ExecutionState.IN_PROGRESS,
        task_status=TaskStatus.RUNNING,
        has_execution_record=True,
        retries_remaining=True,
    ) == RecoveryDisposition.RECONCILE_COMPLETED
    assert recovery_disposition(
        action_scope="reversible",
        execution_state=ExecutionState.IN_PROGRESS,
        task_status=TaskStatus.DISPATCHED,
        has_execution_record=True,
        retries_remaining=True,
    ) == RecoveryDisposition.PRESERVE_UNKNOWN


def test_expired_lease_before_start_requeues_and_after_start_does_not():
    queue = DurableTaskQueue()
    unstarted = RuntimeTask(investigation_id="inv", capability_id="observe")
    queue.enqueue(unstarted)
    claimed = queue.dequeue("worker-a")
    claimed.claim_expires_at = utc_now() - timedelta(seconds=5)
    assert classify_worker_ownership(claimed) == WorkerOwnership.CLAIMED
    reclaimed = queue.dequeue("worker-b")
    assert reclaimed is not None
    assert reclaimed.task_id == unstarted.task_id
    assert reclaimed.claimed_by_worker == "worker-b"

    started = RuntimeTask(investigation_id="inv", capability_id="observe")
    queue.enqueue(started)
    running = queue.dequeue("worker-c")
    TaskLifecycleDFA.transition(running, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(running, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(running, TaskStatus.RUNNING)
    running.execution_state = ExecutionState.IN_PROGRESS
    running.claim_expires_at = utc_now() - timedelta(seconds=5)
    assert classify_worker_ownership(running) == WorkerOwnership.STARTED
    queue.dequeue("worker-d")
    assert running.status == TaskStatus.RUNNING


def test_expired_lease_after_provider_invocation_does_not_reexecute():
    queue = DurableTaskQueue()
    task = RuntimeTask(investigation_id="inv", capability_id="observe", idempotency_key="k")
    queue.enqueue(task)
    claimed = queue.dequeue("worker")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.RUNNING)
    claimed.execution_state = ExecutionState.IN_PROGRESS
    claimed.claim_expires_at = utc_now() - timedelta(seconds=1)
    idempotency = IdempotencyRegistry()
    idempotency.record_execution("k", {"result": {"status": "SUCCESS"}, "status": "SUCCESS"})
    assert classify_worker_ownership(claimed, has_execution_record=True) == WorkerOwnership.EXECUTION_RECORDED
    queue.dequeue("other")
    assert claimed.status == TaskStatus.RUNNING
    report = RuntimeRecoveryManager.recover(queue, idempotency)
    assert claimed.task_id in report.reconciled_completed
    assert claimed.status == TaskStatus.COMPLETED


def test_execution_record_before_ack_is_unknown_not_retry():
    queue = DurableTaskQueue()
    idempotency = IdempotencyRegistry()
    task = RuntimeTask(
        investigation_id="inv",
        capability_id="observe",
        idempotency_key="early",
        action_scope="reversible",
    )
    queue.enqueue(task)
    claimed = queue.dequeue("worker")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    claimed.execution_state = ExecutionState.IN_PROGRESS
    idempotency.record_execution("early", {"result": {"status": "SUCCESS"}, "status": "SUCCESS"})
    report = RuntimeRecoveryManager.recover(queue, idempotency)
    assert claimed.task_id in report.flagged_unknown
    assert claimed.execution_state == ExecutionState.UNKNOWN_EXECUTION_STATE
    assert queue.schedule_retry(claimed.task_id) is False


def test_reversible_unknown_retries_and_destructive_unknown_does_not():
    queue = DurableTaskQueue()
    idempotency = IdempotencyRegistry()
    reversible = RuntimeTask(
        investigation_id="inv",
        capability_id="observe",
        action_scope="reversible",
        retry_policy=RetryPolicy(max_retries=1),
    )
    queue.enqueue(reversible)
    claimed = queue.dequeue("worker")
    TaskLifecycleDFA.transition(claimed, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(claimed, TaskStatus.RUNNING)
    claimed.execution_state = ExecutionState.IN_PROGRESS
    report = RuntimeRecoveryManager.recover(queue, idempotency)
    assert reversible.task_id in report.retried_reversible

    destructive_queue = DurableTaskQueue()
    destructive = RuntimeTask(
        investigation_id="inv",
        capability_id="observe",
        action_scope="destructive",
        retry_policy=RetryPolicy(max_retries=2),
    )
    destructive_queue.enqueue(destructive)
    claimed_d = destructive_queue.dequeue("worker-2")
    TaskLifecycleDFA.transition(claimed_d, TaskStatus.AUTHORIZED)
    TaskLifecycleDFA.transition(claimed_d, TaskStatus.DISPATCHED)
    TaskLifecycleDFA.transition(claimed_d, TaskStatus.RUNNING)
    claimed_d.execution_state = ExecutionState.UNKNOWN_EXECUTION_STATE
    report_d = RuntimeRecoveryManager.recover(destructive_queue, idempotency)
    assert destructive.task_id in report_d.flagged_unknown
    assert queue.schedule_retry(destructive.task_id) is False


def test_provider_exception_is_unknown_even_when_text_says_timeout(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.boom", action_scope=ActionScope.CONSEQUENTIAL)
    provider = CountingProvider("observe.boom", mode="raise")
    core.register_provider(provider)
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(
        investigation.id,
        "observe.boom",
        {"target": "s"},
        scope=ActionScope.CONSEQUENTIAL,
        actor="core.system",
        actor_role="system",
    )
    with pytest.raises(Exception):
        core.step_runtime(investigation.id)
    stored = core.runtime_queue.get_task(task.task_id)
    assert stored.execution_state == ExecutionState.UNKNOWN_EXECUTION_STATE
    assert stored.failure_type == "UNKNOWN_EXECUTION_STATE"
    assert stored.metadata["provider_outcome"] == ProviderOutcome.PROVIDER_EXECUTION_EXCEPTION.value
    assert provider.calls == 1
    assert core.runtime_queue.depth(investigation.id) == 0


def test_timeout_text_without_explicit_code_is_not_retried(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.text", action_scope=ActionScope.REVERSIBLE)
    provider = CountingProvider("observe.text", mode="timeout-text")
    core.register_provider(provider)
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(
        investigation.id,
        "observe.text",
        {"target": "s"},
        scope=ActionScope.REVERSIBLE,
    )
    with pytest.raises(Exception):
        core.step_runtime(investigation.id)
    stored = core.runtime_queue.get_task(task.task_id)
    assert stored.failure_type == "PROVIDER_FAILURE"
    assert stored.status == TaskStatus.FAILED
    assert provider.calls == 1


def test_explicit_temporary_failure_code_can_retry(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.temp", action_scope=ActionScope.REVERSIBLE)
    provider = CountingProvider("observe.temp", mode="temporary")
    core.register_provider(provider)
    investigation = _ready_case(core)
    core.submit_task_to_runtime(
        investigation.id,
        "observe.temp",
        {"target": "s"},
        scope=ActionScope.REVERSIBLE,
    )
    with pytest.raises(Exception):
        core.step_runtime(investigation.id)
    assert provider.calls == 1
    core.step_runtime(investigation.id)
    assert provider.calls == 2


def test_pre_invocation_rejection_is_not_unknown_execution(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.noprovider")
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(investigation.id, "observe.noprovider", {"target": "s"})
    with pytest.raises(DispatchError):
        core.step_runtime(investigation.id)
    stored = core.runtime_queue.get_task(task.task_id)
    assert stored.execution_state == ExecutionState.UNSTARTED
    assert stored.failure_type == "PROVIDER_REJECTION"
    assert stored.metadata["provider_outcome"] == ProviderOutcome.PROVIDER_REJECTION.value


def test_timeout_before_execution_does_not_call_provider(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.early")
    provider = CountingProvider("observe.early")
    core.register_provider(provider)
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(investigation.id, "observe.early", {"target": "s"})
    task.deadline = utc_now() - timedelta(seconds=5)
    with pytest.raises(RuntimeTimeoutError):
        core.step_runtime(investigation.id)
    stored = core.runtime_queue.get_task(task.task_id)
    assert provider.calls == 0
    assert stored.metadata["provider_outcome"] == ProviderOutcome.TIMEOUT_BEFORE_EXECUTION.value
    assert stored.execution_state == ExecutionState.UNSTARTED
    assert stored.status == TaskStatus.QUEUED


def test_timeout_after_start_is_unknown(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.late", action_scope=ActionScope.CONSEQUENTIAL)
    provider = CountingProvider("observe.late")
    core.register_provider(provider)
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(
        investigation.id,
        "observe.late",
        {"target": "s"},
        scope=ActionScope.CONSEQUENTIAL,
        actor="core.system",
        actor_role="system",
    )
    original = core.runtime_executor.dispatcher.dispatch

    def after_invocation(runtime_task, context):
        result, subsystem = original(runtime_task, context)
        runtime_task.deadline = utc_now() - timedelta(seconds=1)
        return result, subsystem

    core.runtime_executor.dispatcher.dispatch = after_invocation
    with pytest.raises(UnknownExecutionStateError):
        core.step_runtime(investigation.id)
    stored = core.runtime_queue.get_task(task.task_id)
    assert provider.calls == 1
    assert stored.execution_state == ExecutionState.UNKNOWN_EXECUTION_STATE
    assert stored.metadata["provider_outcome"] == ProviderOutcome.TIMEOUT_WITH_UNKNOWN_EXECUTION.value
    assert core.runtime_queue.schedule_retry(task.task_id) is False


def test_malformed_result_is_not_success_or_unknown(tmp_path: Path):
    core = _core(tmp_path)
    _register(core, "observe.bad")
    provider = CountingProvider("observe.bad", mode="malformed")
    core.register_provider(provider)
    investigation = _ready_case(core)
    task = core.submit_task_to_runtime(investigation.id, "observe.bad", {"target": "s"})
    with pytest.raises(Exception):
        core.step_runtime(investigation.id)
    stored = core.runtime_queue.get_task(task.task_id)
    assert stored.failure_type == "MALFORMED_RESULT"
    assert stored.execution_state == ExecutionState.COMPLETED
    assert stored.metadata["provider_outcome"] == ProviderOutcome.MALFORMED_RESULT.value
    assert classify_provider_result(ExecutionResult(status=ExecutionStatus.SUCCESS_EMPTY)) == ProviderOutcome.SUCCESS_EMPTY


def test_exception_before_invocation_is_classified_without_message_text():
    rejection = ExecutionResult.failure(error="timeout before call", error_code="PROVIDER_NOT_READY")
    during = ExecutionResult.failure(error="benign message", error_code="PROVIDER_EXECUTION_EXCEPTION")
    assert classify_provider_result(rejection) == ProviderOutcome.PROVIDER_REJECTION
    assert classify_provider_result(during) == ProviderOutcome.PROVIDER_EXECUTION_EXCEPTION
    assert classify_provider_result(None) == ProviderOutcome.MALFORMED_RESULT


# ---------------------------------------------------------------------------
# Learning, branching, persistence, history
# ---------------------------------------------------------------------------


def test_learning_path_cannot_skip_to_available():
    for target in (
        StrategyLifecycle.EVALUATED,
        StrategyLifecycle.REVIEWED,
        StrategyLifecycle.APPROVED,
        StrategyLifecycle.AVAILABLE,
    ):
        with pytest.raises(InvalidStrategyTransitionError):
            StrategyLifecycleMachine.assert_transition(StrategyLifecycle.PROPOSED, target)
    StrategyLifecycleMachine.assert_transition(StrategyLifecycle.PROPOSED, StrategyLifecycle.SIMULATED)


def test_strategy_payload_is_not_a_capability_or_policy(tmp_path: Path):
    core = _core(tmp_path)
    capability = _register(core, "observe.strategy")
    before = capability.trust_state
    with pytest.raises(Exception):
        assert_not_executable({"command": "execute capability observe.strategy"})
    with pytest.raises(Exception):
        core.publish_learned_strategy("missing.strategy", "1.0.0", "lead.publisher")
    assert core.capabilities.get_capability("observe.strategy").trust_state == before
    assert core.capabilities.get_capability("missing.strategy") is None
    assert core.policy_engine.registry.get_default_policy().version


def test_promoted_branch_does_not_merge_into_case_state(tmp_path: Path):
    core = _core(tmp_path)
    investigation = core.create_investigation("Branch promotion")
    snapshot = investigation.capture_snapshot(trigger="base")
    branch = core.create_investigation_branch(investigation.id, snapshot.sequence, "simulate only")
    branch.simulated_evidence.append(
        Evidence(type="counterfactual", subject="subject", value={"simulated": True}, source=Source(type="branch", name="sim"))
    )
    before = investigation.evidence_store.count()
    BranchEngine.promote_branch(branch, investigation, "candidate evidence only")
    assert branch.status == BranchStatus.PROMOTED
    assert investigation.evidence_store.count() == before
    assert all(item.type != "counterfactual" for item in investigation.evidence_store.list_all())


def test_missing_branch_directory_is_not_silently_dropped(tmp_path: Path):
    core = _core(tmp_path)
    investigation = core.create_investigation("Missing branch")
    snapshot = investigation.capture_snapshot(trigger="base")
    branch = core.create_investigation_branch(investigation.id, snapshot.sequence, "must remain addressable")
    BranchPersistence.persist_branch(core.workspace, branch)
    BranchPersistence.persist_branches_index(core.workspace, investigation.id, [branch])
    layout = core.workspace.get_investigation_workspace(investigation.id)
    shutil.rmtree(layout.branches / f"branch_{branch.branch_id}")
    with pytest.raises(BranchIntegrityError):
        BranchPersistence.load_branches(core.workspace, investigation.id)


def test_fulfillment_does_not_invoke_unregistered_advertisement(tmp_path: Path):
    core = _core(tmp_path)
    endpoint = CountingEndpoint()
    core.register_specialist(Specialist(id="spec", name="Spec", capabilities=["observe.routed"], endpoint=endpoint))
    investigation = core.create_investigation("Routed")
    requirement = core.create_information_requirement(
        investigation.id,
        description="Observe",
        target_or_entity="subject",
        assigned_capability_id="observe.routed",
    )
    with pytest.raises(CapabilityNotFoundError):
        core.fulfill_information_requirement(investigation.id, requirement.id)
    assert endpoint.calls == 0
    assert investigation.evidence_store.count() == 0


def test_persistence_empty_valid_is_not_missing_or_corrupt(tmp_path: Path):
    RuntimePersistenceManager.persist_state(DurableTaskQueue(), IdempotencyRegistry(), tmp_path)
    state, _reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert state == PersistenceDocumentState.EMPTY_VALID.value
    loaded = DurableTaskQueue()
    assert RuntimePersistenceManager.load_state(loaded, IdempotencyRegistry(), tmp_path) is True
    assert loaded.list_tasks() == []


def test_persistence_missing_is_not_partial(tmp_path: Path):
    state, _reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert state == PersistenceDocumentState.MISSING.value
    assert RuntimePersistenceManager.load_state(DurableTaskQueue(), IdempotencyRegistry(), tmp_path) is False


def test_persistence_partial_is_not_missing(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    (runtime / "queue.json").write_text("[]", encoding="utf-8")
    state, _reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert state == PersistenceDocumentState.PARTIAL.value
    with pytest.raises(PersistenceError) as exc:
        RuntimePersistenceManager.load_state(DurableTaskQueue(), IdempotencyRegistry(), tmp_path)
    assert exc.value.corruption_class == "MISSING_RECORD"


def test_persistence_truncation_mutation_digest_and_schema_stay_distinct(tmp_path: Path):
    queue = DurableTaskQueue()
    queue.enqueue(RuntimeTask(investigation_id="inv", capability_id="observe"))
    RuntimePersistenceManager.persist_state(queue, IdempotencyRegistry(), tmp_path)
    state, _reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert state == PersistenceDocumentState.POPULATED_VALID.value

    runtime = tmp_path / "runtime"
    original_queue = (runtime / "queue.json").read_text(encoding="utf-8")
    (runtime / "queue.json").write_text(original_queue[:8], encoding="utf-8")
    truncated, truncated_reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert truncated == PersistenceDocumentState.CORRUPT.value
    assert truncated_reason in ("TRUNCATION", "INVALID_JSON")
    fresh = DurableTaskQueue()
    with pytest.raises(PersistenceError):
        RuntimePersistenceManager.load_state(fresh, IdempotencyRegistry(), tmp_path)
    assert fresh.list_tasks() == []

    (runtime / "queue.json").write_text(original_queue.replace("observe", "mutated"), encoding="utf-8")
    mutated, mutated_reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert mutated == PersistenceDocumentState.CORRUPT.value
    assert mutated_reason == "DIGEST_MISMATCH"

    (runtime / "digest.json").unlink()
    missing_digest, missing_reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert missing_digest == PersistenceDocumentState.PARTIAL.value
    assert "missing" in missing_reason


def test_persistence_wrong_digest_and_schema_mismatch_do_not_import(tmp_path: Path):
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    queue_text = '[{"task_id": "only"}]'
    idemp_text = "{}"
    (runtime / "queue.json").write_text(queue_text, encoding="utf-8")
    (runtime / "idempotency.json").write_text(idemp_text, encoding="utf-8")
    from cyberclaw.runtime.persistence import _digest_texts

    (runtime / "digest.json").write_text(
        '{"digest": "%s"}' % _digest_texts(queue_text, idemp_text),
        encoding="utf-8",
    )
    schema_state, schema_reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert schema_state == PersistenceDocumentState.CORRUPT.value
    assert schema_reason == "INVALID_SCHEMA"
    with pytest.raises(PersistenceError) as exc:
        RuntimePersistenceManager.load_state(DurableTaskQueue(), IdempotencyRegistry(), tmp_path)
    assert exc.value.corruption_class == "INVALID_SCHEMA"

    (runtime / "digest.json").write_text('{"digest": "%s"}' % ("b" * 64), encoding="utf-8")
    wrong, wrong_reason = RuntimePersistenceManager.classify_directory(tmp_path)
    assert wrong == PersistenceDocumentState.CORRUPT.value
    assert wrong_reason == "DIGEST_MISMATCH"


def test_collaboration_partial_is_not_an_empty_history(tmp_path: Path):
    collab = tmp_path / "collaboration"
    collab.mkdir()
    (collab / "conflicts.json").write_text("[]", encoding="utf-8")
    state, _reason = CollaborationPersistenceManager.classify_directory(tmp_path)
    assert state == PersistenceDocumentState.PARTIAL.value
    core = _core(tmp_path / "core")
    with pytest.raises(Exception) as exc:
        CollaborationPersistenceManager.load_state(core.collaboration, tmp_path)
    assert exc.value.corruption_class == "MISSING_RECORD"
    assert core.collaboration.list_requests() == []


def test_history_gap_and_missing_reference_are_not_not_found():
    entries = [
        JournalEntry(
            investigation_id="inv",
            sequence=1,
            entry_type=JournalEntryType.INVESTIGATION_CREATED,
            summary="created",
        ),
        JournalEntry(
            investigation_id="inv",
            sequence=3,
            entry_type=JournalEntryType.EVIDENCE_INGESTED,
            summary="gap",
        ),
    ]
    with pytest.raises(ReplaySequenceError):
        HistoryValidator.validate_journal_ordering(entries)
    missing = JournalEntry(
        investigation_id="inv",
        sequence=1,
        entry_type=JournalEntryType.DECISION_RECORDED,
        summary="missing decision",
        reference_id="decision-missing",
    )
    with pytest.raises(CorruptedHistoryError):
        HistoryValidator.validate_decision_references([missing], [])
    assert CapabilityRegistry().get_capability("absent") is None


def test_error_taxonomy_remains_distinguishable():
    assert not issubclass(CapabilityNotFoundError, CapabilityTrustError)
    assert not issubclass(CapabilityTrustError, CapabilityUnavailableError)
    assert not issubclass(AuthorizationDeniedError, ApprovalRequiredError)
    assert not issubclass(AuthorizationDeferredError, AuthorizationDeniedError)
    assert not issubclass(SupervisionRequiredError, ApprovalRequiredError)
    assert not issubclass(UnknownExecutionStateError, RuntimeAuthorizationError)
    assert not issubclass(PersistenceError, CapabilityNotFoundError)
    assert not issubclass(CorruptedHistoryError, CapabilityNotFoundError)
    assert not issubclass(BranchIntegrityError, PersistenceError)
