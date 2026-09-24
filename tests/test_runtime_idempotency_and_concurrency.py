"""Tests for stable task identity, idempotency, duplicate protection, and concurrency serialization."""

from __future__ import annotations

import concurrent.futures
from typing import Any, Dict, List
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.investigation import Investigation
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.engine import PolicyEngine
from cyberclaw.runtime.dispatcher import SpecialistDispatcher
from cyberclaw.runtime.events import EventFactory, RuntimeEventType
from cyberclaw.runtime.executor import RuntimeExecutor
from cyberclaw.runtime.idempotency import (
    IdempotencyRegistry,
    compute_task_idempotency_key,
)
from cyberclaw.runtime.models import (
    ExecutionState,
    RuntimeTask,
    TaskStatus,
)
from cyberclaw.runtime.queue import DurableTaskQueue
from cyberclaw.runtime.scheduler import RuntimeScheduler
from cyberclaw.specialists.registry import SpecialistRegistry
from cyberclaw.types import Source


class MockCountProvider(CapabilityProvider):
    """Provider tracking invocation count to verify duplicate execution prevention."""

    def __init__(self, capability_id: str) -> None:
        super().__init__(id=f"provider.{capability_id}", capability_id=capability_id, name="Count Provider")
        self.call_count = 0

    def is_ready(self, context: Any = None):
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        self.call_count += 1
        ev = Evidence(
            type="counter_finding",
            subject=parameters.get("target", "unknown"),
            value={"invocation_count": self.call_count},
            source=Source(type="mock", name=self.id),
        )
        return ExecutionResult.success(output={"count": self.call_count}, evidence=[ev])


def test_stable_task_identity_computation():
    """Verify compute_task_idempotency_key produces stable keys regardless of dict ordering."""
    p1 = {"domain": "apex.org", "port": 443}
    p2 = {"port": 443, "domain": "apex.org"}

    k1 = compute_task_idempotency_key(
        investigation_id="inv-idemp-01",
        capability_id="tool.scan",
        parameters=p1,
    )
    k2 = compute_task_idempotency_key(
        investigation_id="inv-idemp-01",
        capability_id="tool.scan",
        parameters=p2,
    )
    assert k1 == k2

    # Different parameter values must produce distinct keys
    p3 = {"domain": "victim.org", "port": 443}
    k3 = compute_task_idempotency_key(
        investigation_id="inv-idemp-01",
        capability_id="tool.scan",
        parameters=p3,
    )
    assert k1 != k3


def test_duplicate_event_delivery_protection():
    """Verify IdempotencyRegistry identifies duplicate events by ID and idempotency key."""
    idemp = IdempotencyRegistry()
    evt = EventFactory.create_event(
        event_type=RuntimeEventType.REQUIREMENT_CREATED,
        investigation_id="inv-idemp-02",
        sequence=1,
        idempotency_key="event-key-100",
    )

    assert idemp.is_duplicate_event(evt.event_id, evt.idempotency_key) is False
    idemp.record_event(evt)
    assert idemp.is_duplicate_event(evt.event_id, evt.idempotency_key) is True
    assert idemp.is_duplicate_event("different_id", "event-key-100") is True


def test_duplicate_execution_prevention():
    """Verify that attempting to execute an already-completed task reconciles without re-running provider."""
    caps = CapabilityRegistry()
    specialists = SpecialistRegistry()
    perms = PermissionManager()
    policy = PolicyEngine()
    queue = DurableTaskQueue()
    idemp = IdempotencyRegistry()
    dispatcher = SpecialistDispatcher(specialists, caps)
    executor = RuntimeExecutor(caps, policy, dispatcher, queue, idemp)

    cap_id = "test.idempotent_cap"
    cap = Capability(
        id=cap_id,
        name="Idempotent Cap",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    caps.register_capability(cap)
    provider = MockCountProvider(cap_id)
    caps.register_provider(provider)

    inv = Investigation(id="inv-idemp-03", title="Idempotency Test Case")
    inv.dfa.transition(CoreState.READY, event="ready")
    inv.dfa.transition(CoreState.INVESTIGATE, event="start")

    idemp_key = compute_task_idempotency_key("inv-idemp-03", cap_id, parameters={"target": "apex.org"})
    t1 = RuntimeTask(
        investigation_id="inv-idemp-03",
        capability_id=cap_id,
        action_scope="reversible",
        parameters={"target": "apex.org"},
        idempotency_key=idemp_key,
    )
    queue.enqueue(t1)

    # First execution: provider is invoked
    claimed1 = queue.dequeue("worker-1")
    res1 = executor.execute_task(claimed1, inv, perms)
    assert res1.status == TaskStatus.COMPLETED
    assert provider.call_count == 1

    # Second execution with identical task identity: provider must NOT be called again
    t2 = RuntimeTask(
        investigation_id="inv-idemp-03",
        capability_id=cap_id,
        action_scope="reversible",
        parameters={"target": "apex.org"},
        idempotency_key=idemp_key,
    )
    queue.enqueue(t2)
    claimed2 = queue.dequeue("worker-2")
    res2 = executor.execute_task(claimed2, inv, perms)
    assert res2.status == TaskStatus.COMPLETED
    assert provider.call_count == 1  # Still 1! Not re-executed!


def test_double_claim_protection():
    """Verify that when multiple concurrent workers race to claim a task, exactly one succeeds."""
    queue = DurableTaskQueue()
    task = RuntimeTask(investigation_id="inv-conc-01", capability_id="tool.probe")
    queue.enqueue(task)

    results: List[Any] = []

    def try_claim(worker_name: str):
        return queue.dequeue(worker_id=worker_name)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        futures = [ex.submit(try_claim, f"worker-{i}") for i in range(8)]
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())

    claimed = [r for r in results if r is not None]
    unclaimed = [r for r in results if r is None]

    assert len(claimed) == 1
    assert len(unclaimed) == 7
    assert claimed[0].task_id == task.task_id


def test_case_level_serialization():
    """Verify concurrent tasks within the same investigation execute serialized without race corruption."""
    caps = CapabilityRegistry()
    specialists = SpecialistRegistry()
    perms = PermissionManager()
    policy = PolicyEngine()
    queue = DurableTaskQueue()
    idemp = IdempotencyRegistry()
    dispatcher = SpecialistDispatcher(specialists, caps)
    executor = RuntimeExecutor(caps, policy, dispatcher, queue, idemp)
    scheduler = RuntimeScheduler(queue, executor)

    cap_id = "test.serial_cap"
    cap = Capability(
        id=cap_id,
        name="Serial Cap",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    caps.register_capability(cap)
    provider = MockCountProvider(cap_id)
    caps.register_provider(provider)

    inv = Investigation(id="inv-serial-01", title="Serial Test Case")
    inv.dfa.transition(CoreState.READY, event="ready")
    inv.dfa.transition(CoreState.INVESTIGATE, event="start")

    # Enqueue 5 distinct tasks
    for i in range(5):
        t = RuntimeTask(
            investigation_id="inv-serial-01",
            capability_id=cap_id,
            action_scope="reversible",
            parameters={"target": f"target-{i}.org"},
            idempotency_key=f"serial-key-{i}",
        )
        queue.enqueue(t)

    assert queue.depth("inv-serial-01") == 5

    def worker_loop(w_id: str):
        processed = []
        while True:
            try:
                task = scheduler.step(inv, perms)
                if not task:
                    break
                processed.append(task.task_id)
            except Exception:
                break
        return processed

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futures = [ex.submit(worker_loop, f"w-{i}") for i in range(4)]
        all_results = []
        for f in concurrent.futures.as_completed(futures):
            all_results.extend(f.result())

    assert len(all_results) == 5
    assert queue.depth("inv-serial-01") == 0
    assert len(inv.case_manager.execution_history) == 5
