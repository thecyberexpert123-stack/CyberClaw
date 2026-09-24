"""Tests for collaboration dependency graphs, cycle detection, hard/soft semantics, and routing."""

from __future__ import annotations

import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.collaboration.dependencies import CollaborationDependencyGraph
from cyberclaw.collaboration.errors import DependencyCycleError
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    ContextSensitivity,
    DependencyRelation,
    DependencyType,
)
from cyberclaw.collaboration.routing import CollaborationRouter
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import SpecialistEndpoint, SpecialistHealth
from cyberclaw.specialists.registry import SpecialistRegistry


class HealthyEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request):
        from cyberclaw.evidence.result import ExecutionResult
        from cyberclaw.specialists.endpoint import SpecialistResponse
        return SpecialistResponse.from_result("healthy", getattr(request, "request_id", "req-1"), ExecutionResult.success())


class DegradedEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.DEGRADED

    def invoke(self, request):
        from cyberclaw.evidence.result import ExecutionResult
        from cyberclaw.specialists.endpoint import SpecialistResponse
        return SpecialistResponse.from_result("degraded", getattr(request, "request_id", "req-1"), ExecutionResult.failure("degraded"))


class UnhealthyEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.UNHEALTHY

    def invoke(self, request):
        from cyberclaw.evidence.result import ExecutionResult
        from cyberclaw.specialists.endpoint import SpecialistResponse
        return SpecialistResponse.from_result("unhealthy", getattr(request, "request_id", "req-1"), ExecutionResult.failure("unhealthy"))


def test_dependency_graph_and_direct_cycle_rejection():
    """Verify dependency graph rejects self-referential cycles immediately."""
    graph = CollaborationDependencyGraph()
    with pytest.raises(DependencyCycleError) as exc:
        graph.add_dependency(source_id="req-A", target_id="req-A")
    assert "Self-referential dependency" in str(exc.value)


def test_dependency_graph_multi_hop_cycle_detection():
    """Verify multi-hop cycles (A -> B -> C -> A) are detected and rolled back."""
    graph = CollaborationDependencyGraph()
    graph.add_dependency(source_id="req-A", target_id="req-B")
    graph.add_dependency(source_id="req-B", target_id="req-C")

    # Adding req-C -> req-A creates a cycle A -> B -> C -> A
    with pytest.raises(DependencyCycleError) as exc:
        graph.add_dependency(source_id="req-C", target_id="req-A")
    assert "Cyclical dependency detected" in str(exc.value)

    # Graph remains valid and acyclic after rollback
    assert graph.detect_cycles() == []


def test_hard_vs_soft_dependency_evaluation():
    """Verify hard dependencies strictly block execution while soft dependencies permit execution with uncertainty markers."""
    graph = CollaborationDependencyGraph()
    graph.add_dependency("task-main", "task-hard-1", dependency_type=DependencyType.HARD)
    graph.add_dependency("task-main", "task-soft-2", dependency_type=DependencyType.SOFT)

    # 1. No dependencies resolved
    can_exec, missing_hard, missing_soft = graph.check_dependencies("task-main", resolved_ids=set())
    assert can_exec is False
    assert "task-hard-1" in missing_hard
    assert "task-soft-2" in missing_soft

    # 2. Only soft dependency resolved (hard still missing)
    can_exec, missing_hard, missing_soft = graph.check_dependencies("task-main", resolved_ids={"task-soft-2"})
    assert can_exec is False
    assert "task-hard-1" in missing_hard
    assert len(missing_soft) == 0

    # 3. Only hard dependency resolved (soft still missing)
    can_exec, missing_hard, missing_soft = graph.check_dependencies("task-main", resolved_ids={"task-hard-1"})
    assert can_exec is True  # Soft dependency allows execution!
    assert len(missing_hard) == 0
    assert "task-soft-2" in missing_soft


def test_collaboration_routing_explicit_target_selection():
    """Verify router honors an explicitly declared target specialist when healthy and authorized."""
    specs = SpecialistRegistry()
    caps = CapabilityRegistry()
    router = CollaborationRouter(specs, caps)

    target = Specialist(
        id="specialist.network",
        name="Network Specialist",
        capabilities=["net.scan"],
        endpoint=HealthyEndpoint(),
        capacity=5,
        active_workload=1,
    )
    specs.register_specialist(target)

    req = CollaborationRequest(
        investigation_id="inv-route-01",
        requesting_specialist="specialist.osint",
        target_specialist="specialist.network",
        objective="Port scan target",
        required_capabilities=["net.scan"],
    )

    decision = router.route(req)
    assert decision.is_successful is True
    assert decision.selected_specialist_id == "specialist.network"
    assert decision.selected_capability_id == "net.scan"
    assert "is eligible and ready" in decision.rationale


def test_collaboration_routing_dynamic_matching_and_capacity_gating():
    """Verify router dynamically selects the best candidate matching capabilities and available capacity without domain hardcoding."""
    specs = SpecialistRegistry()
    caps = CapabilityRegistry()
    router = CollaborationRouter(specs, caps)

    # Specialist 1: Busy at full capacity (10/10)
    spec_busy = Specialist(
        id="spec.provider.busy",
        name="Busy Worker",
        capabilities=["service.identify"],
        endpoint=HealthyEndpoint(),
        capacity=10,
        active_workload=10,
    )
    # Specialist 2: Degraded health
    spec_degraded = Specialist(
        id="spec.provider.unhealthy",
        name="Unhealthy Worker",
        capabilities=["service.identify"],
        endpoint=DegradedEndpoint(),
        capacity=10,
        active_workload=0,
    )
    # Specialist 3: Healthy with available capacity (2/10 active)
    spec_available = Specialist(
        id="spec.provider.available",
        name="Available Worker",
        capabilities=["service.identify"],
        endpoint=HealthyEndpoint(),
        capacity=10,
        active_workload=2,
    )

    specs.register_specialist(spec_busy)
    specs.register_specialist(spec_degraded)
    specs.register_specialist(spec_available)

    req = CollaborationRequest(
        investigation_id="inv-route-02",
        requesting_specialist="specialist.osint",
        target_specialist=None,  # Dynamic routing
        objective="Identify service protocol on port 8443",
        required_capabilities=["service.identify"],
    )

    decision = router.route(req)
    assert decision.is_successful is True
    assert decision.selected_specialist_id == "spec.provider.available"
    assert decision.selected_capability_id == "service.identify"
    assert len(decision.candidate_evaluations) == 3

    # Check candidate explanations
    busy_eval = next(c for c in decision.candidate_evaluations if c["specialist_id"] == "spec.provider.busy")
    assert busy_eval["is_eligible"] is False
    assert any("at capacity" in r for r in busy_eval["reasons"])

    degraded_eval = next(c for c in decision.candidate_evaluations if c["specialist_id"] == "spec.provider.unhealthy")
    assert degraded_eval["is_eligible"] is False
    assert any("degraded" in r.lower() for r in degraded_eval["reasons"])


def test_collaboration_routing_missing_capability():
    """Verify routing fails gracefully with diagnostic explanations when no specialist supports the required capability."""
    specs = SpecialistRegistry()
    caps = CapabilityRegistry()
    router = CollaborationRouter(specs, caps)

    spec = Specialist(
        id="spec.network_only",
        name="Network Specialist",
        endpoint=HealthyEndpoint(),
        capabilities=["net.probe"],
    )
    specs.register_specialist(spec)

    req = CollaborationRequest(
        investigation_id="inv-route-03",
        requesting_specialist="specialist.osint",
        objective="Analyze binary firmware",
        required_capabilities=["firmware.decompile"],
    )

    decision = router.route(req)
    assert decision.is_successful is False
    assert decision.selected_specialist_id is None
    assert "Lacks required capabilities" in decision.rationale


def test_dependency_graph_blocking_semantics_and_unblocking():
    """Verify DAG correctly tracks blocking relationships and unblocks downstream requests upon dependency satisfaction."""
    graph = CollaborationDependencyGraph()

    req_upstream = "req-upstream-001"
    req_downstream = "req-downstream-002"

    graph.add_dependency(
        source_id=req_downstream,
        target_id=req_upstream,
        dependency_type=DependencyType.HARD,
        relation=DependencyRelation.DEPENDS_ON,
    )

    # Downstream is blocked
    can_exec, missing_hard, _ = graph.check_dependencies(req_downstream, resolved_ids=set())
    assert can_exec is False
    assert req_upstream in missing_hard
    assert graph.is_blocked(req_downstream, resolved_ids=set()) is True

    # Once upstream resolves, downstream is unblocked
    resolved = {req_upstream}
    can_exec_after, missing_after, _ = graph.check_dependencies(req_downstream, resolved_ids=resolved)
    assert can_exec_after is True
    assert len(missing_after) == 0
    assert graph.is_blocked(req_downstream, resolved_ids=resolved) is False


def test_collaboration_routing_unhealthy_endpoint():
    """Verify specialists with UNHEALTHY health status are disqualified from routing."""
    specs = SpecialistRegistry()
    caps = CapabilityRegistry()
    router = CollaborationRouter(specs, caps)

    cap = Capability(id="osint.scrape", name="Scraper")
    caps.register_capability(cap)

    spec_unhealthy = Specialist(
        id="spec.offline",
        name="Offline Specialist",
        endpoint=UnhealthyEndpoint(),
        capabilities=["osint.scrape"],
        capacity=5,
        active_workload=0,
    )
    specs.register_specialist(spec_unhealthy)

    req = CollaborationRequest(
        investigation_id="inv-route-04",
        requesting_specialist="specialist.planner",
        target_specialist="spec.offline",
        objective="Scrape web source",
        required_capabilities=["osint.scrape"],
    )

    decision = router.route(req)
    assert decision.is_successful is False
    assert "unhealthy" in decision.rationale.lower()

