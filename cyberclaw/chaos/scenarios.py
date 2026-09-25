"""Cross-subsystem chaos scenarios. They use existing engines; they do not reimplement them."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.chaos.faults import FaultInjector, FaultedProvider
from cyberclaw.chaos.invariants import InvariantContext, InvariantRegistry
from cyberclaw.chaos.models import FaultSpec, FaultType
from cyberclaw.chaos.reports import build_report, bundle_from_parts
from cyberclaw.chaos.runner import investigation_structure, structure_digest, trace
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.models import Policy, PolicyEffect, PolicyExecutionContext
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.types import Source


class CountingProvider(CapabilityProvider):
    def __init__(self, capability_id: str = "chaos.observe") -> None:
        super().__init__(id=f"provider.{capability_id}", name="Counting provider", capability_id=capability_id)
        self.calls = 0

    def is_ready(self, context=None):
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        self.calls += 1
        evidence = Evidence(
            id=f"ev-{self.capability_id}-{self.calls}",
            type="finding",
            subject=parameters.get("target", "subject"),
            value={"observed": True, "call": self.calls},
            source=Source(type="fixture", name=self.id, id="chaos-source"),
        )
        return ExecutionResult.success([evidence], output={"call": self.calls})


def _core(tmp_path: Path) -> CyberClawCore:
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    return core


def scenario_runtime_crash_recovery_replay(tmp_path: Path, seed: int = 17) -> Dict[str, Any]:
    """Claim, crash before execution, recover, complete, replay, reconstruct learning."""
    core = _core(tmp_path)
    capability = Capability(id="chaos.observe", name="Observe", action_scope=ActionScope.REVERSIBLE)
    core.register_capability(capability)
    provider = CountingProvider()
    core.register_provider(provider)
    investigation = core.create_investigation("Chaos runtime crash", targets=["subject-a"])
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="chaos.start")
    requirement = investigation.create_information_requirement(
        description="Observe subject",
        target_or_entity="subject-a",
        evidence_types_sought=["finding"],
        assigned_capability_id="chaos.observe",
    )
    task = core.submit_task_to_runtime(
        investigation.id,
        "chaos.observe",
        {"target": "subject-a"},
        requirement_id=requirement.id,
        actor="core.system",
    )
    claimed = core.runtime_queue.dequeue("chaos-worker")
    recovery = core.recover_runtime()
    core.process_runtime_queue(investigation.id)
    calls_before = provider.calls
    authorize_calls = {"count": 0}
    original = core.policy_engine.authorize

    def _counting_authorize(*args, **kwargs):
        authorize_calls["count"] += 1
        return original(*args, **kwargs)

    core.policy_engine.authorize = _counting_authorize
    replayed = ReplayEngine.replay(investigation)
    core.policy_engine.authorize = original
    calls_after = provider.calls
    ingest = core.ingest_investigation_experience(investigation.id)
    learning_replay = core.replay_learning_state()
    from cyberclaw.knowledge.materialization import KnowledgeMaterializer

    graph = KnowledgeMaterializer.materialize_from_investigation(investigation)
    graph_again = KnowledgeMaterializer.materialize_from_investigation(investigation)
    registry = InvariantRegistry()
    context = InvariantContext(
        provider_calls=provider.calls,
        evidence_count=len(investigation.evidence_store.list_all()),
        completion_count=1 if task.status.value == "COMPLETED" or core.runtime_queue.get_task(task.task_id).status.value == "COMPLETED" else 0,
        task_ids=[task.task_id],
        provider_calls_before_replay=calls_before,
        provider_calls_after_replay=calls_after,
        policy_calls_during_replay=authorize_calls["count"],
        journal_sequences=[entry.sequence for entry in investigation.case_manager.journal.entries],
    )
    invariants = registry.evaluate_many(["INV-RUNTIME-001", "INV-REPLAY-001", "INV-JOURNAL-001"], context)
    parts = {
        "journal": [entry.entry_type.value for entry in investigation.case_manager.journal.entries],
        "evidence": [item.subject for item in investigation.evidence_store.list_all()],
        "runtime": recovery.to_dict(),
        "learning_events": len(core.learning.events),
        "graph_nodes": len(graph.get_nodes()),
    }
    report = build_report(
        scenario_id="SCN-RUNTIME-CRASH-REPLAY",
        seed=seed,
        faults=[FaultSpec(fault_id="fault-worker-crash", fault_type=FaultType.WORKER_CRASH, target="runtime.worker")],
        trace=trace(["queue", "claim", "crash", "recover", "complete", "replay", "learn"]),
        invariants=invariants,
        expected={"provider_calls": 1, "replay_provider_calls": 0, "detectors_executed": 0},
        observed={
            "provider_calls": provider.calls,
            "claimed_status_before_recovery": claimed.status.value if claimed else None,
            "recovery": recovery.to_dict(),
            "replay_events": replayed.events_replayed_count,
            "learning_ok": ingest.ok,
            "detectors_executed": learning_replay.detectors_executed,
            "graph_digest_stable": graph.calculate_graph_digest() == graph_again.calculate_graph_digest(),
        },
        recovery=recovery.to_dict(),
        replay={"events": replayed.events_replayed_count, "dfa": replayed.dfa_state},
        digests=bundle_from_parts(parts),
    )
    return {
        "report": report,
        "structural_digest": structure_digest(investigation, {"calls": provider.calls}),
        "provider_calls": provider.calls,
        "detectors_executed": learning_replay.detectors_executed,
        "graph_stable": graph.calculate_graph_digest() == graph_again.calculate_graph_digest(),
        "core": core,
        "investigation": investigation,
    }


def scenario_policy_time_travel(tmp_path: Path, seed: int = 19) -> Dict[str, Any]:
    """Historical ALLOW must survive a later DENY policy, and the reverse."""
    core = _core(tmp_path)
    investigation = core.create_investigation("Chaos policy time travel")
    allow_policy = Policy(
        policy_id="chaos.time",
        name="Chaos time A",
        version="1.0.0",
        default_effect=PolicyEffect.ALLOW,
        rules=[],
    )
    deny_policy = Policy(
        policy_id="chaos.time",
        name="Chaos time B",
        version="2.0.0",
        default_effect=PolicyEffect.DENY,
        rules=[],
    )
    core.policy_engine.registry.register_policy(allow_policy)
    context = PolicyExecutionContext(
        investigation_id=investigation.id,
        case_stage=investigation.current_state.value,
        actor_id="core.system",
        actor_role="system",
        capability_id="chaos.observe",
        capability_version="1.0.0",
        action_type="execute",
        action_scope="reversible",
        lifecycle_state="AVAILABLE",
        trust_state="TRUSTED_WITH_SCOPE",
    )
    historical = core.policy_engine.authorize(context, policy_id="chaos.time", policy_version="1.0.0")
    core.policy_engine.record_in_journal(historical, investigation.case_manager)
    core.policy_engine.registry.register_policy(deny_policy)
    current = core.policy_engine.authorize(context, policy_id="chaos.time")
    calls = {"count": 0}
    original = core.policy_engine.authorize

    def _guard(*args, **kwargs):
        calls["count"] += 1
        return original(*args, **kwargs)

    core.policy_engine.authorize = _guard
    replayed = ReplayEngine.replay(investigation)
    core.policy_engine.authorize = original
    replayed_decision = None
    for decision in replayed.decisions:
        if (decision.outcome or {}).get("decision_id") == historical.decision_id or (decision.outcome or {}).get("decision"):
            replayed_decision = (decision.outcome or {}).get("decision")
    registry = InvariantRegistry()
    invariant = registry.evaluate(
        "INV-POLICY-001",
        InvariantContext(
            historical_decision=historical.decision.value,
            current_decision=current.decision.value,
            replayed_decision=replayed_decision,
            decision_ids=[historical.decision_id],
        ),
    )
    report = build_report(
        scenario_id="SCN-POLICY-TIME-TRAVEL",
        seed=seed,
        faults=[FaultSpec(fault_id="fault-policy-version", fault_type=FaultType.POLICY_VERSION_CHANGE, target="policy.registry")],
        trace=trace(["authorize-v1", "persist", "register-v2", "authorize-current", "replay"]),
        invariants=[invariant],
        expected={"historical": "ALLOW", "current": "DENY", "replayed": "ALLOW", "policy_calls_during_replay": 0},
        observed={
            "historical": historical.decision.value,
            "current": current.decision.value,
            "replayed": replayed_decision,
            "policy_calls_during_replay": calls["count"],
            "current_version": current.policy_version,
        },
        replay={"decision": replayed_decision, "policy_calls": calls["count"]},
        digests=bundle_from_parts({"journal": [e.entry_type.value for e in investigation.case_manager.journal.entries]}),
    )
    return {"report": report, "structural_digest": structure_digest(investigation), "core": core, "investigation": investigation}


def scenario_branch_learning_isolation(tmp_path: Path, seed: int = 23) -> Dict[str, Any]:
    """Counterfactual evidence and experience must not become authoritative authority."""
    core = _core(tmp_path)
    core.register_capability(Capability(id="chaos.observe", name="Observe", action_scope=ActionScope.REVERSIBLE))
    investigation = core.create_investigation("Chaos branch isolation", targets=["subject-b"])
    core.transition_investigation(investigation.id, CoreState.INVESTIGATE, event="chaos.branch")
    evidence = Evidence(
        id="ev-authoritative",
        type="finding",
        subject="subject-b",
        value={"authoritative": True},
        source=Source(type="fixture", name="source-b", id="source-b"),
    )
    investigation.add_evidence(evidence)
    snapshot = investigation.capture_snapshot(trigger="chaos-branch")
    before_ids = sorted(item.id for item in investigation.evidence_store.list_all())
    trust_before = core.capabilities.get_capability("chaos.observe").trust_state
    permissions_before = sorted(core.permissions.get_effective_permissions("core.system"))
    policy_count_before = len(core.policy_engine.registry.list_policies())
    branch = investigation.create_branch(snapshot.sequence, purpose="counterfactual leak attempt")
    from cyberclaw.branching.engine import BranchEngine

    leaked = Evidence(
        id="ev-counterfactual",
        type="finding",
        subject="subject-b",
        value={"counterfactual": True},
        source=Source(type="fixture", name="branch-source", id="branch-source"),
    )
    BranchEngine.simulate_evidence(branch, [leaked])
    after_ids = sorted(item.id for item in investigation.evidence_store.list_all())
    from cyberclaw.learning.errors import BranchExperienceQuarantineError
    from cyberclaw.learning.extraction import ExperienceExtractor

    experience = ExperienceExtractor.extract(investigation)
    counterfactual = experience.model_copy(update={"is_counterfactual": True, "branch_id": branch.branch_id})
    quarantined = False
    try:
        core.learning.store_experience(counterfactual, actor="learning.engine")
    except BranchExperienceQuarantineError:
        core.learning.quarantine_experience(counterfactual, actor="learning.engine")
        quarantined = True
    from cyberclaw.learning.errors import SelfApprovalError
    from cyberclaw.learning.governance import assert_external_actor

    self_approved = False
    try:
        assert_external_actor("learning.engine", proposer_id="analyst.proposer")
        self_approved = True
    except SelfApprovalError:
        self_approved = False
    investigation.promote_branch(branch.branch_id, reason="attempted promotion", actor="lead.reviewer")
    promoted_ids = sorted(item.id for item in investigation.evidence_store.list_all())
    registry = InvariantRegistry()
    invariants = [
        registry.evaluate(
            "INV-BRANCH-001",
            InvariantContext(
                authoritative_evidence_changed=before_ids != promoted_ids,
                capability_trust_changed=core.capabilities.get_capability("chaos.observe").trust_state != trust_before,
                permissions_changed=sorted(core.permissions.get_effective_permissions("core.system")) != permissions_before,
                policy_mutated_by_branch=len(core.policy_engine.registry.list_policies()) != policy_count_before,
                branch_ids=[branch.branch_id],
            ),
        ),
        registry.evaluate(
            "INV-LEARNING-001",
            InvariantContext(
                counterfactual_quarantined=quarantined,
                counterfactual_in_authoritative_experience=counterfactual.experience_id in core.learning._experiences,
                self_approval_succeeded=self_approved,
            ),
        ),
    ]
    report = build_report(
        scenario_id="SCN-BRANCH-LEARNING-ISOLATION",
        seed=seed,
        faults=[
            FaultSpec(fault_id="fault-branch", fault_type=FaultType.BRANCH_MUTATION_ATTEMPT, target="branch"),
            FaultSpec(fault_id="fault-leak", fault_type=FaultType.COUNTERFACTUAL_LEAK_ATTEMPT, target="learning"),
        ],
        trace=trace(["snapshot", "branch", "simulate-evidence", "quarantine", "self-approve", "promote"]),
        invariants=invariants,
        expected={"authoritative_evidence": before_ids, "self_approved": False},
        observed={"authoritative_evidence": promoted_ids, "quarantined": quarantined, "branch_counterfactual": branch.is_counterfactual},
        branch_digest=branch.calculate_state_digest(),
    )
    return {"report": report, "structural_digest": structure_digest(investigation), "core": core, "branch": branch}
