"""Explicit invariant registry. A failure explains the boundary, not just a boolean."""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from cyberclaw.chaos.models import CHAOS_SCHEMA_VERSION, InvariantResult, InvariantSeverity


class Invariant:
    def __init__(
        self,
        invariant_id: str,
        description: str,
        subsystem: str,
        severity: InvariantSeverity,
        check: Callable[["InvariantContext"], InvariantResult],
    ) -> None:
        self.invariant_id = invariant_id
        self.description = description
        self.subsystem = subsystem
        self.severity = severity
        self.check = check


class InvariantContext:
    """Observations collected by a scenario. Invariants do not invent missing facts."""

    def __init__(self, **observed: Any) -> None:
        self.observed = observed

    def get(self, key: str, default: Any = None) -> Any:
        return self.observed.get(key, default)


def _result(
    invariant: Invariant,
    passed: bool,
    what: str,
    expected: str,
    observed: str,
    boundary: str,
    references: Optional[List[str]] = None,
    digest: str = "",
) -> InvariantResult:
    return InvariantResult(
        invariant_id=invariant.invariant_id,
        description=invariant.description,
        subsystem=invariant.subsystem,
        severity=invariant.severity,
        passed=passed,
        what_happened=what,
        expected=expected,
        observed=observed,
        boundary=boundary,
        references=references or [],
        digest=digest,
        version=CHAOS_SCHEMA_VERSION,
    )


def _check_runtime_no_duplicate_execution(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    calls = int(ctx.get("provider_calls", 0))
    evidence = int(ctx.get("evidence_count", 0))
    completions = int(ctx.get("completion_count", 0))
    passed = calls <= 1 and evidence <= max(calls, 1) and completions <= 1
    return _result(
        invariant,
        passed,
        "Counted provider calls, evidence items, and completions after recovery.",
        "At most one provider execution and no duplicate evidence for one task identity.",
        f"calls={calls} evidence={evidence} completions={completions}",
        "runtime.idempotency",
        references=list(ctx.get("task_ids") or []),
    )


def _check_replay_does_not_execute(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    before = int(ctx.get("provider_calls_before_replay", 0))
    after = int(ctx.get("provider_calls_after_replay", before))
    passed = after == before and int(ctx.get("policy_calls_during_replay", 0)) == 0
    return _result(
        invariant,
        passed,
        "Replay was invoked after recording provider and policy call counts.",
        "Replay reconstructs history and does not call providers or PolicyEngine.authorize.",
        f"provider_before={before} provider_after={after} policy_calls={ctx.get('policy_calls_during_replay', 0)}",
        "replay.no_execution",
    )


def _check_historical_policy(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    historical = ctx.get("historical_decision")
    current = ctx.get("current_decision")
    replayed = ctx.get("replayed_decision")
    passed = historical is not None and replayed == historical and current != historical
    return _result(
        invariant,
        passed,
        "A later policy version was registered and both current authorization and replay were observed.",
        "Replay reports the historical decision. Current policy may differ and must not rewrite history.",
        f"historical={historical} replayed={replayed} current={current}",
        "policy.historical_decision",
        references=list(ctx.get("decision_ids") or []),
    )


def _check_branch_isolation(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    leaked = bool(ctx.get("authoritative_evidence_changed"))
    trust_changed = bool(ctx.get("capability_trust_changed"))
    permissions_changed = bool(ctx.get("permissions_changed"))
    policy_changed = bool(ctx.get("policy_mutated_by_branch"))
    passed = not leaked and not trust_changed and not permissions_changed and not policy_changed
    return _result(
        invariant,
        passed,
        "A counterfactual branch produced candidate evidence and a learning candidate.",
        "Authoritative evidence, capability trust, permissions, and policy remain unchanged.",
        f"evidence_changed={leaked} trust_changed={trust_changed} permissions_changed={permissions_changed} policy_changed={policy_changed}",
        "branch.isolation",
        references=list(ctx.get("branch_ids") or []),
    )


def _check_learning_quarantine(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    quarantined = bool(ctx.get("counterfactual_quarantined"))
    in_authoritative = bool(ctx.get("counterfactual_in_authoritative_experience"))
    self_approved = bool(ctx.get("self_approval_succeeded"))
    passed = quarantined and not in_authoritative and not self_approved
    return _result(
        invariant,
        passed,
        "A counterfactual experience was offered to the learning registry and self-approval was attempted.",
        "Counterfactual experience stays quarantined. The learning engine cannot approve itself.",
        f"quarantined={quarantined} in_authoritative={in_authoritative} self_approved={self_approved}",
        "learning.quarantine",
    )


def _check_journal_integrity(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    sequences = list(ctx.get("journal_sequences") or [])
    expected = list(range(1, len(sequences) + 1))
    passed = sequences == expected
    return _result(
        invariant,
        passed,
        "Journal sequences were read after the scenario.",
        "Sequences are contiguous starting at 1 with no gaps or duplicates.",
        f"sequences={sequences}",
        "case.journal",
    )


def _check_unknown_not_retried(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    retried = bool(ctx.get("unknown_was_retried"))
    state = ctx.get("execution_state")
    passed = not retried and state == "UNKNOWN_EXECUTION_STATE"
    return _result(
        invariant,
        passed,
        "A consequential or destructive task crashed with no recorded execution.",
        "UNKNOWN_EXECUTION_STATE is preserved and the task is not re-queued.",
        f"retried={retried} execution_state={state} status={ctx.get('task_status')}",
        "runtime.unknown_execution",
        references=list(ctx.get("task_ids") or []),
    )


def _check_corruption_fail_closed(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    raised = bool(ctx.get("corruption_raised"))
    imported = bool(ctx.get("corrupted_state_imported"))
    kind = ctx.get("corruption_class")
    passed = raised and not imported and bool(kind)
    return _result(
        invariant,
        passed,
        "A controlled corruption was applied to a persisted record and load was attempted.",
        "Load fails closed, reports a corruption class, and does not import the record.",
        f"raised={raised} imported={imported} class={kind}",
        "persistence.fail_closed",
    )


def _check_collaboration_not_authority(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    participants = int(ctx.get("participant_count", 0))
    became_authoritative = bool(ctx.get("collaboration_became_authoritative_without_evidence"))
    duplicate_corroboration = bool(ctx.get("duplicate_request_inflated_independence"))
    passed = participants >= 1 and not became_authoritative and not duplicate_corroboration
    return _result(
        invariant,
        passed,
        "Multiple specialists participated or a duplicate request was replayed.",
        "Participation count is not authority. Duplicate requests do not create extra independent sources.",
        f"participants={participants} unauthorized_authority={became_authoritative} inflated={duplicate_corroboration}",
        "collaboration.epistemic",
    )


def _check_knowledge_temporal(ctx: InvariantContext, invariant: Invariant) -> InvariantResult:
    historical_present = bool(ctx.get("historical_edge_present"))
    inference_marked = bool(ctx.get("inference_not_observation"))
    contradiction_kept = bool(ctx.get("contradiction_retained"))
    executed = int(ctx.get("providers_executed_during_graph_replay", 0))
    passed = historical_present and inference_marked and contradiction_kept and executed == 0
    return _result(
        invariant,
        passed,
        "A temporal graph was queried historically and replayed.",
        "Historical edges remain, inferences stay inferences, contradictions remain, and graph replay executes nothing.",
        f"historical={historical_present} inference_ok={inference_marked} contradiction={contradiction_kept} executed={executed}",
        "knowledge.temporal",
    )


class InvariantRegistry:
    """Stable catalog of architectural invariants."""

    def __init__(self) -> None:
        self._items: Dict[str, Invariant] = {}
        self._register_defaults()

    def register(self, invariant: Invariant) -> None:
        self._items[invariant.invariant_id] = invariant

    def get(self, invariant_id: str) -> Invariant:
        if invariant_id not in self._items:
            raise KeyError(f"Unknown invariant '{invariant_id}'")
        return self._items[invariant_id]

    def ids(self) -> List[str]:
        return sorted(self._items)

    def evaluate(self, invariant_id: str, context: InvariantContext) -> InvariantResult:
        invariant = self.get(invariant_id)
        return invariant.check(context)

    def evaluate_many(self, invariant_ids: List[str], context: InvariantContext) -> List[InvariantResult]:
        return [self.evaluate(item, context) for item in invariant_ids]

    def _register_defaults(self) -> None:
        specs = [
            ("INV-RUNTIME-001", "Recovery must not duplicate execution or evidence.", "runtime", InvariantSeverity.RUNTIME, _check_runtime_no_duplicate_execution),
            ("INV-RUNTIME-002", "Unknown execution state must not be blindly retried.", "runtime", InvariantSeverity.RUNTIME, _check_unknown_not_retried),
            ("INV-REPLAY-001", "Replay must not execute providers or re-authorize.", "replay", InvariantSeverity.RUNTIME, _check_replay_does_not_execute),
            ("INV-POLICY-001", "Historical authorization must survive current policy changes.", "policy", InvariantSeverity.POLICY, _check_historical_policy),
            ("INV-BRANCH-001", "Branch mutation must not mutate authoritative authority.", "branching", InvariantSeverity.BRANCHING, _check_branch_isolation),
            ("INV-LEARNING-001", "Counterfactual experience must not become authoritative or self-approve.", "learning", InvariantSeverity.LEARNING, _check_learning_quarantine),
            ("INV-PERSISTENCE-001", "Corrupted history must fail closed and stay unimported.", "persistence", InvariantSeverity.PERSISTENCE, _check_corruption_fail_closed),
            ("INV-JOURNAL-001", "Journal sequences must stay contiguous.", "case", InvariantSeverity.PERSISTENCE, _check_journal_integrity),
            ("INV-COLLAB-001", "Collaboration participation is not authority.", "collaboration", InvariantSeverity.COLLABORATION, _check_collaboration_not_authority),
            ("INV-KNOWLEDGE-001", "Temporal knowledge must preserve history, inference, and contradiction.", "knowledge", InvariantSeverity.KNOWLEDGE, _check_knowledge_temporal),
        ]
        for invariant_id, description, subsystem, severity, check in specs:
            invariant = Invariant(invariant_id, description, subsystem, severity, lambda ctx, inv=None, fn=check: fn(ctx, inv))
            # Bind the invariant object into the closure correctly.
            def _bound(ctx: InvariantContext, fn=check, holder=None) -> InvariantResult:
                return fn(ctx, holder)

            # The holder is assigned after construction via a small wrapper class method.
            self._items[invariant_id] = _BoundInvariant(invariant_id, description, subsystem, severity, check)


class _BoundInvariant(Invariant):
    def __init__(self, invariant_id, description, subsystem, severity, check) -> None:
        super().__init__(invariant_id, description, subsystem, severity, self._run)
        self._fn = check

    def _run(self, ctx: InvariantContext) -> InvariantResult:
        return self._fn(ctx, self)
