"""Approval and publication gates. The learning engine cannot approve itself."""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

from cyberclaw.learning.errors import (
    LearningThresholdError,
    SelfApprovalError,
    StrategyGovernanceError,
)
from cyberclaw.learning.models import (
    ARCHITECTURAL_MIN_INDEPENDENT_CASES,
    ARCHITECTURAL_MIN_INDEPENDENT_SOURCE_FAMILIES,
    LEARNING_ENGINE_ACTORS,
    ApprovalDecisionKind,
    InvestigationStrategy,
    PromotionThresholdPolicy,
    StrategyApprovalDecision,
    StrategyLifecycle,
    utc_now,
    stable_id,
)
from cyberclaw.learning.strategies import StrategyLifecycleMachine, assert_not_executable


def assert_external_actor(actor: str, proposer_id: Optional[str] = None) -> None:
    if not actor or not actor.strip():
        raise SelfApprovalError("Approval requires an external actor identity.")
    if actor in LEARNING_ENGINE_ACTORS or actor.startswith("learning."):
        raise SelfApprovalError(
            f"Actor '{actor}' is part of the learning engine and cannot approve, publish, or review its own output."
        )
    if proposer_id and actor == proposer_id:
        raise SelfApprovalError(
            f"Actor '{actor}' proposed this strategy and cannot approve it."
        )


def validate_threshold_policy(policy: PromotionThresholdPolicy) -> None:
    if policy.min_independent_cases < ARCHITECTURAL_MIN_INDEPENDENT_CASES:
        raise LearningThresholdError(
            "Threshold policy cannot lower the architectural floor of 2 independent cases."
        )
    if policy.min_independent_source_families < ARCHITECTURAL_MIN_INDEPENDENT_SOURCE_FAMILIES:
        raise LearningThresholdError(
            "Threshold policy cannot lower the architectural floor of 2 independent source families."
        )


class PolicyPrecheckResult:
    def __init__(self, allowed: bool, decision: str, decision_ids: List[str], policy_id: str, policy_version: str, reasons: List[str]) -> None:
        self.allowed = allowed
        self.decision = decision
        self.decision_ids = decision_ids
        self.policy_id = policy_id
        self.policy_version = policy_version
        self.reasons = reasons


class StrategyGovernance:
    """External approval, policy precheck, and lifecycle enforcement.

    This component does not modify policies, permissions, capability trust,
    DFA definitions, or Core code. It only records learning-ledger decisions.
    """

    @staticmethod
    def precheck(
        strategy: InvestigationStrategy,
        policy_engine: Any,
        *,
        investigation_id: str,
        actor: str,
        actor_role: str,
        case_stage: str = "INVESTIGATE",
    ) -> PolicyPrecheckResult:
        if policy_engine is None:
            return PolicyPrecheckResult(
                allowed=False,
                decision="DENY",
                decision_ids=[],
                policy_id="",
                policy_version="",
                reasons=["Fail-closed: no PolicyEngine was supplied. Learning cannot bypass policy."],
            )
        from cyberclaw.policy.engine import PolicyEngine
        from cyberclaw.policy.models import PolicyExecutionContext

        isolated = PolicyEngine(registry=policy_engine.registry.create_isolated_snapshot())
        decision_ids: List[str] = []
        reasons: List[str] = []
        allowed = True
        policy_id = ""
        policy_version = ""
        caps = list(strategy.required_capabilities) or ["learning.strategy.consult"]
        for capability_id in caps:
            context = PolicyExecutionContext(
                investigation_id=investigation_id,
                case_stage=case_stage,
                actor_id=actor,
                actor_role=actor_role,
                capability_id=capability_id,
                capability_version="1.0.0",
                action_type="consult",
                action_scope=strategy.risk_profile.required_action_scope or "reversible",
                lifecycle_state="AVAILABLE",
                trust_state="TRUSTED_WITH_SCOPE",
                parameters={},
            )
            decision = isolated.authorize(context)
            decision_ids.append(decision.decision_id)
            policy_id = decision.policy_id
            policy_version = decision.policy_version
            reasons.extend(decision.reasons)
            if not decision.is_authorized:
                allowed = False
        return PolicyPrecheckResult(
            allowed=allowed,
            decision="ALLOW" if allowed else "DENY",
            decision_ids=decision_ids,
            policy_id=policy_id,
            policy_version=policy_version,
            reasons=reasons,
        )

    @classmethod
    def transition(
        cls,
        strategy: InvestigationStrategy,
        target: StrategyLifecycle,
        actor: str,
    ) -> InvestigationStrategy:
        assert_external_actor(actor, proposer_id=None if target not in {
            StrategyLifecycle.APPROVED,
            StrategyLifecycle.AVAILABLE,
        } else strategy.proposer_id)
        if target in {StrategyLifecycle.APPROVED, StrategyLifecycle.AVAILABLE}:
            assert_external_actor(actor, strategy.proposer_id)
        StrategyLifecycleMachine.assert_transition(strategy.lifecycle_state, target)
        assert_not_executable(strategy.model_dump(mode="json"))
        return strategy.model_copy(update={"lifecycle_state": target})

    @classmethod
    def record_approval(
        cls,
        strategy: InvestigationStrategy,
        *,
        actor: str,
        decision: ApprovalDecisionKind,
        reason: str,
        evidence_refs: Optional[Sequence[str]] = None,
        policy_id: Optional[str] = None,
        policy_version: Optional[str] = None,
        timestamp: Any = None,
    ) -> tuple:
        assert_external_actor(actor, strategy.proposer_id)
        if strategy.lifecycle_state != StrategyLifecycle.REVIEWED and decision == ApprovalDecisionKind.APPROVE:
            raise StrategyGovernanceError(
                f"Approval requires lifecycle REVIEWED, found {strategy.lifecycle_state.value}. "
                "PROPOSED cannot jump to APPROVED."
            )
        approval = StrategyApprovalDecision(
            decision_id=stable_id("approval", strategy.strategy_id, strategy.version, actor, decision.value, reason),
            strategy_id=strategy.strategy_id,
            version=strategy.version,
            decision=decision,
            actor=actor,
            reason=reason,
            timestamp=timestamp or utc_now(),
            evidence_refs=list(evidence_refs or []),
            policy_id=policy_id,
            policy_version=policy_version,
            externally_generated=True,
        )
        updated = strategy
        if decision == ApprovalDecisionKind.APPROVE:
            StrategyLifecycleMachine.assert_transition(strategy.lifecycle_state, StrategyLifecycle.APPROVED)
            updated = strategy.model_copy(
                update={
                    "lifecycle_state": StrategyLifecycle.APPROVED,
                    "approval_history": list(strategy.approval_history) + [approval.decision_id],
                }
            )
        elif decision == ApprovalDecisionKind.REJECT:
            if StrategyLifecycle.REJECTED in __import__(
                "cyberclaw.learning.models", fromlist=["ALLOWED_LIFECYCLE_TRANSITIONS"]
            ).ALLOWED_LIFECYCLE_TRANSITIONS.get(strategy.lifecycle_state, set()):
                updated = strategy.model_copy(
                    update={
                        "lifecycle_state": StrategyLifecycle.REJECTED,
                        "approval_history": list(strategy.approval_history) + [approval.decision_id],
                    }
                )
            else:
                updated = strategy.model_copy(
                    update={"approval_history": list(strategy.approval_history) + [approval.decision_id]}
                )
        else:
            updated = strategy.model_copy(
                update={"approval_history": list(strategy.approval_history) + [approval.decision_id]}
            )
        return updated, approval
