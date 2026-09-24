"""Deterministic Policy Evaluator implementing fail-closed conflict resolution."""

from __future__ import annotations

from typing import List, Tuple
from cyberclaw.policy.models import (
    AuthorizationDecision,
    AuthorizationDecisionType,
    Policy,
    PolicyEffect,
    PolicyExecutionContext,
    PolicyRule,
    RiskAssessment,
)
from cyberclaw.policy.rules import match_rule_conditions


class PolicyEvaluator:
    """Evaluates policies deterministically against execution contexts and risk assessments.

    Enforces fail-closed semantics and explicit precedence:
    DENY > REQUIRE_APPROVAL > REQUIRE_SUPERVISION > DEFER > ALLOW.
    """

    @classmethod
    def evaluate(
        cls,
        policy: Policy,
        context: PolicyExecutionContext,
        risk: RiskAssessment,
    ) -> AuthorizationDecision:
        """Evaluate a Policy against the execution context and risk assessment."""
        # Sort rules strictly deterministically by priority (lower number = higher priority)
        sorted_rules = sorted(policy.rules, key=lambda r: (r.priority, r.rule_id))

        matched_rules: List[PolicyRule] = []
        match_reasons: List[str] = []

        for rule in sorted_rules:
            is_match, reason = match_rule_conditions(rule, context, risk)
            if is_match:
                matched_rules.append(rule)
                if reason:
                    match_reasons.append(f"[{rule.rule_id}] {reason}")

        # If no rules match, fail closed using policy's default effect
        if not matched_rules:
            default_decision = policy.default_effect.to_decision_type()
            reasons = [f"No matching policy rules found; fallback to fail-closed default: {default_decision.value}"]
            return AuthorizationDecision(
                decision=default_decision,
                policy_id=policy.policy_id,
                policy_version=policy.version,
                risk_assessment=risk,
                matched_rules=[],
                reasons=reasons,
                obligations=[],
                context_snapshot=context.model_dump(),
            )

        # Precedence resolution: DENY > REQUIRE_APPROVAL > REQUIRE_SUPERVISION > DEFER > ALLOW
        highest_precedence = -1
        selected_effect: PolicyEffect = policy.default_effect
        winning_rule: Optional[PolicyRule] = None

        for rule in matched_rules:
            dec_type = rule.effect.to_decision_type()
            prec = dec_type.precedence
            if prec > highest_precedence:
                highest_precedence = prec
                selected_effect = rule.effect
                winning_rule = rule

        final_decision_type = selected_effect.to_decision_type()
        obligations: List[str] = []

        # Check approval token or supervision override
        if final_decision_type in (AuthorizationDecisionType.REQUIRE_APPROVAL, AuthorizationDecisionType.REQUIRE_SUPERVISION):
            if context.approval_token:
                final_decision_type = AuthorizationDecisionType.ALLOW
                match_reasons.append(f"Requirement fulfilled via approval token '{context.approval_token}' by approver '{context.approver_id or 'unknown'}'.")
                obligations.append("LOG_APPROVAL_DISPATCH")
            elif final_decision_type == AuthorizationDecisionType.REQUIRE_SUPERVISION:
                if context.requires_supervision_acknowledged:
                    final_decision_type = AuthorizationDecisionType.ALLOW
                    match_reasons.append(f"Supervision requirement fulfilled; acknowledged by supervisor '{context.supervisor_id or 'unknown'}'.")
                    obligations.append("LOG_SUPERVISED_EXECUTION")
                else:
                    obligations.append("SOLICIT_SUPERVISOR_ACKNOWLEDGMENT")
            else:
                obligations.append("SOLICIT_HUMAN_APPROVAL")

        if final_decision_type == AuthorizationDecisionType.ALLOW:
            obligations.append("RECORD_EXECUTION_JOURNAL")

        return AuthorizationDecision(
            decision=final_decision_type,
            policy_id=policy.policy_id,
            policy_version=policy.version,
            risk_assessment=risk,
            matched_rules=[r.rule_id for r in matched_rules],
            reasons=match_reasons,
            obligations=obligations,
            context_snapshot=context.model_dump(),
        )
