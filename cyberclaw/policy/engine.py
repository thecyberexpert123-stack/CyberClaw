"""Core PolicyEngine coordinating risk evaluation, policy lookup, and authorization decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4
from cyberclaw.case.models import DecisionType, JournalEntryType
from cyberclaw.policy.errors import (
    ApprovalRequiredError,
    AuthorizationDeniedError,
    InvalidPolicyContextError,
    PolicyNotFoundError,
    PolicyValidationError,
    SupervisionRequiredError,
)
from cyberclaw.policy.evaluator import PolicyEvaluator
from cyberclaw.policy.models import (
    ActorRole,
    ApprovalGrant,
    AuthorizationDecision,
    AuthorizationDecisionType,
    Policy,
    PolicyExecutionContext,
    RiskAssessment,
    RiskLevel,
    utc_now,
)
from cyberclaw.policy.registry import PolicyRegistry
from cyberclaw.policy.risk import RiskEvaluator


class PolicyEngine:
    """The central Policy Engine responsible for contextual, risk-aware authorization decisions."""

    def __init__(self, registry: Optional[PolicyRegistry] = None) -> None:
        self.registry: PolicyRegistry = registry or PolicyRegistry()
        self._decisions: Dict[str, AuthorizationDecision] = {}
        self._pending_approvals: Dict[str, AuthorizationDecision] = {}
        self._approval_grants: Dict[str, ApprovalGrant] = {}

    def authorize(
        self,
        context: PolicyExecutionContext,
        policy_id: Optional[str] = None,
        policy_version: Optional[str] = None,
    ) -> AuthorizationDecision:
        """Contextually evaluate whether an action is authorized.

        Fails closed on any ambiguity, missing context, or unknown policy.
        """
        # Validate context integrity
        if not context.investigation_id or not context.capability_id or not context.actor_id:
            raise InvalidPolicyContextError(
                "PolicyExecutionContext requires valid investigation_id, capability_id, and actor_id."
            )

        # 1. Deterministic Risk Assessment
        risk_assessment = RiskEvaluator.evaluate(context)

        # 2. Retrieve Policy
        try:
            if policy_id:
                policy = self.registry.get_policy(policy_id, version=policy_version)
            else:
                policy = self.registry.get_default_policy()
        except PolicyNotFoundError as pnf:
            # Fail-closed: policy not found results in hard DENY
            decision = AuthorizationDecision(
                decision=AuthorizationDecisionType.DENY,
                policy_id=policy_id or "unknown",
                policy_version=policy_version or "unknown",
                risk_assessment=risk_assessment,
                matched_rules=[],
                reasons=[f"Policy lookup failed (fail-closed): {pnf.message}"],
                obligations=[],
                context_snapshot=context.model_dump(),
            )
            self._decisions[decision.decision_id] = decision
            return decision

        # 3. Policy Rule Evaluation. The evaluator does not treat a token string as approval.
        decision = PolicyEvaluator.evaluate(policy=policy, context=context, risk=risk_assessment)
        decision = self._apply_approval_grant(decision, context)

        # 4. Record and track
        self._decisions[decision.decision_id] = decision
        if decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL:
            self._pending_approvals[decision.decision_id] = decision

        return decision

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def _match_grant(self, context: PolicyExecutionContext) -> Tuple[Optional[ApprovalGrant], str]:
        """Resolve a caller token to an approval record bound to this request.

        A missing, expired, or mismatched record is not approval. The token
        value itself is never evidence.
        """
        token = context.approval_token or ""
        grant = self._approval_grants.get(token)
        if grant is None:
            return None, "no approval record"
        if grant.expires_at is not None and self._as_utc(grant.expires_at) <= utc_now():
            return None, "approval record expired"
        if grant.approver_id == grant.actor_id:
            return None, "proposer approved their own proposal"
        if grant.investigation_id != context.investigation_id:
            return None, "different case"
        if grant.capability_id != context.capability_id:
            return None, "different capability"
        if grant.capability_version != context.capability_version:
            return None, "different capability version"
        if grant.action_scope != context.action_scope:
            return None, "different scope"
        if grant.actor_id != context.actor_id:
            return None, "different requester"
        valid_roles = {ActorRole.LEAD_INVESTIGATOR.value, ActorRole.SYSTEM.value}
        if grant.approver_role.lower() not in valid_roles:
            return None, "unauthorized approver role"
        return grant, ""

    def _apply_approval_grant(
        self,
        decision: AuthorizationDecision,
        context: PolicyExecutionContext,
    ) -> AuthorizationDecision:
        """Fulfill REQUIRE_APPROVAL only from a matching grant.

        DENY is not upgraded. A token that does not resolve remains unapproved.
        """
        if decision.decision != AuthorizationDecisionType.REQUIRE_APPROVAL or not context.approval_token:
            return decision
        grant, reason = self._match_grant(context)
        if grant is None:
            decision.reasons.append(f"Approval validation rejected token: {reason}")
            return decision
        decision.decision = AuthorizationDecisionType.ALLOW
        decision.reasons.append(
            f"Requirement fulfilled via approval record issued to approver '{grant.approver_id}'."
        )
        decision.obligations = [item for item in decision.obligations if item != "SOLICIT_HUMAN_APPROVAL"]
        decision.obligations.append("LOG_APPROVAL_DISPATCH")
        return decision

    def request_approval(
        self,
        decision_id: str,
        approver_id: str,
        approver_role: str = ActorRole.LEAD_INVESTIGATOR.value,
        reason: str = "Lead investigator approved execution",
        expires_at: Optional[datetime] = None,
    ) -> AuthorizationDecision:
        """Grant explicit human or lead approval for an action requiring authorization."""
        if decision_id not in self._decisions:
            raise PolicyValidationError(f"Authorization decision '{decision_id}' not found.")

        old_decision = self._decisions[decision_id]
        if old_decision.decision != AuthorizationDecisionType.REQUIRE_APPROVAL:
            raise PolicyValidationError(
                f"Decision '{decision_id}' is in status '{old_decision.decision.value}', not REQUIRE_APPROVAL."
            )

        # Role authority check: only lead_investigator or system can approve
        valid_approver_roles = {
            ActorRole.LEAD_INVESTIGATOR.value,
            ActorRole.SYSTEM.value,
        }
        if approver_role.lower() not in valid_approver_roles:
            raise PolicyValidationError(
                f"Actor with role '{approver_role}' lacks authority to approve; requires lead or system authority."
            )

        snapshot = dict(old_decision.context_snapshot)
        proposer = str(snapshot.get("actor_id") or "")
        if approver_id == proposer:
            raise PolicyValidationError(
                f"Actor '{approver_id}' cannot approve their own proposal."
            )

        token = str(uuid4())
        grant = ApprovalGrant(
            token=token,
            decision_id=decision_id,
            investigation_id=str(snapshot.get("investigation_id") or ""),
            capability_id=str(snapshot.get("capability_id") or ""),
            capability_version=str(snapshot.get("capability_version") or "1.0.0"),
            action_scope=str(snapshot.get("action_scope") or ""),
            actor_id=proposer,
            approver_id=approver_id,
            approver_role=approver_role,
            issued_at=utc_now(),
            expires_at=expires_at,
        )
        self._approval_grants[token] = grant
        snapshot["approval_token"] = token
        snapshot["approver_id"] = approver_id
        new_context = PolicyExecutionContext(**snapshot)

        # Re-evaluate with approval token
        approved_decision = self.authorize(
            context=new_context,
            policy_id=old_decision.policy_id,
            policy_version=old_decision.policy_version,
        )
        approved_decision.reasons.append(f"Approved by '{approver_id}' ({approver_role}): {reason}")
        self._pending_approvals.pop(decision_id, None)
        return approved_decision

    def reject_approval(
        self,
        decision_id: str,
        rejecter_id: str,
        reason: str = "Approval rejected by lead investigator",
    ) -> AuthorizationDecision:
        """Reject approval for an action, resulting in a hard DENY."""
        if decision_id not in self._decisions:
            raise PolicyValidationError(f"Authorization decision '{decision_id}' not found.")

        old_decision = self._decisions[decision_id]
        self._pending_approvals.pop(decision_id, None)

        rejected_decision = AuthorizationDecision(
            decision=AuthorizationDecisionType.DENY,
            policy_id=old_decision.policy_id,
            policy_version=old_decision.policy_version,
            risk_assessment=old_decision.risk_assessment,
            matched_rules=old_decision.matched_rules,
            reasons=old_decision.reasons + [f"Approval rejected by '{rejecter_id}': {reason}"],
            obligations=[],
            context_snapshot=old_decision.context_snapshot,
        )
        self._decisions[rejected_decision.decision_id] = rejected_decision
        return rejected_decision

    def acknowledge_supervision(
        self,
        decision_id: str,
        supervisor_id: str,
        supervisor_role: str = ActorRole.LEAD_INVESTIGATOR.value,
        reason: str = "Supervision acknowledged",
    ) -> AuthorizationDecision:
        """Acknowledge supervision for an action requiring supervision."""
        if decision_id not in self._decisions:
            raise PolicyValidationError(f"Authorization decision '{decision_id}' not found.")

        old_decision = self._decisions[decision_id]
        if old_decision.decision != AuthorizationDecisionType.REQUIRE_SUPERVISION:
            raise PolicyValidationError(
                f"Decision '{decision_id}' does not require supervision (status: {old_decision.decision.value})."
            )

        # Re-construct context with acknowledged supervision
        snapshot = dict(old_decision.context_snapshot)
        snapshot["requires_supervision_acknowledged"] = True
        snapshot["supervisor_id"] = supervisor_id
        new_context = PolicyExecutionContext(**snapshot)

        supervised_decision = self.authorize(
            context=new_context,
            policy_id=old_decision.policy_id,
            policy_version=old_decision.policy_version,
        )
        supervised_decision.reasons.append(f"Supervision acknowledged by '{supervisor_id}' ({supervisor_role}): {reason}")
        return supervised_decision

    def record_in_journal(self, decision: AuthorizationDecision, case_manager: Any) -> None:
        """Record all authorization and risk assessment events into the Case Journal."""
        if not hasattr(case_manager, "journal"):
            return

        ctx = decision.context_snapshot
        req_id = ctx.get("capability_id", "unknown")

        # 1. Authorization Requested
        case_manager.journal.append_entry(
            entry_type=JournalEntryType.AUTHORIZATION_REQUESTED,
            summary=f"Authorization requested for capability '{ctx.get('capability_id')}' by actor '{ctx.get('actor_id')}'",
            reference_id=decision.decision_id,
            details={
                "capability_id": ctx.get("capability_id"),
                "actor_id": ctx.get("actor_id"),
                "action_scope": ctx.get("action_scope"),
                "case_stage": ctx.get("case_stage"),
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
            },
        )

        # 2. Risk Assessed
        case_manager.journal.append_entry(
            entry_type=JournalEntryType.RISK_ASSESSED,
            summary=f"Assessed risk as {decision.risk_assessment.overall_risk.value} (score: {decision.risk_assessment.score})",
            reference_id=decision.risk_assessment.assessment_id,
            details={
                "overall_risk": decision.risk_assessment.overall_risk.value,
                "score": decision.risk_assessment.score,
                "rationale": decision.risk_assessment.rationale,
                "factors_count": len(decision.risk_assessment.factors),
            },
        )

        # 3. Decision Outcome
        if decision.decision == AuthorizationDecisionType.ALLOW:
            entry_type = JournalEntryType.AUTHORIZATION_GRANTED
            summary = f"Authorization GRANTED for capability '{ctx.get('capability_id')}' under policy '{decision.policy_id}'"
        elif decision.decision == AuthorizationDecisionType.DENY:
            entry_type = JournalEntryType.AUTHORIZATION_DENIED
            summary = f"Authorization DENIED for capability '{ctx.get('capability_id')}' under policy '{decision.policy_id}': {'; '.join(decision.reasons)}"
        elif decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL:
            entry_type = JournalEntryType.APPROVAL_REQUESTED
            summary = f"Authorization REQUIRES APPROVAL for capability '{ctx.get('capability_id')}': {'; '.join(decision.reasons)}"
        else:
            entry_type = JournalEntryType.AUTHORIZATION_DEFERRED
            summary = f"Authorization DEFERRED for capability '{ctx.get('capability_id')}': {'; '.join(decision.reasons)}"

        case_manager.journal.append_entry(
            entry_type=entry_type,
            summary=summary,
            reference_id=decision.decision_id,
            details={
                "decision": decision.decision.value,
                "policy_id": decision.policy_id,
                "policy_version": decision.policy_version,
                "matched_rules": decision.matched_rules,
                "reasons": decision.reasons,
                "obligations": decision.obligations,
            },
        )

        # Also append formal decision record to case manager decision history
        if hasattr(case_manager, "record_decision"):
            case_manager.record_decision(
                decision_type=DecisionType.AUTHORIZATION_DECISION,
                actor=ctx.get("actor_id", "core.system"),
                rationale="; ".join(decision.reasons) or summary,
                inputs={
                    "capability_id": ctx.get("capability_id"),
                    "action_scope": ctx.get("action_scope"),
                    "policy_id": decision.policy_id,
                },
                outcome={
                    "decision": decision.decision.value,
                    "decision_id": decision.decision_id,
                    "risk_level": decision.risk_assessment.overall_risk.value,
                },
                metadata={
                    "matched_rules": decision.matched_rules,
                    "obligations": decision.obligations,
                },
            )

    def get_decision(self, decision_id: str) -> Optional[AuthorizationDecision]:
        """Retrieve recorded decision by ID."""
        return self._decisions.get(decision_id)
