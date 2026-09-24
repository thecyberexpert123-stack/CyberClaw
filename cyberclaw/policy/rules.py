"""Declarative policy rule evaluation and standard built-in rules for CyberClaw."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.dfa.states import CoreState
from cyberclaw.policy.models import (
    ActorRole,
    PolicyEffect,
    PolicyExecutionContext,
    PolicyRule,
    RiskAssessment,
    RiskLevel,
)


def match_rule_conditions(
    rule: PolicyRule,
    context: PolicyExecutionContext,
    risk: RiskAssessment,
) -> Tuple[bool, Optional[str]]:
    """Deterministically evaluate if all rule conditions are satisfied.

    A rule matches IF AND ONLY IF all of its specified conditions are met.
    Returns (True, reason) if all conditions match, or (False, None) if any condition fails.
    """
    conds = rule.conditions
    if not conds:
        return True, f"Rule '{rule.name}' has unconditional match."

    # 1. Lifecycle State conditions
    if "allowed_lifecycle_states" in conds:
        allowed = [s.upper() for s in conds["allowed_lifecycle_states"]]
        if context.lifecycle_state.upper() not in allowed:
            return False, None

    if "disallowed_lifecycle_states" in conds:
        disallowed = [s.upper() for s in conds["disallowed_lifecycle_states"]]
        if context.lifecycle_state.upper() not in disallowed:
            return False, None

    # 2. Trust State conditions
    if "allowed_trust_states" in conds:
        allowed = [t.upper() for t in conds["allowed_trust_states"]]
        if context.trust_state.upper() not in allowed:
            return False, None

    if "disallowed_trust_states" in conds:
        disallowed = [t.upper() for t in conds["disallowed_trust_states"]]
        if context.trust_state.upper() not in disallowed:
            return False, None

    # 3. Action Scope conditions
    if "allowed_action_scopes" in conds:
        allowed = [s.lower() for s in conds["allowed_action_scopes"]]
        if context.action_scope.lower() not in allowed:
            return False, None

    if "disallowed_action_scopes" in conds:
        disallowed = [s.lower() for s in conds["disallowed_action_scopes"]]
        if context.action_scope.lower() not in disallowed:
            return False, None

    # 4. Actor Role conditions
    if "allowed_roles" in conds:
        allowed = [r.lower() for r in conds["allowed_roles"]]
        if context.actor_role.lower() not in allowed:
            return False, None

    if "disallowed_roles" in conds:
        disallowed = [r.lower() for r in conds["disallowed_roles"]]
        if context.actor_role.lower() not in disallowed:
            return False, None

    # 5. DFA Case Stage conditions
    if "allowed_case_stages" in conds:
        allowed = [s.upper() for s in conds["allowed_case_stages"]]
        if context.case_stage.upper() not in allowed:
            return False, None

    if "disallowed_case_stages" in conds:
        disallowed = [s.upper() for s in conds["disallowed_case_stages"]]
        if context.case_stage.upper() not in disallowed:
            return False, None

    # 6. Risk Level conditions
    if "min_risk_level" in conds:
        min_lvl = conds["min_risk_level"]
        if isinstance(min_lvl, str):
            min_lvl = RiskLevel(min_lvl)
        if risk.overall_risk.severity_rank < min_lvl.severity_rank:
            return False, None

    if "max_risk_level" in conds:
        max_lvl = conds["max_risk_level"]
        if isinstance(max_lvl, str):
            max_lvl = RiskLevel(max_lvl)
        if risk.overall_risk.severity_rank > max_lvl.severity_rank:
            return False, None

    if "exact_risk_levels" in conds:
        exact = [RiskLevel(l) if isinstance(l, str) else l for l in conds["exact_risk_levels"]]
        if risk.overall_risk not in exact:
            return False, None

    # 7. Branch isolation condition
    if conds.get("disallow_branches"):
        if not context.is_branch:
            return False, None

    # 8. Capability filter
    if "allowed_capabilities" in conds:
        if context.capability_id not in conds["allowed_capabilities"]:
            return False, None

    if "disallowed_capabilities" in conds:
        if context.capability_id not in conds["disallowed_capabilities"]:
            return False, None

    # 9. Supervised condition
    if conds.get("supervision_required"):
        if context.requires_supervision_acknowledged:
            return False, None

    # 10. Approval condition
    if conds.get("approval_required"):
        if context.approval_token:
            return False, None

    return True, f"Matched rule '{rule.name}'."


def create_standard_rules() -> List[PolicyRule]:
    """Generate the standard baseline rule collection for default system policies."""
    return [
        # Highest priority hard denials
        PolicyRule(
            rule_id="R001-DENY-REVOKED-OR-UNTRUSTED",
            name="Deny Revoked or Untrusted Capabilities",
            description="Capabilities with revoked or untrusted tier cannot be executed.",
            effect=PolicyEffect.DENY,
            priority=10,
            conditions={
                "disallowed_trust_states": [
                    CapabilityTrustState.REVOKED.value,
                    CapabilityTrustState.UNTRUSTED.value,
                ]
            },
        ),
        PolicyRule(
            rule_id="R002-DENY-INACTIVE-LIFECYCLE",
            name="Deny Inactive or Quarantined Capabilities",
            description="Capabilities in retired, disabled, rejected, or quarantined states cannot execute.",
            effect=PolicyEffect.DENY,
            priority=11,
            conditions={
                "disallowed_lifecycle_states": [
                    CapabilityLifecycleState.DISABLED.value,
                    CapabilityLifecycleState.RETIRED.value,
                    CapabilityLifecycleState.REJECTED.value,
                    "QUARANTINED",
                ]
            },
        ),
        PolicyRule(
            rule_id="R003-DENY-AUDITOR-MUTATIONS",
            name="Deny Auditor Mutating Operations",
            description="Auditors have read-only inspection authority and cannot perform mutating actions.",
            effect=PolicyEffect.DENY,
            priority=15,
            conditions={
                "disallowed_roles": [ActorRole.AUDITOR.value],
                "disallowed_action_scopes": ["consequential", "destructive", "irreversible"],
            },
        ),
        PolicyRule(
            rule_id="R004-DENY-TERMINAL-STAGE-MUTATIONS",
            name="Deny Mutating Actions in Terminal Stages",
            description="Resolved, failed, or paused investigations cannot execute mutating actions.",
            effect=PolicyEffect.DENY,
            priority=16,
            conditions={
                "disallowed_case_stages": [
                    CoreState.RESOLVE.value,
                    CoreState.FAILED.value,
                    CoreState.PAUSED.value,
                ],
                "disallowed_action_scopes": ["consequential", "destructive", "irreversible"],
            },
        ),
        PolicyRule(
            rule_id="R005-DENY-BRANCH-DESTRUCTIVE",
            name="Deny Destructive Operations in Branches",
            description="Counterfactual branches are strictly isolated and cannot execute destructive actions.",
            effect=PolicyEffect.DENY,
            priority=20,
            conditions={
                "disallow_branches": True,
                "disallowed_action_scopes": ["destructive", "irreversible"],
            },
        ),
        PolicyRule(
            rule_id="R006-DENY-CRITICAL-RISK",
            name="Deny Critical Unmitigated Risk",
            description="Actions assessed at CRITICAL risk cannot be executed automatically.",
            effect=PolicyEffect.DENY,
            priority=25,
            conditions={"exact_risk_levels": [RiskLevel.CRITICAL]},
        ),
        # Human/Lead Approval Gates
        PolicyRule(
            rule_id="R010-APPROVE-EXPERIMENTAL",
            name="Require Approval for Experimental Capabilities",
            description="Experimental skills must be explicitly approved before execution.",
            effect=PolicyEffect.REQUIRE_APPROVAL,
            priority=40,
            conditions={
                "disallowed_lifecycle_states": [CapabilityLifecycleState.EXPERIMENTAL.value]
            },
        ),
        PolicyRule(
            rule_id="R011-APPROVE-DESTRUCTIVE",
            name="Require Approval for Destructive Actions",
            description="Destructive actions require explicit lead investigator approval.",
            effect=PolicyEffect.REQUIRE_APPROVAL,
            priority=45,
            conditions={
                "disallowed_action_scopes": ["destructive", "irreversible"]
            },
        ),
        PolicyRule(
            rule_id="R012-APPROVE-HIGH-RISK",
            name="Require Approval for High Risk Operations",
            description="Operations assessed with HIGH risk level require human/lead approval.",
            effect=PolicyEffect.REQUIRE_APPROVAL,
            priority=50,
            conditions={"exact_risk_levels": [RiskLevel.HIGH]},
        ),
        # Supervision Gates
        PolicyRule(
            rule_id="R020-SUPERVISE-CONSEQUENTIAL",
            name="Require Supervision for Consequential Analyst Actions",
            description="Consequential actions by analysts require operational supervision acknowledgment.",
            effect=PolicyEffect.REQUIRE_SUPERVISION,
            priority=60,
            conditions={
                "allowed_roles": [ActorRole.ANALYST.value, ActorRole.OPERATOR.value],
                "disallowed_action_scopes": ["consequential"],
            },
        ),
        # Normal Authorized Paths
        PolicyRule(
            rule_id="R030-ALLOW-READ-ONLY",
            name="Allow Read-Only Trusted Operations",
            description="Read-only operations on trusted capabilities are authorized.",
            effect=PolicyEffect.ALLOW,
            priority=80,
            conditions={
                "allowed_action_scopes": ["read_only", "informational", "reversible"],
                "allowed_trust_states": [
                    CapabilityTrustState.FULLY_TRUSTED.value,
                    CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
                ],
                "max_risk_level": RiskLevel.MODERATE,
            },
        ),
        PolicyRule(
            rule_id="R031-ALLOW-LEAD-CONSEQUENTIAL",
            name="Allow Lead/System Consequential Actions",
            description="Lead investigators and system principals may execute consequential actions.",
            effect=PolicyEffect.ALLOW,
            priority=85,
            conditions={
                "allowed_roles": [ActorRole.LEAD_INVESTIGATOR.value, ActorRole.SYSTEM.value],
                "allowed_action_scopes": ["reversible", "consequential"],
                "allowed_trust_states": [
                    CapabilityTrustState.FULLY_TRUSTED.value,
                    CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
                ],
                "max_risk_level": RiskLevel.MODERATE,
            },
        ),
        PolicyRule(
            rule_id="R032-ALLOW-SPECIALIST-EXECUTION",
            name="Allow Specialist Domain Execution",
            description="Specialists are authorized to execute reversible and consequential actions within their domain.",
            effect=PolicyEffect.ALLOW,
            priority=86,
            conditions={
                "allowed_roles": [ActorRole.SPECIALIST.value],
                "allowed_action_scopes": ["read_only", "informational", "reversible", "consequential"],
                "allowed_trust_states": [
                    CapabilityTrustState.FULLY_TRUSTED.value,
                    CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
                ],
                "max_risk_level": RiskLevel.MODERATE,
            },
        ),
    ]
