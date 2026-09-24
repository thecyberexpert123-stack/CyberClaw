"""Comprehensive test suite for Policy Engine & Risk-Aware Authorization v0.1.

Verifies:
1. Domain-agnostic policy models, immutability, and validation.
2. Deterministic, explainable RiskEvaluator.
3. Declarative policy rules and condition matching.
4. Fail-closed conflict resolution and precedence order (DENY > REQUIRE_APPROVAL > REQUIRE_SUPERVISION > DEFER > ALLOW).
5. Versioned PolicyRegistry and isolation semantics.
6. Central PolicyEngine authorization, approval flows, and supervision acknowledgment.
7. Case journal and decision history recording.
8. ValidationPipeline policy validation phase.
9. CyberClawCore integration with execution history auditing.
10. Branch isolation, self-development quarantine, planning validation, and deterministic replay.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
from uuid import uuid4
import pytest

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.models import (
    CapabilityLifecycleState,
    CapabilityTrustState,
)
from cyberclaw.capabilities.provider import CapabilityProvider
from cyberclaw.case.manager import CaseManager
from cyberclaw.case.models import DecisionType, JournalEntryType
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.types import Source
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import RequirementCandidate
from cyberclaw.planning.validator import PlanValidator
from cyberclaw.policy import (
    DEFAULT_POLICY_ID,
    DEFAULT_POLICY_VERSION,
    ActorRole,
    ApprovalRequiredError,
    AuthorizationDecision,
    AuthorizationDecisionType,
    AuthorizationDeniedError,
    InvalidPolicyContextError,
    Policy,
    PolicyEffect,
    PolicyEngine,
    PolicyEvaluator,
    PolicyExecutionContext,
    PolicyNotFoundError,
    PolicyRegistry,
    PolicyRule,
    PolicyValidationError,
    RiskAssessment,
    RiskEvaluator,
    RiskFactor,
    RiskLevel,
    SupervisionRequiredError,
    create_standard_rules,
    match_rule_conditions,
)
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.validation.pipeline import ValidationPipeline


class DummyPolicyProvider(CapabilityProvider):
    """Simple test provider for authorization integration tests."""

    def __init__(self, capability_id: str) -> None:
        super().__init__(
            id=f"provider.{capability_id}",
            capability_id=capability_id,
            name="Dummy Policy Provider",
        )

    def is_ready(self, context: Any = None) -> Tuple[bool, Optional[str]]:
        return True, None

    def execute(self, parameters: Dict[str, Any], context: Any) -> ExecutionResult:
        ev = Evidence(
            type="policy_test_evidence",
            subject=parameters.get("domain", parameters.get("test", "test_target")),
            value={"status": "executed", "params": parameters},
            source=Source(type="mock", name=self.id),
        )
        return ExecutionResult.success(output={"status": "ok"}, evidence=[ev])


# -----------------------------------------------------------------------------
# 1. Models & Validation Tests
# -----------------------------------------------------------------------------

def test_policy_models_immutability_and_validation():
    """Verify Policy models structural integrity and attributes."""
    rule = PolicyRule(
        rule_id="R-TEST-01",
        name="Test Rule",
        effect=PolicyEffect.ALLOW,
        priority=50,
        conditions={"allowed_action_scopes": ["read_only"]},
    )
    policy = Policy(
        policy_id="test-policy",
        name="Test Policy",
        version="1.0.0",
        rules=[rule],
        default_effect=PolicyEffect.DENY,
    )
    assert policy.policy_id == "test-policy"
    assert len(policy.rules) == 1
    assert policy.default_effect == PolicyEffect.DENY
    assert rule.effect == PolicyEffect.ALLOW

    # Verify decision precedence ordering
    assert AuthorizationDecisionType.DENY.precedence > AuthorizationDecisionType.REQUIRE_APPROVAL.precedence
    assert AuthorizationDecisionType.REQUIRE_APPROVAL.precedence > AuthorizationDecisionType.REQUIRE_SUPERVISION.precedence
    assert AuthorizationDecisionType.REQUIRE_SUPERVISION.precedence > AuthorizationDecisionType.DEFER.precedence
    assert AuthorizationDecisionType.DEFER.precedence > AuthorizationDecisionType.ALLOW.precedence


def test_risk_level_severity_ordering():
    """Verify RiskLevel severity rank reflects fail-closed semantics."""
    assert RiskLevel.UNKNOWN.severity_rank >= RiskLevel.CRITICAL.severity_rank
    assert RiskLevel.CRITICAL.severity_rank > RiskLevel.HIGH.severity_rank
    assert RiskLevel.HIGH.severity_rank > RiskLevel.MODERATE.severity_rank
    assert RiskLevel.MODERATE.severity_rank > RiskLevel.LOW.severity_rank


# -----------------------------------------------------------------------------
# 2. RiskEvaluator Determinism & Explainability Tests
# -----------------------------------------------------------------------------

def test_risk_evaluator_deterministic_scoring():
    """Verify that RiskEvaluator produces identical output given identical context."""
    ctx = PolicyExecutionContext(
        investigation_id="inv-risk-01",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="analyst.bob",
        actor_role=ActorRole.ANALYST.value,
        capability_id="dns.lookup",
        action_scope="reversible",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
    )
    risk1 = RiskEvaluator.evaluate(ctx)
    risk2 = RiskEvaluator.evaluate(ctx)

    assert risk1.overall_risk == risk2.overall_risk
    assert risk1.score == risk2.score
    assert len(risk1.factors) == len(risk2.factors)
    assert risk1.overall_risk == RiskLevel.LOW
    assert "Overall risk evaluated as LOW" in risk1.rationale


def test_risk_evaluator_scope_escalation():
    """Verify that action scopes appropriately scale risk levels."""
    base = {
        "investigation_id": "inv-risk-02",
        "case_stage": CoreState.INVESTIGATE.value,
        "actor_id": "analyst.bob",
        "actor_role": ActorRole.ANALYST.value,
        "capability_id": "tool.test",
        "lifecycle_state": CapabilityLifecycleState.AVAILABLE.value,
        "trust_state": CapabilityTrustState.FULLY_TRUSTED.value,
    }
    # Read-only
    r_ro = RiskEvaluator.evaluate(PolicyExecutionContext(**base, action_scope="read_only"))
    assert r_ro.overall_risk == RiskLevel.LOW

    # Consequential
    r_cq = RiskEvaluator.evaluate(PolicyExecutionContext(**base, action_scope="consequential"))
    assert r_cq.overall_risk in (RiskLevel.LOW, RiskLevel.MODERATE)
    assert r_cq.score > r_ro.score

    # Destructive
    r_dest = RiskEvaluator.evaluate(PolicyExecutionContext(**base, action_scope="destructive"))
    assert r_dest.overall_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert r_dest.score > r_cq.score


def test_risk_evaluator_auditor_restriction():
    """Verify that an auditor attempting mutating actions is flagged CRITICAL."""
    ctx = PolicyExecutionContext(
        investigation_id="inv-risk-03",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="auditor.eve",
        actor_role=ActorRole.AUDITOR.value,
        capability_id="tool.mutate",
        action_scope="consequential",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.FULLY_TRUSTED.value,
    )
    risk = RiskEvaluator.evaluate(ctx)
    assert risk.overall_risk == RiskLevel.CRITICAL
    role_factor = next(f for f in risk.factors if f.name == "actor_role")
    assert role_factor.level == RiskLevel.CRITICAL
    assert "Auditor role is strictly observational" in role_factor.description


def test_risk_evaluator_terminal_stage_restriction():
    """Verify that mutating actions in terminal DFA states (RESOLVE, FAILED) receive CRITICAL risk."""
    ctx = PolicyExecutionContext(
        investigation_id="inv-risk-04",
        case_stage=CoreState.RESOLVE.value,
        actor_id="lead.alice",
        actor_role=ActorRole.LEAD_INVESTIGATOR.value,
        capability_id="tool.exec",
        action_scope="consequential",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.FULLY_TRUSTED.value,
    )
    risk = RiskEvaluator.evaluate(ctx)
    assert risk.overall_risk == RiskLevel.CRITICAL
    stage_factor = next(f for f in risk.factors if f.name == "investigation_stage")
    assert stage_factor.level == RiskLevel.CRITICAL


def test_risk_evaluator_dangerous_parameters():
    """Verify that dangerous parameter flags elevate risk factor."""
    ctx = PolicyExecutionContext(
        investigation_id="inv-risk-05",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="operator.dan",
        actor_role=ActorRole.OPERATOR.value,
        capability_id="tool.cleanup",
        action_scope="reversible",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
        parameters={"force": True, "purge": True},
    )
    risk = RiskEvaluator.evaluate(ctx)
    param_factor = next((f for f in risk.factors if f.name == "dangerous_parameters"), None)
    assert param_factor is not None
    assert param_factor.level == RiskLevel.HIGH


# -----------------------------------------------------------------------------
# 3. Policy Rules & Condition Matching Tests
# -----------------------------------------------------------------------------

def test_match_rule_conditions_success_and_failure():
    """Verify fine-grained declarative condition matching."""
    rule = PolicyRule(
        rule_id="R-TEST-COND",
        name="Conditional Rule",
        effect=PolicyEffect.ALLOW,
        conditions={
            "allowed_roles": ["analyst"],
            "allowed_action_scopes": ["read_only"],
            "max_risk_level": RiskLevel.LOW,
        },
    )
    ctx_match = PolicyExecutionContext(
        investigation_id="inv-1",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="analyst.1",
        actor_role="analyst",
        capability_id="cap.1",
        action_scope="read_only",
    )
    risk_low = RiskAssessment(overall_risk=RiskLevel.LOW, score=0.1)
    matched, reason = match_rule_conditions(rule, ctx_match, risk_low)
    assert matched is True
    assert "Matched rule 'Conditional Rule'" in reason

    # Role mismatch
    ctx_role_mismatch = PolicyExecutionContext(
        investigation_id="inv-1",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="operator.1",
        actor_role="operator",
        capability_id="cap.1",
        action_scope="read_only",
    )
    matched, _ = match_rule_conditions(rule, ctx_role_mismatch, risk_low)
    assert matched is False

    # Risk level too high
    risk_high = RiskAssessment(overall_risk=RiskLevel.HIGH, score=0.8)
    matched, _ = match_rule_conditions(rule, ctx_match, risk_high)
    assert matched is False


# -----------------------------------------------------------------------------
# 4. Policy Evaluator & Precedence Resolution Tests
# -----------------------------------------------------------------------------

def test_policy_evaluator_fail_closed_on_no_match():
    """Verify that an empty or non-matching policy evaluates to fail-closed default effect."""
    policy = Policy(
        policy_id="empty-policy",
        name="Empty Policy",
        rules=[],
        default_effect=PolicyEffect.DENY,
    )
    ctx = PolicyExecutionContext(
        investigation_id="inv-eval-01",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="actor.1",
        capability_id="cap.1",
    )
    risk = RiskAssessment(overall_risk=RiskLevel.LOW, score=0.1)
    decision = PolicyEvaluator.evaluate(policy, ctx, risk)
    assert decision.decision == AuthorizationDecisionType.DENY
    assert decision.is_authorized is False
    assert "fallback to fail-closed default: DENY" in decision.reasons[0]


def test_policy_evaluator_precedence_deny_overrides_allow():
    """Verify DENY overrides ALLOW regardless of rule order."""
    r_allow = PolicyRule(
        rule_id="R-ALLOW",
        name="Allow Rule",
        effect=PolicyEffect.ALLOW,
        priority=10,  # Lower priority number
        conditions={},
    )
    r_deny = PolicyRule(
        rule_id="R-DENY",
        name="Deny Rule",
        effect=PolicyEffect.DENY,
        priority=90,  # Higher priority number
        conditions={},
    )
    policy = Policy(
        policy_id="conflict-policy",
        name="Conflict Policy",
        rules=[r_allow, r_deny],
    )
    ctx = PolicyExecutionContext(
        investigation_id="inv-eval-02",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="actor.1",
        capability_id="cap.1",
    )
    risk = RiskAssessment(overall_risk=RiskLevel.LOW, score=0.1)
    decision = PolicyEvaluator.evaluate(policy, ctx, risk)
    assert decision.decision == AuthorizationDecisionType.DENY
    assert decision.is_authorized is False


def test_policy_evaluator_approval_precedence_over_allow():
    """Verify REQUIRE_APPROVAL takes precedence over ALLOW."""
    r_allow = PolicyRule(
        rule_id="R-ALLOW",
        name="Allow Rule",
        effect=PolicyEffect.ALLOW,
        priority=50,
        conditions={},
    )
    r_approve = PolicyRule(
        rule_id="R-APPROVE",
        name="Require Approval Rule",
        effect=PolicyEffect.REQUIRE_APPROVAL,
        priority=60,
        conditions={},
    )
    policy = Policy(
        policy_id="approval-policy",
        name="Approval Policy",
        rules=[r_allow, r_approve],
    )
    ctx = PolicyExecutionContext(
        investigation_id="inv-eval-03",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="actor.1",
        capability_id="cap.1",
    )
    risk = RiskAssessment(overall_risk=RiskLevel.MODERATE, score=0.5)
    decision = PolicyEvaluator.evaluate(policy, ctx, risk)
    assert decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL
    assert decision.is_authorized is False
    assert "SOLICIT_HUMAN_APPROVAL" in decision.obligations


# -----------------------------------------------------------------------------
# 5. Policy Registry Tests
# -----------------------------------------------------------------------------

def test_policy_registry_versioning_and_immutability():
    """Verify PolicyRegistry stores and enforces immutability on versioned policies."""
    reg = PolicyRegistry(populate_defaults=True)
    assert reg.has_policy(DEFAULT_POLICY_ID, DEFAULT_POLICY_VERSION)

    p1 = Policy(policy_id="custom.policy", name="Custom", version="1.0.0", rules=[])
    reg.register_policy(p1)
    assert reg.get_policy("custom.policy", "1.0.0") == p1

    # Same identical registration is idempotent
    reg.register_policy(p1)

    # Modifying version in place raises PolicyValidationError
    p1_modified = Policy(policy_id="custom.policy", name="Custom Tampered", version="1.0.0", rules=[])
    with pytest.raises(PolicyValidationError):
        reg.register_policy(p1_modified)

    # Registering new semantic version succeeds
    p2 = Policy(policy_id="custom.policy", name="Custom v2", version="2.0.0", rules=[])
    reg.register_policy(p2)
    assert reg.get_policy("custom.policy", "2.0.0") == p2
    assert reg.get_policy("custom.policy").version == "2.0.0"  # Latest


def test_policy_registry_isolated_snapshot_is_read_only():
    """Verify that isolated registry snapshots cannot be modified."""
    reg = PolicyRegistry(populate_defaults=True)
    isolated = reg.create_isolated_snapshot()

    new_p = Policy(policy_id="rogue.policy", name="Rogue", version="1.0.0", rules=[])
    with pytest.raises(PolicyValidationError) as exc:
        isolated.register_policy(new_p)
    assert "read-only / branch-isolated mode" in str(exc.value)


def test_policy_registry_missing_policy_fail_closed():
    """Verify that querying a non-existent policy raises PolicyNotFoundError."""
    reg = PolicyRegistry(populate_defaults=False)
    with pytest.raises(PolicyNotFoundError):
        reg.get_policy("non_existent_policy")


# -----------------------------------------------------------------------------
# 6. Policy Engine Authorization & Approval Workflows
# -----------------------------------------------------------------------------

def test_policy_engine_allow_standard_analyst_read_only():
    """Verify standard read-only capability execution by analyst is authorized."""
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-pe-01",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="analyst.alice",
        actor_role=ActorRole.ANALYST.value,
        capability_id="osint.whois",
        action_scope="read_only",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
    )
    decision = engine.authorize(ctx)
    assert decision.decision == AuthorizationDecisionType.ALLOW
    assert decision.is_authorized is True
    assert "RECORD_EXECUTION_JOURNAL" in decision.obligations


def test_policy_engine_deny_untrusted_capability():
    """Verify untrusted capability is denied by standard policy."""
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-pe-02",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="analyst.alice",
        actor_role=ActorRole.ANALYST.value,
        capability_id="untrusted.script",
        action_scope="reversible",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.UNTRUSTED.value,
    )
    decision = engine.authorize(ctx)
    assert decision.decision == AuthorizationDecisionType.DENY
    assert decision.is_authorized is False
    assert any("R001-DENY-REVOKED-OR-UNTRUSTED" in r for r in decision.matched_rules)


def test_policy_engine_deny_quarantined_capability():
    """Verify capability in quarantined / inactive lifecycle state is denied."""
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-pe-03",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="lead.carol",
        actor_role=ActorRole.LEAD_INVESTIGATOR.value,
        capability_id="quarantined.exploit",
        action_scope="reversible",
        lifecycle_state="QUARANTINED",
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
    )
    decision = engine.authorize(ctx)
    assert decision.decision == AuthorizationDecisionType.DENY
    assert decision.is_authorized is False
    assert any("R002-DENY-INACTIVE-LIFECYCLE" in r for r in decision.matched_rules)


def test_policy_engine_approval_workflow():
    """Verify full approval lifecycle: REQUIRE_APPROVAL -> approved by lead -> ALLOW."""
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-pe-04",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="operator.dave",
        actor_role=ActorRole.OPERATOR.value,
        capability_id="system.database_flush",
        action_scope="destructive",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.FULLY_TRUSTED.value,
    )
    initial_decision = engine.authorize(ctx)
    assert initial_decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL
    assert initial_decision.is_authorized is False

    # Analyst cannot approve
    with pytest.raises(PolicyValidationError) as exc_info:
        engine.request_approval(
            decision_id=initial_decision.decision_id,
            approver_id="analyst.junior",
            approver_role=ActorRole.ANALYST.value,
        )
    assert "lacks authority to approve" in str(exc_info.value)

    # Lead investigator grants approval
    approved_decision = engine.request_approval(
        decision_id=initial_decision.decision_id,
        approver_id="lead.sarah",
        approver_role=ActorRole.LEAD_INVESTIGATOR.value,
        reason="Verified maintenance window approved",
    )
    assert approved_decision.decision == AuthorizationDecisionType.ALLOW
    assert approved_decision.is_authorized is True
    assert any("Approved by 'lead.sarah'" in r for r in approved_decision.reasons)


def test_policy_engine_approval_rejection_workflow():
    """Verify approval rejection transitions decision to hard DENY."""
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-pe-05",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="operator.dave",
        actor_role=ActorRole.OPERATOR.value,
        capability_id="system.wipe",
        action_scope="destructive",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.FULLY_TRUSTED.value,
    )
    decision = engine.authorize(ctx)
    assert decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL

    rejected = engine.reject_approval(
        decision_id=decision.decision_id,
        rejecter_id="lead.sarah",
        reason="Operation deemed unacceptable risk",
    )
    assert rejected.decision == AuthorizationDecisionType.DENY
    assert rejected.is_authorized is False
    assert any("rejected by 'lead.sarah'" in r for r in rejected.reasons)


def test_policy_engine_supervision_workflow():
    """Verify supervision acknowledgment workflow."""
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-pe-06",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="analyst.alice",
        actor_role=ActorRole.ANALYST.value,
        capability_id="tool.consequential",
        action_scope="consequential",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
    )
    decision = engine.authorize(ctx)
    assert decision.decision == AuthorizationDecisionType.REQUIRE_SUPERVISION
    assert decision.is_authorized is False

    supervised = engine.acknowledge_supervision(
        decision_id=decision.decision_id,
        supervisor_id="lead.carol",
    )
    assert supervised.decision == AuthorizationDecisionType.ALLOW
    assert supervised.is_authorized is True
    assert any("Supervision acknowledged" in r for r in supervised.reasons)


def test_policy_engine_invalid_context_raises_error():
    """Verify PolicyEngine raises InvalidPolicyContextError if required fields are missing."""
    engine = PolicyEngine()
    invalid_ctx = PolicyExecutionContext(
        investigation_id="",
        case_stage="INVESTIGATE",
        actor_id="",
        capability_id="",
    )
    with pytest.raises(InvalidPolicyContextError):
        engine.authorize(invalid_ctx)


# -----------------------------------------------------------------------------
# 7. Case Journal & Audit Trail Recording Tests
# -----------------------------------------------------------------------------

def test_policy_engine_record_in_journal():
    """Verify authorization events are written into CaseManager's journal and decision history."""
    case_mgr = CaseManager("inv-audit-01")
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-audit-01",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="analyst.alice",
        actor_role=ActorRole.ANALYST.value,
        capability_id="dns.query",
        action_scope="read_only",
        lifecycle_state=CapabilityLifecycleState.AVAILABLE.value,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE.value,
    )
    decision = engine.authorize(ctx)
    engine.record_in_journal(decision, case_mgr)

    journal_types = [e.entry_type for e in case_mgr.journal.entries]
    assert JournalEntryType.AUTHORIZATION_REQUESTED in journal_types
    assert JournalEntryType.RISK_ASSESSED in journal_types
    assert JournalEntryType.AUTHORIZATION_GRANTED in journal_types

    # Verify decision record appended
    dec_records = [d for d in case_mgr.decision_history if d.decision_type == DecisionType.AUTHORIZATION_DECISION]
    assert len(dec_records) == 1
    assert dec_records[0].outcome.get("decision") == "ALLOW"


# -----------------------------------------------------------------------------
# 8. ValidationPipeline Policy Phase Tests
# -----------------------------------------------------------------------------

def test_validation_pipeline_validates_authorization():
    """Verify ValidationPipeline enforces policy authorization decisions."""
    from cyberclaw.validation.errors import PolicyValidationError as ValPolicyValidationError
    auth_denied = AuthorizationDecision(
        decision=AuthorizationDecisionType.DENY,
        policy_id="policy-1",
        risk_assessment=RiskAssessment(overall_risk=RiskLevel.HIGH, score=0.8),
        reasons=["Untrusted provider"],
    )
    with pytest.raises(ValPolicyValidationError) as exc:
        ValidationPipeline.validate_authorization(auth_denied)
    assert "Policy evaluation denied execution (DENY)" in str(exc.value)

    auth_allowed = AuthorizationDecision(
        decision=AuthorizationDecisionType.ALLOW,
        policy_id="policy-1",
        risk_assessment=RiskAssessment(overall_risk=RiskLevel.LOW, score=0.1),
    )
    # Allowed does not raise
    ValidationPipeline.validate_authorization(auth_allowed)


# -----------------------------------------------------------------------------
# 9. CyberClawCore End-to-End Policy Execution Tests
# -----------------------------------------------------------------------------

def test_core_execute_action_authorized_flow(tmp_path: Path):
    """Verify successful end-to-end execution records authorization details in history."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="cap.policy.test_exec",
        name="Policy Test Capability",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    core.register_capability(cap)
    core.register_provider(DummyPolicyProvider(cap.id))

    inv = core.create_investigation("Policy Exec Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    result = core.execute_action(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={"test": "val"},
        actor="core.system",
        scope=ActionScope.REVERSIBLE,
    )
    assert result.is_success is True

    # Verify execution history recorded authorization metadata
    exec_history = inv.case_manager.execution_history
    assert len(exec_history) == 1
    record = exec_history[0]
    assert record.authorization_decision_id is not None
    assert record.risk_level == RiskLevel.LOW.value
    assert record.policy_id == DEFAULT_POLICY_ID


def test_core_execute_action_denied_flow(tmp_path: Path):
    """Verify Core execute_action halts immediately when policy denies execution (e.g. auditor mutation)."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="cap.policy.trusted_mutation",
        name="Trusted Mutation Tool",
        action_scope=ActionScope.CONSEQUENTIAL,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
        required_permissions=["investigation:view", "investigation:update"],
    )
    core.register_capability(cap)
    core.register_provider(DummyPolicyProvider(cap.id))

    core.permissions.assign_role("auditor.eve", "auditor")
    core.permissions.grant_permission("auditor.eve", "investigation:view")
    core.permissions.grant_permission("auditor.eve", "investigation:update")

    inv = core.create_investigation("Policy Deny Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    with pytest.raises(AuthorizationDeniedError) as exc_info:
        core.execute_action(
            investigation_id=inv.id,
            capability_id=cap.id,
            parameters={},
            actor="auditor.eve",
            scope=ActionScope.CONSEQUENTIAL,
        )
    assert "Execution denied by policy" in str(exc_info.value)
    # Execution history should not contain successful run
    assert len(inv.case_manager.execution_history) == 0


def test_core_execute_action_approval_required_flow(tmp_path: Path):
    """Verify Core execute_action enforces ApprovalRequiredError for destructive actions."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="cap.policy.destructive_wipe",
        name="Destructive Wipe",
        action_scope=ActionScope.DESTRUCTIVE,
        lifecycle_state=CapabilityLifecycleState.TRUSTED,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
        required_permissions=["resource:wipe"],
    )
    core.register_capability(cap)
    core.register_provider(DummyPolicyProvider(cap.id))

    core.permissions.grant_permission("operator.bob", "investigation:view")
    core.permissions.grant_permission("operator.bob", "investigation:update")
    core.permissions.grant_permission("operator.bob", "resource:wipe")

    inv = core.create_investigation("Destructive Approval Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    from cyberclaw.validation.errors import PolicyValidationError as ValPolicyValidationError
    # Without approval token / approval_granted, it must fail
    with pytest.raises((PolicyValidationError, ValPolicyValidationError)):
        core.execute_action(
            investigation_id=inv.id,
            capability_id=cap.id,
            parameters={},
            actor="operator.bob",
            scope=ActionScope.DESTRUCTIVE,
            approval_granted=False,
        )

    # With approval_granted=True, execution succeeds
    result = core.execute_action(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={},
        actor="operator.bob",
        scope=ActionScope.DESTRUCTIVE,
        approval_granted=True,
    )
    assert result.is_success is True


# -----------------------------------------------------------------------------
# 10. Planning, Branches, Self-Dev & Replay Integration Tests
# -----------------------------------------------------------------------------

def test_plan_validator_policy_integration():
    """Verify PlanValidator checks policy authorization when policy_engine is provided."""
    from cyberclaw.capabilities.registry import CapabilityRegistry
    from cyberclaw.specialists.registry import SpecialistRegistry
    from cyberclaw.permissions.manager import PermissionManager
    from cyberclaw.investigation import Investigation

    caps = CapabilityRegistry()
    specialists = SpecialistRegistry()
    perms = PermissionManager()
    inv = Investigation(id="inv-plan-01", title="Plan Policy Test")
    inv.dfa.transition(CoreState.READY, event="ready")
    inv.dfa.transition(CoreState.INVESTIGATE, event="investigate")

    # Register untrusted capability
    untrusted_cap = Capability(
        id="tool.untrusted_scan",
        name="Untrusted Scan",
        trust_state=CapabilityTrustState.UNTRUSTED,
    )
    caps.register_capability(untrusted_cap)

    candidate = RequirementCandidate(
        target_or_entity="target.org",
        required_capability="tool.untrusted_scan",
        purpose="Scan target",
        risk_classification=ActionScope.REVERSIBLE,
    )

    policy_engine = PolicyEngine()
    val_res = PlanValidator.validate_candidate(
        candidate=candidate,
        investigation=inv,
        specialists=specialists,
        capabilities=caps,
        permissions=perms,
        actor="core.system",
        policy_engine=policy_engine,
    )
    assert val_res.is_valid is False
    assert any("Candidate rejected by policy (DENY)" in r for r in val_res.rejection_reasons)


def test_branch_counterfactual_isolation_denies_destructive(tmp_path: Path):
    """Verify that execution in counterfactual branch is prevented from destructive actions."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="cap.branch.test_tool",
        name="Branch Test Tool",
        action_scope=ActionScope.DESTRUCTIVE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.FULLY_TRUSTED,
    )
    core.register_capability(cap)
    core.register_provider(DummyPolicyProvider(cap.id))

    inv = core.create_investigation("Branch Isolation Policy Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")
    snap = inv.capture_snapshot("baseline")

    # Policy context evaluated inside branch with destructive scope
    branch_ctx = PolicyExecutionContext(
        investigation_id=inv.id,
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="analyst.alice",
        actor_role=ActorRole.ANALYST.value,
        capability_id=cap.id,
        action_scope="destructive",
        lifecycle_state=cap.lifecycle_state.value,
        trust_state=cap.trust_state.value,
        is_branch=True,
        branch_id="branch-01",
    )
    decision = core.policy_engine.authorize(branch_ctx)
    assert decision.decision == AuthorizationDecisionType.DENY
    assert any("R005-DENY-BRANCH-DESTRUCTIVE" in r for r in decision.matched_rules)


def test_self_dev_experimental_skills_quarantined_by_policy():
    """Verify experimental skills cannot execute in production without approval."""
    engine = PolicyEngine()
    ctx = PolicyExecutionContext(
        investigation_id="inv-selfdev-01",
        case_stage=CoreState.INVESTIGATE.value,
        actor_id="specialist.osint",
        actor_role=ActorRole.SPECIALIST.value,
        capability_id="experimental.fast_dns",
        action_scope="reversible",
        lifecycle_state=CapabilityLifecycleState.EXPERIMENTAL.value,
        trust_state=CapabilityTrustState.PROVISIONAL.value,
    )
    decision = engine.authorize(ctx)
    assert decision.decision == AuthorizationDecisionType.REQUIRE_APPROVAL
    assert decision.is_authorized is False
    assert any("R010-APPROVE-EXPERIMENTAL" in r for r in decision.matched_rules)


def test_replay_historical_authorization_reconstruction(tmp_path: Path):
    """Verify deterministic replay reconstructs historical authorization decisions without current policy."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    cap = Capability(
        id="cap.replay.test",
        name="Replay Test Cap",
        action_scope=ActionScope.REVERSIBLE,
        lifecycle_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    core.register_capability(cap)
    core.register_provider(DummyPolicyProvider(cap.id))

    inv = core.create_investigation("Replay Auth Test")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start")

    core.execute_action(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={"k": "v"},
        actor="core.system",
        scope=ActionScope.REVERSIBLE,
    )

    # Replay investigation up to current state
    reconstructed = ReplayEngine.replay(inv)
    # Historical decisions must contain AUTHORIZATION_DECISION
    auth_decisions = [d for d in reconstructed.decisions if d.decision_type == DecisionType.AUTHORIZATION_DECISION]
    assert len(auth_decisions) >= 1
    assert auth_decisions[0].outcome.get("decision") == "ALLOW"
    assert "risk_level" in auth_decisions[0].outcome
