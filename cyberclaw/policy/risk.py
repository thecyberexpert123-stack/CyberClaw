"""Deterministic, explainable risk evaluation engine for CyberClaw actions."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from cyberclaw.capabilities.models import CapabilityLifecycleState, CapabilityTrustState
from cyberclaw.dfa.states import CoreState
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.policy.models import (
    ActorRole,
    PolicyExecutionContext,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
)


class RiskEvaluator:
    """Evaluates contextual risk across action scope, trust, lifecycle, stage, role, and parameters.

    Operates deterministically without black-box heuristics or stochastic LLM calls.
    """

    @classmethod
    def evaluate(
        cls,
        context: PolicyExecutionContext,
        additional_factors: Optional[List[RiskFactor]] = None,
    ) -> RiskAssessment:
        """Deterministically assess risk for a proposed execution context."""
        factors: List[RiskFactor] = []

        # 1. Action Scope Risk
        scope_factor = cls._evaluate_scope_risk(context.action_scope)
        factors.append(scope_factor)

        # 2. Lifecycle State Risk
        lifecycle_factor = cls._evaluate_lifecycle_risk(context.lifecycle_state)
        factors.append(lifecycle_factor)

        # 3. Trust State Risk
        trust_factor = cls._evaluate_trust_risk(context.trust_state)
        factors.append(trust_factor)

        # 4. Investigation DFA Stage Risk
        stage_factor = cls._evaluate_stage_risk(context.case_stage, context.action_scope)
        factors.append(stage_factor)

        # 5. Actor Role Risk
        role_factor = cls._evaluate_role_risk(context.actor_role, context.action_scope)
        factors.append(role_factor)

        # 6. Counterfactual / Branch Risk
        branch_factor = cls._evaluate_branch_risk(context.is_branch, context.action_scope)
        if branch_factor:
            factors.append(branch_factor)

        # 7. Parameter & Input Risk
        param_factor = cls._evaluate_parameters_risk(context.parameters)
        if param_factor:
            factors.append(param_factor)

        if additional_factors:
            factors.extend(additional_factors)

        # Compute deterministic weighted score
        total_weight = sum(f.weight for f in factors)
        if total_weight <= 0:
            weighted_score = 1.0
        else:
            weighted_score = sum(f.score * f.weight for f in factors) / total_weight

        # Check for overriding critical factor (fail-closed severity gate)
        has_critical = any(f.level == RiskLevel.CRITICAL for f in factors)
        has_high = any(f.level == RiskLevel.HIGH for f in factors)
        has_unknown = any(f.level == RiskLevel.UNKNOWN for f in factors)

        if has_unknown or has_critical:
            overall_risk = RiskLevel.CRITICAL
            weighted_score = max(weighted_score, 0.90)
        elif has_high or weighted_score >= 0.70:
            overall_risk = RiskLevel.HIGH
            weighted_score = max(weighted_score, 0.70)
        elif weighted_score >= 0.40:
            overall_risk = RiskLevel.MODERATE
        else:
            overall_risk = RiskLevel.LOW

        rationale_parts = [
            f"Overall risk evaluated as {overall_risk.value} (score: {weighted_score:.2f})."
        ]
        high_critical_factors = [f for f in factors if f.level in (RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.UNKNOWN)]
        if high_critical_factors:
            rationale_parts.append(
                "Elevated by factors: " + "; ".join(f"{f.name} ({f.level.value}: {f.description})" for f in high_critical_factors)
            )
        else:
            rationale_parts.append("All risk dimensions within standard operational bounds.")

        return RiskAssessment(
            overall_risk=overall_risk,
            score=round(weighted_score, 4),
            factors=factors,
            rationale=" ".join(rationale_parts),
        )

    @staticmethod
    def _evaluate_scope_risk(action_scope: str) -> RiskFactor:
        norm_scope = action_scope.lower()
        if norm_scope in ("read_only", "informational"):
            return RiskFactor(
                name="action_scope",
                score=0.10,
                weight=1.5,
                level=RiskLevel.LOW,
                description=f"Action scope '{action_scope}' is read-only / non-mutating.",
            )
        elif norm_scope == "reversible":
            return RiskFactor(
                name="action_scope",
                score=0.25,
                weight=1.5,
                level=RiskLevel.LOW,
                description=f"Action scope '{action_scope}' can be rolled back safely.",
            )
        elif norm_scope == "consequential":
            return RiskFactor(
                name="action_scope",
                score=0.55,
                weight=2.0,
                level=RiskLevel.MODERATE,
                description=f"Action scope '{action_scope}' alters external environment or produces persistent mutations.",
            )
        elif norm_scope in ("destructive", "irreversible"):
            return RiskFactor(
                name="action_scope",
                score=0.90,
                weight=2.5,
                level=RiskLevel.HIGH,
                description=f"Action scope '{action_scope}' has irreversible or destructive impacts.",
            )
        else:
            return RiskFactor(
                name="action_scope",
                score=1.0,
                weight=3.0,
                level=RiskLevel.UNKNOWN,
                description=f"Unrecognized action scope '{action_scope}'; defaulting to maximum risk.",
            )

    @staticmethod
    def _evaluate_lifecycle_risk(lifecycle_state: str) -> RiskFactor:
        norm = lifecycle_state.upper()
        if norm in (CapabilityLifecycleState.AVAILABLE.value, CapabilityLifecycleState.TRUSTED.value):
            return RiskFactor(
                name="lifecycle_state",
                score=0.10,
                weight=1.0,
                level=RiskLevel.LOW,
                description=f"Capability is in stable lifecycle state '{norm}'.",
            )
        elif norm == CapabilityLifecycleState.VALIDATED.value:
            return RiskFactor(
                name="lifecycle_state",
                score=0.20,
                weight=1.0,
                level=RiskLevel.LOW,
                description=f"Capability is formally validated '{norm}'.",
            )
        elif norm == CapabilityLifecycleState.PROPOSED.value:
            return RiskFactor(
                name="lifecycle_state",
                score=0.60,
                weight=1.5,
                level=RiskLevel.MODERATE,
                description="Capability is merely proposed and has not passed full lifecycle validation.",
            )
        elif norm == CapabilityLifecycleState.EXPERIMENTAL.value:
            return RiskFactor(
                name="lifecycle_state",
                score=0.75,
                weight=2.0,
                level=RiskLevel.HIGH,
                description="Capability is experimental / unproven; execution carries elevated operational risk.",
            )
        elif norm == CapabilityLifecycleState.DEPRECATED.value:
            return RiskFactor(
                name="lifecycle_state",
                score=0.80,
                weight=2.0,
                level=RiskLevel.HIGH,
                description="Capability is deprecated and scheduled for retirement.",
            )
        elif norm in (
            CapabilityLifecycleState.DISABLED.value,
            CapabilityLifecycleState.RETIRED.value,
            CapabilityLifecycleState.REJECTED.value,
            "QUARANTINED",
        ):
            return RiskFactor(
                name="lifecycle_state",
                score=1.0,
                weight=3.0,
                level=RiskLevel.CRITICAL,
                description=f"Capability is in non-executable lifecycle state '{norm}'.",
            )
        else:
            return RiskFactor(
                name="lifecycle_state",
                score=1.0,
                weight=3.0,
                level=RiskLevel.UNKNOWN,
                description=f"Unrecognized capability lifecycle state '{lifecycle_state}'.",
            )

    @staticmethod
    def _evaluate_trust_risk(trust_state: str) -> RiskFactor:
        norm = trust_state.upper()
        if norm == CapabilityTrustState.FULLY_TRUSTED.value:
            return RiskFactor(
                name="trust_state",
                score=0.05,
                weight=1.0,
                level=RiskLevel.LOW,
                description="Capability has full cryptographic/organizational trust tier.",
            )
        elif norm == CapabilityTrustState.TRUSTED_WITH_SCOPE.value:
            return RiskFactor(
                name="trust_state",
                score=0.20,
                weight=1.0,
                level=RiskLevel.LOW,
                description="Capability is trusted within its declared operational scope.",
            )
        elif norm == CapabilityTrustState.PROVISIONAL.value:
            return RiskFactor(
                name="trust_state",
                score=0.65,
                weight=1.5,
                level=RiskLevel.MODERATE,
                description="Capability has only provisional trust; strict boundary checks required.",
            )
        elif norm == CapabilityTrustState.UNTRUSTED.value:
            return RiskFactor(
                name="trust_state",
                score=0.85,
                weight=2.5,
                level=RiskLevel.HIGH,
                description="Capability has untrusted origin or unverified provenance.",
            )
        elif norm == CapabilityTrustState.REVOKED.value:
            return RiskFactor(
                name="trust_state",
                score=1.0,
                weight=3.0,
                level=RiskLevel.CRITICAL,
                description="Capability trust has been explicitly REVOKED.",
            )
        else:
            return RiskFactor(
                name="trust_state",
                score=1.0,
                weight=3.0,
                level=RiskLevel.UNKNOWN,
                description=f"Unknown capability trust state '{trust_state}'.",
            )

    @staticmethod
    def _evaluate_stage_risk(case_stage: str, action_scope: str) -> RiskFactor:
        stage_norm = case_stage.upper()
        is_mutating = action_scope.lower() not in ("read_only", "informational")

        if stage_norm in (CoreState.RESOLVE.value, CoreState.FAILED.value):
            return RiskFactor(
                name="investigation_stage",
                score=0.95 if is_mutating else 0.40,
                weight=2.0,
                level=RiskLevel.CRITICAL if is_mutating else RiskLevel.MODERATE,
                description=f"Investigation is in terminal state '{stage_norm}'; actions should be strictly read-only.",
            )
        elif stage_norm == CoreState.PAUSED.value:
            return RiskFactor(
                name="investigation_stage",
                score=0.60 if is_mutating else 0.15,
                weight=1.2,
                level=RiskLevel.MODERATE if is_mutating else RiskLevel.LOW,
                description=f"Investigation is in PAUSED state; mutating actions carry elevated risk.",
            )
        else:
            return RiskFactor(
                name="investigation_stage",
                score=0.15,
                weight=1.0,
                level=RiskLevel.LOW,
                description=f"Investigation is in active investigative state '{stage_norm}'.",
            )

    @staticmethod
    def _evaluate_role_risk(actor_role: str, action_scope: str) -> RiskFactor:
        norm_role = actor_role.lower()
        is_mutating = action_scope.lower() not in ("read_only", "informational")
        is_destructive = action_scope.lower() in ("destructive", "irreversible")

        if norm_role == ActorRole.AUDITOR.value:
            if is_mutating:
                return RiskFactor(
                    name="actor_role",
                    score=0.95,
                    weight=3.0,
                    level=RiskLevel.CRITICAL,
                    description="Auditor role is strictly observational and must never execute mutating or consequential actions.",
                )
            return RiskFactor(
                name="actor_role",
                score=0.05,
                weight=1.0,
                level=RiskLevel.LOW,
                description="Auditor role performing non-mutating inspection.",
            )
        elif norm_role in (ActorRole.SYSTEM.value, ActorRole.LEAD_INVESTIGATOR.value):
            return RiskFactor(
                name="actor_role",
                score=0.10,
                weight=1.0,
                level=RiskLevel.LOW,
                description=f"Authorized principal role '{actor_role}'.",
            )
        elif norm_role in (ActorRole.ANALYST.value, ActorRole.OPERATOR.value, ActorRole.SPECIALIST.value):
            if is_destructive:
                return RiskFactor(
                    name="actor_role",
                    score=0.85,
                    weight=2.0,
                    level=RiskLevel.HIGH,
                    description=f"Role '{actor_role}' attempting destructive action requires lead authority.",
                )
            return RiskFactor(
                name="actor_role",
                score=0.25,
                weight=1.0,
                level=RiskLevel.LOW,
                description=f"Standard principal role '{actor_role}'.",
            )
        else:
            return RiskFactor(
                name="actor_role",
                score=1.0,
                weight=3.0,
                level=RiskLevel.UNKNOWN,
                description=f"Unrecognized actor role '{actor_role}'.",
            )

    @staticmethod
    def _evaluate_branch_risk(is_branch: bool, action_scope: str) -> Optional[RiskFactor]:
        if not is_branch:
            return None
        norm_scope = action_scope.lower()
        if norm_scope in ("destructive", "irreversible"):
            return RiskFactor(
                name="branch_containment",
                score=0.95,
                weight=2.5,
                level=RiskLevel.CRITICAL,
                description="Counterfactual branches must never perform destructive external operations.",
            )
        return RiskFactor(
            name="branch_containment",
            score=0.15,
            weight=0.8,
            level=RiskLevel.LOW,
            description="Execution is isolated within a counterfactual branch sandbox.",
        )

    @staticmethod
    def _evaluate_parameters_risk(parameters: Dict[str, Any]) -> Optional[RiskFactor]:
        if not parameters:
            return None

        risky_keys = {"force", "drop", "delete", "destroy", "purge", "overwrite", "raw_exec"}
        found_risky = [k for k in parameters.keys() if k.lower() in risky_keys and bool(parameters[k])]

        if found_risky:
            return RiskFactor(
                name="dangerous_parameters",
                score=0.85,
                weight=2.0,
                level=RiskLevel.HIGH,
                description=f"Execution parameters contain dangerous flags: {found_risky}",
            )
        return None
