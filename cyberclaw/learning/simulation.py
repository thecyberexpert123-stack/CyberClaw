"""Counterfactual strategy simulation. Never executes providers or mutates authoritative state."""

from __future__ import annotations

from typing import Any, List, Optional, Sequence

from cyberclaw.learning.models import (
    SIMULATION_VERSION,
    AssessmentLabel,
    CandidateBranchExperience,
    InvestigationExperience,
    InvestigationStrategy,
    SimulationAnswer,
    SimulationReport,
    canonical_digest,
    stable_id,
)


Q_GAP = "Would this strategy have resolved the historical information gap?"
Q_ACTIONS = "Would it have reduced unnecessary actions?"
Q_CONTRADICTIONS = "Would it have introduced additional contradictions?"
Q_CAPABILITIES = "Would it have required unavailable capabilities?"
Q_AUTH = "Would it have crossed authorization boundaries?"


class StrategySimulator:
    """Structural counterfactual comparison against historical experiences and branches.

    The simulator answers fit questions. It does not claim causation, does not
    call providers, and does not write to authoritative case state.
    """

    VERSION = SIMULATION_VERSION

    @classmethod
    def simulate(
        cls,
        strategy: InvestigationStrategy,
        experiences: Sequence[InvestigationExperience],
        *,
        available_capabilities: Optional[Sequence[str]] = None,
        policy_engine: Any = None,
        actor: str = "lead.simulator",
        actor_role: str = "lead_investigator",
    ) -> List[SimulationReport]:
        reports = []
        for experience in experiences:
            reports.append(
                cls._simulate_one(
                    strategy,
                    experience,
                    available_capabilities=available_capabilities,
                    policy_engine=policy_engine,
                    actor=actor,
                    actor_role=actor_role,
                )
            )
        return reports

    @classmethod
    def _simulate_one(
        cls,
        strategy: InvestigationStrategy,
        experience: InvestigationExperience,
        *,
        available_capabilities: Optional[Sequence[str]],
        policy_engine: Any,
        actor: str,
        actor_role: str,
    ) -> SimulationReport:
        catalog = set(available_capabilities) if available_capabilities is not None else set(experience.capabilities_used)
        required = set(strategy.required_capabilities)
        missing = sorted(required - catalog)
        denials = [
            outcome
            for outcome in experience.authorization_outcomes
            if str(outcome.get("decision", "")).upper() in {"DENY", "DENIED", "AUTHORIZATION_DENIED"}
            and (not outcome.get("capability_id") or outcome.get("capability_id") in required or not required)
        ]
        policy_boundary: List[str] = []
        live_decisions_before = None
        if policy_engine is not None:
            live_decisions_before = len(getattr(policy_engine, "_decisions", {}))
            policy_boundary = cls._isolated_precheck(
                strategy, policy_engine, experience.investigation_id, actor, actor_role, experience.case_stage or "INVESTIGATE"
            )
        gap_overlap = bool(
            set(strategy.applicability.information_gap_structure) & set(experience.uncertainty_types)
            or set(strategy.applicability.uncertainty_characteristics) & set(experience.uncertainty_types)
        )
        if missing:
            gap_assessment = AssessmentLabel.NOT_SUPPORTED
            gap_rationale = (
                "Required capabilities were not present in the historical catalog. "
                "This is a structural precondition failure, not a causal claim."
            )
        elif denials or policy_boundary:
            gap_assessment = AssessmentLabel.BOUNDARY_CROSSED
            gap_rationale = "Historical or policy authorization boundaries would have been crossed. Execution was not attempted."
        elif gap_overlap or experience.requirements_unresolved or experience.contradictions:
            gap_assessment = AssessmentLabel.STRUCTURAL_FIT
            gap_rationale = (
                "The historical case contained a matching gap or contradiction structure and the required "
                "capabilities were present. This is a counterfactual structural fit, not evidence that the "
                "strategy would have succeeded."
            )
        else:
            gap_assessment = AssessmentLabel.INDETERMINATE
            gap_rationale = "Historical records do not contain enough gap structure to support even a structural fit."

        historical_actions = len(experience.actions_taken)
        step_count = len(strategy.steps)
        if step_count < historical_actions:
            action_assessment = AssessmentLabel.FEWER_STEPS
            action_rationale = (
                f"Strategy has {step_count} intent steps versus {historical_actions} historical actions. "
                "Fewer steps is a structural comparison, not a promise of lower cost."
            )
        elif step_count > historical_actions:
            action_assessment = AssessmentLabel.MORE_STEPS
            action_rationale = (
                f"Strategy has {step_count} intent steps versus {historical_actions} historical actions."
            )
        else:
            action_assessment = AssessmentLabel.EQUAL_STEPS
            action_rationale = "Intent step count equals the historical action count."

        if experience.contradictions and experience.outcome.value == "FAILURE":
            contradiction_assessment = AssessmentLabel.CORRELATED_NOT_CAUSAL
            contradiction_rationale = (
                "A historical failure in a related context co-occurred with contradictions. "
                "Correlation is not causation."
            )
        else:
            contradiction_assessment = AssessmentLabel.NO_HISTORICAL_CORRELATION
            contradiction_rationale = "No historical correlation was recorded that this strategy introduces contradictions."

        cap_assessment = AssessmentLabel.UNAVAILABLE if missing else AssessmentLabel.NOT_SUPPORTED
        if not missing:
            cap_assessment = AssessmentLabel.STRUCTURAL_FIT
        auth_assessment = AssessmentLabel.BOUNDARY_CROSSED if (denials or policy_boundary) else AssessmentLabel.NOT_SUPPORTED
        if not denials and not policy_boundary:
            auth_assessment = AssessmentLabel.NO_HISTORICAL_CORRELATION

        answers = [
            SimulationAnswer(question=Q_GAP, assessment=gap_assessment, rationale=gap_rationale),
            SimulationAnswer(question=Q_ACTIONS, assessment=action_assessment, rationale=action_rationale),
            SimulationAnswer(
                question=Q_CONTRADICTIONS,
                assessment=contradiction_assessment,
                rationale=contradiction_rationale,
            ),
            SimulationAnswer(
                question=Q_CAPABILITIES,
                assessment=cap_assessment,
                rationale="Missing capabilities: " + (", ".join(missing) if missing else "none"),
            ),
            SimulationAnswer(
                question=Q_AUTH,
                assessment=auth_assessment,
                rationale="Authorization boundaries: "
                + (", ".join(policy_boundary) if policy_boundary else "none from isolated precheck")
                + f"; historical denials={len(denials)}",
            ),
        ]
        live_after = len(getattr(policy_engine, "_decisions", {})) if policy_engine is not None else 0
        live_delta = 0
        if live_decisions_before is not None:
            live_delta = live_after - live_decisions_before
        payload = {
            "strategy_id": strategy.strategy_id,
            "strategy_version": strategy.version,
            "experience_id": experience.experience_id,
            "assessments": [answer.assessment.value for answer in answers],
            "missing": missing,
        }
        return SimulationReport(
            report_id=stable_id("sim", canonical_digest(payload)),
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            experience_id=experience.experience_id,
            investigation_id=experience.investigation_id,
            answers=answers,
            missing_capabilities=missing,
            authorization_boundaries=[item.get("journal_entry_id", "") for item in denials if item.get("journal_entry_id")] + policy_boundary,
            providers_executed=0,
            authoritative_state_mutated=False,
            policy_decisions_on_live_engine=live_delta,
            capabilities_granted=0,
        )

    @staticmethod
    def _isolated_precheck(
        strategy: InvestigationStrategy,
        policy_engine: Any,
        investigation_id: str,
        actor: str,
        actor_role: str,
        case_stage: str,
    ) -> List[str]:
        """Evaluate policy on an isolated engine so the live decision store is untouched."""
        from cyberclaw.policy.engine import PolicyEngine
        from cyberclaw.policy.models import PolicyExecutionContext

        isolated = PolicyEngine(registry=policy_engine.registry.create_isolated_snapshot())
        boundaries = []
        caps = strategy.required_capabilities or ["learning.strategy.consult"]
        for capability_id in caps:
            context = PolicyExecutionContext(
                investigation_id=investigation_id,
                case_stage=case_stage or "INVESTIGATE",
                actor_id=actor,
                actor_role=actor_role,
                capability_id=capability_id,
                capability_version="1.0.0",
                action_type="consult",
                action_scope="reversible",
                lifecycle_state="AVAILABLE",
                trust_state="TRUSTED_WITH_SCOPE",
                parameters={},
            )
            decision = isolated.authorize(context)
            if not decision.is_authorized:
                boundaries.append(f"{capability_id}:{decision.decision.value}")
        return boundaries

    @classmethod
    def simulate_on_branch(
        cls,
        strategy: InvestigationStrategy,
        branch: Any,
        experience: Optional[InvestigationExperience] = None,
        *,
        source_snapshot: Optional[str] = None,
    ) -> CandidateBranchExperience:
        """Record a counterfactual branch evaluation. Does not touch authoritative history."""
        snapshot = source_snapshot or getattr(branch, "source_snapshot_id", "")
        pseudo = experience
        if pseudo is None:
            pseudo = _branch_experience_view(branch, snapshot)
        report = cls._simulate_one(
            strategy,
            pseudo,
            available_capabilities=pseudo.capabilities_used,
            policy_engine=None,
            actor="lead.simulator",
            actor_role="lead_investigator",
        )
        candidate = CandidateBranchExperience(
            candidate_id=stable_id("branch-exp", strategy.strategy_id, getattr(branch, "branch_id", "branch"), snapshot),
            strategy_id=strategy.strategy_id,
            strategy_version=strategy.version,
            branch_id=getattr(branch, "branch_id", ""),
            investigation_id=getattr(branch, "investigation_id", pseudo.investigation_id),
            source_snapshot=snapshot,
            evaluation_context={
                "strategy_id": strategy.strategy_id,
                "strategy_version": strategy.version,
                "is_counterfactual": True,
                "source_snapshot": snapshot,
                "report_id": report.report_id,
            },
            report=report,
        )
        if hasattr(branch, "metadata") and isinstance(branch.metadata, dict):
            records = list(branch.metadata.get("strategy_evaluations") or [])
            records.append(candidate.evaluation_context)
            branch.metadata["strategy_evaluations"] = records
        try:
            from cyberclaw.branching.engine import BranchEngine
            from cyberclaw.case.models import JournalEntryType

            if getattr(branch, "status", None) and str(getattr(branch.status, "value", branch.status)) == "ACTIVE":
                BranchEngine.apply_simulated_event(
                    branch,
                    entry_type=JournalEntryType.STRATEGY_SIMULATION_RECORDED,
                    summary=f"Counterfactual simulation of strategy {strategy.strategy_id}@{strategy.version}",
                    reference_id=strategy.strategy_id,
                    details=candidate.evaluation_context,
                )
        except Exception:
            # Branch recording is best-effort and must not be required to mutate authoritative state.
            pass
        return candidate


def _branch_experience_view(branch: Any, snapshot: str) -> InvestigationExperience:
    """Minimal read-only view so branch simulation does not require a full extraction."""
    from datetime import datetime, timezone

    from cyberclaw.learning.models import OutcomeClass

    investigation_id = getattr(branch, "investigation_id", "branch-investigation")
    caps = list(getattr(branch, "metadata", {}).get("capabilities_used", []) or [])
    return InvestigationExperience(
        experience_id=stable_id("branch-view", getattr(branch, "branch_id", "branch"), snapshot),
        investigation_id=investigation_id,
        case_id=investigation_id,
        objective=getattr(branch, "purpose", "") or "",
        capabilities_used=caps,
        source_family_key=f"branch:{getattr(branch, 'branch_id', 'branch')}",
        uncertainty_types=list(getattr(branch, "metadata", {}).get("uncertainty_types", []) or []),
        case_stage="INVESTIGATE",
        outcome=OutcomeClass.INDETERMINATE,
        is_counterfactual=True,
        branch_id=getattr(branch, "branch_id", None),
        extracted_at=datetime.now(timezone.utc),
        content_digest=stable_id("digest", snapshot),
    )
