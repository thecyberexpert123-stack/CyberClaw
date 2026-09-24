"""Experience-to-proposal loop. Proposal is explicit. Approval is never implicit."""

from __future__ import annotations

from typing import Any, List, Optional

from cyberclaw.learning.errors import LearningError, PatternNotFoundError, PatternNotValidatedError
from cyberclaw.learning.extraction import ExperienceExtractor
from cyberclaw.learning.models import (
    InvestigationExperience,
    LearningEventType,
    ObservedPattern,
    PatternScope,
)
from cyberclaw.learning.normalization import ExperienceNormalizer
from cyberclaw.learning.patterns import PatternDetector
from cyberclaw.learning.strategies import StrategyBuilder


class IngestResult:
    def __init__(
        self,
        experience: Optional[InvestigationExperience],
        quarantined: bool,
        patterns: List[ObservedPattern],
        failure: Optional[str] = None,
    ) -> None:
        self.experience = experience
        self.quarantined = quarantined
        self.patterns = patterns
        self.failure = failure

    @property
    def ok(self) -> bool:
        return self.failure is None and self.experience is not None


class LearningService:
    """Primary learning loop up to, but not including, approval or execution."""

    def __init__(self, registry: Any) -> None:
        self.registry = registry

    def ingest(self, investigation: Any, *, actor: str = "learning.engine") -> IngestResult:
        journal_before = _journal_length(investigation)
        policy_before = _policy_count(getattr(investigation, "_policy_engine", None))
        try:
            experience = ExperienceExtractor.extract(investigation)
            if _journal_length(investigation) != journal_before:
                raise LearningError("Experience extraction mutated authoritative journal state.")
            if experience.is_counterfactual:
                self.registry.quarantine_experience(experience, actor=actor)
                return IngestResult(experience, True, [])
            normalized = ExperienceNormalizer.normalize(experience)
            self.registry.store_experience(experience, actor=actor)
            self.registry.store_normalized(normalized, actor=actor)
            patterns = self.registry.redetect(actor=actor)
            if _journal_length(investigation) != journal_before or _policy_count(getattr(investigation, "_policy_engine", None)) != policy_before:
                raise LearningError("Learning ingest mutated authoritative investigation state.")
            return IngestResult(experience, False, patterns)
        except LearningError as exc:
            self.registry.record_failure(str(exc), actor=actor, subject_id=getattr(investigation, "id", "unknown"))
            if _journal_length(investigation) != journal_before:
                raise LearningError("Learning failure mutated authoritative state.") from exc
            return IngestResult(None, False, [], failure=str(exc))

    def propose(self, pattern_id: str, proposer_id: str, *, pattern_version: Optional[str] = None):
        pattern = self.registry.get_pattern(pattern_id, pattern_version)
        if pattern is None:
            raise PatternNotFoundError(f"Pattern '{pattern_id}' was not found.")
        if pattern.scope != PatternScope.VALIDATED:
            raise PatternNotValidatedError(
                "A single case or an unvalidated pattern cannot create a global strategy."
            )
        experiences = [
            self.registry.get_experience(inst.experience_id)
            for inst in pattern.instances
            if self.registry.get_experience(inst.experience_id) is not None
        ]
        strategy = StrategyBuilder.propose(pattern, experiences, proposer_id, self.registry.threshold_policy)
        return self.registry.store_strategy(strategy, actor=proposer_id, event_type=LearningEventType.STRATEGY_PROPOSED)

    def redetect(self, actor: str = "learning.engine") -> List[ObservedPattern]:
        return self.registry.redetect(actor=actor)

    def record_simulation(self, strategy_id: str, version: str, actor: str):
        from cyberclaw.learning.governance import StrategyGovernance
        from cyberclaw.learning.models import StrategyLifecycle

        strategy = self.registry.get_strategy(strategy_id, version)
        updated = StrategyGovernance.transition(strategy, StrategyLifecycle.SIMULATED, actor)
        return self.registry.store_strategy(
            updated, actor=actor, event_type=LearningEventType.STRATEGY_SIMULATED
        )

    def record_evaluation(self, evaluation, actor: str):
        from cyberclaw.learning.governance import StrategyGovernance
        from cyberclaw.learning.models import StrategyLifecycle

        strategy = self.registry.get_strategy(evaluation.strategy_id, evaluation.strategy_version)
        if strategy.lifecycle_state == StrategyLifecycle.SIMULATED:
            strategy = StrategyGovernance.transition(strategy, StrategyLifecycle.EVALUATED, actor)
            self.registry.store_strategy(strategy, actor=actor, event_type=LearningEventType.STRATEGY_EVALUATED)
        return self.registry.store_evaluation(evaluation, actor=actor)

    def mark_reviewed(self, strategy_id: str, version: str, actor: str):
        from cyberclaw.learning.governance import StrategyGovernance
        from cyberclaw.learning.models import StrategyLifecycle

        strategy = self.registry.get_strategy(strategy_id, version)
        updated = StrategyGovernance.transition(strategy, StrategyLifecycle.REVIEWED, actor)
        return self.registry.store_strategy(
            updated, actor=actor, event_type=LearningEventType.STRATEGY_REVIEWED
        )

    def approve(self, strategy_id: str, version: str, actor: str, decision, reason: str, evidence_refs=None, policy_id=None, policy_version=None):
        from cyberclaw.learning.governance import StrategyGovernance

        strategy = self.registry.get_strategy(strategy_id, version)
        updated, approval = StrategyGovernance.record_approval(
            strategy,
            actor=actor,
            decision=decision,
            reason=reason,
            evidence_refs=evidence_refs,
            policy_id=policy_id,
            policy_version=policy_version,
        )
        self.registry.store_approval(approval, updated, actor=actor)
        return updated, approval

    def publish(self, strategy_id: str, version: str, actor: str, actor_role: str, policy_engine, investigation_id: str, case_stage: str = "INVESTIGATE"):
        from cyberclaw.learning.errors import StrategyGovernanceError
        from cyberclaw.learning.governance import StrategyGovernance
        from cyberclaw.learning.models import StrategyLifecycle

        strategy = self.registry.get_strategy(strategy_id, version)
        precheck = StrategyGovernance.precheck(
            strategy,
            policy_engine,
            investigation_id=investigation_id,
            actor=actor,
            actor_role=actor_role,
            case_stage=case_stage,
        )
        if not precheck.allowed:
            raise StrategyGovernanceError(
                "Policy precheck denied strategy publication: " + "; ".join(precheck.reasons),
                details={"decision_ids": precheck.decision_ids},
            )
        updated = StrategyGovernance.transition(strategy, StrategyLifecycle.AVAILABLE, actor)
        stored = self.registry.store_strategy(
            updated, actor=actor, event_type=LearningEventType.STRATEGY_LIFECYCLE_TRANSITION
        )
        return stored, precheck

    def apply_regression_review(self, strategy_id: str, version: str, actor: str, target: str):
        from cyberclaw.learning.governance import StrategyGovernance
        from cyberclaw.learning.models import StrategyLifecycle

        strategy = self.registry.get_strategy(strategy_id, version)
        lifecycle = StrategyLifecycle(target)
        updated = StrategyGovernance.transition(strategy, lifecycle, actor)
        updated = updated.model_copy(update={"regression_status": "REVIEWED"})
        stored = self.registry.store_strategy(
            updated, actor=actor, event_type=LearningEventType.REGRESSION_REVIEWED
        )
        self.registry.append_event(
            LearningEventType.REGRESSION_REVIEWED,
            actor=actor,
            subject_id=strategy_id,
            subject_version=version,
            payload={"strategy": stored.model_dump(mode="json"), "decision": target},
        )
        return stored


def _journal_length(investigation: Any) -> int:
    manager = getattr(investigation, "case_manager", None)
    if manager is None:
        return 0
    return len(manager.journal.entries)


def _policy_count(policy_engine: Any) -> int:
    if policy_engine is None:
        return 0
    registry = getattr(policy_engine, "registry", None)
    if registry is None:
        return 0
    return len(registry.list_policies())


def detect_patterns(registry: Any):
    """Pure detection against the registry's authoritative experiences."""
    experiences = registry.authoritative_experiences()
    normalized = {exp.experience_id: registry.get_normalized(exp.experience_id) for exp in experiences}
    normalized = {key: value for key, value in normalized.items() if value is not None}
    return PatternDetector.detect(experiences, normalized, registry.threshold_policy)
