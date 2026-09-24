"""Version-aware learning and strategy registry. Lookup is by id and version, not preference."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from cyberclaw.learning.errors import (
    BranchExperienceQuarantineError,
    LearningReplayError,
    PatternNotFoundError,
    StrategyNotFoundError,
)
from cyberclaw.learning.governance import validate_threshold_policy
from cyberclaw.learning.models import (
    LEARNING_LEDGER_VERSION,
    PATTERN_DETECTOR_VERSION,
    CandidateBranchExperience,
    CollaborationPattern,
    FailurePattern,
    InvestigationExperience,
    InvestigationStrategy,
    LearningEvent,
    LearningEventType,
    NormalizedExperience,
    ObservedPattern,
    PromotionThresholdPolicy,
    ReconstructedLearningState,
    RegressionSignal,
    StrategyApprovalDecision,
    StrategyEvaluation,
    StrategyLifecycle,
    StrategyOriginExplanation,
    StrategyOutcome,
    bump_minor,
    canonical_digest,
    semver_key,
    stable_id,
    utc_now,
)
from cyberclaw.learning.patterns import PatternDetector
from cyberclaw.learning.strategies import assert_not_executable


class LearningRegistry:
    """Cross-case learning store. Case-local observations do not become global authority here."""

    def __init__(self, threshold_policy: Optional[PromotionThresholdPolicy] = None) -> None:
        self._experiences: Dict[str, InvestigationExperience] = {}
        self._normalized: Dict[str, NormalizedExperience] = {}
        self._patterns: Dict[str, Dict[str, ObservedPattern]] = {}
        self._strategies: Dict[str, Dict[str, InvestigationStrategy]] = {}
        self._evaluations: Dict[str, List[StrategyEvaluation]] = {}
        self._approvals: Dict[str, List[StrategyApprovalDecision]] = {}
        self._outcomes: Dict[str, List[StrategyOutcome]] = {}
        self._failure_patterns: Dict[str, FailurePattern] = {}
        self._collaboration_patterns: Dict[str, CollaborationPattern] = {}
        self._quarantine: Dict[str, Any] = {}
        self._regressions: List[RegressionSignal] = []
        self._events: List[LearningEvent] = []
        self._threshold_policies: Dict[str, Dict[str, PromotionThresholdPolicy]] = {}
        policy = threshold_policy or PromotionThresholdPolicy()
        self.register_threshold_policy(policy, actor="learning.registry", make_active=True)
        self._active_threshold_policy_id = policy.policy_id
        self._active_threshold_policy_version = policy.version

    @property
    def events(self) -> List[LearningEvent]:
        return list(self._events)

    @property
    def threshold_policy(self) -> PromotionThresholdPolicy:
        return self._threshold_policies[self._active_threshold_policy_id][self._active_threshold_policy_version]

    def register_threshold_policy(
        self,
        policy: PromotionThresholdPolicy,
        *,
        actor: str,
        make_active: bool = False,
    ) -> PromotionThresholdPolicy:
        validate_threshold_policy(policy)
        self._threshold_policies.setdefault(policy.policy_id, {})
        existing = self._threshold_policies[policy.policy_id].get(policy.version)
        if existing is not None and existing != policy:
            from cyberclaw.learning.errors import LearningThresholdError

            raise LearningThresholdError(
                f"Threshold policy {policy.policy_id}@{policy.version} is already registered and immutable."
            )
        self._threshold_policies[policy.policy_id][policy.version] = policy
        if make_active:
            self._active_threshold_policy_id = policy.policy_id
            self._active_threshold_policy_version = policy.version
        self.append_event(
            LearningEventType.THRESHOLD_POLICY_REGISTERED,
            actor=actor,
            subject_id=policy.policy_id,
            subject_version=policy.version,
            payload=policy.model_dump(mode="json"),
            threshold_policy_id=policy.policy_id,
            threshold_policy_version=policy.version,
        )
        return policy

    def append_event(
        self,
        event_type: LearningEventType,
        *,
        actor: str,
        subject_id: str,
        payload: Dict[str, Any],
        subject_version: Optional[str] = None,
        is_counterfactual: bool = False,
        detector_version: Optional[str] = None,
        evaluator_version: Optional[str] = None,
        normalization_version: Optional[str] = None,
        applicability_version: Optional[str] = None,
        threshold_policy_id: Optional[str] = None,
        threshold_policy_version: Optional[str] = None,
        policy_id: Optional[str] = None,
        policy_version: Optional[str] = None,
        timestamp: Any = None,
    ) -> LearningEvent:
        sequence = len(self._events) + 1
        event = LearningEvent(
            event_id=stable_id("lev", str(sequence), event_type.value, subject_id, subject_version or ""),
            sequence=sequence,
            event_type=event_type,
            timestamp=timestamp or utc_now(),
            actor=actor,
            subject_id=subject_id,
            subject_version=subject_version,
            schema_version=LEARNING_LEDGER_VERSION,
            detector_version=detector_version,
            evaluator_version=evaluator_version,
            normalization_version=normalization_version,
            applicability_version=applicability_version,
            threshold_policy_id=threshold_policy_id or self._active_threshold_policy_id,
            threshold_policy_version=threshold_policy_version or self._active_threshold_policy_version,
            policy_id=policy_id,
            policy_version=policy_version,
            payload=payload,
            is_counterfactual=is_counterfactual,
        )
        self._events.append(event)
        return event

    def store_experience(self, experience: InvestigationExperience, *, actor: str) -> InvestigationExperience:
        if experience.is_counterfactual:
            raise BranchExperienceQuarantineError(
                "Counterfactual experience cannot be stored as authoritative experience."
            )
        self._experiences[experience.experience_id] = experience
        self.append_event(
            LearningEventType.EXPERIENCE_EXTRACTED,
            actor=actor,
            subject_id=experience.experience_id,
            subject_version=experience.schema_version,
            payload=experience.model_dump(mode="json"),
            normalization_version=None,
        )
        return experience

    def quarantine_experience(self, experience: InvestigationExperience, *, actor: str) -> InvestigationExperience:
        self._quarantine[experience.experience_id] = experience
        self.append_event(
            LearningEventType.EXPERIENCE_QUARANTINED,
            actor=actor,
            subject_id=experience.experience_id,
            payload=experience.model_dump(mode="json"),
            is_counterfactual=True,
        )
        return experience

    def store_normalized(self, normalized: NormalizedExperience, *, actor: str) -> NormalizedExperience:
        self._normalized[normalized.experience_id] = normalized
        self.append_event(
            LearningEventType.EXPERIENCE_NORMALIZED,
            actor=actor,
            subject_id=normalized.normalized_id,
            subject_version=normalized.normalization_version,
            payload=normalized.model_dump(mode="json"),
            normalization_version=normalized.normalization_version,
        )
        return normalized

    def get_experience(self, experience_id: str) -> Optional[InvestigationExperience]:
        return self._experiences.get(experience_id)

    def get_normalized(self, experience_id: str) -> Optional[NormalizedExperience]:
        return self._normalized.get(experience_id)

    def authoritative_experiences(self) -> List[InvestigationExperience]:
        return [exp for exp in self._experiences.values() if not exp.is_counterfactual]

    def redetect(self, *, actor: str = "learning.engine") -> List[ObservedPattern]:
        experiences = self.authoritative_experiences()
        normalized = {
            exp.experience_id: self._normalized[exp.experience_id]
            for exp in experiences
            if exp.experience_id in self._normalized
        }
        result = PatternDetector.detect(experiences, normalized, self.threshold_policy)
        current = []
        for pattern in result.patterns:
            current.append(self._store_pattern_version(pattern, actor=actor))
        for failure in result.failure_patterns:
            self._failure_patterns[failure.failure_pattern_id] = failure
        for collab in result.collaboration_patterns:
            self._collaboration_patterns[collab.collaboration_pattern_id] = collab
        return current

    def _store_pattern_version(self, pattern: ObservedPattern, *, actor: str) -> ObservedPattern:
        versions = self._patterns.setdefault(pattern.pattern_id, {})
        if not versions:
            stored = pattern
        else:
            latest = versions[sorted(versions, key=semver_key)[-1]]
            same_observation = (
                latest.signature == pattern.signature
                and latest.scope == pattern.scope
                and [inst.experience_id for inst in latest.instances] == [inst.experience_id for inst in pattern.instances]
            )
            if same_observation:
                return latest
            stored = pattern.model_copy(update={"version": bump_minor(latest.version)})
            stored = stored.model_copy(
                update={
                    "content_digest": canonical_digest(
                        {
                            "pattern_id": stored.pattern_id,
                            "version": stored.version,
                            "signature": stored.signature,
                            "scope": stored.scope.value,
                            "instances": [inst.experience_id for inst in stored.instances],
                        }
                    )
                }
            )
        versions[stored.version] = stored
        self.append_event(
            LearningEventType.PATTERN_VERSION_RECORDED,
            actor=actor,
            subject_id=stored.pattern_id,
            subject_version=stored.version,
            payload=stored.model_dump(mode="json"),
            detector_version=stored.detector_version,
            threshold_policy_id=stored.threshold_policy_id,
            threshold_policy_version=stored.threshold_policy_version,
        )
        return stored

    def get_pattern(self, pattern_id: str, version: Optional[str] = None) -> ObservedPattern:
        versions = self._patterns.get(pattern_id)
        if not versions:
            raise PatternNotFoundError(f"Pattern '{pattern_id}' not found.")
        if version is None:
            version = sorted(versions, key=semver_key)[-1]
        if version not in versions:
            raise PatternNotFoundError(f"Pattern '{pattern_id}' version '{version}' not found.")
        return versions[version]

    def list_patterns(self) -> List[ObservedPattern]:
        found = []
        for pattern_id in sorted(self._patterns):
            version = sorted(self._patterns[pattern_id], key=semver_key)[-1]
            found.append(self._patterns[pattern_id][version])
        return found

    def store_strategy(
        self,
        strategy: InvestigationStrategy,
        *,
        actor: str,
        event_type: LearningEventType = LearningEventType.STRATEGY_LIFECYCLE_TRANSITION,
    ) -> InvestigationStrategy:
        assert_not_executable(strategy.model_dump(mode="json"))
        versions = self._strategies.setdefault(strategy.strategy_id, {})
        existing = versions.get(strategy.version)
        if existing is not None and existing.content_digest != strategy.content_digest:
            from cyberclaw.learning.errors import LearningValidationError

            raise LearningValidationError(
                f"Strategy {strategy.strategy_id}@{strategy.version} content is immutable. "
                "Create a new version instead of rewriting history."
            )
        versions[strategy.version] = strategy
        self.append_event(
            event_type,
            actor=actor,
            subject_id=strategy.strategy_id,
            subject_version=strategy.version,
            payload={"strategy": strategy.model_dump(mode="json"), "content_digest": strategy.content_digest},
            detector_version=strategy.provenance.get("detector_version"),
        )
        return strategy

    def get_strategy(self, strategy_id: str, version: Optional[str] = None) -> InvestigationStrategy:
        versions = self._strategies.get(strategy_id)
        if not versions:
            raise StrategyNotFoundError(f"Strategy '{strategy_id}' not found.")
        if version is None:
            version = sorted(versions, key=semver_key)[-1]
        if version not in versions:
            raise StrategyNotFoundError(f"Strategy '{strategy_id}' version '{version}' not found.")
        return versions[version]

    def list_strategies(self, lifecycle: Optional[StrategyLifecycle] = None) -> List[InvestigationStrategy]:
        items: List[InvestigationStrategy] = []
        for strategy_id in sorted(self._strategies):
            for version in sorted(self._strategies[strategy_id], key=semver_key):
                strategy = self._strategies[strategy_id][version]
                if lifecycle is None or strategy.lifecycle_state == lifecycle:
                    items.append(strategy)
        return items

    def store_evaluation(self, evaluation: StrategyEvaluation, *, actor: str) -> StrategyEvaluation:
        self._evaluations.setdefault(evaluation.strategy_id, []).append(evaluation)
        strategy = self.get_strategy(evaluation.strategy_id, evaluation.strategy_version)
        updated = strategy.model_copy(
            update={"evaluation_history": list(strategy.evaluation_history) + [evaluation.evaluation_id]}
        )
        self._strategies[strategy.strategy_id][strategy.version] = updated
        self.append_event(
            LearningEventType.STRATEGY_EVALUATED,
            actor=actor,
            subject_id=evaluation.strategy_id,
            subject_version=evaluation.strategy_version,
            payload={"evaluation": evaluation.model_dump(mode="json"), "strategy": updated.model_dump(mode="json")},
            evaluator_version=evaluation.evaluation_version,
        )
        return evaluation

    def store_approval(self, approval: StrategyApprovalDecision, strategy: InvestigationStrategy, *, actor: str) -> None:
        self._approvals.setdefault(strategy.strategy_id, []).append(approval)
        self._strategies[strategy.strategy_id][strategy.version] = strategy
        self.append_event(
            LearningEventType.STRATEGY_APPROVAL_RECORDED,
            actor=actor,
            subject_id=strategy.strategy_id,
            subject_version=strategy.version,
            payload={"approval": approval.model_dump(mode="json"), "strategy": strategy.model_dump(mode="json")},
            policy_id=approval.policy_id,
            policy_version=approval.policy_version,
        )

    def record_outcome(self, outcome: StrategyOutcome, *, actor: str) -> StrategyOutcome:
        if outcome.is_counterfactual:
            self._quarantine[outcome.outcome_id] = outcome
            self.append_event(
                LearningEventType.STRATEGY_OUTCOME_RECORDED,
                actor=actor,
                subject_id=outcome.strategy_id,
                subject_version=outcome.strategy_version,
                payload=outcome.model_dump(mode="json"),
                is_counterfactual=True,
            )
            return outcome
        self._outcomes.setdefault(outcome.strategy_id, []).append(outcome)
        self.append_event(
            LearningEventType.STRATEGY_OUTCOME_RECORDED,
            actor=actor,
            subject_id=outcome.strategy_id,
            subject_version=outcome.strategy_version,
            payload=outcome.model_dump(mode="json"),
        )
        return outcome

    def outcomes_for(self, strategy_id: str, version: Optional[str] = None) -> List[StrategyOutcome]:
        items = list(self._outcomes.get(strategy_id, []))
        if version:
            items = [item for item in items if item.strategy_version == version]
        return items

    def record_regression(self, signal: RegressionSignal, *, actor: str) -> RegressionSignal:
        self._regressions.append(signal)
        if signal.status == "REVIEW_RECOMMENDED":
            strategy = self.get_strategy(signal.strategy_id, signal.strategy_version)
            flagged = strategy.model_copy(update={"regression_status": "REVIEW_RECOMMENDED"})
            self._strategies[strategy.strategy_id][strategy.version] = flagged
        self.append_event(
            LearningEventType.REGRESSION_DETECTED,
            actor=actor,
            subject_id=signal.strategy_id,
            subject_version=signal.strategy_version,
            payload=signal.model_dump(mode="json"),
            threshold_policy_id=signal.threshold_policy_id,
            threshold_policy_version=signal.threshold_policy_version,
        )
        return signal

    def quarantine_branch_experience(self, candidate: CandidateBranchExperience, *, actor: str) -> CandidateBranchExperience:
        if not candidate.is_counterfactual or candidate.promoted_to_authoritative_experience:
            raise BranchExperienceQuarantineError("Branch experience must remain counterfactual and unpromoted.")
        self._quarantine[candidate.candidate_id] = candidate
        self.append_event(
            LearningEventType.BRANCH_EXPERIENCE_QUARANTINED,
            actor=actor,
            subject_id=candidate.candidate_id,
            subject_version=candidate.strategy_version,
            payload=candidate.model_dump(mode="json"),
            is_counterfactual=True,
        )
        return candidate

    def record_failure(self, message: str, *, actor: str, subject_id: str) -> None:
        self.append_event(
            LearningEventType.LEARNING_FAILURE,
            actor=actor,
            subject_id=subject_id,
            payload={"message": message, "authoritative_state_mutated": False},
        )

    def project_learning_graph(self) -> Any:
        """Project learned relationships onto a separate knowledge graph.

        This graph is not a case graph. Counterfactual branch experiences are
        excluded so they cannot leak into authoritative learning structure.
        """
        from cyberclaw.knowledge.edges import KnowledgeEdge
        from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
        from cyberclaw.knowledge.models import EdgeStatus, RelationshipType
        from cyberclaw.knowledge.nodes import KnowledgeNode

        graph = TemporalKnowledgeGraph(
            investigation_id="__learning_registry__",
            case_id="learning",
            is_counterfactual=False,
        )
        stamp = "1970-01-01T00:00:00+00:00"
        from datetime import datetime

        created = datetime.fromisoformat(stamp)

        def add_node(node_id: str, node_type: str, label: str, metadata: Dict[str, Any]) -> None:
            node = KnowledgeNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                created_at=created,
                valid_from=created,
                investigation_id="__learning_registry__",
                case_id="learning",
                provenance_references=[node_id],
                metadata=metadata,
                is_counterfactual=False,
            )
            node.seal()
            graph.add_node(node)

        def add_edge(source: str, target: str, rel: str, learning_relation: str, provenance: List[str]) -> None:
            edge = KnowledgeEdge(
                edge_id=stable_id("ledge", source, target, learning_relation),
                source_node_id=source,
                target_node_id=target,
                relationship_type=rel,
                created_at=created,
                valid_from=created,
                status=EdgeStatus.ACTIVE,
                confidence=0.0,
                epistemic_nature="INFERENCE",
                provenance_ids=provenance,
                investigation_id="__learning_registry__",
                case_id="learning",
                is_counterfactual=False,
                metadata={
                    "learning_relation": learning_relation,
                    "causal_claim": "NONE",
                    "confidence_is_not_objective_truth": True,
                    "confidence_placeholder": 0.0,
                },
            )
            edge.seal()
            graph.add_edge(edge)

        for strategy in self.list_strategies():
            sid = f"strategy:{strategy.strategy_id}:{strategy.version}"
            add_node(
                sid,
                "ARTIFACT",
                strategy.objective_intent,
                {"learning_kind": "STRATEGY", "lifecycle": strategy.lifecycle_state.value, "executable": False},
            )
            pid = f"pattern:{strategy.created_from_pattern_id}:{strategy.created_from_pattern_version}"
            if pid not in graph._nodes:
                add_node(pid, "ARTIFACT", strategy.created_from_pattern_id, {"learning_kind": "PATTERN"})
            add_edge(sid, pid, RelationshipType.DERIVED_FROM.value, "SUPPORTED_BY", [strategy.content_digest])
            context_id = f"context:{strategy.strategy_id}:{strategy.version}"
            add_node(
                context_id,
                "ARTIFACT",
                "applicability",
                {"learning_kind": "CONTEXT", "profile": strategy.applicability.model_dump(mode="json")},
            )
            add_edge(sid, context_id, RelationshipType.RELATED_TO.value, "APPLICABLE_TO", [strategy.content_digest])
            for case_id in strategy.supporting_case_ids:
                inv_node = f"investigation:{case_id}"
                if inv_node not in graph._nodes:
                    add_node(inv_node, "INVESTIGATION", case_id, {"learning_kind": "INVESTIGATION_REFERENCE"})
                add_edge(pid, inv_node, RelationshipType.ASSOCIATED_WITH.value, "OBSERVED_IN", [strategy.content_digest])
                experience = next((exp for exp in self._experiences.values() if exp.investigation_id == case_id), None)
                if experience:
                    for ref in experience.evidence_generated:
                        ev_node = f"evidence:{ref.record_id}"
                        if ev_node not in graph._nodes:
                            add_node(ev_node, "EVIDENCE", ref.record_id, {"learning_kind": "EVIDENCE_REFERENCE"})
                        add_edge(inv_node, ev_node, RelationshipType.GENERATED_BY.value, "GENERATED", [ref.record_id])
            for failure in strategy.known_failures:
                for case_id in strategy.supporting_case_ids:
                    inv_node = f"investigation:{case_id}"
                    if inv_node in graph._nodes:
                        add_edge(sid, inv_node, RelationshipType.RELATED_TO.value, "FAILED_IN", [failure])
                        break
            for outcome in self.outcomes_for(strategy.strategy_id, strategy.version):
                if outcome.success or outcome.is_counterfactual:
                    continue
                inv_node = f"investigation:{outcome.investigation_id}"
                if inv_node not in graph._nodes:
                    add_node(inv_node, "INVESTIGATION", outcome.investigation_id, {"learning_kind": "INVESTIGATION_REFERENCE"})
                add_edge(sid, inv_node, RelationshipType.RELATED_TO.value, "FAILED_IN", [outcome.outcome_id])
        return graph


class LearningReplay:
    """Reconstruct historical learning state from ledger events only."""

    @staticmethod
    def replay_learning_state(
        events: Sequence[LearningEvent],
        until_sequence: Optional[int] = None,
    ) -> ReconstructedLearningState:
        selected = [event for event in events if until_sequence is None or event.sequence <= until_sequence]
        if until_sequence is not None and until_sequence < 0:
            raise LearningReplayError("until_sequence cannot be negative.")
        experiences: Dict[str, Any] = {}
        patterns: Dict[str, Any] = {}
        pattern_versions: Dict[str, Dict[str, Any]] = {}
        strategies: Dict[str, Dict[str, Any]] = {}
        approvals: List[Dict[str, Any]] = []
        evaluations: List[Dict[str, Any]] = []
        policies: Dict[str, Any] = {}
        detector_versions = []
        evaluator_versions = []
        for event in selected:
            if event.detector_version and event.detector_version not in detector_versions:
                detector_versions.append(event.detector_version)
            if event.evaluator_version and event.evaluator_version not in evaluator_versions:
                evaluator_versions.append(event.evaluator_version)
            if event.event_type == LearningEventType.THRESHOLD_POLICY_REGISTERED:
                policies[f"{event.subject_id}@{event.subject_version}"] = event.payload
            elif event.event_type == LearningEventType.EXPERIENCE_EXTRACTED:
                experiences[event.payload.get("experience_id", event.subject_id)] = event.payload
            elif event.event_type == LearningEventType.PATTERN_VERSION_RECORDED:
                pattern_versions.setdefault(event.subject_id, {})[event.subject_version or ""] = event.payload
                patterns[event.subject_id] = event.payload
            elif event.event_type in {
                LearningEventType.STRATEGY_PROPOSED,
                LearningEventType.STRATEGY_LIFECYCLE_TRANSITION,
                LearningEventType.STRATEGY_REVIEWED,
                LearningEventType.STRATEGY_SIMULATED,
                LearningEventType.STRATEGY_EVALUATED,
                LearningEventType.STRATEGY_APPROVAL_RECORDED,
            }:
                strategy_payload = event.payload.get("strategy", event.payload)
                if "strategy_id" in strategy_payload:
                    strategies.setdefault(event.subject_id, {})[event.subject_version or strategy_payload.get("version", "")] = strategy_payload
                if event.event_type == LearningEventType.STRATEGY_APPROVAL_RECORDED:
                    approvals.append(event.payload.get("approval", {}))
                if event.event_type == LearningEventType.STRATEGY_EVALUATED:
                    evaluations.append(event.payload.get("evaluation", {}))
        last = selected[-1].sequence if selected else 0
        return ReconstructedLearningState(
            until_sequence=until_sequence if until_sequence is not None else last,
            experiences=experiences,
            patterns=patterns,
            pattern_versions=pattern_versions,
            strategies=strategies,
            approvals=approvals,
            evaluations=evaluations,
            threshold_policies=policies,
            detector_versions_seen=detector_versions,
            evaluator_versions_seen=evaluator_versions,
            detectors_executed=0,
            evaluators_executed=0,
            providers_executed=0,
        )

    @staticmethod
    def get_strategy_history(events: Sequence[LearningEvent], strategy_id: str) -> List[LearningEvent]:
        return [event for event in events if event.subject_id == strategy_id]

    @staticmethod
    def get_pattern_history(events: Sequence[LearningEvent], pattern_id: str) -> List[LearningEvent]:
        return [event for event in events if event.subject_id == pattern_id]

    @staticmethod
    def explain_strategy_origin(events: Sequence[LearningEvent], strategy_id: str, version: Optional[str] = None) -> StrategyOriginExplanation:
        history = [
            event
            for event in events
            if event.subject_id == strategy_id and (version is None or event.subject_version == version)
        ]
        proposal = next((event for event in history if event.event_type == LearningEventType.STRATEGY_PROPOSED), None)
        if proposal is None and history:
            proposal = history[0]
        if proposal is None:
            raise LearningReplayError(f"No recorded origin for strategy '{strategy_id}'.")
        strategy_payload = proposal.payload.get("strategy", proposal.payload)
        provenance = strategy_payload.get("provenance", {})
        pattern_id = provenance.get("pattern_id") or strategy_payload.get("created_from_pattern_id")
        pattern_events = [event for event in events if event.subject_id == pattern_id] if pattern_id else []
        pattern_payload = pattern_events[-1].payload if pattern_events else {}
        instances = pattern_payload.get("instances") or []
        supporting_cases = sorted({inst.get("investigation_id") for inst in instances if inst.get("investigation_id")})
        supporting_events = sorted({eid for inst in instances for eid in inst.get("supporting_event_ids", [])})
        successful = [inst.get("investigation_id") for inst in instances if inst.get("outcome") == "SUCCESS"]
        contradicting = [inst.get("investigation_id") for inst in instances if inst.get("outcome") == "FAILURE"]
        excluded = pattern_payload.get("excluded") or []
        return StrategyOriginExplanation(
            strategy_id=strategy_id,
            strategy_version=version or strategy_payload.get("version", ""),
            pattern_id=pattern_id,
            pattern_version=provenance.get("pattern_version") or pattern_payload.get("version"),
            supporting_cases=supporting_cases or list(strategy_payload.get("supporting_case_ids") or []),
            supporting_event_ids=supporting_events,
            successful_cases=[item for item in successful if item],
            contradicting_cases=[item for item in contradicting if item],
            excluded=excluded,
            exclusion_reasons=sorted({item.get("reason", "") for item in excluded if item.get("reason")}),
            detector_version=proposal.detector_version or provenance.get("detector_version") or PATTERN_DETECTOR_VERSION,
            threshold_policy_id=proposal.threshold_policy_id,
            threshold_policy_version=proposal.threshold_policy_version,
        )
