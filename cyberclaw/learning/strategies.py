"""Strategy construction and lifecycle. Strategies propose intent; they do not execute."""

from __future__ import annotations

import json
from typing import List, Sequence

from cyberclaw.learning.errors import (
    ExecutableStrategyRejectedError,
    InvalidStrategyTransitionError,
    PatternNotValidatedError,
)
from cyberclaw.learning.models import (
    FORBIDDEN_EXECUTABLE_FRAGMENTS,
    STRATEGY_SCHEMA_VERSION,
    ApplicabilityProfile,
    InvestigationExperience,
    InvestigationStrategy,
    ObservedPattern,
    PatternKind,
    PatternScope,
    PromotionThresholdPolicy,
    StepKind,
    StrategyLifecycle,
    StrategyRiskProfile,
    StrategyStep,
    canonical_digest,
    stable_id,
)
from cyberclaw.learning.normalization import objective_tokens


def assert_not_executable(payload: object) -> None:
    blob = json.dumps(payload, default=str, sort_keys=True).lower()
    for fragment in FORBIDDEN_EXECUTABLE_FRAGMENTS:
        if fragment.lower() in blob:
            raise ExecutableStrategyRejectedError(
                f"Learned strategy rejected because it contains forbidden executable fragment '{fragment}'.",
                details={"fragment": fragment},
            )
    if isinstance(payload, dict):
        for key in ("code", "script", "command", "python", "shell", "executable_code"):
            if payload.get(key):
                raise ExecutableStrategyRejectedError(
                    f"Learned strategy rejected because field '{key}' would carry executable content."
                )


class StrategyLifecycleMachine:
    """Deterministic lifecycle. PROPOSED cannot become AVAILABLE or APPROVED directly."""

    @staticmethod
    def assert_transition(current: StrategyLifecycle, target: StrategyLifecycle) -> None:
        from cyberclaw.learning.models import ALLOWED_LIFECYCLE_TRANSITIONS

        allowed = ALLOWED_LIFECYCLE_TRANSITIONS.get(current, set())
        if target not in allowed:
            raise InvalidStrategyTransitionError(
                f"Cannot transition strategy from {current.value} to {target.value}.",
                details={"current": current.value, "target": target.value},
            )


class StrategyBuilder:
    """Build an immutable strategy proposal from a validated pattern."""

    @classmethod
    def propose(
        cls,
        pattern: ObservedPattern,
        experiences: Sequence[InvestigationExperience],
        proposer_id: str,
        policy: PromotionThresholdPolicy,
    ) -> InvestigationStrategy:
        if pattern.scope != PatternScope.VALIDATED:
            raise PatternNotValidatedError(
                f"Pattern '{pattern.pattern_id}' scope is {pattern.scope.value}; "
                "patterns do not become strategies until validated across independent cases.",
                details={"pattern_id": pattern.pattern_id, "scope": pattern.scope.value},
            )
        if pattern.confidence.single_score_is_objective_truth:
            raise PatternNotValidatedError("Pattern confidence illegally claims objective truth.")
        by_id = {exp.experience_id: exp for exp in experiences}
        members = [by_id[inst.experience_id] for inst in pattern.instances if inst.experience_id in by_id]
        successes = [exp for exp in members if exp.outcome.value == "SUCCESS"]
        basis = successes or members
        required_caps = sorted(set.intersection(*[set(exp.capabilities_used) for exp in basis])) if basis else []
        if not required_caps and pattern.capability_sequence:
            required_caps = list(pattern.capability_sequence)
        permissions = sorted(
            {
                decision.get("policy_id")
                for exp in basis
                for decision in exp.policy_decisions
                if decision.get("policy_id")
            }
        )
        # Permissions are actor permissions, not policy ids. Record observed permission scopes separately.
        observed_permissions = sorted(
            {
                str(outcome["permission"])
                for exp in basis
                for outcome in exp.authorization_outcomes
                if outcome.get("permission")
            }
        )
        gap_structure = sorted({utype for exp in basis for utype in exp.uncertainty_types})
        if pattern.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION and "CONTRADICTION_RESOLUTION" not in gap_structure:
            gap_structure = sorted(set(gap_structure) | {"CONTRADICTION_RESOLUTION", "CONTRADICTED"})
        evidence_chars = sorted({etype for exp in basis for etype in exp.evidence_types})
        stages = sorted({exp.case_stage for exp in basis if exp.case_stage})
        specialists = sorted({spec for exp in basis for spec in exp.specialists_involved})
        tokens = sorted({token for exp in basis for token in objective_tokens(exp.objective)})
        failure_conditions = sorted({f.get("error") or "unspecified_failure" for exp in members for f in exp.failures})
        exclusions = sorted({exp.case_stage or "" for exp in members if exp.outcome.value == "FAILURE"} - {""})
        profile = ApplicabilityProfile(
            investigation_objectives=sorted({exp.objective for exp in basis if exp.objective}),
            objective_tokens=tokens,
            information_gap_structure=gap_structure,
            available_capabilities_observed=sorted({cap for exp in basis for cap in exp.capabilities_used}),
            specialist_roles_observed=specialists,
            authorization_requirements=observed_permissions,
            case_stages=stages,
            evidence_characteristics=evidence_chars,
            uncertainty_characteristics=gap_structure,
            applicable_contexts=[
                "matching information-gap structure",
                "required capabilities available",
                "policy authorization still required at execution time",
            ],
            known_exclusions=exclusions,
            required_capabilities=required_caps,
            required_permissions=observed_permissions,
            known_failure_conditions=failure_conditions,
            similarity_algorithm=policy.similarity_algorithm,
            similarity_parameters=dict(policy.similarity_parameters),
        )
        steps = cls._steps(pattern, required_caps, specialists)
        risk = StrategyRiskProfile(
            structural_factors=[
                f"required_capabilities={len(required_caps)}",
                f"specialist_dependencies={len(specialists)}",
                f"known_failure_conditions={len(failure_conditions)}",
                "strategy_does_not_execute_itself",
            ]
        )
        content = {
            "schema_version": STRATEGY_SCHEMA_VERSION,
            "pattern_id": pattern.pattern_id,
            "pattern_version": pattern.version,
            "objective": pattern.description,
            "steps": [step.model_dump(mode="json") for step in steps],
            "required_capabilities": required_caps,
            "required_permissions": observed_permissions,
        }
        digest = canonical_digest(content)
        strategy = InvestigationStrategy(
            strategy_id=stable_id("strategy", pattern.pattern_id, pattern.version, digest),
            version="1.0.0",
            lifecycle_state=StrategyLifecycle.PROPOSED,
            objective_intent=cls._objective(pattern),
            steps=steps,
            proposer_id=proposer_id,
            provenance={
                "pattern_id": pattern.pattern_id,
                "pattern_version": pattern.version,
                "detector_version": pattern.detector_version,
                "threshold_policy_id": policy.policy_id,
                "threshold_policy_version": policy.version,
                "supporting_experience_ids": [exp.experience_id for exp in members],
                "causal_claim": "NONE",
            },
            applicability=profile,
            required_capabilities=required_caps,
            required_permissions=observed_permissions,
            risk_profile=risk,
            supporting_pattern_ids=[pattern.pattern_id],
            supporting_pattern_versions={pattern.pattern_id: pattern.version},
            supporting_case_ids=sorted({exp.investigation_id for exp in members}),
            known_failures=failure_conditions,
            created_from_pattern_id=pattern.pattern_id,
            created_from_pattern_version=pattern.version,
            executable=False,
            content_digest=digest,
            metadata={"permissions_are_not_policy_ids": permissions},
        )
        assert_not_executable(strategy.model_dump(mode="json"))
        return strategy

    @staticmethod
    def _objective(pattern: ObservedPattern) -> str:
        if pattern.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION:
            return "Resolve contradictory evidence without treating correlation as causation."
        if pattern.kind == PatternKind.REPEATED_FAILURE:
            return "Avoid repeating a historically failing sequence unless new evidence justifies it."
        if pattern.kind == PatternKind.SPECIALIST_COLLABORATION_PATTERN:
            return "Coordinate specialists through governed collaboration, not a hidden channel."
        return "Address a recurring information gap using a governed capability sequence."

    @staticmethod
    def _steps(
        pattern: ObservedPattern,
        capabilities: Sequence[str],
        specialists: Sequence[str],
    ) -> List[StrategyStep]:
        if pattern.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION:
            return [
                StrategyStep(
                    order=1,
                    step_kind=StepKind.IDENTIFY_CONFLICTING_CLAIMS,
                    intent="Identify conflicting claims recorded in authoritative case history.",
                    expected_evidence_characteristics=["contradiction_record"],
                    notes="Observation of a conflict is not a resolution.",
                ),
                StrategyStep(
                    order=2,
                    step_kind=StepKind.CLASSIFY_TEMPORAL_DISAGREEMENT,
                    intent="Determine whether the disagreement is temporal, simultaneous, or unresolved.",
                    notes="Temporal change is not the same as a true contradiction.",
                ),
                StrategyStep(
                    order=3,
                    step_kind=StepKind.REQUEST_INDEPENDENT_EVIDENCE,
                    intent="Request an independent evidence source through Runtime, PolicyEngine, and capability governance.",
                    requested_capability_id=capabilities[0] if capabilities else None,
                    required_capability_classes=list(capabilities),
                    expected_evidence_characteristics=["independent_source"],
                ),
                StrategyStep(
                    order=4,
                    step_kind=StepKind.REEVALUATE_CONSENSUS,
                    intent="Re-evaluate consensus using source-independent evidence. Do not treat agreement as proof.",
                ),
                StrategyStep(
                    order=5,
                    step_kind=StepKind.REPLAN_IF_UNRESOLVED,
                    intent="Replan if the contradiction remains. Do not force a winner.",
                ),
            ]
        steps: List[StrategyStep] = [
            StrategyStep(
                order=1,
                step_kind=StepKind.IDENTIFY_INFORMATION_GAP,
                intent="Identify the current information gap from the knowledge graph and open requirements.",
            )
        ]
        order = 2
        for capability in capabilities:
            steps.append(
                StrategyStep(
                    order=order,
                    step_kind=StepKind.REQUEST_AUTHORIZED_CAPABILITY,
                    intent=(
                        f"Request authorized execution of capability '{capability}' through the Runtime. "
                        "This step is a proposal, not an invocation."
                    ),
                    requested_capability_id=capability,
                    required_capability_classes=[capability],
                    expected_evidence_characteristics=["evidence_produced"],
                )
            )
            order += 1
        if len(specialists) >= 2:
            steps.append(
                StrategyStep(
                    order=order,
                    step_kind=StepKind.HANDOFF_THROUGH_COLLABORATION,
                    intent=(
                        "Hand off through the Collaboration subsystem. "
                        "Do not open a hidden specialist channel."
                    ),
                    notes="participants=" + ">".join(specialists),
                )
            )
            order += 1
        steps.append(
            StrategyStep(
                order=order,
                step_kind=StepKind.REEVALUATE_CONSENSUS,
                intent="Re-evaluate hypotheses and requirements after authorized evidence is ingested.",
            )
        )
        return steps
