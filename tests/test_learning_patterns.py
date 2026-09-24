"""Pattern detection, source independence, and false-correlation prevention."""

from __future__ import annotations

from pathlib import Path

from cyberclaw.core import CyberClawCore
from cyberclaw.learning.models import PatternKind, PatternScope
from tests.learning_support import build_completed_investigation


def _ingest_pair(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    first = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    second = build_completed_investigation(
        core, family="fam-b", target="subject-b", source_id="src-b", with_retry=True
    )
    core.ingest_investigation_experience(first.id)
    core.ingest_investigation_experience(second.id)
    return core, first, second


def test_repeated_success_requires_independent_cases(tmp_path: Path):
    core, first, second = _ingest_pair(tmp_path)
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_SUCCESS)
    assert pattern.scope == PatternScope.VALIDATED
    assert pattern.success_count == 2
    assert pattern.independent_case_count == 2
    assert pattern.independent_source_family_count == 2
    assert pattern.causal_claim == "NONE"
    assert "does not mean the regularity always works" in pattern.description
    assert {first.id, second.id} == {inst.investigation_id for inst in pattern.instances}


def test_repeated_failure_is_correlation_not_causation(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    first = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a", failing=True)
    second = build_completed_investigation(core, family="fam-b", target="subject-b", source_id="src-b", failing=True)
    core.ingest_investigation_experience(first.id)
    core.ingest_investigation_experience(second.id)
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_FAILURE)
    assert pattern.failure_count == 2
    assert pattern.causal_claim == "NONE"
    assert pattern.scope != PatternScope.VALIDATED
    failure = next(iter(core.learning._failure_patterns.values()))
    assert failure.causal_claim == "NONE"
    assert "not a causal explanation" in failure.statement
    assert failure.preceding_actions


def test_collaboration_and_capability_sequences_are_detected(tmp_path: Path):
    core, _, _ = _ingest_pair(tmp_path)
    collab = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.SPECIALIST_COLLABORATION_PATTERN)
    caps = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.CAPABILITY_SEQUENCE_PATTERN)
    assert collab.specialist_sequence == ["specialist.alpha", "specialist.beta"]
    assert caps.capability_sequence == ["cap.observe", "cap.corroborate"]
    assert caps.algorithm == "signature_equality_v0.1"
    assert caps.algorithm_parameters["fuzzy_matching"] is False
    stored = next(iter(core.learning._collaboration_patterns.values()))
    assert stored.hidden_channel is False
    assert "Runtime" in stored.execution_path


def test_contradiction_resolution_pattern_corroborates_nonidentical_cases(tmp_path: Path):
    core, first, second = _ingest_pair(tmp_path)
    pattern = next(
        item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_CONTRADICTION_RESOLUTION
    )
    assert pattern.scope == PatternScope.VALIDATED
    assert pattern.signature == "contradiction_resolved:competing_claims"
    assert {first.id, second.id} <= {inst.investigation_id for inst in pattern.instances}
    assert first.id != second.id


def test_same_source_family_does_not_inflate_independence(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    for index in range(4):
        inv = build_completed_investigation(
            core,
            family="template-42",
            target=f"subject-{index}",
            source_id=f"src-{index}",
        )
        core.ingest_investigation_experience(inv.id)
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_SUCCESS)
    assert pattern.sample_count == 4
    assert pattern.independent_case_count == 4
    assert pattern.independent_source_family_count == 1
    assert pattern.scope == PatternScope.CASE_LOCAL
    assert pattern.confidence.band.value == "INSUFFICIENT"
    assert pattern.confidence.single_score_is_objective_truth is False
    assert "independent_source_family_count=1" in pattern.confidence.explanation
    assert core.learning.list_strategies() == []


def test_shared_upstream_source_collapses_declared_families(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    first = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="shared-feed")
    second = build_completed_investigation(core, family="fam-b", target="subject-b", source_id="shared-feed")
    core.ingest_investigation_experience(first.id)
    core.ingest_investigation_experience(second.id)
    pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.CAPABILITY_SEQUENCE_PATTERN)
    assert pattern.independent_case_count == 2
    assert pattern.independent_source_family_count == 1
    assert pattern.scope == PatternScope.CASE_LOCAL


def test_pattern_detection_does_not_create_a_strategy(tmp_path: Path):
    core, _, _ = _ingest_pair(tmp_path)
    assert any(item.scope == PatternScope.VALIDATED for item in core.learning.list_patterns())
    assert core.learning.list_strategies() == []


def test_counterfactual_cases_are_excluded_from_pattern_counts(tmp_path: Path):
    core, _, _ = _ingest_pair(tmp_path)
    before = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_SUCCESS).sample_count
    ghost = build_completed_investigation(core, family="fam-z", target="subject-z", source_id="src-z")
    ghost.metadata["is_counterfactual"] = True
    ghost.metadata["branch_id"] = "branch-z"
    result = core.ingest_investigation_experience(ghost.id)
    after = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.REPEATED_SUCCESS)
    assert result.quarantined is True
    assert after.sample_count == before
    assert any(item.reason.startswith("COUNTERFACTUAL") for item in after.excluded) or result.experience.is_counterfactual


def test_detector_and_threshold_versions_are_recorded(tmp_path: Path):
    core, _, _ = _ingest_pair(tmp_path)
    pattern = core.learning.list_patterns()[0]
    assert pattern.detector_version == "0.1.0"
    assert pattern.threshold_policy_id == "default-learning-thresholds"
    assert pattern.threshold_policy_version == "0.1.0"
    assert pattern.confidence.threshold_policy_version == "0.1.0"


def test_stopping_and_evidence_yield_patterns_are_structural(tmp_path: Path):
    core, _, _ = _ingest_pair(tmp_path)
    stopping = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.STOPPING_PATTERN)
    yield_pattern = next(item for item in core.learning.list_patterns() if item.kind == PatternKind.EVIDENCE_YIELD_PATTERN)
    assert stopping.signature.startswith("stop:OBJECTIVE_SATISFIED")
    assert yield_pattern.signature.startswith("yield:")
    assert yield_pattern.causal_claim == "NONE"
