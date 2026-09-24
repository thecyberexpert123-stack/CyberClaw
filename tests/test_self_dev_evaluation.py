"""Tests for Baseline Comparison and Skill Evaluation artifacts."""

import pytest
from cyberclaw.evidence.models import Evidence
from cyberclaw.specialists.self_development.evaluation import (
    SkillEvaluation,
    SkillEvaluator,
)
from cyberclaw.specialists.self_development.experiment import SkillExperiment
from cyberclaw.types import Source


def test_evaluation_recommends_promotion_on_clear_benefit():
    source = Source(type="mock", name="eval")
    ev1 = Evidence(type="f", subject="t", value="1", source=source)
    ev2 = Evidence(type="f", subject="t", value="2", source=source)

    exp = SkillExperiment(
        skill_id="skill.improved",
        skill_version="0.1.0",
        input_context={"target": "victim.org"},
        baseline_metrics={"duration_ms": 100.0, "evidence_count": 1, "is_failure": False, "is_empty": False},
        experimental_metrics={"duration_ms": 80.0, "evidence_count": 2, "is_failure": False, "is_empty": False},
        evidence_produced=[ev1, ev2],
        success=True,
    )

    evaluation = SkillEvaluator.evaluate(exp)
    assert evaluation.recommendation == "PROPOSE_PROMOTION"
    assert len(evaluation.observed_benefits) >= 1
    assert len(evaluation.observed_regressions) == 0
    assert evaluation.differences["evidence_delta"] == 1


def test_evaluation_recommends_reject_on_regression():
    exp = SkillExperiment(
        skill_id="skill.regressed",
        skill_version="0.1.0",
        input_context={"target": "victim.org"},
        baseline_metrics={"duration_ms": 50.0, "evidence_count": 3, "is_failure": False, "is_empty": False},
        experimental_metrics={"duration_ms": 250.0, "evidence_count": 1, "is_failure": False, "is_empty": False},
        evidence_produced=[],
        success=True,
    )

    evaluation = SkillEvaluator.evaluate(exp)
    assert evaluation.recommendation == "REJECT"
    assert len(evaluation.observed_regressions) >= 1


def test_evaluation_recommends_retain_experimental_on_tradeoffs():
    source = Source(type="mock", name="eval")
    ev = Evidence(type="f", subject="t", value="1", source=source)

    exp = SkillExperiment(
        skill_id="skill.tradeoffs",
        skill_version="0.1.0",
        input_context={"target": "victim.org"},
        # Baseline was faster, but experimental produced more evidence
        baseline_metrics={"duration_ms": 40.0, "evidence_count": 1, "is_failure": False, "is_empty": False},
        experimental_metrics={"duration_ms": 180.0, "evidence_count": 3, "is_failure": False, "is_empty": False},
        evidence_produced=[ev, ev, ev],
        success=True,
    )

    evaluation = SkillEvaluator.evaluate(exp)
    assert evaluation.recommendation == "RETAIN_EXPERIMENTAL"
    assert len(evaluation.observed_benefits) >= 1
    assert len(evaluation.observed_regressions) >= 1
    assert any("Tradeoffs observed" in lim for lim in evaluation.limitations)
