"""Evaluation and baseline comparison for experimental skills."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.specialists.self_development.experiment import SkillExperiment


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SkillEvaluation(BaseModel):
    """Formal evaluation artifact measuring experimental skill performance against baseline."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    experiment_id: str
    skill_id: str
    baseline_metrics: Dict[str, Any]
    experimental_metrics: Dict[str, Any]
    differences: Dict[str, Any]
    observed_benefits: List[str] = Field(default_factory=list)
    observed_regressions: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.85, ge=0.0, le=1.0)
    limitations: List[str] = Field(default_factory=list)
    recommendation: str = Field(description="'PROPOSE_PROMOTION', 'RETAIN_EXPERIMENTAL', 'REJECT'")
    created_at: datetime = Field(default_factory=utc_now)


class SkillEvaluator:
    """Evaluates experiment outcomes deterministically comparing against baseline metrics."""

    @classmethod
    def evaluate(
        cls,
        experiment: SkillExperiment,
        min_evidence_threshold: int = 1,
    ) -> SkillEvaluation:
        b_metrics = experiment.baseline_metrics
        e_metrics = experiment.experimental_metrics

        benefits: List[str] = []
        regressions: List[str] = []
        limitations: List[str] = []

        # Compare evidence yields
        b_ev_count = b_metrics.get("evidence_count", 0)
        e_ev_count = e_metrics.get("evidence_count", 0)
        ev_delta = e_ev_count - b_ev_count

        if ev_delta > 0:
            benefits.append(f"Produced {ev_delta} more evidence items than baseline ({e_ev_count} vs {b_ev_count})")
        elif ev_delta < 0:
            regressions.append(f"Produced fewer evidence items than baseline ({e_ev_count} vs {b_ev_count})")

        # Compare execution duration
        b_dur = b_metrics.get("duration_ms", 0.0)
        e_dur = e_metrics.get("duration_ms", 0.0)
        dur_delta = e_dur - b_dur

        if b_dur > 0 and dur_delta > 100.0:
            regressions.append(f"Higher latency than baseline (+{dur_delta:.1f}ms)")
        elif b_dur > 0 and dur_delta < -50.0:
            benefits.append(f"Lower latency than baseline ({dur_delta:.1f}ms)")

        # Compare failure / empty outcomes
        if e_metrics.get("is_failure"):
            regressions.append(f"Experimental execution failed: {experiment.error}")
        if e_metrics.get("is_empty") and not b_metrics.get("is_empty"):
            regressions.append("Experimental execution returned empty results whereas baseline had findings")

        # Determine recommendation
        if e_metrics.get("is_failure"):
            recommendation = "REJECT"
            limitations.append("Execution encountered unhandled failure")
        elif regressions and not benefits:
            recommendation = "REJECT"
            limitations.append("Demonstrated regression relative to baseline")
        elif benefits and not regressions:
            recommendation = "PROPOSE_PROMOTION"
        else:
            # Mixed tradeoffs or equivalent
            recommendation = "RETAIN_EXPERIMENTAL"
            limitations.append("Tradeoffs observed between latency and evidence yield; further experimentation required")

        differences = {
            "evidence_delta": ev_delta,
            "duration_delta_ms": dur_delta,
            "has_benefits": len(benefits) > 0,
            "has_regressions": len(regressions) > 0,
        }

        return SkillEvaluation(
            experiment_id=experiment.id,
            skill_id=experiment.skill_id,
            baseline_metrics=b_metrics,
            experimental_metrics=e_metrics,
            differences=differences,
            observed_benefits=benefits,
            observed_regressions=regressions,
            confidence_score=0.9 if not regressions else 0.6,
            limitations=limitations,
            recommendation=recommendation,
        )
