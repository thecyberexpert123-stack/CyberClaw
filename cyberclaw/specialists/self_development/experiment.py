"""Controlled Experiment Sandbox for testing experimental skills against baselines."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.specialists.self_development.skill import ExperimentalSkill


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SkillExperiment(BaseModel):
    """Artifact recording an execution of an experimental skill alongside baseline comparison."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    skill_id: str
    skill_version: str
    input_context: Dict[str, Any]
    baseline_metrics: Dict[str, Any] = Field(default_factory=dict)
    experimental_metrics: Dict[str, Any] = Field(default_factory=dict)
    evidence_produced: List[Evidence] = Field(default_factory=list)
    success: bool
    is_empty: bool = False
    error: Optional[str] = None
    reproducibility_count: int = 1
    created_at: datetime = Field(default_factory=utc_now)


class ExperimentSandbox:
    """Isolated execution sandbox for testing experimental skills without altering trusted state."""

    def __init__(self, capability_invoker: Callable[[str, Dict[str, Any], ExecutionContext], ExecutionResult]) -> None:
        self.capability_invoker = capability_invoker

    def run_experiment(
        self,
        skill: ExperimentalSkill,
        input_parameters: Dict[str, Any],
        baseline_runner: Optional[Callable[[Dict[str, Any], ExecutionContext], ExecutionResult]] = None,
        context: Optional[ExecutionContext] = None,
    ) -> SkillExperiment:
        """Execute experimental skill steps in isolation, run baseline if provided, and measure."""
        exec_ctx = context or ExecutionContext(
            execution_id=str(uuid4()),
            actor="specialist.experiment_sandbox",
        )

        # 1. Run Baseline (if supplied)
        baseline_metrics: Dict[str, Any] = {}
        if baseline_runner:
            start_b = time.perf_counter()
            base_res = baseline_runner(input_parameters, exec_ctx)
            dur_b = (time.perf_counter() - start_b) * 1000.0
            baseline_metrics = {
                "duration_ms": dur_b,
                "success": base_res.is_success,
                "is_empty": base_res.is_empty,
                "is_failure": base_res.is_failure,
                "evidence_count": len(base_res.evidence),
                "capability_calls": 1,
            }

        # 2. Run Experimental Procedure
        exp_evidence: List[Evidence] = []
        start_exp = time.perf_counter()
        capability_calls = 0
        failure_error: Optional[str] = None
        has_failed = False

        steps = skill.procedure.get("steps", [])
        for step in steps:
            cap_id = step.get("capability_id")
            # Merge step params with input parameters
            params = dict(input_parameters)
            params.update(step.get("parameters", {}))

            capability_calls += 1
            res = self.capability_invoker(cap_id, params, exec_ctx)
            if res.is_failure:
                has_failed = True
                failure_error = res.error
                break
            if res.is_success:
                exp_evidence.extend(res.evidence)

        dur_exp = (time.perf_counter() - start_exp) * 1000.0

        is_empty_res = (not has_failed) and (len(exp_evidence) == 0)
        is_success_res = (not has_failed) and (len(exp_evidence) > 0)

        experimental_metrics = {
            "duration_ms": dur_exp,
            "success": is_success_res,
            "is_empty": is_empty_res,
            "is_failure": has_failed,
            "evidence_count": len(exp_evidence),
            "capability_calls": capability_calls,
        }

        return SkillExperiment(
            skill_id=skill.skill_id,
            skill_version=skill.version,
            input_context=input_parameters,
            baseline_metrics=baseline_metrics,
            experimental_metrics=experimental_metrics,
            evidence_produced=exp_evidence,
            success=is_success_res,
            is_empty=is_empty_res,
            error=failure_error,
        )
