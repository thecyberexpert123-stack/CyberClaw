"""Tests for Experiment Sandbox execution and environment isolation."""

import pytest
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.self_development.experiment import ExperimentSandbox
from cyberclaw.specialists.self_development.skill import ExperimentalSkill
from cyberclaw.types import Source


def _mock_invoker(cap_id: str, params: dict, ctx: ExecutionContext) -> ExecutionResult:
    if params.get("simulate_failure"):
        return ExecutionResult.failure(error="Simulated provider failure", error_code="ERR_FAIL")
    if params.get("simulate_empty"):
        return ExecutionResult.success_empty()

    ev = Evidence(
        type="test.evidence",
        subject=params.get("target", "domain.test"),
        value={"cap": cap_id},
        source=Source(type="mock", name="invoker"),
    )
    return ExecutionResult.success(evidence=[ev], output={"cap": cap_id})


def test_sandbox_successful_experiment_run():
    sandbox = ExperimentSandbox(capability_invoker=_mock_invoker)

    skill = ExperimentalSkill(
        skill_id="exp.combined_probe",
        purpose="Combined probe test",
        author_origin="osint_specialist",
        hypothesis="Gathers multiple evidence items",
        procedure={
            "steps": [
                {"capability_id": "probe.a"},
                {"capability_id": "probe.b"},
            ]
        },
    )

    experiment = sandbox.run_experiment(
        skill=skill,
        input_parameters={"target": "victim.org"},
    )

    assert experiment.success is True
    assert experiment.is_empty is False
    assert len(experiment.evidence_produced) == 2
    assert experiment.experimental_metrics["capability_calls"] == 2
    assert experiment.experimental_metrics["duration_ms"] >= 0.0


def test_sandbox_empty_result():
    sandbox = ExperimentSandbox(capability_invoker=_mock_invoker)

    skill = ExperimentalSkill(
        skill_id="exp.empty_probe",
        purpose="Empty probe test",
        author_origin="osint_specialist",
        hypothesis="Handles empty results",
        procedure={"steps": [{"capability_id": "probe.empty"}]},
    )

    experiment = sandbox.run_experiment(
        skill=skill,
        input_parameters={"target": "empty.org", "simulate_empty": True},
    )

    assert experiment.success is False
    assert experiment.is_empty is True
    assert len(experiment.evidence_produced) == 0


def test_sandbox_failure_handling():
    sandbox = ExperimentSandbox(capability_invoker=_mock_invoker)

    skill = ExperimentalSkill(
        skill_id="exp.failing_probe",
        purpose="Failure test",
        author_origin="osint_specialist",
        hypothesis="Handles failures safely",
        procedure={"steps": [{"capability_id": "probe.fail"}]},
    )

    experiment = sandbox.run_experiment(
        skill=skill,
        input_parameters={"target": "fail.org", "simulate_failure": True},
    )

    assert experiment.success is False
    assert experiment.error == "Simulated provider failure"
    assert experiment.experimental_metrics["is_failure"] is True


def test_sandbox_isolation_from_trusted():
    sandbox = ExperimentSandbox(capability_invoker=_mock_invoker)

    # Trusted mock baseline runner
    trusted_called = False
    def baseline(params, ctx):
        nonlocal trusted_called
        trusted_called = True
        return ExecutionResult.success(evidence=[], output={"baseline": True})

    skill = ExperimentalSkill(
        skill_id="exp.isolated",
        purpose="Isolation test",
        author_origin="osint_specialist",
        hypothesis="Does not modify baseline",
        procedure={"steps": [{"capability_id": "cap.isolated"}]},
    )

    exp = sandbox.run_experiment(
        skill=skill,
        input_parameters={"target": "iso.org"},
        baseline_runner=baseline,
    )

    assert trusted_called is True
    assert "duration_ms" in exp.baseline_metrics
    assert exp.skill_id == "exp.isolated"
