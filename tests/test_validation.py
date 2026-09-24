"""Tests for ValidationPipeline ensuring multi-phase contract enforcement."""

import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.types import Source
from cyberclaw.validation.errors import (
    PolicyValidationError,
    ResultValidationError,
    SchemaValidationError,
    StateValidationError,
)
from cyberclaw.validation.pipeline import ValidationPipeline


def test_validation_pipeline_schema():
    cap = Capability(
        id="test.schema",
        name="Schema Test",
        input_schema={
            "required": ["domain", "depth"],
            "properties": {
                "domain": {"type": "string"},
                "depth": {"type": "integer"},
            },
        },
    )

    # Missing parameter
    with pytest.raises(SchemaValidationError) as exc:
        ValidationPipeline.validate_schema(cap, {"domain": "test.com"})
    assert "Missing required parameter 'depth'" in str(exc.value)

    # Wrong parameter type
    with pytest.raises(SchemaValidationError) as exc:
        ValidationPipeline.validate_schema(cap, {"domain": "test.com", "depth": "not_an_int"})
    assert "must be an integer" in str(exc.value)

    # Valid schema passes
    ValidationPipeline.validate_schema(cap, {"domain": "test.com", "depth": 2})


def test_validation_pipeline_dfa_state():
    # Attempting to execute when in FAILED state
    with pytest.raises(StateValidationError) as exc:
        ValidationPipeline.validate_dfa_state(
            current_state=CoreState.FAILED,
            allowed_states=[CoreState.READY, CoreState.INVESTIGATE],
            action_name="run_scan",
        )
    assert "cannot be executed in state 'FAILED'" in str(exc.value)


def test_validation_pipeline_policy():
    pm = PermissionManager()
    cap = Capability(
        id="restricted.cap",
        name="Restricted Cap",
        required_permissions=["restricted:use"],
    )

    # Actor has not been granted restricted:use
    with pytest.raises(PolicyValidationError) as exc:
        ValidationPipeline.validate_permissions(
            capability=cap,
            actor="untrusted_agent",
            permission_manager=pm,
        )
    assert "lacks permission 'restricted:use'" in str(exc.value)


def test_validation_pipeline_result_integrity():
    source = Source(type="unit", name="Unit")
    ev = Evidence(type="finding", subject="host", value="x", source=source)

    # SUCCESS without evidence is invalid
    bad_success = ExecutionResult(status="success", evidence=[])
    with pytest.raises(ResultValidationError):
        ValidationPipeline.validate_result(bad_success)

    # SUCCESS_EMPTY with evidence is invalid
    bad_empty = ExecutionResult(status="success_empty", evidence=[ev])
    with pytest.raises(ResultValidationError):
        ValidationPipeline.validate_result(bad_empty)

    # FAILURE without error message is invalid
    bad_failure = ExecutionResult(status="failure", evidence=[], error=None)
    with pytest.raises(ResultValidationError):
        ValidationPipeline.validate_result(bad_failure)
