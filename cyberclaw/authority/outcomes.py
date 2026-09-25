"""Provider outcome classification.

Classification comes from the execution boundary and explicit error codes.
Message text such as "timeout" is not evidence.
"""

from __future__ import annotations

from typing import Optional

from cyberclaw.authority.models import ProviderOutcome
from cyberclaw.evidence.result import ExecutionResult


_PRE_INVOCATION = {
    "CAPABILITY_NOT_FOUND": ProviderOutcome.PROVIDER_REJECTION,
    "CAPABILITY_UNAVAILABLE": ProviderOutcome.PROVIDER_REJECTION,
    "PROVIDER_NOT_READY": ProviderOutcome.PROVIDER_REJECTION,
    "PROVIDER_REJECTION": ProviderOutcome.PROVIDER_REJECTION,
    "SPECIALIST_NOT_FOUND": ProviderOutcome.PROVIDER_REJECTION,
    "SPECIALIST_CAPABILITY_NOT_FOUND": ProviderOutcome.PROVIDER_REJECTION,
    "CONTRACT_MISMATCH": ProviderOutcome.VALIDATION_FAILURE,
    "VALIDATION_FAILURE": ProviderOutcome.VALIDATION_FAILURE,
}
_AMBIGUOUS_INVOCATION = {
    "PROVIDER_EXECUTION_EXCEPTION",
    "SPECIALIST_INVOCATION_EXCEPTION",
}
_EXPLICIT_RETRYABLE = "PROVIDER_TEMPORARY_FAILURE"


def classify_provider_result(result: Optional[ExecutionResult]) -> ProviderOutcome:
    """Classify a returned provider result. Do not inspect exception text."""
    if result is None or not isinstance(result, ExecutionResult):
        return ProviderOutcome.MALFORMED_RESULT
    code = result.error_code or ""
    if code in _AMBIGUOUS_INVOCATION:
        return ProviderOutcome.PROVIDER_EXECUTION_EXCEPTION
    if code == "MALFORMED_RESULT":
        return ProviderOutcome.MALFORMED_RESULT
    if result.is_success and result.output is None and not result.evidence:
        return ProviderOutcome.MALFORMED_RESULT
    if result.is_empty:
        return ProviderOutcome.SUCCESS_EMPTY
    if result.is_success:
        return ProviderOutcome.SUCCESS
    if code in _PRE_INVOCATION:
        return _PRE_INVOCATION[code]
    if result.is_failure:
        return ProviderOutcome.KNOWN_FAILURE
    return ProviderOutcome.UNKNOWN_EXECUTION_STATE


def explicit_temporary_failure(result: Optional[ExecutionResult]) -> bool:
    """A known temporary failure is an explicit code, not a word in the message."""
    return bool(result is not None and result.error_code == _EXPLICIT_RETRYABLE)
