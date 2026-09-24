"""Result representations for CyberClaw capability and specialist execution.

Enforces the explicit distinction between:
1. SUCCESS: Operation executed successfully and produced structured evidence/findings.
2. SUCCESS_EMPTY: Operation executed completely and successfully, but discovered no findings.
3. FAILURE: Operation failed (network error, missing dependency, crash, timeout, permission error).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4
from pydantic import BaseModel, Field

from cyberclaw.evidence.models import Evidence


class ExecutionStatus(str, Enum):
    """Execution status distinguishing successful findings, successful empty results, and failures."""

    SUCCESS = "success"
    SUCCESS_EMPTY = "success_empty"
    FAILURE = "failure"


class ExecutionResult(BaseModel):
    """Standardized result envelope for all capability and specialist executions."""

    execution_id: str = Field(default_factory=lambda: str(uuid4()))
    status: ExecutionStatus
    evidence: List[Evidence] = Field(default_factory=list)
    output: Any = Field(default=None, description="Raw or auxiliary non-evidence output")
    error: Optional[str] = Field(default=None, description="Error message if status is FAILURE")
    error_code: Optional[str] = Field(default=None, description="Machine-readable error category")
    duration_ms: float = Field(default=0.0, ge=0.0)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def is_success(self) -> bool:
        """True if the operation completed successfully with findings."""
        return self.status == ExecutionStatus.SUCCESS

    @property
    def is_empty(self) -> bool:
        """True if the operation completed successfully with zero findings."""
        return self.status == ExecutionStatus.SUCCESS_EMPTY

    @property
    def is_failure(self) -> bool:
        """True if the operation failed."""
        return self.status == ExecutionStatus.FAILURE

    @property
    def completed_normally(self) -> bool:
        """True if operation ran without error (either with findings or empty)."""
        return self.status in (ExecutionStatus.SUCCESS, ExecutionStatus.SUCCESS_EMPTY)

    @classmethod
    def success(
        cls,
        evidence: List[Evidence],
        output: Any = None,
        duration_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Construct a successful result with positive evidence findings."""
        kwargs: Dict[str, Any] = {
            "status": ExecutionStatus.SUCCESS,
            "evidence": evidence,
            "output": output,
            "duration_ms": duration_ms,
            "metadata": metadata or {},
        }
        if execution_id:
            kwargs["execution_id"] = execution_id
        return cls(**kwargs)

    @classmethod
    def success_empty(
        cls,
        output: Any = None,
        duration_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Construct a successful result that confirmed zero findings."""
        kwargs: Dict[str, Any] = {
            "status": ExecutionStatus.SUCCESS_EMPTY,
            "evidence": [],
            "output": output,
            "duration_ms": duration_ms,
            "metadata": metadata or {},
        }
        if execution_id:
            kwargs["execution_id"] = execution_id
        return cls(**kwargs)

    @classmethod
    def failure(
        cls,
        error: str,
        error_code: Optional[str] = None,
        output: Any = None,
        duration_ms: float = 0.0,
        metadata: Optional[Dict[str, Any]] = None,
        execution_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Construct a failure result."""
        kwargs: Dict[str, Any] = {
            "status": ExecutionStatus.FAILURE,
            "evidence": [],
            "output": output,
            "error": error,
            "error_code": error_code,
            "duration_ms": duration_ms,
            "metadata": metadata or {},
        }
        if execution_id:
            kwargs["execution_id"] = execution_id
        return cls(**kwargs)
