"""Deterministic, test-only fault injection. No shell, network, or external mutation."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.chaos.errors import ChaosSecurityError
from cyberclaw.chaos.models import FaultSpec, FaultType
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.types import Source

FORBIDDEN_FRAGMENTS = (
    "eval(",
    "exec(",
    "compile(",
    "__import__",
    "subprocess",
    "os.system",
    "socket.socket",
    "pty.spawn",
    "bash -c",
    "powershell",
)


def assert_fault_is_safe(spec: FaultSpec) -> None:
    """Refuse faults that would become arbitrary execution."""
    blob = json.dumps(spec.parameters, sort_keys=True, default=str)
    lowered = blob.lower()
    for fragment in FORBIDDEN_FRAGMENTS:
        if fragment in lowered or fragment in blob:
            raise ChaosSecurityError(
                f"Fault '{spec.fault_id}' contains a forbidden executable fragment.",
                details={"fragment": fragment, "fault_type": spec.fault_type.value},
            )


class FaultAudit:
    """Append-only record of injected faults. Not a case journal."""

    def __init__(self) -> None:
        self.applied: List[Dict[str, Any]] = []

    def record(self, spec: FaultSpec, outcome: str) -> None:
        self.applied.append(
            {
                "fault_id": spec.fault_id,
                "fault_type": spec.fault_type.value,
                "target": spec.target,
                "schedule_index": spec.schedule_index,
                "outcome": outcome,
            }
        )

    def digest(self) -> str:
        raw = json.dumps(self.applied, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class FaultInjector:
    """Applies an explicit, ordered fault schedule. The same schedule is reproducible."""

    def __init__(self, faults: Optional[List[FaultSpec]] = None, seed: int = 0) -> None:
        self.seed = seed
        self.faults = list(faults or [])
        for spec in self.faults:
            assert_fault_is_safe(spec)
        self.audit = FaultAudit()
        self._cursor = 0

    def next_fault(self, target: Optional[str] = None) -> Optional[FaultSpec]:
        while self._cursor < len(self.faults):
            spec = self.faults[self._cursor]
            self._cursor += 1
            if target is None or spec.target == target:
                return spec
        return None

    def provider(self, capability_id: str, subject: str = "subject") -> "FaultedProvider":
        return FaultedProvider(self, capability_id=capability_id, subject=subject)


class FaultedProvider(CapabilityProvider):
    """In-process provider whose failures are scheduled. It never opens a socket or shell."""

    def __init__(self, injector: FaultInjector, capability_id: str, subject: str) -> None:
        super().__init__(id=f"chaos.provider.{capability_id}", name="Chaos provider", capability_id=capability_id)
        self.injector = injector
        self.subject = subject
        self.calls = 0
        self.evidence_ids: List[str] = []

    def is_ready(self, context: Optional[ExecutionContext] = None):
        return True, None

    def execute(self, parameters: Dict[str, Any], context: ExecutionContext) -> ExecutionResult:
        self.calls += 1
        spec = self.injector.next_fault(self.capability_id)
        if spec is None:
            evidence = Evidence(
                id=f"ev-{self.capability_id}-{self.calls}",
                type="finding",
                subject=parameters.get("target", self.subject),
                value={"call": self.calls, "status": "observed"},
                source=Source(type="fixture", name=self.id, id=self.id),
            )
            self.evidence_ids.append(evidence.id)
            return ExecutionResult.success([evidence], output={"call": self.calls})
        self.injector.audit.record(spec, "injected")
        kind = spec.fault_type
        if kind in (FaultType.PROVIDER_FAILURE, FaultType.SPECIALIST_FAILURE):
            return ExecutionResult.failure(error="scheduled provider failure", error_code="PROVIDER_FAILURE")
        if kind == FaultType.PARTIAL_RESULT:
            return ExecutionResult.success_empty(output={"partial": True, "complete": False})
        if kind == FaultType.MALFORMED_RESULT:
            return ExecutionResult.failure(error="malformed provider payload", error_code="MALFORMED_RESULT")
        if kind == FaultType.MISSING_EVIDENCE:
            return ExecutionResult.success_empty(output={"status": "ok", "evidence_missing": True})
        if kind == FaultType.TASK_TIMEOUT:
            raise TimeoutError("scheduled task timeout")
        if kind == FaultType.RUNTIME_CRASH or kind == FaultType.WORKER_CRASH:
            raise RuntimeError("scheduled worker crash before result")
        return ExecutionResult.failure(error=f"unhandled fault {kind.value}", error_code=kind.value)
