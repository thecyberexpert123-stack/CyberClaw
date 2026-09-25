"""Structured chaos reports. A failure must be diagnosable."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Optional

from cyberclaw.chaos.models import ChaosReport, DigestBundle, FaultSpec, InvariantResult, TraceEvent


def structural_digest(parts: Dict[str, Any]) -> str:
    """Equivalence digest over scenario structure, excluding wall-clock stamps and generated UUIDs."""
    raw = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def bundle_from_parts(parts: Dict[str, Any]) -> DigestBundle:
    return DigestBundle(
        case_state=str(parts.get("case_state", "")),
        journal=str(parts.get("journal", "")),
        snapshots=str(parts.get("snapshots", "")),
        runtime=str(parts.get("runtime", "")),
        knowledge_graph=str(parts.get("knowledge_graph", "")),
        branch=str(parts.get("branch", "")),
        learning=str(parts.get("learning", "")),
        structural=structural_digest(parts),
    )


def build_report(
    scenario_id: str,
    seed: int,
    faults: List[FaultSpec],
    trace: List[TraceEvent],
    invariants: List[InvariantResult],
    expected: Dict[str, Any],
    observed: Dict[str, Any],
    recovery: Optional[Dict[str, Any]] = None,
    replay: Optional[Dict[str, Any]] = None,
    digests: Optional[DigestBundle] = None,
    replay_digest: Optional[DigestBundle] = None,
    recovery_digest: Optional[DigestBundle] = None,
    branch_digest: str = "",
) -> ChaosReport:
    violations = [item.invariant_id for item in invariants if not item.passed]
    comparison = {
        "structural": digests.structural if digests else "",
        "replay_structural": replay_digest.structural if replay_digest else "",
        "recovery_structural": recovery_digest.structural if recovery_digest else "",
        "branch": branch_digest,
        "match_note": "Structural digests exclude wall-clock timestamps and generated identifiers.",
    }
    return ChaosReport(
        scenario_id=scenario_id,
        seed=seed,
        injected_faults=faults,
        execution_trace=trace,
        invariant_results=invariants,
        expected_state=expected,
        observed_state=observed,
        recovery_result=recovery or {},
        replay_result=replay or {},
        digest_comparison=comparison,
        boundary_violations=violations,
        final_digest=digests or DigestBundle(),
        replay_digest=replay_digest or DigestBundle(),
        recovery_digest=recovery_digest or DigestBundle(),
        branch_digest=branch_digest,
        passed=not violations,
    )


def render_text(report: ChaosReport) -> str:
    lines = [
        f"Scenario: {report.scenario_id}",
        f"Seed: {report.seed}",
        "Injected Faults:",
    ]
    if not report.injected_faults:
        lines.append("  (none)")
    for fault in report.injected_faults:
        lines.append(f"  - {fault.fault_id} {fault.fault_type.value} target={fault.target}")
    lines.append("Execution Trace:")
    for event in report.execution_trace:
        lines.append(f"  {event.sequence}. {event.action} {event.detail}".rstrip())
    lines.append("Invariant Results:")
    for item in report.invariant_results:
        status = "PASS" if item.passed else "FAIL"
        lines.append(f"  {status} {item.invariant_id}: {item.what_happened}")
        if not item.passed:
            lines.append(f"    expected: {item.expected}")
            lines.append(f"    observed: {item.observed}")
            lines.append(f"    boundary: {item.boundary}")
    lines.append(f"Expected State: {json.dumps(report.expected_state, sort_keys=True, default=str)}")
    lines.append(f"Observed State: {json.dumps(report.observed_state, sort_keys=True, default=str)}")
    lines.append(f"Recovery Result: {json.dumps(report.recovery_result, sort_keys=True, default=str)}")
    lines.append(f"Replay Result: {json.dumps(report.replay_result, sort_keys=True, default=str)}")
    lines.append(f"Digest Comparison: {json.dumps(report.digest_comparison, sort_keys=True)}")
    lines.append("Boundary Violations: " + (", ".join(report.boundary_violations) or "(none)"))
    return "\n".join(lines)
