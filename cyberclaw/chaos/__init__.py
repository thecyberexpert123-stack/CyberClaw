"""Deterministic adversarial invariant and chaos validation.

The framework injects controlled failures and checks architectural boundaries.
It does not execute shells, open networks, approve strategies, or mutate policy.
"""

from cyberclaw.chaos.corruption import classify_text
from cyberclaw.chaos.errors import ChaosError, ChaosSecurityError
from cyberclaw.chaos.faults import FaultInjector, assert_fault_is_safe
from cyberclaw.chaos.invariants import InvariantContext, InvariantRegistry
from cyberclaw.chaos.models import ChaosReport, FaultSpec, FaultType
from cyberclaw.chaos.persistence import ChaosReportStore
from cyberclaw.chaos.reports import render_text
from cyberclaw.chaos.runner import CRASH_BOUNDARIES, ChaosRunner, simulate_boundary_crash
from cyberclaw.chaos.scheduler import DeterministicInterleaver

__all__ = [
    "CRASH_BOUNDARIES",
    "ChaosError",
    "ChaosReport",
    "ChaosReportStore",
    "ChaosRunner",
    "ChaosSecurityError",
    "DeterministicInterleaver",
    "FaultInjector",
    "FaultSpec",
    "FaultType",
    "InvariantContext",
    "InvariantRegistry",
    "assert_fault_is_safe",
    "classify_text",
    "render_text",
    "simulate_boundary_crash",
]
