"""End-to-end capability lifecycle, governance, degradation, and historical replay test matching Section 27."""

from pathlib import Path
import pytest
from cyberclaw.capabilities.bridge import CapabilityBridge
from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.governance import CapabilityGovernance
from cyberclaw.capabilities.models import (
    CapabilityHealth,
    CapabilityLifecycleState,
    CapabilityProvenance,
    CapabilityTrustState,
    CapabilityValidationRecord,
)
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.permissions.policy import ActionScope
from cyberclaw.planning.models import CapabilityGap
from cyberclaw.replay.engine import ReplayEngine
from cyberclaw.types import Source


class SimulatedCertProvider(CapabilityProvider):
    def __init__(self, capability_id: str):
        super().__init__(id="provider.sim_cert_v1", name="Simulated Cert Provider", capability_id=capability_id)
        self.is_failing = False

    def is_ready(self, context: ExecutionContext):
        if self.is_failing:
            return False, "Certificate transparency API rate limit exceeded"
        return True, None

    def execute(self, parameters, context):
        if self.is_failing:
            return ExecutionResult.failure(error="Provider connection timeout")
        ev = Evidence(
            type="cert_transparency_log",
            subject=parameters.get("domain", "apex.org"),
            value={"issuer": "GlobalSign", "san": ["api.apex.org", "vpn.apex.org"]},
            source=Source(type="ct_log", name="ct_monitor"),
        )
        return ExecutionResult.success(output={"status": "ok"}, evidence=[ev])


def test_section_27_complete_capability_lifecycle_scenario(tmp_path: Path):
    """Execute complete Section 27 full lifecycle capability governance scenario."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Grant required permissions to system actor
    core.permissions.grant_permission("core.system", "capability:cert_enum")

    # 1. CapabilityGap observed during planning
    gap = CapabilityGap(
        investigation_id="inv-sec-27",
        target_or_entity="apex.org",
        desired_evidence_type="cert_transparency_log",
        reason="Need certificate transparency data to map subdomains",
    )

    # 2. Candidate Capability formulated from Gap
    candidate = CapabilityBridge.candidate_from_gap(
        gap=gap,
        proposed_capability_id="capability.osint.cert_transparency_enum",
        name="Certificate Transparency Enumerator",
        description="Queries public CT logs for domain certificates",
        action_scope=ActionScope.CONSEQUENTIAL,
        required_permissions=["capability:cert_enum"],
    )

    # 3. Materialize candidate into PROPOSED capability
    cap = CapabilityBridge.realize_candidate(candidate)
    assert cap.lifecycle_state == CapabilityLifecycleState.PROPOSED
    assert cap.trust_state == CapabilityTrustState.UNTRUSTED

    # 4. Formal Validation assessment
    val_rec = CapabilityValidationRecord(
        capability_id=cap.id,
        capability_version=cap.version,
        validator="qa.automated_sandbox",
        tests_performed=["schema_test", "mock_network_test"],
        result="PASSED",
    )
    CapabilityGovernance.validate_capability(cap, val_rec, actor="qa.automated_sandbox")
    assert cap.lifecycle_state == CapabilityLifecycleState.VALIDATED

    # 5. Explicit Approval
    CapabilityGovernance.approve_capability(
        capability=cap,
        approver="security.director",
        rationale="Approved for production OSINT usage following sandbox validation",
        target_state=CapabilityLifecycleState.AVAILABLE,
        trust_state=CapabilityTrustState.TRUSTED_WITH_SCOPE,
    )
    assert cap.lifecycle_state == CapabilityLifecycleState.AVAILABLE
    assert cap.trust_state == CapabilityTrustState.TRUSTED_WITH_SCOPE

    # 6. Capability & Provider Registration
    core.register_capability(cap)
    provider = SimulatedCertProvider(cap.id)
    core.register_provider(provider)

    # 7. Health Check -> HEALTHY
    assert core.get_capability_health(cap.id) == CapabilityHealth.HEALTHY

    # 8. Investigation setup & Authorized Execution
    inv = core.create_investigation("APT Infrastructure Mapping", "Section 27 Verification")
    core.transition_investigation(inv.id, CoreState.INVESTIGATE, event="start_recon")

    res = core.execute_action(
        investigation_id=inv.id,
        capability_id=cap.id,
        parameters={"domain": "apex.org"},
        actor="core.system",
        scope=ActionScope.CONSEQUENTIAL,
    )
    assert res.is_success is True
    assert len(res.evidence) == 1
    assert inv.evidence_store.count() == 1

    # Capture snapshot with successful execution
    snap_1 = inv.capture_snapshot(trigger="post_ct_execution")

    # 9. Provider failure -> Capability becomes DEGRADED / UNAVAILABLE
    provider.is_failing = True
    assert core.get_capability_health(cap.id) == CapabilityHealth.UNAVAILABLE

    # 10. Capability disabled for remediation
    core.disable_capability(cap.id, actor="core.admin", rationale="Provider failing due to upstream API limits")
    assert cap.lifecycle_state == CapabilityLifecycleState.DISABLED

    # Verify disabled capability cannot execute
    ctx = ExecutionContext()
    res_blocked = core.capabilities.execute_capability(cap.id, {"domain": "apex.org"}, ctx)
    assert res_blocked.is_failure is True
    assert res_blocked.error_code == "CAPABILITY_UNAVAILABLE"

    # 11. Capability revalidated and re-enabled
    provider.is_failing = False
    core.enable_capability(cap.id, actor="core.admin", rationale="API quota restored")
    assert cap.lifecycle_state == CapabilityLifecycleState.AVAILABLE
    assert core.get_capability_health(cap.id) == CapabilityHealth.HEALTHY

    # 12. Capability deprecated
    core.deprecate_capability(cap.id, actor="core.admin", rationale="Migration to CTLogProviderV2 planned")
    assert cap.lifecycle_state == CapabilityLifecycleState.DEPRECATED

    # 13. Capability retired
    core.retire_capability(cap.id, actor="core.admin", rationale="Decommissioned; superseded by v2")
    assert cap.lifecycle_state == CapabilityLifecycleState.RETIRED

    # Verify retired capability cannot execute
    res_retired = core.capabilities.execute_capability(cap.id, {"domain": "apex.org"}, ctx)
    assert res_retired.is_failure is True
    assert res_retired.error_code == "CAPABILITY_UNAVAILABLE"

    # 14. Replay the original investigation: historical execution and metadata remain intact
    recon = core.replay_investigation(inv.id, until_snapshot=snap_1.sequence)
    assert len(recon.evidence) == 1
    assert recon.evidence[0].type == "cert_transparency_log"
    assert recon.dfa_state == CoreState.INVESTIGATE.value

    # Verify live case remains immutable
    assert inv.evidence_store.count() == 1
