"""Tests for case persistence, disk reconstitution, and long-horizon audit reproducibility."""

from pathlib import Path
import pytest
from cyberclaw.capabilities.capability import Capability
from cyberclaw.case.models import DecisionType
from cyberclaw.core import CyberClawCore
from cyberclaw.dfa.states import CoreState
from cyberclaw.evidence.models import Evidence, Provenance
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.types import Source


class MockPersistentEndpoint(SpecialistEndpoint):
    def health(self) -> SpecialistHealth:
        return SpecialistHealth.HEALTHY

    def invoke(self, request: SpecialistRequest) -> SpecialistResponse:
        ev = Evidence(
            type="osint.cert_metadata",
            subject="persisted.target",
            value={"san": "api.persisted.target", "issuer": "Audit Authority"},
            source=Source(type="mock_cert", name="cert_auditor"),
            provenance=Provenance(specialist_id="mock_specialist", execution_id=request.request_id),
            confidence=0.98,
        )
        return SpecialistResponse.from_result("mock_specialist", request.request_id, ExecutionResult.success(evidence=[ev]))


def test_full_case_persistence_and_reconstitution(tmp_path: Path):
    """Verify that case state, snapshots, decisions, and journal are durably persisted to disk and reloadable."""
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()

    # Register mock specialist
    mock_spec = Specialist(
        id="mock_specialist",
        name="Mock Specialist",
        capabilities=["osint.cert_metadata"],
        endpoint=MockPersistentEndpoint(),
    )
    core.register_specialist(mock_spec)
    core.register_capability(
        Capability(id="osint.cert_metadata", name="Cert Metadata", description="Cert lookup")
    )

    # 1. Create Investigation
    inv = core.create_investigation(
        title="Durable Case Investigation",
        targets=["persisted.target"],
    )
    inv.add_entity("domain", "persisted.target")

    # Verify initial snapshot was persisted
    snapshots_loaded = core.workspace.load_snapshots(inv.id)
    assert len(snapshots_loaded) >= 1
    assert snapshots_loaded[0].sequence == 1
    assert snapshots_loaded[0].verify_integrity() is True

    # 2. Transition State to INVESTIGATE
    core.transition_investigation(
        investigation_id=inv.id,
        target_state=CoreState.INVESTIGATE,
        event="investigation.start",
    )

    # 3. Create and Fulfill Requirement
    req = core.create_information_requirement(
        investigation_id=inv.id,
        description="Fetch certificate for persisted.target",
        target_or_entity="persisted.target",
        assigned_capability_id="osint.cert_metadata",
    )
    core.fulfill_information_requirement(
        investigation_id=inv.id,
        requirement_id=req.id,
    )

    # 4. Link an experience record
    inv.case_manager.link_experience("exp-global-lesson-42")

    # 5. Persist case
    core._persist_case(inv)

    # Verify directory layout contains snapshots and journal
    inv_ws = core.workspace.get_investigation_workspace(inv.id)
    assert inv_ws.snapshots.exists()
    assert inv_ws.journal.exists()

    # 6. Verify reloading from disk
    disk_snapshots = core.workspace.load_snapshots(inv.id)
    assert len(disk_snapshots) >= 3  # init, transition, requirement fulfilled
    for s in disk_snapshots:
        assert s.verify_integrity() is True

    disk_journal = core.workspace.load_journal(inv.id)
    assert len(disk_journal) >= 3

    disk_decisions = core.workspace.load_decisions(inv.id)
    assert len(disk_decisions) >= 1
    assert any(d.decision_type == DecisionType.REQUIREMENT_RESOLUTION for d in disk_decisions)

    # 7. Verify Case State assembled and explainable
    case_state = core.get_case_state(inv.id)
    assert case_state.current_dfa_state == "INVESTIGATE"
    assert len(case_state.evidence_registry) == 1
    assert "exp-global-lesson-42" in case_state.experience_references

    explanation = core.explain_case_at(inv.id, 1)
    assert explanation["sequence"] == 1
    assert explanation["integrity_valid"] is True

    core.shutdown()
