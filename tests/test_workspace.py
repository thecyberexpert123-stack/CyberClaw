"""Tests for WorkspaceManager layout, isolation, atomic persistence, and integrity."""

import json
from pathlib import Path
import pytest
from cyberclaw.evidence.models import Evidence
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.types import Source
from cyberclaw.workspace.layout import WorkspaceLayout
from cyberclaw.workspace.manager import WorkspaceAccessError, WorkspaceManager


def test_workspace_layout_creation(tmp_path: Path):
    ws = WorkspaceManager(tmp_path)
    layout = ws.global_layout

    # Verify standard directory structure exists
    assert layout.skills.exists()
    assert layout.workflows.exists()
    assert layout.experiments.exists()
    assert layout.memory.exists()
    assert layout.experience.exists()
    assert layout.evidence.exists()
    assert layout.artifacts.exists()


def test_investigation_workspace_isolation(tmp_path: Path):
    ws = WorkspaceManager(tmp_path)
    inv_a = ws.get_investigation_workspace("case-001")
    inv_b = ws.get_investigation_workspace("case-002")

    assert inv_a.root != inv_b.root
    assert inv_a.evidence.exists()
    assert inv_b.evidence.exists()


def test_workspace_boundary_protection(tmp_path: Path):
    ws = WorkspaceManager(tmp_path)

    # Attempting to write outside workspace base path must raise WorkspaceAccessError
    external_path = tmp_path.parent / "escape.txt"
    with pytest.raises(WorkspaceAccessError):
        ws.atomic_write(external_path, "malicious")

    # Attempting to read outside workspace base path must raise WorkspaceAccessError
    with pytest.raises(WorkspaceAccessError):
        ws.read_text(external_path)


def test_workspace_evidence_and_experience_persistence(tmp_path: Path):
    ws = WorkspaceManager(tmp_path)
    inv_id = "inv-persistence-test"

    # Persist evidence
    ev = Evidence(
        type="finding",
        subject="host-omega",
        value={"cve": "CVE-2024-1234"},
        source=Source(type="scanner", name="VulnScan"),
    )
    ws.persist_evidence(inv_id, [ev])

    # Load evidence back
    loaded_ev = ws.load_evidence(inv_id)
    assert len(loaded_ev) == 1
    assert loaded_ev[0].id == ev.id
    assert loaded_ev[0].subject == "host-omega"
    assert loaded_ev[0].value == {"cve": "CVE-2024-1234"}

    # Persist experience
    exp = ExperienceRecord(
        action="execute:test",
        result_status="success",
        success=True,
        lesson="Tested persistence successfully.",
    )
    ws.persist_experience(inv_id, [exp])

    # Load experience back
    loaded_exp = ws.load_experience(inv_id)
    assert len(loaded_exp) == 1
    assert loaded_exp[0].id == exp.id
    assert loaded_exp[0].lesson == "Tested persistence successfully."
