"""Tests for OSINT Specialist workflows and composite skills."""

from pathlib import Path
import pytest
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.specialists.endpoint import SpecialistRequest
from cyberclaw.specialists.osint.specialist import OSINTSpecialist
from cyberclaw.specialists.osint.workflows.domain_triage import DomainTriageWorkflow


def test_domain_triage_workflow_execution(tmp_path: Path):
    specialist = OSINTSpecialist(workspace_base=tmp_path)

    request = SpecialistRequest(
        investigation_id="inv-workflow-1",
        capability_id="osint.workflow:domain_triage",
        parameters={"target": "example.com"},
        context=ExecutionContext(investigation_id="inv-workflow-1"),
    )

    response = specialist.invoke(request)
    assert response.status.value == "success"
    res = response.result
    assert res.is_success is True

    # Check evidence from all 3 steps was gathered
    evidence_types = {e.type for e in res.evidence}
    assert "osint.domain_metadata" in evidence_types
    assert "osint.dns_record" in evidence_types
    assert "osint.certificate" in evidence_types

    # Check relationships extracted
    relationships = res.output.get("relationships", [])
    assert len(relationships) >= 2
    rel_types = {r["relation_type"] for r in relationships}
    assert "resolves_to_ip" in rel_types
    assert "delegated_to_nameserver" in rel_types

    # Check metadata in response
    assert response.metadata["local_state"] == "COMPLETE"
    assert response.metadata["target_type"] == "domain"


def test_domain_triage_workflow_missing_target(tmp_path: Path):
    workflow = DomainTriageWorkflow()
    ctx = ExecutionContext()
    res = workflow.execute({}, ctx, lambda c, p, ctx: None)
    assert res.is_failure is True
    assert res.error_code == "MISSING_TARGET"
