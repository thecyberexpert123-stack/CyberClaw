"""Complete end-to-end demonstration of the Specialist Self-Development loop.

Validates the complete Definition of Done:
Past Experience
      ↓
Detected Pattern
      ↓
Experimental Skill Proposal
      ↓
Validated Experiment
      ↓
Baseline Comparison
      ↓
Measured Evaluation
      ↓
Promotion Proposal
      ↓
Explicit Policy Approval
      ↓
Trusted Skill Deployed
      ↓
Invoked by Core through SpecialistEndpoint!
"""

from pathlib import Path
import pytest

from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.core import CyberClawCore
from cyberclaw.evidence.models import Evidence
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.specialists.osint.capabilities.definitions import (
    CAPABILITY_CERT_METADATA,
    CAPABILITY_DNS_LOOKUP,
    CAPABILITY_DOMAIN_METADATA,
    get_osint_capabilities,
)
from cyberclaw.specialists.osint.specialist import OSINTSpecialist
from cyberclaw.specialists.self_development.maturity import SkillMaturityState
from cyberclaw.types import Source


def test_complete_self_development_lifecycle(tmp_path: Path):
    core_ws = tmp_path / "core_workspace"
    specialist_ws = tmp_path / "osint_workspace"

    # -------------------------------------------------------------------------
    # 1. Initialize Core and OSINT Specialist
    # -------------------------------------------------------------------------
    core = CyberClawCore(workspace_path=core_ws)
    core.startup()

    specialist = OSINTSpecialist(workspace_base=specialist_ws)
    for cap in get_osint_capabilities():
        core.register_capability(cap)
    core.register_specialist(specialist.as_specialist())

    # -------------------------------------------------------------------------
    # 2. Accumulate Operational Experiences
    # -------------------------------------------------------------------------
    # Simulate past successful operations on domain targets
    dummy_ev = Evidence(type="dummy", subject="target.com", value={}, source=Source(type="mock", name="test"))
    success_res = ExecutionResult.success(evidence=[dummy_ev], output={"status": "ok"})

    for i in range(3):
        specialist.experiences.record_provider_run(
            capability_id=CAPABILITY_DNS_LOOKUP,
            provider_id="mock.osint.dns_lookup",
            target=f"target{i}.com",
            result=success_res,
            conditions={"target_class": "domain", "protocol": "udp"},
        )

    experiences = specialist.experiences.list_all()
    assert len(experiences) >= 3

    # -------------------------------------------------------------------------
    # 3. Detect Reusable Pattern
    # -------------------------------------------------------------------------
    patterns = specialist.self_development.detect_patterns(experiences)
    assert len(patterns) >= 1
    pattern = patterns[0]
    assert pattern.pattern_type.value == "repeated_success"
    assert "osint.execute:mock.osint.dns_lookup" in pattern.action_or_sequence[0]

    # -------------------------------------------------------------------------
    # 4. Propose an Experimental Skill & Validate
    # -------------------------------------------------------------------------
    proposal = specialist.self_development.propose_skill(
        intended_objective="Fast Passive Domain Profiler",
        hypothesis="Executing DNS and TLS cert checks in sequence doubles discovery coverage",
        proposed_procedure={
            "steps": [
                {"capability_id": CAPABILITY_DNS_LOOKUP},
                {"capability_id": CAPABILITY_CERT_METADATA},
            ]
        },
        expected_benefit="Collects both network IPs and TLS SANs in one composite step",
        required_capabilities=[CAPABILITY_DNS_LOOKUP, CAPABILITY_CERT_METADATA],
        required_permissions=["network:read"],
        source_pattern_ids=[pattern.id],
    )
    assert proposal.status == "PROPOSED"

    # -------------------------------------------------------------------------
    # 5. Create Experimental Skill Artifact
    # -------------------------------------------------------------------------
    skill = specialist.self_development.create_experimental_skill(
        skill_id="skill.fast_domain_profiler",
        proposal=proposal,
    )
    assert skill.maturity == SkillMaturityState.EXPERIMENTAL
    assert skill.validation_status == "VALIDATED"
    # Verify saved in experimental workspace
    exp_file = specialist.self_development.experimental_dir / f"{skill.skill_id}.json"
    assert exp_file.exists()

    # -------------------------------------------------------------------------
    # 6. Run Experiment in Sandbox against Baseline
    # -------------------------------------------------------------------------
    # Define baseline runner (only runs DNS)
    def baseline_runner(params, ctx):
        return specialist.execute_local_capability(CAPABILITY_DNS_LOOKUP, params, ctx)

    experiment = specialist.self_development.run_experiment(
        skill=skill,
        input_parameters={"target": "company-target.com"},
        baseline_runner=baseline_runner,
    )
    assert experiment.success is True
    # Experimental ran DNS + Cert, so it should produce more evidence than baseline DNS alone!
    assert experiment.experimental_metrics["evidence_count"] > experiment.baseline_metrics["evidence_count"]

    # -------------------------------------------------------------------------
    # 7. Evaluate Experiment
    # -------------------------------------------------------------------------
    evaluation = specialist.self_development.evaluate_skill(skill, experiment)
    assert skill.maturity == SkillMaturityState.EVALUATED
    assert evaluation.recommendation == "PROPOSE_PROMOTION"
    assert len(evaluation.observed_benefits) >= 1

    # -------------------------------------------------------------------------
    # 8. Submit Promotion Proposal
    # -------------------------------------------------------------------------
    promotion_proposal = specialist.self_development.propose_promotion(
        skill=skill,
        evaluation=evaluation,
        rationale="Demonstrated 2x evidence yield in controlled sandbox testing with negligible latency impact.",
    )
    assert skill.maturity == SkillMaturityState.PROPOSED
    assert promotion_proposal.skill_id == skill.skill_id

    # -------------------------------------------------------------------------
    # 9. Human / Policy Authorization Decision
    # -------------------------------------------------------------------------
    decision = specialist.self_development.review_promotion(
        proposal_id=promotion_proposal.id,
        skill=skill,
        approver="security.lead_analyst",  # Explicit external authorized actor
        approved=True,
        reason="Verified sandbox metrics confirm superior evidence yield without security regressions.",
    )
    assert decision.approved is True
    assert skill.maturity == SkillMaturityState.APPROVED

    # -------------------------------------------------------------------------
    # 10. Deploy to Trusted
    # -------------------------------------------------------------------------
    trusted_skill = specialist.self_development.deploy_to_trusted(skill, decision)
    assert trusted_skill.maturity == SkillMaturityState.TRUSTED

    # Verify saved in trusted workspace
    trusted_file = specialist.self_development.trusted_dir / f"{trusted_skill.skill_id}.json"
    assert trusted_file.exists()

    # -------------------------------------------------------------------------
    # 11. Specialist Activates Promoted Skill as Production Workflow
    # -------------------------------------------------------------------------
    specialist.deploy_promoted_skill_as_workflow(trusted_skill)
    promoted_capability_id = f"osint.skill:{trusted_skill.skill_id}"
    assert promoted_capability_id in specialist.list_capabilities()

    # Re-register updated capability manifest with Core
    core.register_specialist(specialist.as_specialist())

    # -------------------------------------------------------------------------
    # 12. Core Invokes Newly Trusted Skill via SpecialistEndpoint
    # -------------------------------------------------------------------------
    inv = core.create_investigation(title="Investigation with Newly Promoted Skill")

    core_result = core.execute_action(
        investigation_id=inv.id,
        capability_id=promoted_capability_id,
        parameters={"target": "victim-enterprise.com"},
    )

    assert core_result.is_success is True
    assert len(core_result.evidence) >= 2
    # Provenance preserved back to OSINT Specialist
    assert core_result.evidence[0].provenance.specialist_id == specialist.SPECIALIST_ID
    assert inv.evidence_store.count() >= 2

    core.shutdown()
