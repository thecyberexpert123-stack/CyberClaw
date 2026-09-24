"""Security and authorization boundary enforcement tests for Self-Development."""

from pathlib import Path
import pytest
from cyberclaw.permissions.manager import PermissionManager
from cyberclaw.specialists.self_development.evaluation import SkillEvaluation
from cyberclaw.specialists.self_development.maturity import SkillMaturityState
from cyberclaw.specialists.self_development.promotion import (
    PromotionManager,
    UnauthorizedPromotionError,
)
from cyberclaw.specialists.self_development.skill import ExperimentalSkill
from cyberclaw.specialists.self_development.validation import (
    SkillValidationError,
    SkillValidator,
)


def test_candidate_skill_cannot_self_promote():
    """Verify Section 15: Specialist cannot self-promote without explicit approval."""
    pm = PromotionManager()

    skill = ExperimentalSkill(
        skill_id="exp.self_promoter",
        purpose="Attempting unapproved promotion",
        author_origin="osint_specialist",
        hypothesis="Testing self-promotion guard",
    )
    skill.transition_maturity(SkillMaturityState.EVALUATED)

    eval_artifact = SkillEvaluation(
        experiment_id="exp-123",
        skill_id=skill.skill_id,
        baseline_metrics={},
        experimental_metrics={},
        differences={},
        recommendation="PROPOSE_PROMOTION",
    )

    proposal = pm.submit_proposal(skill, eval_artifact, rationale="I want to be trusted")
    assert skill.maturity == SkillMaturityState.PROPOSED

    # 1. Specialist cannot approve its own proposal
    with pytest.raises(UnauthorizedPromotionError) as exc:
        pm.review_proposal(
            proposal_id=proposal.id,
            skill=skill,
            approver="osint_specialist",  # Self-approval attempt
            approved=True,
            reason="Self-approving my own skill",
        )
    assert "cannot self-approve its own promotion proposal" in str(exc.value)

    # 2. Cannot deploy to trusted without APPROVED state
    with pytest.raises(UnauthorizedPromotionError):
        from cyberclaw.specialists.self_development.promotion import ApprovalDecision
        pm.deploy_to_trusted(skill, ApprovalDecision(proposal_id=proposal.id, approver="admin", approved=False, reason="Denied"))


def test_candidate_skill_cannot_initialize_as_trusted():
    """Verify Section 3 & 7: Skill cannot initialize directly in TRUSTED state."""
    with pytest.raises(SkillValidationError) as exc:
        skill = ExperimentalSkill(
            skill_id="bad.skill",
            purpose="Sneaky skill",
            author_origin="osint_specialist",
            hypothesis="Testing initialization bypass",
            maturity=SkillMaturityState.TRUSTED,  # Illegal initial state
        )
        SkillValidator.enforce_valid_skill(skill, ["network:read"], ["osint.dns_lookup"])
    assert "cannot initialize in 'TRUSTED' state" in str(exc.value)


def test_candidate_skill_cannot_escalate_permissions():
    """Verify Section 7 & 15: Skill cannot grant itself unauthorized permissions."""
    skill = ExperimentalSkill(
        skill_id="priv.esc",
        purpose="Attempting permission escalation",
        author_origin="osint_specialist",
        hypothesis="Testing permission escalation",
        permissions_required=["system:admin", "priv:kernel_write"],
    )

    with pytest.raises(SkillValidationError) as exc:
        SkillValidator.enforce_valid_skill(
            skill,
            specialist_permissions=["network:read"],
            known_capabilities=["osint.dns_lookup"],
        )
    assert "exceeds specialist authority" in str(exc.value)


def test_candidate_skill_cannot_alter_dfa_or_core(tmp_path: Path):
    """Verify Section 15: Skill procedure cannot illegally reference core architecture."""
    from cyberclaw.specialists.self_development.proposals import SkillProposal

    proposal = SkillProposal(
        originating_specialist="osint_specialist",
        intended_objective="Bypass DFA control",
        hypothesis="Attempting core bypass",
        proposed_procedure={"steps": [{"action": "dfa.transition = None"}]},
        expected_benefit="Total control",
        required_capabilities=["osint.dns_lookup"],
        required_permissions=["network:read"],
    )

    with pytest.raises(SkillValidationError) as exc:
        from cyberclaw.specialists.self_development.engine import SpecialistSelfDevelopmentEngine
        engine = SpecialistSelfDevelopmentEngine(
            specialist_id="osint_specialist",
            workspace_root=tmp_path,
            capability_invoker=lambda c, p, ctx: None,
            specialist_permissions=["network:read"],
            known_capabilities=["osint.dns_lookup"],
        )
        engine.propose_skill(
            intended_objective="Bypass DFA",
            hypothesis="Testing",
            proposed_procedure={"steps": [{"target": "cyberclaw.core.dfa"}]},
            required_capabilities=["osint.dns_lookup"],
            required_permissions=["network:read"],
        )
    assert "illegally references architectural component" in str(exc.value)
