"""Tests for the Skill Maturity Model and deterministic lifecycle transitions."""

import pytest
from cyberclaw.specialists.self_development.maturity import (
    InvalidMaturityTransitionError,
    SkillMaturityState,
)
from cyberclaw.specialists.self_development.skill import ExperimentalSkill


def _make_skill() -> ExperimentalSkill:
    return ExperimentalSkill(
        skill_id="skill.test_domain",
        purpose="Testing lifecycle transitions",
        author_origin="osint_specialist",
        hypothesis="Skill enhances triage speed",
    )


def test_valid_maturity_lifecycle_progression():
    skill = _make_skill()
    assert skill.maturity == SkillMaturityState.EXPERIMENTAL

    # EXPERIMENTAL -> EVALUATED
    skill.transition_maturity(SkillMaturityState.EVALUATED)
    assert skill.maturity == SkillMaturityState.EVALUATED

    # EVALUATED -> PROPOSED
    skill.transition_maturity(SkillMaturityState.PROPOSED)
    assert skill.maturity == SkillMaturityState.PROPOSED

    # PROPOSED -> APPROVED
    skill.transition_maturity(SkillMaturityState.APPROVED)
    assert skill.maturity == SkillMaturityState.APPROVED

    # APPROVED -> TRUSTED
    skill.transition_maturity(SkillMaturityState.TRUSTED)
    assert skill.maturity == SkillMaturityState.TRUSTED


def test_illegal_jump_experimental_to_trusted_rejected():
    skill = _make_skill()
    assert skill.maturity == SkillMaturityState.EXPERIMENTAL

    # Cannot jump directly from EXPERIMENTAL to TRUSTED
    with pytest.raises(InvalidMaturityTransitionError) as exc:
        skill.transition_maturity(SkillMaturityState.TRUSTED)
    assert "Invalid maturity transition from 'EXPERIMENTAL' to 'TRUSTED'" in str(exc.value)
    assert skill.maturity == SkillMaturityState.EXPERIMENTAL


def test_illegal_jump_experimental_to_proposed_rejected():
    skill = _make_skill()
    # Cannot jump to PROPOSED without being EVALUATED first
    with pytest.raises(InvalidMaturityTransitionError):
        skill.transition_maturity(SkillMaturityState.PROPOSED)


def test_illegal_jump_proposed_to_trusted_rejected():
    skill = _make_skill()
    skill.transition_maturity(SkillMaturityState.EVALUATED)
    skill.transition_maturity(SkillMaturityState.PROPOSED)

    # Cannot jump directly from PROPOSED to TRUSTED without APPROVED
    with pytest.raises(InvalidMaturityTransitionError):
        skill.transition_maturity(SkillMaturityState.TRUSTED)


def test_rejection_transition():
    skill = _make_skill()
    skill.transition_maturity(SkillMaturityState.EVALUATED)
    skill.transition_maturity(SkillMaturityState.PROPOSED)
    skill.transition_maturity(SkillMaturityState.REJECTED)
    assert skill.maturity == SkillMaturityState.REJECTED

    # From REJECTED, can return to EXPERIMENTAL for rework
    skill.transition_maturity(SkillMaturityState.EXPERIMENTAL)
    assert skill.maturity == SkillMaturityState.EXPERIMENTAL
