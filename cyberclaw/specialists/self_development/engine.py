"""Specialist Self-Development Engine.

Coordinates the complete controlled lifecycle:
Observation -> Pattern Detection -> Proposal -> Validation -> Sandbox Experiment ->
Evaluation -> Promotion Proposal -> Policy Approval -> Trusted Deployment.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from cyberclaw.capabilities.provider import ExecutionContext
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.specialists.self_development.evaluation import (
    SkillEvaluation,
    SkillEvaluator,
)
from cyberclaw.specialists.self_development.experiment import (
    ExperimentSandbox,
    SkillExperiment,
)
from cyberclaw.specialists.self_development.maturity import SkillMaturityState
from cyberclaw.specialists.self_development.patterns import (
    PatternDetector,
    PatternObservation,
)
from cyberclaw.specialists.self_development.promotion import (
    ApprovalDecision,
    PromotionManager,
    PromotionProposal,
)
from cyberclaw.specialists.self_development.proposals import SkillProposal
from cyberclaw.specialists.self_development.skill import ExperimentalSkill
from cyberclaw.specialists.self_development.validation import SkillValidator


class SpecialistSelfDevelopmentEngine:
    """Manages autonomous skill development within a Specialist's authority boundary."""

    def __init__(
        self,
        specialist_id: str,
        workspace_root: Path,
        capability_invoker: Callable[[str, Dict[str, Any], ExecutionContext], ExecutionResult],
        specialist_permissions: List[str],
        known_capabilities: List[str],
    ) -> None:
        self.specialist_id = specialist_id
        self.workspace_root = workspace_root.resolve()
        self.capability_invoker = capability_invoker
        self.specialist_permissions = specialist_permissions
        self.known_capabilities = known_capabilities

        # Initialize subcomponents
        self.pattern_detector = PatternDetector()
        self.sandbox = ExperimentSandbox(capability_invoker)
        self.promotion_manager = PromotionManager()

        # Workspace paths for skills
        self.experimental_dir = self.workspace_root / "skills" / "experimental"
        self.trusted_dir = self.workspace_root / "skills" / "trusted"
        self.evaluations_dir = self.workspace_root / "skills" / "evaluations"

        self.experimental_dir.mkdir(parents=True, exist_ok=True)
        self.trusted_dir.mkdir(parents=True, exist_ok=True)
        self.evaluations_dir.mkdir(parents=True, exist_ok=True)

        self._experimental_skills: Dict[str, ExperimentalSkill] = {}
        self._evaluations: Dict[str, SkillEvaluation] = {}

    # --------------------------------------------------------------------------
    # 1. Pattern Detection
    # --------------------------------------------------------------------------

    def detect_patterns(self, experiences: List[ExperienceRecord]) -> List[PatternObservation]:
        """Analyze Specialist experiences to detect reusable operational patterns."""
        return self.pattern_detector.detect_patterns(experiences)

    # --------------------------------------------------------------------------
    # 2. Proposal Generation & Validation
    # --------------------------------------------------------------------------

    def propose_skill(
        self,
        intended_objective: str,
        hypothesis: str,
        proposed_procedure: Dict[str, Any],
        required_capabilities: List[str],
        required_permissions: List[str],
        expected_benefit: str = "",
        source_pattern_ids: Optional[List[str]] = None,
        source_experience_ids: Optional[List[str]] = None,
    ) -> SkillProposal:
        """Create a formal SkillProposal from detected patterns."""
        proposal = SkillProposal(
            originating_specialist=self.specialist_id,
            source_pattern_ids=source_pattern_ids or [],
            source_experience_ids=source_experience_ids or [],
            intended_objective=intended_objective,
            proposed_procedure=proposed_procedure,
            expected_benefit=expected_benefit,
            required_capabilities=required_capabilities,
            required_permissions=required_permissions,
            hypothesis=hypothesis,
        )

        # Validate proposal immediately
        val_res = SkillValidator.validate_proposal(
            proposal=proposal,
            specialist_permissions=self.specialist_permissions,
            known_capabilities=self.known_capabilities,
        )
        if not val_res.is_valid:
            proposal.status = "REJECTED"
            from cyberclaw.specialists.self_development.validation import SkillValidationError
            raise SkillValidationError("PROPOSAL_VALIDATION_FAILED", "; ".join(val_res.rejection_reasons))

        return proposal

    # --------------------------------------------------------------------------
    # 3. Create Experimental Skill
    # --------------------------------------------------------------------------

    def create_experimental_skill(
        self,
        skill_id: str,
        proposal: SkillProposal,
    ) -> ExperimentalSkill:
        """Instantiate and store an ExperimentalSkill in the experimental workspace."""
        skill = proposal.to_experimental_skill(skill_id=skill_id)

        # Validate skill
        SkillValidator.enforce_valid_skill(
            skill=skill,
            specialist_permissions=self.specialist_permissions,
            known_capabilities=self.known_capabilities,
        )
        skill.validation_status = "VALIDATED"

        # Persist to experimental workspace
        self._experimental_skills[skill.skill_id] = skill
        file_path = self.experimental_dir / f"{skill.skill_id}.json"
        file_path.write_text(skill.model_dump_json(indent=2), encoding="utf-8")

        return skill

    # --------------------------------------------------------------------------
    # 4. Sandbox Experiment & Measurement
    # --------------------------------------------------------------------------

    def run_experiment(
        self,
        skill: ExperimentalSkill,
        input_parameters: Dict[str, Any],
        baseline_runner: Optional[Callable[[Dict[str, Any], ExecutionContext], ExecutionResult]] = None,
    ) -> SkillExperiment:
        """Execute experimental skill in sandbox alongside baseline."""
        return self.sandbox.run_experiment(
            skill=skill,
            input_parameters=input_parameters,
            baseline_runner=baseline_runner,
        )

    # --------------------------------------------------------------------------
    # 5. Evaluation
    # --------------------------------------------------------------------------

    def evaluate_skill(
        self,
        skill: ExperimentalSkill,
        experiment: SkillExperiment,
    ) -> SkillEvaluation:
        """Formally evaluate experimental skill against baseline results."""
        evaluation = SkillEvaluator.evaluate(experiment)
        self._evaluations[evaluation.id] = evaluation

        # Update skill maturity: EXPERIMENTAL -> EVALUATED
        skill.transition_maturity(
            SkillMaturityState.EVALUATED,
            reason=f"Evaluated in experiment {experiment.id}; recommendation: {evaluation.recommendation}",
        )
        skill.evaluation_id = evaluation.id

        # Persist evaluation artifact
        eval_path = self.evaluations_dir / f"{evaluation.id}.json"
        eval_path.write_text(evaluation.model_dump_json(indent=2), encoding="utf-8")

        # Update experimental skill on disk
        skill_path = self.experimental_dir / f"{skill.skill_id}.json"
        skill_path.write_text(skill.model_dump_json(indent=2), encoding="utf-8")

        return evaluation

    # --------------------------------------------------------------------------
    # 6. Promotion Proposal & Policy Decision
    # --------------------------------------------------------------------------

    def propose_promotion(
        self,
        skill: ExperimentalSkill,
        evaluation: SkillEvaluation,
        rationale: str,
        risks: Optional[List[str]] = None,
    ) -> PromotionProposal:
        """Specialist requests promotion based on evaluation evidence."""
        return self.promotion_manager.submit_proposal(
            skill=skill,
            evaluation=evaluation,
            rationale=rationale,
            risks=risks,
        )

    def review_promotion(
        self,
        proposal_id: str,
        skill: ExperimentalSkill,
        approver: str,
        approved: bool,
        reason: str,
    ) -> ApprovalDecision:
        """Explicit human/policy authorization decision."""
        return self.promotion_manager.review_proposal(
            proposal_id=proposal_id,
            skill=skill,
            approver=approver,
            approved=approved,
            reason=reason,
        )

    def deploy_to_trusted(
        self,
        skill: ExperimentalSkill,
        approval: ApprovalDecision,
    ) -> ExperimentalSkill:
        """Deploy approved skill into the trusted catalog and persist to trusted workspace."""
        trusted_skill = self.promotion_manager.deploy_to_trusted(skill, approval)

        # Write to trusted workspace
        trusted_path = self.trusted_dir / f"{trusted_skill.skill_id}.json"
        trusted_path.write_text(trusted_skill.model_dump_json(indent=2), encoding="utf-8")

        return trusted_skill

    def get_trusted_skill(self, skill_id: str) -> Optional[ExperimentalSkill]:
        return self.promotion_manager.get_trusted_skill(skill_id)

    def list_trusted_skills(self) -> List[ExperimentalSkill]:
        return self.promotion_manager.list_trusted_skills()
