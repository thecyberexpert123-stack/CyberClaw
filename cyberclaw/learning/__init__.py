"""Cross-case experience and investigation strategy learning.

Experience remembers what happened. Patterns describe what recurred.
Strategies propose what may be tried. Governance decides what may be deployed.
Learning never becomes authority by itself.
"""

from cyberclaw.learning.applicability import ApplicabilityEngine
from cyberclaw.learning.clustering import SourceFamilyGrouper
from cyberclaw.learning.confidence import PatternConfidenceModel
from cyberclaw.learning.errors import (
    BranchExperienceQuarantineError,
    ExecutableStrategyRejectedError,
    InvalidStrategyTransitionError,
    LearningError,
    LearningExtractionError,
    LearningPersistenceError,
    LearningReplayError,
    LearningTamperError,
    LearningThresholdError,
    PatternNotFoundError,
    PatternNotValidatedError,
    SelfApprovalError,
    StrategyGovernanceError,
    StrategyNotFoundError,
)
from cyberclaw.learning.evaluation import StrategyEvaluator, StrategyRegressionDetector
from cyberclaw.learning.extraction import ExperienceExtractor
from cyberclaw.learning.governance import StrategyGovernance, assert_external_actor
from cyberclaw.learning.models import (
    ARCHITECTURAL_MIN_INDEPENDENT_CASES,
    ARCHITECTURAL_MIN_INDEPENDENT_SOURCE_FAMILIES,
    PATTERN_ALGORITHM,
    SIMILARITY_ALGORITHM,
    ApplicabilityProfile,
    ApprovalDecisionKind,
    ConfidenceBand,
    InvestigationExperience,
    InvestigationStrategy,
    PatternKind,
    PatternScope,
    PromotionThresholdPolicy,
    StrategyLifecycle,
)
from cyberclaw.learning.normalization import ExperienceNormalizer
from cyberclaw.learning.patterns import PatternDetector, explain_pattern
from cyberclaw.learning.persistence import LearningPersistenceManager
from cyberclaw.learning.proposals import LearningService
from cyberclaw.learning.registry import LearningRegistry, LearningReplay
from cyberclaw.learning.simulation import StrategySimulator
from cyberclaw.learning.strategies import StrategyBuilder, StrategyLifecycleMachine

__all__ = [
    "ApplicabilityEngine",
    "ApplicabilityProfile",
    "ApprovalDecisionKind",
    "ARCHITECTURAL_MIN_INDEPENDENT_CASES",
    "ARCHITECTURAL_MIN_INDEPENDENT_SOURCE_FAMILIES",
    "BranchExperienceQuarantineError",
    "ConfidenceBand",
    "ExecutableStrategyRejectedError",
    "ExperienceExtractor",
    "ExperienceNormalizer",
    "InvalidStrategyTransitionError",
    "InvestigationExperience",
    "InvestigationStrategy",
    "LearningError",
    "LearningExtractionError",
    "LearningPersistenceError",
    "LearningPersistenceManager",
    "LearningRegistry",
    "LearningReplay",
    "LearningReplayError",
    "LearningService",
    "LearningTamperError",
    "LearningThresholdError",
    "PATTERN_ALGORITHM",
    "PatternDetector",
    "PatternKind",
    "PatternNotFoundError",
    "PatternNotValidatedError",
    "PatternScope",
    "PatternConfidenceModel",
    "PromotionThresholdPolicy",
    "SIMILARITY_ALGORITHM",
    "SelfApprovalError",
    "SourceFamilyGrouper",
    "StrategyBuilder",
    "StrategyEvaluator",
    "StrategyGovernance",
    "StrategyGovernanceError",
    "StrategyLifecycle",
    "StrategyLifecycleMachine",
    "StrategyNotFoundError",
    "StrategyRegressionDetector",
    "StrategySimulator",
    "assert_external_actor",
    "explain_pattern",
]
