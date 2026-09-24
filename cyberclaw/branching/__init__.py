"""Investigation Branching and Counterfactual Analysis subsystem."""

from cyberclaw.branching.engine import BranchEngine
from cyberclaw.branching.errors import (
    BranchError,
    BranchExecutionBlockedError,
    BranchIntegrityError,
    BranchLifecycleError,
    BranchNotFoundError,
    BranchPromotionError,
    BranchSequenceError,
)
from cyberclaw.branching.lifecycle import VALID_BRANCH_TRANSITIONS, transition_branch
from cyberclaw.branching.models import (
    BranchComparison,
    BranchJournalEntry,
    BranchStatus,
    CandidateBranchExperience,
    InvestigationBranch,
)
from cyberclaw.branching.persistence import BranchPersistence
from cyberclaw.branching.validator import BranchValidator

__all__ = [
    "BranchEngine",
    "BranchValidator",
    "BranchPersistence",
    "transition_branch",
    "VALID_BRANCH_TRANSITIONS",
    "BranchStatus",
    "BranchJournalEntry",
    "InvestigationBranch",
    "BranchComparison",
    "CandidateBranchExperience",
    "BranchError",
    "BranchNotFoundError",
    "BranchIntegrityError",
    "BranchLifecycleError",
    "BranchSequenceError",
    "BranchExecutionBlockedError",
    "BranchPromotionError",
]
