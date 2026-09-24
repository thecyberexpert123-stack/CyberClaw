"""Deterministic lifecycle management for investigation branches."""

from __future__ import annotations

from typing import Dict, Optional, Set
from cyberclaw.branching.errors import BranchLifecycleError
from cyberclaw.branching.models import BranchStatus, InvestigationBranch
from cyberclaw.case.models import utc_now

VALID_BRANCH_TRANSITIONS: Dict[BranchStatus, Set[BranchStatus]] = {
    BranchStatus.ACTIVE: {
        BranchStatus.COMPLETED,
        BranchStatus.ABANDONED,
        BranchStatus.REJECTED,
        BranchStatus.PROMOTED,
        BranchStatus.EXPIRED,
    },
    BranchStatus.COMPLETED: {
        BranchStatus.PROMOTED,
        BranchStatus.ABANDONED,
        BranchStatus.REJECTED,
    },
    BranchStatus.ABANDONED: set(),
    BranchStatus.REJECTED: set(),
    BranchStatus.PROMOTED: set(),
    BranchStatus.EXPIRED: set(),
}


def transition_branch(
    branch: InvestigationBranch,
    target_status: BranchStatus,
    reason: Optional[str] = None,
) -> None:
    """Transition a branch to a new lifecycle state enforcing strict state machine rules."""
    current_status = branch.status
    if current_status == target_status:
        return

    allowed = VALID_BRANCH_TRANSITIONS.get(current_status, set())
    if target_status not in allowed:
        raise BranchLifecycleError(
            f"Invalid branch transition from '{current_status.value}' to '{target_status.value}'. "
            f"Allowed targets: {[s.value for s in allowed]}",
            branch_id=branch.branch_id,
        )

    branch.status = target_status
    branch.updated_at = utc_now()
    if reason:
        branch.metadata["status_reason"] = reason
