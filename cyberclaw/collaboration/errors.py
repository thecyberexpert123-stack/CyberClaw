"""Failure taxonomy and exception hierarchy for Multi-Specialist Collaboration & Evidence Consensus v0.1."""

from __future__ import annotations

from typing import Optional


class CollaborationError(Exception):
    """Base exception for all collaboration subsystem failures."""

    def __init__(
        self,
        message: str,
        request_id: Optional[str] = None,
        investigation_id: Optional[str] = None,
        specialist_id: Optional[str] = None,
    ) -> None:
        self.message = message
        self.request_id = request_id
        self.investigation_id = investigation_id
        self.specialist_id = specialist_id
        context_parts = []
        if request_id:
            context_parts.append(f"req={request_id}")
        if investigation_id:
            context_parts.append(f"inv={investigation_id}")
        if specialist_id:
            context_parts.append(f"spec={specialist_id}")
        ctx_str = f" [{', '.join(context_parts)}]" if context_parts else ""
        super().__init__(f"{message}{ctx_str}")


class CollaborationValidationError(CollaborationError):
    """Raised when collaboration request syntax, schema, or parameters are invalid."""
    pass


class CollaborationAuthorizationError(CollaborationError):
    """Raised when policy engine denies collaboration or required approval is absent."""
    pass


class SpecialistUnavailableError(CollaborationError):
    """Raised when target specialist is unhealthy, missing, or lacks capacity."""
    pass


class SpecialistRejectedRequestError(CollaborationError):
    """Raised when target specialist rejects a collaboration request."""
    pass


class DependencyUnresolvedError(CollaborationError):
    """Raised when mandatory hard dependencies are unsatisfied."""
    pass


class DependencyCycleError(CollaborationError):
    """Raised when a cyclical dependency is detected in the collaboration graph."""
    pass


class CollaborationTimeoutError(CollaborationError):
    """Raised when a collaboration request or response deadline is exceeded."""
    pass


class ResultSchemaError(CollaborationError):
    """Raised when a specialist collaboration result fails structural validation."""
    pass


class EvidenceNormalizationError(CollaborationError):
    """Raised when normalizing specialist findings into evidence fails."""
    pass


class ConflictProcessingError(CollaborationError):
    """Raised on invalid conflict state transitions or reconciliation failures."""
    pass


class CollaborationPersistenceError(CollaborationError):
    """Raised when collaboration state fails atomic disk persistence or deserialization."""
    pass


class CollaborationStateTransitionError(CollaborationError):
    """Raised on illegal transitions within the Collaboration Lifecycle DFA."""
    pass


class UnauthorizedContextAccessError(CollaborationError):
    """Raised when a specialist attempts to access context exceeding its sensitivity clearance."""
    pass
