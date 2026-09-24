"""Multi-Specialist Collaboration & Evidence Consensus v0.1 for CyberClaw.

Central Principles:
- SPECIALISTS REASON LOCALLY.
- COLLABORATION IS STRUCTURED.
- AUTHORITY REMAINS CENTRALIZED.
- EVIDENCE REMAINS PROVENANCE-PRESERVING.
- DISAGREEMENT REMAINS VISIBLE.
"""

from __future__ import annotations

from cyberclaw.collaboration.conflicts import (
    ConflictDetector,
    ConflictManager,
)
from cyberclaw.collaboration.consensus import (
    ConsensusEngine,
)
from cyberclaw.collaboration.coordinator import (
    CollaborationCoordinator,
)
from cyberclaw.collaboration.dependencies import (
    CollaborationDependencyGraph,
)
from cyberclaw.collaboration.errors import (
    CollaborationAuthorizationError,
    CollaborationError,
    CollaborationPersistenceError,
    CollaborationStateTransitionError,
    CollaborationTimeoutError,
    CollaborationValidationError,
    ConflictProcessingError,
    DependencyCycleError,
    DependencyUnresolvedError,
    EvidenceNormalizationError,
    ResultSchemaError,
    SpecialistRejectedRequestError,
    SpecialistUnavailableError,
    UnauthorizedContextAccessError,
)
from cyberclaw.collaboration.evidence import (
    EvidenceHandoffNormalizer,
)
from cyberclaw.collaboration.models import (
    CollaborationContext,
    CollaborationDependency,
    CollaborationRequest,
    CollaborationResult,
    CollaborationStatus,
    ConflictStatus,
    ConflictType,
    ConsensusAssessment,
    ConsensusStatus,
    ContextSensitivity,
    DependencyRelation,
    DependencyType,
    FindingNature,
    RoutingDecision,
    SpecialistConflict,
)
from cyberclaw.collaboration.persistence import (
    CollaborationPersistenceManager,
)
from cyberclaw.collaboration.protocol import (
    CollaborationLifecycleDFA,
    ContextFilter,
)
from cyberclaw.collaboration.routing import (
    CollaborationRouter,
)

__all__ = [
    # Models & Enums
    "CollaborationRequest",
    "CollaborationResult",
    "CollaborationContext",
    "SpecialistConflict",
    "ConsensusAssessment",
    "RoutingDecision",
    "CollaborationDependency",
    "CollaborationStatus",
    "FindingNature",
    "ContextSensitivity",
    "DependencyType",
    "DependencyRelation",
    "ConflictType",
    "ConflictStatus",
    "ConsensusStatus",
    # Subsystems
    "CollaborationCoordinator",
    "CollaborationRouter",
    "CollaborationLifecycleDFA",
    "ContextFilter",
    "CollaborationDependencyGraph",
    "EvidenceHandoffNormalizer",
    "ConflictDetector",
    "ConflictManager",
    "ConsensusEngine",
    "CollaborationPersistenceManager",
    # Errors
    "CollaborationError",
    "CollaborationValidationError",
    "CollaborationAuthorizationError",
    "SpecialistUnavailableError",
    "SpecialistRejectedRequestError",
    "DependencyUnresolvedError",
    "DependencyCycleError",
    "CollaborationTimeoutError",
    "ResultSchemaError",
    "EvidenceNormalizationError",
    "ConflictProcessingError",
    "CollaborationPersistenceError",
    "CollaborationStateTransitionError",
    "UnauthorizedContextAccessError",
]
