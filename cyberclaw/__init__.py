"""CyberClaw Core: Extensible autonomous cybersecurity investigation platform.

Local autonomy, global coordination.
"""

from cyberclaw.capabilities.capability import Capability
from cyberclaw.capabilities.provider import CapabilityProvider, ExecutionContext
from cyberclaw.capabilities.registry import CapabilityRegistry
from cyberclaw.core import CyberClawCore
from cyberclaw.coordination.coordinator import InvestigationCoordinator
from cyberclaw.coordination.requirements import (
    InformationRequirement,
    RequirementStatus,
)
from cyberclaw.coordination.router import RequirementRouter
from cyberclaw.correlation.engine import CorrelationEngine, CorrelationResult
from cyberclaw.correlation.models import ContradictionRecord, CorrelationProvenance
from cyberclaw.correlation.rules import (
    CertificateIdentityCorrelationRule,
    CorrelationRule,
    DnsResolutionCorrelationRule,
    NetworkServiceCorrelationRule,
    SharedInfrastructureCorrelationRule,
)
from cyberclaw.dfa.machine import CoreDFA, InvalidTransitionError
from cyberclaw.dfa.states import CoreState
from cyberclaw.events.bus import EventBus
from cyberclaw.events.event import Event
from cyberclaw.evidence.models import Evidence, Observation, Provenance
from cyberclaw.evidence.result import ExecutionResult, ExecutionStatus
from cyberclaw.evidence.store import EvidenceStore
from cyberclaw.investigation import Investigation
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.memory.memory import MemoryFact, MemoryStore
from cyberclaw.memory.store import ExperienceStore
from cyberclaw.observability.logger import ObservabilityRecord, StructuredLogger
from cyberclaw.permissions.manager import (
    ApprovalRequiredError,
    PermissionDeniedError,
    PermissionManager,
)
from cyberclaw.permissions.policy import ActionScope, Permission, Role
from cyberclaw.specialists.base import Specialist
from cyberclaw.specialists.endpoint import (
    SpecialistEndpoint,
    SpecialistHealth,
    SpecialistRequest,
    SpecialistResponse,
)
from cyberclaw.specialists.registry import SpecialistRegistry
from cyberclaw.types import Entity, Hypothesis, Relationship, Source
from cyberclaw.validation.errors import (
    PolicyValidationError,
    ResultValidationError,
    SchemaValidationError,
    StateValidationError,
    ValidationError,
)
from cyberclaw.validation.pipeline import ValidationPipeline
from cyberclaw.workspace.layout import WorkspaceLayout
from cyberclaw.workspace.manager import WorkspaceAccessError, WorkspaceManager

__version__ = "0.1.0"

__all__ = [
    # Top-level Orchestrator
    "CyberClawCore",
    "Investigation",
    # Types
    "Entity",
    "Source",
    "Relationship",
    "Hypothesis",
    # DFA
    "CoreDFA",
    "CoreState",
    "InvalidTransitionError",
    # Evidence & Results
    "Evidence",
    "Observation",
    "Provenance",
    "ExecutionResult",
    "ExecutionStatus",
    "EvidenceStore",
    # Capabilities & Providers
    "Capability",
    "CapabilityProvider",
    "ExecutionContext",
    "CapabilityRegistry",
    # Specialists
    "Specialist",
    "SpecialistEndpoint",
    "SpecialistHealth",
    "SpecialistRequest",
    "SpecialistResponse",
    "SpecialistRegistry",
    # Events
    "Event",
    "EventBus",
    # Memory & Experience
    "MemoryFact",
    "MemoryStore",
    "ExperienceRecord",
    "ExperienceStore",
    # Permissions
    "Permission",
    "Role",
    "ActionScope",
    "PermissionManager",
    "PermissionDeniedError",
    "ApprovalRequiredError",
    # Validation
    "ValidationPipeline",
    "ValidationError",
    "SchemaValidationError",
    "PolicyValidationError",
    "StateValidationError",
    "ResultValidationError",
    # Observability
    "StructuredLogger",
    "ObservabilityRecord",
    # Workspace
    "WorkspaceLayout",
    "WorkspaceManager",
    "WorkspaceAccessError",
    # Coordination & Correlation
    "InformationRequirement",
    "RequirementStatus",
    "RequirementRouter",
    "InvestigationCoordinator",
    "CorrelationEngine",
    "CorrelationResult",
    "CorrelationProvenance",
    "ContradictionRecord",
    "CorrelationRule",
    "DnsResolutionCorrelationRule",
    "CertificateIdentityCorrelationRule",
    "NetworkServiceCorrelationRule",
    "SharedInfrastructureCorrelationRule",
]
