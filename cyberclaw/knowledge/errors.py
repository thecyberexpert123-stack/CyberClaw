"""Structured failure taxonomy and exception hierarchy for Knowledge Graph operations."""

from __future__ import annotations

from typing import Any, Dict, Optional


class KnowledgeError(Exception):
    """Base exception for all Knowledge Graph failures."""

    def __init__(
        self,
        message: str,
        code: str = "KNOWLEDGE_ERROR",
        investigation_id: Optional[str] = None,
        node_id: Optional[str] = None,
        edge_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code
        self.investigation_id = investigation_id
        self.node_id = node_id
        self.edge_id = edge_id
        self.details = details or {}

    def __str__(self) -> str:
        ctx = []
        if self.investigation_id:
            ctx.append(f"inv={self.investigation_id}")
        if self.node_id:
            ctx.append(f"node={self.node_id}")
        if self.edge_id:
            ctx.append(f"edge={self.edge_id}")
        ctx_str = f" [{', '.join(ctx)}]" if ctx else ""
        return f"[{self.code}] {self.message}{ctx_str}"


class KnowledgeValidationError(KnowledgeError):
    """Raised when node, edge, or mutation schema or structure fails validation."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="KNOWLEDGE_VALIDATION_FAILURE", **kwargs)


class KnowledgeAuthorizationError(KnowledgeError):
    """Raised when a graph mutation is rejected by PolicyEngine or lacks required permissions."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="KNOWLEDGE_AUTHORIZATION_FAILURE", **kwargs)


class KnowledgeNodeNotFoundError(KnowledgeError):
    """Raised when a referenced node ID is missing from the graph."""

    def __init__(self, node_id: str, **kwargs: Any) -> None:
        super().__init__(f"Knowledge node '{node_id}' not found.", code="NODE_NOT_FOUND", node_id=node_id, **kwargs)


class KnowledgeEdgeNotFoundError(KnowledgeError):
    """Raised when a referenced edge ID is missing from the graph."""

    def __init__(self, edge_id: str, **kwargs: Any) -> None:
        super().__init__(f"Knowledge edge '{edge_id}' not found.", code="EDGE_NOT_FOUND", edge_id=edge_id, **kwargs)


class KnowledgeTemporalError(KnowledgeError):
    """Raised on invalid temporal intervals or historical point-in-time errors."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="TEMPORAL_ERROR", **kwargs)


class KnowledgeConsistencyError(KnowledgeError):
    """Raised when strict structural consistency check fails."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="CONSISTENCY_FAILURE", **kwargs)


class KnowledgeMutationError(KnowledgeError):
    """Raised when a graph mutation cannot be applied."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="MUTATION_ERROR", **kwargs)


class KnowledgePersistenceError(KnowledgeError):
    """Raised on graph persistence or restoration failures."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="PERSISTENCE_FAILURE", **kwargs)


class KnowledgeIntegrityError(KnowledgeError):
    """Raised when node, edge, or graph SHA-256 integrity digest fails verification."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="INTEGRITY_FAILURE", **kwargs)


class KnowledgeBranchLeakError(KnowledgeError):
    """Raised when counterfactual branch entities or edges attempt to enter authoritative graph state."""

    def __init__(self, message: str, **kwargs: Any) -> None:
        super().__init__(message, code="BRANCH_LEAK_DETECTED", **kwargs)
