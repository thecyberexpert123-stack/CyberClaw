"""Explicit dependency graph modeling, cycle detection, and hard/soft dependency semantics."""

from __future__ import annotations

from typing import Dict, List, Optional, Set, Tuple
from cyberclaw.collaboration.errors import DependencyCycleError
from cyberclaw.collaboration.models import (
    CollaborationDependency,
    DependencyRelation,
    DependencyType,
)


class CollaborationDependencyGraph:
    """Manages multi-specialist collaboration dependencies, cycle detection, and readiness gating."""

    def __init__(self) -> None:
        # source_id -> list of dependencies (source_id depends on target_id)
        self._dependencies: Dict[str, List[CollaborationDependency]] = {}
        # target_id -> list of dependents (source_ids that depend on target_id)
        self._reverse_dependencies: Dict[str, List[CollaborationDependency]] = {}

    def add_dependency(
        self,
        source_id: str,
        target_id: str,
        dependency_type: DependencyType = DependencyType.HARD,
        relation: DependencyRelation = DependencyRelation.DEPENDS_ON,
        description: str = "",
    ) -> CollaborationDependency:
        """Add a dependency relationship. Validates that no cycle is introduced."""
        if source_id == target_id:
            raise DependencyCycleError(
                f"Self-referential dependency detected on '{source_id}'.",
                request_id=source_id,
            )

        dep = CollaborationDependency(
            source_id=source_id,
            target_id=target_id,
            dependency_type=dependency_type,
            relation=relation,
            description=description,
        )

        # Tentatively add and check for cycles
        self._dependencies.setdefault(source_id, []).append(dep)
        self._reverse_dependencies.setdefault(target_id, []).append(dep)

        cycles = self.detect_cycles()
        if cycles:
            # Revert change
            self._dependencies[source_id].remove(dep)
            self._reverse_dependencies[target_id].remove(dep)
            cycle_str = " -> ".join(cycles[0])
            raise DependencyCycleError(
                f"Cyclical dependency detected: {cycle_str}",
                request_id=source_id,
            )

        return dep

    def detect_cycles(self) -> List[List[str]]:
        """Detect all cycles in the dependency graph using depth-first search."""
        visited: Set[str] = set()
        rec_stack: Set[str] = set()
        cycles: List[List[str]] = []

        def dfs(node: str, path: List[str]):
            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            for dep in self._dependencies.get(node, []):
                neighbor = dep.target_id
                if neighbor not in visited:
                    dfs(neighbor, path)
                elif neighbor in rec_stack:
                    # Cycle found: extract cycle subpath
                    idx = path.index(neighbor)
                    cycles.append(path[idx:] + [neighbor])

            rec_stack.remove(node)
            path.pop()

        for node in list(self._dependencies.keys()):
            if node not in visited:
                dfs(node, [])

        return cycles

    def check_dependencies(
        self,
        source_id: str,
        resolved_ids: Set[str],
    ) -> Tuple[bool, List[str], List[str]]:
        """Evaluate dependencies for source_id against the set of resolved task/request IDs.

        Returns: (can_execute, missing_hard_deps, missing_soft_deps)
        - can_execute is True only if ALL hard dependencies are in resolved_ids.
        - missing_soft_deps can be non-empty; execution proceeds with an uncertainty marker.
        """
        deps = self._dependencies.get(source_id, [])
        missing_hard: List[str] = []
        missing_soft: List[str] = []

        for dep in deps:
            if dep.target_id not in resolved_ids:
                if dep.dependency_type == DependencyType.HARD:
                    missing_hard.append(dep.target_id)
                else:
                    missing_soft.append(dep.target_id)

        can_execute = (len(missing_hard) == 0)
        return can_execute, missing_hard, missing_soft

    def get_dependencies(self, source_id: str) -> List[CollaborationDependency]:
        """Get all dependencies that source_id relies upon."""
        return list(self._dependencies.get(source_id, []))

    def is_blocked(self, source_id: str, resolved_ids: Set[str]) -> bool:
        """Return True if source_id is blocked by unresolved hard dependencies."""
        can_exec, missing_hard, _ = self.check_dependencies(source_id, resolved_ids)
        return not can_exec

    def get_dependents(self, target_id: str) -> List[CollaborationDependency]:
        """Get all dependent items waiting upon target_id."""
        return list(self._reverse_dependencies.get(target_id, []))
