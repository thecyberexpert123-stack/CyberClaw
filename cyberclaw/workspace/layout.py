"""Workspace layout conventions for CyberClaw persistent working state."""

from __future__ import annotations

from pathlib import Path
from typing import Dict


class WorkspaceLayout:
    """Standardized directory layout for persistent agent workspaces."""

    SUBDIRECTORIES = [
        "skills",        # Proposed or verified reusable skills
        "workflows",     # Composite playbooks and investigation workflows
        "experiments",   # Isolated sandbox experiments and tests
        "memory",        # Case facts and working memory files
        "experience",    # Operational experience logs and lessons
        "evidence",      # Normalized structured evidence objects
        "artifacts",     # Raw outputs, captures, logs, and files
        "snapshots",     # Point-in-time sealed investigation snapshots
        "journal",       # Chronological case journal and decision trail
        "branches",      # Isolated branch contexts and counterfactual history
        "collaboration", # Collaboration requests, conflicts, and dependency graphs
        "knowledge",     # Temporal Knowledge Graph nodes, edges, manifests, integrity
    ]

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.skills = self.root / "skills"
        self.workflows = self.root / "workflows"
        self.experiments = self.root / "experiments"
        self.memory = self.root / "memory"
        self.experience = self.root / "experience"
        self.evidence = self.root / "evidence"
        self.artifacts = self.root / "artifacts"
        self.snapshots = self.root / "snapshots"
        self.journal = self.root / "journal"
        self.branches = self.root / "branches"
        self.collaboration = self.root / "collaboration"
        self.knowledge = self.root / "knowledge"

    def ensure_directories(self) -> None:
        """Create all standard workspace subdirectories if they do not exist."""
        for subdir_name in self.SUBDIRECTORIES:
            path = self.root / subdir_name
            path.mkdir(parents=True, exist_ok=True)

    def as_dict(self) -> Dict[str, Path]:
        """Return layout paths as dictionary."""
        return {
            "root": self.root,
            "skills": self.skills,
            "workflows": self.workflows,
            "experiments": self.experiments,
            "memory": self.memory,
            "experience": self.experience,
            "evidence": self.evidence,
            "artifacts": self.artifacts,
            "snapshots": self.snapshots,
            "journal": self.journal,
        }
