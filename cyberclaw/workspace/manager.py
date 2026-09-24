"""Persistent workspace manager for CyberClaw Core.

Guarantees isolation, atomic persistence, and protects trusted Core code
from unauthorized dynamic modifications.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional
from cyberclaw.evidence.models import Evidence
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.workspace.layout import WorkspaceLayout


class WorkspaceAccessError(Exception):
    """Raised when an operation attempts to breach workspace boundaries."""
    pass


class WorkspaceManager:
    """Manages persistent workspace storage for Core and Investigations."""

    def __init__(self, base_path: Path) -> None:
        self.base_path = base_path.resolve()
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.global_layout = WorkspaceLayout(self.base_path)
        self.global_layout.ensure_directories()

    def get_investigation_workspace(self, investigation_id: str) -> WorkspaceLayout:
        """Get or initialize an isolated workspace for a specific investigation."""
        # Sanitize investigation_id to prevent directory traversal
        safe_id = Path(investigation_id).name
        inv_dir = self.base_path / "investigations" / safe_id
        layout = WorkspaceLayout(inv_dir)
        layout.ensure_directories()
        return layout

    def atomic_write(self, target_path: Path, content: str) -> None:
        """Atomically write content to file using a temporary file to avoid corruption."""
        resolved = target_path.resolve()
        # Verify the file is strictly contained within base_path
        if not str(resolved).startswith(str(self.base_path)):
            raise WorkspaceAccessError(
                f"Attempted write outside workspace boundary: {resolved}"
            )

        resolved.parent.mkdir(parents=True, exist_ok=True)
        # Write to temporary file in the same directory, then rename
        with tempfile.NamedTemporaryFile("w", dir=resolved.parent, delete=False, encoding="utf-8") as tf:
            tf.write(content)
            temp_name = tf.name

        os.replace(temp_name, resolved)

    def read_text(self, target_path: Path) -> str:
        """Read text from a workspace file."""
        resolved = target_path.resolve()
        if not str(resolved).startswith(str(self.base_path)):
            raise WorkspaceAccessError(
                f"Attempted read outside workspace boundary: {resolved}"
            )
        return resolved.read_text(encoding="utf-8")

    def persist_evidence(self, investigation_id: str, evidence_list: List[Evidence]) -> Path:
        """Persist structured evidence list to investigation workspace."""
        layout = self.get_investigation_workspace(investigation_id)
        evidence_file = layout.evidence / "evidence.json"
        data = [json.loads(ev.model_dump_json()) for ev in evidence_list]
        self.atomic_write(evidence_file, json.dumps(data, indent=2))
        return evidence_file

    def load_evidence(self, investigation_id: str) -> List[Evidence]:
        """Load structured evidence list from investigation workspace."""
        layout = self.get_investigation_workspace(investigation_id)
        evidence_file = layout.evidence / "evidence.json"
        if not evidence_file.exists():
            return []
        raw = self.read_text(evidence_file)
        data = json.loads(raw)
        return [Evidence.model_validate(item) for item in data]

    def persist_experience(
        self, investigation_id: str, experiences: List[ExperienceRecord]
    ) -> Path:
        """Persist experience records to investigation workspace."""
        layout = self.get_investigation_workspace(investigation_id)
        exp_file = layout.experience / "experiences.json"
        data = [json.loads(exp.model_dump_json()) for exp in experiences]
        self.atomic_write(exp_file, json.dumps(data, indent=2))
        return exp_file

    def load_experience(self, investigation_id: str) -> List[ExperienceRecord]:
        """Load experience records from investigation workspace."""
        layout = self.get_investigation_workspace(investigation_id)
        exp_file = layout.experience / "experiences.json"
        if not exp_file.exists():
            return []
        raw = self.read_text(exp_file)
        data = json.loads(raw)
        return [ExperienceRecord.model_validate(item) for item in data]

    def persist_state(self, investigation_id: str, state_data: Dict[str, Any]) -> Path:
        """Persist investigation metadata and DFA state."""
        layout = self.get_investigation_workspace(investigation_id)
        state_file = layout.root / "state.json"
        self.atomic_write(state_file, json.dumps(state_data, indent=2, default=str))
        return state_file

    def load_state(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        """Load persisted investigation state if present."""
        layout = self.get_investigation_workspace(investigation_id)
        state_file = layout.root / "state.json"
        if not state_file.exists():
            return None
        raw = self.read_text(state_file)
        return json.loads(raw)

    def persist_snapshots(
        self, investigation_id: str, snapshots: List[Any]
    ) -> Path:
        """Persist investigation snapshots to the investigation workspace."""
        layout = self.get_investigation_workspace(investigation_id)
        index_file = layout.snapshots / "snapshots_index.json"
        data = [json.loads(s.model_dump_json()) for s in snapshots]
        self.atomic_write(index_file, json.dumps(data, indent=2))

        # Also write individual files
        for s in snapshots:
            snap_file = layout.snapshots / f"snapshot_{s.sequence:04d}.json"
            self.atomic_write(snap_file, json.dumps(json.loads(s.model_dump_json()), indent=2))

        return index_file

    def load_snapshots(self, investigation_id: str) -> List[Any]:
        """Load investigation snapshots from workspace."""
        from cyberclaw.case.models import InvestigationSnapshot
        layout = self.get_investigation_workspace(investigation_id)
        index_file = layout.snapshots / "snapshots_index.json"
        if not index_file.exists():
            return []
        raw = self.read_text(index_file)
        data = json.loads(raw)
        return [InvestigationSnapshot.model_validate(item) for item in data]

    def persist_journal(self, investigation_id: str, entries: List[Any]) -> Path:
        """Persist chronological case journal to workspace."""
        layout = self.get_investigation_workspace(investigation_id)
        journal_file = layout.journal / "journal.json"
        data = [json.loads(e.model_dump_json()) for e in entries]
        self.atomic_write(journal_file, json.dumps(data, indent=2))
        return journal_file

    def load_journal(self, investigation_id: str) -> List[Any]:
        """Load case journal from workspace."""
        from cyberclaw.case.models import JournalEntry
        layout = self.get_investigation_workspace(investigation_id)
        journal_file = layout.journal / "journal.json"
        if not journal_file.exists():
            return []
        raw = self.read_text(journal_file)
        data = json.loads(raw)
        return [JournalEntry.model_validate(item) for item in data]

    def persist_decisions(self, investigation_id: str, decisions: List[Any]) -> Path:
        """Persist decision history records to workspace."""
        layout = self.get_investigation_workspace(investigation_id)
        dec_file = layout.journal / "decisions.json"
        data = [json.loads(d.model_dump_json()) for d in decisions]
        self.atomic_write(dec_file, json.dumps(data, indent=2))
        return dec_file

    def load_decisions(self, investigation_id: str) -> List[Any]:
        """Load decision records from workspace."""
        from cyberclaw.case.models import DecisionRecord
        layout = self.get_investigation_workspace(investigation_id)
        dec_file = layout.journal / "decisions.json"
        if not dec_file.exists():
            return []
        raw = self.read_text(dec_file)
        data = json.loads(raw)
        return [DecisionRecord.model_validate(item) for item in data]

    def persist_branches(self, investigation_id: str, branches: List[Any]) -> Path:
        """Persist all investigation branches and their index to workspace."""
        from cyberclaw.branching.persistence import BranchPersistence
        for b in branches:
            BranchPersistence.persist_branch(self, b)
        return BranchPersistence.persist_branches_index(self, investigation_id, branches)

    def load_branches(self, investigation_id: str) -> List[Any]:
        """Load all persisted investigation branches from workspace."""
        from cyberclaw.branching.persistence import BranchPersistence
        return BranchPersistence.load_branches(self, investigation_id)


