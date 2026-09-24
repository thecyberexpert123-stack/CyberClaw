"""Isolated persistent workspace manager for the OSINT Specialist."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any, Dict, List, Optional
from cyberclaw.evidence.models import Evidence
from cyberclaw.workspace.layout import WorkspaceLayout


class OSINTWorkspaceManager:
    """Manages files and persistence exclusively within the OSINT Specialist boundary."""

    def __init__(self, base_path: Optional[Path] = None) -> None:
        self.base_path = (base_path or Path("./workspace/specialists/osint")).resolve()
        self.layout = WorkspaceLayout(self.base_path)
        self.layout.ensure_directories()

    def get_investigation_workspace(self, investigation_id: str) -> WorkspaceLayout:
        """Create or retrieve isolated workspace for a specific OSINT inquiry."""
        safe_id = Path(investigation_id).name
        inv_dir = self.base_path / "investigations" / safe_id
        layout = WorkspaceLayout(inv_dir)
        layout.ensure_directories()
        return layout

    def atomic_write(self, target_path: Path, content: str) -> None:
        """Atomically write text into specialist workspace preventing file corruption."""
        resolved = target_path.resolve()
        if not str(resolved).startswith(str(self.base_path)):
            raise PermissionError(
                f"OSINT Specialist attempted write outside specialist workspace: {resolved}"
            )

        resolved.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", dir=resolved.parent, delete=False, encoding="utf-8") as tf:
            tf.write(content)
            temp_name = tf.name

        os.replace(temp_name, resolved)

    def read_text(self, target_path: Path) -> str:
        resolved = target_path.resolve()
        if not str(resolved).startswith(str(self.base_path)):
            raise PermissionError(
                f"OSINT Specialist attempted read outside specialist workspace: {resolved}"
            )
        return resolved.read_text(encoding="utf-8")

    def persist_local_evidence(self, investigation_id: str, evidence_list: List[Evidence]) -> Path:
        layout = self.get_investigation_workspace(investigation_id)
        file_path = layout.evidence / "local_evidence.json"
        data = [json.loads(ev.model_dump_json()) for ev in evidence_list]
        self.atomic_write(file_path, json.dumps(data, indent=2))
        return file_path

    def load_local_evidence(self, investigation_id: str) -> List[Evidence]:
        layout = self.get_investigation_workspace(investigation_id)
        file_path = layout.evidence / "local_evidence.json"
        if not file_path.exists():
            return []
        data = json.loads(self.read_text(file_path))
        return [Evidence.model_validate(item) for item in data]

    def persist_investigation_state(self, investigation_id: str, state_dict: Dict[str, Any]) -> Path:
        layout = self.get_investigation_workspace(investigation_id)
        file_path = layout.root / "investigation_state.json"
        self.atomic_write(file_path, json.dumps(state_dict, indent=2, default=str))
        return file_path

    def load_investigation_state(self, investigation_id: str) -> Optional[Dict[str, Any]]:
        layout = self.get_investigation_workspace(investigation_id)
        file_path = layout.root / "investigation_state.json"
        if not file_path.exists():
            return None
        return json.loads(self.read_text(file_path))
