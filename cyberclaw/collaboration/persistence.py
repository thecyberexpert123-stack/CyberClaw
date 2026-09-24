"""Atomic persistence operations for collaboration requests, conflicts, and dependency records."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from cyberclaw.collaboration.conflicts import ConflictManager
from cyberclaw.collaboration.coordinator import CollaborationCoordinator
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    CollaborationStatus,
    ConflictStatus,
    ConflictType,
    ContextSensitivity,
    SpecialistConflict,
)


class CollaborationPersistenceManager:
    """Manages atomic serialization and loading of collaboration requests and conflict history."""

    @staticmethod
    def _atomic_write(file_path: Path, data: str) -> None:
        file_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = file_path.with_suffix(f"{file_path.suffix}.tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
        tmp_path.replace(file_path)

    @classmethod
    def persist_state(
        cls,
        coordinator: CollaborationCoordinator,
        base_dir: Path,
    ) -> None:
        """Atomically persist collaboration requests and conflicts to disk under collaboration/ directory."""
        collab_dir = base_dir / "collaboration"
        collab_dir.mkdir(parents=True, exist_ok=True)

        # 1. Requests
        requests_data = [
            req.model_dump(mode="json")
            for req in coordinator._requests.values()
        ]
        cls._atomic_write(
            collab_dir / "requests.json",
            json.dumps(requests_data, indent=2, default=str),
        )

        # 2. Conflicts
        conflicts_data = [
            conf.model_dump(mode="json")
            for conf in coordinator.conflict_manager.list_conflicts()
        ]
        cls._atomic_write(
            collab_dir / "conflicts.json",
            json.dumps(conflicts_data, indent=2, default=str),
        )

    @classmethod
    def load_state(
        cls,
        coordinator: CollaborationCoordinator,
        base_dir: Path,
    ) -> bool:
        """Load persisted requests and conflicts into coordinator."""
        collab_dir = base_dir / "collaboration"
        req_file = collab_dir / "requests.json"
        conf_file = collab_dir / "conflicts.json"

        if not req_file.exists():
            return False

        try:
            with open(req_file, "r", encoding="utf-8") as f:
                reqs = json.load(f)
                for r in reqs:
                    request = CollaborationRequest(**r)
                    coordinator._requests[request.request_id] = request
                    if request.status == CollaborationStatus.COMPLETED:
                        coordinator._resolved_ids.add(request.request_id)

            if conf_file.exists():
                with open(conf_file, "r", encoding="utf-8") as f:
                    confs = json.load(f)
                    for c in confs:
                        conflict = SpecialistConflict(**c)
                        coordinator.conflict_manager.register_conflict(conflict)
            return True
        except Exception:
            return False
