"""Atomic persistence operations for collaboration requests, conflicts, and dependency records."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from cyberclaw.authority.models import PersistenceDocumentState
from cyberclaw.collaboration.coordinator import CollaborationCoordinator
from cyberclaw.collaboration.errors import CollaborationPersistenceError
from cyberclaw.collaboration.models import (
    CollaborationRequest,
    CollaborationStatus,
    SpecialistConflict,
)


def _digest_texts(*parts: str) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def _read_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise CollaborationPersistenceError(
            f"Collaboration file is empty: {path.name}",
            corruption_class="TRUNCATION",
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        tail = text.rstrip()[-1:] if text.rstrip() else ""
        kind = "TRUNCATION" if tail not in ("}", "]") else "INVALID_JSON"
        raise CollaborationPersistenceError(
            f"Collaboration file {path.name} is not valid JSON: {exc}",
            corruption_class=kind,
        ) from exc


class CollaborationPersistenceManager:
    """Manages atomic serialization and loading of collaboration requests and conflict history.

    Corruption is reported by class and does not partially replace in-memory requests.
    """

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

        requests_data = [req.model_dump(mode="json") for req in coordinator._requests.values()]
        conflicts_data = [conf.model_dump(mode="json") for conf in coordinator.conflict_manager.list_conflicts()]
        requests_text = json.dumps(requests_data, indent=2, default=str)
        conflicts_text = json.dumps(conflicts_data, indent=2, default=str)
        cls._atomic_write(collab_dir / "requests.json", requests_text)
        cls._atomic_write(collab_dir / "conflicts.json", conflicts_text)
        cls._atomic_write(
            collab_dir / "digest.json",
            json.dumps({"digest": _digest_texts(requests_text, conflicts_text)}, indent=2),
        )

    @classmethod
    def load_state(
        cls,
        coordinator: CollaborationCoordinator,
        base_dir: Path,
    ) -> bool:
        """Load persisted requests and conflicts. Missing files mean no state. Corruption raises."""
        collab_dir = base_dir / "collaboration"
        req_file = collab_dir / "requests.json"
        conf_file = collab_dir / "conflicts.json"
        digest_file = collab_dir / "digest.json"

        present = [path.exists() for path in (req_file, conf_file, digest_file)]
        if not any(present):
            return False
        if not all(present):
            raise CollaborationPersistenceError(
                "Collaboration history is incomplete. Refusing to load a partial record.",
                corruption_class="MISSING_RECORD",
            )

        requests_text = req_file.read_text(encoding="utf-8")
        conflicts_text = conf_file.read_text(encoding="utf-8")
        requests_data = _read_json(req_file)
        conflicts_data = _read_json(conf_file)
        digest_data = _read_json(digest_file)
        if not isinstance(requests_data, list) or not isinstance(conflicts_data, list):
            raise CollaborationPersistenceError(
                "Collaboration persistence schema is invalid.",
                corruption_class="INVALID_SCHEMA",
            )
        if not isinstance(digest_data, dict) or "digest" not in digest_data:
            raise CollaborationPersistenceError(
                "Collaboration digest file is invalid.",
                corruption_class="INVALID_SCHEMA",
            )
        actual = _digest_texts(requests_text, conflicts_text)
        if actual != digest_data["digest"]:
            raise CollaborationPersistenceError(
                "Collaboration persistence digest mismatch. Refusing to load corrupted state.",
                corruption_class="DIGEST_MISMATCH",
            )

        parsed_requests: List[CollaborationRequest] = []
        for index, body in enumerate(requests_data):
            if not isinstance(body, dict) or not body.get("request_id"):
                raise CollaborationPersistenceError(
                    f"Collaboration request {index} is missing request_id.",
                    corruption_class="INVALID_SCHEMA",
                )
            try:
                parsed_requests.append(CollaborationRequest.model_validate(body))
            except Exception as exc:
                raise CollaborationPersistenceError(
                    f"Collaboration request {index} failed schema validation: {exc}",
                    corruption_class="INVALID_SCHEMA",
                ) from exc
        parsed_conflicts: List[SpecialistConflict] = []
        for index, body in enumerate(conflicts_data):
            try:
                parsed_conflicts.append(SpecialistConflict.model_validate(body))
            except Exception as exc:
                raise CollaborationPersistenceError(
                    f"Collaboration conflict {index} failed schema validation: {exc}",
                    corruption_class="INVALID_SCHEMA",
                ) from exc

        for request in parsed_requests:
            coordinator._requests[request.request_id] = request
            if request.status == CollaborationStatus.COMPLETED:
                coordinator._resolved_ids.add(request.request_id)
        for conflict in parsed_conflicts:
            coordinator.conflict_manager.register_conflict(conflict)
        return True

    @classmethod
    def classify_directory(cls, base_dir: Path) -> tuple[str, str]:
        """Classify collaboration files without importing them."""
        collab_dir = base_dir / "collaboration"
        req_file = collab_dir / "requests.json"
        conf_file = collab_dir / "conflicts.json"
        digest_file = collab_dir / "digest.json"
        present = [path for path in (req_file, conf_file, digest_file) if path.exists()]
        if not present:
            return PersistenceDocumentState.MISSING.value, "no collaboration persistence files"
        if len(present) != 3:
            return PersistenceDocumentState.PARTIAL.value, "companion collaboration record is missing"
        try:
            requests_text = req_file.read_text(encoding="utf-8")
            conflicts_text = conf_file.read_text(encoding="utf-8")
            requests_data = _read_json(req_file)
            conflicts_data = _read_json(conf_file)
            digest_data = _read_json(digest_file)
        except CollaborationPersistenceError as exc:
            return PersistenceDocumentState.CORRUPT.value, exc.corruption_class
        if not isinstance(requests_data, list) or not isinstance(conflicts_data, list):
            return PersistenceDocumentState.CORRUPT.value, "INVALID_SCHEMA"
        if not isinstance(digest_data, dict) or "digest" not in digest_data:
            return PersistenceDocumentState.CORRUPT.value, "INVALID_SCHEMA"
        if _digest_texts(requests_text, conflicts_text) != digest_data["digest"]:
            return PersistenceDocumentState.CORRUPT.value, "DIGEST_MISMATCH"
        if requests_data or conflicts_data:
            return PersistenceDocumentState.POPULATED_VALID.value, "digest matches populated collaboration state"
        return PersistenceDocumentState.EMPTY_VALID.value, "digest matches an empty collaboration document"
