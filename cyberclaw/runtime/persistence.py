"""Atomic persistence for durable queue state, event logs, and idempotency mappings."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List
from cyberclaw.authority.models import PersistenceDocumentState
from cyberclaw.runtime.errors import PersistenceError
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.models import RuntimeTask
from cyberclaw.runtime.queue import DurableTaskQueue


def _digest_texts(*parts: str) -> str:
    raw = "\n".join(parts).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _read_json(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        raise PersistenceError(
            f"Runtime persistence file is empty: {path.name}",
            corruption_class="TRUNCATION",
        )
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        tail = text.rstrip()[-1:] if text.rstrip() else ""
        kind = "TRUNCATION" if tail not in ("}", "]") else "INVALID_JSON"
        raise PersistenceError(
            f"Runtime persistence file {path.name} is not valid JSON: {exc}",
            corruption_class=kind,
        ) from exc


class RuntimePersistenceManager:
    """Manages atomic serialization and loading of runtime queue and idempotency records.

    A present but unreadable record is corruption, not an empty queue. Loading
    validates the full document before mutating in-memory state.
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
        queue: DurableTaskQueue,
        idempotency: IdempotencyRegistry,
        base_dir: Path,
    ) -> None:
        """Atomically persist runtime queue and idempotency state to disk."""
        runtime_dir = base_dir / "runtime"
        runtime_dir.mkdir(parents=True, exist_ok=True)

        queue_data = queue.export_state()
        idemp_data = idempotency.export_state()
        queue_text = json.dumps(queue_data, indent=2, default=str)
        idemp_text = json.dumps(idemp_data, indent=2, default=str)
        cls._atomic_write(runtime_dir / "queue.json", queue_text)
        cls._atomic_write(runtime_dir / "idempotency.json", idemp_text)
        cls._atomic_write(
            runtime_dir / "digest.json",
            json.dumps({"digest": _digest_texts(queue_text, idemp_text)}, indent=2),
        )

    @classmethod
    def load_state(
        cls,
        queue: DurableTaskQueue,
        idempotency: IdempotencyRegistry,
        base_dir: Path,
    ) -> bool:
        """Load persisted runtime state. Missing files mean no state. Corruption raises."""
        runtime_dir = base_dir / "runtime"
        queue_file = runtime_dir / "queue.json"
        idemp_file = runtime_dir / "idempotency.json"
        digest_file = runtime_dir / "digest.json"

        present = [path.exists() for path in (queue_file, idemp_file, digest_file)]
        if not any(present):
            return False
        if not all(present):
            raise PersistenceError(
                "Runtime persistence is partial. Refusing to treat a missing companion record as an empty queue.",
                corruption_class="MISSING_RECORD",
            )

        queue_text = queue_file.read_text(encoding="utf-8")
        idemp_text = idemp_file.read_text(encoding="utf-8")
        queue_data = _read_json(queue_file)
        idemp_data = _read_json(idemp_file)
        digest_data = _read_json(digest_file)
        if not isinstance(queue_data, list):
            raise PersistenceError("Runtime queue must be a list.", corruption_class="INVALID_SCHEMA")
        if not isinstance(idemp_data, dict):
            raise PersistenceError("Runtime idempotency record must be an object.", corruption_class="INVALID_SCHEMA")
        if not isinstance(digest_data, dict) or "digest" not in digest_data:
            raise PersistenceError("Runtime digest file is invalid.", corruption_class="INVALID_SCHEMA")

        actual = _digest_texts(queue_text, idemp_text)
        if actual != digest_data["digest"]:
            raise PersistenceError(
                "Runtime persistence digest mismatch. Refusing to load corrupted state.",
                corruption_class="DIGEST_MISMATCH",
            )

        parsed: List[RuntimeTask] = []
        for index, item in enumerate(queue_data):
            if not isinstance(item, dict) or not item.get("task_id") or not item.get("investigation_id"):
                raise PersistenceError(
                    f"Runtime queue item {index} is missing required identity fields.",
                    corruption_class="INVALID_SCHEMA",
                )
            try:
                parsed.append(RuntimeTask.model_validate(item))
            except Exception as exc:
                raise PersistenceError(
                    f"Runtime queue item {index} failed schema validation: {exc}",
                    corruption_class="INVALID_SCHEMA",
                ) from exc

        # Commit only after the full document validates. Never partial-import.
        queue.import_state([task.model_dump(mode="json") for task in parsed])
        idempotency.import_state(idemp_data)
        return True

    @classmethod
    def classify_directory(cls, base_dir: Path) -> tuple[str, str]:
        """Classify a runtime directory without importing it.

        MISSING, EMPTY_VALID, POPULATED_VALID, PARTIAL, and CORRUPT are distinct.
        An empty file is corruption, not a valid empty document.
        """
        runtime_dir = base_dir / "runtime"
        queue_file = runtime_dir / "queue.json"
        idemp_file = runtime_dir / "idempotency.json"
        digest_file = runtime_dir / "digest.json"
        present = [path for path in (queue_file, idemp_file, digest_file) if path.exists()]
        if not present:
            return PersistenceDocumentState.MISSING.value, "no runtime persistence files"
        if len(present) != 3:
            return PersistenceDocumentState.PARTIAL.value, "companion runtime record is missing"
        try:
            queue_text = queue_file.read_text(encoding="utf-8")
            idemp_text = idemp_file.read_text(encoding="utf-8")
            queue_data = _read_json(queue_file)
            idemp_data = _read_json(idemp_file)
            digest_data = _read_json(digest_file)
        except PersistenceError as exc:
            return PersistenceDocumentState.CORRUPT.value, exc.corruption_class
        if not isinstance(queue_data, list) or not isinstance(idemp_data, dict):
            return PersistenceDocumentState.CORRUPT.value, "INVALID_SCHEMA"
        if not isinstance(digest_data, dict) or "digest" not in digest_data:
            return PersistenceDocumentState.CORRUPT.value, "INVALID_SCHEMA"
        if _digest_texts(queue_text, idemp_text) != digest_data["digest"]:
            return PersistenceDocumentState.CORRUPT.value, "DIGEST_MISMATCH"
        for item in queue_data:
            if not isinstance(item, dict) or not item.get("task_id") or not item.get("investigation_id"):
                return PersistenceDocumentState.CORRUPT.value, "INVALID_SCHEMA"
        populated = bool(queue_data) or any(
            idemp_data.get(key) for key in ("seen_events", "event_keys", "authorizations", "executions")
        )
        if populated:
            return PersistenceDocumentState.POPULATED_VALID.value, "digest matches populated runtime state"
        return PersistenceDocumentState.EMPTY_VALID.value, "digest matches an empty runtime document"
