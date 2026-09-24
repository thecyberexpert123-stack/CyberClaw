"""Atomic persistence for durable queue state, event logs, and idempotency mappings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from cyberclaw.runtime.idempotency import IdempotencyRegistry
from cyberclaw.runtime.queue import DurableTaskQueue


class RuntimePersistenceManager:
    """Manages atomic serialization and loading of runtime queue and idempotency records."""

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

        # 1. Queue tasks
        queue_data = queue.export_state()
        cls._atomic_write(
            runtime_dir / "queue.json",
            json.dumps(queue_data, indent=2, default=str),
        )

        # 2. Idempotency registry
        idemp_data = idempotency.export_state()
        cls._atomic_write(
            runtime_dir / "idempotency.json",
            json.dumps(idemp_data, indent=2, default=str),
        )

    @classmethod
    def load_state(
        cls,
        queue: DurableTaskQueue,
        idempotency: IdempotencyRegistry,
        base_dir: Path,
    ) -> bool:
        """Load persisted runtime state into queue and idempotency registry if present."""
        runtime_dir = base_dir / "runtime"
        queue_file = runtime_dir / "queue.json"
        idemp_file = runtime_dir / "idempotency.json"

        if not queue_file.exists():
            return False

        try:
            with open(queue_file, "r", encoding="utf-8") as f:
                queue_data = json.load(f)
                queue.import_state(queue_data)

            if idemp_file.exists():
                with open(idemp_file, "r", encoding="utf-8") as f:
                    idemp_data = json.load(f)
                    idempotency.import_state(idemp_data)
            return True
        except Exception:
            return False
