"""Controlled corruption of persisted files. Never repairs authoritative history."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from cyberclaw.chaos.models import CorruptionClass


def classify_text(text: str, *, expect_object: bool = False) -> Optional[CorruptionClass]:
    """Classify a document without importing it into authoritative state."""
    if text is None:
        return CorruptionClass.MISSING_RECORD
    if not text.strip():
        return CorruptionClass.TRUNCATION
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        tail = text.rstrip()[-1:] if text.rstrip() else ""
        if tail not in ("}", "]"):
            return CorruptionClass.TRUNCATION
        return CorruptionClass.INVALID_JSON
    if expect_object and not isinstance(payload, dict):
        return CorruptionClass.INVALID_SCHEMA
    if not expect_object and not isinstance(payload, (dict, list)):
        return CorruptionClass.INVALID_SCHEMA
    return None


def truncate(path: Path, keep: int = 8) -> None:
    raw = path.read_text(encoding="utf-8")
    path.write_text(raw[:keep], encoding="utf-8")


def invalidate_json(path: Path) -> None:
    path.write_text("{not-json", encoding="utf-8")


def modify_record(path: Path, replacement: str) -> None:
    path.write_text(replacement, encoding="utf-8")


def break_digest(path: Path) -> None:
    document = json.loads(path.read_text(encoding="utf-8"))
    document["digest"] = "0" * 64
    path.write_text(json.dumps(document), encoding="utf-8")


def journal_sequences(entries: list) -> list:
    return [int(getattr(entry, "sequence", entry.get("sequence"))) for entry in entries]


def has_sequence_gap(sequences: list) -> bool:
    if not sequences:
        return False
    return sequences != list(range(1, len(sequences) + 1))
