"""Semantic version ordering.

``1.10.0`` is newer than ``1.9.0``. String sort is not version order.
"""

from __future__ import annotations


def semantic_version_key(version: str) -> tuple:
    """Order dotted versions numerically. Non-numeric pieces sort after numbers."""
    parts = []
    for piece in (version or "").split("."):
        try:
            parts.append((0, int(piece)))
        except ValueError:
            parts.append((1, piece))
    return tuple(parts)
