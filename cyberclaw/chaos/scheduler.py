"""Deterministic interleaving. No wall-clock races."""

from __future__ import annotations

import hashlib
import json
from typing import Callable, Dict, List


class DeterministicInterleaver:
    """Runs a recorded action sequence. A seed is stored even when the sequence is explicit."""

    def __init__(self, seed: int, actions: Dict[str, Callable[[], str]]) -> None:
        self.seed = seed
        self.actions = actions
        self.trace: List[str] = []

    def run(self, sequence: List[str]) -> List[str]:
        self.trace = []
        for name in sequence:
            if name not in self.actions:
                raise KeyError(f"Interleaving action '{name}' is not registered.")
            detail = self.actions[name]() or ""
            self.trace.append(f"{name}:{detail}")
        return list(self.trace)

    def digest(self) -> str:
        payload = {"seed": self.seed, "trace": self.trace}
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()
