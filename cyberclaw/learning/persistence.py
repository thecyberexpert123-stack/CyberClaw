"""Atomic persistence for the learning ledger and registry snapshots."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Dict

from cyberclaw.learning.errors import LearningPersistenceError, LearningTamperError
from cyberclaw.learning.models import (
    CandidateBranchExperience,
    CollaborationPattern,
    FailurePattern,
    InvestigationExperience,
    InvestigationStrategy,
    LearningEvent,
    NormalizedExperience,
    ObservedPattern,
    PromotionThresholdPolicy,
    RegressionSignal,
    StrategyApprovalDecision,
    StrategyEvaluation,
    StrategyOutcome,
    canonical_digest,
)
from cyberclaw.learning.registry import LearningRegistry


class LearningPersistenceManager:
    """Save and reload learning state with a digest. Corruption is a hard failure."""

    FILENAME = "registry.json"
    DIGEST_FILENAME = "digest.json"

    @classmethod
    def save(cls, registry: LearningRegistry, workspace_path: Path) -> Path:
        base = Path(workspace_path) / "learning"
        base.mkdir(parents=True, exist_ok=True)
        payload = cls._dump(registry)
        digest = canonical_digest(payload)
        document = {"digest": digest, "payload": payload}
        target = base / cls.FILENAME
        cls._atomic_write(target, document)
        cls._atomic_write(base / cls.DIGEST_FILENAME, {"digest": digest})
        return target

    @classmethod
    def load(cls, workspace_path: Path, *, verify: bool = True) -> LearningRegistry:
        path = Path(workspace_path) / "learning" / cls.FILENAME
        if not path.exists():
            raise LearningPersistenceError(f"Learning registry file not found: {path}")
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise LearningTamperError(f"Learning registry is not valid JSON: {exc}") from exc
        payload = document.get("payload")
        recorded = document.get("digest")
        if not isinstance(payload, dict) or not recorded:
            raise LearningTamperError("Learning registry is missing payload or digest.")
        actual = canonical_digest(payload)
        if verify and actual != recorded:
            raise LearningTamperError(
                "Learning registry digest mismatch. Refusing to load potentially corrupted state.",
                details={"expected": recorded, "actual": actual},
            )
        digest_path = Path(workspace_path) / "learning" / cls.DIGEST_FILENAME
        if verify and digest_path.exists():
            side = json.loads(digest_path.read_text(encoding="utf-8"))
            if side.get("digest") != recorded:
                raise LearningTamperError("Learning digest sidecar does not match registry digest.")
        return cls._load(payload)

    @staticmethod
    def _atomic_write(path: Path, document: Dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(document, sort_keys=True, separators=(",", ":"))
        tmp_name = None
        try:
            with NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
                tmp_name = handle.name
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
        except Exception as exc:
            if tmp_name and os.path.exists(tmp_name):
                os.unlink(tmp_name)
            raise LearningPersistenceError(f"Atomic write failed for {path}: {exc}") from exc

    @classmethod
    def _dump(cls, registry: LearningRegistry) -> Dict[str, Any]:
        return {
            "active_threshold_policy_id": registry._active_threshold_policy_id,
            "active_threshold_policy_version": registry._active_threshold_policy_version,
            "threshold_policies": {
                pid: {ver: policy.model_dump(mode="json") for ver, policy in versions.items()}
                for pid, versions in registry._threshold_policies.items()
            },
            "experiences": {key: value.model_dump(mode="json") for key, value in registry._experiences.items()},
            "normalized": {key: value.model_dump(mode="json") for key, value in registry._normalized.items()},
            "patterns": {
                pid: {ver: pattern.model_dump(mode="json") for ver, pattern in versions.items()}
                for pid, versions in registry._patterns.items()
            },
            "strategies": {
                sid: {ver: strategy.model_dump(mode="json") for ver, strategy in versions.items()}
                for sid, versions in registry._strategies.items()
            },
            "evaluations": {
                sid: [item.model_dump(mode="json") for item in items]
                for sid, items in registry._evaluations.items()
            },
            "approvals": {
                sid: [item.model_dump(mode="json") for item in items]
                for sid, items in registry._approvals.items()
            },
            "outcomes": {
                sid: [item.model_dump(mode="json") for item in items]
                for sid, items in registry._outcomes.items()
            },
            "failure_patterns": {key: value.model_dump(mode="json") for key, value in registry._failure_patterns.items()},
            "collaboration_patterns": {
                key: value.model_dump(mode="json") for key, value in registry._collaboration_patterns.items()
            },
            "quarantine": {key: _dump_any(value) for key, value in registry._quarantine.items()},
            "regressions": [item.model_dump(mode="json") for item in registry._regressions],
            "events": [event.model_dump(mode="json") for event in registry.events],
        }

    @classmethod
    def _load(cls, payload: Dict[str, Any]) -> LearningRegistry:
        policies = payload.get("threshold_policies") or {}
        first_policy = None
        for versions in policies.values():
            for body in versions.values():
                first_policy = PromotionThresholdPolicy.model_validate(body)
                break
            if first_policy:
                break
        registry = LearningRegistry(threshold_policy=first_policy)
        # Rebuild from the persisted snapshot rather than replaying detection.
        registry._events = []
        registry._threshold_policies = {}
        for pid, versions in policies.items():
            registry._threshold_policies[pid] = {
                ver: PromotionThresholdPolicy.model_validate(body) for ver, body in versions.items()
            }
        registry._active_threshold_policy_id = payload["active_threshold_policy_id"]
        registry._active_threshold_policy_version = payload["active_threshold_policy_version"]
        registry._experiences = {
            key: InvestigationExperience.model_validate(body) for key, body in payload.get("experiences", {}).items()
        }
        registry._normalized = {
            key: NormalizedExperience.model_validate(body) for key, body in payload.get("normalized", {}).items()
        }
        registry._patterns = {
            pid: {ver: ObservedPattern.model_validate(body) for ver, body in versions.items()}
            for pid, versions in payload.get("patterns", {}).items()
        }
        registry._strategies = {
            sid: {ver: InvestigationStrategy.model_validate(body) for ver, body in versions.items()}
            for sid, versions in payload.get("strategies", {}).items()
        }
        registry._evaluations = {
            sid: [StrategyEvaluation.model_validate(item) for item in items]
            for sid, items in payload.get("evaluations", {}).items()
        }
        registry._approvals = {
            sid: [StrategyApprovalDecision.model_validate(item) for item in items]
            for sid, items in payload.get("approvals", {}).items()
        }
        registry._outcomes = {
            sid: [StrategyOutcome.model_validate(item) for item in items]
            for sid, items in payload.get("outcomes", {}).items()
        }
        registry._failure_patterns = {
            key: FailurePattern.model_validate(body) for key, body in payload.get("failure_patterns", {}).items()
        }
        registry._collaboration_patterns = {
            key: CollaborationPattern.model_validate(body)
            for key, body in payload.get("collaboration_patterns", {}).items()
        }
        registry._quarantine = payload.get("quarantine", {})
        registry._regressions = [RegressionSignal.model_validate(item) for item in payload.get("regressions", [])]
        registry._events = [LearningEvent.model_validate(item) for item in payload.get("events", [])]
        return registry


def _dump_any(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value
