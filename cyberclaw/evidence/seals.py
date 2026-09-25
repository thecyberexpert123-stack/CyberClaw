"""Sealed evidence payloads for historical replay.

Replay must not treat the live evidence object as the historical record.
These helpers copy a payload at ingestion time. They do not execute providers
or authorize anything.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional

from cyberclaw.evidence.models import Evidence


def seal_evidence(evidence: Evidence) -> Dict[str, Any]:
    """Return a JSON-safe snapshot and digest of one evidence object."""
    record = evidence.model_dump(mode="json")
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    return {
        "id": evidence.id,
        "digest": hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
        "record": record,
    }


def evidence_digest(evidence: Evidence) -> str:
    """Digest the evidence object as it exists now."""
    return seal_evidence(evidence)["digest"]


def evidence_from_seal(seal: Dict[str, Any]) -> Evidence:
    """Restore the payload captured at ingestion."""
    return Evidence.model_validate(seal["record"])


def select_historical_evidence(
    evidence_id: str,
    live_evidence: list,
    seals: Dict[str, Dict[str, Any]],
) -> Optional[Evidence]:
    """Prefer the ingestion seal when the live object has changed.

    An unchanged live object is copied through so existing reconstructions
    keep their original round-trip behavior. A changed live object is not
    allowed to rewrite history.
    """
    live = next((item for item in live_evidence if getattr(item, "id", None) == evidence_id), None)
    seal = seals.get(evidence_id)
    if seal and live is not None and evidence_digest(live) != seal.get("digest"):
        return evidence_from_seal(seal)
    if live is not None:
        return live.model_copy(deep=True)
    if seal:
        return evidence_from_seal(seal)
    return None
