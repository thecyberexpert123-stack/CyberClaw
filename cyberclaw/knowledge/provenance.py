"""Knowledge provenance records, backward lineage tracing, and source independence evaluation."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field

from cyberclaw.knowledge.models import utc_now


class KnowledgeProvenanceRecord(BaseModel):
    """Immutable audit record binding graph objects to their generating execution lineage."""

    model_config = ConfigDict(frozen=True)

    provenance_id: str = Field(default_factory=lambda: str(uuid4()))
    target_id: str = Field(description="ID of node or edge described by this record")
    originating_specialist: Optional[str] = None
    capability_id: Optional[str] = None
    capability_version: Optional[str] = None
    provider_id: Optional[str] = None
    authorization_decision_id: Optional[str] = None
    upstream_evidence_ids: List[str] = Field(default_factory=list)
    parent_provenance_ids: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)
    metadata: Dict[str, Any] = Field(default_factory=dict)


def build_provenance_chain(
    provenance_records: Dict[str, KnowledgeProvenanceRecord],
    start_provenance_ids: List[str],
) -> List[KnowledgeProvenanceRecord]:
    """Recursively reconstruct complete upstream provenance chain without duplicates."""
    chain: List[KnowledgeProvenanceRecord] = []
    visited: Set[str] = set()
    queue = list(start_provenance_ids)

    while queue:
        current_id = queue.pop(0)
        if current_id in visited:
            continue
        visited.add(current_id)
        rec = provenance_records.get(current_id)
        if rec:
            chain.append(rec)
            for parent_id in rec.parent_provenance_ids:
                if parent_id not in visited:
                    queue.append(parent_id)

    return sorted(chain, key=lambda r: r.timestamp)


def calculate_source_independence(
    supporting_evidence_ids: List[str],
    evidence_items: List[Any],
) -> Tuple[int, List[str]]:
    """Determine the count of genuinely independent source roots supporting a set of evidence IDs.

    Prevents artificial consensus caused by multiple evidence objects sharing identical upstream sources or derived inferences.
    """
    evidence_map = {e.id: e for e in evidence_items if hasattr(e, "id")}
    selected_evidence = [evidence_map[eid] for eid in supporting_evidence_ids if eid in evidence_map]

    if not selected_evidence:
        return 0, []

    # Cluster evidence items by shared source roots or direct derivations
    clusters: List[List[Any]] = []
    for ev in selected_evidence:
        placed = False
        src_name = getattr(getattr(ev, "source", None), "name", None) or getattr(getattr(ev, "source", None), "id", "")
        src_name_norm = str(src_name).strip().lower()

        derived_from = set(getattr(ev, "metadata", {}).get("derived_from_evidence_ids", []))
        same_source = getattr(ev, "metadata", {}).get("same_source_as")

        for cluster in clusters:
            rep = cluster[0]
            rep_src = getattr(getattr(rep, "source", None), "name", None) or getattr(getattr(rep, "source", None), "id", "")
            rep_src_norm = str(rep_src).strip().lower()

            # 1. Matching source identity/name
            if src_name_norm and rep_src_norm and src_name_norm == rep_src_norm:
                cluster.append(ev)
                placed = True
                break

            # 2. Explicit same_source marker
            if same_source and (same_source == rep.id or same_source in [c.id for c in cluster]):
                cluster.append(ev)
                placed = True
                break

            # 3. Direct derivation chain if pure inference
            is_inference = getattr(ev, "metadata", {}).get("finding_nature") == "INFERENCE" or getattr(getattr(ev, "source", None), "type", "") == "inference"
            if is_inference and rep.id in derived_from:
                cluster.append(ev)
                placed = True
                break

        if not placed:
            clusters.append([ev])

    independent_count = len(clusters)
    root_sources: List[str] = []
    for cluster in clusters:
        rep = cluster[0]
        name = getattr(getattr(rep, "source", None), "name", None) or getattr(getattr(rep, "source", None), "id", None) or rep.id
        root_sources.append(str(name))

    return independent_count, root_sources
