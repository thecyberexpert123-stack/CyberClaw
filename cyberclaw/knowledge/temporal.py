"""Temporal semantics, interval evaluation, and temporal contradiction classification."""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Tuple

from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.models import TemporalContradictionType, utc_now


def is_active(
    valid_from: datetime,
    valid_until: Optional[datetime],
    at_time: Optional[datetime] = None,
) -> bool:
    """Evaluate if an entity or edge is active at the specified timestamp (defaults to current time)."""
    check_time = at_time or utc_now()
    if check_time < valid_from:
        return False
    if valid_until and check_time >= valid_until:
        return False
    return True


def intervals_overlap(
    start_a: datetime,
    end_a: Optional[datetime],
    start_b: datetime,
    end_b: Optional[datetime],
) -> bool:
    """Determine if two temporal validity intervals overlap."""
    # If a ends before b starts
    if end_a and end_a <= start_b:
        return False
    # If b ends before a starts
    if end_b and end_b <= start_a:
        return False
    return True


def classify_temporal_contradiction(
    edge_a: KnowledgeEdge,
    edge_b: KnowledgeEdge,
    stale_threshold_seconds: float = 86400.0,
) -> Tuple[TemporalContradictionType, str]:
    """Classify whether a contradiction between two edges is temporal or simultaneous."""
    overlap = intervals_overlap(
        edge_a.valid_from, edge_a.valid_until,
        edge_b.valid_from, edge_b.valid_until,
    )

    if not overlap:
        # Determine temporal progression
        if edge_a.valid_until and edge_a.valid_until <= edge_b.valid_from:
            return (
                TemporalContradictionType.TEMPORAL_CHANGE,
                f"Relationship transitioned over time: Edge '{edge_a.edge_id}' was valid until {edge_a.valid_until.isoformat()} prior to Edge '{edge_b.edge_id}' commencing at {edge_b.valid_from.isoformat()}.",
            )
        elif edge_b.valid_until and edge_b.valid_until <= edge_a.valid_from:
            return (
                TemporalContradictionType.TEMPORAL_CHANGE,
                f"Relationship transitioned over time: Edge '{edge_b.edge_id}' was valid until {edge_b.valid_until.isoformat()} prior to Edge '{edge_a.edge_id}' commencing at {edge_a.valid_from.isoformat()}.",
            )

    # If overlapping, check if one edge is significantly older/stale
    time_diff = abs((edge_a.created_at - edge_b.created_at).total_seconds())
    if time_diff > stale_threshold_seconds:
        older = edge_a if edge_a.created_at < edge_b.created_at else edge_b
        newer = edge_b if edge_a.created_at < edge_b.created_at else edge_a
        return (
            TemporalContradictionType.STALE_INFORMATION,
            f"Edge '{older.edge_id}' (created {older.created_at.isoformat()}) may represent stale information superseded by Edge '{newer.edge_id}' (created {newer.created_at.isoformat()}).",
        )

    # Overlapping intervals with concurrent disagreement
    return (
        TemporalContradictionType.SIMULTANEOUS_CONTRADICTION,
        f"Edges '{edge_a.edge_id}' and '{edge_b.edge_id}' make competing assertions concurrently across overlapping validity intervals.",
    )
