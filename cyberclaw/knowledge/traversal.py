"""Safe, bounded graph traversal engine with cycle prevention and depth limits."""

from __future__ import annotations

from collections import deque
from typing import Any, List, Optional, Set

from cyberclaw.knowledge.models import EdgeStatus
from cyberclaw.knowledge.nodes import KnowledgeNode


def traverse(
    graph: Any,
    start_node_id: str,
    depth: int = 2,
    relationship_types: Optional[List[str]] = None,
    current_only: bool = True,
    direction: str = "both",
) -> List[KnowledgeNode]:
    """Execute bounded multi-hop graph traversal from a start node.

    Parameters:
    - graph: TemporalKnowledgeGraph instance
    - start_node_id: ID of the starting KnowledgeNode
    - depth: maximum hop distance (capped at 10 for deterministic safety)
    - relationship_types: optional list of edge types to follow
    - current_only: if True, traverse only currently active edges and nodes
    - direction: "out" (source->target), "in" (target->source), or "both"
    """
    bounded_depth = max(1, min(depth, 10))
    start_node = graph.get_node(start_node_id)
    if not start_node:
        return []

    visited_nodes: Set[str] = {start_node_id}
    result_nodes: List[KnowledgeNode] = []

    # Queue contains tuples of (node_id, current_hop_level)
    queue = deque([(start_node_id, 0)])

    rel_filter = set(relationship_types) if relationship_types else None

    while queue:
        curr_nid, hop = queue.popleft()
        if hop >= bounded_depth:
            continue

        candidate_edge_ids: Set[str] = set()
        if direction in ("out", "both"):
            candidate_edge_ids.update(graph._edges_by_source.get(curr_nid, set()))
        if direction in ("in", "both"):
            candidate_edge_ids.update(graph._edges_by_target.get(curr_nid, set()))

        for eid in candidate_edge_ids:
            edge = graph.get_edge(eid)
            if not edge:
                continue
            if current_only and edge.status != EdgeStatus.ACTIVE:
                continue
            if rel_filter and edge.relationship_type not in rel_filter:
                continue

            # Determine next node in traversal
            next_nid = edge.target_node_id if edge.source_node_id == curr_nid else edge.source_node_id
            if next_nid in visited_nodes:
                continue

            next_node = graph.get_node(next_nid)
            if not next_node:
                continue
            if current_only and next_node.valid_until is not None:
                continue

            visited_nodes.add(next_nid)
            result_nodes.append(next_node)
            queue.append((next_nid, hop + 1))

    return result_nodes
