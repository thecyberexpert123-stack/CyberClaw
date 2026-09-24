"""Atomic, crash-safe, and verifiable persistence for TemporalKnowledgeGraph."""

from __future__ import annotations

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional

from cyberclaw.knowledge.edges import KnowledgeEdge
from cyberclaw.knowledge.errors import (
    KnowledgeIntegrityError,
    KnowledgePersistenceError,
)
from cyberclaw.knowledge.graph import TemporalKnowledgeGraph
from cyberclaw.knowledge.models import utc_now
from cyberclaw.knowledge.nodes import KnowledgeNode
from cyberclaw.knowledge.provenance import KnowledgeProvenanceRecord


class KnowledgePersistenceManager:
    """Manages atomic serialization and verifiable restoration of Knowledge Graphs."""

    @classmethod
    def save_graph(
        cls,
        graph: TemporalKnowledgeGraph,
        workspace_path: Path,
    ) -> Path:
        """Atomically persist complete graph state into workspace layout."""
        try:
            if graph.is_counterfactual and graph.branch_id:
                base_dir = workspace_path / "branches" / graph.branch_id / "knowledge"
            else:
                base_dir = workspace_path / "knowledge"

            nodes_dir = base_dir / "nodes"
            edges_dir = base_dir / "edges"
            indexes_dir = base_dir / "indexes"
            manifests_dir = base_dir / "manifests"
            integrity_dir = base_dir / "integrity"

            for d in (nodes_dir, edges_dir, indexes_dir, manifests_dir, integrity_dir):
                d.mkdir(parents=True, exist_ok=True)

            # 1. Serialize nodes
            nodes_data = [n.model_dump(mode="json") for n in graph.get_nodes()]
            cls._atomic_write_json(nodes_dir / "nodes.json", nodes_data)

            # 2. Serialize edges
            edges_data = [e.model_dump(mode="json") for e in graph.get_edges()]
            cls._atomic_write_json(edges_dir / "edges.json", edges_data)

            # 3. Serialize provenance
            prov_data = [p.model_dump(mode="json") for p in graph._provenance.values()]
            cls._atomic_write_json(nodes_dir / "provenance.json", prov_data)

            # 4. Serialize indexes
            indexes_payload = {
                "nodes_by_type": {k: list(v) for k, v in graph._nodes_by_type.items()},
                "edges_by_source": {k: list(v) for k, v in graph._edges_by_source.items()},
                "edges_by_target": {k: list(v) for k, v in graph._edges_by_target.items()},
                "edges_by_rel": {k: list(v) for k, v in graph._edges_by_rel.items()},
                "edges_by_evidence": {k: list(v) for k, v in graph._edges_by_evidence.items()},
                "edges_by_status": {k: list(v) for k, v in graph._edges_by_status.items()},
            }
            cls._atomic_write_json(indexes_dir / "indexes.json", indexes_payload)

            # 5. Digest & Manifest
            digest = graph.calculate_graph_digest()
            cls._atomic_write_json(integrity_dir / "digest.json", {"graph_digest": digest})

            manifest_payload = {
                "investigation_id": graph.investigation_id,
                "case_id": graph.case_id,
                "is_counterfactual": graph.is_counterfactual,
                "branch_id": graph.branch_id,
                "node_count": len(graph._nodes),
                "edge_count": len(graph._edges),
                "provenance_count": len(graph._provenance),
                "saved_at": utc_now().isoformat(),
                "graph_digest": digest,
            }
            cls._atomic_write_json(manifests_dir / "manifest.json", manifest_payload)

            return base_dir

        except Exception as exc:
            raise KnowledgePersistenceError(
                f"Failed to persist knowledge graph: {str(exc)}",
                investigation_id=graph.investigation_id,
            ) from exc

    @classmethod
    def load_graph(
        cls,
        investigation_id: str,
        workspace_path: Path,
        is_counterfactual: bool = False,
        branch_id: Optional[str] = None,
        verify_digest: bool = True,
    ) -> Optional[TemporalKnowledgeGraph]:
        """Restore and verify TemporalKnowledgeGraph from workspace files."""
        if is_counterfactual and branch_id:
            base_dir = workspace_path / "branches" / branch_id / "knowledge"
        else:
            base_dir = workspace_path / "knowledge"

        manifest_path = base_dir / "manifests" / "manifest.json"
        if not manifest_path.exists():
            return None

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)

            graph = TemporalKnowledgeGraph(
                investigation_id=manifest.get("investigation_id", investigation_id),
                case_id=manifest.get("case_id", ""),
                is_counterfactual=manifest.get("is_counterfactual", False),
                branch_id=manifest.get("branch_id"),
            )

            # Load nodes
            nodes_file = base_dir / "nodes" / "nodes.json"
            if nodes_file.exists():
                with open(nodes_file, "r", encoding="utf-8") as f:
                    nodes_data = json.load(f)
                for nd in nodes_data:
                    graph.add_node(KnowledgeNode(**nd), enforce_integrity=False)

            # Load provenance
            prov_file = base_dir / "nodes" / "provenance.json"
            if prov_file.exists():
                with open(prov_file, "r", encoding="utf-8") as f:
                    prov_data = json.load(f)
                for pd in prov_data:
                    graph.attach_provenance(KnowledgeProvenanceRecord(**pd))

            # Load edges
            edges_file = base_dir / "edges" / "edges.json"
            if edges_file.exists():
                with open(edges_file, "r", encoding="utf-8") as f:
                    edges_data = json.load(f)
                for ed in edges_data:
                    graph.add_edge(KnowledgeEdge(**ed), enforce_integrity=False)

            if verify_digest and "graph_digest" in manifest:
                current_digest = graph.calculate_graph_digest()
                if current_digest != manifest["graph_digest"]:
                    raise KnowledgeIntegrityError(
                        f"Graph digest mismatch upon reload! Stored: {manifest['graph_digest']}, calculated: {current_digest}",
                        investigation_id=investigation_id,
                    )

            return graph

        except KnowledgeIntegrityError:
            raise
        except Exception as exc:
            raise KnowledgePersistenceError(
                f"Failed to load knowledge graph: {str(exc)}",
                investigation_id=investigation_id,
            ) from exc

    @classmethod
    def _atomic_write_json(cls, destination: Path, payload: Any) -> None:
        """Write JSON payload to a temporary file in destination's directory and atomically rename."""
        parent = destination.parent
        parent.mkdir(parents=True, exist_ok=True)
        with NamedTemporaryFile("w", dir=str(parent), delete=False, encoding="utf-8") as tmp:
            json.dump(payload, tmp, indent=2, sort_keys=True, default=str)
            tmp_path = Path(tmp.name)
        os.replace(tmp_path, destination)
