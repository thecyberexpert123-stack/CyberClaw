"""Atomic persistence and reloading for investigation branches."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from cyberclaw.branching.errors import BranchIntegrityError
from cyberclaw.branching.models import (
    BranchJournalEntry,
    BranchStatus,
    InvestigationBranch,
)
from cyberclaw.case.models import ContradictionRecord, DecisionRecord
from cyberclaw.coordination.requirements import InformationRequirement
from cyberclaw.evidence.models import Evidence
from cyberclaw.replay.models import ReconstructedState
from cyberclaw.types import Entity, Hypothesis, Relationship, normalize_entity_index
from cyberclaw.workspace.manager import WorkspaceManager


class BranchPersistence:
    """Manages atomic file persistence and loading of branch metadata, history, and state."""

    @classmethod
    def persist_branch(
        cls,
        workspace: WorkspaceManager,
        branch: InvestigationBranch,
    ) -> Path:
        """Atomically persist a single branch into isolated workspace directory."""
        layout = workspace.get_investigation_workspace(branch.investigation_id)
        branch_dir = layout.branches / f"branch_{branch.branch_id}"
        branch_dir.mkdir(parents=True, exist_ok=True)

        # 1. metadata.json
        meta_data = {
            "branch_id": branch.branch_id,
            "investigation_id": branch.investigation_id,
            "parent_branch_id": branch.parent_branch_id,
            "source_snapshot_id": branch.source_snapshot_id,
            "source_snapshot_sequence": branch.source_snapshot_sequence,
            "source_sequence": branch.source_sequence,
            "status": branch.status.value,
            "purpose": branch.purpose,
            "originating_decision_id": branch.originating_decision_id,
            "stopping_condition": branch.stopping_condition,
            "created_at": branch.created_at.isoformat(),
            "updated_at": branch.updated_at.isoformat(),
            "evidence_references": branch.evidence_references,
            "capability_gaps": branch.capability_gaps,
            "metadata": branch.metadata,
            "is_counterfactual": branch.is_counterfactual,
        }
        workspace.atomic_write(branch_dir / "metadata.json", json.dumps(meta_data, indent=2))

        # 2. journal.json
        journal_data = [json.loads(e.model_dump_json()) for e in branch.journal]
        workspace.atomic_write(branch_dir / "journal.json", json.dumps(journal_data, indent=2))

        # 3. state.json (derived state + simulated evidence/entities/hypotheses/requirements)
        state_data = {
            "dfa_state": branch.derived_state.dfa_state if branch.derived_state else "INIT",
            "simulated_evidence": [json.loads(e.model_dump_json()) for e in branch.simulated_evidence],
            "entities": {k: json.loads(v.model_dump_json()) for k, v in branch.entities.items()},
            "relationships": [json.loads(r.model_dump_json()) for r in branch.relationships],
            "hypotheses": {k: json.loads(h.model_dump_json()) for k, h in branch.hypotheses.items()},
            "requirements": {k: json.loads(r.model_dump_json()) for k, r in branch.requirements.items()},
            "contradictions": [json.loads(c.model_dump_json()) for c in branch.contradictions],
            "stopping_condition": branch.stopping_condition,
        }
        workspace.atomic_write(branch_dir / "state.json", json.dumps(state_data, indent=2))

        # 4. decisions.json
        decisions_data = [json.loads(d.model_dump_json()) for d in branch.decisions]
        workspace.atomic_write(branch_dir / "decisions.json", json.dumps(decisions_data, indent=2))

        return branch_dir

    @classmethod
    def persist_branches_index(
        cls,
        workspace: WorkspaceManager,
        investigation_id: str,
        branches: List[InvestigationBranch],
    ) -> Path:
        """Atomically persist branches index summary file."""
        layout = workspace.get_investigation_workspace(investigation_id)
        layout.branches.mkdir(parents=True, exist_ok=True)
        index_file = layout.branches / "branches_index.json"

        index_data = [
            {
                "branch_id": b.branch_id,
                "status": b.status.value,
                "purpose": b.purpose,
                "source_snapshot_sequence": b.source_snapshot_sequence,
                "source_snapshot_id": b.source_snapshot_id,
                "created_at": b.created_at.isoformat(),
                "journal_events_count": len(b.journal),
            }
            for b in branches
        ]
        workspace.atomic_write(index_file, json.dumps(index_data, indent=2))
        return index_file

    @classmethod
    def load_branches(
        cls,
        workspace: WorkspaceManager,
        investigation_id: str,
    ) -> List[InvestigationBranch]:
        """Load all persisted branches for a given investigation workspace."""
        layout = workspace.get_investigation_workspace(investigation_id)
        if not layout.branches.exists():
            return []

        index_file = layout.branches / "branches_index.json"
        if not index_file.exists():
            return []

        index_data = json.loads(workspace.read_text(index_file))
        loaded_branches: List[InvestigationBranch] = []

        for item in index_data:
            bid = item["branch_id"]
            b_dir = layout.branches / f"branch_{bid}"
            if not b_dir.exists():
                raise BranchIntegrityError(
                    f"Branch index references '{bid}' but its directory is missing. "
                    "Refusing to silently drop historical branch state.",
                    branch_id=bid,
                )

            meta = json.loads(workspace.read_text(b_dir / "metadata.json"))
            journal_raw = json.loads(workspace.read_text(b_dir / "journal.json"))
            journal_entries = [BranchJournalEntry.model_validate(e) for e in journal_raw]

            state_raw = json.loads(workspace.read_text(b_dir / "state.json"))
            decisions_raw = json.loads(workspace.read_text(b_dir / "decisions.json"))
            decisions = [DecisionRecord.model_validate(d) for d in decisions_raw]

            simulated_ev = [Evidence.model_validate(e) for e in state_raw.get("simulated_evidence", [])]
            raw_entities = {k: Entity.model_validate(v) for k, v in state_raw.get("entities", {}).items()}
            entities = normalize_entity_index(raw_entities)
            if set(entities) != set(raw_entities):
                meta["metadata"] = dict(meta.get("metadata") or {})
                meta["metadata"]["entity_index_migrated"] = True
            relationships = [Relationship.model_validate(r) for r in state_raw.get("relationships", [])]
            hypotheses = {k: Hypothesis.model_validate(h) for k, h in state_raw.get("hypotheses", {}).items()}
            requirements = {k: InformationRequirement.model_validate(r) for k, r in state_raw.get("requirements", {}).items()}
            contradictions = [ContradictionRecord.model_validate(c) for c in state_raw.get("contradictions", [])]

            # Reconstruct ReconstructedState placeholder
            derived_state = ReconstructedState(
                investigation_id=investigation_id,
                target_sequence=meta.get("source_sequence", 0),
                dfa_state=state_raw.get("dfa_state", "INIT"),
                evidence=list(simulated_ev),
                entities=dict(entities),
                relationships=list(relationships),
                hypotheses=dict(hypotheses),
                requirements=dict(requirements),
                contradictions=list(contradictions),
                decisions=list(decisions),
                stopping_condition=state_raw.get("stopping_condition"),
            )
            derived_state.seal()

            branch = InvestigationBranch(
                branch_id=meta["branch_id"],
                investigation_id=investigation_id,
                parent_branch_id=meta.get("parent_branch_id"),
                source_snapshot_id=meta["source_snapshot_id"],
                source_snapshot_sequence=meta["source_snapshot_sequence"],
                source_sequence=meta.get("source_sequence", 0),
                status=BranchStatus(meta["status"]),
                purpose=meta["purpose"],
                originating_decision_id=meta.get("originating_decision_id"),
                derived_state=derived_state,
                journal=journal_entries,
                evidence_references=meta.get("evidence_references", []),
                simulated_evidence=simulated_ev,
                entities=entities,
                relationships=relationships,
                hypotheses=hypotheses,
                requirements=requirements,
                contradictions=contradictions,
                decisions=decisions,
                stopping_condition=state_raw.get("stopping_condition"),
                capability_gaps=meta.get("capability_gaps", []),
                metadata=meta.get("metadata", {}),
                is_counterfactual=True,
            )
            loaded_branches.append(branch)

        return loaded_branches
