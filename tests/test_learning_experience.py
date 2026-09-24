"""Experience extraction, normalization, provenance, and case isolation."""

from __future__ import annotations

from pathlib import Path

from cyberclaw.core import CyberClawCore
from cyberclaw.learning.extraction import ExperienceExtractor
from cyberclaw.learning.models import OutcomeClass
from cyberclaw.learning.normalization import ExperienceNormalizer
from cyberclaw.learning.patterns import explain_pattern
from tests.learning_support import build_completed_investigation


def test_extraction_uses_authoritative_refs_and_does_not_invent_knowledge_changes(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    experience = ExperienceExtractor.extract(inv)

    evidence_ids = {ref.record_id for ref in experience.evidence_generated}
    journal_ids = {ref.record_id for ref in experience.authoritative_refs if ref.record_type == "journal"}
    assert evidence_ids
    assert journal_ids
    assert all(ref.investigation_id == inv.id for ref in experience.authoritative_refs)
    assert "knowledge_graph_changes" in experience.absent_fields
    assert experience.knowledge_graph_changes == []
    assert experience.source_family_key == "fam-a"
    assert experience.outcome == OutcomeClass.SUCCESS
    assert experience.schema_version == "0.1.0"


def test_extraction_is_deterministic_for_an_unmodified_case(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    first = ExperienceExtractor.extract(inv)
    second = ExperienceExtractor.extract(inv)
    assert first.experience_id == second.experience_id
    assert first.content_digest == second.content_digest
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_extraction_does_not_mutate_the_case_journal(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    before = [entry.id for entry in inv.case_manager.journal.entries]
    ExperienceExtractor.extract(inv)
    after = [entry.id for entry in inv.case_manager.journal.entries]
    assert before == after


def test_learning_failure_does_not_mutate_authoritative_journal(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    before = len(inv.case_manager.journal.entries)

    class Broken:
        case_manager = inv.case_manager
        id = ""

    result = core.learning_service.ingest(Broken())
    assert result.ok is False
    assert len(inv.case_manager.journal.entries) == before
    assert any(event.event_type.value == "LEARNING_FAILURE" for event in core.learning.events)


def test_normalization_retains_source_lineage_and_version(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    experience = ExperienceExtractor.extract(inv)
    normalized = ExperienceNormalizer.normalize(experience)

    assert normalized.normalization_version == "0.1.0"
    assert normalized.experience_id == experience.experience_id
    assert normalized.timestamp == experience.extracted_at
    assert normalized.capability_sequence == ["cap.observe", "cap.corroborate"]
    for feature in normalized.features:
        assert feature.source_investigation_id == inv.id
        assert feature.normalization_version == "0.1.0"
        assert feature.source_record_ids
        assert feature.timestamp == experience.extracted_at
    assert experience.objective.startswith("Resolve contradictory evidence")


def test_retry_is_retained_but_successful_sequence_collapses_duplicates(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(
        core, family="fam-b", target="subject-b", source_id="src-b", with_retry=True
    )
    experience = ExperienceExtractor.extract(inv)
    normalized = ExperienceNormalizer.normalize(experience)
    assert experience.retry_count >= 1
    assert normalized.capability_sequence == ["cap.observe", "cap.corroborate"]
    assert any(action.error == "temporary_unavailable" for action in experience.actions_taken)


def test_single_case_remains_local_and_cannot_propose_a_strategy(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    result = core.ingest_investigation_experience(inv.id)
    assert result.ok
    assert core.learning.list_strategies() == []
    assert all(pattern.scope.value == "CASE_LOCAL" for pattern in result.patterns)
    pattern = result.patterns[0]
    try:
        core.propose_learned_strategy(pattern.pattern_id, "analyst.proposer")
        raised = False
    except Exception:
        raised = True
    assert raised


def test_counterfactual_experience_is_quarantined(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    inv.metadata["is_counterfactual"] = True
    inv.metadata["branch_id"] = "branch-1"
    before = len(core.learning.authoritative_experiences())
    result = core.ingest_investigation_experience(inv.id)
    assert result.quarantined is True
    assert result.experience.is_counterfactual is True
    assert len(core.learning.authoritative_experiences()) == before
    assert result.experience.experience_id not in {
        exp.experience_id for exp in core.learning.authoritative_experiences()
    }


def test_pattern_explanation_lists_cases_events_and_exclusions(tmp_path: Path):
    core = CyberClawCore(workspace_path=tmp_path)
    core.startup()
    inv = build_completed_investigation(core, family="fam-a", target="subject-a", source_id="src-a")
    result = core.ingest_investigation_experience(inv.id)
    pattern = next(item for item in result.patterns if item.kind.value == "REPEATED_SUCCESS")
    explanation = explain_pattern(pattern)
    assert explanation["cases"] == [inv.id]
    assert explanation["successful_cases"] == [inv.id]
    assert explanation["supporting_event_ids"]
    assert explanation["causal_claim"] == "NONE"
    assert "exclusion_reasons" in explanation
