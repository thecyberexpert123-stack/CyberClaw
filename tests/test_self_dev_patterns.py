"""Tests for deterministic pattern detection over operational experiences."""

import pytest
from cyberclaw.evidence.result import ExecutionResult
from cyberclaw.memory.experience import ExperienceRecord
from cyberclaw.specialists.self_development.patterns import (
    PatternDetector,
    PatternType,
)


def _make_exp(action: str, success: bool, conditions: dict) -> ExperienceRecord:
    res = ExecutionResult.success(evidence=[]) if success else ExecutionResult.failure("err")
    return ExperienceRecord(
        action=action,
        result_status=res.status,
        success=success,
        lesson=f"Action {action} outcome",
        conditions=conditions,
    )


def test_repeated_success_pattern_detected():
    detector = PatternDetector(min_occurrence_threshold=2)

    exps = [
        _make_exp("osint.dns_lookup", True, {"target_type": "domain"}),
        _make_exp("osint.dns_lookup", True, {"target_type": "domain"}),
    ]

    patterns = detector.detect_patterns(exps)
    assert len(patterns) == 1
    pat = patterns[0]
    assert pat.pattern_type == PatternType.REPEATED_SUCCESS
    assert "osint.dns_lookup" in pat.action_or_sequence
    assert pat.conditions == {"target_type": "domain"}
    assert pat.confidence >= 0.8
    assert len(pat.source_experience_ids) == 2


def test_repeated_failure_pattern_detected():
    detector = PatternDetector(min_occurrence_threshold=2)

    exps = [
        _make_exp("osint.whois_lookup", False, {"target_tld": ".gov"}),
        _make_exp("osint.whois_lookup", False, {"target_tld": ".gov"}),
    ]

    patterns = detector.detect_patterns(exps)
    assert len(patterns) == 1
    pat = patterns[0]
    assert pat.pattern_type == PatternType.REPEATED_FAILURE
    assert pat.conditions == {"target_tld": ".gov"}


def test_insufficient_evidence_threshold():
    detector = PatternDetector(min_occurrence_threshold=3)

    # Only 2 occurrences when 3 required
    exps = [
        _make_exp("osint.cert_metadata", True, {"port": 443}),
        _make_exp("osint.cert_metadata", True, {"port": 443}),
    ]

    patterns = detector.detect_patterns(exps)
    assert len(patterns) == 0


def test_pattern_revision_on_contradictory_evidence():
    detector = PatternDetector(min_occurrence_threshold=2)
    exps = [
        _make_exp("probe.service", True, {"firewall": False}),
        _make_exp("probe.service", True, {"firewall": False}),
    ]
    patterns = detector.detect_patterns(exps)
    original_pat = patterns[0]
    assert original_pat.revision == 1
    assert original_pat.is_active is True

    # New contradictory evidence arrives: fails when rate limited
    revised = detector.revise_pattern(
        pattern_id=original_pat.id,
        contradiction_evidence_ids=["ev-contradict-1"],
        revised_description="Probe succeeds only when firewall is off AND rate limit not exceeded.",
        revised_conditions={"firewall": False, "rate_limited": False},
        reason="Observed repeated failures when rate limits were hit.",
    )

    assert revised.revision == 2
    assert revised.revises_pattern_id == original_pat.id
    assert original_pat.is_active is False
    assert original_pat.superseded_by == revised.id
    assert revised.conditions == {"firewall": False, "rate_limited": False}
