"""Tests for Structured Observability records, sinks, and queries."""

import pytest
from cyberclaw.observability.logger import ObservabilityRecord, StructuredLogger


def test_structured_logger_answers_core_questions():
    logger = StructuredLogger()

    record = logger.record(
        operation="dfa.transition",
        component="DFA",
        state="INVESTIGATE",
        event="evidence.gathered",
        correlation_id="case-42",
        result="success",
        reason="Triggered automatic progression to verify phase",
        evidence_ids=["ev-01", "ev-02"],
        duration_ms=4.2,
        metadata={"transition": "INVESTIGATE -> VERIFY"},
    )

    # What happened?
    assert record.operation == "dfa.transition"
    assert record.event == "evidence.gathered"

    # Why did it happen?
    assert record.reason == "Triggered automatic progression to verify phase"

    # What state was the system in?
    assert record.state == "INVESTIGATE"

    # What component initiated it?
    assert record.component == "DFA"

    # What evidence was produced/referenced?
    assert record.evidence_ids == ["ev-01", "ev-02"]

    # What was the result?
    assert record.result == "success"


def test_structured_logger_queries():
    logger = StructuredLogger()

    logger.record("op1", "Core", correlation_id="c1")
    logger.record("op2", "DFA", correlation_id="c2")
    logger.record("op3", "Core", correlation_id="c1")

    records_c1 = logger.get_records(correlation_id="c1")
    assert len(records_c1) == 2
    assert [r.operation for r in records_c1] == ["op1", "op3"]

    records_dfa = logger.get_records(component="DFA")
    assert len(records_dfa) == 1
    assert records_dfa[0].operation == "op2"


def test_structured_logger_sink():
    sink_records = []
    logger = StructuredLogger(sinks=[lambda r: sink_records.append(r)])

    logger.record("audit", "Security", result="authorized")
    assert len(sink_records) == 1
    assert sink_records[0].operation == "audit"
