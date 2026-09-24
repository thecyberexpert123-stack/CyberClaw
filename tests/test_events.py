"""Tests for Event and Evidence Bus."""

import pytest
from cyberclaw.events.bus import EventBus
from cyberclaw.events.event import Event


def test_event_bus_publish_and_subscribe():
    bus = EventBus()
    received_events = []

    def handler(event: Event):
        received_events.append(event)

    bus.subscribe("evidence.created", handler)

    ev = Event(
        type="evidence.created",
        source="unit_test",
        correlation_id="inv-999",
        payload={"count": 2},
    )
    bus.publish(ev)

    assert len(received_events) == 1
    assert received_events[0].correlation_id == "inv-999"
    assert received_events[0].payload["count"] == 2


def test_event_bus_wildcard_subscription():
    bus = EventBus()
    received = []

    bus.subscribe("dfa.*", lambda e: received.append(e.type))

    bus.publish(Event(type="dfa.transition", source="core"))
    bus.publish(Event(type="dfa.rejected", source="core"))
    bus.publish(Event(type="evidence.created", source="core"))

    assert received == ["dfa.transition", "dfa.rejected"]


def test_event_bus_history_and_correlation_filter():
    bus = EventBus()

    bus.publish(Event(type="t1", source="s1", correlation_id="case-A"))
    bus.publish(Event(type="t2", source="s2", correlation_id="case-B"))
    bus.publish(Event(type="t3", source="s1", correlation_id="case-A"))

    history_a = bus.get_history(correlation_id="case-A")
    assert len(history_a) == 2
    assert [e.type for e in history_a] == ["t1", "t3"]

    history_b = bus.get_history(correlation_id="case-B")
    assert len(history_b) == 1
    assert history_b[0].type == "t2"
