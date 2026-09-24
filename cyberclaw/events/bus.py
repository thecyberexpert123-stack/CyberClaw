"""Structured event and evidence bus for Core and Specialist coordination."""

from __future__ import annotations

import logging
from typing import Callable, Dict, List, Optional
from cyberclaw.events.event import Event

logger = logging.getLogger(__name__)

EventHandler = Callable[[Event], None]


class EventBus:
    """Synchronous in-memory event bus with audit history and topic routing."""

    def __init__(self) -> None:
        self._subscribers: Dict[str, List[EventHandler]] = {}
        self._global_subscribers: List[EventHandler] = []
        self._history: List[Event] = []

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Subscribe to a specific event topic or wildcard pattern (e.g. 'evidence.*')."""
        handlers = self._subscribers.setdefault(event_type, [])
        if handler not in handlers:
            handlers.append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe to all events across the entire bus."""
        if handler not in self._global_subscribers:
            self._global_subscribers.append(handler)

    def unsubscribe(self, event_type: str, handler: EventHandler) -> None:
        """Unsubscribe a handler from a topic."""
        if event_type in self._subscribers:
            self._subscribers[event_type] = [h for h in self._subscribers[event_type] if h != handler]

    def publish(self, event: Event) -> None:
        """Publish an event to all matched subscribers and append to audit history."""
        self._history.append(event)

        # Notify topic-specific subscribers
        handlers_to_notify: List[EventHandler] = []

        # Exact match
        if event.type in self._subscribers:
            handlers_to_notify.extend(self._subscribers[event.type])

        # Prefix wildcard match (e.g. 'evidence.*')
        for pattern, handlers in self._subscribers.items():
            if pattern.endswith(".*"):
                prefix = pattern[:-2]
                if event.type.startswith(prefix) and pattern != event.type:
                    handlers_to_notify.extend(handlers)

        # Global subscribers
        handlers_to_notify.extend(self._global_subscribers)

        # Execute handlers safely
        for handler in handlers_to_notify:
            try:
                handler(event)
            except Exception as exc:
                logger.error(
                    f"EventBus handler {getattr(handler, '__name__', str(handler))} failed on event {event.type}: {exc}",
                    exc_info=True,
                )

    def get_history(
        self,
        correlation_id: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Event]:
        """Query historical events filtered by correlation ID or event type."""
        events = self._history
        if correlation_id is not None:
            events = [e for e in events if e.correlation_id == correlation_id]
        if event_type is not None:
            events = [e for e in events if e.type == event_type]
        return list(events)

    def clear(self) -> None:
        """Clear event audit history."""
        self._history.clear()
