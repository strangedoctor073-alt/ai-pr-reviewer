"""V4.6-E07-T02 — in-process dispatcher with a bounded pending buffer
and backpressure.

Design constraints from plan §C.4 (event platform non-goals):

* **no workers, no threads, no ``queue`` module** — dispatch happens
  inline inside ``emit()`` via a drain loop over a plain ``list``; the
  T05 negative architecture test pins that this generation adds zero
  queue/worker/threading symbols to the codebase;
* **bounded everywhere** — subscriber count, pending buffer and the
  work one ``emit()`` performs are all capped. Overflow applies
  backpressure by dropping the NEWEST pending event and counting it
  (``stats.dropped``); the emitter is never blocked, memory never grows
  without bound, and no review can livelock on a misbehaving handler;
* **handlers cannot fail the review** — a handler that raises is
  quarantined (unsubscribed, counted) and delivery continues with the
  remaining subscribers; the exception never reaches the caller;
* **FIFO, non-recursive** — an event emitted from inside a handler is
  buffered and delivered after the current dispatch finishes (depth is
  always 1; no stack growth).

Not thread-safe by design: this generation is single-process,
single-thread dispatch. Callers that need cross-thread delivery do not
exist yet, and adding one would violate the zero-worker rule.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .schema import EventEnvelope

Handler = Callable[[EventEnvelope], None]

MAX_SUBSCRIBERS = 16
MAX_PENDING_EVENTS = 64
# Work cap per emit(): a handler that re-feeds the buffer forever gets
# one bounded slice of progress per call, then the loop returns.
MAX_DRAIN_STEPS = 1024


@dataclass
class BusStats:
    """Counters a caller can diff across an ``emit()`` (T05 surfaces
    drops as warnings)."""

    events: int = 0         # envelopes taken off the buffer
    deliveries: int = 0     # successful handler invocations
    dropped: int = 0        # backpressure: buffer full, newest event dropped
    quarantined: int = 0    # handlers removed after they raised

    def to_dict(self) -> dict[str, int]:
        return {"events": self.events, "deliveries": self.deliveries,
                "dropped": self.dropped, "quarantined": self.quarantined}


class EventBus:
    """Synchronous in-process fan-out with bounded buffering."""

    def __init__(self) -> None:
        self._subscribers: list[Handler] = []
        self._pending: list[EventEnvelope] = []
        self._draining = False
        self.stats = BusStats()

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    def subscribe(self, handler: Handler) -> None:
        """Register a handler (idempotent). Raises only for programmer
        errors: non-callables and subscriber-cap overflow."""
        if not callable(handler):
            raise TypeError("event subscriber must be callable")
        if handler in self._subscribers:
            return                          # duplicate registration: no-op
        if len(self._subscribers) >= MAX_SUBSCRIBERS:
            raise ValueError(
                f"event subscriber cap reached (max {MAX_SUBSCRIBERS})")
        self._subscribers.append(handler)

    def unsubscribe(self, handler: Handler) -> None:
        if handler in self._subscribers:
            self._subscribers.remove(handler)

    def emit(self, event: EventEnvelope) -> None:
        """Buffer ``event`` and drain synchronously.

        Re-entrant calls (a handler emitting during dispatch) only
        buffer: they never recurse, and overflow is dropped-newest with
        a counter — the backpressure contract.
        """
        if not isinstance(event, EventEnvelope):
            raise ValueError(
                "event bus accepts validated EventEnvelope instances only")
        self._pending.append(event)
        if len(self._pending) > MAX_PENDING_EVENTS:
            self._pending.pop()             # drop-newest (we just added it)
            self.stats.dropped += 1
        if self._draining:
            return                          # the active drain loop delivers it
        self._drain()

    def _drain(self) -> None:
        self._draining = True
        try:
            steps = 0
            while self._pending and steps < MAX_DRAIN_STEPS:
                event = self._pending.pop(0)
                steps += 1
                self.stats.events += 1
                # Snapshot: quarantine during iteration only affects
                # subsequent events, never skips a live subscriber now.
                for handler in list(self._subscribers):
                    try:
                        handler(event)
                        self.stats.deliveries += 1
                    except Exception:       # noqa: BLE001 — isolate handlers
                        self.stats.quarantined += 1
                        if handler in self._subscribers:
                            self._subscribers.remove(handler)
        finally:
            self._draining = False
