"""V4.6-E07-T04 — subscriber contracts + reference subscribers.

The three consumers the plan names (telemetry, analytics, dashboard
sync) are REFERENCE implementations inside this package — deliberately
self-contained. The real telemetry pipeline, analytics storage and
dashboard views are NOT modified by this epic (Wave-2 ground rule:
tickets other than the budget epic *report* to ``dashboard/`` rather
than add views; integration happens later behind its own ticket).

``SUBSCRIBER_CONTRACT`` is the written seam: what any future subscriber
may assume and must uphold. It exists as data so tests can pin every
reference sink against it, and so a later V4.8 consumer has one place to
read the rules.

All sinks are synchronous, in-memory and bounded (a subscriber that
grows without bound would defeat the bus's own backpressure caps).
"""
from __future__ import annotations

from .log import EventLog

SUBSCRIBER_CONTRACT: tuple[str, ...] = (
    "receives validated, REDACTED EventEnvelopes only (deliver scrubs "
    "before dispatch; the envelope is frozen and its payload a private "
    "copy — never mutated, never trusted as anything but data)",
    "runs synchronously, inline inside emit() — fast, no network, no "
    "prompt building; the only sanctioned file writer is the log "
    "subscriber, bounded by the log's append-only caps",
    "must not raise: a raising subscriber is quarantined (unsubscribed, "
    "counted) and the failure never reaches the review",
    "bounded memory: caps with counted overflow — a sink must never "
    "accumulate one row per event without limit",
    "emitting re-entrantly from a handler is allowed (the bus buffers, "
    "delivery depth stays 1)",
)

MAX_SINK_KEYS = 64              # distinct event types per aggregate sink
MAX_SYNC_BUFFER = 64            # dashboard sync buffer (drop-newest, counted)


class TelemetrySink:
    """Reference telemetry subscriber: per-type COUNTS only.

    Allowlist-style by construction — never stores event content, just
    ``(event_type, count)`` rows, which is exactly the shape a telemetry
    row may carry. Rows are sorted, so two runs over the same events
    produce byte-identical output (determinism).
    """

    def __init__(self) -> None:
        self._counts: dict[str, int] = {}
        self.overflow = 0         # distinct types beyond MAX_SINK_KEYS

    def __call__(self, event) -> None:
        name = event.event_type
        if name in self._counts:
            self._counts[name] += 1
        elif len(self._counts) < MAX_SINK_KEYS:
            self._counts[name] = 1
        else:
            self.overflow += 1

    @property
    def total(self) -> int:
        return sum(self._counts.values())

    def rows(self) -> list[dict]:
        return [{"event_type": name, "count": count}
                for name, count in sorted(self._counts.items())]


class AnalyticsSink:
    """Reference analytics subscriber: per-type aggregates with bounded
    subject tracking (subjects are untrusted-derived paths/ids — stored
    as data, capped, never interpreted)."""

    def __init__(self) -> None:
        self._stats: dict[str, dict] = {}
        self.overflow = 0

    def __call__(self, event) -> None:
        name = event.event_type
        entry = self._stats.get(name)
        if entry is None:
            if len(self._stats) >= MAX_SINK_KEYS:
                self.overflow += 1
                return
            entry = {"count": 0, "first": event.timestamp,
                     "last": event.timestamp, "subjects": set()}
            self._stats[name] = entry
        entry["count"] += 1
        entry["last"] = event.timestamp
        if event.subject and len(entry["subjects"]) < MAX_SINK_KEYS:
            entry["subjects"].add(event.subject)

    def rows(self) -> list[dict]:
        return [{"event_type": name, "count": entry["count"],
                 "first_seen": entry["first"], "last_seen": entry["last"],
                 "subjects": sorted(entry["subjects"])}
                for name, entry in sorted(self._stats.items())]


class DashboardSyncSink:
    """Reference dashboard-sync subscriber: a bounded newest-state buffer.

    Buffer overflow drops the NEWEST event and counts it (same
    backpressure semantics as the bus). ``snapshot()`` exposes ONLY
    envelope scalars — untrusted payload content never rides along in a
    dashboard row; a consumer that needs payload goes through the log.
    """

    def __init__(self) -> None:
        self._buffer: list[dict] = []
        self.dropped = 0

    def __call__(self, event) -> None:
        row = {"event_id": event.event_id, "event_type": event.event_type,
               "source": event.source, "subject": event.subject,
               "timestamp": event.timestamp}
        if len(self._buffer) >= MAX_SYNC_BUFFER:
            self.dropped += 1        # drop-newest, counted (backpressure)
            return
        self._buffer.append(row)

    @property
    def pending(self) -> int:
        return len(self._buffer)

    def snapshot(self) -> list[dict]:
        """Deterministic (chronological) copy for a dashboard read."""
        return [dict(row) for row in self._buffer]


class LogSubscriber:
    """Feeds every delivered event into an ``EventLog``.

    The log's own ``append`` never raises (it returns labels), so this
    subscriber honors the contract trivially: refusals are collected for
    the caller to surface as warnings.
    """

    def __init__(self, log: EventLog) -> None:
        self.log = log
        self.labels: list[str] = []

    def __call__(self, event) -> None:
        label = self.log.append(event)
        if label is not None:
            self.labels.append(label)
