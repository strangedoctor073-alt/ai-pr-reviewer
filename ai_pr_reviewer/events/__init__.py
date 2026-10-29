"""V4.6-E07 — internal event platform v1.

In-process by design: schema + bounded dispatch + append-only local log
with replay. **No distributed broker, no queues-as-infrastructure, no
workers** — the negative architecture test in T05 pins that this
generation adds none (plan §C.4 non-goals and the zero-queue/worker
exit criterion).

The event log is internal test/diagnostic data; it is never part of the
public report contract (report JSON stays additive-only).
"""
from .bus import (MAX_DRAIN_STEPS, MAX_PENDING_EVENTS, MAX_SUBSCRIBERS,
                   BusStats, EventBus)
from .schema import (MAX_PAYLOAD_JSON_CHARS, SCHEMA_VERSION,
                     SUPPORTED_SCHEMA_VERSIONS, EventEnvelope, make_event,
                     validate_event)

__all__ = [
    "BusStats",
    "EventBus",
    "EventEnvelope",
    "MAX_DRAIN_STEPS",
    "MAX_PAYLOAD_JSON_CHARS",
    "MAX_PENDING_EVENTS",
    "MAX_SUBSCRIBERS",
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "make_event",
    "validate_event",
]
