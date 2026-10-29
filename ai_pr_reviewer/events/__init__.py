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
from .log import (MAX_EVENT_LOG_LINE_CHARS, MAX_LOG_BYTES, MAX_LOG_EVENTS,
                   EventLog, ReplayResult)
from .redact import deliver, redact_event
from .schema import (MAX_PAYLOAD_JSON_CHARS, SCHEMA_VERSION,
                     SUPPORTED_SCHEMA_VERSIONS, EventEnvelope, make_event,
                     validate_event)
from .subscribers import (SUBSCRIBER_CONTRACT, AnalyticsSink,
                          DashboardSyncSink, LogSubscriber, TelemetrySink)

__all__ = [
    "SUBSCRIBER_CONTRACT",
    "AnalyticsSink",
    "BusStats",
    "DashboardSyncSink",
    "EventBus",
    "EventEnvelope",
    "EventLog",
    "LogSubscriber",
    "MAX_DRAIN_STEPS",
    "MAX_EVENT_LOG_LINE_CHARS",
    "MAX_LOG_BYTES",
    "MAX_LOG_EVENTS",
    "MAX_PAYLOAD_JSON_CHARS",
    "MAX_PENDING_EVENTS",
    "MAX_SUBSCRIBERS",
    "ReplayResult",
    "SCHEMA_VERSION",
    "SUPPORTED_SCHEMA_VERSIONS",
    "TelemetrySink",
    "deliver",
    "make_event",
    "redact_event",
    "validate_event",
]
