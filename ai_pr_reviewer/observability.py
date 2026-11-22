"""Unified Observability Platform (V4.8-E07).

Connects telemetry records (counts and durations) and the internal event bus
into unified, bounded review traces with zero-egress by default and OTLP-compatible
opt-in serialization.

Tickets:
- V4.8-E07-T01: Unified metrics/trace schema over telemetry + events
- V4.8-E07-T02: Per-stage review traces (context -> specialists -> merge -> synthesis -> verify -> reporter)
- V4.8-E07-T03: Redaction-at-emit + opt-in export endpoints (no implicit egress)
- V4.8-E07-T04: Health/SLO dashboards + Action-image leanness test
"""
from __future__ import annotations

import contextlib
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator, Mapping, Sequence

from .events.schema import EventEnvelope
from .security import redact_secrets, sanitize_warning
from .telemetry import RunTelemetry, to_telemetry_row

ALLOWED_STAGES = (
    "context",
    "specialists",
    "merger",
    "synthesis",
    "verify",
    "reporter",
    "post",
)

MAX_SPANS_PER_TRACE = 100
MAX_EVENTS_PER_TRACE = 200
MAX_ATTR_STRING_LEN = 1000


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sanitize_attributes(raw: Mapping[str, Any] | None) -> dict[str, Any]:
    if not raw:
        return {}
    clean: dict[str, Any] = {}
    for k, v in raw.items():
        key_str = sanitize_warning(str(k))[:64]
        if isinstance(v, (int, float, bool)):
            clean[key_str] = v
        elif isinstance(v, str):
            clean[key_str] = redact_secrets(v)[:MAX_ATTR_STRING_LEN]
        elif isinstance(v, (list, tuple)):
            clean[key_str] = [
                redact_secrets(str(item))[:MAX_ATTR_STRING_LEN] if isinstance(item, str) else item
                for item in v[:50]
            ]
        elif isinstance(v, dict):
            clean[key_str] = _sanitize_attributes(v)
        else:
            clean[key_str] = redact_secrets(str(v))[:MAX_ATTR_STRING_LEN]
    return clean


@dataclass(frozen=True)
class StageSpan:
    """Represents the execution lifecycle of a single review stage."""
    stage: str
    start_ts: str
    end_ts: str
    duration_ms: float
    status: str = "ok"  # "ok", "error", "skipped"
    attributes: dict[str, Any] = field(default_factory=dict)
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "stage": self.stage,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "duration_ms": round(self.duration_ms, 3),
            "status": self.status,
            "attributes": self.attributes,
        }
        if self.error_message:
            d["error_message"] = self.error_message
        return d


@dataclass
class UnifiedTrace:
    """Unified trace tying together telemetry, events, and lifecycle spans."""
    trace_id: str
    run_id: str
    spans: list[StageSpan] = field(default_factory=list)
    events: list[EventEnvelope] = field(default_factory=list)
    telemetry: RunTelemetry | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "spans": [s.to_dict() for s in self.spans[:MAX_SPANS_PER_TRACE]],
            "events": [e.to_dict() for e in self.events[:MAX_EVENTS_PER_TRACE]],
            "telemetry": to_telemetry_row(self.telemetry) if self.telemetry else None,
        }


class ReviewTracer:
    """Collector and context manager for stage-by-stage tracing."""

    def __init__(self, trace_id: str = "", run_id: str = "") -> None:
        self.trace_id = trace_id or str(uuid.uuid4())
        self.run_id = run_id or str(uuid.uuid4())
        self.spans: list[StageSpan] = []
        self.events: list[EventEnvelope] = []

    @contextlib.contextmanager
    def trace_stage(
        self, stage: str, attributes: Mapping[str, Any] | None = None
    ) -> Iterator[dict[str, Any]]:
        if stage not in ALLOWED_STAGES:
            raise ValueError(f"invalid stage '{stage}'; allowed: {ALLOWED_STAGES}")

        start_time = time.monotonic()
        start_ts = _iso_now()
        active_attrs = dict(attributes or {})
        status = "ok"
        error_msg = ""

        try:
            yield active_attrs
        except Exception as exc:
            status = "error"
            error_msg = sanitize_warning(str(exc))
            raise
        finally:
            end_time = time.monotonic()
            end_ts = _iso_now()
            duration_ms = max(0.0, (end_time - start_time) * 1000.0)

            span = StageSpan(
                stage=stage,
                start_ts=start_ts,
                end_ts=end_ts,
                duration_ms=duration_ms,
                status=status,
                attributes=_sanitize_attributes(active_attrs),
                error_message=redact_secrets(error_msg),
            )
            if len(self.spans) < MAX_SPANS_PER_TRACE:
                self.spans.append(span)

    def record_event(self, event: EventEnvelope) -> None:
        if len(self.events) < MAX_EVENTS_PER_TRACE:
            self.events.append(event)

    def finish(self, telemetry: RunTelemetry | None = None) -> UnifiedTrace:
        return UnifiedTrace(
            trace_id=self.trace_id,
            run_id=self.run_id,
            spans=list(self.spans),
            events=list(self.events),
            telemetry=telemetry,
        )


class TraceExporter:
    """Base interface for trace export."""
    def export(self, trace: UnifiedTrace) -> None:
        raise NotImplementedError


class NoopExporter(TraceExporter):
    """Default local-first exporter: zero network egress."""
    def export(self, trace: UnifiedTrace) -> None:
        pass


class InMemoryExporter(TraceExporter):
    """Test and buffer exporter."""
    def __init__(self) -> None:
        self.traces: list[UnifiedTrace] = []

    def export(self, trace: UnifiedTrace) -> None:
        self.traces.append(trace)


def export_otlp_dict(trace: UnifiedTrace) -> dict[str, Any]:
    """Convert UnifiedTrace into an OTLP-compatible JSON structure."""
    otlp_spans = []
    for s in trace.spans:
        otlp_spans.append({
            "traceId": trace.trace_id,
            "spanId": str(uuid.uuid4().hex[:16]),
            "name": s.stage,
            "kind": 1,  # SPAN_KIND_INTERNAL
            "startTimeUnixNano": int(datetime.fromisoformat(s.start_ts).timestamp() * 1e9),
            "endTimeUnixNano": int(datetime.fromisoformat(s.end_ts).timestamp() * 1e9),
            "attributes": [
                {"key": k, "value": {"stringValue": str(v)}}
                for k, v in s.attributes.items()
            ],
            "status": {
                "code": 1 if s.status == "ok" else 2,  # 1: OK, 2: ERROR
                "message": s.error_message,
            },
        })

    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"stringValue": "ai-pr-reviewer"}},
                        {"key": "run.id", "value": {"stringValue": trace.run_id}},
                    ]
                },
                "scopeSpans": [
                    {
                        "scope": {"name": "ai_pr_reviewer.observability", "version": "v4.8"},
                        "spans": otlp_spans,
                    }
                ],
            }
        ]
    }


@dataclass
class SLOTargets:
    """SLO targets for review health monitoring."""
    max_duration_ms: float | None = 60000.0  # 60s
    max_tokens: int | None = 20000
    max_cost_usd: float | None = 0.50
    max_stage_error_rate: float = 0.0


def evaluate_slo_health(trace: UnifiedTrace, targets: SLOTargets | None = None) -> dict[str, Any]:
    """Evaluate health and SLO conformance of a review run."""
    targets = targets or SLOTargets()
    violations: list[str] = []

    total_duration_ms = sum(s.duration_ms for s in trace.spans)
    error_spans = [s for s in trace.spans if s.status == "error"]
    error_rate = len(error_spans) / max(1, len(trace.spans))

    total_tokens = 0
    estimated_cost_usd = 0.0

    if trace.telemetry and trace.telemetry.usage:
        usage = trace.telemetry.usage
        total_tokens = (usage.input_tokens or 0) + (usage.output_tokens or 0)

    if targets.max_duration_ms is not None and total_duration_ms > targets.max_duration_ms:
        violations.append(f"duration_ms ({total_duration_ms:.1f}) exceeded SLO ({targets.max_duration_ms:.1f})")

    if targets.max_tokens is not None and total_tokens > targets.max_tokens:
        violations.append(f"total_tokens ({total_tokens}) exceeded SLO ({targets.max_tokens})")

    if error_rate > targets.max_stage_error_rate:
        violations.append(f"stage error rate ({error_rate:.2%}) exceeded SLO ({targets.max_stage_error_rate:.2%})")

    overall_status = "healthy" if not violations else "degraded"

    return {
        "overall_status": overall_status,
        "slo_violations": violations,
        "metrics": {
            "total_duration_ms": round(total_duration_ms, 2),
            "stages_count": len(trace.spans),
            "error_stages_count": len(error_spans),
            "total_tokens": total_tokens,
            "estimated_cost_usd": estimated_cost_usd,
        },
    }
