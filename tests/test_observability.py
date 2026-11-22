"""Tests for V4.8-E07: Observability Platform.

Coverage:
- V4.8-E07-T01: Unified metrics/trace schema over telemetry + events
- V4.8-E07-T02: Per-stage review traces (context -> specialists -> merge -> synthesis -> verify -> reporter)
- V4.8-E07-T03: Redaction-at-emit + opt-in export endpoints (no implicit egress)
- V4.8-E07-T04: Health/SLO dashboards + Action-image leanness test
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ai_pr_reviewer.events.schema import make_event
from ai_pr_reviewer.observability import (
    ALLOWED_STAGES,
    InMemoryExporter,
    NoopExporter,
    ReviewTracer,
    SLOTargets,
    StageSpan,
    UnifiedTrace,
    evaluate_slo_health,
    export_otlp_dict,
)
from ai_pr_reviewer.telemetry import RunTelemetry, UsageRecord


def test_unified_trace_schema_and_serialization():
    """V4.8-E07-T01: Unified trace connects telemetry and events."""
    telemetry = RunTelemetry(
        usage=UsageRecord.for_call("test", "model", 100, 50),
        batch_count=1,
    )
    event = make_event(
        event_type="review.stage_completed",
        source="test",
        subject="stage:context",
        payload={"stage": "context", "status": "ok"},
    )
    span = StageSpan(
        stage="context",
        start_ts="2026-11-22T00:00:00Z",
        end_ts="2026-11-22T00:00:01Z",
        duration_ms=1000.0,
        status="ok",
        attributes={"files_count": 5},
    )

    trace = UnifiedTrace(
        trace_id="test-trace-123",
        run_id="run-456",
        spans=[span],
        events=[event],
        telemetry=telemetry,
    )

    d = trace.to_dict()
    assert d["trace_id"] == "test-trace-123"
    assert d["run_id"] == "run-456"
    assert len(d["spans"]) == 1
    assert d["spans"][0]["stage"] == "context"
    assert d["spans"][0]["duration_ms"] == 1000.0
    assert len(d["events"]) == 1
    assert d["events"][0]["event_type"] == "review.stage_completed"
    assert d["telemetry"]["usage"]["input_tokens"] == 100
    assert d["telemetry"]["usage"]["output_tokens"] == 50

    # Ensure JSON-serializable
    encoded = json.dumps(d)
    assert "test-trace-123" in encoded


def test_per_stage_review_tracing():
    """V4.8-E07-T02: Per-stage review tracing through lifecycle."""
    tracer = ReviewTracer(trace_id="review-trace-1", run_id="run-1")

    # Trace each stage
    for stage in ("context", "specialists", "merger", "synthesis", "verify", "reporter"):
        with tracer.trace_stage(stage, attributes={"step": stage}):
            pass

    trace = tracer.finish()
    assert len(trace.spans) == 6
    stages_recorded = [s.stage for s in trace.spans]
    assert stages_recorded == ["context", "specialists", "merger", "synthesis", "verify", "reporter"]
    for s in trace.spans:
        assert s.status == "ok"
        assert s.duration_ms >= 0.0

    # Test error handling inside stage
    with pytest.raises(ValueError):
        with tracer.trace_stage("context"):
            raise ValueError("simulated stage error")

    failed_span = tracer.spans[-1]
    assert failed_span.status == "error"
    assert "simulated stage error" in failed_span.error_message


def test_unknown_stage_refused():
    """Stage must be in ALLOWED_STAGES."""
    tracer = ReviewTracer(trace_id="trace-x", run_id="run-x")
    with pytest.raises(ValueError, match="invalid stage"):
        with tracer.trace_stage("arbitrary_unknown_stage"):
            pass


def test_redaction_at_emit_and_no_implicit_egress():
    """V4.8-E07-T03: Redaction at emit and opt-in export endpoints."""
    # Secrets in span attributes must be redacted
    tracer = ReviewTracer(trace_id="trace-sec", run_id="run-sec")
    with tracer.trace_stage("specialists", attributes={"api_key": "AKIAIOSFODNN7EXAMPLE", "prompt": "token=ghp_12345678901234567890"}):
        pass

    trace = tracer.finish()
    span = trace.spans[0]
    # Check that secrets are scrubbed
    serialized_attrs = json.dumps(span.attributes)
    assert "AKIAIOSFODNN7EXAMPLE" not in serialized_attrs
    assert "ghp_12345678901234567890" not in serialized_attrs

    # No implicit egress: NoopExporter does nothing
    noop = NoopExporter()
    noop.export(trace)

    # Opt-in export: InMemoryExporter captures trace
    mem = InMemoryExporter()
    mem.export(trace)
    assert len(mem.traces) == 1

    # OTLP format conversion
    otlp = export_otlp_dict(trace)
    assert "resourceSpans" in otlp
    scope_spans = otlp["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert len(scope_spans) == 1
    assert scope_spans[0]["name"] == "specialists"


def test_slo_health_and_dashboard_metrics():
    """V4.8-E07-T04: Health/SLO dashboards and thresholds."""
    tracer = ReviewTracer(trace_id="trace-slo", run_id="run-slo")
    with tracer.trace_stage("context"):
        pass
    with tracer.trace_stage("reporter"):
        pass

    telemetry = RunTelemetry(
        usage=UsageRecord.for_call("test", "model", 2000, 500),
        batch_count=2,
    )
    trace = tracer.finish(telemetry=telemetry)

    targets = SLOTargets(
        max_duration_ms=60000.0,
        max_tokens=10000,
        max_cost_usd=0.50,
    )

    health = evaluate_slo_health(trace, targets)
    assert health["overall_status"] == "healthy"
    assert health["slo_violations"] == []
    assert health["metrics"]["total_duration_ms"] >= 0
    assert health["metrics"]["total_tokens"] == 2500

    # Violating SLO
    strict_targets = SLOTargets(max_tokens=1000)
    strict_health = evaluate_slo_health(trace, strict_targets)
    assert strict_health["overall_status"] == "degraded"
    assert any("token" in v for v in strict_health["slo_violations"])


def test_action_image_leanness():
    """V4.8-E07-T04: Action image leanness - no bloated observability dependencies."""
    action_reqs_path = Path(__file__).resolve().parent.parent / "requirements-action.txt"
    assert action_reqs_path.is_file(), "requirements-action.txt must exist"

    content = action_reqs_path.read_text(encoding="utf-8").lower()
    heavy_packages = [
        "opentelemetry",
        "prometheus",
        "datadog",
        "sentry",
        "newrelic",
        "grafana",
        "jaeger",
    ]
    for pkg in heavy_packages:
        assert pkg not in content, f"Action image must not depend on heavy observability package '{pkg}'"

    # Action dependencies should remain <= 5 packages
    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith("#")]
    assert len(lines) <= 5, f"Action requirements must remain lean (expected <= 5, got {len(lines)})"
