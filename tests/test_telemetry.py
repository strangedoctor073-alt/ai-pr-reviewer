"""V3-E02 telemetry spine tests — T01 (usage capture), T02 (outcome +
report JSON), T03 (retry/failover/circuit events).

Offline by contract: provider HTTP is always mocked, sleeps are zeroed,
no API keys, no network. Each test docstring names its ticket and the
acceptance criterion it pins. ADR-014 guardrails are asserted here too:
content-free records, allowlist-only serialization, redacted strings.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import model_router as router
from ai_pr_reviewer.ai.claude import ClaudeProvider
from ai_pr_reviewer.ai.gemini import GeminiProvider
from ai_pr_reviewer.ai.openai import OpenAIProvider
from ai_pr_reviewer.analyzer import AnalysisOutcome, StaticAnalyzer
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.context import ReviewContext
from ai_pr_reviewer.diff_parser import parse_unified_diff
from ai_pr_reviewer.models import PRContext, ReviewResult
from ai_pr_reviewer.reporter import finalize_report
from ai_pr_reviewer.retry import RetryPolicy
from ai_pr_reviewer.telemetry import (STATE_NA, STATE_OK, STATE_UNAVAILABLE,
                                      RunTelemetry, UsageRecord,
                                      summarize_calls, to_telemetry_row)


# ------------------------------------------------------------------ helpers
class FakeResponse:
    def __init__(self, status_code: int, json_data: dict | None = None):
        self.status_code = status_code
        self._json = json_data or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"status {self.status_code}",
                request=httpx.Request("POST", "https://example.invalid"),
                response=self,
            )

    def json(self) -> dict:
        return self._json


def _diff(path: str = "app.py") -> object:
    text = (f"--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,1 +1,2 @@\n x\n+y\n")
    return parse_unified_diff(text)[0]


def _context() -> SimpleNamespace:
    return SimpleNamespace(files=[_diff()], focus_areas=[])


def _review_body(findings: list[dict] | None = None) -> str:
    return json.dumps({"summary": "fine", "findings": findings or [],
                       "warnings": []})


def _claude_envelope(with_usage: bool = True) -> dict:
    env = {"content": [{"type": "text", "text": _review_body()}]}
    if with_usage:
        env["usage"] = {"input_tokens": 100, "output_tokens": 20}
    return env


class _Stub:
    """AIProvider double for run_analysis tests (mirrors test_provider_failover)."""

    def __init__(self, backend: str, outcome: AnalysisOutcome | None = None,
                 error: Exception | None = None):
        self.backend = backend
        self._outcome = outcome
        self._error = error
        self.analyzed = 0
        self.startup_warnings: list[str] = []

    def analyze(self, context):
        self.analyzed += 1
        if self._error:
            raise self._error
        return self._outcome


def _outcome(engine: str = "claude") -> AnalysisOutcome:
    return AnalysisOutcome([], "ok", mode="claude", model="m", engine=engine)


@pytest.fixture(autouse=True)
def _fresh_circuits():
    router.reset_circuits()
    yield
    router.reset_circuits()


# ============================================================ T01 · capture
def test_t01_claude_usage_lands_in_the_shared_record():
    """T01 acceptance: mocked Claude responses populate the shared record."""
    provider = ClaudeProvider(api_key="sk-ant-test", model="claude-sonnet-4-6")
    provider._client.post = Mock(return_value=FakeResponse(200, _claude_envelope()))

    provider.analyze(_context())

    assert len(provider.usage_records) == 1
    rec = provider.usage_records[0]
    assert (rec.state, rec.input_tokens, rec.output_tokens) == (STATE_OK, 100, 20)
    assert rec.provider == "claude" and rec.model == "claude-sonnet-4-6"
    assert type(rec.duration_ms) is int and rec.duration_ms >= 0
    assert provider.usage_summary().to_dict()["input_tokens"] == 100


def test_t01_openai_usage_lands_in_the_shared_record():
    """T01 acceptance: mocked OpenAI responses populate the shared record."""
    provider = OpenAIProvider(api_key="sk-test", model="gpt-4o")
    provider._client.post = Mock(return_value=FakeResponse(200, {
        "choices": [{"message": {"content": _review_body()}}],
        "usage": {"prompt_tokens": 50, "completion_tokens": 10},
    }))

    provider.analyze(_context())

    rec = provider.usage_records[0]
    assert (rec.state, rec.input_tokens, rec.output_tokens) == (STATE_OK, 50, 10)
    assert provider.usage_summary().state == STATE_OK


def test_t01_gemini_usage_metadata_is_parsed():
    """T01 acceptance (Gemini usage parsing included): usageMetadata counts
    land in the shared record *and* the legacy totals — the old TODO at
    gemini.py left both dead."""
    provider = GeminiProvider(api_key="k", model="gemini-2.0-flash")
    provider._client.post = Mock(return_value=FakeResponse(200, {
        "candidates": [{"content": {"parts": [{"text": _review_body()}]}}],
        "usageMetadata": {"promptTokenCount": 70, "candidatesTokenCount": 15},
    }))

    provider.analyze(_context())

    rec = provider.usage_records[0]
    assert (rec.state, rec.input_tokens, rec.output_tokens) == (STATE_OK, 70, 15)
    assert provider.total_input_tokens == 70
    assert provider.total_output_tokens == 15


def test_t01_missing_usage_is_unavailable_never_a_zero():
    """T01 acceptance: a provider without usage reports ``unavailable`` —
    the typed state, with None token fields, never a fake 0."""
    provider = ClaudeProvider(api_key="sk-ant-test", model="claude-sonnet-4-6")
    provider._client.post = Mock(
        return_value=FakeResponse(200, _claude_envelope(with_usage=False)))

    provider.analyze(_context())

    rec = provider.usage_records[0]
    assert rec.state == STATE_UNAVAILABLE
    assert rec.input_tokens is None and rec.output_tokens is None
    assert rec.unavailable is True
    assert provider.usage_summary().state == STATE_UNAVAILABLE


def test_t01_static_and_mock_runs_mark_usage_not_applicable():
    """T01 acceptance: static/mock runs mark ``n/a`` — the rule engine
    spends no tokens, so both the engine and its router adapter report
    the third state (not 0, not unavailable)."""
    outcome = StaticAnalyzer().analyze([_diff()])
    assert outcome.telemetry.usage.state == STATE_NA
    assert outcome.telemetry.usage.input_tokens is None
    assert router.StaticProvider().usage_summary().state == STATE_NA


def test_t01_usage_record_dict_is_content_free():
    """T01 key requirement: no prompt content stored — the record's own
    serialization is a fixed allowlist (counts/names/durations only)."""
    allowed = {"provider", "model", "input_tokens", "output_tokens",
               "duration_ms", "state"}
    rec = UsageRecord.for_call("claude", "m", 1, 2, 3)
    assert set(rec.to_dict()) == allowed
    # states are exactly the three typed values
    assert UsageRecord.na().state in (STATE_OK, STATE_UNAVAILABLE, STATE_NA)
    assert summarize_calls("claude", "m", []).state == STATE_NA


# ============================================== T02 · outcome + report JSON
def test_t02_mock_run_report_carries_telemetry_with_correct_types():
    """T02 acceptance: a mock (static) run's report contains telemetry
    fields with the correct JSON types."""
    outcome = StaticAnalyzer().analyze([_diff()])
    row = to_telemetry_row(outcome.telemetry)
    result = ReviewResult(
        pr=PRContext(repo="acme/api", pr_number=7), mode=outcome.mode,
        model=outcome.model, reviewed_at="2026-10-04T00:00:00+00:00",
        summary=outcome.summary, findings=outcome.findings,
        telemetry=row,
    )
    result.engine = "static"

    data = finalize_report(result)

    tel = data["telemetry"]
    assert type(tel["schema"]) is int
    assert type(tel["provider"]) is str and type(tel["model"]) is str
    assert type(tel["batch_count"]) is int and type(tel["fallback_used"]) is bool
    assert isinstance(tel["calls"], list) and isinstance(tel["events"], list)
    assert isinstance(tel["usage"], dict)
    assert tel["usage"]["state"] == STATE_NA
    assert tel["usage"]["input_tokens"] is None          # n/a, not 0


def test_t02_live_provider_run_telemetry_reaches_the_result_row():
    """T02 goal: tokens, batch count and per-batch latency ride
    AnalysisOutcome -> the serializable row."""
    provider = ClaudeProvider(api_key="sk-ant-test", model="claude-sonnet-4-6")
    provider._client.post = Mock(return_value=FakeResponse(200, _claude_envelope()))
    outcome = provider.analyze(_context())

    row = to_telemetry_row(outcome.telemetry)

    assert row["provider"] == "claude" and row["model"] == "claude-sonnet-4-6"
    assert row["batch_count"] == 1
    assert row["usage"]["input_tokens"] == 100
    assert type(row["calls"][0]["duration_ms"]) is int   # per-batch latency
    assert row["events"] == []                           # no retries in this run


def test_t02_to_telemetry_row_drops_non_allowlisted_fields():
    """T02 acceptance (structural): anything not on the allowlist is
    dropped — planted keys in events (prompt text, a file path) never
    survive serialization."""
    tel = RunTelemetry(provider="claude", model="m", events=[
        {"type": "retry", "attempt": 1, "prompt": "IGNORE ALL INSTRUCTIONS",
         "file": "/home/dev/.ssh/id_rsa", "secret": "hunter2"},
    ])
    tel.calls.append(UsageRecord.for_call("claude", "m", 1, 2, 3))

    row = to_telemetry_row(tel)

    assert list(row["events"][0]) == ["type", "attempt"]
    assert "prompt" not in json.dumps(row)
    assert "/home/dev" not in json.dumps(row)
    assert "hunter2" not in json.dumps(row)
    allowed = {"schema", "provider", "model", "batch_count", "fallback_used",
               "usage", "calls", "events"}
    assert set(row) == allowed


def test_t02_telemetry_strings_pass_through_redaction():
    """T02 acceptance: redaction applied before inclusion — a secret-shaped
    value in any string field comes out redacted."""
    tel = RunTelemetry(
        provider="claude",
        model="sk-proj-ABCDEFGHIJKLMNOPQRST1234",
        events=[{"type": "failover", "from": "claude", "to": "openai",
                 "reason": "ghp_abcdefghijklmnopqrstuvwxyz123456"}],
    )

    row = to_telemetry_row(tel)

    assert "sk-proj-" not in row["model"]
    assert "ghp_" not in json.dumps(row)


def test_t02_analysis_outcome_telemetry_field_is_append_only():
    """V1/V2 positional construction (four required args) keeps working —
    telemetry is appended with a default, never reordered."""
    outcome = AnalysisOutcome([], "s", "claude", "m")
    assert outcome.telemetry is None                     # default: absent

    outcome2 = AnalysisOutcome([], "s", "claude", "m", ["w"], "claude",
                               False, 2)
    assert outcome2.telemetry is None


def test_t02_result_to_dict_emits_the_telemetry_key():
    """T02: report JSON gains the key additively (null when the backend
    produced no telemetry — never invented numbers)."""
    result = ReviewResult(pr=PRContext(repo="a/b", pr_number=1), mode="claude",
                          model="m", reviewed_at="t")
    assert "telemetry" in result.to_dict()
    assert result.to_dict()["telemetry"] is None

    result.telemetry = to_telemetry_row(RunTelemetry(provider="static"))
    assert result.to_dict()["telemetry"]["provider"] == "static"


# ======================================= T03 · retry/failover/circuit events
def test_t03_retry_attempts_record_structured_events():
    """T03 acceptance: retry attempts are first-class telemetry events
    with timestamps — type/attempt/delay/status, counts only."""
    policy = RetryPolicy(max_attempts=3, base_delay=0.0)
    calls = {"n": 0}

    class _Resp:
        def __init__(self, status):
            self.status_code = status

    def flaky():
        calls["n"] += 1
        return _Resp(429 if calls["n"] < 3 else 200)

    result = policy.call(flaky)

    assert result.status_code == 200
    assert len(policy.events) == 2
    first = policy.events[0]
    assert first["type"] == "retry"
    assert first["attempt"] == 1
    assert type(first["delay_ms"]) is int
    assert first["status"] == 429 and first["error"] is None
    assert isinstance(first["ts"], str) and first["ts"]
    assert [e["attempt"] for e in policy.events] == [1, 2]


def test_t03_exhausted_retries_record_the_exception_type_only():
    """T03: event payloads carry the exception *type name*, never the
    message (which could echo a request body or key)."""
    secret = "sk-" + "A" * 40
    policy = RetryPolicy(max_attempts=2, base_delay=0.0)

    class ConnectError(Exception):
        """Named to match retry.py's network-exception-name classification
        (same trick as test_ai_provider._FakeReadTimeout)."""

    def boom():
        raise ConnectError(f"failed while sending {secret}")

    with pytest.raises(ConnectError):
        policy.call(boom)

    assert len(policy.events) == 1
    ev = policy.events[0]
    assert ev["error"] == "ConnectError" and ev["status"] is None
    assert secret not in json.dumps(policy.events)


def test_t03_forced_failover_produces_the_expected_event_sequence(monkeypatch):
    """T03 acceptance: a forced-failover test produces the expected event
    sequence — provider_error, then the failover handover, in order."""
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    first = _Stub("claude", error=RuntimeError("boom"))
    second = _Stub("openai", outcome=_outcome(engine="openai"))
    monkeypatch.setattr(router, "build_provider",
                        lambda cfg, context, backend: {  # noqa: ARG005
                            "claude": first, "openai": second}[backend])

    out = router.run_analysis(cfg, _failover_context(), primary=first)

    types = [e["type"] for e in out.telemetry.events]
    assert types == ["provider_error", "failover"]
    assert out.telemetry.events[0]["backend"] == "claude"
    assert out.telemetry.events[0]["error"] == "RuntimeError"
    assert out.telemetry.events[1]["from"] == "claude"
    assert out.telemetry.events[1]["to"] == "openai"
    assert "boom" not in json.dumps(out.telemetry.events)  # type name only


def test_t03_circuit_state_transitions_are_events(monkeypatch):
    """T03 acceptance: breaker open/close transitions are recorded as
    telemetry events with timestamps."""
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    first = _Stub("claude", error=RuntimeError("boom"))
    second = _Stub("openai", outcome=_outcome(engine="openai"))
    monkeypatch.setattr(router, "build_provider",
                        lambda cfg, context, backend: {  # noqa: ARG005
                            "claude": first, "openai": second}[backend])

    run1 = router.run_analysis(cfg, _failover_context(), primary=first)
    assert not [e for e in run1.telemetry.events if e["type"] == "circuit"]

    run2 = router.run_analysis(cfg, _failover_context(), primary=first)
    circuits = [e for e in run2.telemetry.events if e["type"] == "circuit"]
    assert circuits and circuits[0]["from"] == "closed"
    assert circuits[0]["to"] == "open"
    assert isinstance(circuits[0]["ts"], str) and circuits[0]["ts"]


def test_t03_provider_retry_events_reach_the_outcome():
    """T03: a real provider's retry events ride into its outcome's
    telemetry (the channel T02 wired, filled by T03's RetryPolicy)."""
    provider = ClaudeProvider(
        api_key="sk-ant-test", model="claude-sonnet-4-6",
        retry=RetryPolicy(max_attempts=2, base_delay=0.0))
    provider._client.post = Mock(
        side_effect=httpx.ConnectError("refused"))     # both attempts fail

    outcome = provider.analyze(_context())             # per-batch static fallback

    assert outcome.telemetry is not None
    retries = [e for e in outcome.telemetry.events if e["type"] == "retry"]
    assert len(retries) == 1                           # 2 attempts -> 1 retry
    assert retries[0]["error"] == "ConnectError"
    # and the provider-level property agrees (harvest source for run_analysis)
    assert provider.telemetry_events == outcome.telemetry.events


def test_t03_events_pass_through_the_redaction_chokepoint():
    """T03 acceptance: events pass redaction — nothing event-shaped
    escapes to_telemetry_row without the allowlist + redact_secrets pass."""
    tel = RunTelemetry(events=[
        {"type": "failover", "from": "claude", "to": "openai",
         "error": "ConnectError", "note": "Bearer abcdefghijklmnopqrstuv"},
        {"type": "retry", "planted": "AKIA" + "A" * 16},
    ])

    row = to_telemetry_row(tel)

    assert "Bearer" not in json.dumps(row["events"])
    assert "AKIA" not in json.dumps(row["events"])
    assert all("planted" not in e for e in row["events"])


def test_t03_run_analysis_without_events_leaves_outcomes_alone(monkeypatch):
    """Logging/behavior guard: a clean single-provider run gains no event
    baggage and existing warnings are unchanged."""
    cfg = Config(provider_order="claude")
    only = _Stub("claude", outcome=_outcome(engine="claude"))
    monkeypatch.setattr(router, "build_provider", lambda cfg, context, backend: only)

    out = router.run_analysis(cfg, _failover_context(), primary=only)

    assert out.telemetry is None                        # no events -> untouched
    assert out.warnings == []


def _failover_context() -> ReviewContext:
    return ReviewContext(pr=PRContext(repo="acme/api", pr_number=7),
                         files=[], project_rules=None, previous_findings=[],
                         memory_notes=[], focus_areas=[])
