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
               "usage", "calls", "events", "cost"}   # V4-E11-T07
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


# =====================================================================
# V4-E11 — T06 latency · T07 cost table (display only) · ingestion route
# =====================================================================
import ast
import re

from ai_pr_reviewer import telemetry as tel_mod
from ai_pr_reviewer.telemetry import (
    PRICE_TABLE_ENV, Price, estimate_cost, latency_from_rows,
    load_price_table, lookup_price, parse_price_table, percentile,
    sanitize_telemetry, summarize_latency,
)

_OK_USAGE = {"provider": "p", "model": "m-1", "input_tokens": 1000,
             "output_tokens": 500, "duration_ms": 10, "state": "ok"}


def _row(**over):
    base = {"schema": 1, "provider": "p", "model": "m-1", "batch_count": 1,
            "fallback_used": False, "usage": dict(_OK_USAGE),
            "calls": [], "events": []}
    base.update(over)
    return base


# ------------------------------------------------------------ T07 · cost
def test_t07_no_model_ids_or_prices_ship_in_source():
    """No price table is baked in: with an empty environment every
    reported-usage run is ``unpriced`` — never a guessed number."""
    assert load_price_table({}) == {}
    cost = estimate_cost(_OK_USAGE, [], load_price_table({}))
    assert cost["state"] == "unpriced"
    assert cost["low"] is None and cost["high"] is None
    src = Path(tel_mod.__file__).read_text(encoding="utf-8")
    for banned in ("claude-", "gpt-", "gemini-"):
        assert banned not in src, f"telemetry.py hard-codes a model id ({banned})"


def test_t07_estimate_is_a_band_from_table_times_usage():
    table = {"m-1": Price(3.0, 15.0, 10.0)}
    cost = estimate_cost(_OK_USAGE, [], table)
    # (1000*3 + 500*15) / 1e6 = 0.0105  ±10 %
    assert cost == {"state": "estimated", "currency": "USD",
                    "low": 0.00945, "high": 0.01155, "display_only": True}


def test_t07_states_mirror_usage_states_never_a_fake_zero():
    table = {"m-1": Price(1.0, 1.0)}
    assert estimate_cost({"state": "n/a"}, [], table)["state"] == "n/a"
    assert estimate_cost({"state": "unavailable"}, [], table)["state"] == "unavailable"
    assert estimate_cost({"state": "n/a"}, [], table)["low"] is None


def test_t07_failover_prices_each_call_by_its_own_model_all_or_nothing():
    table = {"a-*": Price(1.0, 1.0, 0.0), "b-exact": Price(2.0, 2.0, 0.0)}
    calls = [{"state": "ok", "model": "a-large", "input_tokens": 1_000_000,
              "output_tokens": 0},
             {"state": "ok", "model": "b-exact", "input_tokens": 1_000_000,
              "output_tokens": 0}]
    assert estimate_cost(_OK_USAGE, calls, table)["low"] == 3.0
    # one unpriced model => no total at all (a partial sum would read as one)
    calls.append({"state": "ok", "model": "c-unknown", "input_tokens": 5,
                  "output_tokens": 5})
    assert estimate_cost(_OK_USAGE, calls, table)["state"] == "unpriced"


def test_t07_prefix_lookup_longest_wins_and_exact_beats_prefix():
    table = parse_price_table({
        "fam-*": {"input_per_mtok": 1, "output_per_mtok": 1},
        "fam-big-*": {"input_per_mtok": 2, "output_per_mtok": 2},
        "fam-big-1": {"input_per_mtok": 9, "output_per_mtok": 9}})
    assert lookup_price(table, "fam-small").input_per_mtok == 1
    assert lookup_price(table, "fam-big-2").input_per_mtok == 2
    assert lookup_price(table, "fam-big-1").input_per_mtok == 9
    assert lookup_price(table, "other") is None
    assert lookup_price(table, None) is None


def test_t07_price_table_parsing_is_strict_and_bounded():
    bad = {"neg": {"input_per_mtok": -1, "output_per_mtok": 1},
           "str": {"input_per_mtok": "1", "output_per_mtok": 1},
           "bool": {"input_per_mtok": True, "output_per_mtok": 1},
           "nan": {"input_per_mtok": float("nan"), "output_per_mtok": 1},
           "huge": {"input_per_mtok": 1e12, "output_per_mtok": 1},
           "missing": {"input_per_mtok": 1},
           "notdict": 5, "": {"input_per_mtok": 1, "output_per_mtok": 1},
           "ok": {"input_per_mtok": 1, "output_per_mtok": 2}}
    assert list(parse_price_table(bad)) == ["ok"]
    assert parse_price_table(["not", "a", "dict"]) == {}
    many = {f"m{i}": {"input_per_mtok": 1, "output_per_mtok": 1}
            for i in range(500)}
    assert len(parse_price_table(many)) <= 64


@pytest.mark.parametrize("text", ["", "not json", "[1,2]", "{" * 5000,
                                  "x" * 30_000])
def test_t07_garbage_env_table_degrades_to_empty_never_raises(text):
    assert load_price_table({PRICE_TABLE_ENV: text}) == {}


def test_t07_cost_is_in_every_report_row_via_the_chokepoint(monkeypatch):
    """Static/n-a runs and unpriced runs carry a typed cost block; a priced
    run carries a band — all through the one serialization chokepoint."""
    monkeypatch.delenv(PRICE_TABLE_ENV, raising=False)
    static = tel_mod.to_telemetry_row(RunTelemetry())
    assert static["cost"]["state"] == "n/a"
    ai = tel_mod.to_telemetry_row(RunTelemetry(
        provider="p", model="m-1",
        usage=tel_mod.UsageRecord.for_call("p", "m-1", 10, 10, 5)))
    assert ai["cost"]["state"] == "unpriced"
    monkeypatch.setenv(PRICE_TABLE_ENV, json.dumps(
        {"m-*": {"input_per_mtok": 1, "output_per_mtok": 1}}))
    priced = tel_mod.to_telemetry_row(RunTelemetry(
        provider="p", model="m-1",
        usage=tel_mod.UsageRecord.for_call("p", "m-1", 10, 10, 5)))
    assert priced["cost"]["state"] == "estimated"
    assert priced["cost"]["display_only"] is True


def test_t07_forged_cost_in_a_payload_cannot_claim_more_than_usage_allows():
    forged = _row(usage={"state": "n/a"},
                  cost={"state": "estimated", "currency": "USD",
                        "low": 1.0, "high": 2.0, "display_only": False})
    cost = sanitize_telemetry(forged)["cost"]
    assert cost["state"] == "n/a" and cost["low"] is None
    assert cost["display_only"] is True          # cannot be turned off
    for lo, hi in ((5, 1), (-1, 1), (float("nan"), 1), ("1", "2"),
                   (True, 2), (1e12, 1e12)):
        out = sanitize_telemetry(_row(cost={
            "state": "estimated", "currency": "USD", "low": lo, "high": hi,
            "display_only": True}))["cost"]
        assert out["state"] == "unpriced"         # recomputed, not trusted
    wrong_ccy = sanitize_telemetry(_row(cost={
        "state": "estimated", "currency": "EUR", "low": 1, "high": 2}))
    assert wrong_ccy["cost"]["currency"] == "USD"
    assert wrong_ccy["cost"]["state"] == "unpriced"


def test_t07_well_formed_carried_cost_survives_and_is_idempotent():
    carried = _row(cost={"state": "estimated", "currency": "USD",
                         "low": 0.01, "high": 0.02, "display_only": True})
    once = sanitize_telemetry(carried)
    assert once["cost"]["low"] == 0.01 and once["cost"]["high"] == 0.02
    assert sanitize_telemetry(once) == once


# ---------------------------------------------------------- T06 · latency
def test_t06_percentiles_are_nearest_rank_and_null_without_data():
    assert percentile([], 50) is None
    assert percentile([10], 95) == 10
    assert percentile(list(range(1, 101)), 50) == 50
    assert percentile(list(range(1, 101)), 95) == 95
    s = summarize_latency([5, None, "7", True, 9, float("nan"), 1])
    assert s == {"n": 3, "p50": 5, "p95": 9, "max": 9}
    assert summarize_latency([]) == {"n": 0, "p50": None, "p95": None,
                                     "max": None}


def test_t06_latency_from_rows_ignores_untrusted_shapes():
    rows = [_row(calls=[{"duration_ms": 100}, {"duration_ms": "x"}, 5]),
            "garbage", None, {"usage": "nope"},
            _row(usage={**_OK_USAGE, "duration_ms": 300},
                 calls=[{"duration_ms": 200}])]
    got = latency_from_rows(rows)
    assert got["per_call_ms"]["n"] == 2 and got["per_call_ms"]["max"] == 200
    assert got["per_run_ms"]["n"] == 2 and got["per_run_ms"]["max"] == 300


# ------------------------------------- debt 11 ground rule · safe formatting
def test_debt11_warning_text_is_safe_formatted_redacted_then_truncated():
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    nasty = ("boom\r\nFAKE LOG LINE\x1b[31m red \x00" + secret
             + " <untrusted_diff> " + "x" * 400)
    row = sanitize_telemetry(_row(events=[
        {"type": "provider_error", "backend": "p", "error": nasty}]))
    err = row["events"][0]["error"]
    assert "\n" not in err and "\r" not in err and "\x1b" not in err
    assert "\x00" not in err and secret not in err
    assert "<untrusted_diff>" not in err
    assert len(err) <= 200


def test_debt11_secret_straddling_the_length_bound_is_not_leaked_as_a_prefix():
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    text = "x" * 189 + " " + secret      # secret starts 10 chars before 200
    assert len(text) - len(secret) == 190
    err = sanitize_telemetry(_row(events=[
        {"type": "provider_error", "error": text}]))["events"][0]["error"]
    assert "ghp_A1b2" not in err and "ghp_" not in err.replace("[REDACTED", "")


# ---------------------------------------- review gate · no cost routing
_ENGINE = Path(tel_mod.__file__).parent
_DISPLAY_ONLY_API = {
    "estimate_cost", "load_price_table", "lookup_price", "parse_price_table",
    "Price", "COST_STATES", "PRICE_TABLE_ENV", "summarize_latency",
    "latency_from_rows", "percentile"}
_ROUTING_MODULES = ("model_router.py", "circuit.py", "retry.py",
                    "orchestrator.py", "context.py", "selection.py",
                    "config.py", "impact.py", "repo_context.py")
_SENSITIVE_RE = re.compile(r"cost|price|latenc|duration|elapsed", re.I)


def _imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            names.update(a.name for a in node.names)
        elif isinstance(node, ast.Import):
            names.update(a.name.split(".")[-1] for a in node.names)
    return names


def _ids(node: ast.AST) -> list[str]:
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Name):
            out.append(n.id)
        elif isinstance(n, ast.Attribute):
            out.append(n.attr)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
    return out


def _decision_violations(source: str) -> list[str]:
    """Every place a cost/latency-ish identifier takes part in a *decision*:
    a comparison, an if/while/ternary test, a boolean op, or a sort/min/max
    key. Recording (``x.duration_ms = ...``) is not a decision."""
    bad = []
    for n in ast.walk(ast.parse(source)):
        tests: list[ast.AST] = []
        if isinstance(n, (ast.Compare, ast.BoolOp)):
            tests.append(n)
        elif isinstance(n, (ast.If, ast.While, ast.IfExp)):
            tests.append(n.test)
        elif isinstance(n, ast.Call):
            fn = n.func.id if isinstance(n.func, ast.Name) else (
                n.func.attr if isinstance(n.func, ast.Attribute) else "")
            if fn in ("sorted", "sort", "min", "max"):
                tests.extend(kw.value for kw in n.keywords if kw.arg == "key")
                tests.extend(n.args)
        for t in tests:
            hits = [i for i in _ids(t) if _SENSITIVE_RE.search(i)]
            if hits:
                bad.append(f"line {getattr(n, 'lineno', '?')}: {hits[:3]}")
    return bad


def test_review_gate_negative_control_the_scanner_can_fail():
    """The gate is only meaningful if it would catch the thing it guards."""
    routed = ("def pick(tel, a, b):\n"
              "    if tel.duration_ms > 3000:\n        return b\n"
              "    return min([a, b], key=lambda p: p.cost)\n")
    assert len(_decision_violations(routed)) >= 2
    recorded = "def done(r, t0):\n    r.duration_ms = int(now() - t0)\n"
    assert _decision_violations(recorded) == []


def test_review_gate_no_engine_module_consumes_the_cost_or_latency_api():
    """V4_THREAT_MODEL §6 / V4-E11-T07: display-only. Only telemetry.py may
    even *import* the price/latency API — no other engine module."""
    offenders = []
    for path in sorted(_ENGINE.rglob("*.py")):
        if path.name == "telemetry.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        used = _imported_names(tree) & _DISPLAY_ONLY_API
        if used:
            offenders.append(f"{path.relative_to(_ENGINE)}: {sorted(used)}")
        if PRICE_TABLE_ENV in path.read_text(encoding="utf-8"):
            offenders.append(f"{path.name}: reads the price-table env var")
    assert offenders == [], offenders


@pytest.mark.parametrize("module", _ROUTING_MODULES)
def test_review_gate_no_routing_decision_depends_on_cost_or_latency(module):
    source = (_ENGINE / module).read_text(encoding="utf-8")
    assert _decision_violations(source) == [], (
        f"{module}: cost/latency/duration participates in a decision — "
        f"V4 has NO cost- or latency-based routing")


def test_review_gate_behavioral_routing_is_blind_to_price_table_and_latency(
        monkeypatch):
    """Same config -> same backend and same failover order, whatever the
    price table says and whatever telemetry latency history exists."""
    cfg = Config(anthropic_api_key="a", openai_api_key="o", gemini_api_key="g",
                 provider_order="gemini, claude, openai", model="")
    before = (router.select_backend(cfg), router.provider_order(cfg))
    monkeypatch.setenv(PRICE_TABLE_ENV, json.dumps({
        "*": {"input_per_mtok": 0, "output_per_mtok": 0},
        "claude-*": {"input_per_mtok": 1e5, "output_per_mtok": 1e5},
        "gemini-*": {"input_per_mtok": 0, "output_per_mtok": 0}}))
    router.reset_circuits()
    after_priced = (router.select_backend(cfg), router.provider_order(cfg))
    assert after_priced == before
    # a pathological latency history changes nothing either
    latency_from_rows([_row(usage={**_OK_USAGE, "duration_ms": 10**9})])
    assert (router.select_backend(cfg), router.provider_order(cfg)) == before


# ------------------------------------------- T06 · ingestion route (debt 15)
from fastapi.testclient import TestClient

from dashboard import app as dashboard_app

_TOKEN = "unit-test-token-0123456789abcdef"
_RID = "acme/widgets#7@abc123def456"


@pytest.fixture()
def dash(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dashboard_app, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(dashboard_app, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(dashboard_app, "_storage", None)
    monkeypatch.setattr(dashboard_app, "_api_token", None)
    monkeypatch.setenv("DASHBOARD_TOKEN", _TOKEN)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(dashboard_app, "limiter",
                        dashboard_app.SlidingWindowLimiter())
    with TestClient(dashboard_app.app) as client:
        yield client, tmp_path


def _post(client, body, token=_TOKEN, **kw):
    headers = {"X-Dashboard-Token": token} if token is not None else {}
    return client.post("/api/telemetry", json=body, headers=headers, **kw)


def test_t06_route_requires_the_dashboard_token(dash):
    client, tmp = dash
    body = {"review_id": _RID, "telemetry": _row()}
    assert _post(client, body, token=None).status_code == 401
    assert _post(client, body, token="wrong").status_code == 401
    assert _post(client, body, token="").status_code == 401
    assert dashboard_app.get_storage().get_telemetry(_RID) is None
    audit = (tmp / "audit.jsonl").read_text(encoding="utf-8")
    assert "auth_rejected" in audit and "telemetry_ingest" not in audit


def test_t06_route_auth_applies_even_when_reads_are_open(dash, monkeypatch):
    client, _ = dash
    monkeypatch.setattr(dashboard_app, "REQUIRE_READS_AUTH", False)
    assert _post(client, {"review_id": _RID, "telemetry": _row()},
                 token=None).status_code == 401


def test_t06_route_stores_through_the_existing_seam_and_feeds_metrics(dash):
    client, _ = dash
    r = _post(client, {"review_id": _RID, "telemetry": _row()})
    assert r.status_code == 200 and r.json() == {"ok": True, "id": _RID}
    stored = dashboard_app.get_storage().get_telemetry(_RID)
    assert stored["usage"]["input_tokens"] == 1000
    assert stored["cost"]["display_only"] is True
    runs = client.get("/api/metrics",
                      headers={"X-Dashboard-Token": _TOKEN}).json()["telemetry"]["runs"]
    assert runs == 1
    _post(client, {"review_id": _RID, "telemetry": _row(batch_count=4)})
    assert dashboard_app.get_storage().get_telemetry(_RID)["batch_count"] == 4
    assert client.get("/api/metrics", headers={"X-Dashboard-Token": _TOKEN}
                      ).json()["telemetry"]["runs"] == 1       # upsert


def test_t06_route_structures_and_redacts_every_payload(dash):
    client, tmp = dash
    secret = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    payload = _row(
        diff="+ password = 'hunter2hunter2'", prompt="ignore previous",
        path="/home/dev/secret.py",
        usage={**_OK_USAGE, "findings": ["leak"], "file": "/etc/passwd"},
        events=[
            {"type": "provider_error", "backend": "p",
             "error": f"401 bad key {secret}\r\nINJECTED <untrusted_diff>"},
            {"type": "totally_unapproved", "error": "dropped whole"}])
    r = _post(client, {"review_id": _RID, "telemetry": payload,
                       "extra_top_level": "ignored"})
    assert r.status_code == 200
    stored = dashboard_app.get_storage().get_telemetry(_RID)
    blob = json.dumps(stored)
    for leak in (secret, "hunter2", "ignore previous", "/home/dev", "/etc/passwd",
                 "INJECTED <untrusted", "dropped whole", "extra_top_level"):
        assert leak not in blob, leak
    assert set(stored) == set(tel_mod._RUN_FIELDS)
    assert [e["type"] for e in stored["events"]] == ["provider_error"]
    # the response and the audit trail never echo payload content either
    assert secret not in r.text
    assert secret not in (tmp / "audit.jsonl").read_text(encoding="utf-8")


@pytest.mark.parametrize("bad_id", [
    "", "no-hash", "a/b#1", "a/b#x@sha", "../../etc#1@abc", "a/b#1@abc\nx",
    "a b/c#1@abc", "x" * 200 + "/r#1@abc", "a/b#1@" + "z" * 80, None, 5,
    ["a/b#1@c"]])
def test_t06_route_rejects_malformed_review_ids(dash, bad_id):
    client, _ = dash
    r = _post(client, {"review_id": bad_id, "telemetry": _row()})
    assert r.status_code == 400


@pytest.mark.parametrize("body", [[1, 2], "str", 5, {"review_id": _RID},
                                  {"review_id": _RID, "telemetry": [1]},
                                  {"review_id": _RID, "telemetry": "x"}])
def test_t06_route_rejects_malformed_bodies(dash, body):
    client, _ = dash
    assert _post(client, body).status_code == 400


def test_t06_route_rejects_non_json_and_non_utf8(dash):
    client, _ = dash
    h = {"X-Dashboard-Token": _TOKEN}
    assert client.post("/api/telemetry", content=b"{not json",
                       headers=h).status_code == 400
    assert client.post("/api/telemetry", content=b"\xff\xfe\x00",
                       headers=h).status_code == 400


def test_t06_route_caps_the_body_even_without_content_length(dash):
    client, _ = dash
    h = {"X-Dashboard-Token": _TOKEN}
    big = json.dumps({"review_id": _RID, "telemetry": _row(),
                      "pad": "x" * 70_000}).encode()
    assert client.post("/api/telemetry", content=big,
                       headers=h).status_code == 413

    def chunks():                      # chunked: no Content-Length header
        for i in range(0, len(big), 4096):
            yield big[i:i + 4096]

    assert client.post("/api/telemetry", content=chunks(),
                       headers=h).status_code == 413
    assert dashboard_app.get_storage().get_telemetry(_RID) is None


def test_t06_route_is_additive_existing_routes_unchanged(dash):
    client, _ = dash
    paths = {r.path for r in dashboard_app.app.routes}
    for existing in ("/api/reports", "/api/metrics", "/api/health",
                     "/api/findings", "/api/settings", "/api/config"):
        assert existing in paths
    assert "/api/telemetry" in paths


def test_t06_route_documents_lan_scope_and_claims_no_network_auth():
    src = Path(dashboard_app.__file__).read_text(encoding="utf-8")
    start = src.index("V4-E11-T06 (debt 15)")
    block = src[start:src.index('@app.post("/api/telemetry")')]
    assert "LAN" in block and "NO network-grade" in block
    doc = dashboard_app.ingest_telemetry.__doc__
    assert "LAN-scope only" in doc


def test_t06_operator_doc_states_lan_scope_and_never_claims_network_auth():
    doc = (ROOT / "docs" / "TELEMETRY_INGESTION.md").read_text(encoding="utf-8")
    low = doc.lower()
    assert "lan / trusted-network only" in low
    assert "no network-grade authentication" in low
    assert "v4.5.0" in doc                      # V5 ships publicly as v4.5.0
    for overclaim in ("secure by default", "production-grade auth",
                      "mutual tls", "is authenticated end-to-end"):
        assert overclaim not in low
    assert "display only" in low and "never influences routing" in low
    # the documented example must be the real parseable shape
    import re as _re
    example = _re.search(r"AI_PR_REVIEWER_PRICE_TABLE='(\{.*?\})'", doc, _re.S)
    assert parse_price_table(json.loads(example.group(1)))
