"""Tests for the AI provider abstraction:
RetryPolicy, ClaudeProvider (success + per-batch static fallback),
model_router provider selection, and the legacy ClaudeAnalyzer adapter that
keeps ``cli.py`` working unchanged.

No network access — the Anthropic HTTP client is always mocked.
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

from ai_pr_reviewer.ai.claude import ClaudeProvider
from ai_pr_reviewer.ai.provider import AIProvider
from ai_pr_reviewer.analyzer import ClaudeAnalyzer
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.diff_parser import parse_unified_diff
from ai_pr_reviewer.model_router import StaticProvider, classify_risk, get_provider
from ai_pr_reviewer.retry import RetryPolicy


# --------------------------------------------------------------------------- helpers
class FakeResponse:
    """Stands in for an httpx.Response without any network I/O."""

    def __init__(self, status_code: int, json_data: dict | None = None):
        self.status_code = status_code
        self._json = json_data or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"status {self.status_code}",
                request=httpx.Request("POST", "https://api.anthropic.com/v1/messages"),
                response=self,
            )

    def json(self) -> dict:
        return self._json


def _claude_envelope(summary: str, findings: list[dict], warnings: list[str] | None = None) -> dict:
    """Wrap a review payload the way the real Anthropic Messages API does."""
    body = json.dumps({"summary": summary, "findings": findings, "warnings": warnings or []})
    return {
        "usage": {"input_tokens": 10, "output_tokens": 5},
        "content": [{"type": "text", "text": body}],
    }


def _diff(path: str, old_lines: list[str], added_after: str):
    """Build a one-hunk FileDiff: `old_lines` as context, `added_after` as a
    single added line following them."""
    ctx = "".join(f" {ln}\n" for ln in old_lines)
    added = f"+{added_after}\n"
    text = (f"--- a/{path}\n+++ b/{path}\n"
           f"@@ -1,{len(old_lines)} +1,{len(old_lines) + 1} @@\n{ctx}{added}")
    return parse_unified_diff(text)[0]


# ------------------------------------------------------------------ RetryPolicy.is_retryable
class _FakeResponseRef:
    def __init__(self, status_code: int):
        self.status_code = status_code


class _FakeExcWithResponse(Exception):
    def __init__(self, status_code: int):
        super().__init__(f"http {status_code}")
        self.response = _FakeResponseRef(status_code)


class _FakeReadTimeout(Exception):
    """Named to match retry.py's exception-name fallback classification."""


def test_is_retryable_auth_errors_are_permanent():
    policy = RetryPolicy()
    assert policy.is_retryable(401, None) is False
    assert policy.is_retryable(403, None) is False
    assert policy.is_retryable(404, None) is False


def test_is_retryable_rate_limit_and_server_errors():
    policy = RetryPolicy()
    assert policy.is_retryable(429, None) is True
    assert policy.is_retryable(500, None) is True
    assert policy.is_retryable(503, None) is True


def test_is_retryable_reads_status_off_wrapped_exception():
    policy = RetryPolicy()
    assert policy.is_retryable(None, _FakeExcWithResponse(429)) is True
    assert policy.is_retryable(None, _FakeExcWithResponse(401)) is False


def test_is_retryable_network_exception_by_name():
    policy = RetryPolicy()
    assert policy.is_retryable(None, _FakeReadTimeout("boom")) is False  # unknown name

    class ConnectError(Exception):
        pass

    assert policy.is_retryable(None, ConnectError("no route")) is True


# -------------------------------------------------------------------------- RetryPolicy.call
def test_retry_gives_up_on_401_immediately():
    fn = Mock(return_value=FakeResponse(401))
    policy = RetryPolicy(max_attempts=3, base_delay=0.0)

    result = policy.call(fn)

    assert result.status_code == 401
    assert fn.call_count == 1  # no retries burned on a permanent failure


def test_retry_succeeds_after_429_and_500(monkeypatch):
    monkeypatch.setattr("ai_pr_reviewer.retry.time.sleep", lambda seconds: None)
    fn = Mock(side_effect=[FakeResponse(429), FakeResponse(500), FakeResponse(200)])
    policy = RetryPolicy(max_attempts=3, base_delay=0.0)

    result = policy.call(fn)

    assert result.status_code == 200
    assert fn.call_count == 3


def test_retry_exhausts_and_returns_last_failing_response(monkeypatch):
    monkeypatch.setattr("ai_pr_reviewer.retry.time.sleep", lambda seconds: None)
    fn = Mock(return_value=FakeResponse(500))
    policy = RetryPolicy(max_attempts=2, base_delay=0.0)

    result = policy.call(fn)

    assert result.status_code == 500
    assert fn.call_count == 2  # tried max_attempts times, then gave the caller the response


def test_retry_reraises_last_exception_when_exhausted(monkeypatch):
    monkeypatch.setattr("ai_pr_reviewer.retry.time.sleep", lambda seconds: None)

    class ConnectError(Exception):
        pass

    fn = Mock(side_effect=ConnectError("no route"))
    policy = RetryPolicy(max_attempts=2, base_delay=0.0)

    with pytest.raises(ConnectError):
        policy.call(fn)
    assert fn.call_count == 2


# ------------------------------------------------------------------------- ClaudeProvider
def test_claude_provider_success_path():
    provider = ClaudeProvider(api_key="sk-ant-test", model="claude-sonnet-4-6")
    fd = _diff("app.py", ["def handler():"], '    return "ok"')
    context = SimpleNamespace(files=[fd], focus_areas=[])

    envelope = _claude_envelope(
        "Straightforward change.",
        [{"file": "app.py", "line": 2, "severity": "low", "category": "style",
          "title": "Minor nit", "explanation": "Consider a constant.",
          "confidence": "medium"}],
    )
    provider._client.post = Mock(return_value=FakeResponse(200, envelope))

    outcome = provider.analyze(context)

    assert provider._client.post.call_count == 1
    assert outcome.engine == "claude"
    assert outcome.fallback_used is False
    assert outcome.batch_count == 1
    assert [f.title for f in outcome.findings] == ["Minor nit"]
    assert provider.total_input_tokens == 10
    assert provider.total_output_tokens == 5


def test_claude_provider_includes_trusted_project_rules():
    provider = ClaudeProvider(api_key="sk-ant-test")
    fd = _diff("app.py", ["def handler():"], '    return "ok"')
    context = SimpleNamespace(
        files=[fd],
        focus_areas=[],
        project_rules=SimpleNamespace(rules=["All database access uses repositories."]),
    )
    provider._client.post = Mock(return_value=FakeResponse(200, _claude_envelope("fine", [])))

    provider.analyze(context)

    request = provider._client.post.call_args.kwargs["json"]
    prompt = request["messages"][0]["content"]
    assert "Repository-owner rules (trusted):" in prompt
    assert "All database access uses repositories." in prompt


def test_claude_provider_per_batch_fallback_on_failed_batch():
    """Acceptance: a batch that fails after retries falls back to the
    deterministic static analyzer for just that batch, and the outcome
    honestly reports engine='claude+static'."""
    provider = ClaudeProvider(
        api_key="sk-ant-test", model="claude-sonnet-4-6",
        batch_chars=1,  # force every file into its own batch
        retry=RetryPolicy(max_attempts=1, base_delay=0.0),  # fail fast, no sleeping
    )

    ok_file = _diff("app.py", ["def handler():"], '    return "ok"')
    bad_file = _diff("utils.py", ["def run(cmd):"], "    eval(cmd)")
    context = SimpleNamespace(files=[ok_file, bad_file], focus_areas=[])

    envelope = _claude_envelope(
        "Looks fine.",
        [{"file": "app.py", "line": 2, "severity": "low", "category": "style",
          "title": "Minor nit", "explanation": "e", "confidence": "medium"}],
    )
    provider._client.post = Mock(side_effect=[
        FakeResponse(200, envelope),           # batch 1 (app.py): Claude succeeds
        httpx.ConnectError("connection reset"),  # batch 2 (utils.py): Claude fails
    ])

    outcome = provider.analyze(context)

    assert outcome.batch_count == 2
    assert outcome.fallback_used is True
    assert outcome.engine == "claude+static"
    titles = {f.title for f in outcome.findings}
    assert "Minor nit" in titles                              # from Claude (batch 1)
    assert any("eval()" in t for t in titles)                 # from static fallback (batch 2)
    fallback_finding = next(f for f in outcome.findings if f.rule_id == "SEC003")
    assert fallback_finding.file == "utils.py"
    assert any("failed after retries" in w for w in outcome.warnings)


def test_claude_provider_all_batches_fail_reports_pure_static_engine():
    provider = ClaudeProvider(
        api_key="sk-ant-test",
        retry=RetryPolicy(max_attempts=1, base_delay=0.0),
    )
    bad_file = _diff("utils.py", ["def run(cmd):"], "    eval(cmd)")
    context = SimpleNamespace(files=[bad_file], focus_areas=[])
    provider._client.post = Mock(side_effect=httpx.ConnectError("down"))

    outcome = provider.analyze(context)

    assert outcome.fallback_used is True
    assert outcome.engine == "static"          # no batch ever succeeded via Claude
    assert any(f.rule_id == "SEC003" for f in outcome.findings)


def test_claude_provider_implements_ai_provider_protocol():
    provider = ClaudeProvider(api_key="sk-ant-test")
    assert isinstance(provider, AIProvider)


# ------------------------------------------------------------- legacy ClaudeAnalyzer adapter
def test_claude_analyzer_legacy_adapter_accepts_raw_file_list():
    """cli.py still calls `analyzer.analyze(files)` with a plain
    list[FileDiff] — verify the adapter over ClaudeProvider keeps that
    working (and still gets retry/fallback behavior for free)."""
    analyzer = ClaudeAnalyzer(api_key="sk-ant-test", model="claude-sonnet-4-6")
    fd = _diff("app.py", ["def handler():"], '    return "ok"')

    envelope = _claude_envelope("fine", [])
    analyzer._provider._client.post = Mock(return_value=FakeResponse(200, envelope))

    outcome = analyzer.analyze([fd])  # raw list, NOT a ReviewContext

    assert outcome.mode == "claude"
    assert outcome.findings == []
    assert analyzer.total_input_tokens == 10


# --------------------------------------------------------------------------- model_router
def test_get_provider_returns_static_when_mock():
    cfg = Config(mock=True)
    provider = get_provider(cfg, SimpleNamespace(files=[], focus_areas=[]))
    assert isinstance(provider, StaticProvider)


def test_get_provider_returns_static_when_no_api_key():
    cfg = Config(anthropic_api_key="", mock=False)
    provider = get_provider(cfg, SimpleNamespace(files=[], focus_areas=[]))
    assert isinstance(provider, StaticProvider)


def test_get_provider_returns_claude_when_api_key_present():
    cfg = Config(anthropic_api_key="sk-ant-test", model="claude-sonnet-4-6", mock=False)
    provider = get_provider(cfg, SimpleNamespace(files=[], focus_areas=[]))
    assert isinstance(provider, ClaudeProvider)
    assert provider.model == "claude-sonnet-4-6"


def test_get_provider_flags_high_risk_pr_as_warning_only():
    cfg = Config(anthropic_api_key="sk-ant-test", mock=False)
    payment_file = _diff("payments/charge.py", ["def charge():"], "    run()")
    provider = get_provider(cfg, SimpleNamespace(files=[payment_file], focus_areas=[]))

    assert isinstance(provider, ClaudeProvider)         # risk doesn't change the provider type
    assert any("high-risk" in w for w in provider.startup_warnings)


def test_get_provider_uses_maximum_project_review_mode():
    cfg = Config(anthropic_api_key="sk-ant-test", mock=False)
    context = SimpleNamespace(
        files=[],
        focus_areas=[],
        project_rules=SimpleNamespace(mode="maximum"),
    )

    provider = get_provider(cfg, context)

    assert isinstance(provider, ClaudeProvider)
    assert provider.max_tokens == 8_192


def test_classify_risk_low_for_ordinary_change():
    plain_file = _diff("README.md", ["# Title"], "Some docs.")
    risk = classify_risk(SimpleNamespace(files=[plain_file], focus_areas=[]))
    assert risk.level == "low"
    assert risk.reasons == []


def test_static_provider_adapts_static_analyzer_to_context():
    provider = StaticProvider()
    bad_file = _diff("utils.py", ["def run(cmd):"], "    eval(cmd)")
    outcome = provider.analyze(SimpleNamespace(files=[bad_file], focus_areas=[]))
    assert outcome.mode == "static"
    assert any(f.rule_id == "SEC003" for f in outcome.findings)
    assert isinstance(provider, AIProvider)
