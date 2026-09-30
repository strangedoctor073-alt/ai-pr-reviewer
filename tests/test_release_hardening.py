"""Regression tests for the v2 pre-release audit.

Each test pins a bug that was found (and reproduced) before release.
"""
from __future__ import annotations

import json
from unittest.mock import Mock

import httpx
import pytest

from ai_pr_reviewer import cli
from ai_pr_reviewer import orchestrator as orch
from ai_pr_reviewer.ai.gemini import GeminiProvider
from ai_pr_reviewer.config import Config, load_config
from ai_pr_reviewer.context import ReviewContext
from ai_pr_reviewer.diff_parser import FileDiff
from ai_pr_reviewer.model_router import (get_provider, provider_config_error,
                                         select_backend)
from ai_pr_reviewer.models import PRContext

GEMINI_KEY = "AIzaSyD-FAKEFAKEFAKEFAKEFAKEFAKEFAKE12345"
DIFF = ("diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
        "@@ -0,0 +1,2 @@\n+import os\n+def f(x=[]): return x\n")


def _ctx():
    ctx = Mock(spec=ReviewContext)
    ctx.files = [FileDiff("a.py", "a.py")]
    ctx.focus_areas = []
    ctx.project_rules = None
    return ctx


# ------------------------------------------------ Gemini key must never be in a URL
def test_gemini_key_is_sent_as_header_not_in_url(monkeypatch):
    provider = GeminiProvider(api_key=GEMINI_KEY, model="some-model")
    seen = {}

    def fake_post(url, **kwargs):
        seen["url"], seen["headers"] = url, kwargs.get("headers", {})
        resp = Mock()
        resp.raise_for_status = Mock()
        resp.json.return_value = {"candidates": [{"content": {"parts": [
            {"text": '{"summary": "ok", "findings": []}'}]}}]}
        return resp

    monkeypatch.setattr(provider._client, "post", fake_post)
    provider.analyze(_ctx())
    assert GEMINI_KEY not in seen["url"]
    assert "key=" not in seen["url"]
    assert seen["headers"].get("x-goog-api-key") == GEMINI_KEY


def test_provider_failure_text_does_not_contain_the_key(monkeypatch):
    """httpx puts the request URL in HTTPStatusError text; it must be key-free."""
    provider = GeminiProvider(api_key=GEMINI_KEY, model="some-model")

    def fake_post(url, **kwargs):
        req = httpx.Request("POST", url)
        resp = httpx.Response(400, json={}, request=req)
        raise httpx.HTTPStatusError(
            f"Client error '400 Bad Request' for url '{url}'",
            request=req, response=resp)

    monkeypatch.setattr(provider._client, "post", fake_post)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    outcome = provider.analyze(_ctx())
    assert outcome.warnings, "a failed batch must surface a warning"
    assert all(GEMINI_KEY not in w for w in outcome.warnings)


# ---------------------------------------------- exact-secret scrubbing (any format)
def test_scrub_removes_configured_credentials_even_if_pattern_unknown():
    cfg = Config(gemini_api_key="totally-custom-key-format-9f8e7d",
                 github_token="tok_abcdef123456")
    text = "boom for url https://x/y?k=totally-custom-key-format-9f8e7d tok_abcdef123456"
    out = orch._scrub(text, cfg)
    assert "totally-custom-key-format-9f8e7d" not in out
    assert "tok_abcdef123456" not in out


# ------------------------------------------------------------ model selection rules
def test_config_has_no_cross_vendor_default_model(monkeypatch):
    monkeypatch.delenv("INPUT_MODEL", raising=False)
    assert Config().model == ""
    args = cli.parse_args(["--repo", "a/b", "--pr", "1"])
    assert load_config(args).model == ""


def test_openai_or_gemini_without_model_is_a_config_error():
    assert "explicit model" in provider_config_error(Config(openai_api_key="k"))
    assert "explicit model" in provider_config_error(Config(gemini_api_key="k"))
    assert provider_config_error(Config(openai_api_key="k", model="m")) is None
    assert provider_config_error(Config(gemini_api_key="k", model="m")) is None


def test_claude_and_static_need_no_explicit_model():
    assert provider_config_error(Config(anthropic_api_key="k")) is None
    assert provider_config_error(Config(mock=True)) is None
    assert provider_config_error(Config()) is None


def test_openai_compatible_endpoint_without_key_selects_openai():
    # Ollama / vLLM style: base URL, no API key.
    cfg = Config(openai_base_url="http://localhost:11434/v1", model="llama3")
    assert select_backend(cfg) == "openai"
    provider = get_provider(cfg, _ctx())
    assert type(provider).__name__ == "OpenAIProvider"
    assert provider.model == "llama3"


def test_router_never_sends_a_claude_model_to_another_vendor():
    cfg = Config(openai_api_key="k", model="gpt-x")
    assert get_provider(cfg, _ctx()).model == "gpt-x"
    cfg = Config(gemini_api_key="k", model="gemini-x")
    assert get_provider(cfg, _ctx()).model == "gemini-x"


def test_cli_exits_1_with_clear_message_when_model_missing(monkeypatch, capsys, tmp_path):
    diff = tmp_path / "d.diff"
    diff.write_text(DIFF)
    for var in ("INPUT_MODEL", "INPUT_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    rc = cli.main(["--diff-file", str(diff), "--repo", "a/b", "--pr", "1",
                   "--openai-api-key", "sk-test", "--no-comment",
                   "--output", str(tmp_path / "r.json")])
    assert rc == 1
    assert "explicit model" in capsys.readouterr().err


# ------------------------------------------- policy file changed by the PR is flagged
def test_pr_that_modifies_policy_file_gets_a_warning(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    policy_diff = ("diff --git a/.ai-pr-reviewer.yml b/.ai-pr-reviewer.yml\n"
                   "--- a/.ai-pr-reviewer.yml\n+++ b/.ai-pr-reviewer.yml\n"
                   "@@ -0,0 +1,2 @@\n+exclude:\n+  - \"**/*.py\"\n") + DIFF
    cfg = Config(mock=True, repo="a/b", pr_number=1)
    pr = PRContext(repo="a/b", pr_number=1)
    result = orch.ReviewOrchestrator(cfg, None, pr=pr, diff_text=policy_diff).run()
    assert any(".ai-pr-reviewer.yml" in w and "untrusted" in w for w in result.warnings)

    clean = orch.ReviewOrchestrator(cfg, None, pr=pr, diff_text=DIFF).run()
    assert not any(".ai-pr-reviewer.yml" in w for w in clean.warnings)


# --------------------------------------------------- declared Action outputs are set
def test_action_writes_every_declared_output(tmp_path, monkeypatch):
    diff = tmp_path / "d.diff"
    diff.write_text(DIFF)
    out_file = tmp_path / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "summary.md"))
    monkeypatch.chdir(tmp_path)
    rc = cli.main(["--diff-file", str(diff), "--repo", "a/b", "--pr", "1",
                   "--mock", "--no-comment", "--output", str(tmp_path / "r.json")])
    assert rc == 0
    written = dict(line.split("=", 1) for line in out_file.read_text().splitlines())
    for name in ("findings_count", "critical_count", "report_path",
                 "health_score", "health_grade"):
        assert name in written, f"declared output {name!r} was never written"
    assert written["health_score"].isdigit()


def test_action_yml_outputs_match_what_the_cli_writes():
    """Every output declared in action.yml must be one the CLI can write."""
    import pathlib
    import re
    text = (pathlib.Path(__file__).resolve().parent.parent / "action.yml").read_text()
    declared = set(re.findall(r"^  (\w+):\n    description:.*\n    value:", text, re.M))
    cli_src = (pathlib.Path(cli.__file__)).read_text()
    for name in declared:
        assert f'"{name}"' in cli_src, f"action.yml declares output {name!r} the CLI never sets"


def test_missing_diff_file_is_a_clean_error_not_a_traceback(tmp_path):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--diff-file", str(tmp_path / "nope.diff"), "--repo", "a/b",
                  "--pr", "1", "--mock", "--no-comment"])
    assert "cannot read --diff-file" in str(exc.value)


def test_orchestrator_scrubs_provider_warnings_end_to_end(tmp_path, monkeypatch):
    """A provider error that echoes the API key must not reach the result."""
    from ai_pr_reviewer.models import AnalysisOutcome

    secret = "totally-custom-key-format-9f8e7d"

    class LeakyProvider:
        def analyze(self, context):
            return AnalysisOutcome(
                findings=[], summary="s", mode="ai", model="m",
                warnings=[f"Batch 1/1 failed (url 'https://h/x?key={secret}')"])

    monkeypatch.setattr(orch, "get_provider", lambda cfg, ctx: LeakyProvider())
    monkeypatch.chdir(tmp_path)
    cfg = Config(gemini_api_key=secret, model="m", repo="a/b", pr_number=1)
    result = orch.ReviewOrchestrator(cfg, None, pr=PRContext(repo="a/b", pr_number=1),
                                     diff_text=DIFF).run()
    assert result.warnings
    assert all(secret not in w for w in result.warnings)
    assert json.dumps([w for w in result.warnings]).count(secret) == 0


def test_get_provider_refuses_to_guess_a_model_for_openai_or_gemini():
    with pytest.raises(ValueError, match="explicit model"):
        get_provider(Config(openai_api_key="k"), _ctx())
    with pytest.raises(ValueError, match="explicit model"):
        get_provider(Config(gemini_api_key="k"), _ctx())


def test_no_retired_model_ids_are_hardcoded_in_the_engine():
    import pathlib
    root = pathlib.Path(cli.__file__).parent
    banned = ("gemini-2.0", "gemini-1.5", "claude-3-5", "claude-3-7")
    for path in root.rglob("*.py"):
        # Explicit encoding: the default is locale-dependent (cp1252 on
        # Windows), and these sources are UTF-8 with non-ASCII punctuation.
        text = path.read_text(encoding="utf-8")
        for b in banned:
            assert b not in text, f"{path.name} hard-codes retired model id {b!r}"
