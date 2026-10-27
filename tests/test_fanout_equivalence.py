"""V4.0-E01-T05 - fan-out feature flag and the single-agent equivalence gate.

The most important test here is the equivalence one: with the flag OFF the
review result is what it was before this epic, and with the flag ON and the
single generalist task it is identical too (modulo the two wall-clock
fields). Everything is offline: fake provider, local-diff mode.
"""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_pr_reviewer import model_router as router
from ai_pr_reviewer import orchestrator as orch
from ai_pr_reviewer.circuit import active_registry
from ai_pr_reviewer.cli import parse_args
from ai_pr_reviewer.config import KNOWN_INPUT_ENV_VARS, Config, load_config
from ai_pr_reviewer.models import AnalysisOutcome, Finding, PRContext
from ai_pr_reviewer.orchestration import runner

ROOT = Path(__file__).resolve().parents[1]
DIFF = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
        "@@ -1,2 +1,3 @@\n ctx\n+x = 1\n ctx2\n")
VOLATILE = ("reviewed_at", "duration_ms")


@pytest.fixture(autouse=True)
def _fresh_circuits():
    router.reset_circuits()
    yield
    router.reset_circuits()


# ------------------------------------------------------------------ the flag

def _clear(monkeypatch):
    for name in ("INPUT_FANOUT_ENABLED", "FANOUT_ENABLED"):
        monkeypatch.delenv(name, raising=False)


def test_flag_defaults_off(monkeypatch):
    _clear(monkeypatch)
    assert Config().fanout_enabled is False
    assert load_config(parse_args([])).fanout_enabled is False


@pytest.mark.parametrize("raw,expected", [
    ("true", True), ("1", True), ("YES", True), ("on", True),
    ("false", False), ("0", False), ("nonsense", False)])
def test_flag_reads_the_environment(monkeypatch, raw, expected):
    _clear(monkeypatch)
    monkeypatch.setenv("INPUT_FANOUT_ENABLED", raw)
    assert load_config(parse_args([])).fanout_enabled is expected


def test_flag_layering_is_cli_then_input_then_plain_env_then_default(monkeypatch):
    _clear(monkeypatch)
    monkeypatch.setenv("FANOUT_ENABLED", "true")
    assert load_config(parse_args([])).fanout_enabled is True          # plain env
    monkeypatch.setenv("INPUT_FANOUT_ENABLED", "false")
    assert load_config(parse_args([])).fanout_enabled is False         # INPUT_* wins
    args = parse_args([])
    args.fanout = True
    assert load_config(args).fanout_enabled is True                    # CLI wins


def test_the_flag_is_declared_but_the_action_contract_is_untouched():
    assert "INPUT_FANOUT_ENABLED" in KNOWN_INPUT_ENV_VARS
    action_text = (ROOT / "action.yml").read_text(encoding="utf-8")
    assert "fanout" not in action_text.lower()          # not an Action input


# ------------------------------------------------------------- wiring helpers

class FakeStorage:
    def __init__(self):
        self.saved = []
        self.set_calls = []

    def save_findings(self, review_id, findings):
        self.saved.append(review_id)

    def set_last_reviewed_sha(self, repo, pr_number, sha, base_sha):
        self.set_calls.append(sha)


class FakeProvider:
    """Fresh outcome per call: the pipeline mutates findings in place."""

    backend = ""
    startup_warnings: list = []

    def __init__(self):
        self.calls = 0

    def analyze(self, context):
        self.calls += 1
        finding = Finding(file="a.py", line=2, severity="high",
                          title="SQL injection", explanation="because")
        return AnalysisOutcome(findings=[finding], summary="all good",
                               mode="claude", model="claude-test",
                               warnings=["w1"], engine="claude", batch_count=3)


def _review(monkeypatch, *, fanout, storage=None, analysis=None):
    provider = FakeProvider()
    monkeypatch.setattr(orch, "build_context", lambda pr, files, cfg, storage=None,
                        gh=None: SimpleNamespace(pr=pr, files=files,
                                                 previous_findings=[]))
    monkeypatch.setattr(orch, "get_provider", lambda cfg, context: provider)
    if analysis is not None:
        monkeypatch.setattr(orch, "run_analysis", analysis)
    cfg = Config(repo="acme/api", pr_number=7, severity_threshold="low",
                 max_comments=20)
    cfg.fanout_enabled = fanout
    pr = PRContext(repo="acme/api", pr_number=7, head_sha="head123")
    result = orch.ReviewOrchestrator(cfg, None, storage, pr=pr,
                                     diff_text=DIFF).run()
    return result, provider


def _stable(result) -> dict:
    data = result.to_dict()
    for key in VOLATILE:
        data.pop(key, None)
    return data


# ----------------------------------------------------------- equivalence gate

def test_flag_off_never_touches_the_fanout_layer(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("fan-out layer ran with the flag off")

    monkeypatch.setattr(runner, "run_fanout_analysis", forbidden)
    result, provider = _review(monkeypatch, fanout=False)
    assert provider.calls == 1 and result.engine == "claude"


def test_flag_off_calls_run_analysis_exactly_as_before(monkeypatch):
    seen = []

    def spy(cfg, context, provider):
        seen.append((cfg, context, provider))
        return provider.analyze(context)

    _, provider = _review(monkeypatch, fanout=False, analysis=spy)
    assert len(seen) == 1 and seen[0][2] is provider


def test_flag_on_single_task_result_is_identical_to_single_agent(monkeypatch):
    off, _ = _review(monkeypatch, fanout=False)
    on, provider = _review(monkeypatch, fanout=True)

    assert provider.calls == 1                       # one call, not two
    assert _stable(on) == _stable(off)
    assert (on.engine, on.fallback_used, on.review_state) == \
        (off.engine, off.fallback_used, off.review_state)
    assert not getattr(on, "analysis_degraded", False)


def test_flag_on_and_off_persist_and_advance_the_sha_identically(monkeypatch):
    s_off, s_on = FakeStorage(), FakeStorage()
    _review(monkeypatch, fanout=False, storage=s_off)
    _review(monkeypatch, fanout=True, storage=s_on)

    assert s_on.set_calls == s_off.set_calls == ["head123"]
    assert len(s_on.saved) == len(s_off.saved) == 1


def test_runner_returns_the_very_same_outcome_object(monkeypatch):
    produced = []

    def analyze(cfg, context, provider):
        outcome = provider.analyze(context)
        produced.append(outcome)
        return outcome

    out = runner.run_fanout_analysis(Config(), SimpleNamespace(files=[]),
                                     FakeProvider(), analyze=analyze)
    assert out is produced[0]


def test_the_generalist_task_runs_inside_its_own_breaker_scope(monkeypatch):
    scopes = []

    def analyze(cfg, context, provider):
        scopes.append(active_registry())
        router.breaker_for("claude").record_failure()
        return provider.analyze(context)

    _review(monkeypatch, fanout=True, analysis=analyze)

    assert scopes[0] is not None
    assert router._BREAKERS == {}                    # global registry untouched
    assert active_registry() is None                 # scope did not leak out


# --------------------------------------------------------- degraded end to end

def test_fanout_task_failure_is_labelled_static_and_never_advances_the_sha(monkeypatch):
    def broken(cfg, context, provider):
        raise RuntimeError("provider exploded with secret-looking-text")

    storage = FakeStorage()
    result, _ = _review(monkeypatch, fanout=True, storage=storage, analysis=broken)
    text = "\n".join(result.warnings)

    assert (result.engine, result.fallback_used, result.review_state) == \
        ("static", True, "fallback")
    assert result.analysis_degraded is True and result.fanout_degraded is True
    assert "Degraded multi-task review" in text
    assert "'generalist' failed (RuntimeError)" in text
    assert "not from an AI review" in text
    assert "not every review task completed" in text
    assert "secret-looking-text" not in text
    assert storage.saved and storage.set_calls == []   # stored, SHA not advanced
    assert result.to_dict()                             # still serializes


def test_partial_degradation_with_an_ai_engine_still_does_not_advance(monkeypatch):
    def overrun(cfg, context, provider):
        outcome = provider.analyze(context)
        outcome.fanout_degraded = True
        return outcome

    storage = FakeStorage()
    result, _ = _review(monkeypatch, fanout=True, storage=storage, analysis=overrun)

    assert result.engine == "claude"                    # AI engine truly ran
    assert result.analysis_degraded is True
    assert storage.set_calls == []


def test_flag_off_degradation_wording_is_unchanged(monkeypatch):
    """The pre-existing static-fallback path keeps its own message verbatim."""
    def failing(cfg, context, provider):
        raise RuntimeError("boom")

    storage = FakeStorage()
    monkeypatch.setattr(orch, "build_context", lambda pr, files, cfg, storage=None,
                        gh=None: SimpleNamespace(pr=pr, files=files,
                                                 previous_findings=[]))
    monkeypatch.setattr(orch, "get_provider", lambda cfg, context: FakeProvider())
    provider = SimpleNamespace(backend="", startup_warnings=[],
                               analyze=lambda ctx: failing(None, None, None))
    monkeypatch.setattr(orch, "get_provider", lambda cfg, context: provider)
    cfg = Config(repo="acme/api", pr_number=7, severity_threshold="low")
    pr = PRContext(repo="acme/api", pr_number=7, head_sha="head123")
    result = orch.ReviewOrchestrator(cfg, None, storage, pr=pr,
                                     diff_text=DIFF).run()

    text = "\n".join(result.warnings)
    assert "no AI provider completed this review" in text
    assert "not every review task completed" not in text
    assert not hasattr(result, "fanout_degraded")
    assert storage.set_calls == []
