"""V3 C6 — provider failover and the circuit breaker.

Failover is only useful if it is *bounded* and *honest*:

* one backend's failure (or bad optional config) never fails the review —
  the next backend runs, and the deterministic rule engine is the last
  fallback, labelled as not-an-AI-review;
* a backend that keeps failing is parked by an in-process circuit breaker
  instead of paying for another timeout on every batch;
* primary configuration errors still fail fast (only the *first* backend is
  strictly validated);
* nothing in a warning may echo an exception message, which can carry a
  request body or a key.
"""
from __future__ import annotations

import time

import pytest

from ai_pr_reviewer import model_router as router
from ai_pr_reviewer.analyzer import AnalysisOutcome
from ai_pr_reviewer.circuit import CLOSED, HALF_OPEN, OPEN, CircuitBreaker
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.context import ReviewContext
from ai_pr_reviewer.models import PRContext


def _context(files=None) -> ReviewContext:
    return ReviewContext(pr=PRContext(repo="acme/api", pr_number=7),
                         files=list(files or []), project_rules=None,
                         previous_findings=[], memory_notes=[], focus_areas=[])


CONTEXT = _context()


def _outcome(engine: str = "claude", summary: str = "ok") -> AnalysisOutcome:
    return AnalysisOutcome(findings=[], summary=summary, mode="claude",
                           model="m", engine=engine)


class Stub:
    """AIProvider test double with a controllable outcome."""

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


@pytest.fixture(autouse=True)
def _fresh_circuits():
    router.reset_circuits()
    yield
    router.reset_circuits()


def _patch_build(monkeypatch, **providers):
    """Route ``build_provider`` to ``providers[backend]`` for every backend."""
    def build(cfg, context, backend):
        if backend not in providers:
            raise AssertionError(f"unexpected build_provider({backend})")
        return providers[backend]

    monkeypatch.setattr(router, "build_provider", build)


# ------------------------------------------------------------------- ordering

def test_parse_provider_order_normalizes_drops_and_deduplicates():
    assert router.parse_provider_order("Claude, openai") == ["claude", "openai"]
    assert router.parse_provider_order("claude claude gemini") == ["claude", "gemini"]
    assert router.parse_provider_order("static,claude") == ["claude"]
    assert router.parse_provider_order("typo,claude") == ["claude"]
    assert router.parse_provider_order("") == []
    assert router.parse_provider_order(None) == []


def test_provider_order_is_the_configured_backend_unless_explicitly_overridden():
    assert router.provider_order(Config()) == []
    assert router.provider_order(Config(anthropic_api_key="k")) == ["claude"]
    assert router.provider_order(Config(mock=True, anthropic_api_key="k")) == []
    assert router.provider_order(
        Config(anthropic_api_key="k", provider_order="gemini,openai")) == \
        ["gemini", "openai"]


def test_static_is_never_part_of_an_explicit_order():
    assert "static" not in router.parse_provider_order("static,static")


# -------------------------------------------------------------- configuration

def test_an_unusable_primary_is_a_config_error():
    assert router.provider_config_error(Config(openai_api_key="k")) is not None
    assert router.provider_config_error(Config(gemini_api_key="k")) is not None
    assert router.provider_config_error(Config(openai_api_key="k", model="gpt-4o")) is None
    assert router.provider_config_error(Config(anthropic_api_key="k")) is None
    assert router.provider_config_error(Config()) is None
    assert router.provider_config_error(Config(provider_order="openai")) is not None


def test_only_the_first_backend_of_a_failover_chain_is_validated_strictly():
    cfg = Config(anthropic_api_key="k", provider_order="claude,openai")

    assert router.provider_config_error(cfg) is None      # claude is usable
    assert router.provider_order(cfg) == ["claude", "openai"]


def test_get_provider_raises_for_a_broken_primary_configuration():
    with pytest.raises(ValueError):
        router.get_provider(Config(provider_order="openai"), CONTEXT)


def test_get_provider_returns_the_static_engine_without_ai_credentials():
    assert isinstance(router.get_provider(Config(), CONTEXT), router.StaticProvider)
    assert isinstance(router.get_provider(Config(mock=True, anthropic_api_key="k"),
                                          CONTEXT), router.StaticProvider)


# ------------------------------------------------------------------ failover

def test_a_failing_primary_hands_over_to_the_next_backend(monkeypatch):
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    first = Stub("claude", error=RuntimeError("boom"))
    second = Stub("openai", outcome=_outcome(engine="openai"))
    _patch_build(monkeypatch, claude=first, openai=second)

    out = router.run_analysis(cfg, CONTEXT, primary=first)

    assert first.analyzed == 1 and second.analyzed == 1
    assert out is second._outcome
    assert any("review failed (RuntimeError)" in w for w in out.warnings)


def test_an_outcome_with_no_engine_field_is_still_a_successful_review(monkeypatch):
    """Pre-v2 providers report no ``engine`` at all — that must not be read
    as "the AI didn't actually review"."""
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    first = Stub("claude", outcome=AnalysisOutcome([], "legacy", "claude", "m"))
    second = Stub("openai", outcome=_outcome(engine="openai"))
    _patch_build(monkeypatch, claude=first, openai=second)

    out = router.run_analysis(cfg, CONTEXT, primary=first)

    assert out is first._outcome
    assert second.analyzed == 0


def test_a_provider_that_fell_back_to_static_is_a_failover_not_a_success(monkeypatch):
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    first = Stub("claude", outcome=_outcome(engine="static"))
    second = Stub("openai", outcome=_outcome(engine="openai"))
    _patch_build(monkeypatch, claude=first, openai=second)

    out = router.run_analysis(cfg, CONTEXT, primary=first)

    assert out is second._outcome
    assert any("every batch fell back to static analysis" in w for w in out.warnings)


def test_every_backend_failing_ends_in_the_rule_engine_and_says_so(monkeypatch):
    cfg = Config(provider_order="claude,openai")
    first = Stub("claude", error=RuntimeError("boom"))
    second = Stub("openai", error=TimeoutError("slow"))
    _patch_build(monkeypatch, claude=first, openai=second)

    out = router.run_analysis(cfg, CONTEXT, primary=first)

    assert (out.engine, out.fallback_used) == ("static", True)
    assert any("not from an AI review" in w for w in out.warnings)
    assert any("trying the next provider" in w for w in out.warnings)
    # and the run produced findings from the deterministic rules, not a crash
    assert isinstance(out.findings, list)


def test_an_unusable_secondary_backend_is_skipped_with_a_warning():
    """``openai`` has no model id here, so building it raises — a *secondary*
    backend's bad config must degrade to a warning, never a fatal error.
    Nothing is monkeypatched: this is the real ``build_provider`` path."""
    cfg = Config(provider_order="claude,openai")
    first = Stub("claude", error=RuntimeError("boom"))

    out = router.run_analysis(cfg, CONTEXT, primary=first)

    assert (out.engine, out.fallback_used) == ("static", True)
    assert any("openai: unavailable" in w for w in out.warnings)


def test_failure_warnings_never_echo_an_exception_message():
    secret = "sk-" + "A" * 40
    cfg = Config(provider_order="claude")            # no second backend to build
    first = Stub("claude", error=RuntimeError(f"request failed: {secret}"))

    out = router.run_analysis(cfg, CONTEXT, primary=first)

    assert all(secret not in w for w in out.warnings)
    assert any("RuntimeError" in w for w in out.warnings)   # type name only


# ------------------------------------------------------------- circuit breaker

def test_a_cooling_down_breaker_admits_exactly_one_recovery_attempt():
    now = {"t": 0.0}
    breaker = CircuitBreaker(failure_threshold=2, recovery_timeout=60.0,
                             clock=lambda: now["t"])

    assert breaker.state() == CLOSED
    breaker.record_failure()
    assert breaker.state() == CLOSED          # threshold not reached yet
    breaker.record_failure()
    assert breaker.state() == OPEN
    assert breaker.allow() is False
    assert breaker.can_attempt() is False

    now["t"] = 61.0
    assert breaker.state() == HALF_OPEN       # reading never mutates state
    assert breaker.state() == HALF_OPEN
    assert breaker.can_attempt() is True
    assert breaker.allow() is True            # claims the single trial
    assert breaker.allow() is False
    assert breaker.can_attempt() is False

    breaker.record_failure()                  # recovery attempt failed
    assert breaker.state() == OPEN

    now["t"] = 130.0                          # cool-down elapsed again
    assert breaker.allow() is True
    breaker.record_success()
    assert breaker.state() == CLOSED
    assert breaker.failures == 0


def test_a_closed_breaker_lets_attempts_through_and_reset_clears_everything():
    breaker = CircuitBreaker(failure_threshold=3)
    assert breaker.allow() is True
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state() == CLOSED
    breaker.reset()
    assert breaker.state() == CLOSED and breaker.failures == 0


def test_breakers_are_per_backend_so_one_outage_never_blocks_another(monkeypatch):
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    first = Stub("claude", error=RuntimeError("boom"))
    second = Stub("openai", outcome=_outcome(engine="openai"))
    _patch_build(monkeypatch, claude=first, openai=second)

    router.run_analysis(cfg, CONTEXT, primary=first)
    router.run_analysis(cfg, CONTEXT, primary=first)

    assert router.breaker_for("claude").failures >= 2
    assert router.breaker_for("claude").state() == OPEN
    assert router.breaker_for("openai").state() == CLOSED


def test_an_open_circuit_makes_run_analysis_skip_the_failing_provider(monkeypatch):
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    first = Stub("claude", error=RuntimeError("boom"))
    second = Stub("openai", outcome=_outcome(engine="openai"))
    _patch_build(monkeypatch, claude=first, openai=second)

    router.run_analysis(cfg, CONTEXT, primary=first)   # 1 failure (closed)
    router.run_analysis(cfg, CONTEXT, primary=first)   # 2 failures (opens)
    assert router.breaker_for("claude").state() == OPEN

    out = router.run_analysis(cfg, CONTEXT, primary=first)   # claude skipped

    assert first.analyzed == 2                  # no third paid attempt
    assert second.analyzed == 3
    assert out is second._outcome
    assert any("circuit open after repeated failures" in w for w in out.warnings)


def test_get_provider_skips_an_open_circuit_and_falls_back_to_static(monkeypatch):
    cfg = Config(provider_order="claude,openai", model="gpt-4o")
    built: list[str] = []

    def build(cfg, context, backend):
        built.append(backend)
        return Stub(backend, outcome=_outcome(engine=backend))

    monkeypatch.setattr(router, "build_provider", build)

    router.breaker_for("claude").record_failure()
    router.breaker_for("claude").record_failure()
    assert router.breaker_for("claude").state() == OPEN

    provider = router.get_provider(cfg, CONTEXT)
    assert provider.backend == "openai"

    router.breaker_for("openai").record_failure()
    router.breaker_for("openai").record_failure()
    assert isinstance(router.get_provider(cfg, CONTEXT), router.StaticProvider)
    assert built == ["openai"]                  # claude was never constructed


def test_reset_circuits_clears_state_between_runs():
    breaker = router.breaker_for("claude")
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state() == OPEN

    router.reset_circuits()

    assert router.breaker_for("claude").state() == CLOSED


# ------------------------------------------------------------------ selection

def test_select_backend_is_unchanged_by_failover():
    assert router.select_backend(Config()) == "static"
    assert router.select_backend(Config(mock=True, anthropic_api_key="k")) == "static"
    assert router.select_backend(Config(anthropic_api_key="k")) == "claude"
    assert router.select_backend(Config(openai_api_key="k", model="gpt-4o")) == "openai"


def test_risk_is_computed_and_is_informational_only():
    from ai_pr_reviewer.diff_parser import FileDiff

    ctx = _context([FileDiff(old_path="a/auth.py", new_path="a/auth.py")])
    risk = router.classify_risk(ctx)

    assert risk.level == "high"
    assert any("auth.py" in r for r in risk.reasons)
    # informational only: routing does not change (see model_router docstring)
    assert router.provider_order(Config(anthropic_api_key="k")) == ["claude"]


def test_static_analyzer_still_produces_findings_for_the_final_fallback():
    outcome = router.StaticProvider().analyze(CONTEXT)

    assert isinstance(outcome, AnalysisOutcome)
    assert isinstance(outcome.findings, list)


def test_time_is_not_part_of_the_breaker_test_surface():
    """Guard against a test accidentally depending on wall-clock sleeps."""
    breaker = CircuitBreaker(recovery_timeout=0.0, clock=time.monotonic)
    breaker.record_failure()
    breaker.record_failure()
    assert breaker.state() == HALF_OPEN          # timeout 0 -> instant recovery
