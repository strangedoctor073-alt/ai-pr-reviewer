"""V4.0-E01-T02 - circuit breakers re-scoped from process-global to per task (C5).

The invariant: under fan-out, one task's provider outage can never trip, heal
or consume the half-open trial of another task's breaker, and nothing on the
fan-out path touches the process-global registry.
"""
from __future__ import annotations

import threading

import pytest

from ai_pr_reviewer import model_router as router
from ai_pr_reviewer.circuit import (CLOSED, HALF_OPEN, OPEN, BreakerRegistry,
                                    CircuitBreaker, active_registry,
                                    scoped_breakers)
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.context import ReviewContext
from ai_pr_reviewer.models import AnalysisOutcome, PRContext
from ai_pr_reviewer.orchestration.executor import FanOutTask, run_fanout


@pytest.fixture(autouse=True)
def _fresh_circuits():
    router.reset_circuits()
    yield
    router.reset_circuits()


class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


# ------------------------------------------------------- thread-safe breaker

def test_half_open_trial_is_claimed_by_exactly_one_thread():
    clock = _Clock()
    breaker = CircuitBreaker(failure_threshold=1, recovery_timeout=10, clock=clock)
    breaker.record_failure()
    assert breaker.state() == OPEN
    clock.t = 11.0
    assert breaker.state() == HALF_OPEN

    barrier = threading.Barrier(16, timeout=5)
    granted: list[bool] = []
    lock = threading.Lock()

    def attempt():
        barrier.wait()
        ok = breaker.allow()
        with lock:
            granted.append(ok)

    threads = [threading.Thread(target=attempt) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(5)

    assert granted.count(True) == 1 and granted.count(False) == 15


def test_failures_are_counted_exactly_under_contention():
    breaker = CircuitBreaker(failure_threshold=10_000)
    barrier = threading.Barrier(8, timeout=5)

    def hammer():
        barrier.wait()
        for _ in range(500):
            breaker.record_failure()

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    assert breaker.failures == 4_000


# ---------------------------------------------------------------- registry

def test_registry_returns_one_breaker_per_backend_and_isolates_registries():
    a, b = BreakerRegistry(), BreakerRegistry()
    assert a.breaker_for("claude") is a.breaker_for("claude")
    assert a.breaker_for("claude") is not a.breaker_for("openai")
    assert a.breaker_for("claude") is not b.breaker_for("claude")


def test_registry_states_are_sorted_and_reset_clears():
    reg = BreakerRegistry()
    reg.breaker_for("openai")
    reg.breaker_for("claude").record_failure()
    reg.breaker_for("claude").record_failure()
    assert reg.states() == {"claude": OPEN, "openai": CLOSED}
    assert list(reg.states()) == ["claude", "openai"]
    reg.reset()
    assert reg.states() == {}


def test_registry_honours_the_injected_clock():
    clock = _Clock()
    reg = BreakerRegistry(clock=clock)
    breaker = reg.breaker_for("claude", failure_threshold=1, recovery_timeout=5)
    breaker.record_failure()
    clock.t = 6.0
    assert breaker.state() == HALF_OPEN


# ------------------------------------------------------------- scope plumbing

def test_breaker_for_uses_the_scoped_registry_and_never_the_global_one():
    reg = BreakerRegistry()
    with scoped_breakers(reg):
        assert active_registry() is reg
        inside = router.breaker_for("claude")
        assert inside is reg.breaker_for("claude")
    assert active_registry() is None
    assert router._BREAKERS == {}
    assert router.breaker_for("claude") is not inside      # global is a different one


def test_scope_is_restored_even_when_the_body_raises():
    with pytest.raises(RuntimeError):
        with scoped_breakers(BreakerRegistry()):
            raise RuntimeError("boom")
    assert active_registry() is None


def test_scopes_nest_and_unwind_in_order():
    outer, inner = BreakerRegistry(), BreakerRegistry()
    with scoped_breakers(outer):
        with scoped_breakers(inner):
            assert active_registry() is inner
        assert active_registry() is outer


def test_flag_off_behavior_is_the_old_global_registry():
    first = router.breaker_for("claude")
    assert router.breaker_for("claude") is first
    assert router._BREAKERS["claude"] is first


# ----------------------------------------------------------- across fan-out

def test_one_tasks_outage_never_touches_a_siblings_breaker():
    both_ready = threading.Barrier(2, timeout=5)
    states = {}

    def make(task_id, fail):
        def run(scope):
            with scoped_breakers(scope.breakers):
                breaker = router.breaker_for("claude")
                both_ready.wait()                   # genuinely concurrent
                if fail:
                    breaker.record_failure()
                    breaker.record_failure()
                states[task_id] = breaker.state()
        return FanOutTask(task_id, run)

    run_fanout([make("down", True), make("healthy", False)], max_concurrency=2)

    assert states == {"down": OPEN, "healthy": CLOSED}
    assert router._BREAKERS == {}                    # global never touched


def test_each_task_scope_owns_a_distinct_registry():
    seen = {}

    def grab(scope):
        seen[scope.task_id] = scope.breakers

    run_fanout([FanOutTask("a", grab), FanOutTask("b", grab)])
    assert seen["a"] is not seen["b"]


def test_run_analysis_inside_a_scope_records_on_the_scoped_breaker():
    class Failing:
        backend = "claude"
        startup_warnings: list = []

        def analyze(self, context):
            raise RuntimeError("provider down")

    ctx = ReviewContext(pr=PRContext(repo="acme/api", pr_number=7), files=[],
                        project_rules=None, previous_findings=[],
                        memory_notes=[], focus_areas=[])
    cfg = Config(anthropic_api_key="synthetic-key", model="claude-test")
    reg = BreakerRegistry()

    with scoped_breakers(reg):
        outcome = router.run_analysis(cfg, ctx, Failing())

    assert isinstance(outcome, AnalysisOutcome) and outcome.engine == "static"
    assert reg.breaker_for("claude").failures == 1
    assert router._BREAKERS == {}
