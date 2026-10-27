"""V4.0-E01-T01 - bounded fan-out scheduler with per-task isolation.

Offline and deterministic: every concurrency assertion is forced with
barriers/events rather than sleeps, so the suite proves the bounds instead of
hoping the scheduler happens to interleave a particular way.
"""
from __future__ import annotations

import contextvars
import threading

import pytest

from ai_pr_reviewer.orchestration import executor as ex
from ai_pr_reviewer.orchestration.executor import (
    FanOutTask, STATUS_FAILED, STATUS_OK, STATUS_SKIPPED, run_fanout)

_WAIT = 5.0     # generous: only ever reached when the scheduler is broken


def _task(task_id, fn=None, budget=1_000):
    return FanOutTask(task_id, fn or (lambda scope: task_id), token_budget=budget)


class _Gauge:
    """Counts tasks in flight and remembers the peak."""

    def __init__(self):
        self._lock = threading.Lock()
        self.now = 0
        self.peak = 0

    def enter(self):
        with self._lock:
            self.now += 1
            self.peak = max(self.peak, self.now)

    def leave(self):
        with self._lock:
            self.now -= 1


# ------------------------------------------------------------ concurrency cap

def test_concurrency_cap_is_enforced_and_actually_reached():
    gauge = _Gauge()
    first_wave = threading.Barrier(3, timeout=_WAIT)   # 3 must overlap, or it breaks

    def work(scope):
        gauge.enter()
        try:
            if scope.index < 3:
                first_wave.wait()                      # proves 3 ran together
            return scope.task_id
        finally:
            gauge.leave()

    tasks = [_task(f"t{i}", work) for i in range(8)]
    report = run_fanout(tasks, max_concurrency=3, max_tasks=8,
                        token_ceiling=100_000)

    assert [r.status for r in report.results] == [STATUS_OK] * 8
    assert gauge.peak == 3                  # reached the cap, never exceeded it
    assert report.max_concurrency == 3


def test_cap_of_one_serializes_everything():
    gauge = _Gauge()

    def work(scope):
        gauge.enter()
        gauge.leave()
        return scope.index

    report = run_fanout([_task(f"t{i}", work) for i in range(4)],
                        max_concurrency=1, token_ceiling=100_000)
    assert gauge.peak == 1
    assert [r.value for r in report.results] == [0, 1, 2, 3]


def test_pool_is_sized_to_the_cap_not_to_the_task_count():
    report = run_fanout([_task("only")], max_concurrency=4, token_ceiling=10_000)
    assert report.max_concurrency == 1      # one task never gets a bigger pool


# ------------------------------------------------------------------ task cap

def test_tasks_beyond_max_tasks_are_skipped_and_never_run():
    ran = []
    tasks = [_task(f"t{i}", lambda s: ran.append(s.task_id)) for i in range(7)]
    report = run_fanout(tasks, max_tasks=5, token_ceiling=1_000_000)

    assert sorted(ran) == ["t0", "t1", "t2", "t3", "t4"]
    skipped = [r for r in report.results if r.status == STATUS_SKIPPED]
    assert [(r.task_id, r.skip_reason) for r in skipped] == [
        ("t5", ex.SKIP_TASK_CAP), ("t6", ex.SKIP_TASK_CAP)]


# ------------------------------------------------------------- token ceiling

def test_token_ceiling_skips_a_task_whose_reservation_does_not_fit():
    ran = []
    tasks = [_task(f"t{i}", lambda s: ran.append(s.task_id), budget=100)
             for i in range(3)]
    report = run_fanout(tasks, token_ceiling=250)

    assert sorted(ran) == ["t0", "t1"]
    assert report.results[2].status == STATUS_SKIPPED
    assert report.results[2].skip_reason == ex.SKIP_TOKEN_CEILING
    assert report.reserved_tokens == 200
    assert report.reserved_tokens <= report.token_ceiling


def test_admission_is_first_fit_in_submission_order():
    tasks = [_task("a", budget=100), _task("big", budget=200),
             _task("small", budget=50)]
    report = run_fanout(tasks, token_ceiling=200)

    assert [(r.task_id, r.status) for r in report.results] == [
        ("a", STATUS_OK), ("big", STATUS_SKIPPED), ("small", STATUS_OK)]
    assert report.reserved_tokens == 150


def test_admission_does_not_depend_on_timing():
    tasks = [_task(f"t{i}", budget=70) for i in range(6)]
    outcomes = {tuple(r.status for r in run_fanout(tasks, token_ceiling=300).results)
                for _ in range(5)}
    assert outcomes == {(STATUS_OK,) * 4 + (STATUS_SKIPPED,) * 2}


@pytest.mark.parametrize("kwargs", [
    {"token_ceiling": 0},
    {"token_ceiling": -1},
    {"token_ceiling": None},
    {"token_ceiling": True},
    {"max_concurrency": 0},
    {"max_concurrency": 2.5},
    {"max_tasks": 0},
])
def test_a_run_is_never_scheduled_without_valid_bounds(kwargs):
    ran = []
    with pytest.raises(ValueError, match="positive integer"):
        run_fanout([_task("t", lambda s: ran.append(1))], **kwargs)
    assert ran == []                         # nothing started


@pytest.mark.parametrize("tasks", [
    [_task("dup"), _task("dup")],
    [_task("Bad Id")],
    [_task("")],
    [_task("x" * 65)],
    [_task("ok", budget=0)],
    [_task("ok", budget=True)],
])
def test_invalid_tasks_are_rejected_before_anything_runs(tasks):
    with pytest.raises(ValueError):
        run_fanout(tasks)


def test_no_tasks_is_an_empty_clean_report():
    report = run_fanout([])
    assert report.results == ()
    assert not report.degraded
    assert report.warnings() == []
    assert report.reserved_tokens == 0


# ------------------------------------------------------------------ isolation

def test_one_failing_task_never_disturbs_its_siblings():
    def boom(scope):
        raise RuntimeError("provider exploded")

    report = run_fanout([_task("a"), _task("b", boom), _task("c")],
                        token_ceiling=100_000)

    assert [(r.task_id, r.status) for r in report.results] == [
        ("a", STATUS_OK), ("b", STATUS_FAILED), ("c", STATUS_OK)]
    assert report.results[0].value == "a"
    assert report.results[2].value == "c"


def test_failure_records_the_type_name_and_never_the_message():
    secret = "sk-ant-api03-" + "A" * 40

    def leaky(scope):
        raise ValueError(f"request failed with key {secret}")

    report = run_fanout([_task("leaky", leaky)])
    result = report.results[0]

    assert result.error_type == "ValueError"
    surfaces = repr(report) + "\n".join(report.warnings()) + repr(result)
    assert secret not in surfaces
    assert "request failed" not in surfaces


def test_each_task_gets_its_own_scope_object():
    seen = {}

    def grab(scope):
        seen[scope.task_id] = scope
        return None

    run_fanout([_task("a", grab, budget=10), _task("b", grab, budget=20)])
    assert seen["a"] is not seen["b"]
    assert (seen["a"].index, seen["a"].token_budget) == (0, 10)
    assert (seen["b"].index, seen["b"].token_budget) == (1, 20)


def test_context_state_set_by_one_task_does_not_leak():
    marker = contextvars.ContextVar("marker", default="unset")
    observed = {}
    set_done = threading.Event()

    def setter(scope):
        marker.set("task-a")
        set_done.set()
        return marker.get()

    def watcher(scope):
        assert set_done.wait(_WAIT)
        observed["b"] = marker.get()

    report = run_fanout([_task("a", setter), _task("b", watcher)],
                        max_concurrency=2)

    assert report.results[0].value == "task-a"
    assert observed["b"] == "unset"
    assert marker.get() == "unset"           # nor the submitting context


# --------------------------------------------------------------- token usage

def test_overrun_of_a_reservation_is_reported_but_the_value_is_kept():
    def greedy(scope):
        scope.record_tokens(scope.token_budget + 1)
        return "paid-for"

    report = run_fanout([_task("g", greedy, budget=500)])
    r = report.results[0]

    assert r.status == STATUS_OK and r.value == "paid-for"
    assert r.budget_exceeded and r.tokens_used == 501
    assert report.degraded
    assert any("more tokens than its reservation (501 > 500)" in w
               for w in report.warnings())


def test_unmeasured_and_in_budget_tasks_are_not_flagged():
    def fine(scope):
        scope.record_tokens(10)

    report = run_fanout([_task("fine", fine, budget=500), _task("quiet")])
    assert not any(r.budget_exceeded for r in report.results)
    assert report.results[1].tokens_used is None
    assert not report.degraded


@pytest.mark.parametrize("bad", [-1, 1.5, "10", None, True])
def test_record_tokens_rejects_non_counts(bad):
    scope = ex.TaskScope("t", 0, 10)
    with pytest.raises(ValueError):
        scope.record_tokens(bad)


# -------------------------------------------------------------- degraded view

def test_degraded_warnings_name_each_missing_task_honestly():
    def boom(scope):
        raise TimeoutError("slow")

    tasks = [_task("ok"), _task("bad", boom), _task("extra", budget=999_999)]
    report = run_fanout(tasks, token_ceiling=10_000)
    warnings = report.warnings()

    assert report.degraded
    assert warnings[0].startswith("Degraded multi-task review: 1 of 3")
    assert any("'bad' failed (TimeoutError)" in w for w in warnings)
    assert any("'extra' was not run (token_ceiling)" in w for w in warnings)
    assert all("slow" not in w for w in warnings)


def test_a_clean_run_reports_no_warnings():
    report = run_fanout([_task("a"), _task("b")])
    assert not report.degraded
    assert report.warnings() == []
