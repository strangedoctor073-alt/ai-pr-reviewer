"""V4.0-E01-T03 (degraded-but-honest) and T04 (completion order is not output).

Offline, deterministic. Ordering is forced with events rather than sleeps, so
"task completion order cannot change the result" is demonstrated, not hoped.
"""
from __future__ import annotations

import random
import threading
import time

import pytest

from ai_pr_reviewer.models import AnalysisOutcome, Finding
from ai_pr_reviewer.orchestration.executor import FanOutTask, run_fanout
from ai_pr_reviewer.orchestration.outcome import combine_outcomes

_WAIT = 5.0


def _finding(file, title):
    return Finding(file=file, line=2, severity="high", title=title,
                   explanation="synthetic")


def _outcome(tag, engine="claude", fallback=False):
    return AnalysisOutcome(findings=[_finding(f"{tag}.py", f"issue-{tag}")],
                           summary=f"summary-{tag}", mode="claude",
                           model=f"model-{tag}", warnings=[f"warn-{tag}"],
                           engine=engine, fallback_used=fallback, batch_count=1)


def _static():
    return AnalysisOutcome(findings=[], summary="static summary", mode="static",
                           model="static-rules-v1", engine="static")


def _ok(tag):
    return FanOutTask(tag, lambda scope: _outcome(tag), token_budget=100)


def _boom(tag):
    def run(scope):
        raise ConnectionError("upstream said: secret-looking-text")
    return FanOutTask(tag, run, token_budget=100)


# ------------------------------------------------------------ T03 · semantics

def test_single_clean_task_is_returned_as_the_same_object_untouched():
    report = run_fanout([_ok("a")])
    outcome = combine_outcomes(report, _static)

    assert outcome is report.results[0].value
    assert outcome.warnings == ["warn-a"]
    assert not hasattr(outcome, "fanout_degraded")


def test_partial_failure_is_a_valid_labelled_review_from_the_survivors():
    report = run_fanout([_ok("a"), _boom("b"), _ok("c")], token_ceiling=10_000)
    outcome = combine_outcomes(report, _static)

    assert [f.title for f in outcome.findings] == ["issue-a", "issue-c"]
    assert outcome.engine == "claude" and outcome.fallback_used is False
    assert outcome.fanout_degraded is True
    assert outcome.warnings[0].startswith("Degraded multi-task review: 2 of 3")
    assert any("'b' failed (ConnectionError)" in w for w in outcome.warnings)
    assert "secret-looking-text" not in "\n".join(outcome.warnings)


def test_a_skipped_task_degrades_the_run_too():
    report = run_fanout([_ok("a"), _ok("b")], token_ceiling=150)
    outcome = combine_outcomes(report, _static)

    assert outcome.fanout_degraded is True
    assert any("'b' was not run (token_ceiling)" in w for w in outcome.warnings)
    assert [f.title for f in outcome.findings] == ["issue-a"]


def test_every_task_failing_falls_back_to_static_and_says_so():
    report = run_fanout([_boom("a"), _boom("b")], token_ceiling=10_000)
    outcome = combine_outcomes(report, _static)

    assert (outcome.engine, outcome.fallback_used) == ("static", True)
    assert outcome.fanout_degraded is True
    joined = "\n".join(outcome.warnings)
    assert "not from an AI review" in joined
    assert "'a' failed (ConnectionError)" in joined


def test_a_task_returning_no_outcome_counts_as_degraded_not_as_success():
    report = run_fanout([FanOutTask("a", lambda s: None, 100), _ok("b")])
    outcome = combine_outcomes(report, _static)

    assert outcome.fanout_degraded is True
    assert any("'a' returned no usable analysis outcome" in w
               for w in outcome.warnings)
    assert [f.title for f in outcome.findings] == ["issue-b"]


def test_a_task_that_overran_its_reservation_marks_the_run_degraded():
    def greedy(scope):
        scope.record_tokens(101)
        return _outcome("g")

    report = run_fanout([FanOutTask("g", greedy, 100)])
    outcome = combine_outcomes(report, _static)

    assert outcome.fanout_degraded is True
    assert [f.title for f in outcome.findings] == ["issue-g"]       # value kept
    assert any("more tokens than its reservation" in w for w in outcome.warnings)


def test_multi_task_merge_is_a_plain_ordered_union_with_honest_metadata():
    report = run_fanout([_ok("a"), _ok("b")])
    outcome = combine_outcomes(report, _static)

    assert [f.title for f in outcome.findings] == ["issue-a", "issue-b"]
    assert outcome.summary == "summary-a\n\nsummary-b"
    assert outcome.model == "model-a+model-b"
    assert outcome.batch_count == 2
    assert outcome.warnings == ["warn-a", "warn-b"]
    assert not hasattr(outcome, "fanout_degraded")


# ------------------------------------------------------- T04 · determinism

def _snapshot(outcome):
    return (
        [(f.file, f.line, f.title) for f in outcome.findings],
        outcome.summary, outcome.model, outcome.engine, outcome.fallback_used,
        outcome.batch_count, list(outcome.warnings),
        getattr(outcome, "fanout_degraded", False),
    )


def _forced_order_run(finish_order):
    """Run 4 tasks that complete in exactly ``finish_order`` (indexes)."""
    done = [threading.Event() for _ in range(4)]
    position = {idx: n for n, idx in enumerate(finish_order)}

    def make(idx):
        def run(scope):
            if position[idx] > 0:      # wait for whoever must finish before us
                assert done[finish_order[position[idx] - 1]].wait(_WAIT)
            done[idx].set()
            return _outcome(f"t{idx}")
        return FanOutTask(f"t{idx}", run, 100)

    return run_fanout([make(i) for i in range(4)], max_concurrency=4,
                      token_ceiling=10_000)


@pytest.mark.parametrize("finish_order", [
    (0, 1, 2, 3), (3, 2, 1, 0), (2, 0, 3, 1), (1, 3, 0, 2)])
def test_completion_order_cannot_change_the_report_or_the_outcome(finish_order):
    baseline = _forced_order_run((0, 1, 2, 3))
    shuffled = _forced_order_run(finish_order)

    assert [r.task_id for r in shuffled.results] == ["t0", "t1", "t2", "t3"]
    assert shuffled == baseline                              # elapsed_s excluded
    assert (_snapshot(combine_outcomes(shuffled, _static))
            == _snapshot(combine_outcomes(baseline, _static)))


def test_jittered_timing_over_many_runs_yields_one_distinct_output():
    def make(idx, rng):
        delay = rng.random() * 0.004

        def run(scope):
            time.sleep(delay)
            if idx == 2:
                raise TimeoutError("flaky")
            return _outcome(f"t{idx}")
        return FanOutTask(f"t{idx}", run, 100)

    seen = set()
    for seed in range(40):
        rng = random.Random(seed)
        report = run_fanout([make(i, rng) for i in range(4)], max_concurrency=4,
                            token_ceiling=10_000)
        seen.add(repr(_snapshot(combine_outcomes(report, _static))))
    assert len(seen) == 1


def test_stress_four_parallel_tasks_over_two_hundred_runs_stay_identical():
    """The roadmap's proposed 200 x 4 stress shape (a proposed baseline, not a
    gate): all runs must agree and none may lose or reorder a result."""
    expected = None
    for _ in range(200):
        report = run_fanout([_ok(f"t{i}") for i in range(4)], max_concurrency=4,
                            token_ceiling=10_000)
        snap = _snapshot(combine_outcomes(report, _static))
        expected = expected or snap
        assert snap == expected
        assert [r.task_id for r in report.results] == ["t0", "t1", "t2", "t3"]
