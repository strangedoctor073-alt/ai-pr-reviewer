"""From task results to one honest outcome (V4.0-E01-T03, T04).

Partial-failure semantics - what a multi-task review is allowed to claim:

* every task completed, in budget -> the outcome is exactly what the tasks
  returned (one task: the *same object*, so a single-task run is
  byte-identical to the single-agent path);
* some tasks failed / were skipped / overran -> a valid review built from the
  tasks that did complete, carrying an explicit degradation notice naming
  each missing task, and ``fanout_degraded = True`` so the orchestrator
  refuses to advance the last-reviewed SHA (the missing analysis must be
  retried, never presumed done);
* no task completed -> the deterministic static engine stands in and the
  outcome says so (``engine="static"``, ``fallback_used=True``): never an AI
  review it did not do.

Determinism (T04): everything is derived by walking results in submission
order, so task completion order cannot change any field.

The merge policy for several completed tasks here is deliberately minimal -
concatenate in submission order - because findings still pass through the
existing dedup/lifecycle pipeline afterwards. Provenance-aware merging,
conflict records and severity reconciliation are V4.0-E03, which replaces
:func:`_merge_completed`; nothing else in this module is expected to change.
"""
from __future__ import annotations

from typing import Any, Callable

from .executor import FanOutReport, TaskResult


def _is_outcome(value: Any) -> bool:
    """Duck-typed on purpose: test doubles and pre-V3 outcomes lack newer
    fields, exactly as the orchestrator already tolerates."""
    return hasattr(value, "findings") and hasattr(value, "summary")


def _unique(items) -> list:
    seen: list = []
    for item in items:
        if item and item not in seen:
            seen.append(item)
    return seen


def _merge_completed(outcomes: list) -> Any:
    """Combine >= 2 completed outcomes. Order = submission order."""
    first = outcomes[0]
    merged = type(first)(
        findings=[f for o in outcomes for f in (o.findings or [])],
        summary="\n\n".join(_unique(str(o.summary or "") for o in outcomes)),
        mode=getattr(first, "mode", ""),
        model="+".join(_unique(str(getattr(o, "model", "") or "") for o in outcomes)),
        warnings=_unique(w for o in outcomes for w in (getattr(o, "warnings", None) or [])),
        engine="+".join(_unique(str(getattr(o, "engine", "") or "") for o in outcomes)),
        fallback_used=any(bool(getattr(o, "fallback_used", False)) for o in outcomes),
        batch_count=sum(int(getattr(o, "batch_count", 0) or 0) for o in outcomes),
    )
    telemetries = [t for t in (getattr(o, "telemetry", None) for o in outcomes) if t]
    if telemetries:
        lead = telemetries[0]
        lead.events = [ev for t in telemetries for ev in (t.events or [])]
        merged.telemetry = lead
    return merged


def combine_outcomes(report: FanOutReport,
                     static_fallback: Callable[[], Any]) -> Any:
    """Turn ``report`` into the single outcome the pipeline consumes.

    ``static_fallback`` builds the deterministic rule-engine outcome; it is
    only called when no task produced a usable outcome.
    """
    usable: list[TaskResult] = [r for r in report.results
                                if r.completed and _is_outcome(r.value)]
    degraded = report.degraded or len(usable) != len(report.completed)
    notices = report.warnings()
    if len(usable) != len(report.completed):
        bad = [r.task_id for r in report.completed if not _is_outcome(r.value)]
        if not notices:
            notices = [f"Degraded multi-task review: {len(usable)} of "
                       f"{len(report.results)} review task(s) completed; "
                       f"findings come only from the completed task(s)."]
        notices += [f"review task '{t}' returned no usable analysis outcome."
                    for t in bad]

    if not usable:
        outcome = static_fallback()
        outcome.warnings = [*notices, *(getattr(outcome, "warnings", None) or []),
                            "No AI provider completed this review — findings "
                            "come from the deterministic static rule engine, "
                            "not from an AI review."]
        outcome.engine = "static"
        outcome.fallback_used = True
        outcome.fanout_degraded = True
        return outcome

    outcomes = [r.value for r in usable]
    outcome = outcomes[0] if len(outcomes) == 1 else _merge_completed(outcomes)
    if degraded:
        outcome.warnings = [*notices, *(getattr(outcome, "warnings", None) or [])]
        outcome.fanout_degraded = True
    return outcome
