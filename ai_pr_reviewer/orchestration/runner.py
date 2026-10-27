"""Opt-in fan-out entry point (V4.0-E01-T05).

``ReviewOrchestrator`` calls :func:`run_fanout_analysis` only when
``Config.fanout_enabled`` is on (default off). It is the *invocation layer*:
it builds the task list, runs it through the bounded executor with each task
inside its own breaker scope, and combines the results.

Until specialists exist (V4.0-E02) the task list is exactly one "generalist"
task wrapping the existing single-agent analysis, which is what makes the
single-agent equivalence guarantee testable today: one task, same provider,
same call, same outcome object. Planning *which* tasks to run - depth
routing (V4.0-E04) and provider wiring (V4.0-E05) - is deliberately not
here; those epics feed this module a longer task list later.

A task never posts to GitHub or touches storage: it only calls the analysis
function it is handed. The orchestrator remains the sole writer.
"""
from __future__ import annotations

from typing import Any, Callable

from ..circuit import scoped_breakers
from .executor import (DEFAULT_MAX_CONCURRENCY, DEFAULT_MAX_TASKS,
                       DEFAULT_RUN_TOKEN_CEILING, DEFAULT_TASK_TOKEN_BUDGET,
                       FanOutTask, TaskScope, run_fanout)
from .outcome import combine_outcomes

GENERALIST_TASK_ID = "generalist"


def build_tasks(cfg: Any, context: Any, primary: Any,
                analyze: Callable[..., Any]) -> list[FanOutTask]:
    """The Wave-1 task list: one generalist task over the existing analysis."""

    def generalist(scope: TaskScope) -> Any:
        # Breaker state for this task's provider calls lives in this task's
        # private registry - never the process-global one (C5).
        with scoped_breakers(scope.breakers):
            return analyze(cfg, context, primary)

    return [FanOutTask(GENERALIST_TASK_ID, generalist,
                       token_budget=DEFAULT_TASK_TOKEN_BUDGET)]


def run_fanout_analysis(cfg: Any, context: Any, primary: Any, *,
                        analyze: Callable[..., Any]) -> Any:
    """Run the review through the fan-out layer; returns one outcome.

    ``analyze`` is the single-agent analysis callable
    (``model_router.run_analysis`` in production); passing it in keeps the
    orchestrator's own binding - and therefore every existing test seam -
    the one that actually runs.
    """
    from ..model_router import StaticProvider

    report = run_fanout(build_tasks(cfg, context, primary, analyze),
                        max_concurrency=DEFAULT_MAX_CONCURRENCY,
                        max_tasks=DEFAULT_MAX_TASKS,
                        token_ceiling=DEFAULT_RUN_TOKEN_CEILING)
    return combine_outcomes(report,
                            static_fallback=lambda: StaticProvider().analyze(context))
