"""Bounded fan-out scheduler (V4.0-E01-T01, T04; ADR-006).

Runs a fixed list of independent review tasks concurrently, in-process,
under three hard bounds that are *enforced* rather than advisory:

* **concurrency** - never more than ``max_concurrency`` tasks in flight
  (the worker pool is sized to the cap, not to the task count);
* **task count** - at most ``max_tasks`` tasks are admitted per run;
* **token ceiling** - every task declares a ``token_budget`` that is
  *reserved up front*; a task whose reservation would push the run past
  ``token_ceiling`` is skipped before anything is spent. A run can never be
  scheduled without a ceiling.

Admission is a pure function of the submitted list, so which tasks run
never depends on timing. What the scheduler does NOT do: it does not
truncate a model call that is already running (each provider call carries
its own ``max_tokens``), it does not know what a "specialist" is
(V4.0-E02), and it does not merge findings (V4.0-E03). It reports a task
that reports more usage than it reserved, but cannot un-spend the tokens;
arbitration across a run is V4.0-E07's ledger.

Isolation: every task gets its own :class:`TaskScope`. One task raising
never reaches a sibling; the scheduler records the exception *type name*
only - an exception message can echo a request body or a credential, so it
is never stored, logged or surfaced here.

Determinism (T04): results are collected and returned in **submission
order**, never completion order, and nothing derived from timing
(``elapsed_s`` aside, which is excluded from equality and from every
warning) enters the report. Two runs of the same tasks produce equal
reports however the threads interleave.
"""
from __future__ import annotations

import contextvars
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Callable, Sequence

from ..circuit import BreakerRegistry

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"

SKIP_TASK_CAP = "task_cap"
SKIP_TOKEN_CEILING = "token_ceiling"

# Proposed baselines (plan §G.7 / AI_AGENT_ARCHITECTURE §4.3) - named here so
# they are one reviewable place, NOT enforced gates: promoting any of them to
# a gate is a human-approval event.
DEFAULT_MAX_CONCURRENCY = 4
DEFAULT_MAX_TASKS = 5
DEFAULT_TASK_TOKEN_BUDGET = 60_000
DEFAULT_RUN_TOKEN_CEILING = 300_000

_TASK_ID_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_TYPE_NAME_RE = re.compile(r"[^A-Za-z0-9_.]")


class TaskScope:
    """What one task may touch: its identity, its token reservation and its
    own mutable state. A scope is created for exactly one task and used by
    exactly one worker thread, so it needs no locking."""

    __slots__ = ("task_id", "index", "token_budget", "breakers", "_tokens_used")

    def __init__(self, task_id: str, index: int, token_budget: int) -> None:
        self.task_id = task_id
        self.index = index
        self.token_budget = token_budget
        # V4.0-E01-T02: this task's private circuit-breaker registry. A task
        # that calls providers wraps them in ``circuit.scoped_breakers`` so
        # breaker state is never shared with a sibling.
        self.breakers = BreakerRegistry()
        self._tokens_used: int | None = None

    def record_tokens(self, tokens: int) -> None:
        """Report actual usage so the scheduler can flag an overrun of the
        reservation. Optional: a task that never calls it is simply
        unmeasured, not assumed to be within budget."""
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise ValueError("tokens must be a non-negative integer")
        self._tokens_used = tokens

    @property
    def tokens_used(self) -> int | None:
        return self._tokens_used


@dataclass(frozen=True)
class FanOutTask:
    """One unit of work: a stable id, a callable, and a token reservation.

    ``run`` receives the task's own :class:`TaskScope` and returns any
    value (normally an ``AnalysisOutcome``). It must not post to GitHub or
    write storage - tasks are pure analysis; only the orchestrator posts.
    """

    task_id: str
    run: Callable[[TaskScope], Any]
    token_budget: int = DEFAULT_TASK_TOKEN_BUDGET


@dataclass(frozen=True)
class TaskResult:
    """Outcome of one task, in submission order.

    ``value`` is excluded from ``repr`` (it can hold finding text);
    ``elapsed_s`` is excluded from equality (it is the only timing-derived
    field and must never influence output).
    """

    task_id: str
    index: int
    status: str
    value: Any = field(default=None, repr=False)
    error_type: str = ""
    skip_reason: str = ""
    token_budget: int = 0
    tokens_used: int | None = None
    budget_exceeded: bool = False
    elapsed_s: float = field(default=0.0, compare=False)

    @property
    def completed(self) -> bool:
        return self.status == STATUS_OK


@dataclass(frozen=True)
class FanOutReport:
    """Everything a caller needs, in submission order. ``results`` has one
    entry per submitted task - failed and skipped ones included - so a
    degraded run can never silently look like a complete one."""

    results: tuple[TaskResult, ...]
    max_concurrency: int
    max_tasks: int
    token_ceiling: int
    reserved_tokens: int

    @property
    def completed(self) -> tuple[TaskResult, ...]:
        return tuple(r for r in self.results if r.completed)

    @property
    def degraded(self) -> bool:
        """True when anything other than a clean, in-budget completion of
        every submitted task happened."""
        return any((not r.completed) or r.budget_exceeded for r in self.results)

    def warnings(self) -> list[str]:
        """Deterministic, redaction-safe degradation notices (empty when the
        run was clean). Only ids, statuses, closed-set reasons and exception
        *type names* appear - never an exception message."""
        if not self.degraded:
            return []
        done = len(self.completed)
        lines = [
            f"Degraded multi-task review: {done} of {len(self.results)} "
            f"review task(s) completed; findings come only from the "
            f"completed task(s)."]
        for r in self.results:
            if r.status == STATUS_FAILED:
                lines.append(f"review task '{r.task_id}' failed ({r.error_type}); "
                             f"its findings are missing from this review.")
            elif r.status == STATUS_SKIPPED:
                lines.append(f"review task '{r.task_id}' was not run "
                             f"({r.skip_reason}); its findings are missing "
                             f"from this review.")
            if r.budget_exceeded:
                lines.append(f"review task '{r.task_id}' used more tokens than "
                             f"its reservation ({r.tokens_used} > "
                             f"{r.token_budget}).")
        return lines


def _type_name(exc: BaseException) -> str:
    return _TYPE_NAME_RE.sub("", type(exc).__name__)[:64] or "Exception"


def _validate(tasks: Sequence[FanOutTask], max_concurrency: int,
              max_tasks: int, token_ceiling: int) -> None:
    for name, value in (("max_concurrency", max_concurrency),
                        ("max_tasks", max_tasks),
                        ("token_ceiling", token_ceiling)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError(
                f"fan-out requires a positive integer {name} (got {value!r}); "
                f"a run is never scheduled without its bounds")
    seen: set[str] = set()
    for t in tasks:
        if not isinstance(t.task_id, str) or not _TASK_ID_RE.fullmatch(t.task_id):
            raise ValueError(f"invalid task id {t.task_id!r}: expected "
                             f"{_TASK_ID_RE.pattern}")
        if t.task_id in seen:
            raise ValueError(f"duplicate task id {t.task_id!r}")
        seen.add(t.task_id)
        if (isinstance(t.token_budget, bool) or not isinstance(t.token_budget, int)
                or t.token_budget < 1):
            raise ValueError(f"task {t.task_id!r}: token_budget must be a "
                             f"positive integer")


def _admit(tasks: Sequence[FanOutTask], max_tasks: int,
           token_ceiling: int) -> tuple[dict[int, TaskResult], int]:
    """Deterministic admission, in submission order, before anything runs.

    Returns ``({index: skipped-result}, reserved_tokens)`` - every index not
    in the mapping is admitted. First-fit: a task that does not fit is
    skipped and later, smaller ones may still be admitted; the outcome
    depends only on the submitted list.
    """
    skipped: dict[int, TaskResult] = {}
    reserved = 0
    admitted = 0
    for idx, task in enumerate(tasks):
        if admitted >= max_tasks:
            skipped[idx] = TaskResult(task.task_id, idx, STATUS_SKIPPED,
                                      skip_reason=SKIP_TASK_CAP,
                                      token_budget=task.token_budget)
        elif reserved + task.token_budget > token_ceiling:
            skipped[idx] = TaskResult(task.task_id, idx, STATUS_SKIPPED,
                                      skip_reason=SKIP_TOKEN_CEILING,
                                      token_budget=task.token_budget)
        else:
            admitted += 1
            reserved += task.token_budget
    return skipped, reserved


def _execute(task: FanOutTask, index: int) -> TaskResult:
    scope = TaskScope(task.task_id, index, task.token_budget)
    started = time.monotonic()
    try:
        value = task.run(scope)
    except Exception as exc:  # noqa: BLE001 - one task's failure is data, not a crash
        return TaskResult(task.task_id, index, STATUS_FAILED,
                          error_type=_type_name(exc),
                          token_budget=task.token_budget,
                          tokens_used=scope.tokens_used,
                          elapsed_s=time.monotonic() - started)
    used = scope.tokens_used
    return TaskResult(task.task_id, index, STATUS_OK, value=value,
                      token_budget=task.token_budget, tokens_used=used,
                      budget_exceeded=used is not None and used > task.token_budget,
                      elapsed_s=time.monotonic() - started)


def run_fanout(tasks: Sequence[FanOutTask], *,
               max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
               max_tasks: int = DEFAULT_MAX_TASKS,
               token_ceiling: int = DEFAULT_RUN_TOKEN_CEILING) -> FanOutReport:
    """Run ``tasks`` under the bounds and return one result per task, in
    submission order. Never raises for a task failure; raises ``ValueError``
    only for an invalid bound, id or reservation (a caller bug, caught
    before any task starts)."""
    tasks = tuple(tasks)
    _validate(tasks, max_concurrency, max_tasks, token_ceiling)
    skipped, reserved = _admit(tasks, max_tasks, token_ceiling)

    slots: list[TaskResult | None] = [skipped.get(i) for i in range(len(tasks))]
    runnable = [(i, t) for i, t in enumerate(tasks) if i not in skipped]
    effective = min(max_concurrency, len(runnable))

    if runnable:
        with ThreadPoolExecutor(max_workers=effective,
                                thread_name_prefix="fanout") as pool:
            # copy_context per task: each worker starts from the submitter's
            # context, and any context-scoped state a task sets (its breaker
            # scope, T02) dies with that copy instead of leaking to siblings.
            futures = [(i, pool.submit(contextvars.copy_context().run,
                                       _execute, t, i))
                       for i, t in runnable]
            # Collect by submission index - never as_completed(): completion
            # order must not be observable in the output (T04).
            for i, future in futures:
                slots[i] = future.result()

    return FanOutReport(results=tuple(slots),  # type: ignore[arg-type]
                        max_concurrency=effective, max_tasks=max_tasks,
                        token_ceiling=token_ceiling, reserved_tokens=reserved)
