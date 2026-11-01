"""V4.0-E07-T01 — per-run token/cost ledger (reserve → allocate → settle).

Cost arbitration for multi-agent and single-pass runs alike: one ledger
per run that (a) **reserves** a hard ceiling up front, (b) **allocates**
that ceiling to named tasks, and (c) **settles** against what was actually
spent, leaving an honest, append-only record of reservations, allocations,
spend and any skip. The design is deliberately *accounting only* — it
enforces no policy of its own beyond the ceiling the caller configured,
and it never touches the network, storage or the provider layer.

Design contract (V4.0-E07 epic; test-enforced):

* **one ledger per run** — ``BudgetLedger.for_run`` is the only
  constructor; the run id is stamped on every record so a caller cannot
  silently merge two runs' money (budgets are per-run, never
  process-global);
* **reserve → allocate → settle, in that order** — the lifecycle is
  checked: allocating or settling before ``reserve`` is an error, and
  re-reserving or allocating after ``settle`` is an error. Spending above
  the ceiling records an honest ``over_spent`` state rather than
  pretending it did not happen;
* **the ceiling is a hard ceiling** — an allocation that would push
  committed spend past the ceiling is REFUSED (with a reason), never
  silently granted; refusals stay on the record, so a skipped task is
  always explainable from the ledger alone;
* **counts only, never content** — every field is a number, an enum, or
  an already-bounded identifier, so a ledger row is safe for telemetry,
  logs and the dashboard (ADR-014: local-first cost accounting, no
  vendor-operated endpoint). There are deliberately no timestamps: the
  same inputs must serialize to the same bytes on every run;
* **no floating-point money** — spend is tracked in *micros* (integer
  millionths of a dollar) so equality and summation are exact; USD is
  derived only for display, and by integer arithmetic (a dashboard total
  can never show ``0.30000000000000004``).

This module is the arithmetic half of the epic; the ``response_budget``
keyword mapping (T03), the orchestrator enforcement (T02) and the
dashboard view (T04) build on it.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "BudgetLedger", "BudgetReservation", "LedgerAllocation",
    "LedgerSettlement", "LedgerError",
    "LEDGER_OPEN", "LEDGER_SETTLED", "LEDGER_OVER_SPENT",
    "MAX_LEDGER_ALLOCATIONS", "MAX_LEDGER_SETTLEMENTS",
    "MICROS_PER_DOLLAR", "format_usd",
]

#: Integer scale for money: 1 USD = 1_000_000 micros. Using integer micros
#: keeps reserve/allocate/settle arithmetic exact (no float drift, so
#: ``spent == reserved`` is a decidable equality).
MICROS_PER_DOLLAR = 1_000_000

#: A run cannot carve its ceiling into more pieces than this; the excess is
#: refused with an honest reason rather than silently dropped.
MAX_LEDGER_ALLOCATIONS = 64

#: Settlements are per-task/per-backend records; the cap matches the
#: allocation cap (a caller cannot allocate more tasks than it can settle)
#: and guards against a runaway caller loop. Exceeding it is a caller bug,
#: so it raises rather than degrading.
MAX_LEDGER_SETTLEMENTS = 64

LEDGER_OPEN = "open"              # reserved and/or allocated, nothing settled
LEDGER_SETTLED = "settled"        # spend settled within the ceiling
LEDGER_OVER_SPENT = "over_spent"  # recorded spend above the ceiling

#: Bounded identifier lengths — a task key is an identifier, not free text.
MAX_TASK_KEY_CHARS = 120
MAX_REASON_CHARS = 200
MAX_RUN_ID_CHARS = 120


class LedgerError(ValueError):
    """Illegal lifecycle transition on a per-run budget ledger."""


def _bounded(value: object, limit: int) -> str:
    """Single-line, bounded identifier (no content, ever, in a ledger)."""
    text = " ".join(str(value if value is not None else "").split())
    return text[:limit]


def _check_amount(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative int, got {value!r}")
    return value


def format_usd(micros: int) -> str:
    """Exact integer-only USD rendering for display (never float math)."""
    amount = int(micros)
    sign = "-" if amount < 0 else ""
    magnitude = abs(amount)
    return (f"{sign}${magnitude // MICROS_PER_DOLLAR}."
            f"{magnitude % MICROS_PER_DOLLAR:06d}")


@dataclass(frozen=True)
class BudgetReservation:
    """The ceiling a run reserved up front (stage one of three).

    ``tokens`` is the *token* ceiling this run may commit to and
    ``micros`` the *dollar* ceiling; a caller may enforce only one, so at
    least one must be stated and the other is recorded as ``None`` —
    "unbounded in that dimension". ``None`` never becomes ``0``, which
    would mean "spend nothing".
    """

    tokens: int | None = None
    micros: int | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if self.tokens is None and self.micros is None:
            raise ValueError("a reservation must state a tokens and/or "
                             "micros ceiling")
        for name in ("tokens", "micros"):
            value = getattr(self, name)
            if value is not None:
                _check_amount(value, f"reservation {name}")
        object.__setattr__(self, "reason", _bounded(self.reason,
                                                    MAX_REASON_CHARS))


@dataclass(frozen=True)
class LedgerAllocation:
    """One task's share of the run's reserved ceiling.

    ``tokens=None`` / ``micros=None`` means the task was *not* granted
    budget in that dimension — including a refused task, which got nothing
    at all and carries the reason it was skipped (never a silent drop).
    """

    task: str
    tokens: int | None = None
    micros: int | None = None
    refused: bool = False
    reason: str = ""

    def __post_init__(self) -> None:
        if not _bounded(self.task, MAX_TASK_KEY_CHARS):
            raise ValueError("allocation task must be a non-empty identifier")
        object.__setattr__(self, "task", _bounded(self.task,
                                                  MAX_TASK_KEY_CHARS))
        object.__setattr__(self, "reason", _bounded(self.reason,
                                                    MAX_REASON_CHARS))
        for name in ("tokens", "micros"):
            value = getattr(self, name)
            if value is not None:
                _check_amount(value, f"allocation {name}")
        if self.refused and (self.tokens is not None or self.micros is not None):
            raise ValueError("a refused allocation grants nothing; its "
                             "amounts must be None")

    @property
    def granted(self) -> bool:
        return not self.refused


@dataclass(frozen=True)
class LedgerSettlement:
    """Actual spend recorded against the ceiling (stage three).

    ``task`` attributes the spend (``""`` = run-level); attribution is
    what makes "spend per run, per backend" answerable from the record.
    """

    task: str = ""
    tokens: int = 0
    micros: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "task", _bounded(self.task,
                                                  MAX_TASK_KEY_CHARS))
        _check_amount(self.tokens, "settlement tokens")
        _check_amount(self.micros, "settlement micros")


class BudgetLedger:
    """One run's reserve → allocate → settle record.

    Not thread-safe by design: a ledger belongs to a single run's control
    flow (the orchestrator's composition root), not to the tasks it
    accounts for. Tasks are accounted *by* the caller, never given the
    ledger, which is what keeps one task from spending another's money.
    """

    def __init__(self, run_id: str) -> None:
        run = _bounded(run_id, MAX_RUN_ID_CHARS)
        if not run:
            raise ValueError("ledger run_id must be a non-empty identifier")
        self._run_id = run
        self._reservation: BudgetReservation | None = None
        self._allocations: list[LedgerAllocation] = []
        self._settlements: list[LedgerSettlement] = []

    @classmethod
    def for_run(cls, run_id: str) -> BudgetLedger:
        """The one constructor: a fresh, empty ledger for a single run."""
        return cls(run_id)

    # ------------------------------------------------------------- record
    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def reservation(self) -> BudgetReservation | None:
        return self._reservation

    @property
    def allocations(self) -> tuple[LedgerAllocation, ...]:
        return tuple(self._allocations)

    @property
    def settlements(self) -> tuple[LedgerSettlement, ...]:
        return tuple(self._settlements)

    @property
    def refused(self) -> tuple[LedgerAllocation, ...]:
        return tuple(a for a in self._allocations if a.refused)

    # ------------------------------------------------------------- stages
    def reserve(self, *, tokens: int | None = None,
                micros: int | None = None, reason: str = "") -> BudgetReservation:
        """Stage one: state the hard ceiling (once, before anything else)."""
        if self._reservation is not None:
            raise LedgerError("reserve called twice on one ledger")
        # ``settle`` itself requires a reservation, so a ledger with
        # settlements always has one and is caught above — no second check.
        reservation = BudgetReservation(tokens=tokens, micros=micros,
                                        reason=reason)
        self._reservation = reservation
        return reservation

    def allocate(self, task: str, *, tokens: int | None = None,
                 micros: int | None = None) -> LedgerAllocation:
        """Stage two: carve ceiling to a named task, or refuse it honestly.

        A refusal is a first-class record — the task got nothing, the
        reason names the ceiling that stopped it, and the caller is
        expected to surface it as a skip warning. Refusing is how the
        ceiling stays *hard*: the alternative is granting an overspend and
        reporting it after the fact.
        """
        if self._reservation is None:
            raise LedgerError("allocate before reserve")
        if self._settlements:
            raise LedgerError("cannot allocate after settle")
        if tokens is None and micros is None:
            raise ValueError("an allocation must request tokens and/or micros")
        if tokens is not None:
            _check_amount(tokens, "allocation tokens")
        if micros is not None:
            _check_amount(micros, "allocation micros")

        granted_tokens = sum(a.tokens or 0 for a in self._allocations
                             if a.granted)
        granted_micros = sum(a.micros or 0 for a in self._allocations
                             if a.granted)
        ceiling = self._reservation
        reason = ""
        if len(self._allocations) >= MAX_LEDGER_ALLOCATIONS:
            reason = (f"allocation cap ({MAX_LEDGER_ALLOCATIONS}) reached; "
                      "no budget left to carve")
        elif ceiling.tokens is not None and tokens is not None \
                and granted_tokens + tokens > ceiling.tokens:
            reason = (f"token ceiling: {ceiling.tokens - granted_tokens} of "
                      f"{ceiling.tokens} uncommitted")
        elif ceiling.micros is not None and micros is not None \
                and granted_micros + micros > ceiling.micros:
            reason = (f"dollar ceiling: "
                      f"{format_usd(ceiling.micros - granted_micros)} of "
                      f"{format_usd(ceiling.micros)} uncommitted")

        if reason:
            allocation = LedgerAllocation(task=task, refused=True,
                                          reason=reason)
        else:
            allocation = LedgerAllocation(task=task, tokens=tokens,
                                          micros=micros)
        self._allocations.append(allocation)
        return allocation

    def settle(self, *, tokens: int = 0, micros: int = 0,
               task: str = "") -> LedgerSettlement:
        """Stage three: record actual spend (append-only, may run past the
        ceiling — the resulting ``over_spent`` state is the honest
        outcome, not a failure to record)."""
        if self._reservation is None:
            raise LedgerError("settle before reserve")
        if len(self._settlements) >= MAX_LEDGER_SETTLEMENTS:
            raise LedgerError(f"settlement cap "
                              f"({MAX_LEDGER_SETTLEMENTS}) reached")
        settlement = LedgerSettlement(task=task, tokens=tokens,
                                      micros=micros)
        self._settlements.append(settlement)
        return settlement

    # ----------------------------------------------------------- derived
    @property
    def state(self) -> str:
        if not self._settlements:
            return LEDGER_OPEN
        over = False
        reservation = self._reservation
        if reservation is not None:
            if reservation.tokens is not None \
                    and self.spent_tokens > reservation.tokens:
                over = True
            if reservation.micros is not None \
                    and self.spent_micros > reservation.micros:
                over = True
        return LEDGER_OVER_SPENT if over else LEDGER_SETTLED

    @property
    def reserved_tokens(self) -> int | None:
        return self._reservation.tokens if self._reservation else None

    @property
    def reserved_micros(self) -> int | None:
        return self._reservation.micros if self._reservation else None

    @property
    def allocated_tokens(self) -> int:
        return sum(a.tokens or 0 for a in self._allocations if a.granted)

    @property
    def allocated_micros(self) -> int:
        return sum(a.micros or 0 for a in self._allocations if a.granted)

    @property
    def spent_tokens(self) -> int:
        return sum(s.tokens for s in self._settlements)

    @property
    def spent_micros(self) -> int:
        return sum(s.micros for s in self._settlements)

    @property
    def remaining_tokens(self) -> int | None:
        """Ceiling left to commit, or ``None`` when unbounded."""
        if self.reserved_tokens is None:
            return None
        return self.reserved_tokens - self.allocated_tokens

    @property
    def remaining_micros(self) -> int | None:
        if self.reserved_micros is None:
            return None
        return self.reserved_micros - self.allocated_micros

    # ---------------------------------------------------------- surfacing
    def skip_warnings(self) -> tuple[str, ...]:
        """One bounded, content-free warning per refused allocation.

        This is the T02 contract in one place: *every* skipped task
        appears in warnings with a reason.
        """
        return tuple(f"budget: task {a.task} skipped: {a.reason}"
                     for a in self.refused)

    def to_dict(self) -> dict:
        """Counts-and-identifiers view for the report/telemetry/dashboard.

        JSON-round-trippable by construction (str/int/bool/None only) and
        bounded by ``MAX_LEDGER_ALLOCATIONS`` / ``MAX_LEDGER_SETTLEMENTS``.
        """
        return {
            "run_id": self._run_id,
            "state": self.state,
            "reserved": {"tokens": self.reserved_tokens,
                         "micros": self.reserved_micros},
            "allocated": {"tokens": self.allocated_tokens,
                          "micros": self.allocated_micros},
            "spent": {"tokens": self.spent_tokens,
                      "micros": self.spent_micros},
            "remaining": {"tokens": self.remaining_tokens,
                          "micros": self.remaining_micros},
            "allocations": [
                {"task": a.task, "tokens": a.tokens, "micros": a.micros,
                 "refused": a.refused, "reason": a.reason}
                for a in self._allocations],
            "settlements": [
                {"task": s.task, "tokens": s.tokens, "micros": s.micros}
                for s in self._settlements],
            "skips": list(self.skip_warnings()),
        }
