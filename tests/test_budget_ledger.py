"""V4.0-E07 — cost/token arbitration (per-run budget ledger).

T01: the ledger itself — reserve → allocate → settle lifecycle, the hard
ceiling (refusal instead of overspend), honest per-skip warnings, exact
integer micro accounting, bounded counts-only serialization, and a
read-only module (AST-enforced).

T02/T03/T04 (enforcement wiring, response_budget mapping, dashboard
view) append below as they land.

Fixtures are deterministic synthetic ledgers; no clock, no network, no
content — the same operations must serialize to the same bytes.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import budget_ledger as bl           # noqa: E402
from ai_pr_reviewer.budget_ledger import (LEDGER_OPEN,    # noqa: E402
                                          LEDGER_OVER_SPENT,
                                          LEDGER_SETTLED,
                                          MAX_LEDGER_ALLOCATIONS,
                                          MAX_LEDGER_SETTLEMENTS,
                                          MICROS_PER_DOLLAR, BudgetLedger,
                                          LedgerError, format_usd)

MODULE_PATH = ROOT / "ai_pr_reviewer" / "budget_ledger.py"


def _ledger(tokens=None, micros=None, run_id="run-1"):
    ledger = BudgetLedger.for_run(run_id)
    if tokens is not None or micros is not None:
        ledger.reserve(tokens=tokens, micros=micros)
    return ledger


# ------------------------------------------------------------ lifecycle
def test_reserve_allocate_settle_happy_path():
    ledger = _ledger(tokens=1_000, micros=5_000_000)
    assert ledger.state == LEDGER_OPEN

    granted = ledger.allocate("analysis", tokens=600, micros=2_000_000)
    assert granted.granted and granted.tokens == 600
    assert ledger.remaining_tokens == 400
    assert ledger.remaining_micros == 3_000_000

    ledger.settle(tokens=550, micros=1_800_000, task="analysis")
    assert ledger.state == LEDGER_SETTLED
    assert ledger.spent_tokens == 550
    assert ledger.spent_micros == 1_800_000


def test_for_run_is_the_only_constructor_and_ledgers_are_independent():
    a = BudgetLedger.for_run("run-a")
    b = BudgetLedger.for_run("run-b")
    a.reserve(tokens=100)
    a.allocate("task", tokens=100)
    # a second run starts empty — no process-global budget to share
    assert b.reservation is None and b.allocations == ()
    assert a.run_id == "run-a" and b.run_id == "run-b"
    with pytest.raises(ValueError):
        BudgetLedger.for_run("   ")          # blank id is not an identity


def test_allocate_before_reserve_is_an_error():
    ledger = BudgetLedger.for_run("run-1")
    with pytest.raises(LedgerError, match="allocate before reserve"):
        ledger.allocate("analysis", tokens=10)


def test_settle_before_reserve_is_an_error():
    ledger = BudgetLedger.for_run("run-1")
    with pytest.raises(LedgerError, match="settle before reserve"):
        ledger.settle(tokens=10)


def test_reserve_is_once_only():
    ledger = _ledger(tokens=100)
    with pytest.raises(LedgerError, match="reserve called twice"):
        ledger.reserve(tokens=200)


def test_nothing_happens_after_settle():
    ledger = _ledger(tokens=100)
    ledger.settle(tokens=10)
    with pytest.raises(LedgerError, match="cannot allocate after settle"):
        ledger.allocate("late", tokens=10)
    with pytest.raises(LedgerError, match="reserve called twice"):
        ledger.reserve(tokens=10)


# -------------------------------------------------------- hard ceiling
def test_allocation_over_the_ceiling_is_refused_not_granted():
    ledger = _ledger(tokens=1_000)
    first = ledger.allocate("a", tokens=800)
    assert first.granted

    refused = ledger.allocate("b", tokens=400)     # 800 + 400 > 1000
    assert not refused.granted
    assert refused.tokens is None and refused.micros is None
    assert "token ceiling" in refused.reason
    assert "200 of 1000 uncommitted" in refused.reason
    # the ceiling stayed hard: committed budget never exceeds the reserve
    assert ledger.allocated_tokens == 800
    assert ledger.remaining_tokens == 200


def test_refusal_reasons_name_the_dollar_ceiling_in_exact_usd():
    ledger = _ledger(micros=1_500_000)
    ledger.allocate("a", micros=1_000_000)
    refused = ledger.allocate("b", micros=1_000_000)
    assert not refused.granted
    assert refused.reason == ("dollar ceiling: $0.500000 of $1.500000 "
                              "uncommitted")


def test_each_ceiling_dimension_is_enforced_independently():
    # tokens bounded, dollars unbounded (None): a huge dollar ask passes
    ledger = _ledger(tokens=100)
    granted = ledger.allocate("rich", tokens=100, micros=10 ** 9)
    assert granted.granted

    dollars = _ledger(micros=1_000)
    also = dollars.allocate("poor", tokens=10 ** 9, micros=1_000)
    assert also.granted


def test_exactly_the_remaining_budget_is_granted():
    ledger = _ledger(tokens=1_000)
    ledger.allocate("a", tokens=400)
    assert ledger.allocate("b", tokens=600).granted     # exact fit
    assert ledger.allocate("c", tokens=1).refused       # one over


def test_allocation_cap_is_a_refusal_not_a_silent_drop():
    ledger = _ledger(tokens=10 ** 12)
    for i in range(MAX_LEDGER_ALLOCATIONS):
        assert ledger.allocate(f"t{i}", tokens=1).granted
    overflow = ledger.allocate("overflow", tokens=1)
    assert not overflow.granted
    assert f"allocation cap ({MAX_LEDGER_ALLOCATIONS})" in overflow.reason
    assert len(ledger.allocations) == MAX_LEDGER_ALLOCATIONS + 1


def test_settlement_cap_raises_because_it_is_a_caller_bug():
    ledger = _ledger(tokens=10 ** 12)
    for _ in range(MAX_LEDGER_SETTLEMENTS):
        ledger.settle(tokens=1)
    with pytest.raises(LedgerError, match="settlement cap"):
        ledger.settle(tokens=1)


# ----------------------------------------------------------- honesty
def test_overspend_records_over_spent_instead_of_being_hidden():
    ledger = _ledger(tokens=1_000)
    ledger.allocate("analysis", tokens=1_000)
    ledger.settle(tokens=4_000, task="analysis")       # the provider lied
    assert ledger.state == LEDGER_OVER_SPENT
    assert ledger.spent_tokens == 4_000
    assert ledger.to_dict()["state"] == LEDGER_OVER_SPENT


def test_spending_exactly_the_ceiling_is_settled_not_over():
    ledger = _ledger(tokens=1_000)
    ledger.settle(tokens=1_000)
    assert ledger.state == LEDGER_SETTLED


def test_settlement_without_any_allocation_is_valid():
    ledger = _ledger(tokens=1_000)
    ledger.settle(tokens=10)
    assert ledger.state == LEDGER_SETTLED


def test_every_refused_task_appears_in_warnings_with_a_reason():
    ledger = _ledger(tokens=100)
    ledger.allocate("kept", tokens=100)
    ledger.allocate("dropped-a", tokens=100)
    ledger.allocate("dropped-b", tokens=100)
    warnings = ledger.skip_warnings()
    assert len(warnings) == 2
    assert all(w.startswith("budget: task ") for w in warnings)
    assert all("skipped:" in w for w in warnings)
    assert any("dropped-a" in w for w in warnings)
    assert any("dropped-b" in w for w in warnings)
    assert not any("kept" in w for w in warnings)


def test_refused_allocation_carries_no_amount_invariant():
    ledger = _ledger(tokens=10)
    refused = ledger.allocate("nope", tokens=100)
    with pytest.raises(ValueError, match="refused allocation grants nothing"):
        bl.LedgerAllocation(task="bad", tokens=5, refused=True)
    assert refused.tokens is None and refused.granted is False


# ------------------------------------------------------------- bounds
def test_reservation_must_state_a_ceiling():
    with pytest.raises(ValueError, match="must state"):
        BudgetLedger.for_run("run-1").reserve()


@pytest.mark.parametrize("bad", [pytest.param(-1, id="negative"),
                                 pytest.param(True, id="bool"),
                                 pytest.param("10", id="str"),
                                 pytest.param(1.5, id="float")])
def test_amounts_are_non_negative_ints_only(bad):
    ledger = BudgetLedger.for_run("run-1")
    with pytest.raises(ValueError, match="non-negative int"):
        ledger.reserve(tokens=bad)
    with pytest.raises(ValueError, match="non-negative int"):
        _ledger(tokens=10).allocate("t", tokens=bad)
    with pytest.raises(ValueError, match="non-negative int"):
        _ledger(tokens=10).settle(tokens=bad)


def test_identifiers_are_non_empty_and_bounded():
    with pytest.raises(ValueError, match="non-empty"):
        _ledger(tokens=10).allocate("", tokens=1)
    with pytest.raises(ValueError, match="non-empty"):
        _ledger(tokens=10).allocate("   ", tokens=1)

    ledger = _ledger(tokens=10)
    ledger.allocate("x" * 500, tokens=1)
    assert len(ledger.allocations[0].task) == bl.MAX_TASK_KEY_CHARS


def test_task_keys_and_reasons_are_single_line():
    ledger = _ledger(tokens=1)
    ledger.allocate("multi\nline\tkey", tokens=1)
    assert ledger.allocations[0].task == "multi line key"
    assert "\n" not in ledger.allocations[0].task
    assert "\t" not in ledger.allocations[0].task


# ------------------------------------------------------- serialization
def test_to_dict_is_json_round_trippable_and_counts_only():
    ledger = _ledger(tokens=1_000, micros=2_000_000, run_id="run-42")
    ledger.allocate("analysis", tokens=500, micros=1_000_000)
    ledger.allocate("too-much", tokens=5_000)
    ledger.settle(tokens=400, micros=900_000, task="analysis")

    data = ledger.to_dict()
    assert json.loads(json.dumps(data)) == data
    assert data["run_id"] == "run-42"
    assert data["reserved"] == {"tokens": 1_000, "micros": 2_000_000}
    assert data["spent"] == {"tokens": 400, "micros": 900_000}
    assert data["allocations"][1]["refused"] is True
    assert len(data["skips"]) == 1
    # no clock anywhere: serialization is a pure function of operations
    assert not any(key in data for key in
                   ("created_at", "timestamp", "ts", "at"))


def test_to_dict_is_deterministic_across_runs():
    def build():
        ledger = _ledger(tokens=1_000, run_id="same")
        ledger.allocate("a", tokens=500)
        ledger.allocate("b", tokens=500)
        ledger.settle(tokens=700, task="a")
        return ledger.to_dict()

    assert build() == build()


def test_usd_formatting_is_exact_integer_arithmetic():
    assert format_usd(0) == "$0.000000"
    assert format_usd(1_500_000) == "$1.500000"
    assert format_usd(1) == "$0.000001"
    assert format_usd(-2_250_000) == "-$2.250000"
    assert format_usd(10 ** 15) == "$1000000000.000000"
    assert MICROS_PER_DOLLAR == 1_000_000
    # a float total would drift; the integer path never does
    assert format_usd(300_000) == "$0.300000"


# -------------------------------------------------------- read-only scan
_BANNED_MODULES = {"urllib", "requests", "httpx", "socket", "ssl", "http",
                   "queue", "threading", "multiprocessing", "asyncio",
                   "concurrent", "subprocess", "os", "pathlib", "logging"}
_BANNED_CALLS = {"write_text", "write_bytes", "unlink", "rename", "open",
                 "eval", "exec", "compile", "__import__", "urlopen"}


def _violations(source: str) -> list[str]:
    tree = ast.parse(source)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if name.split(".")[0] in _BANNED_MODULES:
                hits.append(f"import {name}")
        if isinstance(node, ast.Call):
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else "")
            if name in _BANNED_CALLS:
                hits.append(f"call {name}")
    return hits


def test_budget_ledger_is_pure_accounting_with_no_side_effects():
    """Ledger arithmetic reaches no I/O, no clock and no network — the
    whole module is a data structure plus sums."""
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert _violations(source) == []
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "").split(".")[0])
    assert roots <= {"__future__", "dataclasses"}, sorted(roots)

    # self-check: every shape the contract exists to catch is caught
    for hostile in ("import socket\n", "import os\n",
                    "from subprocess import run\n", "open('f').read()\n",
                    "p.write_text('x')\n", "eval('1')\n"):
        assert _violations(hostile), hostile
    assert _violations("from dataclasses import dataclass\n") == []
