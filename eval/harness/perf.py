"""V4-E11-T06 — wall-clock latency for the evaluation run (offline).

TESTING_EVALUATION_PLAN §8 #8: *Latency p50/p95 — index build, per-provider
call, end-to-end duration — budgets reported; index p95 < 2 s on fixture
repos.* This module measures what the offline harness can measure for real:

* ``index_build``  — the production ``build_index`` over each case's fixture
  checkout (cases that ship ``checkout/``);
* ``pipeline``     — the production ``ReviewOrchestrator.run()`` end to end
  for every case that ran (the "stubbed pipeline" of §4: static engine, no
  network).

Wall-clock is **not byte-stable** (§5.3), so none of this is ever written
into the scorecard, the baseline, or ``--json``; it has its own opt-in
``--perf`` printout and ``--perf-json`` file. Exactly one budget is
enforceable in ``--gate`` — the plan's explicit one, ``index p95 < 2 s`` —
and it sits ~2 orders of magnitude above what a tiny fixture needs, so it
trips on a real algorithmic regression, not on a noisy CI host. The §4
stubbed-pipeline p95 < 5 s is reported with its verdict but never blocks
(it is a *proposed* baseline).

With few samples the nearest-rank p95 equals the max — stated in the
output (``n=``) rather than dressed up. ``no_data`` is never a pass.

Latency numbers are display/telemetry only: nothing here (or anywhere in
the engine) may feed a routing decision (V4_THREAT_MODEL §6).
"""
from __future__ import annotations

import json
from typing import Iterable

from ai_pr_reviewer.telemetry import latency_from_rows, summarize_latency

from .runner import CaseRun

PERF_SCHEMA_VERSION = 1
INDEX_P95_BUDGET_MS = 2000.0      # §8 #8 — enforced by --gate
PIPELINE_P95_BUDGET_MS = 5000.0   # §4 proposed baseline — reported only


def _verdict(summary: dict, budget_ms: float) -> str:
    if not summary["n"]:
        return "no_data"
    return "ok" if summary["p95"] < budget_ms else "over_budget"


def build_perf(runs: Iterable[CaseRun]) -> dict:
    """Latency summaries (ms, rounded to 0.1) + budget verdicts."""
    runs = [r for r in runs if r.run_status == "ran"]
    index = summarize_latency(r.timings_ms["index_build"] for r in runs
                              if "index_build" in r.timings_ms)
    pipe = summarize_latency(r.timings_ms["pipeline"] for r in runs
                             if "pipeline" in r.timings_ms)

    def rounded(summary: dict) -> dict:
        return {k: (round(v, 1) if isinstance(v, float) else v)
                for k, v in summary.items()}

    perf = {
        "schema_version": PERF_SCHEMA_VERSION,
        "note": "wall-clock; not byte-stable; never part of the baseline",
        "index_build_ms": rounded(index),
        "pipeline_ms": rounded(pipe),
        "budgets": {
            "index_p95_ms": {"limit": INDEX_P95_BUDGET_MS,
                             "verdict": _verdict(index, INDEX_P95_BUDGET_MS),
                             "enforced_by_gate": True},
            "pipeline_p95_ms": {"limit": PIPELINE_P95_BUDGET_MS,
                                "verdict": _verdict(pipe,
                                                    PIPELINE_P95_BUDGET_MS),
                                "enforced_by_gate": False},
        },
    }
    # Provider-reported per-call/per-run latency from captured telemetry
    # rows (Tier-B runs; static runs carry n/a usage, so this is empty).
    perf["provider_ms"] = latency_from_rows(
        r.telemetry for r in runs if r.telemetry)
    return perf


def perf_budget_failures(perf: dict) -> list[str]:
    """Gate failures: only the enforced budget, only on real evidence."""
    budget = perf["budgets"]["index_p95_ms"]
    if budget["verdict"] == "over_budget":
        return [f"index build p95 {perf['index_build_ms']['p95']} ms exceeds "
                f"the {budget['limit']:.0f} ms budget on fixture repos "
                f"(TESTING_EVALUATION_PLAN §8 #8)"]
    return []


def format_perf(perf: dict) -> list[str]:
    lines = []
    for key, label in (("index_build_ms", "index_build"),
                       ("pipeline_ms", "pipeline")):
        s = perf[key]
        lines.append(f"perf: {label} n={s['n']} p50={s['p50']}ms "
                     f"p95={s['p95']}ms max={s['max']}ms")
    for name, b in perf["budgets"].items():
        gate = "gate" if b["enforced_by_gate"] else "report-only"
        lines.append(f"perf: budget {name} < {b['limit']:.0f} ms "
                     f"-> {b['verdict']} ({gate})")
    return lines


def dumps_perf(perf: dict) -> str:
    return json.dumps(perf, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
