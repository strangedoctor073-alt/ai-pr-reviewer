"""V4-E11-T08 — Tier-B (live provider) evaluation: REPORTING ONLY.

ADR-016 two-tier strategy: Tier A (offline, deterministic) blocks PRs;
Tier B (AI/model layers) is scheduled and **never** blocks a contributor.
TESTING_EVALUATION_PLAN §8: *Tier-B provider precision floor ≥ 0.80 at
release — reporting-only until a provider environment is available; never
a hard CI dependency for offline contributors.*

``python -m eval.harness --engine claude|openai|gemini --model <id>``
runs the corpus cases whose ``engine_matrix`` lists that provider through
the *real* pipeline and writes a report. Properties, all deliberate:

* **Explicit opt-in.** Nothing here runs unless ``--engine`` names a
  provider; ``--gate`` and the default run never touch it, so offline
  contributors and the CI ``evaluation`` job have no provider dependency.
* **No hardcoded model ids.** ``--model`` (or ``INPUT_MODEL``) is required
  for openai/gemini — the same "explicit model" rule the router enforces —
  and optional for claude (the router's own default applies). Credentials
  come from the standard env vars; none are read from the corpus.
* **Honest attribution.** A run is scored only when the pipeline reports
  exactly the requested engine; a silent static/provider fallback is
  ``skipped`` (runner), never a fake provider number.
* **Floor is a verdict, not a gate.** ``meets_floor`` / ``below_floor`` /
  ``not_measured`` — the process exits 0 whatever the verdict. ``not_measured``
  (no credentials, no posted findings) is stated as such: no data beats a
  fabricated number.
* **Stochastic ⇒ rates over N repetitions** (§5.3, proposed N=3); each
  repetition is scored as its own run and the ratios are micro-averaged.
* **Bounded spend.** ``--budget-tokens`` stops issuing further runs once the
  provider-reported tokens reach the cap (remaining runs are ``skipped``).
* Token/cost/latency figures are *display only* (V4_THREAT_MODEL §6) and
  appear in the report; they influence nothing.

The live path needs credentials and network and has NOT been exercised
against a real provider in this repository's tests — those prove the
plumbing with a canned provider (tests/test_evaluation_harness.py).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Mapping

from ai_pr_reviewer.telemetry import latency_from_rows

from .loader import Case
from .runner import CaseRun, run_case
from .score import score_corpus, scorecard_to_dict

TIER_B_SCHEMA_VERSION = 1
TIER_B_PRECISION_FLOOR = 0.80          # §8 — reporting-only
DEFAULT_REPEAT = 3                     # §5.3 proposed baseline
ENGINES = ("claude", "openai", "gemini")

_KEY_ENV = {"claude": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY",
            "gemini": "GEMINI_API_KEY"}
_KEY_FIELD = {"claude": "anthropic_api_key", "openai": "openai_api_key",
              "gemini": "gemini_api_key"}


def engine_config(engine: str, model: str | None,
                  environ: Mapping[str, str]) -> tuple[dict | None, str | None]:
    """``(Config kwargs, None)`` or ``(None, reason)`` — never raises."""
    if engine not in ENGINES:
        return None, f"unknown engine {engine!r}; choose from {ENGINES}"
    key = environ.get(_KEY_ENV[engine], "").strip()
    base_url = environ.get("OPENAI_BASE_URL", "").strip() \
        if engine == "openai" else ""
    if not key and not base_url:
        return None, f"no credentials: set {_KEY_ENV[engine]}"
    model = (model or "").strip()
    if engine in ("openai", "gemini") and not model:
        return None, (f"{engine} needs an explicit --model (the router "
                      f"never guesses a cross-vendor model id)")
    cfg: dict = {_KEY_FIELD[engine]: key}
    if base_url:
        cfg["openai_base_url"] = base_url
    if model:
        cfg["model"] = model
    return cfg, None


def _tokens(run: CaseRun) -> int:
    usage = (run.telemetry or {}).get("usage") or {}
    if usage.get("state") != "ok":
        return 0
    return int(usage.get("input_tokens") or 0) + int(
        usage.get("output_tokens") or 0)


def _aggregate_cost(runs: list[CaseRun]) -> dict:
    rows = [r.telemetry["cost"] for r in runs
            if r.telemetry and isinstance(r.telemetry.get("cost"), dict)]
    states = {c.get("state") for c in rows}
    if not rows:
        return {"state": "n/a", "currency": "USD", "low": None, "high": None,
                "display_only": True}
    if states == {"estimated"}:
        return {"state": "estimated", "currency": "USD",
                "low": round(sum(c["low"] for c in rows), 6),
                "high": round(sum(c["high"] for c in rows), 6),
                "display_only": True}
    state = "unpriced" if "unpriced" in states else sorted(
        s for s in states if s)[0]
    return {"state": state, "currency": "USD", "low": None, "high": None,
            "display_only": True}


def run_tier_b(cases: tuple[Case, ...], engine: str, workdir: Path, *,
               model: str | None = None,
               environ: Mapping[str, str] | None = None,
               repeat: int = DEFAULT_REPEAT,
               budget_tokens: int | None = None,
               runner: Callable[..., CaseRun] = run_case) -> dict:
    """Run ``engine``'s corpus cases and return the (non-byte-stable)
    Tier-B report dict. ``runner`` is injectable for tests."""
    import os
    environ = os.environ if environ is None else environ
    base = {"schema_version": TIER_B_SCHEMA_VERSION, "engine": engine,
            "model": (model or "") or None, "repeat": repeat,
            "reporting_only": True,
            "floor": {"metric": "precision", "value": TIER_B_PRECISION_FLOOR}}
    cfg, reason = engine_config(engine, model, environ)
    if cfg is None:
        return {**base, "verdict": "not_measured", "reason": reason,
                "metrics": None, "counts": {"runs": 0, "skipped": 0},
                "tokens": 0, "cost": _aggregate_cost([]),
                "latency_ms": latency_from_rows([])}

    selected = [c for c in cases if engine in c.engine_matrix]
    pairs: list[tuple[Case, CaseRun]] = []
    spent = 0
    for rep in range(max(1, repeat)):
        for case in selected:
            if budget_tokens is not None and spent >= budget_tokens:
                run = CaseRun(case.id, case.layer, "skipped",
                              skipped_reason="--budget-tokens exhausted")
            else:
                run = runner(case, Path(workdir) / f"{case.id}.r{rep}",
                             engine=engine, engine_config=cfg)
                spent += _tokens(run)
            pairs.append((case, run))
    card = score_corpus(tuple(c for c, _ in pairs), [r for _, r in pairs])
    runs = [r for _, r in pairs]
    precision = card.precision
    verdict = ("not_measured" if precision is None else
               "meets_floor" if precision >= TIER_B_PRECISION_FLOOR - 1e-12
               else "below_floor")
    return {
        **base, "verdict": verdict, "reason": None,
        "metrics": scorecard_to_dict(card)["metrics"],
        "counts": {"runs": len(runs),
                   "ran": sum(r.run_status == "ran" for r in runs),
                   "skipped": sum(r.run_status == "skipped" for r in runs),
                   "errors": sum(r.run_status == "error" for r in runs),
                   **{k: card.counts[k] for k in
                      ("labels_total", "labels_matched", "findings_posted")}},
        "skipped_reasons": sorted({r.skipped_reason for r in runs
                                   if r.skipped_reason})[:5],
        "tokens": spent,
        "cost": _aggregate_cost(runs),                 # display only
        "latency_ms": latency_from_rows(r.telemetry for r in runs
                                        if r.telemetry),
    }


def format_tier_b(report: dict) -> list[str]:
    m = report.get("metrics") or {}
    p = m.get("precision")
    lines = [f"tier-b: engine={report['engine']} model="
             f"{report['model'] or '(provider default)'} "
             f"repeat={report['repeat']} -> {report['verdict']} "
             f"(precision floor {TIER_B_PRECISION_FLOOR:.2f}, "
             f"reporting-only)"]
    if report.get("reason"):
        lines.append(f"tier-b: not measured — {report['reason']}")
    else:
        lines.append(
            f"tier-b: precision={'null' if p is None else f'{p:.3f}'} "
            f"recall={m.get('recall')} runs={report['counts']['runs']} "
            f"skipped={report['counts']['skipped']} "
            f"tokens={report['tokens']} cost={report['cost']['state']} "
            f"(display only)")
    return lines


def dumps_tier_b(report: dict) -> str:
    return json.dumps(report, sort_keys=True, indent=2, ensure_ascii=True) + "\n"
