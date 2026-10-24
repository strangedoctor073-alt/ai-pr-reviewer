"""``python -m eval.harness`` — offline evaluation corpus runner (V3-E03).

One command runs the corpus and prints per-case results plus a score::

    python -m eval.harness [--layer L]... [--corpus DIR] [--json PATH]
    python -m eval.harness --gate         # CI: fail (exit 1) on regression
    python -m eval.harness --update-baseline   # deliberate baseline rewrite

Exit codes (stable contract, relied on by CI and by the tests):

* ``0`` — every case ran and (with ``--gate``) no documented threshold
  was breached;
* ``1`` — a case errored, or the gate reported a regression / missing or
  unreadable baseline, or ``--update-baseline`` was refused (failing or
  errored cases must never be baselined);
* ``2`` — the corpus itself is invalid (malformed label file, unknown
  layer, duplicate id, missing diff) — loud, never silently skipped.

Fully offline: no network, no API keys (V3-E03-T01).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from .gate import (build_baseline, check_gate, corpus_hash,
                   dumps_baseline)
from .loader import VALID_LAYERS, CorpusError, load_corpus
from .perf import build_perf, dumps_perf, format_perf
from .report import build_report, dumps_report
from .tier_b import (DEFAULT_REPEAT, ENGINES, dumps_tier_b, format_tier_b,
                     run_tier_b)
from .runner import run_case
from .score import score_corpus, scorecard_to_dict

DEFAULT_CORPUS = Path(__file__).resolve().parents[1] / "corpus"
DEFAULT_BASELINE = Path(__file__).resolve().parents[1] / "baseline.json"
REPO_ROOT = Path(__file__).resolve().parents[2]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m eval.harness",
        description="Run the offline evaluation corpus through the "
                    "deterministic review pipeline.",
    )
    parser.add_argument("--corpus", default=str(DEFAULT_CORPUS),
                        help="corpus root (default: eval/corpus)")
    parser.add_argument("--layer", action="append", choices=VALID_LAYERS,
                        help="only run this layer (repeatable)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--gate", action="store_true",
                       help="compare this run against the baseline and "
                            "exit 1 on a regression beyond the documented "
                            "thresholds (CI mode)")
    group.add_argument("--update-baseline", action="store_true",
                       help="regenerate the baseline file (deliberate "
                            "action — commit the reviewed diff)")
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE),
                        help="baseline path (default: eval/baseline.json)")
    parser.add_argument("--json", metavar="PATH",
                        help="write a machine-readable JSON report (score, "
                             "case count, corpus hash, git commit/dirty) "
                             "to PATH; byte-stable on the same commit")
    tier = parser.add_argument_group(
        "Tier B (live provider, REPORTING ONLY — never blocks, never run by "
        "--gate; needs credentials in the environment)")
    tier.add_argument("--engine", choices=ENGINES,
                      help="run this provider's corpus cases through the "
                           "real pipeline and report precision vs the "
                           "0.80 floor (exit 0 whatever the verdict)")
    tier.add_argument("--model", help="explicit model id (required for "
                                      "openai/gemini; never hardcoded here)")
    tier.add_argument("--repeat", type=int, default=DEFAULT_REPEAT,
                      help=f"repetitions per case (default {DEFAULT_REPEAT})")
    tier.add_argument("--budget-tokens", type=int, metavar="N",
                      help="stop issuing runs once provider-reported "
                           "tokens reach N")
    tier.add_argument("--tier-b-json", metavar="PATH",
                      help="write the Tier-B report (not byte-stable)")
    parser.add_argument("--perf", action="store_true",
                        help="also print wall-clock latency p50/p95 (index "
                             "build, pipeline) and budget verdicts — "
                             "non-deterministic, so off by default")
    parser.add_argument("--perf-json", metavar="PATH",
                        help="write the (non-byte-stable) latency report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        cases = load_corpus(Path(args.corpus), args.layer or None)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2

    if args.engine:
        if args.gate or args.update_baseline:
            print("--engine (Tier B) is reporting-only and cannot be "
                  "combined with --gate/--update-baseline", file=sys.stderr)
            return 2
        with tempfile.TemporaryDirectory(prefix="eval-tier-b-") as tmp:
            report = run_tier_b(
                cases, args.engine, Path(tmp),
                model=args.model or os.environ.get("INPUT_MODEL"),
                repeat=args.repeat, budget_tokens=args.budget_tokens)
        for line in format_tier_b(report):
            print(line)
        if args.tier_b_json:
            Path(args.tier_b_json).write_text(
                dumps_tier_b(report), encoding="utf-8", newline="\n")
            print(f"tier-b report written: {args.tier_b_json}")
        return 0                       # reporting-only: never a CI failure

    with tempfile.TemporaryDirectory(prefix="eval-harness-") as tmp:
        runs = [run_case(case, Path(tmp) / case.id) for case in cases]

    card = score_corpus(cases, runs)

    # Per-case verdicts in corpus order (load_corpus sorts stably).
    for case, run, score in zip(cases, runs, card.cases):
        line = (f"{score.status:>7}  {case.layer}/{case.id}  "
                f"engine={run.engine or '-'}  "
                f"findings={len(run.findings)} below={len(run.below)}")
        if run.skipped_reason:
            line += f"  ({run.skipped_reason})"
        print(line)
        for failure in score.failures:
            print(f"           ! {failure}")

    def _fmt(value: float | None) -> str:
        return "null" if value is None else f"{value:.3f}"

    print(f"score: precision={_fmt(card.precision)} recall={_fmt(card.recall)} "
          f"fp_rate={_fmt(card.false_positive_rate)} "
          f"recall_critical_high={_fmt(card.recall_critical_high)} "
          f"relevance@10={_fmt(card.relevance_at_10)} "
          f"labels={card.counts['labels_total']}/"
          f"{card.counts['labels_matched']} "
          f"posted={card.counts['findings_posted']}")
    print(f"v4: severity_accuracy={_fmt(card.severity_accuracy)} "
          f"fix_usefulness={_fmt(card.fix_usefulness)} "
          f"verification_accuracy={_fmt(card.verification_accuracy)} "
          f"misverify={card.counts['misverify']} "
          f"missverify={card.counts['missverify']}")

    errors = card.counts["errors"]
    skipped = card.counts["skipped"]
    print(f"cases={len(runs)} ran={len(runs) - errors - skipped} "
          f"errors={errors} skipped={skipped}")

    perf = build_perf(runs)
    if args.perf:
        for line in format_perf(perf):
            print(line)
    if args.perf_json:
        Path(args.perf_json).write_text(dumps_perf(perf), encoding="utf-8",
                                        newline="\n")
        print(f"perf report written: {args.perf_json}")

    if args.update_baseline or args.gate or args.json:
        digest = corpus_hash(args.corpus)
    if args.update_baseline or args.gate:
        payload = build_baseline(scorecard_to_dict(card), digest)

    if args.json:
        report = build_report(card, digest, REPO_ROOT)
        Path(args.json).write_text(dumps_report(report), encoding="utf-8",
                                   newline="\n")
        print(f"report written: {args.json}")

    if args.update_baseline:
        blocked = {k: v for k, v in card.counts.items()
                   if k in ("errors", "failed", "violations") and v}
        if blocked:
            print(f"baseline NOT written: refusing to bake a broken state "
                  f"into the baseline {blocked} — fix or xfail the case "
                  f"first", file=sys.stderr)
            return 1
        Path(args.baseline).write_text(dumps_baseline(payload),
                                       encoding="utf-8", newline="\n")
        print(f"baseline written: {args.baseline}")
        return 0

    if args.gate:
        baseline_path = Path(args.baseline)
        try:
            baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            print(f"gate: FAIL baseline not found: {baseline_path} — run "
                  f"python -m eval.harness --update-baseline and commit it",
                  file=sys.stderr)
            return 1
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            print(f"gate: FAIL baseline unreadable ({exc}) — regenerate "
                  f"it deliberately", file=sys.stderr)
            return 1
        result = check_gate(payload, baseline, digest, perf=perf)
        if result.ok:
            print("gate: OK — no regression beyond documented thresholds")
            return 0
        for message in result.failures:
            print(f"gate: FAIL {message}", file=sys.stderr)
        return 1

    return 1 if errors else 0


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(main())
