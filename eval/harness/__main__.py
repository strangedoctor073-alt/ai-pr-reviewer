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
import sys
import tempfile
from pathlib import Path

from .gate import (build_baseline, check_gate, corpus_hash,
                   dumps_baseline)
from .loader import VALID_LAYERS, CorpusError, load_corpus
from .report import build_report, dumps_report
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
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        cases = load_corpus(Path(args.corpus), args.layer or None)
    except CorpusError as exc:
        print(f"corpus error: {exc}", file=sys.stderr)
        return 2

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
          f"labels={card.counts['labels_total']}/"
          f"{card.counts['labels_matched']} "
          f"posted={card.counts['findings_posted']}")

    errors = card.counts["errors"]
    skipped = card.counts["skipped"]
    print(f"cases={len(runs)} ran={len(runs) - errors - skipped} "
          f"errors={errors} skipped={skipped}")

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
        result = check_gate(payload, baseline, digest)
        if result.ok:
            print("gate: OK — no regression beyond documented thresholds")
            return 0
        for message in result.failures:
            print(f"gate: FAIL {message}", file=sys.stderr)
        return 1

    return 1 if errors else 0


if __name__ == "__main__":  # pragma: no cover - exercised via subprocess
    raise SystemExit(main())
