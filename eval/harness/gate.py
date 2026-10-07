"""V3-E03-T03 — baseline capture and the offline regression gate.

The gate answers one question on every CI run: *did this change make the
review engine measurably worse on the golden corpus?* — using only
deterministic, offline inputs (ADR-016 Tier A: deterministic layers block,
AI layers never do).

**Baseline file** (``eval/baseline.json``) is a scorecard plus:

* ``corpus_hash``  — sha256 over every corpus file (path + bytes,
  slash-normalized order). ANY corpus edit changes it, so a baseline can
  only move together with the corpus it describes: lowering expected-label
  coverage cannot quietly improve a score, because the gate fails on
  drift until a human regenerates the baseline deliberately
  (``--update-baseline``) and reviews the diff;
* ``thresholds``   — the **allowed drop** per metric. Documented,
  versioned in the file itself:
  - ``precision``               → 0.0
  - ``recall``                  → 0.0
  - ``recall_critical_high``    → 0.0 — **proposed baseline** (uncalibrated):
    *any* drop in critical/high recall fails the gate. This is the
    blocking guard of §5.4.
  - ``false_positive_rate``     → 0.0 (a rise of any size fails: it is a
    "badness" metric — the check is inverted below)

  These are deliberately strict for a deterministic, fully-synthetic
  corpus: nothing here depends on a model vendor, so any movement is our
  own doing and should be a conscious, reviewed choice.

**Gate verdict** fails (exit 1) on: baseline-format version mismatch,
corpus/baseline drift, any watched metric below ``baseline - allowed_drop``
(inverted for ``false_positive_rate``), a metric that had data and now has
none, any ``violations``, any case ``errors``, and any non-xfail ``fail``
— a known-bug case (``xfail``) is expected to fail and never blocks; an
``xpass`` unblocks nobody but is reported. Skips (engines that need a live
provider) never block either — they are honest "not measured here".

Improvements always pass; they only enter the baseline when a human runs
``--update-baseline`` and commits the resulting reviewed diff.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from .score import SCORECARD_SCHEMA_VERSION

BASELINE_SCHEMA_VERSION = 1

# Allowed drop per metric (see module docstring — proposed, uncalibrated).
DEFAULT_THRESHOLDS: dict[str, float] = {
    "precision": 0.0,
    "recall": 0.0,
    "recall_critical_high": 0.0,
    "false_positive_rate": 0.0,
}
# Metrics where a *higher* value is worse (allowed rise, not drop).
_INVERTED = ("false_positive_rate",)


def corpus_hash(root: Path | str) -> str:
    """sha256 over every file in the corpus (relative path + bytes).

    Paths are slash-normalized and sorted, so the digest is identical on
    Windows and POSIX checkouts of the same commit (§5.3 reproducibility).
    """
    root = Path(root)
    digest = hashlib.sha256()
    files = [p for p in root.rglob("*")
             if p.is_file() and "__pycache__" not in p.parts]
    for path in sorted(files, key=lambda p: str(p.relative_to(root))
                       .replace("\\", "/")):
        rel = str(path.relative_to(root)).replace("\\", "/")
        digest.update(rel.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def build_baseline(scorecard: dict, corpus_digest: str,
                   thresholds: dict[str, float] | None = None) -> dict:
    """Baseline payload: scorecard + corpus identity + documented limits.

    Deliberately contains no timestamp, hostname or git sha — regenerating
    it on an unchanged corpus yields byte-identical output, so any diff in
    a committed baseline is a real, reviewable score change.
    """
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "corpus_hash": corpus_digest,
        "thresholds": dict(thresholds or DEFAULT_THRESHOLDS),
        "scorecard": scorecard,
    }


def dumps_baseline(baseline: dict) -> str:
    return json.dumps(baseline, sort_keys=True, indent=2,
                      ensure_ascii=True) + "\n"


@dataclass(frozen=True)
class GateResult:
    ok: bool
    failures: tuple[str, ...]


def check_gate(current: dict, baseline: dict,
               corpus_digest: str) -> GateResult:
    """Compare a freshly built baseline payload against the committed one.

    ``current`` is ``build_baseline(...)`` output for this run;
    ``corpus_digest`` is the hash of the corpus this run evaluated.
    Every failure message states what to do (regenerate deliberately, or
    fix the regression).
    """
    failures: list[str] = []

    if current.get("schema_version") != BASELINE_SCHEMA_VERSION:
        failures.append(
            f"current results use format version "
            f"{current.get('schema_version')!r}, gate expects "
            f"{BASELINE_SCHEMA_VERSION}")
    if baseline.get("schema_version") != BASELINE_SCHEMA_VERSION:
        failures.append(
            f"baseline format version {baseline.get('schema_version')!r} != "
            f"{BASELINE_SCHEMA_VERSION} — regenerate the baseline with "
            f"--update-baseline after reviewing the format change")
    if current.get("corpus_hash") != corpus_digest:
        failures.append("internal: current payload does not match the "
                        "corpus that was just evaluated")
    if baseline.get("corpus_hash") != corpus_digest:
        failures.append(
            "corpus changed since the baseline was written (corpus_hash "
            "mismatch): if this edit is intentional, regenerate with "
            "python -m eval.harness --update-baseline and commit the "
            "reviewed diff")

    thresholds = {**DEFAULT_THRESHOLDS, **(baseline.get("thresholds") or {})}
    cur_metrics = (current.get("scorecard") or {}).get("metrics", {})
    base_metrics = (baseline.get("scorecard") or {}).get("metrics", {})

    for metric, allowed in sorted(thresholds.items()):
        base_value = base_metrics.get(metric)
        cur_value = cur_metrics.get(metric)
        if base_value is None:
            continue                      # baseline had no data — nothing to hold
        if cur_value is None:
            failures.append(
                f"{metric}: baseline has {base_value} but this run has no "
                f"data (missing inputs are a regression, not a free pass)")
            continue
        if metric in _INVERTED:
            if cur_value > base_value + allowed + 1e-12:
                failures.append(
                    f"{metric} rose {base_value} -> {cur_value} "
                    f"(allowed rise {allowed})")
        elif cur_value < base_value - allowed - 1e-12:
            failures.append(
                f"{metric} regressed {base_value} -> {cur_value} "
                f"(allowed drop {allowed})")

    cur_counts = (current.get("scorecard") or {}).get("counts", {})
    for key, message in (
        ("violations", "must_not_report / no_findings violations"),
        ("errors", "cases that errored"),
        ("failed", "cases failing expectations"),
    ):
        if cur_counts.get(key, 0) > 0:
            failures.append(
                f"{key}={cur_counts[key]}: {message} (see per-case "
                f"output above)")

    return GateResult(ok=not failures, failures=tuple(failures))
