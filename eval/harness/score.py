"""V3-E03-T02 — metrics: definitions, per-case verdicts, scorecard.

METRIC DEFINITIONS — this module is the authoritative, executable version
(``TESTING_EVALUATION_PLAN.md`` §4 points here; "documented alongside
code" per V3-E03-T02):

``precision``
    = matched **posted-bucket** labels / posted findings, micro-averaged
    over the scored corpus. A "posted" finding is a report finding at/above
    the severity threshold (§4: "findings the engine posted"). **Null when
    nothing was posted** — no data beats a fabricated 0 or 1.

``recall``
    = satisfied expected labels / all expected labels, where a label is
    *satisfied in the bucket it is declared in*: ``bucket: reported``
    against posted findings, ``bucket: below_threshold`` against the
    retained below-threshold findings (the D3 contract — those findings
    are part of the report). Null when the scored corpus declares no
    labels.

``false_positive_rate``
    = unmatched posted findings / posted findings. This is the project's
    FP definition from §4 ("posted findings adjudicated wrong / findings
    actually posted"); the classic specificity-based FPR needs a
    true-negative population a diff corpus cannot define, so no classic
    FPR is ever reported under this name. Null when nothing was posted.

``recall_critical_high``
    = satisfied labels that declare ``severity_min`` **high** or
    **critical** / all such labels. Labels that declare no severity floor
    cannot be classified into this guard and are excluded from it. This is
    the blocking guard the CI gate uses (T03). Null when no such label
    exists.

Rules that keep the numbers honest:

* **Zero-input ratios are null**, never ``0.0``/``1.0`` invented from an
  empty denominator; counts sit next to every ratio so the denominator is
  always visible.
* **Errored / skipped cases contribute nothing to the metrics** — their
  run did not produce trustworthy inputs (they stay visible as statuses
  and in ``counts``). Metrics over an empty scored subset are all null.
* **``xfail`` (known-bug) cases are outside the metrics too** — their
  unsatisfied labels are the open defect, not a regression: they stay
  visible in ``counts["xfail"]`` and in their per-case entry, and become
  measured (as ``xpass``) the moment the bug is fixed.
* **Violations** (``must_not_report`` / ``no_findings`` hits) are listed
  per case with file/line/reason; any violation fails the case outright —
  traps are absolute contracts, not partial credit.
* **Verdicts**: ``pass`` (no failures) · ``fail`` (unmatched label,
  violation, state or report-order assertion failed) · ``error`` /
  ``skipped`` (run-level) · ``xfail`` (known-bug case failing as
  expected — visible, non-blocking, §5.4) · ``xpass`` (an xfail case that
  now passes — visible prompt to drop the marker, non-blocking).

Everything is a pure function of (corpus labels, run results): no clocks,
no environment, no dict-iteration order — two consecutive runs serialize
byte-identically (§5.3).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .loader import Case
from .match import match_labels, violation_hits
from .runner import CaseRun

SCORECARD_SCHEMA_VERSION = 1

_GUARD_FLOORS = ("high", "critical")

_EMPTY_COUNTS = (
    "cases", "passed", "failed", "errors", "skipped", "xfail", "xpass",
    "violations", "labels_total", "labels_matched",
    "findings_posted", "findings_below",
)


@dataclass
class CaseScore:
    case_id: str
    layer: str
    status: str                     # pass|fail|error|skipped|xfail|xpass
    labels: int = 0                 # declared expected findings
    matched_labels: int = 0         # satisfied (in their declared bucket)
    posted: int = 0                 # posted-bucket findings
    below: int = 0                  # below-threshold bucket findings
    true_positives: int = 0         # matched posted-bucket labels
    false_positives: int = 0        # unmatched posted findings
    violations: list[dict] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def scored(self) -> bool:
        """Does this case feed the corpus metrics?"""
        return self.status in ("pass", "fail", "xpass")


def _label_desc(label) -> str:
    parts = [f"{label.file}:{label.line_hint}"]
    if label.severity_min:
        parts.append(f">={label.severity_min}")
    if label.category:
        parts.append(label.category)
    if label.title_match:
        parts.append(f"title~/{label.title_match}/")
    if label.bucket != "reported":
        parts.append(f"bucket={label.bucket}")
    return " ".join(parts)


def score_case(case: Case, run: CaseRun) -> CaseScore:
    """Evaluate one case's expectations against its raw run result."""
    cs = CaseScore(case_id=case.id, layer=case.layer, status="pass")

    if run.run_status == "error":
        cs.status = "error"
        cs.failures.append(f"run error: {run.error}")
        return cs
    if run.run_status == "skipped":
        cs.status = "skipped"
        return cs

    cs.posted = len(run.findings)
    cs.below = len(run.below)

    if case.expect.config_error:
        # The clean string-SystemExit path is the only "ran" outcome.
        return cs

    posted_labels = tuple(l for l in case.expect.findings
                          if l.bucket == "reported")
    below_labels = tuple(l for l in case.expect.findings
                         if l.bucket == "below_threshold")
    cs.labels = len(case.expect.findings)

    posted_match = match_labels(posted_labels, run.findings)
    below_match = match_labels(below_labels, run.below)

    cs.true_positives = len(posted_match.matched)
    cs.matched_labels = len(posted_match.matched) + len(below_match.matched)
    cs.false_positives = len(posted_match.unmatched_findings)

    for li in posted_match.unmatched_labels:
        cs.failures.append(
            f"unmatched expected finding: {_label_desc(posted_labels[li])}")
    for li in below_match.unmatched_labels:
        cs.failures.append(
            f"unmatched expected finding: {_label_desc(below_labels[li])}")

    # state assertions on matched labels
    for pool_labels, pool_findings, match in (
        (posted_labels, run.findings, posted_match),
        (below_labels, run.below, below_match),
    ):
        for li, fi, _dist in match.matched:
            expected_state = pool_labels[li].state
            if expected_state is None:
                continue
            actual = pool_findings[fi].get("state")
            if actual != expected_state:
                cs.failures.append(
                    f"state assertion failed: "
                    f"{pool_labels[li].file}:{pool_labels[li].line_hint} "
                    f"expected state={expected_state}, got {actual}")

    # traps: evaluated against everything the report shows (posted + below)
    visible = run.findings + run.below
    for kind, traps in (("must_not_report", case.expect.must_not_report),
                        ("no_findings", case.expect.no_findings)):
        for ti, fi in violation_hits(traps, visible):
            trap = traps[ti]
            hit = visible[fi]
            where = (f"{hit['file']}:{hit['line']}" if hit["line"] is not None
                     else str(hit["file"]))
            reason = f" — {trap.reason.strip()}" if trap.reason else ""
            cs.violations.append(
                {"kind": kind, "file": hit["file"], "line": hit["line"],
                 "finding_title": hit["title"],
                 "reason": (trap.reason or "").strip()})
            cs.failures.append(f"{kind} violated at {where}: "
                               f"finding {hit['title']!r}{reason}")

    # report order (D5): the declared file sequence must appear in order
    if case.expect.report_order:
        wanted = list(case.expect.report_order)
        seen = [f["file"] for f in run.findings if f["file"] in set(wanted)]
        if seen != wanted:
            cs.failures.append(
                f"report order mismatch: expected {wanted}, got {seen}")

    if cs.failures and case.xfail:
        cs.status = "xfail"
    elif cs.failures:
        cs.status = "fail"
    elif case.xfail:
        cs.status = "xpass"
    return cs


@dataclass
class Scorecard:
    cases: list[CaseScore]
    precision: float | None
    recall: float | None
    false_positive_rate: float | None
    recall_critical_high: float | None
    counts: dict[str, int]


def _ratio(num: int, den: int) -> float | None:
    return num / den if den else None


def score_corpus(cases: tuple[Case, ...],
                 runs: list[CaseRun]) -> Scorecard:
    scores = [score_case(case, run) for case, run in zip(cases, runs)]

    scored = [s for s in scores if s.scored]
    tp = sum(s.true_positives for s in scored)
    posted = sum(s.posted for s in scored)
    fp = sum(s.false_positives for s in scored)
    labels = sum(s.labels for s in scored)
    matched = sum(s.matched_labels for s in scored)

    guard_total = guard_matched = 0
    for case, score, run in zip(cases, scores, runs):
        if not score.scored:
            continue
        for bucket, pool in (("reported", run.findings),
                             ("below_threshold", run.below)):
            guard_labels = tuple(l for l in case.expect.findings
                                 if l.severity_min in _GUARD_FLOORS
                                 and l.bucket == bucket)
            if not guard_labels:
                continue
            guard_total += len(guard_labels)
            guard_matched += len(match_labels(guard_labels, pool).matched)

    counts = {key: 0 for key in _EMPTY_COUNTS}
    counts["cases"] = len(scores)
    for s in scores:
        counts["violations"] += len(s.violations)
    counts["passed"] = sum(1 for s in scores if s.status == "pass")
    counts["failed"] = sum(1 for s in scores if s.status == "fail")
    counts["errors"] = sum(1 for s in scores if s.status == "error")
    counts["skipped"] = sum(1 for s in scores if s.status == "skipped")
    counts["xfail"] = sum(1 for s in scores if s.status == "xfail")
    counts["xpass"] = sum(1 for s in scores if s.status == "xpass")
    counts["labels_total"] = labels
    counts["labels_matched"] = matched
    counts["findings_posted"] = posted
    counts["findings_below"] = sum(s.below for s in scored)

    return Scorecard(
        cases=scores,
        precision=_ratio(tp, posted),
        recall=_ratio(matched, labels),
        false_positive_rate=_ratio(fp, posted),
        recall_critical_high=_ratio(guard_matched, guard_total),
        counts=counts,
    )


# ------------------------------------------------------------- serialization
def scorecard_to_dict(card: Scorecard) -> dict:
    """Fixed-shape, JSON-safe projection (stable key set → diffable,
    byte-stable under ``sort_keys``)."""
    return {
        "schema_version": SCORECARD_SCHEMA_VERSION,
        "metrics": {
            "precision": card.precision,
            "recall": card.recall,
            "false_positive_rate": card.false_positive_rate,
            "recall_critical_high": card.recall_critical_high,
        },
        "counts": dict(sorted(card.counts.items())),
        "cases": [
            {
                "id": s.case_id,
                "layer": s.layer,
                "status": s.status,
                "labels": s.labels,
                "matched_labels": s.matched_labels,
                "posted": s.posted,
                "below": s.below,
                "true_positives": s.true_positives,
                "false_positives": s.false_positives,
                "violations": list(s.violations),
                "failures": list(s.failures),
            }
            for s in card.cases
        ],
    }


def dumps_scorecard(card: Scorecard) -> str:
    """Canonical serialization: sorted keys, fixed separators, newline at
    EOF — byte-identical for identical inputs (§5.3)."""
    return json.dumps(scorecard_to_dict(card), sort_keys=True,
                      indent=2, ensure_ascii=True) + "\n"
