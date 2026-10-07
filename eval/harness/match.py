"""V3-E03-T02 — expected-label ↔ finding matching (one-to-one, greedy).

The implemented definition of "a corpus finding *matches* an expected
label" (TESTING_EVALUATION_PLAN.md §4). A label and a finding match iff
**all** of:

1. **file**     — equal after ``\\``→``/`` normalization (case-sensitive;
   case-folding would make ``README`` and ``readme`` the same path, which
   they are not on every platform this engine runs on);
2. **line**     — a label *without* ``line_hint`` matches any line
   (file-level expectation, e.g. a line-less test-gap finding); a label
   *with* ``line_hint`` requires the finding's line within ``tolerance``
   — and a line-less finding (``line: None``) can never satisfy a
   line-scoped label, so a trap scoped to one line is not tripped by a
   file-level note;
3. **category** — a label without ``category`` matches any; else equality;
4. **severity** — a label without ``severity_min`` matches any; else the
   finding's rank must be **>=** the label's (``severity_min`` is a floor,
   not an exact severity);
5. **title**    — a label without ``title_match`` matches any; else a
   case-insensitive regex *search* against the finding title. The pattern
   is compiled at load time (``loader`` validates it) and only ever used
   with :func:`re.search` — corpus data never executes as code.

**Assignment is one-to-one.** Candidate pairs are ordered by
(line distance, label index, finding index) and assigned greedily: one
finding can never satisfy two labels — a duplicated finding must not
inflate recall — and the outcome is independent of dict/set iteration
order (reproducibility rule §5.3).

:func:`violation_hits` reuses the same predicate for the trap/benign
lists (``must_not_report`` / ``no_findings``): every hit is a violation,
with no one-to-one constraint — a trap must fire regardless of how many
findings land on it.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ai_pr_reviewer.models import SEVERITY_ORDER

from .loader import Label


def _norm(path: str | None) -> str:
    return (path or "").replace("\\", "/")


def matches(label: Label, finding: dict) -> bool:
    """Does ``finding`` satisfy ``label``? (pure — no allocation side
    effects, total order, no I/O.)"""
    if _norm(label.file) != _norm(finding.get("file")):
        return False
    # line
    if label.line_hint is not None:
        line = finding.get("line")
        if line is None:
            return False
        if abs(int(line) - label.line_hint) > label.tolerance:
            return False
    # category
    if label.category is not None and label.category != finding.get("category"):
        return False
    # severity floor
    if label.severity_min is not None:
        actual = SEVERITY_ORDER.get(finding.get("severity"), -1)
        floor = SEVERITY_ORDER.get(label.severity_min, 99)
        if actual < floor:
            return False
    # title regex (validated at load time; re.search only)
    if label.title_match is not None:
        if not re.search(label.title_match, str(finding.get("title") or ""),
                         re.I):
            return False
    return True


def _distance(label: Label, finding: dict) -> int:
    """Greedy preference: exact line before within-tolerance, everything
    else (file-level labels) before nothing."""
    if label.line_hint is None or finding.get("line") is None:
        return 0
    return abs(int(finding["line"]) - label.line_hint)


@dataclass(frozen=True)
class MatchResult:
    matched: tuple[tuple[int, int, int], ...]   # (label idx, finding idx, dist)
    unmatched_labels: tuple[int, ...]
    unmatched_findings: tuple[int, ...]


def match_labels(labels: tuple[Label, ...],
                 findings: list[dict]) -> MatchResult:
    """One-to-one greedy assignment (see module docstring)."""
    candidates: list[tuple[int, int, int]] = []
    for li, label in enumerate(labels):
        for fi, finding in enumerate(findings):
            if matches(label, finding):
                candidates.append((_distance(label, finding), li, fi))
    # Stable, explicit ordering: distance first, then corpus-declared order.
    candidates.sort(key=lambda c: (c[0], c[1], c[2]))

    used_labels: set[int] = set()
    used_findings: set[int] = set()
    matched: list[tuple[int, int, int]] = []
    for dist, li, fi in candidates:
        if li in used_labels or fi in used_findings:
            continue
        used_labels.add(li)
        used_findings.add(fi)
        matched.append((li, fi, dist))

    return MatchResult(
        matched=tuple(matched),
        unmatched_labels=tuple(i for i in range(len(labels))
                               if i not in used_labels),
        unmatched_findings=tuple(i for i in range(len(findings))
                                 if i not in used_findings),
    )


def violation_hits(trap_labels: tuple[Label, ...],
                   visible_findings: list[dict]) -> tuple[tuple[int, int], ...]:
    """All (trap index, finding index) hits — every hit is a violation."""
    hits: list[tuple[int, int]] = []
    for ti, trap in enumerate(trap_labels):
        for fi, finding in enumerate(visible_findings):
            if matches(trap, finding):
                hits.append((ti, fi))
    return tuple(hits)
