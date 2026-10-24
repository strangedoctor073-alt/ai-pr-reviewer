"""V4-E09-T07 — feedback effectiveness evaluation (descriptive, read-only).

Implements metric #11 of ``TESTING_EVALUATION_PLAN.md`` §8: the
*repeat false-positive rate of adjudicated findings before vs after
suppression rules*. A finding is **adjudicated** when a human voted it
``down`` (false positive). A **repeat** is a later review in which the same
fingerprint is observed again.

Pure function over plain rows — no I/O, no clock, no storage, nothing it
returns can change engine behavior. Per the plan it makes **no automatic
success claim**: the result carries ``claim: "none"`` and a ``state`` of
``no_data`` whenever there is nothing to measure (no votes, no rules, or no
review observed after a rule existed — which is exactly what a repository
with ``feedback.enabled=false`` looks like, and it is stated as such).

Inputs (all scoped to ONE repository by the caller):

* ``events``       — ``feedback_events`` rows;
* ``rules``        — ``suppression_rules`` rows, *including* inactive ones
  (a rule's window is ``[created_at, min(expires_at, disabled_at))``);
* ``observations`` — stored finding rows (``Storage.list_findings``) with
  ``fingerprint``, ``state``, ``reviewed_at``, ``file``, ``rule_id``.
"""
from __future__ import annotations

from datetime import datetime
from typing import Iterable

from . import storage_schema as S
from .feedback import SuppressionRule
from .models import Finding

_CLOSED = frozenset({"resolved", "dismissed", "muted"})

METRIC_NOTE = ("Descriptive only: counts of repeat appearances of down-voted "
               "findings, split by whether a human-created rule was in force "
               "at the time. No success claim is made. A 'muted' state while "
               "a covering rule was in force is attributed to the rule; it "
               "cannot be told apart from a V3 mute of the same finding.")


def _windows(rules: Iterable[dict], repo: str):
    """``[(SuppressionRule, start, end)]`` for every structurally valid rule
    of ``repo``, whether or not it is still in force today."""
    out = []
    for row in rules:
        if not isinstance(row, dict):
            continue
        parsed = SuppressionRule.from_row({**row, "disabled_at": ""}, repo)
        start = S.parse_feedback_iso(row.get("created_at"))
        end = S.parse_feedback_iso(row.get("expires_at"))
        off = S.parse_feedback_iso(row.get("disabled_at"))
        if parsed is None or start is None or end is None:
            continue
        if off is not None and off < end:
            end = off
        out.append((parsed, start, end))
    return out


def evaluate_effectiveness(repo: str, events: list[dict], rules: list[dict],
                           observations: list[dict]) -> dict:
    """Compute the before/after repeat-FP counts for ``repo``."""
    events = [e for e in events if isinstance(e, dict) and e.get("repo") == repo]
    rules = [r for r in rules if isinstance(r, dict) and r.get("repo") == repo]

    voted: dict[str, datetime] = {}
    for e in events:
        if e.get("kind") != "down":
            continue
        at = S.parse_feedback_iso(e.get("created_at"))
        fp = e.get("fingerprint")
        if at is not None and isinstance(fp, str) \
                and (fp not in voted or at < voted[fp]):
            voted[fp] = at

    windows = _windows(rules, repo)
    result = {
        "repo": repo,
        "claim": "none",
        "note": METRIC_NOTE,
        "adjudicated_fingerprints": len(voted),
        "rules_total": len(windows),
        "repeat_posted_before_rule": 0,
        "posted_after_rule": 0,
        "suppressed_after_rule": 0,
        "leak_rate_after_rule": None,
        "repeats_before_rule_per_fingerprint": None,
        "state": "no_data",
        "reason": "",
    }
    if not voted:
        result["reason"] = "no adjudicated (down-voted) findings"
        return result

    before = posted = suppressed = 0
    for obs in observations:
        if not isinstance(obs, dict):
            continue
        fp = obs.get("fingerprint")
        seen = S.parse_feedback_iso(obs.get("reviewed_at"))
        if fp not in voted or seen is None or seen <= voted[fp]:
            continue
        state = str(obs.get("state") or "new")
        finding = Finding(file=str(obs.get("file") or ""), line=None,
                          rule_id=obs.get("rule_id"))
        covered = any(start <= seen < end and rule.matches(finding, fp)
                      for rule, start, end in windows)
        if covered:
            if state == "muted":
                suppressed += 1
            elif state not in _CLOSED:
                posted += 1
        elif state not in _CLOSED:
            before += 1

    result.update(
        repeat_posted_before_rule=before, posted_after_rule=posted,
        suppressed_after_rule=suppressed,
        repeats_before_rule_per_fingerprint=round(before / len(voted), 3))
    if not windows:
        result["reason"] = "no suppression rules have been created"
    elif posted + suppressed == 0:
        result["reason"] = ("no review was observed while a rule was in "
                            "force (feedback may be disabled)")
    else:
        result["state"] = "observed"
        result["leak_rate_after_rule"] = round(
            posted / (posted + suppressed), 3)
    return result
