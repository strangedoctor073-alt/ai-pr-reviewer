"""Tests for findings.py: fingerprinting, deduplication, and lifecycle
tracking.

Standalone by design -- the only external dependency is
ai_pr_reviewer.models.Finding.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.findings import (apply_lifecycle, deduplicate,
                                      fingerprint_finding, mark_dismissed)
from ai_pr_reviewer.models import Finding


def _finding(**overrides) -> Finding:
    """Build a Finding with sane defaults, overridable per test."""
    defaults = dict(
        file="payments.py",
        line=42,
        category="security",
        title="SQL injection via string-formatted query",
        severity="high",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# --------------------------------------------------------------- fingerprint

def test_fingerprint_stable_across_line_number_changes():
    a = _finding(line=42)
    b = _finding(line=48)  # same file/category/title, line shifted by a push
    assert fingerprint_finding(a) == fingerprint_finding(b)


def test_fingerprint_stable_across_trivial_title_formatting():
    a = _finding(title="SQL injection via string-formatted query")
    b = _finding(title="  sql injection   via string-formatted   query  ")
    assert fingerprint_finding(a) == fingerprint_finding(b)


def test_fingerprint_differs_for_different_category():
    a = _finding(category="security")
    b = _finding(category="bug")
    assert fingerprint_finding(a) != fingerprint_finding(b)


def test_fingerprint_differs_for_different_file():
    a = _finding(file="payments.py")
    b = _finding(file="refunds.py")
    assert fingerprint_finding(a) != fingerprint_finding(b)


def test_fingerprint_differs_for_different_title():
    a = _finding(title="SQL injection via string-formatted query")
    b = _finding(title="Missing error handling on refund path")
    assert fingerprint_finding(a) != fingerprint_finding(b)


def test_fingerprint_is_16_hex_chars():
    fp = fingerprint_finding(_finding())
    assert len(fp) == 16
    int(fp, 16)  # raises ValueError if not valid hex


# --------------------------------------------------------------- deduplicate

def test_deduplicate_collapses_three_near_identical_findings_to_one():
    findings = [
        _finding(line=42, confidence="high"),    # kept: first occurrence
        _finding(line=48, confidence="medium"),  # dup: same issue, line shifted
        _finding(line=42, title="  SQL Injection Via String-Formatted Query  "),
    ]
    deduped = deduplicate(findings)
    assert len(deduped) == 1
    assert deduped[0].confidence == "high"  # the first (highest-priority) one survived


def test_deduplicate_keeps_genuinely_distinct_findings():
    findings = [
        _finding(file="payments.py", title="SQL injection"),
        _finding(file="refunds.py", title="SQL injection"),
        _finding(file="payments.py", title="Missing error handling"),
    ]
    deduped = deduplicate(findings)
    assert len(deduped) == 3


def test_deduplicate_does_not_collapse_across_engines_different_wording():
    # Documented limitation: Claude's wording vs. static's wording of the
    # SAME underlying issue won't match -- both survive dedup in v2.
    claude_wording = _finding(title="Possible SQL injection: query built with f-string")
    static_wording = _finding(title="SEC003: raw SQL string interpolation")
    deduped = deduplicate([claude_wording, static_wording])
    assert len(deduped) == 2


# --------------------------------------------------------------- lifecycle
#
# Acceptance criteria calls for one clear test walking through three
# synthetic review rounds so the resolve -> reopen path is explicitly
# proven, rather than three separate tests. Round 1: finding X appears.
# Round 2: X is fixed (gone), Y appears. Round 3: X reappears (regression),
# Y is still present (still active).

def test_lifecycle_three_rounds_new_active_resolved_reopened():
    x = _finding(file="payments.py", title="SQL injection", category="security")
    y = _finding(file="refunds.py", title="Missing error handling", category="bug")

    # --- Round 1: X shows up for the first time. No history yet. ---
    round1 = apply_lifecycle(previous=[], current=[x])
    assert len(round1) == 1
    assert round1[0].state == "new"
    x_fp = round1[0].fingerprint
    assert x_fp == fingerprint_finding(x)

    # --- Round 2: developer fixes X (it's gone from `current`); Y shows up. ---
    round2 = apply_lifecycle(previous=round1, current=[y])
    by_state = {f.state: f for f in round2}
    assert set(by_state) == {"resolved", "new"}
    assert by_state["resolved"].fingerprint == x_fp
    assert by_state["resolved"].resolved_at is not None
    assert by_state["new"].fingerprint == fingerprint_finding(y)

    # --- Round 3: X regresses and comes back; Y is still present (active). ---
    round3 = apply_lifecycle(previous=round2, current=[x, y])
    by_fp = {f.fingerprint: f for f in round3}
    assert len(round3) == 2
    assert by_fp[x_fp].state == "reopened"          # was resolved, is back
    assert by_fp[x_fp].resolved_at is None            # no longer resolved
    assert by_fp[fingerprint_finding(y)].state == "active"  # unchanged, still open


def test_lifecycle_does_not_reemit_finding_already_resolved_and_still_absent():
    x = _finding()
    round1 = apply_lifecycle(previous=[], current=[x])          # new
    round2 = apply_lifecycle(previous=round1, current=[])       # resolved
    assert round2[0].state == "resolved"

    # X stays absent in round 3 too -- should NOT synthesize another
    # "resolved" event with a fresh timestamp.
    round3 = apply_lifecycle(previous=round2, current=[])
    assert round3 == []


def test_lifecycle_pure_no_mutation_of_inputs():
    x = _finding()
    previous = [replace_state(x, "new")]
    current = [x]
    before_state = previous[0].state
    apply_lifecycle(previous=previous, current=current)
    assert previous[0].state == before_state  # input list untouched


def replace_state(finding: Finding, state: str) -> Finding:
    from dataclasses import replace
    return replace(finding, state=state)


# ----------------------------------------------------------- mark_dismissed

def test_mark_dismissed_mutes_only_matching_fingerprints():
    x = _finding(file="payments.py", title="SQL injection")
    y = _finding(file="refunds.py", title="Missing error handling")
    dismissed = {fingerprint_finding(x)}

    result = mark_dismissed([x, y], dismissed)
    by_file = {f.file: f for f in result}

    assert by_file["payments.py"].state == "muted"
    assert by_file["refunds.py"].state == y.state  # untouched


def test_mark_dismissed_empty_set_changes_nothing():
    findings = [_finding(), _finding(file="other.py")]
    result = mark_dismissed(findings, set())
    assert [f.state for f in result] == [f.state for f in findings]


def test_mark_dismissed_never_rewrites_a_resolved_finding():
    """A stale mute entry must not flip "fixed" history to "muted" —
    those are different facts, and the flip would repeat every run."""
    fixed = _finding(file="payments.py", title="SQL injection", state="resolved")
    live = _finding(file="refunds.py", title="Missing error handling", state="active")
    dismissed = {fingerprint_finding(fixed), fingerprint_finding(live)}

    result = mark_dismissed([fixed, live], dismissed)
    by_file = {f.file: f for f in result}

    assert by_file["payments.py"].state == "resolved"   # untouched
    assert by_file["refunds.py"].state == "muted"
