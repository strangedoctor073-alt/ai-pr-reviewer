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
                                     fingerprint_finding, mark_dismissed,
                                     occurrence_key)
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


# ---------------------------------------------------------------------------
# V4-E05-T04 · layered-identity continuity (ADR-005)
#
# v1 fingerprints are the storage/lifecycle/mute/comment key forever; the
# occurrence key is additive. These tests pin the continuity guarantees:
# the v1 formula is frozen, the occurrence key is churn-tolerant, and every
# v1 consumer keeps working across a cross-engine merge.
# ---------------------------------------------------------------------------

def _v4_finding(file="app/payments.py", line=10, title="Possible SQL injection in 'users' table",
                category="security", severity="high"):
    return Finding(file=file, line=line, title=title, category=category,
                   severity=severity)


def test_v1_fingerprint_formula_is_frozen():
    """The v1 hash inputs are an identity-affecting contract (ADR-005):
    changing them orphans every stored row, mute and comment binding."""
    assert fingerprint_finding(_v4_finding()) == "0dc303916d0ea3ea"


def test_v1_fingerprint_survives_line_churn():
    """'line 42 moved to line 48' must hash identically."""
    a = _v4_finding(line=42)
    b = _v4_finding(line=48)
    assert fingerprint_finding(a) == fingerprint_finding(b)


def test_occurrence_key_is_line_tolerant_and_quote_tolerant():
    """The occurrence key abstracts literals and ignores lines, so two
    engines' renderings of one issue share a key while their v1
    fingerprints legitimately differ (the C4 gap it exists to close)."""
    a = _v4_finding(title="Possible SQL injection in 'users' table")
    b = _v4_finding(title='Possible SQL injection in "users" table', line=99)
    assert fingerprint_finding(a) != fingerprint_finding(b)
    assert occurrence_key(a) == occurrence_key(b) != ""


def test_occurrence_key_differs_for_different_issues():
    a = _v4_finding(title="Possible SQL injection in 'users' table")
    b = _v4_finding(title="Possible SQL injection in 'orders' table")
    # Same file + same symbol; the gist still separates the targets.
    assert occurrence_key(a) != occurrence_key(b)


def test_merged_finding_keeps_full_lifecycle_continuity():
    """E05-T04: after a cross-engine merge, the survivor's v1 fingerprint
    drives lifecycle, mutes and resolution exactly as before."""
    from ai_pr_reviewer.models import ProvenanceSource

    ai = _v4_finding()
    ai.provenance_engine, ai.provenance_origin = "claude", "ai"
    ai.provenance_sources = (ProvenanceSource(
        engine="claude", model="m1", origin="ai"),)
    static = _v4_finding(title='Possible SQL injection in "users" table')
    static.provenance_engine, static.provenance_origin = "static", "static"
    static.provenance_sources = (ProvenanceSource(
        engine="static", model="static-rules-v1", origin="static"),)

    merged = deduplicate([ai, static])
    assert len(merged) == 1
    survivor = merged[0]
    # The survivor's identity is the AI finding's v1 fingerprint; a stored
    # mute row keyed by it still applies, and lifecycle still resolves it.
    fp = fingerprint_finding(survivor)
    assert fp == fingerprint_finding(ai)
    muted = mark_dismissed([survivor], {fp})
    assert muted[0].state == "muted"
    prev = [Finding.from_dict({**survivor.to_dict(), "state": "resolved"})]
    reopened = apply_lifecycle(prev, [survivor])
    assert {f.state for f in reopened} == {"reopened"}


def test_merged_finding_carries_both_attributions_into_report_rows():
    """The merge trail is auditable in the serialized report row."""
    from ai_pr_reviewer.models import ProvenanceSource

    a = _v4_finding()
    a.provenance_sources = (ProvenanceSource(engine="claude", model="m1",
                                             origin="ai"),)
    b = _v4_finding(title='Possible SQL injection in "users" table')
    b.provenance_sources = (ProvenanceSource(engine="static",
                                             model="static-rules-v1",
                                             origin="static"),)
    row = deduplicate([a, b])[0].to_dict()
    assert {s["engine"] for s in row["provenance_sources"]} == {"claude", "static"}
    assert row["merged_fingerprints"] == [fingerprint_finding(b)]


# ---------------------------------------------------------------------------
# V4-E05 hardening (audit of the as-built occurrence-key pass)
#
# Two defects found when the shipped T02/T03 were probed with realistic
# provider output; both are pinned here so they cannot return:
#   1. the cross-engine merge let INPUT ORDER decide which rendering won, and
#      the pipeline calls deduplicate() on raw provider output (providers are
#      not trusted to arrive sorted -- defect D5), so a critical rendering
#      could be swallowed by a medium one that merely came first;
#   2. a sentence-final period split the occurrence key ("... key" vs
#      "... key."), i.e. the most trivial cross-engine formatting difference.
# ---------------------------------------------------------------------------

def test_cross_engine_merge_never_downgrades_severity_whatever_the_input_order():
    medium = _v4_finding(severity="medium")
    critical = _v4_finding(title='Possible SQL injection in "users" table',
                           severity="critical")
    assert fingerprint_finding(medium) != fingerprint_finding(critical)

    for order in ([medium, critical], [critical, medium]):
        out = deduplicate(list(order))
        assert len(out) == 1
        assert out[0].severity == "critical"
        # the survivor's storage key is the critical rendering's v1 fingerprint
        assert fingerprint_finding(out[0]) == fingerprint_finding(critical)
        assert fingerprint_finding(medium) in out[0].merged_fingerprints


def test_equal_severity_cross_engine_merge_still_keeps_first_in_input_order():
    """Documented tie-break is unchanged: equal severity -> first wins."""
    a = _v4_finding(severity="high")
    b = _v4_finding(title='Possible SQL injection in "users" table',
                    severity="high")
    assert fingerprint_finding(deduplicate([a, b])[0]) == fingerprint_finding(a)
    assert fingerprint_finding(deduplicate([b, a])[0]) == fingerprint_finding(b)


def test_dedup_keeps_input_order_of_survivors_and_unanchored_findings():
    """Winner selection is by severity but the returned list stays in input
    order of the *surviving* renderings (nothing is re-sorted)."""
    plain = _v4_finding(title="The logic looks wrong here", severity="low")
    med = _v4_finding(severity="medium")
    other = _v4_finding(file="app/other.py", title="Weak hash md5() used",
                        severity="high")
    crit = _v4_finding(title='Possible SQL injection in "users" table',
                       severity="critical")
    out = deduplicate([plain, med, other, crit])
    # `crit` outranks `med` (same occurrence key) so `med` is merged away;
    # survivors appear in the input order of the renderings that survived.
    assert [f.title for f in out] == [plain.title, other.title, crit.title]
    assert fingerprint_finding(med) in out[2].merged_fingerprints


def test_unknown_severity_ranks_like_medium_in_the_merge():
    """models.from_dict coerces unknown severities to 'medium'; a hand-built
    Finding with a junk severity must neither crash nor mis-rank: it outranks
    'low' (it is treated as medium) and loses to 'high'."""
    junk = _v4_finding(severity="bogus")
    low = _v4_finding(title='Possible SQL injection in "users" table',
                      severity="low")
    high = _v4_finding(title='Possible SQL injection in "users" table',
                       severity="high")
    for order in ([junk, low], [low, junk]):
        out = deduplicate(list(order))
        assert len(out) == 1 and out[0].severity == "bogus"
    for order in ([junk, high], [high, junk]):
        out = deduplicate(list(order))
        assert len(out) == 1 and out[0].severity == "high"


def test_occurrence_key_ignores_edge_punctuation_but_keeps_dotted_names():
    a = _v4_finding(title="Hardcoded API key in config_loader")
    b = _v4_finding(title="Hardcoded API key in config_loader.")
    c = _v4_finding(title="Hardcoded API key in config_loader...")
    assert fingerprint_finding(a) != fingerprint_finding(b)      # v1 unchanged
    assert occurrence_key(a) == occurrence_key(b) == occurrence_key(c) != ""

    # interior dots are part of a name and still discriminate
    d = _v4_finding(title="Use of os.system() on user input")
    e = _v4_finding(title="Use of os_system() on user input")
    assert occurrence_key(d) != occurrence_key(e)
