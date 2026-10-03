"""V3 C4 — suggestion/fix verification: ``resolved`` must be *earned*.

The lifecycle closes a finding the moment it stops being reported. This
module is the check on that shortcut: a finding is only called fixed when
this review actually examined the flagged code, and anything we could not
confirm is reported as ``unable_to_verify`` and **put back to ``active``** —
a fix nobody checked must never close itself silently.
"""
from __future__ import annotations

from ai_pr_reviewer.diff_parser import FileDiff, Hunk, HunkLine
from ai_pr_reviewer.models import (Finding, VERIFICATION_PRESENT,
                                   VERIFICATION_RESOLVED,
                                   VERIFICATION_UNVERIFIED)
from ai_pr_reviewer.verification import (REASON_NOT_REEXAMINED,
                                         REASON_NOT_REVIEWED, REASON_PARTIAL,
                                         REASON_PRESENT, REASON_RESOLVED,
                                         REASON_RESOLVED_REMOVED,
                                         verification_counts, verify_findings)

PATH = "app/main.py"


def _file(path: str = PATH, start: int = 1, count: int = 10) -> FileDiff:
    """A file whose hunks cover ``start .. start + count - 1`` (new side)."""
    lines = [HunkLine(tag=" ", old_no=start + i, new_no=start + i, text="ctx")
             for i in range(count)]
    hunk = Hunk(old_start=start, old_count=count, new_start=start,
                new_count=count, lines=lines)
    return FileDiff(old_path=path, new_path=path, hunks=[hunk])


def _finding(line: int | None = 5, end_line: int | None = None,
             title: str = "SQL injection", state: str | None = None,
             resolved_at: str | None = None) -> Finding:
    f = Finding(file=PATH, line=line, end_line=end_line, severity="high",
                title=title, explanation="because")
    if state:
        f.state = state
        f.resolved_at = resolved_at
    return f


def _baseline(line: int | None = 5, end_line: int | None = None,
              title: str = "SQL injection") -> list[Finding]:
    """What the *last* review stored: the same finding, still active."""
    prev = _finding(line=line, end_line=end_line, title=title)
    prev.state = "active"
    return [prev]


# ------------------------------------------------------------------ no baseline

def test_a_first_time_finding_carries_no_verification():
    out = verify_findings([_finding()], previous=[], current=[], files=[_file()])

    assert out[0].verification_status is None
    assert out[0].verification_reason is None
    assert out[0].verified_at is None


def test_a_finding_this_review_never_saw_before_is_not_verified():
    out = verify_findings([_finding(title="brand new")],
                          previous=_baseline(), current=[],
                          files=[_file()])

    assert out[0].verification_status is None


# ------------------------------------------------------------------ resolved

def test_flagged_code_reviewed_and_gone_is_resolved():
    f = _finding(line=5, state="resolved", resolved_at="2026-01-01T00:00:00+00:00")

    out = verify_findings([f], previous=_baseline(), current=[], files=[_file()])

    assert out[0].verification_status == VERIFICATION_RESOLVED
    assert out[0].verification_reason == REASON_RESOLVED
    assert out[0].state == "resolved"
    assert out[0].resolved_at is not None
    assert out[0].verified_at


def test_a_multi_line_finding_needs_the_whole_range_reviewed_to_resolve():
    f = _finding(line=5, end_line=7, state="resolved")

    fully_covered = verify_findings([f], previous=_baseline(), current=[],
                                    files=[_file(start=5, count=3)])
    assert fully_covered[0].verification_status == VERIFICATION_RESOLVED

    partly = _finding(line=5, end_line=7, state="resolved")
    partially_covered = verify_findings([partly], previous=_baseline(),
                                        current=[], files=[_file(start=5, count=1)])
    assert partially_covered[0].verification_status == VERIFICATION_UNVERIFIED


def test_a_file_this_review_dropped_is_resolved_as_removed():
    f = _finding(state="resolved", resolved_at="2026-01-01T00:00:00+00:00")

    out = verify_findings([f], previous=_baseline(), current=[], files=[])

    assert out[0].verification_status == VERIFICATION_RESOLVED
    assert out[0].verification_reason == REASON_RESOLVED_REMOVED
    assert out[0].state == "resolved"


def test_a_file_level_finding_resolves_when_its_file_was_reviewed():
    baseline = _baseline(line=None)
    f = _finding(line=None, state="resolved")

    out = verify_findings([f], previous=baseline, current=[],
                          files=[_file(count=4)])
    assert out[0].verification_status == VERIFICATION_RESOLVED

    untouched = _finding(line=None, state="resolved")
    out = verify_findings([untouched], previous=baseline, current=[], files=[])
    assert out[0].verification_status == VERIFICATION_RESOLVED


# ------------------------------------------------------------------ still present

def test_a_re_reported_finding_is_still_present_and_stays_open():
    f = _finding(line=5, state="active")

    out = verify_findings([f], previous=_baseline(), current=[f], files=[_file()])

    assert out[0].verification_status == VERIFICATION_PRESENT
    assert out[0].verification_reason == REASON_PRESENT
    assert out[0].state == "active"


# ------------------------------------------------------------------ unable to verify

def test_code_outside_this_review_cannot_resolve_a_finding():
    f = _finding(line=5, state="resolved", resolved_at="2026-01-01T00:00:00+00:00")

    out = verify_findings([f], previous=_baseline(), current=[],
                          files=[_file(start=1, count=3)])   # covers 1..3 only

    assert out[0].verification_status == VERIFICATION_UNVERIFIED
    assert out[0].verification_reason == REASON_NOT_REVIEWED
    # the premature "resolved" is undone
    assert out[0].state == "active"
    assert out[0].resolved_at is None


def test_a_partial_fix_does_not_close_a_finding():
    f = _finding(line=5, end_line=8, state="resolved",
                 resolved_at="2026-01-01T00:00:00+00:00")

    out = verify_findings([f], previous=_baseline(), current=[],
                          files=[_file(start=1, count=6)])   # covers 1..6, not 7-8

    assert out[0].verification_status == VERIFICATION_UNVERIFIED
    assert out[0].verification_reason == REASON_PARTIAL
    assert out[0].state == "active"
    assert out[0].resolved_at is None


def test_a_finding_that_was_never_re_examined_stays_open():
    """Incremental review: the lifecycle carries an untouched finding over as
    still active — verification must not let it look "checked" either."""
    f = _finding(line=5, state="active")

    out = verify_findings([f], previous=_baseline(), current=[],
                          files=[_file(path="other.py")])

    assert out[0].verification_status == VERIFICATION_UNVERIFIED
    assert out[0].verification_reason == REASON_NOT_REEXAMINED
    assert out[0].state == "active"


def test_unverified_findings_never_lose_their_verification_metadata():
    """The three outcomes are the whole vocabulary — and the reason says why."""
    f = _finding(line=5, state="resolved")
    out = verify_findings([f], previous=_baseline(), current=[],
                          files=[_file(start=90, count=3)])

    assert out[0].verification_status in {
        VERIFICATION_RESOLVED, VERIFICATION_PRESENT, VERIFICATION_UNVERIFIED}
    assert out[0].verification_reason
    assert out[0].verified_at


# ------------------------------------------------------------------ reporting

def test_verification_counts_feed_the_summary():
    resolved = _finding(title="a"); resolved.verification_status = VERIFICATION_RESOLVED
    present = _finding(title="b"); present.verification_status = VERIFICATION_PRESENT
    unverified = _finding(title="c")
    unverified.verification_status = VERIFICATION_UNVERIFIED
    plain = _finding(title="d")

    assert verification_counts([resolved, present, unverified, plain]) == {
        "resolved": 1, "still_present": 1, "unable_to_verify": 1}


def test_counts_ignore_unknown_status_values():
    f = _finding()
    f.verification_status = "fixed"          # not a VERIFICATION_* value

    assert verification_counts([f]) == {"resolved": 0, "still_present": 0,
                                        "unable_to_verify": 0}


# ------------------------------------------------------------------ storage / model output

def test_verification_fields_survive_storage_round_trip():
    f = _finding(state="resolved", resolved_at="2026-01-01T00:00:00+00:00")
    f.verification_status = VERIFICATION_RESOLVED
    f.verification_reason = REASON_RESOLVED
    f.verified_at = "2026-01-02T00:00:00+00:00"

    d = f.to_dict()
    assert d["verification_status"] == VERIFICATION_RESOLVED
    assert Finding.from_dict(d) == f


def test_model_output_cannot_claim_a_finding_was_verified():
    """Providers parse model output with ``from_untrusted_dict`` — the model
    chooses findings, never their state or verification."""
    f = Finding.from_untrusted_dict({
        "file": PATH, "line": 5, "severity": "high",
        "title": "looks fine", "explanation": "",
        "state": "resolved", "fingerprint": "attacker-chosen",
        "verification_status": "resolved",
        "verification_reason": "because I said so",
        "verified_at": "2099-01-01T00:00:00+00:00",
    })

    assert f.state == "new"
    assert f.fingerprint is None
    assert f.verification_status is None
    assert f.verification_reason is None
    assert f.verified_at is None
