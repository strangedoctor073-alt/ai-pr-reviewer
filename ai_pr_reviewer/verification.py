"""Suggestion/fix verification for findings (V3 C4).

Once a finding has been reported, the next reviews can answer a better
question than "is it still in the diff?" — *did the developer actually fix
it?* This module compares, per finding:

* the **original finding** (its fingerprint + stored previous state),
* the **changed code** (which lines of the flagged range this review
  actually examined),
* and the **current PR state** (whether the reviewer re-reported it).

and produces one of three results — never a fourth:

``resolved``
    the flagged code was part of this review and the issue was not
    reported again (or the file left the change entirely).
``still_present``
    the reviewer reports it again.
``unable_to_verify``
    we have no evidence either way — including the *partial* fix case,
    which is deliberately never a resolution. **This never becomes
    "resolved"**: the lifecycle's automatic "not seen again ⇒ resolved" is
    corrected back to ``active`` so an unverified finding cannot quietly
    close itself.

Deliberate limits (all of them security/product decisions):

* purely deterministic — no model call, no repository download. The only
  inputs are findings and the diff already in memory, so verification can
  never become an unbounded API or token cost.
* it never modifies code, never applies a suggested patch and never
  executes anything: a suggestion is untrusted model output, and the only
  thing this module may do with it is mention that one existed.
* ``fingerprint_finding`` identity comes from ``findings.py``, so the
  comparison is stable across pushes (line numbers move, the fingerprint
  does not).

Verification tiers (V4.2-E05 — C2 naming: T0/T1/T2)
---------------------------------------------------

The three-state result above records *what* verification concluded; the
tier records *what evidence it concluded from* — additive attribution,
never a fourth state:

``t0`` (coverage floor)
    the diff-coverage check this module has always run; its decisions
    stay bit-identical to pre-tier behavior.
``t1`` (static re-check — handler, E05-T02)
    the deterministic rule that produced the finding matches no
    non-comment hunk line of the file anymore.
``t2`` (observed test evidence — adapter, E05-T03)
    an intact, canonical ``tev1`` record with a *passed* observed
    outcome covers the finding's file (ADR-012: never a model claim,
    never an in-review test execution).

Attribution itself is unconditional (E05-T04 stamps the tier that made
each decision); *escalation* above T0 is opt-in (``VERIFICATION_TIERS``
env, default off) and budgeted (``MAX_TIER_ESCALATIONS``). The tier
lives in ``models.VERIFICATION_TIERS`` — the closed vocabulary — and is
pipeline-owned like every other verification field.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .diff_parser import FileDiff
from .findings import fingerprint_finding
from .models import (Finding, VERIFICATION_PRESENT, VERIFICATION_RESOLVED,
                     VERIFICATION_TIER_T0, VERIFICATION_TIER_T1,
                     VERIFICATION_TIER_T2, VERIFICATION_TIERS,
                     VERIFICATION_UNVERIFIED)

REASON_RESOLVED = "the flagged code was part of this review and was not reported again"
REASON_RESOLVED_REMOVED = "the file is no longer part of the reviewed change"
REASON_PRESENT = "the reviewer still reports this finding"
REASON_NOT_REVIEWED = "the flagged code was not part of this review"
REASON_PARTIAL = "only part of the flagged code was part of this review"
REASON_NOT_REEXAMINED = "the finding was not re-reviewed in this run"

#: Strict tier order — escalation may only ever move up this ladder.
VERIFICATION_TIER_RANK = {tier: rank for rank, tier in enumerate(VERIFICATION_TIERS)}

#: Which evidence kind each tier stands on (report/debug rendering; the
#: semantics C2 pinned — labels, never branch conditions).
TIER_EVIDENCE = {
    VERIFICATION_TIER_T0: "diff-coverage",
    VERIFICATION_TIER_T1: "static-recheck",
    VERIFICATION_TIER_T2: "test-evidence",
}


def stronger_tier(*tiers: str | None) -> str | None:
    """The strongest tier among ``tiers`` (``None`` means "no tier yet").

    Closed vocabulary: a value outside ``models.VERIFICATION_TIERS``
    raises instead of winning silently — a tier is pipeline-owned
    evidence attribution, and tolerating an unknown value here would let
    a caller mint an evidence kind the report then renders as trusted.
    """
    best: str | None = None
    for tier in tiers:
        if tier is None:
            continue
        if tier not in VERIFICATION_TIERS:
            raise ValueError(
                f"unknown verification tier {tier!r}; "
                f"known: {list(VERIFICATION_TIERS)}")
        if best is None or VERIFICATION_TIER_RANK[tier] > VERIFICATION_TIER_RANK[best]:
            best = tier
    return best


def _fp(f: Finding) -> str:
    return f.fingerprint or fingerprint_finding(f)


def _flagged_range(f: Finding) -> range:
    start = f.line if f.line is not None else 0
    end = f.end_line if f.end_line is not None else start
    if end < start:
        end = start
    return range(start, end + 1)


def _coverage(f: Finding, files_by_path: dict[str, FileDiff]) -> str:
    """``"all" | "partial" | "none" | "file-missing"`` — how much of the
    flagged range this review actually contained."""
    fd = files_by_path.get(f.file)
    if fd is None:
        return "file-missing"
    if f.line is None:                      # file-level finding
        return "all" if fd.hunks else "none"
    span = _flagged_range(f)
    reviewed = fd.new_line_numbers()
    hit = sum(1 for n in span if n in reviewed)
    if hit == 0:
        return "none"
    if hit == len(span):
        return "all"
    return "partial"


def verify_findings(findings: list[Finding], previous: list[Finding],
                    current: list[Finding], files: list[FileDiff]) -> list[Finding]:
    """Annotate ``findings`` with verification metadata (in place).

    ``previous``  — what the last review stored (the baseline to compare).
    ``current``   — what this review's pipeline detected (post-dedupe,
                    pre-lifecycle), i.e. the findings still open right now.
    ``files``     — the diffs this run actually reviewed.

    Findings with no previous state are left untouched: there is nothing to
    verify yet, and "not verified" must stay distinguishable from
    "unable to verify".
    """
    if not previous:
        return findings

    prev_fps = {_fp(f) for f in previous}
    cur_fps = {_fp(f) for f in current}
    files_by_path = {f.path: f for f in files}
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for f in findings:
        fp = _fp(f)
        if fp not in prev_fps:
            continue                                   # brand-new finding

        if fp in cur_fps:
            f.verification_status = VERIFICATION_PRESENT
            f.verification_reason = REASON_PRESENT
            f.verified_at = now
            continue

        if f.state == "resolved":
            coverage = _coverage(f, files_by_path)
            if coverage == "file-missing":
                f.verification_status = VERIFICATION_RESOLVED
                f.verification_reason = REASON_RESOLVED_REMOVED
                f.verified_at = now
            elif coverage == "all":
                f.verification_status = VERIFICATION_RESOLVED
                f.verification_reason = REASON_RESOLVED
                f.verified_at = now
            else:
                _unverify(f, REASON_PARTIAL if coverage == "partial"
                          else REASON_NOT_REVIEWED, now)
            continue

        # Seen before, not reported now, and never re-examined this run
        # (an untouched file on an incremental review).
        _unverify(f, REASON_NOT_REEXAMINED, now)

    return findings


def _unverify(f: Finding, reason: str, now: str) -> None:
    """Record ``unable_to_verify`` and undo a premature "resolved".

    The lifecycle closes a finding the moment it stops being reported; when
    we cannot actually prove the fix, the finding goes back to ``active``
    (and loses ``resolved_at``) so it keeps counting against the health
    score until something re-examines it.
    """
    f.verification_status = VERIFICATION_UNVERIFIED
    f.verification_reason = reason
    f.verified_at = now
    if f.state == "resolved":
        f.state = "active"
        f.resolved_at = None


def verification_counts(findings: list[Finding]) -> dict[str, int]:
    """``{resolved, still_present, unable_to_verify}`` for summaries/UI."""
    out = {VERIFICATION_RESOLVED: 0, VERIFICATION_PRESENT: 0,
           VERIFICATION_UNVERIFIED: 0}
    for f in findings:
        status = getattr(f, "verification_status", None)
        if status in out:
            out[status] += 1
    return out


__all__ = [
    "verify_findings", "verification_counts",
    "REASON_RESOLVED", "REASON_RESOLVED_REMOVED", "REASON_PRESENT",
    "REASON_NOT_REVIEWED", "REASON_PARTIAL", "REASON_NOT_REEXAMINED",
    # V4.2-E05-T01: the tier model (constants re-exported from models).
    "VERIFICATION_TIERS", "VERIFICATION_TIER_T0", "VERIFICATION_TIER_T1",
    "VERIFICATION_TIER_T2", "VERIFICATION_TIER_RANK", "TIER_EVIDENCE",
    "stronger_tier",
]
