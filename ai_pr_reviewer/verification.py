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
from typing import TYPE_CHECKING

from .diff_parser import FileDiff
from .findings import fingerprint_finding
from .models import (Finding, VERIFICATION_PRESENT, VERIFICATION_RESOLVED,
                     VERIFICATION_TIER_T0, VERIFICATION_TIER_T1,
                     VERIFICATION_TIER_T2, VERIFICATION_TIERS,
                     VERIFICATION_UNVERIFIED)

if TYPE_CHECKING:
    from .static.registry import RuleRegistry

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


# ------------------------------------------------- tier handlers (E05-T02/T03)

def static_recheck_confirms(finding: Finding, fd: FileDiff | None,
                            *, registry: RuleRegistry | None = None) -> bool:
    """T1: does the line rule that produced ``finding`` still match this
    file's hunks? ``True`` means the pattern is gone.

    Bounded re-check over the diff this review already has in memory —
    no file read, no process, no network (the E05 exit scan pins that):

    * **only line rules** carry a pattern, so a file-rule (``AST*``) or
      diff-rule (``TEST001``) finding honestly never confirms (``False``);
    * **added *and* context lines are scanned**, unlike the engine (added
      only): a pattern sitting in a context line is still in the file —
      without this, a committed-but-unfixed flagged line would read as
      "gone" and false-confirm the resolution;
    * **removed lines are never scanned** — they are the pre-fix content;
      matching them is the fix, not a counter-example;
    * **comment lines are skipped with the engine's own predicate**, so a
      commented-out pattern counts as gone exactly when the engine would
      stop firing on it;
    * the engine's **language filter is mirrored**: a rule that could
      never fire for this file cannot speak to it.

    Absent evidence returns ``False`` — escalation may only move up on
    positive confirmation, never on silence.
    """
    if fd is None or fd.is_binary or not finding.rule_id:
        return False
    if fd.path != finding.file:
        # Caller mix-up guard: confirming this file against another file's
        # clean hunks would attribute someone else's diff to the finding.
        # (Production looks the FileDiff up by ``finding.file`` — this only
        # ever fires for a hand-assembled call.)
        return False
    # Lazy: verification stays import-cheap for callers that never
    # escalate, and the static stack pulls in the whole rule corpus.
    from .static.engine import _COMMENT_LINE_RE, build_default_registry
    from .static.registry import lang_of

    if registry is None:
        registry = build_default_registry()
    rule = next((r for r in registry.line_rules
                 if r.rule_id == finding.rule_id), None)
    if rule is None:
        return False
    if rule.languages and lang_of(fd.path) not in rule.languages:
        return False
    for hunk in fd.hunks:
        for hl in hunk.lines:
            if hl.tag == "-":
                continue                       # pre-fix content, expected to match
            if _COMMENT_LINE_RE.match(hl.text):
                continue                       # the engine skips these too
            if rule.pattern.search(hl.text):
                return False                   # pattern still present in hunks
    return True


def observed_test_evidence_confirms(finding: Finding) -> bool:
    """T2: does *observed* test evidence pass over this finding's file?

    The consumed test-evidence adapter (E05-T03): read-only over records
    the pipeline already holds in ``Finding.evidence`` — never an
    execution, never a fetch.

    * ADR-012: only **observed** ``tev1`` records count (origins
      ``ci_ingest``/``test_report``). Static mappings are display-only, a
      model's "tests pass" claim is not a record at all, and a tampered
      record fails its integrity check — all three yield nothing.
    * a passing record must **name this file in ``covers``** — attribution
      is explicit, never stem-guessed; an unrelated or absent pass
      confirms nothing.
    * ``failed``/``errored``/``skipped`` never confirm — and, deliberately,
      never downgrade anything either: tiers escalate attribution, the
      three-state machine stays the coverage floor's alone.
    """
    if not finding.file:
        return False
    # Lazy: a review that never escalates never imports the taxonomy module.
    from .test_intel import observed_test_evidence

    for ev in observed_test_evidence(finding.evidence):
        if ev.outcome == "passed" and finding.file in ev.covers:
            return True
    return False


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
    # V4.2-E05-T02: the static re-check tier handler.
    "static_recheck_confirms",
    # V4.2-E05-T03: the consumed test-evidence adapter (ADR-012).
    "observed_test_evidence_confirms",
]
