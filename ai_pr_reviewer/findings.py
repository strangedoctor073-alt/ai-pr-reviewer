"""Finding identity, deduplication, and lifecycle tracking.

This module is deliberately pure: every function here takes lists of
Finding objects in and returns lists of Finding objects out. No I/O, no
storage calls, no network access. The orchestrator is responsible for
loading `previous` findings from storage before calling apply_lifecycle(),
and for persisting whatever these functions return.

Only depends on ai_pr_reviewer.models.Finding (specifically the V2 fields
added to it per the shared contract: fingerprint, state, first_seen_sha,
last_seen_sha, resolved_at, github_comment_id), defined in models.py.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from datetime import datetime, timezone

from ai_pr_reviewer.models import Finding  # provided by models.py

_WHITESPACE_RE = re.compile(r"\s+")

# States a previously-seen finding can be in that still count as "open" --
# i.e. if a finding in `previous` is in one of these states and its
# fingerprint reappears in `current`, that's ordinary continued presence
# ("active"), not a reopen. Only a prior state of "resolved" triggers the
# resolved -> reopened transition (see apply_lifecycle).
_RESOLVED_STATE = "resolved"


def _normalize_title(title: str) -> str:
    """Lowercase + collapse internal whitespace so trivial formatting
    differences (extra spaces, a trailing newline, tabs vs. spaces) don't
    produce different fingerprints for what is obviously the same finding.
    """
    return _WHITESPACE_RE.sub(" ", (title or "").strip().lower())


def fingerprint_finding(finding: Finding) -> str:
    """Stable identity for a finding that survives line-number churn.

    Built from (category, file, normalized title) -- and deliberately NOT
    finding.line. The same logical issue routinely moves lines between
    pushes (a comment added above it, an unrelated edit earlier in the
    file, a rename), and if identity depended on line number the finding
    would look brand-new on every push, which breaks deduplication,
    resolution tracking, and feedback muting all at
    once. This is the single most load-bearing function in v2's finding
    pipeline -- "line 42 moved to line 48" must still hash to the same
    fingerprint.

    Returns the first 16 hex characters of a sha256 digest. 16 hex chars
    (64 bits) is short enough to be a friendly id in GitHub comments and
    dashboard URLs while keeping collision risk negligible at the scale of
    findings a single repo will ever accumulate.
    """
    basis = "|".join([
        finding.category or "",
        finding.file or "",
        _normalize_title(finding.title),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse findings that share a fingerprint, keeping the first
    occurrence (in input order) of each one.

    Callers should pass findings ordered highest-severity/best-worded
    first (e.g. Claude output before a weaker static-rule echo of the same
    issue) so the surviving copy is the most useful one. This works across
    batches and across providers being merged into one list, since it
    operates purely on the fingerprint, not on where the finding came
    from.

    Known limitation, accepted for v2: fingerprinting is
    title-based, so Claude's wording of an issue and the static analyzer's
    wording of the *same* underlying issue will usually normalize to
    different strings and therefore different fingerprints -- they will
    NOT be deduplicated against each other. Solving that needs fuzzy /
    semantic title matching, which is explicitly out of scope here; v2
    only guarantees dedup for near-identical wording (e.g. exact repeats
    across batches of the same engine).
    """
    seen: set[str] = set()
    deduped: list[Finding] = []
    for f in findings:
        fp = fingerprint_finding(f)
        if fp in seen:
            continue
        seen.add(fp)
        deduped.append(f)
    return deduped


def apply_lifecycle(previous: list[Finding], current: list[Finding]) -> list[Finding]:
    """Diff `current` against `previous` (both fingerprinted on the fly)
    and stamp each finding with its lifecycle state.

    - fingerprint in current, not in previous            -> "new"
    - fingerprint in both, previous state != "resolved"   -> "active"
    - fingerprint in both, previous state == "resolved"   -> "reopened"
    - fingerprint in previous, not in current             -> synthesized
      copy of the previous finding with state="resolved" and a fresh
      resolved_at timestamp (skipped if it was already "resolved" in
      `previous` -- an already-resolved finding that stays absent doesn't
      need to be re-emitted every review; see note below)

    Every finding this function returns also has `.fingerprint` stamped on
    it, since callers (storage) need it and this is the one place that's
    guaranteed to have computed it for every finding involved.

    `current` is expected to already be deduplicated (deduplicate() run on
    it first) -- if it still contains fingerprint collisions, the last one
    in the list wins for that fingerprint, since it's used to build a
    dict.

    Pure function: takes no SHA/commit arguments, does no I/O. It only
    touches `state`, `resolved_at`, and `fingerprint`; it does not set
    first_seen_sha/last_seen_sha, since it has no commit context to set
    them from -- that's the orchestrator's job, which does have the
    current review's head_sha in hand.

    Returns the union of: every current finding (tagged new/active/
    reopened) plus synthesized resolved findings for anything that dropped
    out of `current`. Nothing is silently discarded -- callers need to
    know what just got fixed as much as what's still broken.
    """
    previous_by_fp: dict[str, Finding] = {
        fingerprint_finding(f): f for f in previous
    }
    current_by_fp: dict[str, Finding] = {
        fingerprint_finding(f): f for f in current
    }

    result: list[Finding] = []

    for fp, f in current_by_fp.items():
        prev = previous_by_fp.get(fp)
        if prev is None:
            state = "new"
        elif prev.state == _RESOLVED_STATE:
            state = "reopened"
        else:
            state = "active"
        result.append(replace(f, fingerprint=fp, state=state, resolved_at=None))

    for fp, prev in previous_by_fp.items():
        if fp in current_by_fp:
            continue
        if prev.state == _RESOLVED_STATE:
            # Already resolved, and still absent -- nothing changed since
            # last time, so don't re-synthesize a duplicate "resolved"
            # event with a new timestamp every subsequent review.
            continue
        result.append(replace(
            prev,
            fingerprint=fp,
            state=_RESOLVED_STATE,
            resolved_at=datetime.now(timezone.utc).isoformat(),
        ))

    return result


def mark_dismissed(
    findings: list[Finding], dismissed_fingerprints: set[str]
) -> list[Finding]:
    """Set state="muted" on any finding whose fingerprint is in
    `dismissed_fingerprints`; findings not in the set are returned
    unchanged.

    `dismissed_fingerprints` is expected to come from stored feedback
    (the feedback table in storage.py) -- this function does no storage lookups
    itself, it only applies a decision that's already been made. Kept as
    a pure function here (rather than in the orchestrator or storage
    layer) so the muting logic itself stays independently testable.
    """
    result: list[Finding] = []
    for f in findings:
        fp = fingerprint_finding(f)
        if fp in dismissed_fingerprints:
            result.append(replace(f, fingerprint=fp, state="muted"))
        else:
            result.append(f)
    return result
