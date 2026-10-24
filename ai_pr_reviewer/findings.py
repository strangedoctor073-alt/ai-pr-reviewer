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

from ai_pr_reviewer.models import (  # provided by models.py
    MAX_EVIDENCE_PER_FINDING,
    MAX_PROVENANCE_SOURCES,
    SEVERITY_ORDER,
    Finding,
    ProvenanceSource,
)

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

    V4-E05 (ADR-005): this v1 fingerprint remains the storage, lifecycle,
    mute and GitHub-comment key indefinitely -- the layered occurrence key
    below never replaces it. The hash inputs are frozen; changing them is
    an identity-affecting decision requiring a new ADR.
    """
    basis = "|".join([
        finding.category or "",
        finding.file or "",
        _normalize_title(finding.title),
    ])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# V4-E05 · layered identity (ADR-005, approved 2026-10-07)
#
# v1 (fingerprint_finding) stays the storage, lifecycle, mute and comment
# key forever -- nothing here changes it. The occurrence key is a second,
# *advisory* identity used only for cross-engine dedup/merge decisions.
# It is computed, never persisted as an authority, and never a storage key.
#
# Occurrence-key formula (ADR-005): normalized_path + symbol + semantic
# gist of the title, line-tolerant.
#
# Worked examples (same issue, different engines/wordings => same key):
#   static: "Possible SQL injection in 'users' table"   @ db/queries.py
#   ai:     'Possible SQL injection in "users" table'   @ db/queries.py
#   -> v1 fingerprints DIFFER (quote characters survive v1 normalization),
#      but the occurrence key strips quote style (keeping the literal) and
#      anchors on the code-like token "SQL": identical keys => merged.
#   static: "Hardcoded API key in config_loader"  / ai: "Hardcoded API key in
#   config_loader." -> same key (edge punctuation is formatting, not gist).
#   Different issues (different file, symbol or gist) => different keys:
#   "…in 'users' table" vs "…in 'orders' table" keep distinct gists.
#
# Failure modes (deliberate, documented):
#   * No code-like symbol in the title => occurrence key degrades to ""
#     and cross-engine merging is *refused* (v1-only dedup). A conservative
#     miss beats a wrong merge: v1 identity is never destabilized.
#   * Re-wording that changes the gist (not just phrasing) will not merge.
#     That is the documented C4 limitation surface, honest by construction:
#     we never claim fuzzy/semantic matching (principle: deterministic).
#   * Which rendering survives a cross-engine merge: the highest-severity
#     one, ties broken by input order (so a critical rendering can never be
#     swallowed by a medium one merely because the provider listed it
#     second -- providers are NOT trusted to arrive sorted, defect D5).
#     A run-to-run engine switch can still change which v1 fingerprint
#     survives -- identical to today's single-engine behavior (each engine
#     has its own v1 fingerprints anyway). The key is NOT consulted across
#     runs: apply_lifecycle/mutes stay v1-only (ADR-005 decision 4).
#
# Rollback to v1 (ADR-005 · V4-E05-T01, specified here as behavior, not
# implemented as a switch): the occurrence key is pure derivation —
# nothing persists it and no storage, lifecycle, mute or comment path
# reads it, so rolling back means exactly "stop consulting
# occurrence_key() in the cross-engine merge path". No migration, no
# stored-state rewrite, no backfill and no identity change: v1
# fingerprints are byte-identical before and after, already-merged
# findings keep their v1 keys, and live runs simply lose cross-engine
# merge dedup (back to conservative v1-only dedup). Reports already
# written are immutable history and need no rewrite. The reverse
# direction (v1 → layered) is likewise migration-free for the same
# reason: nothing in v1 ever depended on the second key.
# ---------------------------------------------------------------------------

_IDENTIFIER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER_RE = re.compile(r"\b\d+\b")
# A "code-like" token: snake_case, contains '_', or followed by '(' in the
# original title -- cheap, deterministic heuristics for "this word names a
# program entity" without a word list or a model.
_CODEISH_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*(?:_[A-Za-z0-9_]+)+"   # snake_case
    r"|[A-Za-z_][A-Za-z0-9_]*\()"                    # call-like
)


def _normalize_path(path: str) -> str:
    """Path normalization for identity: separators only. Case is preserved
    (POSIX paths are case-sensitive) and no basename munging -- the same
    file must hash the same on every platform."""
    return (path or "").replace("\\", "/").strip()


def _title_gist(title: str) -> str:
    """Semantic gist of a title: quote-style and numbers normalized away.

    Quote *characters* are stripped while the literal content is kept:
    engines describing one issue may quote it differently ("in 'users'
    table" vs 'in "users" table') and must share a gist -- but two
    genuinely different targets ("users" vs "orders") must NOT merge.
    Standalone numbers collapse to ``<n>`` because incidental counts and
    line references differ across engines ("at line 40" vs "at line 42").
    """
    t = _NUMBER_RE.sub("<n>", title or "")
    t = t.lower()
    t = re.sub(r"[^a-z0-9_<>.]+", " ", t)
    # '.' survives inside a token (``os.system``, ``config.py``) but not at
    # its edges: a sentence-final period or an ellipsis is formatting, and
    # engines disagree on it ("Hardcoded API key" vs "Hardcoded API key.").
    return " ".join(tok for tok in (w.strip(".") for w in t.split()) if tok)


def _title_symbol(title: str) -> str:
    """Best-effort code-like symbol anchor from a title ("" when none).

    Deterministic, no word list, no model: snake_case or call-like tokens
    win first; otherwise the first token with an *internal* capital or
    digit (SQL, API, findById, md5) reads as a program entity. A
    sentence-initial capitalized word ("The logic ...") deliberately does
    NOT qualify -- ordinary English must never anchor a merge.
    """
    m = _CODEISH_RE.search(title or "")
    if m:
        return m.group(1).rstrip("(").lower()
    for tok in _IDENTIFIER_RE.findall(title or ""):
        if any(c.isdigit() for c in tok[1:]) or any(c.isupper() for c in tok[1:]):
            return tok.lower()
    return ""


def occurrence_key(finding: Finding) -> str:
    """Advisory cross-engine identity (V4-E05, ADR-005) -- 16 hex chars.

    Layered on top of :func:`fingerprint_finding`: v1 stays the storage,
    lifecycle, mute and comment key; this key is used *only* by dedup to
    merge two engines' renderings of one issue. Returns ``""`` when no
    symbol anchor exists (see the failure-mode note above) -- callers must
    treat "" as "no cross-engine identity", never as a merge group.
    """
    symbol = _title_symbol(finding.title)
    gist = _title_gist(finding.title)
    if not symbol:
        return ""
    basis = "|".join([_normalize_path(finding.file), symbol, gist])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _provenance_sources(f: Finding) -> list[ProvenanceSource]:
    """The effective provenance list of a finding: the explicit list when
    present, else a single source synthesized from the scalar fields."""
    if f.provenance_sources:
        return list(f.provenance_sources)
    if f.provenance_engine or f.provenance_model or f.provenance_origin:
        return [ProvenanceSource(
            engine=f.provenance_engine, model=f.provenance_model,
            origin=f.provenance_origin, agent=f.provenance_agent)]
    return []


def _merge_duplicate(winner: Finding, loser: Finding,
                     merged_fp: str | None = None) -> Finding:
    """Fold ``loser`` into ``winner`` (V4-E04-T03 + V4-E05-T03).

    Keeps the winner's identity and content untouched; merges what dedup
    used to destroy: attribution (provenance sources, de-duplicated by
    engine/model/origin/agent) and evidence records (de-duplicated by
    kind+locator, bounded). When the merge crosses v1 fingerprints (the
    cross-engine case), the loser's fingerprint is recorded on the winner
    so the merge is auditable, never silent. Bounded on every list.
    """
    merged = winner
    # --- attribution (fixes C3: "dedup destroys attribution") ---
    sources = _provenance_sources(winner)
    seen = {s.key() for s in sources}
    for s in _provenance_sources(loser):
        if s.key() not in seen:
            sources.append(s)
            seen.add(s.key())
    # --- evidence ---
    ev = list(winner.evidence)
    ev_keys = {(e.kind, e.locator) for e in ev}
    for e in loser.evidence:
        if (e.kind, e.locator) not in ev_keys:
            ev.append(e)
            ev_keys.add((e.kind, e.locator))
    # --- merge trail ---
    trail = list(winner.merged_fingerprints)
    for fp in ((merged_fp,) if merged_fp else ()) + loser.merged_fingerprints:
        if fp and fp != fingerprint_finding(winner) and fp not in trail:
            trail.append(fp)
    return replace(
        merged,
        provenance_sources=tuple(sources[:MAX_PROVENANCE_SOURCES]),
        evidence=tuple(ev[:MAX_EVIDENCE_PER_FINDING]),
        merged_fingerprints=tuple(trail[:16]),
    )


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate findings, keeping the first occurrence (in input
    order) of each one, and merging what duplicates carry (V4-E04-T03).

    Two passes, both deterministic:

    1. **v1 fingerprint pass** (unchanged identity): findings sharing a
       ``fingerprint_finding`` collapse to the first occurrence; the loser's
       provenance sources and evidence are merged into the winner instead of
       being destroyed (C3 fix).
    2. **occurrence-key pass** (V4-E05-T03, new): two findings with
       *different* v1 fingerprints but the *same* :func:`occurrence_key`
       are the same issue seen by two engines (C4 gap); the highest-severity
       rendering wins (ties: first in input order), its v1 fingerprint
       remains the storage/comment/mute key, and the loser's fingerprint is
       recorded in ``merged_fingerprints``. Findings with no symbol anchor
       (occurrence key ``""``) are never merged here -- a conservative miss
       beats a wrong merge. The returned order is still the input order of
       the surviving renderings.

    Pass 1 keeps its historical first-wins rule, so callers should still
    pass findings ordered highest-severity first (the pipeline sorts only
    *after* dedup). Pass 2 does not depend on that ordering: a critical
    rendering is never hidden behind a medium one that happened to come
    first. Nothing else about identity changes: ``fingerprint_finding`` is
    byte-for-byte the v1 formula, and every v1 consumer (lifecycle, mutes,
    comment sync) is untouched.
    """
    order: list[str] = []
    by_fp: dict[str, Finding] = {}
    for f in findings:
        fp = fingerprint_finding(f)
        if fp in by_fp:
            by_fp[fp] = _merge_duplicate(by_fp[fp], f)
        else:
            by_fp[fp] = f
            order.append(fp)

    # Pass 2: cross-engine occurrence merge. Visit candidates highest
    # severity first (stable: ties keep input order) so the survivor of a
    # merge is deterministic and never the less severe rendering; remember
    # each survivor's input position so the output order is unchanged.
    position = {fp: i for i, fp in enumerate(order)}
    medium = SEVERITY_ORDER["medium"]    # unknown severity ranks like medium
    ranked = sorted(
        order, key=lambda p: -SEVERITY_ORDER.get(by_fp[p].severity, medium))
    survivors: dict[int, Finding] = {}
    by_occ: dict[str, int] = {}
    for fp in ranked:
        f = by_fp[fp]
        occ = occurrence_key(f)
        if not occ:
            survivors[position[fp]] = f
        elif occ in by_occ:
            idx = by_occ[occ]
            survivors[idx] = _merge_duplicate(survivors[idx], f, merged_fp=fp)
        else:
            by_occ[occ] = position[fp]
            survivors[position[fp]] = f
    return [survivors[i] for i in sorted(survivors)]


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
    touches `state`, `resolved_at`, `fingerprint` and carries the
    ``github_comment_id`` forward (the GitHub comment a previous review
    posted for this fingerprint, so the next review can update it instead
    of opening a duplicate); it does not set first_seen_sha/last_seen_sha,
    since it has no commit context to set them from -- that's the
    orchestrator's job, which does have the current review's head_sha in
    hand.

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
        # The comment id is ours, not the model's (model output is parsed
        # with from_untrusted_dict), so reusing it here is safe and keeps a
        # stable internal-finding <-> GitHub-comment mapping across reviews.
        result.append(replace(
            f, fingerprint=fp, state=state, resolved_at=None,
            github_comment_id=(f.github_comment_id
                               or (prev.github_comment_id if prev else None)),
        ))

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

    A finding that is already "resolved" is left alone even when its
    fingerprint is dismissed: "fixed" and "muted" are different facts,
    and letting a stale mute entry rewrite history would make an absent
    problem look like one somebody silenced (and would flip the state
    back and forth between runs).
    """
    result: list[Finding] = []
    for f in findings:
        fp = fingerprint_finding(f)
        if fp in dismissed_fingerprints and f.state != _RESOLVED_STATE:
            result.append(replace(f, fingerprint=fp, state="muted"))
        else:
            result.append(f)
    return result
