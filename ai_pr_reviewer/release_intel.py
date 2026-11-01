"""V4.6-E03-T01 — configured release/tag ingestion (opt-in, read-only).

Release intelligence for reviews: a repository owner exports release
records (tags from GitHub releases or a tag list) to a JSON file; this
module loads, normalizes and bounds them so later tickets can compute
the diff since the last release (T02), aggregate shipped-change context
(T03) and draft release notes for a human (T04). The platform observes
release state — it never publishes, tags, or rolls back anything
(draft notes are human-triggered only, never emitted by the pipeline).

Read-only contract (V4.6-E03; test-enforced):

* **no network, no writes, no subprocess** — ingestion reads the one
  configured local file and nothing else; there is no outbound path of
  any kind (the GitHub client has no release endpoints and gains none
  here — new egress needs human sign-off this epic does not have);
* **absent configuration is zero surface** — no file, no records, no
  warnings, byte-identical review output;
* **the config is trusted, the data is not** — the file lives in the
  base-revision checkout and its name is containment-checked before any
  byte is read; every extracted field is secret-redacted, control-
  stripped and bounded at ingest. The ``tag`` is an identity field and
  REFUSES to truncate (a cut tag names a different release); free text
  (``body``) truncates at ``MAX_BODY_CHARS`` AFTER redaction so a
  secret is never cut in half;
* **selection-critical fields are fail-closed** — ``draft`` and
  ``prerelease`` must be JSON booleans when present; anything else
  drops the record with a warning (a malformed flag that silently read
  as ``False`` could promote a prerelease to "last shipped");
* **commit shas are validated, never guessed** — only a full 40- or
  64-hex token is kept; anything else records as absent and T02 falls
  back to the published-at basis with a label.

Config file (default ``.ai-pr-reviewer-releases.json`` in the repo
root, override with the plain env var ``RELEASE_SOURCES_FILE``):

    {"releases": [{"tag": "v4.10.0", "name": "4.10.0",
                   "published_at": "2026-10-20T09:00:00Z",
                   "commit_sha": "0123456789abcdef0123456789abcdef01234567",
                   "prerelease": false, "draft": false,
                   "body": "Highlights: …"}]}

File order is preserved and is the tie-breaker later tickets rely on.
"""
from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .index.limits import is_contained
from .models import STATIC_ENGINE_ID, EvidenceRecord, Finding, ProvenanceSource
from .security import redact_secrets

# No history-package import here, not even for typing: the history index
# enters a review through context.py only (test_history_index pins that
# single wiring point). Every ``index`` parameter is duck-typed instead.

DEFAULT_SOURCES_FILE = ".ai-pr-reviewer-releases.json"

# Bounds: a hostile or accidental export can never flood a review, a
# report row or a prompt. Each cap trip is a labeled degradation.
MAX_RELEASES = 50
MAX_SOURCE_FILE_BYTES = 262_144          # 256 KiB per config file
MAX_TAG_CHARS = 200                      # refuse-to-truncate identity
MAX_NAME_CHARS = 200
MAX_BODY_CHARS = 2_000                   # free text: truncate at the bound
MAX_SHA_CHARS = 64
MAX_TIMESTAMP_CHARS = 40
MAX_WARNINGS = 10
MAX_WARNING_CHARS = 300

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)

_CONTROL = {c: " " for c in (*range(0x20), 0x7F, *range(0x80, 0xA0),
                              0x2028, 0x2029)}

log = logging.getLogger(__name__)


def _clean(text: object, limit: int,
           scrub: Callable[[str], str] | None = None) -> str:
    """Redact, strip control characters, collapse to one line, bound."""
    out = redact_secrets(str(text if text is not None else ""))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    return out[:limit].strip()


def _identity(value: object, limit: int,
              scrub: Callable[[str], str] | None = None) -> str | None:
    """Identity field (``tag``): cleaned like ``_clean`` but REFUSING to
    truncate. ``None`` means "over long — drop the record" (a cut tag
    names a different release); ``""`` means absent/empty.
    """
    if value is None:
        return ""
    out = redact_secrets(str(value))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    if len(out) > limit:
        return None
    return out


def _warn(msg: str, warnings: list[str],
          scrub: Callable[[str], str] | None = None) -> None:
    if len(warnings) < MAX_WARNINGS:
        warnings.append(_clean(msg, MAX_WARNING_CHARS, scrub))


def _normalize_ts(value: object) -> str:
    """ISO-8601 text -> normalized UTC ISO text, or ``""``.

    Never raises: an unparseable timestamp is recorded as absent (T02
    then refuses a time-based basis rather than inventing one).
    """
    if not isinstance(value, str) or not value.strip():
        return ""
    text = value.strip()[:MAX_TIMESTAMP_CHARS]
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _strict_bool(value: object) -> bool | None:
    """JSON boolean, else ``None`` (the caller drops the record).

    ``None`` is deliberate fail-closed: this flag decides whether a
    release may become "the last shipped release", so a malformed value
    must never coerce to ``False``.
    """
    return value if isinstance(value, bool) else None


def _normalize_sha(value: object) -> str:
    """Full 40/64-hex sha (lowercased), else ``""`` — never a guess."""
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    return text if _SHA_RE.match(text) else ""


@dataclass(frozen=True)
class ReleaseRecord:
    """One normalized release from the configured export.

    ``tag`` is already redacted, single-line and bounded; ``commit_sha``
    is a validated full sha or ``""``; ``published_at`` is normalized
    UTC ISO or ``""`` (never guessed).
    """

    tag: str
    name: str = ""
    published_at: str = ""            # normalized ISO or ""
    commit_sha: str = ""              # 40/64-hex or ""
    prerelease: bool = False
    draft: bool = False
    body: str = ""                    # redacted, bounded free text
    source: str = ""                  # the config file it came from


def _sources_filename() -> str:
    return (os.environ.get("RELEASE_SOURCES_FILE", "").strip()
            or DEFAULT_SOURCES_FILE)


def _normalize_release(raw: object, *, source: str,
                       scrub: Callable[[str], str] | None
                       ) -> ReleaseRecord | None:
    """One untrusted release object -> a bounded, redacted record.

    Returns ``None`` (drop) for: non-objects, an over-long tag
    (refuse-to-truncate), an empty tag, and malformed selection-critical
    flags. Drops are silent per-record; the caller warns only about
    shapes worth surfacing (a record nobody can name is simply not
    evidence).
    """
    if not isinstance(raw, dict):
        return None
    tag = _identity(raw.get("tag"), MAX_TAG_CHARS, scrub)
    if tag is None or not tag:
        return None
    prerelease = _strict_bool(raw.get("prerelease", False))
    draft = _strict_bool(raw.get("draft", False))
    if prerelease is None or draft is None:
        return None
    return ReleaseRecord(
        tag=tag,
        name=_clean(raw.get("name"), MAX_NAME_CHARS, scrub),
        published_at=_normalize_ts(raw.get("published_at")),
        commit_sha=_normalize_sha(raw.get("commit_sha")),
        prerelease=prerelease,
        draft=draft,
        body=_clean(raw.get("body"), MAX_BODY_CHARS, scrub),
        source=_clean(source, MAX_NAME_CHARS, scrub),
    )


def ingest_releases(repo_root: str, *,
                    scrub: Callable[[str], str] | None = None,
                    filename: str = ""
                    ) -> tuple[tuple[ReleaseRecord, ...], tuple[str, ...]]:
    """Load the configured releases file into normalized records.

    Deterministic order (file order, preserved). Never raises: every
    failure mode degrades to a warning that names the config path but
    never echoes file content.
    """
    warnings: list[str] = []

    def warn(msg: str) -> None:
        _warn(msg, warnings, scrub)

    name = filename or _sources_filename()
    if not is_contained(repo_root, name):
        warn(f"release source path escapes the repository: {name}")
        return (), tuple(warnings)
    path = Path(repo_root) / name
    try:
        if not path.exists():
            return (), ()               # absent config = zero surface
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            warn(f"release source exceeds size cap: {name}")
            return (), tuple(warnings)
        data = json.loads(path.read_text(encoding="utf-8",
                                         errors="replace"))
    except OSError:
        warn(f"release source unreadable: {name}")
        return (), tuple(warnings)
    except ValueError as exc:
        # Type only, never file content: a parse failure cannot echo
        # the file it failed on.
        warn(f"release source is not valid JSON ({type(exc).__name__}): "
             f"{name}")
        return (), tuple(warnings)

    entries = data.get("releases") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        warn(f"release source has no releases list: {name}")
        return (), tuple(warnings)

    records: list[ReleaseRecord] = []
    skipped_flags = 0
    for index, raw in enumerate(entries):
        if index >= MAX_RELEASES:
            warn(f"release cap ({MAX_RELEASES}) reached; remaining "
                 f"releases skipped")
            break
        if not isinstance(raw, dict):
            continue                    # malformed entry: silent skip
        if not isinstance(raw.get("draft", False), bool) \
                or not isinstance(raw.get("prerelease", False), bool):
            # selection-critical flag is malformed: drop + count (a
            # silent False could promote a prerelease to "last shipped")
            if isinstance(raw.get("tag"), str) and raw.get("tag"):
                skipped_flags += 1
            continue
        record = _normalize_release(raw, source=name, scrub=scrub)
        if record is None:
            continue                    # unnamed/over-long: silent drop
        records.append(record)
    if skipped_flags:
        warn(f"{skipped_flags} release(s) skipped (draft/prerelease flag "
             f"is not a boolean)")
    return tuple(records), tuple(warnings)


# ------------------------------------------------------ V4.6-E03-T02
# Diff-since-last-release (bounded, deterministic): WHICH release is
# "last shipped" is decided here by closed rules, and WHAT shipped since
# it is computed over the V4.4-E01 history index — never fetched, never
# guessed. Every degradation is a labeled reason; an absent or
# undegraded-invisible history window can only make the answer smaller
# and say so (``partial``), never larger.

BASIS_COMMIT_SHA = "commit_sha"
BASIS_PUBLISHED_AT = "published_at"
BASIS_NOT_ASSESSABLE = "not_assessable"

MAX_DIFF_COMMITS = 100                # commits listed per release diff
MAX_DIFF_PATHS = 500                  # distinct shipped paths listed
MAX_SCAN_COMMITS = 5_000              # matches the history layer's hard cap


def _epoch(iso: str) -> int | None:
    """Normalized UTC ISO -> epoch seconds, or ``None`` (never guessed)."""
    if not iso:
        return None
    try:
        return int(datetime.fromisoformat(iso).timestamp())
    except ValueError:
        return None


def _norm(path: str) -> str:
    """Shared diff-path normalization (windows separators, ``./``)."""
    return path.replace("\\", "/").removeprefix("./")


def select_last_release(
        releases: Iterable[ReleaseRecord]) -> ReleaseRecord | None:
    """The newest SHIPPED release, or ``None``.

    Closed rules: drafts and prereleases are never eligible; a release
    with no comparable ``published_at`` cannot be ordered and is never
    selected; ties on the timestamp keep the FIRST in file order (the
    ingest order is the deterministic tie-breaker).
    """
    if releases is None:
        return None
    best: ReleaseRecord | None = None
    best_ts: int | None = None
    for record in releases:
        if record.draft or record.prerelease:
            continue
        ts = _epoch(record.published_at)
        if ts is None:
            continue                    # unorderable: never selected
        if best_ts is None or ts > best_ts:
            best, best_ts = record, ts
    return best


@dataclass(frozen=True)
class ReleaseDiff:
    """What the history index can prove shipped since one release.

    ``basis`` names the rule that anchored the comparison (closed set);
    ``commits`` is (sha, subject) newest-first; ``paths`` is the sorted
    union of changed paths, capped. ``commits_total``/``paths_total``
    always state the full counts — the caps only bound what is listed.
    ``partial`` means the history window starts AFTER the release, so
    the listing is provably incomplete (never silently presented as
    everything).
    """

    release_tag: str = ""
    basis: str = BASIS_NOT_ASSESSABLE
    commits: tuple[tuple[str, str], ...] = ()
    paths: tuple[str, ...] = ()
    commits_total: int = 0
    paths_total: int = 0
    truncated: bool = False
    partial: bool = False
    reasons: tuple[str, ...] = ()
    #: Full sha listing per shipped path (newest-first), keyed by the
    #: normalized path. Full shas stay here for computation; every
    #: rendered citation uses the short form (see ``CITED_SHA_CHARS``).
    path_shas: dict[str, tuple[str, ...]] = field(default_factory=dict)


def shipped_changes(release: ReleaseRecord | None, index,
                    *, max_commits: int = MAX_DIFF_COMMITS,
                    max_paths: int = MAX_DIFF_PATHS) -> ReleaseDiff:
    """Commits/paths shipped since ``release`` per the history index.

    Anchor ladder (fail-closed, each step labeled):
    1. ``commit_sha`` — the release's validated sha found in the index;
       everything NEWER (the index is newest-first) shipped after it;
    2. ``published_at`` — commits committed strictly after the release
       timestamp (also the fallback when the sha is outside the window,
       with a reason);
    3. ``not_assessable`` — neither anchor exists: no comparison, no
       numbers, a labeled reason instead.

    ``index`` is duck-typed over the V4.4-E01 ``HistoryIndex`` (state,
    window_start, commits) so tests can pin behavior without the git
    layer.
    """
    if release is None:
        return ReleaseDiff()
    tag = release.tag
    if index is None or not getattr(index, "is_available", False):
        return ReleaseDiff(release_tag=tag, basis=BASIS_NOT_ASSESSABLE,
                           reasons=("history index unavailable",))
    commits = tuple(getattr(index, "commits", ()) or ())
    reasons: list[str] = []
    if len(commits) > MAX_SCAN_COMMITS:
        commits = commits[:MAX_SCAN_COMMITS]
        reasons.append("history commit list exceeds the scan cap; "
                       "older commits were not compared")
    window_start = getattr(index, "window_start", 0) or 0

    basis = BASIS_NOT_ASSESSABLE
    newer: tuple = ()
    partial = False
    if release.commit_sha:
        for position, commit in enumerate(commits):
            if commit.sha == release.commit_sha:
                basis = BASIS_COMMIT_SHA
                newer = commits[:position]
                break
        else:
            reasons.append("release sha is outside the history window; "
                           "using the published timestamp instead")
    if basis != BASIS_COMMIT_SHA:
        epoch = _epoch(release.published_at)
        if epoch is None:
            return ReleaseDiff(release_tag=tag,
                               basis=BASIS_NOT_ASSESSABLE,
                               reasons=tuple(reasons) or (
                                   "release has neither a sha in the "
                                   "history window nor a parseable "
                                   "published timestamp",))
        basis = BASIS_PUBLISHED_AT
        newer = tuple(c for c in commits if c.committed_at > epoch)
        if window_start > epoch:
            # the window cannot see the release itself, so anything
            # between the release and the window edge is missing
            partial = True
            reasons.append("history window starts after the release; "
                           "the listing is provably incomplete")

    shas_by_path: dict[str, tuple[str, ...]] = {}
    for commit in newer:
        for path in (getattr(commit, "paths", ()) or ()):
            key = _norm(path)
            if key:
                # ``newer`` is newest-first, so appending keeps each
                # file's sha list newest-first (the render order)
                shas_by_path[key] = shas_by_path.get(key, ()) + (commit.sha,)
    capped_commits = tuple((c.sha, c.subject) for c in newer[:max_commits])
    capped_paths = tuple(sorted(shas_by_path)[:max_paths])
    return ReleaseDiff(
        release_tag=tag,
        basis=basis,
        commits=capped_commits,
        paths=capped_paths,
        commits_total=len(newer),
        paths_total=len(shas_by_path),
        truncated=len(newer) > max_commits or len(shas_by_path) > max_paths,
        partial=partial,
        reasons=tuple(reasons),
        path_shas=shas_by_path,
    )


# ------------------------------------------------------ V4.6-E03-T03
# Surfacing: the changed files this PR also shipped since the last
# release, as evidence findings plus the additive ``releases`` report
# section, behind the RELEASE_INTEL flag (default OFF, config.py;
# orchestrator hook joins findings before dedup). Wording is pinned to
# shipped HISTORY only: the anchor basis labels the confidence, every
# claim is backed by cited shas, and nothing here predicts or prescribes
# what this change will do (tests pin the forbidden vocabulary).
# Evidence-or-dropped, deterministic diff order, capped listings with
# full totals -- the same honesty rules as the correlation surfacing.

RELEASE_RULE_ID = "RELEASE_INTEL"
MAX_RELEASE_FINDINGS = 5
MAX_CITED_COMMITS = 5            # shas cited per finding / report row
MAX_REPORT_FILES = 25            # intersection rows in the report
MAX_PATH_CHARS = 200
MAX_TITLE_CHARS = 200
MAX_EXPLANATION_CHARS = 900
MAX_EVIDENCE_SUMMARY_CHARS = 400        # mirrors models.MAX_EVIDENCE_SUMMARY_CHARS
# Rendered citations use git's 7-char short form on purpose:
# redact_secrets' high-entropy-hex rule (security.py) erases any 40-64
# hex token as credential-looking, and the redaction chokepoint is
# never weakened for convenience. Full shas stay in
# ``ReleaseDiff.path_shas`` for computation; every rendered citation is
# the short form -- the same convention history/retrieval.py uses.
CITED_SHA_CHARS = 7
RELEASE_CONTRACT = (
    "deterministic aggregation of shipped changes from the configured "
    "release file and the read-only history index: files this change "
    "also modifies were touched after the last shipped release (anchor "
    "basis commit_sha | published_at); shipped-history evidence, never "
    "a claim about this change")

# Anchor strength -> finding confidence (the frozen low|medium|high set).
# A sha position is exact; a timestamp comparison is only as good as the
# release's own published_at. not_assessable yields NO findings at all.
_BASIS_CONFIDENCE = {
    BASIS_COMMIT_SHA: "high",
    BASIS_PUBLISHED_AT: "medium",
}


def _changed_paths(files) -> tuple[str, ...]:
    """Distinct diff paths in review order (first spelling wins)."""
    out: list[str] = []
    seen: set[str] = set()
    for fd in files or ():
        raw = str(getattr(fd, "path", "") or "")
        if not raw:
            continue
        key = _norm(raw)
        if key in seen:
            continue
        seen.add(key)
        out.append(raw)
    return tuple(out)


def release_findings(diff: ReleaseDiff, files, *,
                     scrub: Callable[[str], str] | None = None
                     ) -> tuple[Finding, ...]:
    """Changed files that also shipped since the release, as findings.

    Evidence-or-dropped (mirrors the correlation/incident renderers): a
    finding whose evidence cannot be built under the evidence contract
    is dropped whole, never emitted half-stamped. Deterministic: diff
    order, capped at ``MAX_RELEASE_FINDINGS``. An unassessable diff
    yields nothing -- there is no shipped history to stand on.
    """
    if diff.basis not in _BASIS_CONFIDENCE:
        return ()                    # nothing assessable: nothing to claim
    out: list[Finding] = []
    for raw in _changed_paths(files):
        if len(out) >= MAX_RELEASE_FINDINGS:
            break
        shas = diff.path_shas.get(_norm(raw))
        if not shas:
            continue                # not shipped since the release
        tag = diff.release_tag
        cited = ", ".join(sha[:CITED_SHA_CHARS]
                          for sha in shas[:MAX_CITED_COMMITS])
        try:
            file_ev = EvidenceRecord.create(
                kind="file_excerpt", locator=raw,
                summary=_clean(
                    f"also touched by {len(shas)} commit(s) after release "
                    f"{tag} (anchor: {diff.basis})",
                    MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type="release_intel", scrub=scrub)
            history_ev = EvidenceRecord.create(
                kind="history_event", locator=f"release:{tag}",
                summary=_clean(
                    f"shipped commits touching {raw} after {tag}: {cited}",
                    MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type="release_intel", scrub=scrub)
            ref_ev = EvidenceRecord.create(
                kind="rule_ref", locator=f"rule:{RELEASE_RULE_ID}",
                summary=_clean(RELEASE_CONTRACT,
                               MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type="release_intel", scrub=scrub)
        except ValueError:
            continue                        # evidence-or-dropped
        explanation = (
            f"This change modifies {raw}. Since release {tag}, "
            f"{len(shas)} commit(s) in the history window also touched "
            f"it (anchor: {diff.basis}): {cited}. Shipped history from "
            f"the configured release file and the read-only history "
            f"index -- evidence about the past, not a claim about this "
            f"change.")
        if diff.partial:
            explanation += (
                " The shipped listing is incomplete (see the report's "
                "reasons).")
        finding = Finding(
            file=raw, line=None, severity="info",
            category="maintainability",
            title=_clean(f"File changed since release {tag}: {raw}",
                         MAX_TITLE_CHARS, scrub),
            explanation=_clean(explanation, MAX_EXPLANATION_CHARS, scrub),
            suggestion=None,
            confidence=_BASIS_CONFIDENCE[diff.basis],
            rule_id=RELEASE_RULE_ID,
            evidence=(file_ev, history_ev, ref_ev),
        )
        source = ProvenanceSource(engine=STATIC_ENGINE_ID,
                                  model="release-intel-v1", origin="rule")
        finding.provenance_engine = source.engine
        finding.provenance_model = source.model
        finding.provenance_agent = None
        finding.provenance_origin = source.origin
        finding.provenance_sources = (source,)
        out.append(finding)
    return tuple(out)


def releases_section(release: ReleaseRecord, diff: ReleaseDiff, files, *,
                     scrub: Callable[[str], str] | None = None) -> dict:
    """The additive report block (``releases``): the selected release,
    the honest totals of the shipped diff, and the changed files it
    already touched (capped rows, full ``files_total``).

    Rows and reasons are re-scrubbed here (redact-at-store chokepoint:
    everything a finding or report can surface is scrubbed as well).
    """
    matched = [raw for raw in _changed_paths(files)
               if diff.path_shas.get(_norm(raw))]
    rows: list[dict] = []
    for raw in matched[:MAX_REPORT_FILES]:
        shas = diff.path_shas[_norm(raw)]
        rows.append({
            "path": _clean(raw, MAX_PATH_CHARS, scrub),
            "commits": len(shas),
            "shas": [_clean(sha[:CITED_SHA_CHARS], MAX_SHA_CHARS, scrub)
                     for sha in shas[:MAX_CITED_COMMITS]],
        })
    return {
        "last_release": _clean(release.tag, MAX_TAG_CHARS, scrub),
        "published_at": release.published_at,
        "basis": diff.basis,
        "shipped_commits": diff.commits_total,
        "shipped_paths": diff.paths_total,
        "files_total": len(matched),
        "files": rows,
        "partial": diff.partial,
        "truncated": diff.truncated,
        "reasons": [_clean(reason, MAX_WARNING_CHARS, scrub)
                    for reason in diff.reasons],
    }


@dataclass(frozen=True)
class ReleaseOutcome:
    """Runner result: findings + warnings + the report section.

    ``releases is None`` means "no release comparison happened" (no
    configured records, nothing selectable, or no changed files): the
    orchestrator then leaves the report key off entirely -- features
    absent => unchanged behavior.
    """

    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    releases: dict | None = None


NOOP = ReleaseOutcome()


def run_release_context(*, repo_root: str, files, history=None,
                        scrub: Callable[[str], str] | None = None
                        ) -> ReleaseOutcome:
    """V4.6-E03 entry point (orchestrator hook; RELEASE_INTEL default OFF).

    * no configured records and no warnings -> ``NOOP``;
    * garbage config / nothing selectable -> warnings alone, no section;
    * no changed files -> nothing to aggregate against: no section;
    * history absent -> a labeled section (basis not_assessable) and no
      findings: the report says why the comparison could not run;
    * any crash -> one labeled warning -- the feature never fails a
      review (mirrors the correlation and incident runners).
    """
    try:
        records, warnings = ingest_releases(repo_root, scrub=scrub)
        if not records:
            return NOOP if not warnings else ReleaseOutcome(
                warnings=warnings)
        release = select_last_release(records)
        if release is None:
            # configured, but nothing selectable (drafts/prereleases or
            # unorderable timestamps only): zero surface beyond warnings
            return NOOP if not warnings else ReleaseOutcome(
                warnings=warnings)
        if not _changed_paths(files):
            return ReleaseOutcome(warnings=warnings)
        diff = shipped_changes(release, history)
        return ReleaseOutcome(
            findings=release_findings(diff, files, scrub=scrub),
            warnings=warnings,
            releases=releases_section(release, diff, files, scrub=scrub))
    except Exception as exc:  # noqa: BLE001 -- opt-in feature never fails a review
        log.warning("release intelligence failed: %s", type(exc).__name__)
        return ReleaseOutcome(warnings=(
            f"release intelligence failed ({type(exc).__name__}); skipped",))


# ------------------------------------------------------ V4.6-E03-T04
# Draft release notes: a pure, bounded markdown DRAFT for a human to
# review and publish themselves. HUMAN-TRIGGERED ONLY -- plan §C.4
# non-goal: no changelog auto-publishing. The pipeline has no path to
# this function (the test suite AST-pins that no production module
# references the symbol at all), the function performs no I/O, and the
# artifact labels itself a draft. Commit subjects are quoted as shipped
# history (sanitized at history ingest, re-redacted here per line);
# sha citations use the short form past the redaction chokepoint.

MAX_NOTE_BULLETS = 30            # bullets per section of the draft
MAX_NOTE_CHARS = 4_000           # total draft size (free text: truncates)
MAX_NOTE_LINE_CHARS = 400        # one line, one subject, bounded
TRUNCATION_MARK = "… (truncated)"


def draft_release_note(release: ReleaseRecord, diff: ReleaseDiff, files, *,
                       scrub: Callable[[str], str] | None = None) -> str:
    """Markdown DRAFT release notes for a human to review and publish.

    Pure and bounded: no I/O, deterministic output, every line through
    the redaction chokepoint, sha citations in short form
    (``CITED_SHA_CHARS``). Nothing is interpreted and nothing here is a
    claim about any pending change -- the draft states what shipped.

    The review pipeline never calls this function; a human triggers it
    directly::

        records, _ = ingest_releases(repo_root)
        release = select_last_release(records)
        diff = shipped_changes(release, history_index)
        print(draft_release_note(release, diff, changed_files))
    """

    def line(text: str) -> str:
        out = redact_secrets(str(text))
        if scrub is not None:
            out = scrub(out)
        return " ".join(out.translate(_CONTROL).split())[:MAX_NOTE_LINE_CHARS]

    heading = f"# {release.tag}"
    if release.name and release.name != release.tag:
        heading += f" ({release.name})"
    lines = [
        line(heading),
        line("_Draft for human review — nothing is published "
             "automatically._"),
    ]
    if diff.basis == BASIS_NOT_ASSESSABLE:
        lines.append(line(f"Anchor {diff.basis}: shipped changes since "
                          f"{release.tag} are unknown."))
    else:
        lines.append(line(
            f"Published {release.published_at or 'unknown'} · anchor "
            f"{diff.basis} · {diff.commits_total} commit(s), "
            f"{diff.paths_total} path(s) shipped since {release.tag}."))
        if diff.commits:
            lines.append("")
            lines.append(f"## Shipped commits since {release.tag}")
            shown = diff.commits[:MAX_NOTE_BULLETS]
            for sha, subject in shown:
                lines.append(line(f"- {sha[:CITED_SHA_CHARS]} {subject}"))
            if diff.commits_total > len(shown):
                lines.append(f"- … {diff.commits_total - len(shown)} "
                             f"further commit(s) not listed")
        matched = [raw for raw in _changed_paths(files)
                   if diff.path_shas.get(_norm(raw))]
        if matched:
            lines.append("")
            lines.append(f"## Files in this review already shipped since "
                         f"{release.tag} ({len(matched)})")
            for raw in matched[:MAX_NOTE_BULLETS]:
                shas = diff.path_shas[_norm(raw)]
                cited = ", ".join(sha[:CITED_SHA_CHARS]
                                  for sha in shas[:MAX_CITED_COMMITS])
                lines.append(line(
                    f"- {raw} — {len(shas)} shipped commit(s): {cited}"))
            if len(matched) > MAX_NOTE_BULLETS:
                lines.append(f"- … {len(matched) - MAX_NOTE_BULLETS} "
                             f"more file(s) not listed")
    caveats = list(diff.reasons)
    if diff.truncated:
        caveats.append("the commit and path listings are capped; the "
                       "totals above are complete")
    if caveats:
        lines.append("")
        lines.append("## Caveats")
        for caveat in caveats:
            lines.append(line(f"- {caveat}"))
    text = "\n".join(lines)
    if len(text) > MAX_NOTE_CHARS:
        # free text truncates at a LINE boundary so no sha or path is
        # ever cut in half; the marker says the draft is incomplete
        kept: list[str] = []
        size = 0
        for entry in lines:
            if size + len(entry) + 1 > MAX_NOTE_CHARS - len(TRUNCATION_MARK) - 1:
                break
            kept.append(entry)
            size += len(entry) + 1
        kept.append(TRUNCATION_MARK)
        text = "\n".join(kept)
    return text
