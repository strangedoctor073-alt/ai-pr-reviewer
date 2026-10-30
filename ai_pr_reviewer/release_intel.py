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
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable

from .index.limits import is_contained
from .security import redact_secrets

if TYPE_CHECKING:
    from .history.builder import HistoryIndex

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

    path_set = {p for c in newer for p in (getattr(c, "paths", ()) or ())}
    capped_commits = tuple((c.sha, c.subject) for c in newer[:max_commits])
    capped_paths = tuple(sorted(path_set)[:max_paths])
    return ReleaseDiff(
        release_tag=tag,
        basis=basis,
        commits=capped_commits,
        paths=capped_paths,
        commits_total=len(newer),
        paths_total=len(path_set),
        truncated=len(newer) > max_commits or len(path_set) > max_paths,
        partial=partial,
        reasons=tuple(reasons),
    )
