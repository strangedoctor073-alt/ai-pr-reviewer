"""V4.4-E04-T01 — configured issue/requirement ingestion (opt-in, read-only).

Linkage intelligence for reviews: a repository owner exports issue and
requirement records to a JSON file; this module loads, normalizes and
bounds them so T02 can score linkage against the changed files and T03
can surface gap signals. The platform observes issue state — it never
files, edits, closes or comments on anything.

Read-only contract (plan §C.3; test-enforced):

* **no network, no writes, no subprocess** — ingestion reads the one
  configured local file and nothing else; there is no outbound path of
  any kind. The plan's ``github_client`` issues endpoint would be new
  egress and needs the human sign-off this epic does not have, so
  issues arrive as a configured export instead (same posture as
  releases, V4.6-E03); with no request surface the family's C8
  rate-limit discipline is satisfied vacuously — there is nothing to
  throttle here;
* **absent configuration is zero surface** — no file, no records, no
  warnings, byte-identical review output;
* **the config is trusted, the data is not** — the file lives in the
  base-revision checkout and its name is containment-checked before any
  byte is read; every extracted field is secret-redacted, control-
  stripped and bounded at ingest. ``key`` is an identity field and
  REFUSES to truncate (a cut key names a different issue); free text
  (``title``/``body``) truncates at its bound AFTER redaction so a
  secret is never cut in half;
* **closed sets** — ``state`` is open/closed/unknown, ``kind`` is
  issue/requirement (default issue) and labels are a capped, deduped
  list: unrecognized values record as the honest default rather than a
  guess;
* **prompt-injection screening at the boundary** — issue text is
  untrusted by definition (anyone can write an issue): key, title, body
  and labels are scanned and hits become capped warnings that name the
  PATTERN but never echo the text. Screening never drops a record —
  text stays data.

Config file (default ``.ai-pr-reviewer-issues.json`` in the repo root,
override with the plain env var ``ISSUE_SOURCES_FILE``):

    {"issues": [{"key": "PAY-123", "title": "Refund expiry",
                 "state": "open", "labels": ["bug"], "kind": "requirement",
                 "updated_at": "2026-10-20T09:00:00Z",
                 "body": "Refunds must expire after 30 days…"}]}

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
from typing import Callable

from .index.limits import is_contained
from .security import redact_secrets, scan_prompt_injection

DEFAULT_ISSUES_FILE = ".ai-pr-reviewer-issues.json"

# Bounds: a hostile or accidental export can never flood a review, a
# report row or a prompt. Each cap trip is a labeled degradation.
MAX_ISSUES = 50
MAX_SOURCE_FILE_BYTES = 262_144          # 256 KiB per config file
MAX_KEY_CHARS = 200                      # refuse-to-truncate identity
MAX_TITLE_CHARS = 300
MAX_BODY_CHARS = 2_000                   # free text: truncate at the bound
MAX_LABELS = 10
MAX_LABEL_CHARS = 60
MAX_TIMESTAMP_CHARS = 40
MAX_WARNINGS = 10
MAX_WARNING_CHARS = 300
MAX_INJECTION_PATTERNS = 3               # pattern names cited per warning

STATE_OPEN = "open"
STATE_CLOSED = "closed"
STATE_UNKNOWN = "unknown"
KIND_ISSUE = "issue"
KIND_REQUIREMENT = "requirement"

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
    """Identity field (``key``): cleaned like ``_clean`` but REFUSING to
    truncate. ``None`` means "over long — drop the record" (a cut key
    names a different issue); ``""`` means absent/empty.
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

    Never raises: an unparseable timestamp is recorded as absent rather
    than guessed.
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


def _normalize_state(value: object) -> str:
    """Closed set: ``open``/``closed``, else the honest ``unknown``.

    A malformed state never coerces to ``open`` (or to ``closed``) —
    linkage must not read an unrecognized value as activity it cannot
    see.
    """
    if isinstance(value, str):
        text = value.strip().lower()
        if text in (STATE_OPEN, STATE_CLOSED):
            return text
    return STATE_UNKNOWN


def _normalize_kind(value: object) -> str:
    """Closed set: ``requirement`` only when it says so; else ``issue``.

    ``kind`` decides whether T03 emits a requirement gap signal, so it
    is affirmative evidence: a record must name itself a requirement to
    be treated as one.
    """
    if isinstance(value, str) and value.strip().lower() == KIND_REQUIREMENT:
        return KIND_REQUIREMENT
    return KIND_ISSUE


def _normalize_labels(value: object, scrub: Callable[[str], str] | None
                      ) -> tuple[str, ...]:
    """Capped, deduped, redacted label list — order preserved."""
    if not isinstance(value, list):
        return ()
    out: list[str] = []
    seen: set[str] = set()
    for raw in value:
        if len(out) >= MAX_LABELS:
            break
        if not isinstance(raw, str):
            continue                    # labels are strings; skip the rest
        label = _clean(raw, MAX_LABEL_CHARS, scrub)
        if label and label not in seen:
            seen.add(label)
            out.append(label)
    return tuple(out)


@dataclass(frozen=True)
class IssueRecord:
    """One normalized issue/requirement from the configured export.

    ``key`` is already redacted, single-line and bounded (refuse-to-
    truncate); ``state``/``kind`` are closed-set values; ``labels`` is a
    capped tuple; ``updated_at`` is normalized UTC ISO or ``""``.
    """

    key: str
    title: str = ""
    body: str = ""                       # redacted, bounded free text
    state: str = STATE_UNKNOWN
    labels: tuple[str, ...] = ()
    kind: str = KIND_ISSUE
    updated_at: str = ""
    source: str = ""                     # the config file it came from


def _sources_filename() -> str:
    return (os.environ.get("ISSUE_SOURCES_FILE", "").strip()
            or DEFAULT_ISSUES_FILE)


def _normalize_issue(raw: object, *, source: str,
                     scrub: Callable[[str], str] | None
                     ) -> IssueRecord | None:
    """One untrusted issue object -> a bounded, redacted record.

    Returns ``None`` (drop) for: non-objects, an over-long key
    (refuse-to-truncate) and an empty/absent key. Drops are silent
    per-record; a record nobody can name is simply not evidence.
    """
    if not isinstance(raw, dict):
        return None
    key = _identity(raw.get("key"), MAX_KEY_CHARS, scrub)
    if key is None or not key:
        return None
    return IssueRecord(
        key=key,
        title=_clean(raw.get("title"), MAX_TITLE_CHARS, scrub),
        body=_clean(raw.get("body"), MAX_BODY_CHARS, scrub),
        state=_normalize_state(raw.get("state")),
        labels=_normalize_labels(raw.get("labels"), scrub),
        kind=_normalize_kind(raw.get("kind")),
        updated_at=_normalize_ts(raw.get("updated_at")),
        source=_clean(source, MAX_TITLE_CHARS, scrub),
    )


def _injection_hits(record: IssueRecord) -> list[str]:
    """Injection-looking constructs in the record's untrusted text.

    The whole record text is screened (key, title, body, labels) —
    already bounded and single-lined by ingest, so the scan itself is
    bounded.
    """
    return scan_prompt_injection(" ".join(
        (record.key, record.title, record.body, *record.labels)))


def ingest_issues(repo_root: str, *,
                  scrub: Callable[[str], str] | None = None,
                  filename: str = ""
                  ) -> tuple[tuple[IssueRecord, ...], tuple[str, ...]]:
    """Load the configured issues file into normalized records.

    Deterministic order (file order, preserved). Never raises: every
    failure mode degrades to a warning that names the config path but
    never echoes file content. Prompt-injection hits in issue text
    surface as warnings that cite pattern names only — never the text.
    """
    warnings: list[str] = []

    def warn(msg: str) -> None:
        _warn(msg, warnings, scrub)

    name = filename or _sources_filename()
    if not is_contained(repo_root, name):
        warn(f"issue source path escapes the repository: {name}")
        return (), tuple(warnings)
    path = Path(repo_root) / name
    try:
        if not path.exists():
            return (), ()               # absent config = zero surface
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            warn(f"issue source exceeds size cap: {name}")
            return (), tuple(warnings)
        data = json.loads(path.read_text(encoding="utf-8",
                                         errors="replace"))
    except OSError:
        warn(f"issue source unreadable: {name}")
        return (), tuple(warnings)
    except ValueError as exc:
        # Type only, never file content: a parse failure cannot echo
        # the file it failed on.
        warn(f"issue source is not valid JSON ({type(exc).__name__}): "
             f"{name}")
        return (), tuple(warnings)

    entries = data.get("issues") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        warn(f"issue source has no issues list: {name}")
        return (), tuple(warnings)

    records: list[IssueRecord] = []
    for index, raw in enumerate(entries):
        if index >= MAX_ISSUES:
            warn(f"issue cap ({MAX_ISSUES}) reached; remaining "
                 f"issues skipped")
            break
        record = _normalize_issue(raw, source=name, scrub=scrub)
        if record is None:
            continue                    # unnamed/over-long: silent drop
        hits = _injection_hits(record)
        if hits:
            # Pattern NAMES only: quoting the hit sample would echo the
            # very text the warning exists to flag.
            cited = ", ".join(h.split(":", 1)[0] for h in
                              hits[:MAX_INJECTION_PATTERNS])
            warn(f"issue {record.key}: prompt-injection-like constructs "
                 f"in issue text ({cited}); text is treated as data only")
        records.append(record)
    return tuple(records), tuple(warnings)
