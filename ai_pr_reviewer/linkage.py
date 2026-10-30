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
from fnmatch import fnmatch
from pathlib import Path
from typing import Callable

from .index.limits import is_contained
from .models import STATIC_ENGINE_ID, EvidenceRecord, Finding, ProvenanceSource
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


# ------------------------------------------------------ V4.4-E04-T02
# Linkage scoring and surfacing: a closed match ladder over the files
# IN THIS REVIEW (exact path mention -> parent-directory mention ->
# nothing), evidence findings, and the additive ``linked_issues`` report
# section, behind the ISSUE_LINKAGE flag (default OFF, config.py;
# orchestrator hook joins findings before dedup).
#
# The privacy core: issue text is only ever a MATCH SIGNAL against the
# changed files — an issue can never introduce a path of its own. The
# anchor is always a path from ``files`` (already exclusion-filtered by
# the orchestrator and re-checked here), and finding prose carries only
# bounded/closed-set fields (key, kind, state, match level, path), never
# issue free text. Score links, render evidence-or-dropped, cap
# deterministically (file order), full totals with capped rows.

LINK_RULE_ID = "ISSUE_LINKAGE"
LINK_CONTRACT = (
    "deterministic match of configured issue records against the files "
    "in this review: exact path mention (high) or parent-directory "
    "mention (medium); issue text never names or anchors a path — only "
    "changed files do; linkage is a signal, never a claim of "
    "requirement compliance")

MATCH_EXACT = "exact_path"
MATCH_DIRECTORY = "directory"
#: Match level -> confidence (the frozen low|medium|high set).
CONFIDENCE_BY_MATCH = {MATCH_EXACT: "high", MATCH_DIRECTORY: "medium"}

MAX_LINK_FINDINGS = 5
MAX_SECTION_ROWS = 10               # rows per section list (totals stay full)
MAX_FINDING_TITLE_CHARS = 200
MAX_EXPLANATION_CHARS = 900
MAX_EVIDENCE_SUMMARY_CHARS = 400        # mirrors models.MAX_EVIDENCE_SUMMARY_CHARS
MAX_PATH_CHARS = 300
EVIDENCE_CHECK_TYPE = "issue_linkage"


def _norm(path: str) -> str:
    """Shared diff-path normalization (windows separators, ``./``)."""
    return path.replace("\\", "/").removeprefix("./")


def _issue_text(record: IssueRecord) -> str:
    """The record's untrusted text, already bounded and single-lined.

    Used for match screening only — rendering paths take the bounded
    title alone (see T04).
    """
    return " ".join((record.key, record.title, record.body,
                     *record.labels))


def _mentions(text: str, needle: str) -> bool:
    """Boundary-aware mention test: ``src/a.py`` matches inside
    ``prefix/src/a.py`` but ``ba.py`` never matches ``a.py`` and
    ``src/payments-old`` never matches ``src/payments``.
    """
    if not needle:
        return False
    return re.search(r"(?<![\w.-])" + re.escape(needle) + r"(?![\w.-])",
                     text) is not None


def match_issue(record: IssueRecord, paths: tuple[str, ...]
                ) -> tuple[str, str] | None:
    """The closed ladder: ``(match level, changed path)`` or ``None``.

    Pass 1 — the issue text mentions a changed file's exact path (any
    file, diff order); pass 2 — it mentions the parent directory of a
    changed file (diff order); otherwise no match. There is deliberately
    NO sha rung: issues are not commit-tied, so a sha mention can never
    score. Both passes run over ``paths`` — the files of this review —
    so a path that is not in the review cannot be produced here at all.
    """
    text = _issue_text(record).replace("\\", "/")
    for raw in paths:
        if _mentions(text, _norm(raw)):
            return MATCH_EXACT, raw
    for raw in paths:
        parent = _norm(raw).rpartition("/")[0]
        if parent and _mentions(text, parent):
            return MATCH_DIRECTORY, raw
    return None


@dataclass(frozen=True)
class Linkage:
    """One scored issue-to-file match (``path`` is a changed file)."""

    record: IssueRecord
    match: str                  # MATCH_EXACT | MATCH_DIRECTORY
    path: str                   # anchor = the changed file (raw spelling)


def score_linkages(records: tuple[IssueRecord, ...],
                   paths: tuple[str, ...]
                   ) -> tuple[tuple[Linkage, ...], tuple[IssueRecord, ...]]:
    """Split records into (linked, unlinked), both in file order."""
    linked: list[Linkage] = []
    unlinked: list[IssueRecord] = []
    for record in records:
        hit = match_issue(record, paths)
        if hit is None:
            unlinked.append(record)
        else:
            linked.append(Linkage(record=record, match=hit[0], path=hit[1]))
    return tuple(linked), tuple(unlinked)


def _excluded(path: str, patterns: list[str]) -> bool:
    """fnmatch mirror of orchestrator._is_excluded — defense-in-depth
    for direct callers (``files`` arrives pre-filtered from the hook)."""
    return any(fnmatch(path, p.strip()) for p in patterns if p.strip())


def _candidate_paths(files, exclusions) -> tuple[str, ...]:
    """Distinct changed paths in review order, minus exclusion globs.

    This list is BOTH sides of every match: the ladder searches only
    these paths and anchors only on them, so an excluded path can never
    surface as a linkage anchor even when handed to this module
    directly.
    """
    patterns = [str(p) for p in (exclusions or ())]
    out: list[str] = []
    seen: set[str] = set()
    for fd in files or ():
        raw = str(getattr(fd, "path", "") or "")
        if not raw:
            continue
        key = _norm(raw)
        if key in seen:
            continue
        if _excluded(raw, patterns) or _excluded(key, patterns):
            continue
        seen.add(key)
        out.append(raw)
    return tuple(out)


def link_findings(linkages: tuple[Linkage, ...], *,
                  scrub: Callable[[str], str] | None = None
                  ) -> tuple[Finding, ...]:
    """Scored linkages as ordinary pipeline findings — evidence-or-
    dropped, deterministic file order, capped.

    The finding's ``file`` is always the matched changed file, so
    anchoring in ``validate_findings`` succeeds; the issue itself
    surfaces as a ``history_event`` evidence record, never as a path or
    a verdict. Prose carries only closed-set/bounded fields — issue
    title/body/labels are never quoted here.
    """
    out: list[Finding] = []
    for item in linkages[:MAX_LINK_FINDINGS]:
        record, anchor = item.record, item.path
        confidence = CONFIDENCE_BY_MATCH[item.match]
        if item.match == MATCH_EXACT:
            where = f"its text mentions the path {anchor}"
        else:
            where = (f"its text mentions the directory "
                     f"{_norm(anchor).rpartition('/')[0]} of {anchor}")
        try:
            file_ev = EvidenceRecord.create(
                kind="file_excerpt", locator=anchor,
                summary=_clean(
                    f"issue {record.key} matches {anchor} "
                    f"({item.match}; confidence {confidence})",
                    MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type=EVIDENCE_CHECK_TYPE, scrub=scrub)
            issue_ev = EvidenceRecord.create(
                kind="history_event", locator=f"issue:{record.key}",
                summary=_clean(
                    f"configured issue {record.key} ({record.kind}, state "
                    f"{record.state}) matched {anchor} at {item.match} "
                    f"level", MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type=EVIDENCE_CHECK_TYPE, scrub=scrub)
            ref_ev = EvidenceRecord.create(
                kind="rule_ref", locator=f"rule:{LINK_RULE_ID}",
                summary=_clean(LINK_CONTRACT,
                               MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type=EVIDENCE_CHECK_TYPE, scrub=scrub)
        except ValueError:
            continue                        # evidence-or-dropped
        finding = Finding(
            file=anchor, line=None, severity="info",
            category="maintainability",
            title=_clean(f"Issue {record.key} linked to {anchor}",
                         MAX_FINDING_TITLE_CHARS, scrub),
            explanation=_clean(
                f"Configured issue {record.key} ({record.kind}, state "
                f"{record.state}) links to this change: {where} "
                f"(match: {item.match}; confidence: {confidence}). "
                f"Linkage comes from the configured issue export — a "
                f"signal about the issue, not a verdict about this "
                f"change.",
                MAX_EXPLANATION_CHARS, scrub),
            suggestion=None, confidence=confidence,
            rule_id=LINK_RULE_ID, evidence=(file_ev, issue_ev, ref_ev),
        )
        source = ProvenanceSource(engine=STATIC_ENGINE_ID,
                                  model="issue-linkage-v1", origin="rule")
        finding.provenance_engine = source.engine
        finding.provenance_model = source.model
        finding.provenance_agent = None
        finding.provenance_origin = source.origin
        finding.provenance_sources = (source,)
        out.append(finding)
    return tuple(out)


def linkage_section(records: tuple[IssueRecord, ...],
                    linked: tuple[Linkage, ...],
                    unlinked: tuple[IssueRecord, ...], *,
                    files_total: int,
                    scrub: Callable[[str], str] | None = None) -> dict:
    """The additive report block (``linked_issues``): full totals plus
    capped linked/unlinked rows.

    Rows and titles are re-scrubbed here (redact-at-store chokepoint:
    everything a finding or report can surface is scrubbed as well);
    ``kind``/``state``/``match`` are closed-set values by construction.
    """
    matched_rows: list[dict] = []
    for item in linked[:MAX_SECTION_ROWS]:
        record = item.record
        matched_rows.append({
            "key": _clean(record.key, MAX_KEY_CHARS, scrub),
            "kind": record.kind,
            "state": record.state,
            "title": _clean(record.title, MAX_TITLE_CHARS, scrub),
            "path": _clean(item.path, MAX_PATH_CHARS, scrub),
            "match": item.match,
            "confidence": CONFIDENCE_BY_MATCH[item.match],
            "updated_at": record.updated_at,
        })
    unmatched_rows: list[dict] = []
    for record in unlinked[:MAX_SECTION_ROWS]:
        unmatched_rows.append({
            "key": _clean(record.key, MAX_KEY_CHARS, scrub),
            "kind": record.kind,
            "state": record.state,
            "title": _clean(record.title, MAX_TITLE_CHARS, scrub),
            "updated_at": record.updated_at,
        })
    return {
        "issues_total": len(records),
        "linked_total": len(linked),
        "unlinked_total": len(unlinked),
        "files_total": files_total,
        "matched": matched_rows,
        "unmatched": unmatched_rows,
    }


@dataclass(frozen=True)
class LinkageOutcome:
    """Runner result: findings + warnings + the report section.

    ``linked_issues is None`` means "no linkage happened" (no configured
    records, or no changed files to match against): the orchestrator
    then leaves the report key off entirely — features absent =>
    unchanged behavior.
    """

    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    linked_issues: dict | None = None


NOOP = LinkageOutcome()


def run_linkage_context(*, repo_root: str, files, exclusions=(),
                        scrub: Callable[[str], str] | None = None
                        ) -> LinkageOutcome:
    """V4.4-E04 entry point (orchestrator hook; ISSUE_LINKAGE default OFF).

    * no configured records and no warnings -> ``NOOP``;
    * garbage config -> warnings alone, no section;
    * no changed files (after exclusions) -> nothing to match against:
      no section;
    * any crash -> one labeled warning -- the feature never fails a
      review (mirrors the correlation, release and incident runners).
    """
    try:
        records, warnings = ingest_issues(repo_root, scrub=scrub)
        if not records:
            return NOOP if not warnings else LinkageOutcome(
                warnings=warnings)
        paths = _candidate_paths(files, exclusions)
        if not paths:
            return LinkageOutcome(warnings=warnings)
        linked, unlinked = score_linkages(records, paths)
        return LinkageOutcome(
            findings=link_findings(linked, scrub=scrub),
            warnings=warnings,
            linked_issues=linkage_section(
                records, linked, unlinked, files_total=len(paths),
                scrub=scrub))
    except Exception as exc:  # noqa: BLE001 -- opt-in feature never fails a review
        log.warning("issue linkage failed: %s", type(exc).__name__)
        return LinkageOutcome(warnings=(
            f"issue linkage failed ({type(exc).__name__}); skipped",))
