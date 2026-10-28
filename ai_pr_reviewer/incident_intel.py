"""V4.6-E06-T01 — configured-source incident ingestion (opt-in, read-only).

Retrospective incident context for reviews: a repository owner exports
incident records to JSON files and lists them in a trusted sources
config; this module loads, normalizes and bounds them so later tickets
(T02 retention, T03 linkage) can turn them into review *evidence* —
never a prediction, never an automated response.

Read-only contract (V4.6-E06; test-enforced in T04):

* **no network, no writes, no subprocess** — ingestion reads the
  configured local files and nothing else; there is no outbound path of
  any kind, so this module cannot page, trigger or update an incident
  tool;
* **absent configuration is zero surface** — no flag, no config file, or
  an empty ``sources`` list all mean: no records, no warnings, no
  findings, byte-identical review output;
* **the config is trusted, the data is not** — the sources file lives in
  the base-revision checkout (a PR cannot retarget it) and every path it
  lists is containment-checked before a single byte is read; the incident
  records themselves are untrusted-derived content, so every field is
  secret-redacted, control-stripped, single-line and bounded at ingest
  (the same posture findings get at the report boundary);
* **bounded everywhere** — per-source file size, record count, field
  lengths; a hostile export degrades to a labeled warning, never an
  exception and never a partial silent success.

Config file (default ``.ai-pr-reviewer-incidents.json`` in the repo
root, override with the plain env var ``INCIDENT_SOURCES_FILE``):

    {"retention_days": 365, "max_incidents": 25,
     "sources": ["incidents/export.json"]}

Each source file holds ``{"incidents": [...]}`` with records carrying at
least ``id``; ``title``/``summary``/``severity``/``occurred_at``/
``resolved_at``/``paths``/``change_shas`` are used when present.
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
from .models import (STATIC_ENGINE_ID, EvidenceRecord, Finding,
                     ProvenanceSource)
from .security import redact_secrets

log = logging.getLogger(__name__)

DEFAULT_SOURCES_FILE = ".ai-pr-reviewer-incidents.json"

# Bounds: a hostile or accidental export can never flood a review, a
# report row or a prompt. Each cap trip is a labeled degradation.
MAX_SOURCES = 10
MAX_INCIDENTS = 50
MAX_SOURCE_FILE_BYTES = 262_144          # 256 KiB per export file
MAX_ID_CHARS = 100
MAX_TITLE_CHARS = 200
MAX_SUMMARY_CHARS = 600
MAX_SEVERITY_CHARS = 20
MAX_TIMESTAMP_CHARS = 40
MAX_PATHS_PER_INCIDENT = 20
MAX_PATH_CHARS = 300
MAX_SHAS_PER_INCIDENT = 10
MAX_SHA_CHARS = 64
MAX_WARNINGS = 10
MAX_WARNING_CHARS = 300
_CONTROL = {c: " " for c in (*range(0x20), 0x7F, *range(0x80, 0xA0),
                              0x2028, 0x2029)}


def _clean(text: object, limit: int,
           scrub: Callable[[str], str] | None = None) -> str:
    """Redact, strip control characters, collapse to one line, bound."""
    out = redact_secrets(str(text if text is not None else ""))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    return out[:limit].strip()


@dataclass(frozen=True)
class IncidentRecord:
    """One normalized incident. Every string is already redacted,
    single-line and bounded; ``occurred_at``/``resolved_at`` keep the
    normalized ISO text (empty when absent or unparseable)."""

    incident_id: str
    title: str = ""
    summary: str = ""
    severity: str = ""
    occurred_at: str = ""
    resolved_at: str = ""
    paths: tuple[str, ...] = ()
    change_shas: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class IncidentSources:
    """Parsed sources config. ``retention_days`` 0 = keep everything;
    ``max_incidents`` 0 = module default. Empty ``sources`` is the
    legitimate 'configured but nothing to ingest' state."""

    retention_days: int = 0
    max_incidents: int = 0
    sources: tuple[str, ...] = ()


def _warn(msg: str, warnings: list[str],
          scrub: Callable[[str], str] | None = None) -> None:
    if len(warnings) < MAX_WARNINGS:
        warnings.append(_clean(msg, MAX_WARNING_CHARS, scrub))


def _nonneg_int(value: object) -> int:
    try:
        out = int(value)          # bool is an int subclass; reject it
    except (TypeError, ValueError):
        return 0
    return out if out > 0 and not isinstance(value, bool) else 0


def _normalize_ts(value: object) -> str:
    """ISO-8601 text -> normalized UTC ISO text, or ``""``.

    Never raises: an unparseable timestamp is recorded as absent (and
    therefore never age-pruned — retention only removes records it can
    PROVE are old).
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


def _string_list(value: object, *, max_items: int,
                 item_limit: int) -> tuple[str, ...]:
    """Bounded list of cleaned strings from untrusted JSON."""
    if not isinstance(value, list):
        return ()
    out: list[str] = []
    for item in value[:max_items]:
        if not isinstance(item, str):
            continue
        text = _clean(item, item_limit)
        if text and text not in out:
            out.append(text)
    return tuple(out)


_SHA_RE = re.compile(r"\A[0-9a-fA-F]{40}\Z")


def _sha_list(value: object, *, max_items: int) -> tuple[str, ...]:
    """Git SHAs, strict-format only: ``^[0-9a-fA-F]{40}$``, lowercased.

    Format allowlisting is stronger than pattern redaction here — every
    recognized credential format carries a prefix or a different length,
    so only genuine 40-hex identifiers survive, and ``redact_secrets``'
    entropy rule (which would mangle real SHAs) is deliberately not
    applied to this field. Surviving SHAs are cited by 8-char prefix
    wherever they surface (T03), never in full.
    """
    if not isinstance(value, list):
        return ()
    out: list[str] = []
    for item in value[:max_items]:
        if not isinstance(item, str):
            continue
        text = item.strip()[:MAX_SHA_CHARS].lower()
        if _SHA_RE.match(text) and text not in out:
            out.append(text)
    return tuple(out)


def _normalize(raw: object, *, source: str,
               scrub: Callable[[str], str] | None) -> IncidentRecord | None:
    """One untrusted JSON object -> a bounded, redacted record.

    ``id`` is the only required field: an incident without an identity
    cannot be linked, counted or deduplicated honestly.
    """
    if not isinstance(raw, dict):
        return None
    incident_id = _clean(raw.get("id"), MAX_ID_CHARS, scrub)
    if not incident_id:
        return None
    return IncidentRecord(
        incident_id=incident_id,
        title=_clean(raw.get("title"), MAX_TITLE_CHARS, scrub),
        summary=_clean(raw.get("summary"), MAX_SUMMARY_CHARS, scrub),
        severity=_clean(raw.get("severity"), MAX_SEVERITY_CHARS,
                        scrub).lower(),
        occurred_at=_normalize_ts(raw.get("occurred_at")),
        resolved_at=_normalize_ts(raw.get("resolved_at")),
        paths=_string_list(raw.get("paths"), max_items=MAX_PATHS_PER_INCIDENT,
                           item_limit=MAX_PATH_CHARS),
        change_shas=_sha_list(raw.get("change_shas"),
                              max_items=MAX_SHAS_PER_INCIDENT),
        source=_clean(source, MAX_ID_CHARS, scrub),
    )


def load_sources_config(repo_root: str, *,
                        filename: str = "") -> IncidentSources | None:
    """Parse the trusted sources config, or ``None`` when it is absent.

    Never raises: malformed config degrades to ``None`` plus a warning
    through the ingest path (the caller decides how to surface it).
    """
    name = filename or _sources_filename()
    if not is_contained(repo_root, name):
        return None
    path = Path(repo_root) / name
    try:
        if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8",
                                         errors="replace"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    sources = _string_list(data.get("sources"), max_items=MAX_SOURCES,
                           item_limit=MAX_PATH_CHARS)
    return IncidentSources(
        retention_days=_nonneg_int(data.get("retention_days")),
        max_incidents=min(_nonneg_int(data.get("max_incidents")),
                          MAX_INCIDENTS),
        sources=sources,
    )


def _sources_filename() -> str:
    return (os.environ.get("INCIDENT_SOURCES_FILE", "").strip()
            or DEFAULT_SOURCES_FILE)


def apply_retention(records: tuple[IncidentRecord, ...], *,
                    retention_days: int,
                    now: datetime | None = None
                    ) -> tuple[IncidentRecord, ...]:
    """Drop incidents provably older than ``retention_days``.

    Honesty rule: retention removes only what it can PROVE is old — a
    record with an absent or unparseable ``occurred_at`` is kept (T01
    records those as empty), because silently deleting an incident we
    cannot date would hide context a review might need. ``now`` is
    injectable so tests are deterministic.
    """
    if retention_days <= 0:
        return records
    moment = now or datetime.now(timezone.utc)
    cutoff = moment.timestamp() - retention_days * 86_400
    kept: list[IncidentRecord] = []
    for record in records:
        try:
            occurred = datetime.fromisoformat(record.occurred_at)
        except ValueError:
            kept.append(record)         # undated: never provably old
            continue
        if occurred.timestamp() >= cutoff:
            kept.append(record)
    return tuple(kept)


def ingest_incidents(*, repo_root: str, sources: IncidentSources,
                     scrub: Callable[[str], str] | None = None,
                     now: datetime | None = None
                     ) -> tuple[tuple[IncidentRecord, ...], tuple[str, ...]]:
    """Load every configured source file into normalized records, then
    apply the configured retention window (T02).

    Allow-list semantics: only paths the trusted config names are read,
    each containment-checked; an unnameable or unreadable path becomes a
    warning and is skipped. Deterministic order (config order, file
    order); duplicates across files (same source+id) keep the first.
    """
    warnings: list[str] = []
    records: list[IncidentRecord] = []
    seen: set[tuple[str, str]] = set()
    budget = sources.max_incidents or MAX_INCIDENTS

    def warn(msg: str) -> None:
        _warn(msg, warnings, scrub)

    for rel in sources.sources:
        if len(records) >= budget:
            warn(f"incident cap ({budget}) reached; remaining sources "
                 f"not ingested")
            break
        if not is_contained(repo_root, rel):
            warn(f"incident source path escapes the repository: {rel}")
            continue
        path = Path(repo_root) / rel
        try:
            if path.stat().st_size > MAX_SOURCE_FILE_BYTES:
                warn(f"incident source exceeds size cap: {rel}")
                continue
            data = json.loads(path.read_text(encoding="utf-8",
                                             errors="replace"))
        except OSError:
            warn(f"incident source unreadable: {rel}")
            continue
        except ValueError as exc:
            # Type only, never file content (same rule as the infra
            # parsers: a parse failure cannot echo the file it failed on).
            warn(f"incident source is not valid JSON "
                 f"({type(exc).__name__}): {rel}")
            continue
        raw_list = data.get("incidents") if isinstance(data, dict) else None
        if not isinstance(raw_list, list):
            warn(f"incident source has no incidents list: {rel}")
            continue
        for raw in raw_list:
            if len(records) >= budget:
                break
            record = _normalize(raw, source=rel, scrub=scrub)
            if record is None:
                continue
            key = (record.source, record.incident_id)
            if key in seen:
                continue
            seen.add(key)
            records.append(record)
    kept = apply_retention(tuple(records),
                           retention_days=sources.retention_days, now=now)
    return kept, tuple(warnings)


# ------------------------------------------------------- change linkage
# V4.6-E06-T03. Retrospective context, never prophecy: an incident link
# states a HISTORICAL fact (this file was listed in that incident), it
# never claims the current change will cause anything. Confidence labels
# the strength of the match, not the risk of the change.

MAX_LINK_FINDINGS = 5
MAX_MATCHED_PATHS = 5
LINK_RULE_ID = "INCIDENT_LINK"
LINK_CONTRACT = (
    "checked: an ingested incident record lists a path this change "
    "modifies (exact match = high, same directory = medium), or the "
    "incident references this PR's head commit (high); confidence "
    "describes the match, not the risk of the change")
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"


@dataclass(frozen=True)
class IncidentLink:
    """One incident connected to the current change set."""

    record: IncidentRecord
    matched_paths: tuple[str, ...] = ()
    sha_matched: bool = False
    # True when at least one match was an exact path hit (as opposed to
    # same-directory only): set by the match ladder, never by callers.
    _exact: bool = False

    @property
    def confidence(self) -> str:
        # High = head-SHA hit or an exact path hit; medium = same-directory
        # only. Labels the STRENGTH of the match, not the risk of the change.
        return CONFIDENCE_HIGH if self.sha_matched or self._exact \
            else CONFIDENCE_MEDIUM


def _norm(path: str) -> str:
    # Strip a leading "./" PREFIX, not a character set: lstrip("./") would
    # mangle "..foo" into "foo" and silently change what matches.
    norm = path.replace("\\", "/").strip()
    while norm.startswith("./"):
        norm = norm[2:]
    return norm


def _dirname(path: str) -> str:
    norm = _norm(path)
    return norm.rsplit("/", 1)[0] if "/" in norm else ""


def link_incidents(records: tuple[IncidentRecord, ...], files,
                   *, head_sha: str | None = None
                   ) -> tuple[IncidentLink, ...]:
    """Match incidents against the changed files. Deterministic order
    (record order); one link per incident; at most
    ``MAX_MATCHED_PATHS`` matched paths are carried per link.

    Match ladder: incident references the PR head commit (high) ->
    exact changed-path match (high) -> same-directory match (medium) ->
    no link at all (an incident that matches nothing is simply not
    surfaced; ambiguity never becomes a claim).
    """
    changed = [fd for fd in files if fd.path]
    head = (head_sha or "").strip().lower()
    links: list[IncidentLink] = []
    for record in records:
        exact: list[str] = []
        dirs: list[str] = []
        incident_dirs = {_dirname(p) for p in record.paths if _dirname(p)}
        for fd in changed:
            candidates = {n for n in (_norm(fd.path), _norm(fd.old_path))
                          if n}
            if candidates & {_norm(p) for p in record.paths}:
                exact.append(fd.path)
            elif {_dirname(c) for c in candidates} & incident_dirs:
                dirs.append(fd.path)
        sha_hit = bool(head and head in record.change_shas)
        matched = tuple((exact + dirs)[:MAX_MATCHED_PATHS])
        if not matched and not sha_hit:
            continue
        links.append(IncidentLink(record=record, matched_paths=matched,
                                  sha_matched=sha_hit, _exact=bool(exact)))
        if len(links) >= MAX_LINK_FINDINGS:
            break
    return tuple(links)


# ------------------------------------------------------------- findings
# MAX_TITLE_CHARS / _CONTROL are defined once in the T01 section above.

MAX_EXPLANATION_CHARS = 900
MAX_EVIDENCE_SUMMARY_CHARS = 400        # mirrors models.MAX_EVIDENCE_SUMMARY_CHARS


def _clean_text(text: object, limit: int,
                scrub: Callable[[str], str] | None) -> str:
    out = redact_secrets(str(text if text is not None else ""))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    return out[:limit].strip()


def link_findings(links: tuple[IncidentLink, ...], files, *,
                  scrub: Callable[[str], str] | None = None
                  ) -> tuple[Finding, ...]:
    """Turn links into ordinary pipeline findings — evidence-or-dropped,
    deterministic provenance, no remediation, no prediction wording.

    The finding's ``file`` is always a changed file (so anchoring in
    ``validate_findings`` succeeds); the incident itself surfaces as a
    ``history_event`` evidence record, not as a verdict on the diff.
    """
    # Membership is a set; ORDER is the diff's, so the sha-only fallback
    # anchor below is deterministic (set iteration order is hash-seed
    # dependent).
    changed_paths = {fd.path for fd in files if fd.path}
    ordered_paths = [fd.path for fd in files if fd.path]
    out: list[Finding] = []
    for link in links:
        record = link.record
        anchor = next((p for p in link.matched_paths if p in changed_paths),
                      None)
        if anchor is None:
            # sha-only link: anchor on the first changed file (diff order)
            anchor = ordered_paths[0] if ordered_paths else None
        if anchor is None:
            continue                        # nothing changed: no finding
        where = ", ".join(link.matched_paths) if link.matched_paths \
            else "this change's head commit"
        when = f" on {record.occurred_at[:10]}" if record.occurred_at else ""
        subject = record.title or record.summary or "incident record"
        explanation = (
            f"Incident {record.incident_id}{when} ({record.severity or 'unspecified severity'}) "
            f"lists {where} in its record. The incident title on file: "
            f"\"{subject}\". Historical context from the configured "
            f"incident source — evidence about the past, not a prediction "
            f"about this change.")
        try:
            file_ev = EvidenceRecord.create(
                kind="file_excerpt", locator=anchor,
                summary=_clean_text(
                    f"matched via {where} (confidence: "
                    f"{link.confidence})", MAX_EVIDENCE_SUMMARY_CHARS,
                    scrub),
                check_type="incident_link", scrub=scrub)
            incident_ev = EvidenceRecord.create(
                kind="history_event", locator=f"incident:{record.incident_id}",
                summary=_clean_text(
                    f"{record.incident_id} ({record.severity or 'n/a'})"
                    f"{when}: {subject}", MAX_EVIDENCE_SUMMARY_CHARS,
                    scrub),
                check_type="incident_link", scrub=scrub)
            ref_ev = EvidenceRecord.create(
                kind="rule_ref", locator=f"rule:{LINK_RULE_ID}",
                summary=_clean_text(LINK_CONTRACT,
                                    MAX_EVIDENCE_SUMMARY_CHARS, scrub),
                check_type="incident_link", scrub=scrub)
        except ValueError:
            continue                        # evidence-or-dropped
        finding = Finding(
            file=anchor, line=None, severity="info",
            category="maintainability",
            title=_clean_text(
                f"Change touches files listed in incident "
                f"{record.incident_id}", MAX_TITLE_CHARS, scrub),
            explanation=_clean_text(explanation, MAX_EXPLANATION_CHARS,
                                    scrub),
            suggestion=None, confidence=link.confidence,
            rule_id=LINK_RULE_ID, evidence=(file_ev, incident_ev, ref_ev),
        )
        source = ProvenanceSource(engine=STATIC_ENGINE_ID,
                                  model="incident-v1", origin="rule")
        finding.provenance_engine = source.engine
        finding.provenance_model = source.model
        finding.provenance_agent = None
        finding.provenance_origin = source.origin
        finding.provenance_sources = (source,)
        out.append(finding)
    return tuple(out)


@dataclass(frozen=True)
class IncidentOutcome:
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()


NOOP = IncidentOutcome()


def run_incident_context(*, repo_root: str, files,
                         head_sha: str | None = None,
                         scrub: Callable[[str], str] | None = None
                         ) -> IncidentOutcome:
    """Single entry point for the review pipeline (V4.6-E06-T03).

    Absent configuration (no sources file, or an empty ``sources`` list)
    is a true NOOP: no records, no warnings, byte-identical output.
    Never raises: any failure becomes one warning and zero findings.
    ``github_token``-style credentials never reach this module's inputs,
    and nothing here can write, post or trigger (read-only contract,
    test-enforced in T04).
    """
    try:
        sources = load_sources_config(repo_root)
        if sources is None or not sources.sources:
            return NOOP
        records, warnings = ingest_incidents(repo_root=repo_root,
                                             sources=sources, scrub=scrub)
        links = link_incidents(records, files, head_sha=head_sha)
        return IncidentOutcome(
            findings=link_findings(links, files, scrub=scrub),
            warnings=warnings)
    except Exception as exc:  # noqa: BLE001 — opt-in feature never fails a review
        log.warning("incident check failed: %s", type(exc).__name__)
        return IncidentOutcome(warnings=(
            f"incident check failed ({type(exc).__name__}); skipped",))
