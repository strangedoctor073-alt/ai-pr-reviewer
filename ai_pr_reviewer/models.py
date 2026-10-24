"""Core data models shared across the review pipeline."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .security import redact_secrets, sanitize_warnings
from .storage_schema import format_review_id
from .telemetry import RunTelemetry, sanitize_telemetry

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_EMOJI = {
    "critical": "\U0001f6a8",  # rotating light
    "high": "\U0001f534",      # red circle
    "medium": "\U0001f7e0",    # orange circle
    "low": "\U0001f535",       # blue circle
    "info": "\u26aa",          # white circle
}

def calculate_health_score(findings: list) -> tuple[int, str]:
    """Compute a deterministic PR Health Score (0-100) and letter grade.
    
    Deductions per finding (not cumulative past 0):
      critical: 35, high: 20, medium: 8, low: 2, info: 0
    Only open findings (not resolved/dismissed/muted) count.
    """
    CLOSED = {"resolved", "dismissed", "muted"}
    deductions = {"critical": 35, "high": 20, "medium": 8, "low": 2, "info": 0}
    score = 100
    for f in findings:
        state = str(getattr(f, "state", "new") or "new").lower()
        if state not in CLOSED:
            score -= deductions.get(getattr(f, "severity", "medium"), 0)
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    else:
        grade = "D"
    return score, grade

VALID_CATEGORIES = {
    "bug", "security", "logic", "error-handling", "performance",
    "race-condition", "resource-leak", "style", "maintainability", "testing",
}

# V3 field contract for Finding.confidence (the dataclass comment and every
# provider prompt document exactly these): a closed low|medium|high set,
# validated at the deserialization boundary like severity and category.
VALID_CONFIDENCES = ("low", "medium", "high")
DEFAULT_CONFIDENCE = "medium"
# rule_id is a short machine identifier ("SEC001", "AST004"); bound the
# length so a tampered row or model output cannot inflate report rows.
MAX_RULE_ID_CHARS = 200


class ReviewState(str, Enum):
    """Lifecycle of one review run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    FALLBACK = "fallback"      # finished, but (partly) via the static engine


class FindingState(str, Enum):
    """Lifecycle of a finding across successive reviews of the same PR."""

    NEW = "new"
    ACTIVE = "active"
    RESOLVED = "resolved"
    REOPENED = "reopened"
    DISMISSED = "dismissed"
    MUTED = "muted"


VALID_FINDING_STATES = {s.value for s in FindingState}

# Fields owned by the review pipeline (lifecycle engine, GitHub poster, storage).
# They must never be taken from model output, which a malicious diff can steer.
LIFECYCLE_FIELDS = (
    "fingerprint", "state", "first_seen_sha", "last_seen_sha",
    "resolved_at", "github_comment_id",
    "verification_status", "verification_reason", "verified_at",
    # V4-E04: provenance is pipeline-owned (set by orchestrator from
    # AnalysisOutcome, never from model output).
    "provenance_engine", "provenance_model", "provenance_agent",
    "provenance_origin",
    # V4-E04 (T02/T03): evidence, the multi-source provenance list and the
    # dedup merge trail are pipeline-owned too -- a model must never be able
    # to forge "evidence: ..." claims or attribution (roadmap V4 security
    # implication: "model output must not forge evidence claims").
    "evidence", "provenance_sources", "merged_fingerprints",
)

# V4-E04 (ADR-004): evidence is a *record, not prose*. The kind set is
# closed exactly like the severity/category sets: new kinds are an explicit
# contract change, never an accident of whatever a caller passed in.
EVIDENCE_KINDS = (
    "diff_hunk", "file_excerpt", "symbol_def", "test_result",
    "log_excerpt", "rule_ref", "history_event",
)
# Bounded everything: an embedded evidence list can never flood a prompt or
# a report row, and summaries/locators are short, redacted slices -- never
# whole files (ADR-004 alternative "store full blobs" was rejected).
MAX_EVIDENCE_PER_FINDING = 8
MAX_EVIDENCE_SUMMARY_CHARS = 400
MAX_EVIDENCE_LOCATOR_CHARS = 200
# Bounded attribution: one finding can cite a handful of engines/models
# (V4 merge), never an unbounded list.
MAX_PROVENANCE_SOURCES = 8
# V4-E04 hardening: every free-text provenance/evidence *metadata* string is
# redacted, single-line and bounded -- the same posture MAX_RULE_ID_CHARS
# gives rule_id. A tampered stored row or a directly-constructed record
# cannot inflate a report row, smuggle a credential, or inject a markdown
# line through engine/model/origin/agent/check_type/content_hash.
MAX_PROVENANCE_FIELD_CHARS = 200
MAX_EVIDENCE_CHECK_TYPE_CHARS = 64
MAX_EVIDENCE_HASH_CHARS = 64
# Attribution ids for the deterministic rule engine (model_router's static
# usage record already reports the same version id).
STATIC_ENGINE_ID = "static"
STATIC_RULE_ENGINE_VERSION = "static-rules-v1"
# Why a finding has no provenance, for renderers that must say so
# explicitly (T04: "unavailable (reason)", never a crash, never a blank).
PROVENANCE_UNAVAILABLE_REASON = "provenance was not recorded for this finding"

# The scalar provenance attributes on Finding (sanitized on assignment).
_PROVENANCE_SCALARS = frozenset((
    "provenance_engine", "provenance_model", "provenance_agent",
    "provenance_origin"))

# C0/C1 control characters and the Unicode line/paragraph separators: none of
# them belong in a one-line identifier, and a newline would let a locator or
# model string start its own markdown line.
_CONTROL_TABLE = {c: " " for c in (*range(0x20), 0x7F, *range(0x80, 0xA0),
                                   0x2028, 0x2029)}


def _safe_line(value: Any, limit: int) -> str | None:
    """Redacted, single-line, bounded text for provenance/evidence metadata.

    None/blank -> None. Redaction runs BEFORE control characters are
    collapsed (a PEM private-key block spans newlines and must still match),
    and before the bound (a secret is never cut in half and left behind).
    Idempotent; never raises.
    """
    if value is None:
        return None
    text = redact_secrets(str(_enum_value(value)))
    text = text.translate(_CONTROL_TABLE).strip()[:limit].strip()
    return text or None


def _bounded_redacted(text: str, limit: int) -> str:
    """Redact then bound free text, iterated to a fixed point.

    One pass is not enough in a contrived case: cutting a longer token at
    the bound can leave a string that *now* matches a secret pattern. The
    fixed point makes this function idempotent, so ``EvidenceRecord.create``
    can hash exactly the text ``__post_init__`` will later leave alone.
    """
    for _ in range(3):
        nxt = redact_secrets(text)[:limit]
        if nxt == text:
            break
        text = nxt
    return text


@dataclass(frozen=True)
class EvidenceRecord:
    """One machine-checkable evidence record (V4-E04, ADR-004).

    ``content_hash`` is integrity over the *stored* (redacted) summary, so a
    later reader can detect tampering instead of silently citing stale
    evidence (:attr:`integrity_ok`). Redaction happens here, at
    construction, not at callers (V4-E04-T05: redaction inside the write
    path), and again at the output chokepoint.
    """

    kind: str
    locator: str
    summary: str
    content_hash: str
    check_type: str | None = None

    def __post_init__(self) -> None:
        """Structural redaction (V4-E04-T05): every construction route --
        ``create``, ``from_dict``, ``dataclasses.replace`` or a plain
        ``EvidenceRecord(...)`` call that bypasses ``create`` -- ends with
        redacted, single-line, bounded text. Without this, redaction lived
        only in ``create`` and a direct constructor call serialized a raw
        credential straight into the report JSON.

        Text only: ``content_hash`` is left as given (modulo the same
        sanitizer), so a record whose summary was altered here no longer
        matches its hash and ``integrity_ok`` says so instead of the
        mismatch being papered over. Idempotent; never raises (evidence is
        a bonus, never fatal).
        """
        put = object.__setattr__            # frozen dataclass
        put(self, "kind", _safe_line(self.kind, 32) or "")
        put(self, "locator",
            _safe_line(self.locator, MAX_EVIDENCE_LOCATOR_CHARS) or "")
        put(self, "summary", _bounded_redacted(
            str(self.summary if self.summary is not None else ""),
            MAX_EVIDENCE_SUMMARY_CHARS))
        put(self, "content_hash",
            _safe_line(self.content_hash, MAX_EVIDENCE_HASH_CHARS) or "")
        put(self, "check_type",
            _safe_line(self.check_type, MAX_EVIDENCE_CHECK_TYPE_CHARS))

    @classmethod
    def create(
        cls,
        *,
        kind: str,
        locator: str,
        summary: str,
        check_type: str | None = None,
        scrub: Callable[[str], str] | None = None,
    ) -> "EvidenceRecord":
        """Validated, redacted, bounded constructor -- the only sanctioned
        way pipeline code creates evidence.

        ``scrub`` (V4-E08-T05 follow-up) layers a caller-supplied redaction
        policy — the orchestrator passes its configured-credential scrub so
        evidence quoting a diff line can never carry THIS run's credentials.
        It applies after the built-in pattern redaction and *before* the
        bounds and the content hash, so the hash always commits to the final
        stored text: integrity semantics are unchanged.
        """
        k = str(_enum_value(kind)).strip().lower()
        if k not in EVIDENCE_KINDS:
            raise ValueError(
                f"unknown evidence kind {kind!r}; allowed: {EVIDENCE_KINDS}")
        loc = redact_secrets(str(locator))
        text = redact_secrets(str(summary))
        if scrub is not None:
            loc, text = scrub(loc), scrub(text)
        loc = _safe_line(loc, MAX_EVIDENCE_LOCATOR_CHARS) or ""
        if not loc:
            raise ValueError("evidence locator must be non-empty")
        # The same fixed-point finalizer __post_init__ applies, so the hash
        # commits to exactly the text the record will hold.
        text = _bounded_redacted(text, MAX_EVIDENCE_SUMMARY_CHARS)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
        return cls(kind=k, locator=loc, summary=text, content_hash=digest,
                   check_type=_opt_str(check_type))

    @property
    def integrity_ok(self) -> bool:
        """True when the stored hash still matches the stored summary."""
        digest = hashlib.sha256(self.summary.encode("utf-8")).hexdigest()[:16]
        return digest == self.content_hash

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "locator": self.locator,
            "check_type": self.check_type,
            "summary": self.summary,
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "EvidenceRecord | None":
        """Lenient reader for data we wrote ourselves (storage/report
        round-trips). Never raises: malformed entries return None so a bad
        row degrades instead of crashing a review. Summary *and* locator
        are re-redacted (idempotent defense-in-depth, V4-E08-T05) and an
        unsupported kind is rejected (the kind set is a closed contract,
        exactly like ``create`` enforces it), so a tampered row cannot
        smuggle credential text or a forged kind past the write path. The
        stored hash is preserved so tampering surfaces via
        ``integrity_ok`` instead of being papered over."""
        if not isinstance(d, dict):
            return None
        kind = _opt_str(d.get("kind"))
        locator = _opt_str(d.get("locator"))
        if kind is None or locator is None:
            return None
        kind = str(_enum_value(kind)).strip().lower()
        if kind not in EVIDENCE_KINDS:
            return None
        summary = _bounded_redacted(str(d.get("summary") or ""),
                                    MAX_EVIDENCE_SUMMARY_CHARS)
        locator = _safe_line(locator, MAX_EVIDENCE_LOCATOR_CHARS)
        if not locator:
            return None
        digest = _safe_line(d.get("content_hash"), MAX_EVIDENCE_HASH_CHARS) \
            or hashlib.sha256(summary.encode("utf-8")).hexdigest()[:16]
        return cls(
            kind=kind,
            locator=locator,
            summary=summary,
            content_hash=digest,
            # redacted + bounded by __post_init__ (and idempotently here)
            check_type=_safe_line(d.get("check_type"),
                                  MAX_EVIDENCE_CHECK_TYPE_CHARS),
        )


@dataclass(frozen=True)
class ProvenanceSource:
    """One attribution record: which engine/model/agent produced a finding.

    V4-E04-T03: dedup keeps the first occurrence *and* merges provenance,
    so a finding merged across two engines retains both sources. The scalar
    ``provenance_*`` fields on :class:`Finding` stay authoritative for the
    first source (backward compatibility); this list is additive.
    """

    engine: str | None = None
    model: str | None = None
    origin: str | None = None
    agent: str | None = None

    def __post_init__(self) -> None:
        """Redacted, single-line, bounded on every construction route (a
        tampered stored row is the realistic source of junk here; see
        ``MAX_PROVENANCE_FIELD_CHARS``). Idempotent; never raises."""
        put = object.__setattr__            # frozen dataclass
        for name in ("engine", "model", "origin", "agent"):
            put(self, name, _safe_line(getattr(self, name),
                                       MAX_PROVENANCE_FIELD_CHARS))

    def key(self) -> tuple[str | None, str | None, str | None, str | None]:
        """Dedup key: two records with the same key are one attribution."""
        return (self.engine, self.model, self.origin, self.agent)

    def to_dict(self) -> dict[str, Any]:
        return {"engine": self.engine, "model": self.model,
                "origin": self.origin, "agent": self.agent}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ProvenanceSource | None":
        if not isinstance(d, dict):
            return None
        return cls(engine=_opt_str(d.get("engine")),
                   model=_opt_str(d.get("model")),
                   origin=_opt_str(d.get("origin")),
                   agent=_opt_str(d.get("agent")))


def _evidence_from_any(v: Any) -> tuple[EvidenceRecord, ...]:
    """Lenient parse of an evidence list (report/storage input)."""
    if not isinstance(v, (list, tuple)):
        return ()
    out: list[EvidenceRecord] = []
    for item in v:
        rec = EvidenceRecord.from_dict(item) if isinstance(item, dict) else None
        if rec is not None:
            out.append(rec)
    return tuple(out[:MAX_EVIDENCE_PER_FINDING])


def _sources_from_any(v: Any) -> tuple[ProvenanceSource, ...]:
    """Lenient parse of a provenance-sources list (report/storage input).

    Bounded like every other embedded list: capped at
    ``MAX_PROVENANCE_SOURCES`` (V4-E08-T05, same bound the merge path
    enforces) so a tampered row cannot flood a report or a prompt.
    """
    if not isinstance(v, (list, tuple)):
        return ()
    out: list[ProvenanceSource] = []
    for item in v:
        rec = ProvenanceSource.from_dict(item) if isinstance(item, dict) else None
        if rec is not None:
            out.append(rec)
    return tuple(out[:MAX_PROVENANCE_SOURCES])


def _str_tuple(v: Any) -> tuple[str, ...]:
    if not isinstance(v, (list, tuple)):
        return ()
    return tuple(str(x) for x in v if isinstance(x, str) and x)[:16]


def _is_rule_engine_finding(finding: Any) -> bool:
    """True when the deterministic rule engine produced this finding.

    The signal is a ``rule_ref`` evidence record: evidence is pipeline-owned
    (``from_untrusted_dict`` strips it), and only the static engine attaches
    ``rule_ref``. ``rule_id`` is deliberately NOT the signal -- it is plain
    content a model can emit, so keying on it would let model output pose as
    the rule engine.
    """
    for e in tuple(getattr(finding, "evidence", ()) or ()):
        if getattr(e, "kind", None) == "rule_ref":
            return True
    return False


def derive_provenance_source(finding: Any, *, outcome_engine: Any,
                             outcome_model: Any) -> ProvenanceSource:
    """The concrete attribution for ONE finding of an analysis outcome
    (V4-E04-T03). Pure; pipeline code calls it, model output never does.

    ``outcome_engine`` describes the *outcome*, which can be a blend: a
    provider that fell back to the rule engine for some batches reports
    ``"claude+static"`` for all of them. Stamping that blend on every
    finding mislabelled rule-engine output as an AI review (and credited the
    AI model with it), and put a composite string into the key a V5 merge
    would dedup on. Per finding the answer is concrete:

    * pure ``static`` outcome -> static / the outcome's model / ``static``
    * ``<ai>+static`` outcome -> a finding the rule engine produced is
      ``static`` / ``static-rules-v1`` / ``static``; every other finding is
      ``<ai>`` / the outcome's model / ``ai``
    * anything else -> the outcome's engine and model, origin ``ai``
      (unchanged from the original stamping)
    """
    engine = (_safe_line(outcome_engine, MAX_PROVENANCE_FIELD_CHARS) or "").lower()
    model = _safe_line(outcome_model, MAX_PROVENANCE_FIELD_CHARS)
    if engine == STATIC_ENGINE_ID:
        return ProvenanceSource(engine=STATIC_ENGINE_ID, model=model,
                                origin="static", agent=None)
    suffix = "+" + STATIC_ENGINE_ID
    if engine.endswith(suffix):
        if _is_rule_engine_finding(finding):
            return ProvenanceSource(engine=STATIC_ENGINE_ID,
                                    model=STATIC_RULE_ENGINE_VERSION,
                                    origin="static", agent=None)
        return ProvenanceSource(engine=engine[:-len(suffix)] or None,
                                model=model, origin="ai", agent=None)
    return ProvenanceSource(engine=engine or None, model=model, origin="ai",
                            agent=None)


def describe_provenance(finding: Any) -> dict[str, Any]:
    """Display-safe provenance/evidence view of one finding (V4-E04-T04).

    The single place a Python renderer (PR comment, step summary, CLI)
    should ask "why was I told this?". Works on any Finding-like object --
    pre-V4 findings, hand-built doubles, tampered rows -- and NEVER raises:
    a finding with nothing recorded answers ``available: False`` plus a
    ``reason``, so it renders as "provenance unavailable", not a crash and
    not a silent blank.

    Everything returned is redacted, single-line and bounded. Evidence is
    *cited*, not quoted: ``kind``/``locator``/``check_type`` and an
    integrity flag, never the summary text (which can quote untrusted
    code). Locators have backticks neutralised so a renderer can wrap them
    in a markdown code span without the span being escapable.
    """
    def field(obj: Any, name: str) -> str | None:
        return _safe_line(getattr(obj, name, None), MAX_PROVENANCE_FIELD_CHARS)

    raw_sources = getattr(finding, "provenance_sources", None)
    sources = []
    for s in (tuple(raw_sources) if isinstance(raw_sources, (list, tuple))
              else ())[:MAX_PROVENANCE_SOURCES]:
        sources.append({k: field(s, k)
                        for k in ("engine", "model", "origin", "agent")})
    engine = field(finding, "provenance_engine")
    model = field(finding, "provenance_model")
    origin = field(finding, "provenance_origin")
    available = bool(engine or model or origin or sources)

    raw_evidence = getattr(finding, "evidence", None)
    evidence_all = (tuple(raw_evidence)
                    if isinstance(raw_evidence, (list, tuple)) else ())
    evidence = []
    for e in evidence_all[:MAX_EVIDENCE_PER_FINDING]:
        locator = _safe_line(getattr(e, "locator", None),
                             MAX_EVIDENCE_LOCATOR_CHARS)
        if not locator:
            continue
        try:
            intact = bool(e.integrity_ok)
        except Exception:               # noqa: BLE001 - a double without it
            intact = False
        evidence.append({
            "kind": _safe_line(getattr(e, "kind", None), 32) or "",
            "locator": locator.replace("`", "'"),
            "check_type": _safe_line(getattr(e, "check_type", None),
                                     MAX_EVIDENCE_CHECK_TYPE_CHARS),
            "integrity_ok": intact,
        })
    merged = getattr(finding, "merged_fingerprints", None)
    return {
        "available": available,
        "reason": None if available else PROVENANCE_UNAVAILABLE_REASON,
        "engine": engine, "model": model, "origin": origin,
        "sources": sources,
        "evidence": evidence,
        "evidence_total": len(evidence_all),
        "merged_count": len(merged) if isinstance(merged, (list, tuple)) else 0,
    }

# Verification statuses (V3 C4). ``None``/"" means "not verified", which is
# distinct from VERIFICATION_UNVERIFIED ("checked, inconclusive").
VERIFICATION_RESOLVED = "resolved"
VERIFICATION_PRESENT = "still_present"
VERIFICATION_UNVERIFIED = "unable_to_verify"
VERIFICATION_STATUSES = (
    VERIFICATION_RESOLVED, VERIFICATION_PRESENT, VERIFICATION_UNVERIFIED,
)


def _enum_value(v: Any) -> Any:
    """Return the plain value for an Enum member, else the value unchanged."""
    return v.value if isinstance(v, Enum) else v


def _opt_str(v: Any) -> str | None:
    """None/blank -> None, otherwise the stripped string."""
    if v is None:
        return None
    return str(_enum_value(v)).strip() or None


def _normalize_state(v: Any) -> str:
    """Coerce a stored/incoming finding state to a valid value ("new" if unknown)."""
    s = str(_enum_value(v)).strip().lower() if v is not None else ""
    return s if s in VALID_FINDING_STATES else FindingState.NEW.value


def _opt_rule_id(v: Any) -> str | None:
    """Coerce an incoming ``rule_id`` to the V3 contract (str | None).

    Model output and tampered storage rows are attacker-steerable: strings
    are stripped and bounded, plain JSON numbers become their decimal
    string, and anything else (nested objects/arrays, booleans) is dropped
    to None rather than stringified into a report row.
    """
    if v is None or isinstance(v, (bool, dict, list, tuple, set)):
        return None
    s = str(v).strip()[:MAX_RULE_ID_CHARS]
    return s or None


@dataclass
class Finding:
    """A single issue the reviewer flagged in the diff."""

    file: str
    line: int | None            # line number in the NEW file (None => file-level note)
    end_line: int | None = None
    severity: str = "medium"    # info | low | medium | high | critical
    category: str = "bug"
    title: str = ""
    explanation: str = ""
    suggestion: str | None = None   # replacement code snippet (optional)
    confidence: str = "medium"      # low | medium | high
    rule_id: str | None = None      # set by the heuristic analyzer
    # --- V2 lifecycle / identity (appended; all optional, see LIFECYCLE_FIELDS) ---
    fingerprint: str | None = None      # stable identity (findings.fingerprint_finding)
    state: str = "new"                  # FindingState value
    first_seen_sha: str | None = None
    last_seen_sha: str | None = None
    resolved_at: str | None = None      # ISO-8601 timestamp
    github_comment_id: int | None = None
    # --- V3 C4 verification (pipeline-owned; see LIFECYCLE_FIELDS) ---
    # None until a finding has previous state to compare against.
    verification_status: str | None = None    # VERIFICATION_* value
    verification_reason: str | None = None    # human-readable explanation
    verified_at: str | None = None            # ISO-8601 timestamp
    # --- V4-E04 provenance (pipeline-owned; see LIFECYCLE_FIELDS) ---
    # Set by the orchestrator from AnalysisOutcome; never from model output.
    provenance_engine: str | None = None     # "claude" | "openai" | "gemini" | "static"
    provenance_model: str | None = None      # model identifier
    provenance_agent: str | None = None      # specialist agent name (V5+; None today)
    provenance_origin: str | None = None     # "ai" | "static" | "rule"
    # --- V4-E04 T02/T03 (pipeline-owned; see LIFECYCLE_FIELDS) ---
    # provenance_sources: every engine/model that produced (or merged into)
    # this finding -- the scalar fields above mirror the first source. It is
    # populated by the orchestrator, and ``from_untrusted_dict`` strips it
    # like every other pipeline-owned field.
    provenance_sources: tuple[ProvenanceSource, ...] = ()
    # evidence: embedded, machine-checkable records (ADR-004 V4 staging) --
    # redacted at construction, bounded in count/size, never model-supplied.
    evidence: tuple[EvidenceRecord, ...] = ()
    # merged_fingerprints: v1 fingerprints folded into this finding by
    # dedup (V4-E05) -- an audit trail so a merge is never silent.
    merged_fingerprints: tuple[str, ...] = ()

    def __setattr__(self, name: str, value: Any) -> None:
        """V4-E04: the scalar provenance strings are redacted, single-line
        and bounded on EVERY assignment -- the constructor, ``replace`` and
        the orchestrator's plain ``f.provenance_model = ...`` alike.

        ``to_dict`` sanitizes the report boundary, but renderers that read
        the attribute directly (the PR-comment ``source: engine (model)``
        suffix) would otherwise see the raw value. Clean values are stored
        unchanged. Nothing else about assignment changes.
        """
        if name in _PROVENANCE_SCALARS:
            value = _safe_line(value, MAX_PROVENANCE_FIELD_CHARS)
        object.__setattr__(self, name, value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "severity": self.severity,
            "category": self.category if self.category in VALID_CATEGORIES else "bug",
            "title": self.title,
            "explanation": self.explanation,
            "suggestion": self.suggestion,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
            "fingerprint": self.fingerprint,
            "state": _normalize_state(self.state),
            "first_seen_sha": self.first_seen_sha,
            "last_seen_sha": self.last_seen_sha,
            "resolved_at": self.resolved_at,
            "github_comment_id": self.github_comment_id,
            "verification_status": self.verification_status,
            "verification_reason": self.verification_reason,
            "verified_at": self.verified_at,
            # V4-E04: redacted/single-line/bounded at the report boundary
            # too (clean values pass through byte-identically): the
            # orchestrator assigns these attributes directly, so no
            # constructor ever saw them.
            "provenance_engine": _safe_line(
                self.provenance_engine, MAX_PROVENANCE_FIELD_CHARS),
            "provenance_model": _safe_line(
                self.provenance_model, MAX_PROVENANCE_FIELD_CHARS),
            "provenance_agent": _safe_line(
                self.provenance_agent, MAX_PROVENANCE_FIELD_CHARS),
            "provenance_origin": _safe_line(
                self.provenance_origin, MAX_PROVENANCE_FIELD_CHARS),
            # V4-E04 T02/T03 (additive): multi-source provenance and the
            # embedded evidence records, serialized in stable order.
            "provenance_sources": [s.to_dict() for s in self.provenance_sources],
            "evidence": [e.to_dict() for e in self.evidence],
            "merged_fingerprints": list(self.merged_fingerprints),
        }

    def redact_text(self, scrub=None) -> None:
        """V4-E08-T05: redact credential-looking text in the finding's
        user-visible fields, in place.

        Field-level half of the output redaction chokepoint: the
        orchestrator calls this at the single point where engine output
        crosses into the pipeline, so every sink that later reads
        ``title`` / ``explanation`` / ``suggestion`` -- inline comment
        bodies, the markdown summary comment, JSON/markdown report
        artifacts, GitHub step summaries, dashboard uploads and persisted
        finding rows -- consumes already-redacted fields instead of each
        sink re-implementing the policy. ``scrub`` lets the caller layer a
        stronger replacement (the orchestrator adds exact
        configured-credential removal on top of ``redact_secrets``).
        Idempotent, never raises, and only rewrites *text values* -- no
        schema or field-type change.
        """
        fn = scrub if scrub is not None else redact_secrets
        if isinstance(self.title, str):
            self.title = fn(self.title)
        if isinstance(self.explanation, str):
            self.explanation = fn(self.explanation)
        if isinstance(self.suggestion, str):
            self.suggestion = fn(self.suggestion)

    @classmethod
    def from_untrusted_dict(cls, d: dict[str, Any]) -> "Finding":
        """Like :meth:`from_dict`, but discards pipeline-owned lifecycle fields.

        Use this for anything a model produced (Claude JSON): output influenced
        by an untrusted diff must not be able to set ``state``, ``fingerprint``
        or ``github_comment_id``. Use :meth:`from_dict` only for data we wrote
        ourselves (storage, dashboard payloads).
        """
        return cls.from_dict({k: v for k, v in d.items() if k not in LIFECYCLE_FIELDS})

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        """Lenient reader for data we wrote ourselves (storage, dashboard
        payloads) and, via :meth:`from_untrusted_dict`, for model output.

        Lenient: malformed values degrade to defaults, never raise — a bad
        row must not lose a review. Neutral with respect to redaction and
        lifecycle: those belong to the output chokepoint and the load
        boundaries, not here. The enum-shaped fields ARE validated here
        (severity, category, confidence) because they are rendered and
        serialized verbatim and both model output and tampered rows are
        attacker-steerable; ``suggestion``/``rule_id`` are coerced to the
        frozen V3 field types (str|None) so nested junk can neither
        smuggle text past redact_text nor violate the report contract.
        """
        sev = str(d.get("severity", "medium")).lower()
        cat = str(d.get("category", "bug")).lower()
        conf = str(d.get("confidence", DEFAULT_CONFIDENCE)).lower()
        comment_id = d.get("github_comment_id")
        vstatus = str(d.get("verification_status") or "").strip().lower()
        suggestion = d.get("suggestion")
        if suggestion is not None and not isinstance(suggestion, str):
            suggestion = None
        return cls(
            file=str(d.get("file", "")),
            line=int(d["line"]) if d.get("line") is not None else None,
            end_line=int(d["end_line"]) if d.get("end_line") is not None else None,
            severity=sev if sev in SEVERITY_ORDER else "medium",
            category=cat if cat in VALID_CATEGORIES else "bug",
            title=str(d.get("title", "Issue")).strip() or "Issue",
            explanation=str(d.get("explanation", "")).strip(),
            suggestion=suggestion,
            confidence=conf if conf in VALID_CONFIDENCES else DEFAULT_CONFIDENCE,
            rule_id=_opt_rule_id(d.get("rule_id")),
            fingerprint=_opt_str(d.get("fingerprint")),
            state=_normalize_state(d.get("state")),
            first_seen_sha=_opt_str(d.get("first_seen_sha")),
            last_seen_sha=_opt_str(d.get("last_seen_sha")),
            resolved_at=_opt_str(d.get("resolved_at")),
            github_comment_id=int(comment_id) if comment_id not in (None, "") else None,
            verification_status=vstatus if vstatus in VERIFICATION_STATUSES else None,
            verification_reason=_opt_str(d.get("verification_reason")),
            verified_at=_opt_str(d.get("verified_at")),
            provenance_engine=_safe_line(d.get("provenance_engine"),
                                         MAX_PROVENANCE_FIELD_CHARS),
            provenance_model=_safe_line(d.get("provenance_model"),
                                        MAX_PROVENANCE_FIELD_CHARS),
            provenance_agent=_safe_line(d.get("provenance_agent"),
                                        MAX_PROVENANCE_FIELD_CHARS),
            provenance_origin=_safe_line(d.get("provenance_origin"),
                                         MAX_PROVENANCE_FIELD_CHARS),
            provenance_sources=_sources_from_any(d.get("provenance_sources")),
            evidence=_evidence_from_any(d.get("evidence")),
            merged_fingerprints=_str_tuple(d.get("merged_fingerprints")),
        )


@dataclass
class ReviewStats:
    files: int = 0
    additions: int = 0
    deletions: int = 0
    hunks: int = 0
    batches: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files": self.files, "additions": self.additions,
            "deletions": self.deletions, "hunks": self.hunks, "batches": self.batches,
        }


@dataclass
class PRContext:
    """Metadata about the pull request under review."""

    repo: str
    pr_number: int
    pr_title: str = ""
    author: str = ""
    branch: str = ""
    base: str = ""
    head_sha: str = ""
    url: str = ""
    base_sha: str = ""          # V2: SHA of the base branch tip (appended; keep last)


@dataclass
class ReviewKey:
    """Deterministic identity of one review: repository + PR + head commit."""

    repo: str
    pr_number: int
    head_sha: str

    def as_id(self) -> str:
        # The shared writer for the id parse_review_id reads back
        # (V3-E04-T03): owner/repo#pr@sha12.
        return format_review_id(self.repo, self.pr_number, self.head_sha)


@dataclass
class ReviewResult:
    """Full result of one PR review run."""

    pr: PRContext
    mode: str = "mock"                # "claude" | "mock"
    model: str = ""
    reviewed_at: str = ""
    duration_ms: int = 0
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    stats: ReviewStats = field(default_factory=ReviewStats)
    posted_inline: int = 0
    suppressed: int = 0               # reported findings over the inline-comment cap
    below_threshold: list[Finding] = field(default_factory=list)  # D3: anchored
                                      # findings under the severity threshold —
                                      # retained in the report, never counted
                                      # towards findings_count / inline comments
    warnings: list[str] = field(default_factory=list)
    health_score: int = 100
    health_grade: str = "A+"
    # V3-E02-T02 (append-only): the allowlisted, redacted telemetry row —
    # already serialized by telemetry.to_telemetry_row (or None when the
    # backend produced no telemetry, e.g. pre-V3 test doubles).
    telemetry: dict | None = None

    def count_by_severity(self) -> dict[str, int]:
        out = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            out[f.severity] = out.get(f.severity, 0) + 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "pr": {
                "repo": self.pr.repo,
                "number": self.pr.pr_number,
                # V4-E08-T05: PR metadata is author-controlled free text that
                # reaches the report, the dashboard push and the artifact.
                "title": redact_secrets(self.pr.pr_title or ""),
                "author": redact_secrets(self.pr.author or ""),
                "branch": redact_secrets(self.pr.branch or ""),
                "base": self.pr.base,
                "head_sha": self.pr.head_sha,
                "url": self.pr.url,
            },
            "mode": self.mode,
            "model": self.model,
            "reviewed_at": self.reviewed_at,
            "duration_ms": self.duration_ms,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "below_threshold": [f.to_dict() for f in self.below_threshold],
            "stats": self.stats.to_dict(),
            "posted_inline": self.posted_inline,
            "suppressed": self.suppressed,
            # V4-E08-T04: report JSON + dashboard push read warnings here.
            "warnings": sanitize_warnings(self.warnings),
            "health_score": self.health_score,
            "health_grade": self.health_grade,
            # V3-E02-T06: the report boundary re-applies the same
            # allowlist + redaction sanitizer (idempotent), so report
            # JSON can only ever carry the approved telemetry structure
            # even if a caller set the field directly. None stays None.
            "telemetry": sanitize_telemetry(self.telemetry)
            if self.telemetry is not None else None,
            # V4-E04-T04 (D10): PR-level risk (C8) and fix-verification
            # counts (C4) — both already rendered by the markdown summary
            # (reporter._risk_row / _verification_row), now surfaced in
            # JSON additively. Always present: None when the orchestrator
            # did not compute them (null-with-reason, E04-T01), so
            # consumers see one stable shape, never key-existence branches.
            "risk": _risk_json(getattr(self, "risk", None)),
            "verification": _verification_json(
                getattr(self, "verification", None)),
            # V4-E09: absent unless feedback.enabled (byte-identical to V3).
            **(getattr(self, "feedback_report_fields", None) or {}),
        }


# ------------------------------------------- V4-E04-T04 · D10 surfacing
# `risk` / `verification` reach the report as bounded, closed-vocab blocks:
# the same data the markdown summary renders, with the same "absent is
# null, never a crash" contract the report boundary applies everywhere.

_RISK_LEVELS = frozenset({"low", "high"})


def _risk_json(risk: object) -> dict | None:
    """``ReviewRisk`` -> ``{"level", "reasons"}``; None when uncomputed.

    * level folds to the closed vocab ``{"low", "high"}`` —
      ``classify_risk`` only ever produces those two; anything else reads
      as "low", matching the markdown row's not-high-is-green semantics;
    * reasons are free text embedding diff paths, so each passes through
      ``redact_secrets()`` like every other stored free text (V4 security
      invariant), each is length-bounded, and the list is capped — a
      report field can never grow without bound.
    """
    if risk is None:
        return None
    level = str(getattr(risk, "level", "") or "low")
    reasons: list[str] = []
    for raw in (getattr(risk, "reasons", None) or [])[:10]:
        text = redact_secrets(str(raw)).strip()
        if text:
            reasons.append(text[:500])
    return {"level": level if level in _RISK_LEVELS else "low",
            "reasons": reasons}


def _verification_json(verification: object) -> dict | None:
    """``verification_counts()`` dict -> the three C4 keys as non-negative
    ints; None when uncomputed. Unknown keys are dropped (allowlist) and
    malformed values become 0 — a count can never read back negative or
    smuggle a payload. The key literals mirror
    ``reporter._verification_row`` (the same C4 vocabulary the markdown
    row reads)."""
    if not isinstance(verification, dict):
        return None
    out: dict[str, int] = {}
    for key in ("resolved", "still_present", "unable_to_verify"):
        try:
            count = int(verification.get(key, 0))
        except (TypeError, ValueError):
            count = 0
        out[key] = max(0, count)
    return out


@dataclass
class AnalysisOutcome:
    """What an analysis backend (Claude or static) returns for a review.

    Moved here from ``analyzer.py`` (V2) so providers, the router and the
    orchestrator can share it without importing the analyzer module. The first
    five fields are unchanged and keep their order (positional construction).
    """

    findings: list[Finding]
    summary: str
    mode: str
    model: str
    warnings: list[str] = field(default_factory=list)
    engine: str = ""                # "claude" | "static" | "claude+static"
    fallback_used: bool = False
    batch_count: int = 0
    # V3-E02-T02 (append-only): per-run telemetry — tokens/latency/model/
    # fallback events, serialized exclusively via telemetry.to_telemetry_row.
    telemetry: RunTelemetry | None = None
