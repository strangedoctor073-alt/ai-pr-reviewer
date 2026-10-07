"""Core data models shared across the review pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

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
)

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
            "provenance_engine": self.provenance_engine,
            "provenance_model": self.provenance_model,
            "provenance_agent": self.provenance_agent,
            "provenance_origin": self.provenance_origin,
        }

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
        sev = str(d.get("severity", "medium")).lower()
        comment_id = d.get("github_comment_id")
        vstatus = str(d.get("verification_status") or "").strip().lower()
        return cls(
            file=str(d.get("file", "")),
            line=int(d["line"]) if d.get("line") is not None else None,
            end_line=int(d["end_line"]) if d.get("end_line") is not None else None,
            severity=sev if sev in SEVERITY_ORDER else "medium",
            category=str(d.get("category", "bug")).lower(),
            title=str(d.get("title", "Issue")).strip() or "Issue",
            explanation=str(d.get("explanation", "")).strip(),
            suggestion=d.get("suggestion"),
            confidence=str(d.get("confidence", "medium")).lower(),
            rule_id=d.get("rule_id"),
            fingerprint=_opt_str(d.get("fingerprint")),
            state=_normalize_state(d.get("state")),
            first_seen_sha=_opt_str(d.get("first_seen_sha")),
            last_seen_sha=_opt_str(d.get("last_seen_sha")),
            resolved_at=_opt_str(d.get("resolved_at")),
            github_comment_id=int(comment_id) if comment_id not in (None, "") else None,
            verification_status=vstatus if vstatus in VERIFICATION_STATUSES else None,
            verification_reason=_opt_str(d.get("verification_reason")),
            verified_at=_opt_str(d.get("verified_at")),
            provenance_engine=_opt_str(d.get("provenance_engine")),
            provenance_model=_opt_str(d.get("provenance_model")),
            provenance_agent=_opt_str(d.get("provenance_agent")),
            provenance_origin=_opt_str(d.get("provenance_origin")),
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
                "title": self.pr.pr_title,
                "author": self.pr.author,
                "branch": self.pr.branch,
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
            "warnings": self.warnings,
            "health_score": self.health_score,
            "health_grade": self.health_grade,
            # V3-E02-T06: the report boundary re-applies the same
            # allowlist + redaction sanitizer (idempotent), so report
            # JSON can only ever carry the approved telemetry structure
            # even if a caller set the field directly. None stays None.
            "telemetry": sanitize_telemetry(self.telemetry)
            if self.telemetry is not None else None,
        }


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
