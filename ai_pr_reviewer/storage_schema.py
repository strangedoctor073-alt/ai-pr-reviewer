"""Cross-store schema contract: key formats, magic literals, capabilities.

One module owns every string that ties the storage implementations
together — engine SQLite (``LocalReviewStorage``), dashboard SQL
(``DbStorage``), dashboard JSON (``JsonStorage``) and the HTTP client
they all speak to — per V3-E04-T03. A key is *built* here, a
``review_id`` is *parsed* here, the mute-row prefix lives here, the
capability names backends declare live here, and every backend's prune
job computes its retention cutoff here (V3-E04-T02) so one policy
definition serves all three; the backends import these helpers instead
of re-deriving the formats, so the C9 duplication cannot silently drift
apart again.

Deliberately a **leaf**: stdlib only, no imports from the rest of the
engine, so ``storage.py`` / ``models.py`` / ``memory.py`` can import it
at module level without a cycle, and the dashboard can import it lazily
(the same pattern as the sandbox's and memory categories' engine use).

Ownership is enforced by ``tests/test_storage_schema.py``: within
``ai_pr_reviewer/`` and ``dashboard/``, the exact literal
``"fingerprint:"``, ``.split("#", 1)`` review-id parsing and the
``}#{`` key-building f-strings may appear only in this file.
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta, timezone

# ------------------------------------------------------------------ mute rows
# A mute (dismissed finding) is stored as a repo-memory row whose
# path_pattern is "fingerprint:<fp>" — it is a decision, never a rule
# (D3/D7); everything that reads or writes mute rows goes through these.

MUTE_PREFIX = "fingerprint:"


def mute_pattern(fingerprint: str) -> str:
    """The ``path_pattern`` a mute row uses for ``fingerprint``."""
    return f"{MUTE_PREFIX}{fingerprint}"


def is_mute_pattern(pattern) -> bool:
    """True when ``pattern`` marks a mute row rather than a path glob."""
    return str(pattern or "").startswith(MUTE_PREFIX)


def mute_fingerprint(pattern) -> str | None:
    """The fingerprint behind a mute row; None for non-mute/empty patterns.

    ``"fingerprint:"`` with nothing after it is malformed and yields
    None (never an empty fingerprint), matching what the HTTP client
    and the SQLite backend always did with such rows.
    """
    text = str(pattern or "")
    if not text.startswith(MUTE_PREFIX):
        return None
    return text[len(MUTE_PREFIX):].strip() or None


# ----------------------------------------------------------------- review ids
def format_review_id(repo: str, pr_number, sha: str) -> str:
    """``owner/repo#pr@sha12`` — the id a review run persists under."""
    return f"{repo}#{pr_number}@{str(sha)[:12]}"


def parse_review_id(review_id) -> tuple[str, int]:
    """``owner/repo#pr@sha`` -> ``(repo, pr)``; malformed -> ``("", 0)``.

    The single reader for the format ``format_review_id`` writes. ``#``
    and ``@`` must both be present and the pr segment must parse as an
    integer; on an integer-parse failure the repo half is kept (``repo,
    0``) — byte-for-byte the lenient semantics every backend had before
    V3-E04-T03 refactored them onto this function.
    """
    repo, pr_number = "", 0
    text = str(review_id or "")
    if "#" in text and "@" in text:
        try:
            repo = text.split("#", 1)[0]
            pr_number = int(text.split("#", 1)[1].split("@", 1)[0])
        except Exception:
            pass
    return repo, pr_number


# -------------------------------------------------------------- cross-store keys
def repo_pr_key(repo: str, pr_number) -> str:
    """``owner/repo#pr`` — the review-state row id and bare review id."""
    return f"{repo}#{pr_number}"


def finding_history_key(repo, pr_number, fingerprint) -> str:
    """``owner/repo#pr#fingerprint`` — the finding-history row id."""
    return f"{repo}#{pr_number}#{fingerprint}"


def memory_row_key(repo: str) -> str:
    """A unique ``owner/repo#<8 hex>`` id for a dashboard memory row."""
    return f"{repo}#{uuid.uuid4().hex[:8]}"


# --------------------------------------------------------- storage capabilities
# A capability is *the name of a method* a storage backend may provide.
# Backends declare ``capabilities: frozenset[str]``; callers branch on it
# through ``ai_pr_reviewer.storage.has_capability`` instead of probing
# with getattr (V3-E04-T04). Core protocol methods are named here too so
# call sites that defensively fall back (previous findings, repo memory)
# share one vocabulary with the genuinely optional capabilities.
CAP_STATE_READ = "get_last_reviewed_sha"
CAP_STATE_WRITE = "set_last_reviewed_sha"
CAP_PREVIOUS_FINDINGS = "get_previous_findings"
CAP_SAVE_FINDINGS = "save_findings"
CAP_REPO_MEMORY = "get_repo_memory"
CAP_LIST_REPO_MEMORY = "list_repo_memory"
CAP_DISMISSED_FINGERPRINTS = "get_dismissed_fingerprints"
CAP_TELEMETRY = "save_telemetry"
CAP_PRUNE = "prune"

#: The five protocol methods every backend must provide. Optional
#: capabilities are OR-ed onto this by each backend's declaration.
CORE_CAPABILITIES = frozenset({
    CAP_STATE_READ,
    CAP_STATE_WRITE,
    CAP_PREVIOUS_FINDINGS,
    CAP_SAVE_FINDINGS,
    CAP_REPO_MEMORY,
})


# ----------------------------------------------------------------- retention
def retention_cutoff(retention_days, now: datetime | None = None) -> str | None:
    """ISO-8601 UTC cutoff for retention pruning, or None when disabled.

    ``retention_days <= 0`` means keep-everything — the default — so
    adding the retention knob changes no behavior until an operator opts
    in (V3-E04-T02). The returned timestamp uses the same
    ``+00:00``-suffixed, second-precision format every writer stores, so
    backends compare it lexicographically against ``updated_at``. A
    non-numeric value disables pruning rather than raising; the config
    layer already rejects garbage inputs strictly (D6).
    """
    try:
        days = int(retention_days)
    except (TypeError, ValueError):
        return None
    if days <= 0:
        return None
    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return (moment - timedelta(days=days)).isoformat(timespec="seconds")


def is_stale(updated_at, cutoff: str) -> bool:
    """True only for a non-empty timestamp strictly older than ``cutoff``.

    The Python half of the retention predicate (V3-E04-T02): ``None``,
    ``""`` and any non-string are unknown ages and are never stale, so
    pruning only ever removes rows whose age we positively know. The SQL
    backends express the same rule as
    ``updated_at IS NOT NULL AND updated_at <> '' AND updated_at < ?``.
    """
    if not isinstance(updated_at, str) or not updated_at:
        return False
    return updated_at < cutoff


# =====================================================================
# V4-E09 · feedback & suppression schema contract
#
# Two additive tables, scoped per repository on every row:
#
#   feedback_events    — one row per human vote (up / down / mute) on a
#                        finding fingerprint. A *record*: nothing in the
#                        engine ever reads these rows to change behavior.
#   suppression_rules  — one row per human-authored rule that parks
#                        matching findings (state "muted") and counts them.
#
# THE INVARIANT (V4_THREAT_MODEL.md §4): a suppression rule can only be
# created by an authenticated dashboard or CLI action. This module is the
# schema half of that guarantee, enforced *by construction*:
#
#   * ``origin`` is NOT NULL and CHECK-constrained to ``RULE_ORIGINS`` — a
#     row whose origin is anything else (a model, a PR, "engine") cannot
#     be inserted by any code path, including a buggy one.
#   * a rule's *shape* is CHECK-constrained so it can never match
#     "everything": a fingerprint rule needs a fingerprint, a rule_path
#     rule needs an exact rule id.
#   * ``expires_at`` is NOT NULL — "never expires" is not representable.
#   * free-text columns carry length CHECKs (stored rule size cap).
#
# The write half (who may call the writers) lives in ``feedback_admin``;
# the engine-side read model lives in ``feedback``. This module stays a
# stdlib-only leaf so both, and the dashboard, can import it freely.
# =====================================================================

FEEDBACK_EVENTS_TABLE = "feedback_events"
SUPPRESSION_RULES_TABLE = "suppression_rules"

#: Vote kinds. Same vocabulary as the V3 ``/api/findings/{fp}/feedback``
#: route so one UI can speak both; a "mute" *event* is only a record — the
#: V3 mute decision itself stays a memory row owned by that route.
FEEDBACK_KINDS = ("up", "down", "mute")

#: How a rule selects findings. Both are *exact* selectors by design:
#: a v1 fingerprint, or one exact finding ``rule_id`` limited to a path glob.
#: There is deliberately no "all findings" / "all rules" selector.
RULE_MATCH_FINGERPRINT = "fingerprint"
RULE_MATCH_RULE_PATH = "rule_path"
RULE_MATCH_KINDS = (RULE_MATCH_FINGERPRINT, RULE_MATCH_RULE_PATH)

#: The only two origins a rule or event row may carry. Never taken from
#: request bodies, PR content or model output — derived from which
#: authenticated entry point performed the write.
ORIGIN_DASHBOARD = "dashboard"
ORIGIN_CLI = "cli"
RULE_ORIGINS = (ORIGIN_DASHBOARD, ORIGIN_CLI)

# ------------------------------------------------------------------- caps
# Every cap is a named, importable constant (the D13 convention) and is
# enforced at the write boundary (``feedback_admin``) — tests/test_feedback.py
# drives each one to its limit.
#: Rules that can be *in force* (not disabled, not expired) per repository.
MAX_ACTIVE_RULES_PER_REPO = 100
#: Rows kept per repository in any state; inactive rows are purged first.
MAX_STORED_RULES_PER_REPO = 400
#: Rule-creation rate: new rules per repository in any rolling hour.
MAX_RULE_CREATES_PER_HOUR = 30
#: Vote rows kept per repository (oldest dropped first — a ring buffer).
MAX_EVENTS_PER_REPO = 5_000
#: Vote-creation rate: events per repository in any rolling hour.
MAX_EVENTS_PER_HOUR = 120
#: Stored rule size: total UTF-8 bytes across a rule's text fields.
MAX_RULE_BYTES = 1_024
MAX_REASON_CHARS = 500
MAX_EVENT_NOTE_CHARS = 500
MAX_FINGERPRINT_CHARS = 64
MAX_RULE_ID_CHARS = 200
MAX_PATH_GLOB_CHARS = 255
MAX_PATH_GLOB_WILDCARDS = 8
#: Default and ceiling for a rule's lifetime. Every rule expires.
DEFAULT_RULE_TTL_DAYS = 30
MAX_RULE_TTL_DAYS = 365
#: Inactive (expired / disabled) rows are kept this long for audit, then
#: become purgeable when a repository needs the room.
INACTIVE_RULE_RETENTION_DAYS = 30
#: Engine read side: never apply more than this many rules in one run,
#: whatever a (possibly tampered) store returns.
MAX_RULES_APPLIED_PER_RUN = 200
#: Effectiveness evaluation reads at most this many stored finding rows.
MAX_EVAL_FINDING_ROWS = 2_000

# ------------------------------------------------------- field grammars
#: v1 finding fingerprint (findings.fingerprint_finding): lowercase hex.
FINGERPRINT_RE = re.compile(r"[0-9a-f]{8,64}")
#: An exact finding ``rule_id`` (static-engine ids such as ``SEC-001``).
RULE_ID_RE = re.compile(r"[A-Za-z0-9_.:\-]{1,200}")
#: ``owner/name`` exactly as the rest of the system keys repositories.
REPO_RE = re.compile(r"[A-Za-z0-9_.\-]{1,100}/[A-Za-z0-9_.\-]{1,100}")
#: A path glob: no spaces, backslashes or ``..`` segments (checked in code).
PATH_GLOB_RE = re.compile(r"[A-Za-z0-9_.\-/*?\[\]@+~]{1,255}")
#: A rule id minted by the dashboard: ``sup_`` + 20 hex.
RULE_ROW_ID_RE = re.compile(r"sup_[0-9a-f]{20}")


def new_feedback_event_id() -> str:
    """``fbe_<20 hex>`` — server-minted; clients never choose row ids."""
    return f"fbe_{uuid.uuid4().hex[:20]}"


def new_suppression_rule_id() -> str:
    """``sup_<20 hex>`` — server-minted; clients never choose row ids."""
    return f"sup_{uuid.uuid4().hex[:20]}"


# --------------------------------------------------------------- columns
FEEDBACK_EVENT_COLUMNS = (
    "id", "repo", "fingerprint", "kind", "note", "origin", "created_at",
)
SUPPRESSION_RULE_COLUMNS = (
    "id", "repo", "match_kind", "fingerprint", "rule_id", "path_glob",
    "reason", "origin", "created_at", "expires_at", "disabled_at",
    "updated_at",
)


def _sql_in(column: str, values) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


#: ``(constraint name, SQL)`` pairs: the single source for both the engine's
#: SQLite DDL below and the dashboard's SQLAlchemy models, so the two can
#: never disagree about what a legal row is (asserted by a parity test).
FEEDBACK_EVENT_CHECKS = (
    ("ck_feedback_events_kind", _sql_in("kind", FEEDBACK_KINDS)),
    ("ck_feedback_events_origin", _sql_in("origin", RULE_ORIGINS)),
    ("ck_feedback_events_note_len",
     f"length(note) <= {MAX_EVENT_NOTE_CHARS}"),
)
SUPPRESSION_RULE_CHECKS = (
    ("ck_suppression_rules_origin", _sql_in("origin", RULE_ORIGINS)),
    ("ck_suppression_rules_match_kind",
     _sql_in("match_kind", RULE_MATCH_KINDS)),
    # A rule can never match everything: each kind must name its target.
    ("ck_suppression_rules_shape",
     f"((match_kind = '{RULE_MATCH_FINGERPRINT}' AND fingerprint <> '' "
     f"AND rule_id = '' AND path_glob = '') OR "
     f"(match_kind = '{RULE_MATCH_RULE_PATH}' AND rule_id <> '' "
     f"AND path_glob <> '' AND fingerprint = ''))"),
    # Every rule expires: "never" is not representable.
    ("ck_suppression_rules_expires", "expires_at <> ''"),
    ("ck_suppression_rules_reason_len",
     f"length(reason) <= {MAX_REASON_CHARS}"),
    ("ck_suppression_rules_glob_len",
     f"length(path_glob) <= {MAX_PATH_GLOB_CHARS}"),
    ("ck_suppression_rules_rule_id_len",
     f"length(rule_id) <= {MAX_RULE_ID_CHARS}"),
    ("ck_suppression_rules_fp_len",
     f"length(fingerprint) <= {MAX_FINGERPRINT_CHARS}"),
)


def feedback_local_ddl() -> str:
    """SQLite DDL for both tables (idempotent, additive).

    Used by tooling/tests that seed an engine-local database. The engine
    itself never executes it: ``LocalReviewStorage`` only *reads* these
    tables, and does so only when they already exist — a V3 database file
    is never altered by merely opening it with feedback disabled.
    """
    ev_checks = ",\n    ".join(f"CONSTRAINT {n} CHECK ({s})"
                               for n, s in FEEDBACK_EVENT_CHECKS)
    ru_checks = ",\n    ".join(f"CONSTRAINT {n} CHECK ({s})"
                               for n, s in SUPPRESSION_RULE_CHECKS)
    return f"""
CREATE TABLE IF NOT EXISTS {FEEDBACK_EVENTS_TABLE} (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL,
    created_at TEXT NOT NULL,
    {ev_checks}
);
CREATE INDEX IF NOT EXISTS ix_feedback_events_repo_created
    ON {FEEDBACK_EVENTS_TABLE} (repo, created_at);
CREATE INDEX IF NOT EXISTS ix_feedback_events_repo_fingerprint
    ON {FEEDBACK_EVENTS_TABLE} (repo, fingerprint);
CREATE TABLE IF NOT EXISTS {SUPPRESSION_RULES_TABLE} (
    id TEXT PRIMARY KEY,
    repo TEXT NOT NULL,
    match_kind TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '',
    rule_id TEXT NOT NULL DEFAULT '',
    path_glob TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    origin TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    disabled_at TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    {ru_checks}
);
CREATE INDEX IF NOT EXISTS ix_suppression_rules_repo
    ON {SUPPRESSION_RULES_TABLE} (repo, expires_at);
"""


# ----------------------------------------------------------- capabilities
#: Engine-readable: ``get_suppression_rules(repo)`` -> active rule rows for
#: exactly that repository. Declared by every backend that can supply rules.
CAP_SUPPRESSION_RULES = "get_suppression_rules"
#: Rule *authoring*. Declared ONLY by the dashboard backends — never by
#: ``LocalReviewStorage`` or ``DashboardStorageClient`` (the engine's two
#: storage classes), which is what makes "the engine cannot write a rule"
#: a structural fact rather than a convention. Pinned by tests.
CAP_FEEDBACK_ADMIN = "create_suppression_rule"
#: Every storage method that creates or mutates a rule or event row. The
#: AST call-graph test asserts the only call sites are the dashboard routes.
FEEDBACK_WRITE_METHODS = frozenset({
    "create_suppression_rule",
    "disable_suppression_rule",
    "disable_all_suppression_rules",
    "record_feedback_event",
})


# ------------------------------------------------------------------ time
def feedback_now(now: datetime | None = None) -> datetime:
    """A timezone-aware UTC ``now`` (injectable so expiry tests never sleep)."""
    moment = now if now is not None else datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def feedback_iso(moment: datetime) -> str:
    """Second-precision ``+00:00`` ISO-8601 — the format every writer here
    stores, so SQL/JSON backends compare timestamps lexicographically."""
    return feedback_now(moment).isoformat(timespec="seconds")


def parse_feedback_iso(value) -> datetime | None:
    """Parse a stored timestamp; unparseable/blank -> None (never raises)."""
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        moment = datetime.fromisoformat(value.strip())
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)
