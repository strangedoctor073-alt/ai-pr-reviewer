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
