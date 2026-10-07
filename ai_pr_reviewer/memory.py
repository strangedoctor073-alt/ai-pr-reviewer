"""Project-memory helpers (V3 C7).

Repository memory is a *human-authored* note attached to a repo and an
optional path pattern — "always check None here", "this directory is
generated", "we accept this pattern on purpose". It is the only text that
gets promoted into a review's prompt from outside the diff, so this module
keeps the rules for reading it in one place:

* **mute rows are not project rules.** A ``fingerprint:<fp>`` path pattern
  is a dismissal decision written by the dashboard feedback endpoint. It
  must never surface as review advice, so it is split out here and read
  back through ``get_dismissed_fingerprints`` instead.
* **disabled rows are inert.** ``enabled == False`` keeps a note on the
  dashboard without feeding it to the reviewer.
* **everything stays untrusted.** Selection here is pure string matching;
  the caller (``context.build_context``) redacts secrets and the providers
  screen + nonce-fence the result before it can reach a prompt.

No PR content, repository file or model output is ever written to memory —
``LocalReviewStorage`` is deliberately read-only for ``repo_memory`` and
the engine has no ``add_repo_memory`` path.
"""
from __future__ import annotations

import fnmatch
from typing import Any, Iterable

from .storage_schema import MUTE_PREFIX   # single owner of the prefix (V3-E04-T03)

# Human-authored categories. Stored values are dashed (they travel through
# URLs and JSON); the reviewer prefixes notes with them so the prompt can
# tell "rule" from "known exception".
DEFAULT_CATEGORY = "project-rule"
CATEGORIES = (
    "project-rule",
    "preferred-pattern",
    "known-exception",
    "review-preference",
)

MAX_MEMORY_ENTRIES = 50     # bounded: a repo can't drown the prompt
MAX_NOTE_CHARS = 1_000      # per note, before the diff budget even applies


def normalize_category(raw: Any) -> str:
    """Coerce an arbitrary value to a known category (default otherwise)."""
    value = str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")
    return value if value in CATEGORIES else DEFAULT_CATEGORY


def is_mute_row(entry: dict[str, Any] | Any) -> bool:
    """True when the row is a dismissal fingerprint rather than a rule."""
    if isinstance(entry, dict):
        pattern = entry.get("path_pattern", "")
    else:
        pattern = getattr(entry, "path_pattern", "")
    return str(pattern or "").startswith(MUTE_PREFIX)


def entry_note(entry: dict[str, Any] | Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("note", "") or "")
    return str(getattr(entry, "note", "") or "")


def entry_pattern(entry: dict[str, Any] | Any) -> str:
    if isinstance(entry, dict):
        return str(entry.get("path_pattern", "") or "*")
    return str(getattr(entry, "path_pattern", "") or "*")


def entry_category(entry: dict[str, Any] | Any) -> str:
    raw = entry.get("category") if isinstance(entry, dict) else getattr(entry, "category", None)
    return normalize_category(raw)


def entry_enabled(entry: dict[str, Any] | Any) -> bool:
    raw = entry.get("enabled", True) if isinstance(entry, dict) else getattr(entry, "enabled", True)
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() not in ("0", "false", "no", "off")


def matches_paths(entry: dict[str, Any] | Any, paths: Iterable[str]) -> bool:
    """Path-scoped memory applies when any reviewed path matches the row's
    pattern; a ``*`` pattern is global. Deterministic fnmatch, no globbing
    of the repository itself."""
    pattern = entry_pattern(entry)
    if pattern == "*":
        return True
    return any(fnmatch.fnmatch(p, pattern) for p in paths)


def select_memory(entries: Iterable[Any], paths: Iterable[str]) -> list[dict[str, str]]:
    """Enabled, non-mute rows that apply to ``paths``, in storage order.

    Returns plain dicts with normalized ``note``/``path_pattern``/
    ``category`` keys so the reviewer has one shape to work with regardless
    of backend. Bounded to :data:`MAX_MEMORY_ENTRIES`.
    """
    out: list[dict[str, str]] = []
    paths = list(paths)
    for entry in entries:
        if isinstance(entry, dict):
            row = entry
        else:
            row = {"note": entry_note(entry), "path_pattern": entry_pattern(entry),
                   "category": getattr(entry, "category", None),
                   "enabled": getattr(entry, "enabled", True)}
        if is_mute_row(row) or not entry_enabled(row):
            continue
        if not matches_paths(row, paths):
            continue
        note = entry_note(row).strip()
        if not note:
            continue
        out.append({
            "note": note[:MAX_NOTE_CHARS],
            "path_pattern": entry_pattern(row),
            "category": entry_category(row),
        })
        if len(out) >= MAX_MEMORY_ENTRIES:
            break
    return out


def format_note(entry: dict[str, Any]) -> str:
    """Prompt-facing rendering: ``[category] note``.

    The default category is omitted so plain notes stay byte-identical to
    what older backends (which store only a note) return.
    """
    note = entry.get("note", "")
    category = str(entry.get("category", "") or "")
    if not category or category == DEFAULT_CATEGORY:
        return note
    return f"[{category}] {note}"
