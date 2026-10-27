"""V4.4-E01-T03 — render history for a prompt: redacted, neutralized, bounded.

Commit subjects are untrusted (a contributor controls them) and often hold
secrets. This module is the retrieval boundary: everything it returns has
been secret-redacted again and stripped of look-alike fence markers, and the
section is size-capped. It still is NOT trusted text — ``context.py`` wraps
it in the same nonce fence used for diffs and repository files
(:func:`ai_pr_reviewer.context.build_untrusted_history_block`) and screens it
for instruction impersonation. Authorship never appears: the section lists
paths, counts, dates and subjects only.
"""
from __future__ import annotations

from datetime import datetime, timezone

from ..security import neutralize_fence_tags, redact_secrets
from .builder import HistoryIndex
from .queries import HistoryReader

#: Defaults for what one review's history section may contain.
DEFAULT_SECTION_CHARS = 3_000
HARD_SECTION_CHARS = 20_000
MAX_PATHS = 12
MAX_PEERS = 3
MAX_SUBJECTS = 2
HEADER = "--- git history (read-only, bounded) ---"


def _day(epoch: int) -> str:
    return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime("%Y-%m-%d")


def _safe(text: str) -> str:
    """Retrieval-time defense: redact again and neutralize fence look-alikes
    (idempotent, so already-clean ingest-time text is unchanged)."""
    return neutralize_fence_tags(redact_secrets(text))


def render_history_section(index: HistoryIndex | None, changed_paths, *,
                           max_chars: int = DEFAULT_SECTION_CHARS,
                           ) -> tuple[str, int]:
    """Render ``(section, omitted_entries)`` for the changed paths.

    ``("", 0)`` when history is disabled/unavailable or no changed path has
    any history — the prompt then stays byte-identical. A degraded index
    (shallow / truncated) is labelled in the section itself, so the model
    and the reader are told the history is partial.
    """
    max_chars = max(0, min(int(max_chars), HARD_SECTION_CHARS))
    reader = HistoryReader(index)
    if max_chars == 0 or not reader.available:
        return "", 0

    entries: list[str] = []
    seen: set[str] = set()
    for path in changed_paths or ():
        if not isinstance(path, str) or path in seen:
            continue
        seen.add(path)
        churn = reader.churn(path)
        if churn is None:
            continue
        lines = [f"{_safe(churn.path)}: changed in {churn.commits} recent "
                 f"commit(s), +{churn.lines_added}/-{churn.lines_deleted} "
                 f"lines, last {_day(churn.last_changed_at)}"]
        peers = reader.co_changed(path, MAX_PEERS)
        if peers:
            lines.append("  often changed together with: " + ", ".join(
                f"{_safe(p.path)} ({p.count}x)" for p in peers))
        for commit in reader.recent_commits(path, MAX_SUBJECTS):
            lines.append(f"  recent: {commit.sha[:7]} {_day(commit.committed_at)}"
                         f" \"{_safe(commit.subject)}\"")
        entries.append("\n".join(lines))

    if not entries:
        return "", 0

    head = [HEADER]
    if not reader.is_complete:
        head.append("note: history is partial — " + "; ".join(
            _safe(r) for r in reader.reasons) if reader.reasons
            else "note: history is partial")
    shown: list[str] = []
    used = sum(len(h) + 1 for h in head)
    for entry in entries[:MAX_PATHS]:
        if used + len(entry) + 1 > max_chars:
            break
        shown.append(entry)
        used += len(entry) + 1
    omitted = len(entries) - len(shown)
    if not shown:
        return "", len(entries)
    return "\n".join([*head, *shown]), omitted


__all__ = ["DEFAULT_SECTION_CHARS", "HARD_SECTION_CHARS", "HEADER",
           "render_history_section"]
