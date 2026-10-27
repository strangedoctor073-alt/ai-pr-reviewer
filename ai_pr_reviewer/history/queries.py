"""V4.4-E01-T02 — read-only query surface over a :class:`HistoryIndex`.

Every consumer of history (prompt retrieval here, release intelligence and
analytics later) reads through :class:`HistoryReader`; none reaches into the
index tuples directly. The V4-E07 "read contract kit" is deferred in this
repository, so this class is the contract for the history feed: it is
total (never raises, unknown paths return empty results), bounded (result
sizes are clamped), deterministic, and carries the index's degradation
label with every answer so a caller cannot present shallow or truncated
history as complete.

No query takes or returns an author identity — there is none to return.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..repo_context import _safe_repo_path
from .builder import (HISTORY_OK, CommitRecord, HistoryIndex, PathChurn)

#: Upper bound on any query's result size, regardless of the caller's ask.
MAX_QUERY_RESULTS = 50


@dataclass(frozen=True)
class CoChangePeer:
    path: str
    count: int


def _clamp(limit) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int):
        return 0
    return max(0, min(limit, MAX_QUERY_RESULTS))


class HistoryReader:
    """Deterministic, bounded reads over one history index."""

    def __init__(self, index: HistoryIndex | None):
        self._index = index
        self._churn: dict[str, PathChurn] = {}
        self._peers: dict[str, list[CoChangePeer]] = {}
        self._commits: dict[str, list[CommitRecord]] = {}
        if index is None or not index.is_available:
            return
        self._churn = {c.path: c for c in index.churn}
        for pair in index.co_change:  # already (-count, a, b) ordered
            self._peers.setdefault(pair.path_a, []).append(
                CoChangePeer(pair.path_b, pair.count))
            self._peers.setdefault(pair.path_b, []).append(
                CoChangePeer(pair.path_a, pair.count))
        for commit in index.commits:  # newest first
            for path in commit.paths:
                self._commits.setdefault(path, []).append(commit)

    # ----------------------------------------------------------- labels
    @property
    def available(self) -> bool:
        return self._index is not None and self._index.is_available

    @property
    def state(self) -> str:
        return self._index.state if self._index is not None else "unavailable"

    @property
    def is_complete(self) -> bool:
        """True only for an undegraded index; callers must not present
        anything else as full history."""
        return self.state == HISTORY_OK

    @property
    def reasons(self) -> tuple[str, ...]:
        if self._index is None:
            return ("history: not collected",)
        return self._index.reasons

    # ----------------------------------------------------------- queries
    def churn(self, path: str) -> PathChurn | None:
        safe = _safe_repo_path(path) if isinstance(path, str) else None
        return self._churn.get(safe) if safe else None

    def co_changed(self, path: str, limit: int = 5) -> tuple[CoChangePeer, ...]:
        safe = _safe_repo_path(path) if isinstance(path, str) else None
        if not safe:
            return ()
        return tuple(self._peers.get(safe, ())[:_clamp(limit)])

    def hotspots(self, limit: int = 10) -> tuple[PathChurn, ...]:
        """Most-changed paths: commits desc, then lines touched desc, then
        path (a total order, so the answer is stable)."""
        ranked = sorted(
            self._churn.values(),
            key=lambda c: (-c.commits, -(c.lines_added + c.lines_deleted),
                           c.path))
        return tuple(ranked[:_clamp(limit)])

    def recent_commits(self, path: str, limit: int = 3) -> tuple[CommitRecord, ...]:
        safe = _safe_repo_path(path) if isinstance(path, str) else None
        if not safe:
            return ()
        return tuple(self._commits.get(safe, ())[:_clamp(limit)])
