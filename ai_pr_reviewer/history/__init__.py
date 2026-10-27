"""V4.4-E01 — git history intelligence (read-only, bounded, ephemeral).

See :mod:`ai_pr_reviewer.history.builder` for the invariants. The package is
OFF at baseline: nothing in the review pipeline imports it yet, so review
output is byte-identical to pre-V4.4 until a later ticket wires it in behind
an explicit, default-off switch.
"""
from __future__ import annotations

from .builder import (HISTORY_OK, HISTORY_SHALLOW, HISTORY_STATES,
                      HISTORY_TRUNCATED, HISTORY_UNAVAILABLE, CoChange,
                      CommitRecord, HistoryIndex, HistoryStats, PathChurn,
                      ROLE_BOT, ROLE_HUMAN, ROLE_UNKNOWN, ROLES,
                      build_history_index, classify_role, clean_subject)
from .queries import MAX_QUERY_RESULTS, CoChangePeer, HistoryReader
from .retrieval import render_history_section
from .git_read import ALLOWED_SUBCOMMANDS, GitRefused, GitResult, run_git
from .limits import HistoryLimits

__all__ = [
    "CoChangePeer", "HistoryReader", "MAX_QUERY_RESULTS", "ROLES", "ROLE_BOT",
    "ROLE_HUMAN", "ROLE_UNKNOWN", "classify_role", "render_history_section",
    "ALLOWED_SUBCOMMANDS", "CoChange", "CommitRecord", "GitRefused",
    "GitResult", "HISTORY_OK", "HISTORY_SHALLOW", "HISTORY_STATES",
    "HISTORY_TRUNCATED", "HISTORY_UNAVAILABLE", "HistoryIndex",
    "HistoryLimits", "HistoryStats", "PathChurn", "build_history_index",
    "clean_subject", "run_git",
]
