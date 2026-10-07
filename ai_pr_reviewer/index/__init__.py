"""V4 repository index (E01) — ephemeral, bounded, deterministic.

A per-review-run view of the checked-out base tree: which files exist
(inventory), what they define (symbol-lite), and how they import each
other (graph). Hard rules for this subsystem (V4 charter + threat model):

* **ephemeral** — built fresh each run, never persisted (no `repo_index`
  table, no Alembic, no migration; ADR-022 outcome 2026-10-07);
* **no execution, no network, no model** — the build reads local files
  with ``open()`` only; a regression test scans this package's imports to
  keep it that way;
* **bounded** — every dimension has an explicit limit from
  :mod:`ai_pr_reviewer.index.limits`; hitting one degrades loudly
  (``budget_state`` + warning), never crashes and never expands.
"""
from __future__ import annotations

from .builder import FileEntry, RepoIndex, Symbol, build_index
from .limits import (DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, HARD_MAX_BYTES,
                     HARD_MAX_FILES, IndexLimits, is_contained, is_excluded,
                     is_vendor_dir, is_vendor_or_minified)

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEFAULT_MAX_FILES",
    "FileEntry",
    "HARD_MAX_BYTES",
    "HARD_MAX_FILES",
    "IndexLimits",
    "RepoIndex",
    "Symbol",
    "build_index",
    "is_contained",
    "is_excluded",
    "is_vendor_dir",
    "is_vendor_or_minified",
]
