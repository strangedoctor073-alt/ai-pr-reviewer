"""V4-E08-T03 — security limits for the ephemeral repository index.

Every dimension of the index build has an explicit, testable bound here;
callers never invent their own caps. The module also owns the two path
guards the index is built on:

* :func:`is_contained` — path containment (``..``/absolute/drive-letter
  rejection plus ``realpath`` symlink resolution) reusing the *existing*
  ``_safe_repo_path`` pattern from ``repo_context.py`` rather than a
  second, drifting implementation;
* :func:`is_excluded` — exclusion-glob matching with the same fnmatch
  semantics as ``orchestrator.filter_files``, so the non-removable
  privacy baseline in ``rules.py`` filters index reads exactly the way
  it filters review files (threat model §1: "excluded path never
  appears in the index").

:func:`is_vendor_or_minified` skips vendor trees, lockfiles and
generated/minified artifacts — the "vendor/minified bombs" control of
threat model §1.

This module (and the whole ``index`` package) performs no execution and
no network I/O: ``tests/test_repository_index.py`` AST-scans the package
imports to pin that invariant (hard rule 2: nothing executes repository
code; index construction has no model dependency either).
"""
from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass

from ..repo_context import _safe_repo_path

# ----------------------------------------------------------------- defaults
# V4-E01-T04: these defaults are what "existing configurations retain their
# previous behavior" rests on — the index build is bounded at 1000 files /
# 10 MiB out of the box, requires no configuration, and (because the index
# is never prompt-attached in E01-T05) changes no review output.

#: Default cap on inventoried files (matches the documented 1000-file
#: build cap C8 in V4_V10_ROADMAP).
DEFAULT_MAX_FILES = 1_000
#: Default cap on total bytes *read* while extracting symbols (10 MiB).
DEFAULT_MAX_BYTES = 10 * 1024 * 1024
#: Default cap on bytes read from a single file (giant files stay in the
#: inventory but are not parsed for symbols).
DEFAULT_MAX_FILE_BYTES = 512 * 1024
#: Default caps on extracted structures (bounded expansion).
DEFAULT_MAX_SYMBOLS_PER_FILE = 500
DEFAULT_MAX_IMPORTS_PER_FILE = 100
DEFAULT_MAX_EDGES = 5_000
#: Default traversal depth cap (directories deeper than this are not walked).
DEFAULT_MAX_DEPTH = 20

# ---------------------------------------------------------------- hard caps
# Configuration may only move the knobs *down* within [1, HARD_*]; a
# hostile or typo'd `.ai-pr-reviewer.yml` can never balloon the build
# past the hard ceiling (warning is raised by rules.py at parse time).
HARD_MAX_FILES = 10_000
HARD_MAX_BYTES = 100 * 1024 * 1024
HARD_MAX_FILE_BYTES = 4 * 1024 * 1024
HARD_MAX_SYMBOLS_PER_FILE = 5_000
HARD_MAX_EDGES = 50_000
HARD_MAX_DEPTH = 64

# ------------------------------------------------------------ vendor skips
#: Directory names that are never indexed (vendor/generated/caches).
VENDOR_DIR_NAMES = frozenset({
    "node_modules", "bower_components", "vendor", "third_party", "thirdparty",
    "site-packages", ".venv", "venv", ".tox", ".nox", ".git", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".gradle", ".idea",
    ".vscode", ".cache", ".next", ".nuxt", ".output", ".dart_tool",
    "dist", "build", "out", "target", "coverage", "htmlcov",
    "eggs", ".eggs", "Pods", "DerivedData",
})

#: Basename suffixes that mark a file as generated/minified/lockfile.
VENDOR_BASENAME_SUFFIXES = (
    ".egg-info", ".min.js", ".min.css", ".min.mjs", ".min.cjs",
    ".map", ".pyc", ".pyo", ".lock",
)

#: Explicit lockfile names (many are ``.json``/``.yaml``, invisible to
#: suffix checks — and they are the classic "bomb").
VENDOR_BASENAMES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "Pipfile.lock", "uv.lock", "Cargo.lock", "go.sum", "composer.lock",
    "Gemfile.lock", "flake.lock", "gradle.lockfile", "requirements.lock",
})


def is_vendor_dir(name: str) -> bool:
    """True when a *directory* name marks a vendor/generated/cache tree."""
    return name in VENDOR_DIR_NAMES or name.endswith(".egg-info")


def is_vendor_or_minified(relpath: str) -> bool:
    """True when ``relpath`` is a vendor/generated/lockfile path (never indexed)."""
    normalized = relpath.replace("\\", "/")
    parts = [p for p in normalized.split("/") if p]
    if not parts:
        return False
    if any(p in VENDOR_DIR_NAMES for p in parts[:-1]):
        return True
    basename = parts[-1]
    if basename in VENDOR_BASENAMES:
        return True
    lowered = basename.lower()
    return any(lowered.endswith(suffix) for suffix in VENDOR_BASENAME_SUFFIXES)


# ------------------------------------------------------------------ guards

def is_excluded(relpath: str, patterns) -> bool:
    """True when an exclusion glob matches ``relpath``.

    Same semantics as ``orchestrator._is_excluded`` (fnmatch on the
    repository-relative path) — a parity test keeps the two from
    drifting, because the privacy baseline must filter index reads and
    review files *identically*.
    """
    return any(fnmatch.fnmatch(relpath, pat.strip())
               for pat in patterns if pat and pat.strip())


def is_contained(root: str, relpath: str) -> bool:
    """True when ``relpath`` resolves to a real path inside ``root``.

    Layered like the rest of the pipeline: textual normalization first
    (``_safe_repo_path`` rejects ``..``, absolute and drive-letter
    paths), then ``realpath`` resolution so a symlink inside the checkout
    that points outside it is rejected too. This runs before *every*
    content read, so an untrusted path name can never drive a read
    outside the worktree (threat model §1/§2).
    """
    safe = _safe_repo_path(relpath)
    if safe is None:
        return False
    try:
        root_real = os.path.normcase(os.path.realpath(root))
        full = os.path.normcase(os.path.realpath(os.path.join(root_real, safe)))
    except (OSError, ValueError):
        return False
    return full == root_real or full.startswith(root_real + os.sep)


# ----------------------------------------------------------------- limits

def clamp_int(value, default: int, high: int) -> int:
    """Coerce a configured limit into ``[1, high]``, falling back to
    ``default`` for values that are not integers (``bool`` excluded).

    Warning on out-of-range values is raised where the config is parsed
    (``rules.py``); this function is the silent second line of defense
    for programmatically constructed policies.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    if value < 1:
        return default
    return min(value, high)


@dataclass(frozen=True)
class IndexLimits:
    """Effective, already-clamped limits for one index build."""

    max_files: int = DEFAULT_MAX_FILES
    max_bytes: int = DEFAULT_MAX_BYTES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_symbols_per_file: int = DEFAULT_MAX_SYMBOLS_PER_FILE
    max_imports_per_file: int = DEFAULT_MAX_IMPORTS_PER_FILE
    max_edges: int = DEFAULT_MAX_EDGES
    max_depth: int = DEFAULT_MAX_DEPTH

    @classmethod
    def from_policy(cls, policy) -> "IndexLimits":
        """Build limits from a ``ReviewPolicy`` (or any object exposing
        ``context_max_files``/``context_max_bytes``; missing attributes
        fall back to defaults — test doubles and older policies work)."""
        return cls(
            max_files=clamp_int(getattr(policy, "context_max_files", None),
                                DEFAULT_MAX_FILES, HARD_MAX_FILES),
            max_bytes=clamp_int(getattr(policy, "context_max_bytes", None),
                                DEFAULT_MAX_BYTES, HARD_MAX_BYTES),
        )
