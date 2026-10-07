"""V4-E01-T01 — bounded file inventory for the ephemeral repository index.

Walks the checked-out base tree under the limits from
:mod:`ai_pr_reviewer.index.limits`: file-count cap, depth cap, vendor
skips, exclusion globs (the non-removable privacy baseline) and path
containment on every entry. The walk never follows symlinks out of the
checkout, never executes anything and never touches the network — it
stats files and, later, reads bytes. Output is sorted by path so the
same tree always produces the same inventory (determinism is a ticket
requirement, not a nicety).
"""
from __future__ import annotations

import logging
import os
import posixpath
import stat
from typing import NamedTuple

from .limits import (IndexLimits, is_contained, is_excluded, is_vendor_dir,
                     is_vendor_or_minified)

log = logging.getLogger(__name__)

# ---------------------------------------------------------------- language

_LANGUAGE_BY_SUFFIX = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".c": "c", ".h": "c",
    ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp", ".hpp": "cpp", ".hh": "cpp",
    ".go": "go", ".rs": "rust", ".rb": "ruby", ".php": "php",
    ".swift": "swift", ".cs": "csharp", ".scala": "scala",
    ".sh": "shell", ".bash": "shell", ".zsh": "shell", ".ps1": "powershell",
    ".yml": "yaml", ".yaml": "yaml", ".toml": "toml", ".json": "json",
    ".ini": "ini", ".cfg": "ini", ".conf": "ini", ".properties": "ini",
    ".xml": "xml", ".sql": "sql", ".tf": "terraform",
    ".md": "markdown", ".rst": "markdown", ".txt": "text",
    ".html": "html", ".css": "css", ".scss": "css",
    ".vue": "vue", ".svelte": "svelte",
}

_SPECIAL_LANGUAGES = {
    "makefile": "make", "gnumakefile": "make",
    "gemfile": "ruby", "rakefile": "ruby",
    "cmakelists.txt": "cmake",
    "go.mod": "go",
}


def detect_language(path: str) -> str:
    """Extension/basename language tag; ``"unknown"`` when unmapped.

    Config/asset files get their real format tag (``yaml``/``json``/…)
    so downstream consumers can tell "no symbols here, by design" from
    "extraction failed".
    """
    base = posixpath.basename(path.replace("\\", "/")).lower()
    if base == "dockerfile" or base.startswith("dockerfile."):
        return "dockerfile"
    if base in _SPECIAL_LANGUAGES:
        return _SPECIAL_LANGUAGES[base]
    suffix = posixpath.splitext(base)[1]
    return _LANGUAGE_BY_SUFFIX.get(suffix, "unknown")


# ---------------------------------------------------------------- walk

class WalkEntry(NamedTuple):
    """One inventoried file: repository-relative path, size in bytes,
    detected language."""

    path: str
    size: int
    language: str


def walk_inventory(root: str, limits: IndexLimits, exclusions) -> tuple[list[WalkEntry], str, list[str]]:
    """Inventory ``root`` under ``limits``.

    Returns ``(entries, budget_state, warnings)`` with entries sorted by
    path. ``budget_state`` is ``"truncated"`` when the file-count or
    depth cap cut the walk short (partial index + warning — threat model
    §1: exhaustion is loud, never a crash); ``"ok"`` otherwise. Content
    reads happen later in the builder — this pass only stats.
    """
    entries: list[WalkEntry] = []
    warnings: list[str] = []
    state = "ok"

    def onerror(exc: OSError) -> None:
        warnings.append(f"index: unreadable path skipped ({type(exc).__name__})")

    stop = False
    for dirpath, dirnames, filenames in os.walk(
            root, topdown=True, onerror=onerror, followlinks=False):
        if stop:
            break
        rel_dir = os.path.relpath(dirpath, root)
        rel_dir = "" if rel_dir == "." else rel_dir.replace("\\", "/")
        depth = 0 if not rel_dir else rel_dir.count("/") + 1

        # depth cap: never descend past it (and say so when we cut)
        if depth >= limits.max_depth:
            if dirnames:
                warnings.append(
                    f"index: directory-depth cap ({limits.max_depth}) reached — "
                    f"deeper paths not inventoried")
                state = "truncated"
            dirnames[:] = []
        else:
            # prune vendor/caches + symlinks-to-dirs (followlinks=False
            # already refuses to descend; pruning keeps the walk cheap)
            kept = []
            for name in sorted(dirnames):
                rel = f"{rel_dir}/{name}" if rel_dir else name
                if is_vendor_dir(name):
                    continue
                full = os.path.join(dirpath, name)
                try:
                    if os.path.islink(full):
                        warnings.append(
                            f"index: symlinked directory not followed: {rel}")
                        continue
                except OSError as exc:
                    onerror(exc)
                    continue
                kept.append(name)
            dirnames[:] = kept

        for name in sorted(filenames):
            if len(entries) >= limits.max_files:
                warnings.append(
                    f"index: file-count cap ({limits.max_files}) reached — "
                    f"inventory truncated")
                state = "truncated"
                stop = True
                break
            rel = f"{rel_dir}/{name}" if rel_dir else name
            if name == ".git":
                continue  # gitlink file in a worktree/submodule checkout
            if is_vendor_or_minified(rel):
                continue
            if is_excluded(rel, exclusions):
                continue
            if not is_contained(root, rel):
                warnings.append(f"index: path rejected (outside checkout): {rel}")
                continue
            full = os.path.join(dirpath, name)
            try:
                st = os.lstat(full)
            except OSError as exc:
                onerror(exc)
                continue
            if not stat.S_ISREG(st.st_mode):
                continue  # fifo/socket/device — never read
            entries.append(WalkEntry(rel, int(st.st_size), detect_language(rel)))

    entries.sort(key=lambda e: e.path)
    return entries, state, warnings
