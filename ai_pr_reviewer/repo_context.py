"""Bounded repository context for a PR review (V3 C3).

The diff only shows what *changed*; a reviewer also needs the code the
change points at. This module collects that — a handful of **other**
repository files, chosen deterministically and paid for out of one strict
character budget:

1. **imports/references** discovered in the changed files' own diff lines
   (the code the change depends on), resolved to repo-relative paths;
2. **project configuration** relevant to almost any change
   (``pyproject.toml``, ``package.json``, …);
3. **the changed files themselves**, as budget filler, so a reviewer sees
   the surrounding code beyond the hunks (they are already in the prompt as
   a diff, so they come last).

Only files we can name are ever fetched — there is no repository listing,
no code search and no recursive walk, so the number of API calls is bounded
by :data:`MAX_CONTEXT_FILES` before the budget is even considered.

Safety, in line with the rest of the pipeline:

* repository content is **untrusted** — it is secret-redacted here and the
  providers additionally screen + nonce-fence it (exactly like the diff)
  before it can reach a prompt; it can never override system/developer
  instructions;
* the ref is the **base** revision, not the PR head, so a PR cannot choose
  which repository text is fed back to the reviewer;
* resolved paths are rejected if they escape the repository root
  (``..``/absolute) — path-traversal protection;
* every failure degrades to "no repository context" plus a warning. A
  review must never fail because GitHub could not hand us a file.
"""
from __future__ import annotations

import logging
import posixpath
import re
from dataclasses import dataclass

from .config import Config
from .diff_parser import FileDiff
from .models import PRContext
from .security import redact_secrets

log = logging.getLogger(__name__)

#: Hard cap on repository-context characters handed to a provider.
DEFAULT_REPO_CONTEXT_CHARS = 12_000
#: Hard cap on how many files one review may fetch for context.
MAX_CONTEXT_FILES = 8
#: Per-file cap — one huge file can't swallow the whole budget.
MAX_PER_FILE_CHARS = 4_000
#: How many project-config paths we are willing to probe for existence.
MAX_CONFIG_CANDIDATES = 4

# Config files that describe how this repository is built, linted and tested.
# ``.ai-pr-reviewer.yml`` is deliberately absent: it is already loaded as the
# trusted ReviewPolicy, so re-fetching it would only duplicate it.
PROJECT_CONFIG_FILES = (
    "pyproject.toml", "package.json", "tsconfig.json", "setup.cfg",
    "tox.ini", "Makefile", ".eslintrc.json", "go.mod", "Cargo.toml",
    "requirements.txt",
)

_PY_FROM_RE = re.compile(r"^\s*from\s+([.\w][\w.]*)\s+import\b")
_PY_IMPORT_RE = re.compile(r"^\s*import\s+([.\w][\w.]*)")
_JS_FROM_RE = re.compile(r"""(?:\bfrom|\brequire\s*|\bimport\s*)\(\s*['"]([^'"]+)['"]""")
_JS_BARE_RE = re.compile(r"""\bfrom\s+['"]([^'"]+)['"]""")

# JS/TS extensions tried, in order, when resolving a bare relative specifier.
_CODE_EXTENSIONS = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go")
_INDEX_FILES = (
    "__init__.py", "index.js", "index.ts", "index.jsx", "index.tsx",
)

_TRUNCATED_MARKER = "\n… [truncated by the repository-context budget]\n"


@dataclass(frozen=True)
class RepoContextEntry:
    """One repository file pulled in as review context."""

    path: str
    content: str
    reason: str


# --------------------------------------------------------------------------- path safety

def _safe_repo_path(candidate: str) -> str | None:
    """Normalize ``candidate`` to a repository-relative path, or ``None``.

    Rejects absolute paths and anything that climbs above the repository
    root after normalization.
    """
    if not candidate:
        return None
    cleaned = candidate.replace("\\", "/").strip()
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:", cleaned):
        return None
    norm = posixpath.normpath(cleaned)
    if norm.startswith("../") or norm == ".." or norm.startswith("/"):
        return None
    return norm if norm not in (".", "") else None


def _relative_to(file_path: str, specifier: str) -> str | None:
    """Resolve a ``./x``/``../x`` import against the importing file's dir."""
    base = posixpath.dirname(file_path.replace("\\", "/"))
    return _safe_repo_path(posixpath.join(base, specifier))


# --------------------------------------------------------------------------- candidate selection

def _module_paths(module: str, *, relative_to_file: str = "") -> list[str]:
    """Repo paths a Python module name could live at (in probe order)."""
    parts = [p for p in module.lstrip(".").split(".") if p]
    if not parts:
        return []
    joined = "/".join(parts)
    if module.startswith("."):
        base = posixpath.dirname(relative_to_file) or "."
        joined = _safe_repo_path(posixpath.join(base, joined)) or ""
        if not joined:
            return []
    stem = joined
    return [f"{stem}.py", f"{stem}/__init__.py"]


def _js_paths(specifier: str, importing_file: str) -> list[str]:
    """Repo paths an ES-module/CommonJS specifier could resolve to."""
    if specifier.startswith("."):
        base = _relative_to(importing_file, specifier)
        if not base:
            return []
        if posixpath.splitext(base)[1]:
            return [base]
        return [base + ext for ext in _CODE_EXTENSIONS] + [
            posixpath.join(base, idx) for idx in _INDEX_FILES
        ]
    return []   # bare module specifiers need a package index we don't have


def _imports_for(file: FileDiff) -> list[str]:
    """Repo-relative import candidates found in one changed file's lines.

    Reads only the diff's own context/added lines — no file is fetched to
    discover this — so selection stays free, deterministic and bounded.
    """
    dir_path = posixpath.dirname(file.path.replace("\\", "/"))
    out: list[str] = []
    seen: set[str] = set()

    def add(path: str | None) -> None:
        if path and path not in seen:
            seen.add(path)
            out.append(path)

    for hunk in file.hunks:
        for line in hunk.lines:
            if line.tag not in ("+", " "):     # removed lines aren't dependencies
                continue
            text = line.text or ""
            m = _PY_FROM_RE.match(text)
            if m:
                spec = m.group(1)
                for cand in _module_paths(spec, relative_to_file=file.path):
                    add(cand)
                if spec.startswith("."):
                    # `from . import sibling` — the package itself
                    for idx in _INDEX_FILES[:1]:
                        add(_safe_repo_path(posixpath.join(dir_path, spec.lstrip("."), idx)))
                continue
            m = _PY_IMPORT_RE.match(text)
            if m:
                for cand in _module_paths(m.group(1)):
                    add(cand)
                continue
            m = _JS_BARE_RE.search(text) or _JS_FROM_RE.search(text)
            if m:
                for cand in _js_paths(m.group(1), file.path):
                    add(cand)
    return out


def select_candidates(files: list[FileDiff]) -> list[tuple[str, str]]:
    """Ordered ``(path, reason)`` candidates, deduplicated, no I/O.

    Deterministic given the same diff: candidates follow the diff's own file
    order, then the fixed project-config list.
    """
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(path: str | None, reason: str) -> None:
        if not path or path in seen:
            return
        seen.add(path)
        candidates.append((path, reason))

    changed = {f.path for f in files}
    for f in files:
        for path in _imports_for(f):
            # An import that lands on a changed file is already in the diff.
            if path in changed:
                continue
            add(path, f"imported by {f.path}")

    for name in PROJECT_CONFIG_FILES[:MAX_CONFIG_CANDIDATES]:
        add(name, "project configuration")

    # Last: the changed files themselves (surrounding context beyond hunks).
    for f in files:
        add(f.path, "changed in this PR")

    return candidates


# --------------------------------------------------------------------------- collection

def collect_repository_context(gh, pr: PRContext, files: list[FileDiff],
                               cfg: Config | None = None,
                               budget: int | None = None) -> tuple[list[RepoContextEntry], list[str]]:
    """Fetch the bounded repository context for one review.

    Returns ``(entries, warnings)``. Never raises: a failed GitHub call
    yields whatever was collected so far plus a warning, and a review
    without repository context is still a review.
    """
    if budget is None:
        budget = int(getattr(cfg, "repo_context_chars", DEFAULT_REPO_CONTEXT_CHARS)
                     if cfg is not None else DEFAULT_REPO_CONTEXT_CHARS)
    if gh is None or budget <= 0 or not files:
        return [], []
    if not callable(getattr(gh, "get_file", None)):
        return [], []      # client without the contents API: nothing to read

    ref = (getattr(pr, "base_sha", "") or getattr(pr, "head_sha", "") or "").strip()
    candidates = select_candidates(files)
    if not candidates:
        return [], []

    entries: list[RepoContextEntry] = []
    warnings: list[str] = []
    fetched: dict[str, str | None] = {}   # path -> content or None when absent
    spent = 0
    skipped_budget = 0
    probes = 0
    max_probes = MAX_CONTEXT_FILES * 2      # probes, including 404 misses

    for path, reason in candidates:
        if len(entries) >= MAX_CONTEXT_FILES:
            break
        if probes >= max_probes:
            break
        if path in fetched:
            content = fetched[path]
        else:
            probes += 1
            try:
                content = gh.get_file(path, ref)
            except Exception as exc:                      # noqa: BLE001
                if getattr(exc, "status_code", None) == 404:
                    fetched[path] = None                  # not in this repo/ref
                    continue
                # Anything else (auth, rate limit, network) — keep what we
                # collected and let the review continue without more of it.
                warnings.append(
                    "repository context unavailable ("
                    f"{type(exc).__name__}); continuing the review without it"
                )
                log.warning("repo context fetch failed for %s: %s", path, exc)
                break
            if not isinstance(content, str) or not content.strip():
                fetched[path] = None
                continue
            fetched[path] = content

        if not content:
            continue

        text = redact_secrets(content)
        if len(text) > MAX_PER_FILE_CHARS:
            text = text[:MAX_PER_FILE_CHARS] + _TRUNCATED_MARKER
        if spent + len(text) > budget:
            skipped_budget += 1
            continue

        spent += len(text)
        entries.append(RepoContextEntry(path=path, content=text, reason=reason))

    if skipped_budget:
        warnings.append(
            f"repository context budget of {budget} characters reached — "
            f"skipped {skipped_budget} candidate file(s)"
        )
    return entries, warnings
