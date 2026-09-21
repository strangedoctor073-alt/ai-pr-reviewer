"""Context assembly for the AI provider.

``build_context`` is the single seam the rest of the V2 pipeline calls
into: it takes the raw diff + config and hands back one ``ReviewContext``
containing everything ``AIProvider.analyze()`` (in
``ai/provider.py``) needs — changed files, best-effort "you might also
want to see" file discovery, the repo's trusted ``ReviewPolicy``, and a
character budget that's already been enforced.

Two things this module deliberately does NOT do:
  * fetch real file contents from GitHub for "relevant files" — V2 ships
    with filename-matching only (no vector database yet);
  * build a real token-aware optimizer for the budget — a simple greedy
    trim from the end is explicitly called out as good enough for V2.
"""
from __future__ import annotations

import copy
import logging
import re
from dataclasses import dataclass

from .config import Config
from .diff_parser import FileDiff
from .models import Finding, PRContext
from .rules import ReviewPolicy, load_project_rules

log = logging.getLogger(__name__)

DEFAULT_TOKEN_BUDGET = 80_000
MAX_RELEVANT_FILES = 5


# --------------------------------------------------------------------------- ReviewContext

@dataclass
class ReviewContext:
    """Everything an :class:`AIProvider` needs to review one PR (shared
    contract type — see ``ai_pr_reviewer/ai/provider.py``)."""

    pr: PRContext
    files: list[FileDiff]
    relevant_files: dict[str, str]         # path -> snippet
    project_rules: ReviewPolicy | None
    previous_findings: list[Finding]
    memory_notes: list[str]
    focus_areas: list[str]
    token_budget: int = DEFAULT_TOKEN_BUDGET


# --------------------------------------------------------------------------- relevant-file discovery

_PY_IMPORT_RE = re.compile(r"^\+?\s*(?:from\s+([.\w]+)\s+import|import\s+([.\w]+))",
                           re.MULTILINE)
_JS_IMPORT_RE = re.compile(r"""(?:from\s+|require\()\s*['"]([./\w-]+)['"]""")


def _local_import_names(diff_text: str, ext: str) -> list[str]:
    """Simple, deliberately non-exhaustive grep for local module names
    referenced in a diff's added/context lines — not a real import
    resolver. Results are only ever used to look up basenames that already
    exist in the repo's file list, so a false positive here just fails to
    match anything rather than pulling in the wrong file."""
    names: list[str] = []
    if ext == "py":
        for m in _PY_IMPORT_RE.finditer(diff_text):
            mod = (m.group(1) or m.group(2) or "").lstrip(".")
            if not mod:
                continue
            leaf = mod.split(".")[-1]
            if leaf and leaf.isidentifier():
                names.append(leaf)
    else:
        for m in _JS_IMPORT_RE.finditer(diff_text):
            mod = m.group(1)
            if mod.startswith("."):
                leaf = mod.rsplit("/", 1)[-1]
                if leaf:
                    names.append(leaf)
    out: list[str] = []
    for n in names:
        if n not in out:
            out.append(n)
    return out


def find_relevant_files(changed_file: str, all_repo_files: list[str],
                        diff_text: str = "") -> list[str]:
    """Best-effort discovery of files that might matter alongside
    ``changed_file``. Filename-matching only — no repo content is
    read here. ``diff_text`` is an optional extra parameter that enables strategy (c); every call site
    that only passes the first two positional args keeps working.

    Cheapest-first, capped at :data:`MAX_RELEVANT_FILES` results so this
    can never return "the whole repo":
      (a) same directory as ``changed_file``
      (b) test-naming convention (``tests/test_X.py``, ``X.test.js``, ...)
      (c) local module names imported in ``diff_text``, matched by basename
          against ``all_repo_files`` (only runs if ``diff_text`` is given)
    """
    changed_norm = changed_file.replace("\\", "/")
    others = [p for p in all_repo_files
             if p and p.replace("\\", "/") != changed_norm]

    found: list[str] = []
    seen = {changed_norm}

    def add(path: str) -> bool:
        """Returns True once the cap is hit (signal to stop early)."""
        if path not in seen:
            seen.add(path)
            found.append(path)
        return len(found) >= MAX_RELEVANT_FILES

    # (a) same directory
    changed_dir = changed_norm.rsplit("/", 1)[0] if "/" in changed_norm else ""
    for p in others:
        norm = p.replace("\\", "/")
        d = norm.rsplit("/", 1)[0] if "/" in norm else ""
        if d == changed_dir and add(norm):
            return found

    # (b) test-naming convention, searched across the whole repo (tests
    # commonly live in a different directory than the code they cover)
    stem = changed_norm.rsplit("/", 1)[-1]
    base, _, ext = stem.rpartition(".")
    base = base or stem
    candidates = set()
    if base:
        candidates.update({
            f"test_{base}.py", f"{base}_test.py",
            f"{base}.test.{ext or 'js'}", f"{base}.spec.{ext or 'js'}",
            f"{base}Test.java", f"{base}_test.go",
        })
        if base.startswith("test_") and ext:
            candidates.add(f"{base[len('test_'):]}.{ext}")
        if base.endswith("_test") and ext:
            candidates.add(f"{base[:-len('_test')]}.{ext}")
    candidates_lower = {c.lower() for c in candidates}
    for p in others:
        norm = p.replace("\\", "/")
        name = norm.rsplit("/", 1)[-1]
        if name.lower() in candidates_lower and add(norm):
            return found

    # (c) local imports grepped from the changed file's own diff text
    if diff_text:
        local_names = _local_import_names(diff_text, ext)
        if local_names:
            by_stem: dict[str, list[str]] = {}
            for p in others:
                norm = p.replace("\\", "/")
                nm = norm.rsplit("/", 1)[-1]
                nm_stem = nm.rsplit(".", 1)[0] if "." in nm else nm
                by_stem.setdefault(nm_stem, []).append(norm)
            for name in local_names:
                for norm in by_stem.get(name, []):
                    if add(norm):
                        return found

    return found


# --------------------------------------------------------------------------- ContextBudget

def _apply_context_budget(files: list[FileDiff], relevant_files: dict[str, str],
                          budget: int) -> tuple[list[FileDiff], dict[str, str], list[str]]:
    """Simple greedy trim so the assembled context stays under ``budget``
    characters. Priority, highest to lowest (changed
    code > relevant files > rules > memory):

      1. drop all relevant-file content first (cheapest, lowest priority
         of the two things this function can actually trim)
      2. only if still over budget, trim the lowest-priority (last)
         changed files' hunks, working backward, dropping a whole file
         only once its hunks are exhausted

    Never mutates the caller's ``files``/``relevant_files`` — the
    orchestrator needs the untrimmed diffs later (e.g. to post inline
    comments), so trimming works on copies.

    A non-positive ``budget`` is treated as "unlimited" rather than as
    "trim everything" — a misconfigured ``cfg.batch_chars`` shouldn't
    silently discard the whole review.
    """
    notes: list[str] = []

    def total(fs: list[FileDiff], rf: dict[str, str]) -> int:
        return sum(len(f.to_diff_text()) for f in fs) + sum(len(v) for v in rf.values())

    if budget <= 0 or total(files, relevant_files) <= budget:
        return list(files), dict(relevant_files), notes

    if relevant_files:
        notes.append(
            f"context budget: dropped {len(relevant_files)} relevant-file "
            f"snippet(s) to stay under the {budget}-char budget")
        relevant_files = {}

    if total(files, relevant_files) <= budget:
        return list(files), relevant_files, notes

    trimmed = [copy.copy(f) for f in files]
    for f in trimmed:
        f.hunks = list(f.hunks)  # own list, so popping doesn't touch the original
    running = sum(len(f.to_diff_text()) for f in trimmed)

    i = len(trimmed) - 1
    while running > budget and i >= 0:
        f = trimmed[i]
        if f.hunks:
            before = len(f.to_diff_text())
            f.hunks = f.hunks[:-1]
            running -= before - len(f.to_diff_text())
            continue
        removed = trimmed.pop(i)
        running -= len(removed.to_diff_text())
        notes.append(f"context budget: dropped {removed.path} entirely "
                     f"(lowest priority, still over budget)")
        i -= 1

    return trimmed, relevant_files, notes


# --------------------------------------------------------------------------- build_context

def build_context(pr: PRContext, files: list[FileDiff], cfg: Config,
                  storage=None,
                  repo_file_contents: dict[str, str] | None = None) -> ReviewContext:
    """Assemble a :class:`ReviewContext` for this PR.

    ``repo_file_contents`` is an optional extra kwarg (path -> full text)
    beyond the shared-contract signature ``build_context(pr, files, cfg,
    storage=None)``; every call site that only passes those four
    positional/keyword args keeps working. It exists so a future content
    fetcher can plug in without changing this signature again. V2 does not
    fetch file contents from GitHub, so when it's omitted ``relevant_files``
    stays ``{}`` — that's fine for now.
    """
    repo_root = getattr(cfg, "repo_root", None) or "."
    rules_file = getattr(cfg, "rules_file", None) or ".ai-pr-reviewer.yml"
    project_rules = load_project_rules(repo_root, filename=rules_file)

    relevant_files: dict[str, str] = {}
    if repo_file_contents:
        all_repo_files = list(repo_file_contents.keys())
        for fd in files:
            for path in find_relevant_files(fd.path, all_repo_files,
                                            diff_text=fd.to_diff_text()):
                if path in repo_file_contents and path not in relevant_files:
                    relevant_files[path] = repo_file_contents[path]

    previous_findings: list[Finding] = []
    if storage is not None:
        getter = getattr(storage, "get_previous_findings", None)
        if callable(getter):
            try:
                raw_findings = getter(pr.repo, pr.pr_number) or []
                previous_findings = [
                    f if isinstance(f, Finding) else Finding.from_dict(f)
                    for f in raw_findings
                ]
            except Exception as exc:
                log.warning("get_previous_findings(%s, %s) failed: %s",
                            pr.repo, pr.pr_number, exc)

    memory_notes: list[str] = []
    if storage is not None:
        try:
            memory_notes = list(storage.get_repo_memory(
                pr.repo, [f.path for f in files]))
        except Exception as exc:  # storage must never take the review down
            log.warning("get_repo_memory(%s) failed — continuing without "
                       "repository memory (%s)", pr.repo, exc)
            memory_notes = []

    focus_areas: list[str] = []
    for area in list(getattr(cfg, "focus_areas", None) or []) + list(project_rules.focus):
        if area and area not in focus_areas:
            focus_areas.append(area)

    budget = int(getattr(cfg, "batch_chars", None) or DEFAULT_TOKEN_BUDGET)
    trimmed_files, relevant_files, trim_notes = _apply_context_budget(
        files, relevant_files, budget)
    memory_notes = memory_notes + trim_notes

    return ReviewContext(
        pr=pr,
        files=trimmed_files,
        relevant_files=relevant_files,
        project_rules=project_rules,
        previous_findings=previous_findings,
        memory_notes=memory_notes,
        focus_areas=focus_areas,
        token_budget=budget,
    )
