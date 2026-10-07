"""Context assembly for the AI provider.

``build_context`` is the single seam the rest of the pipeline calls
into: it takes the raw diff + config and hands back one ``ReviewContext``
containing everything ``AIProvider.analyze()`` (in
``ai/provider.py``) needs — changed files, the repo's trusted
``ReviewPolicy``, previous findings, repository memory, repository
context, and a character budget that's already been enforced.

Two things this module deliberately does NOT do:
  * browse the repository. ``repo_context`` is a *bounded* set of named
    files collected by :mod:`ai_pr_reviewer.repo_context` (strict budget,
    no listing, no search); everything else about the repo stays out;
  * build a real token-aware optimizer for the budget — a simple greedy
    trim from the end is explicitly called out as good enough.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass, field

from . import memory as memory_rules
from .config import Config
from .diff_parser import FileDiff
from .models import Finding, PRContext
from .repo_context import RepoContextEntry, collect_repository_context
from .rules import ReviewPolicy, load_project_rules
from .security import redact_secrets
from .storage import has_capability
from .storage_schema import (CAP_LIST_REPO_MEMORY, CAP_PREVIOUS_FINDINGS,
                             CAP_REPO_MEMORY)

log = logging.getLogger(__name__)

DEFAULT_TOKEN_BUDGET = 80_000


# --------------------------------------------------------------------------- ReviewContext

@dataclass
class ReviewContext:
    """Everything an :class:`AIProvider` needs to review one PR (shared
    contract type — see ``ai_pr_reviewer/ai/provider.py``)."""

    pr: PRContext
    files: list[FileDiff]
    project_rules: ReviewPolicy | None
    previous_findings: list[Finding]
    memory_notes: list[str]
    focus_areas: list[str]
    token_budget: int = DEFAULT_TOKEN_BUDGET
    # V3 C3: other repository files worth showing the reviewer (untrusted,
    # already secret-redacted; the providers screen + fence them).
    repo_context: list[RepoContextEntry] = field(default_factory=list)
    # V3 C3: collection problems (budget reached, GitHub unavailable) that
    # must surface as run warnings rather than silently vanish.
    context_warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- ContextBudget

def _apply_context_budget(files: list[FileDiff],
                          budget: int) -> tuple[list[FileDiff], list[str]]:
    """Simple greedy trim so the assembled context stays under ``budget``
    characters: trim the lowest-priority (last) changed files' hunks,
    working backward, dropping a whole file only once its hunks are
    exhausted.

    Never mutates the caller's ``files`` — the orchestrator needs the
    untrimmed diffs later (e.g. to post inline comments), so trimming
    works on copies.

    A non-positive ``budget`` is treated as "unlimited" rather than as
    "trim everything" — a misconfigured ``cfg.batch_chars`` shouldn't
    silently discard the whole review.
    """
    notes: list[str] = []

    def total(fs: list[FileDiff]) -> int:
        return sum(len(f.to_diff_text()) for f in fs)

    if budget <= 0 or total(files) <= budget:
        return list(files), notes

    trimmed = [copy.copy(f) for f in files]
    for f in trimmed:
        f.hunks = list(f.hunks)  # own list, so popping doesn't touch the original
    running = total(trimmed)

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

    return trimmed, notes


# --------------------------------------------------------------------------- memory / repo context

def _load_memory_entries(storage, repo: str, paths: list[str]) -> list[dict]:
    """Human-authored project memory for ``paths``, or ``[]``.

    V3-E04-T04: the backend's *declared* capability picks the path —
    ``list_repo_memory`` gets the C7 treatment (categories, disabled
    rows, mute rows split out); a backend without it falls back to
    ``get_repo_memory`` (plain notes, logged as a degradation); a
    backend with neither continues without memory, also logged.
    Storage failure is always "no memory", never a failed review.
    """
    if storage is None:
        return []

    if has_capability(storage, CAP_LIST_REPO_MEMORY):
        try:
            return memory_rules.select_memory(storage.list_repo_memory(repo) or [], paths)
        except Exception as exc:  # noqa: BLE001 — storage must never take the review down
            log.warning("list_repo_memory(%s) failed — continuing without "
                        "repository memory (%s)", repo, exc)
            return []

    if has_capability(storage, CAP_REPO_MEMORY):
        log.warning("storage backend %s lacks list_repo_memory — falling back "
                    "to plain get_repo_memory (no categories/disabled/mute-row "
                    "handling)", type(storage).__name__)
        try:
            notes = storage.get_repo_memory(repo, paths) or []
        except Exception as exc:  # noqa: BLE001
            log.warning("get_repo_memory(%s) failed — continuing without "
                        "repository memory (%s)", repo, exc)
            return []
        return memory_rules.select_memory(
            [{"note": n, "path_pattern": "*"} for n in notes if n], paths)

    log.warning("storage backend %s provides no repository-memory capability "
                "— continuing without memory", type(storage).__name__)
    return []


def _collect_repo_context(gh, pr: PRContext, files: list[FileDiff],
                          cfg: Config) -> tuple[list[RepoContextEntry], list[str]]:
    """Bounded repository context; never raises, never blocks a review."""
    if gh is None:
        return [], []
    try:
        return collect_repository_context(gh, pr, files, cfg)
    except Exception as exc:  # noqa: BLE001 — context is a bonus, not a dependency
        log.warning("repository context collection failed: %s", exc)
        return [], ["repository context unavailable "
                    f"({type(exc).__name__}); continuing the review without it"]


# --------------------------------------------------------------------------- build_context

def build_context(pr: PRContext, files: list[FileDiff], cfg: Config,
                  storage=None, gh=None) -> ReviewContext:
    """Assemble a :class:`ReviewContext` for this PR.

    Repository memory (``memory_notes``) comes from whatever storage
    backend is configured — in practice the dashboard, where humans write
    it through the feedback/memory API. It is PR-adjacent text, so it is
    secret-redacted here; the providers additionally fence it as untrusted
    data before it reaches a prompt.

    Repository context (``repo_context``) is fetched from GitHub through
    ``gh`` when one is available (local ``--diff-file`` runs have none). It
    is bounded by ``cfg.repo_context_chars``, a non-positive value disables
    it, and any GitHub failure degrades to a warning — see
    :mod:`ai_pr_reviewer.repo_context`.
    """
    repo_root = getattr(cfg, "repo_root", None) or "."
    rules_file = getattr(cfg, "rules_file", None) or ".ai-pr-reviewer.yml"
    project_rules = load_project_rules(repo_root, filename=rules_file)

    previous_findings: list[Finding] = []
    if has_capability(storage, CAP_PREVIOUS_FINDINGS):
        try:
            raw_findings = storage.get_previous_findings(pr.repo, pr.pr_number) or []
            previous_findings = [
                f if isinstance(f, Finding) else Finding.from_dict(f)
                for f in raw_findings
            ]
        except Exception as exc:
            log.warning("get_previous_findings(%s, %s) failed: %s",
                        pr.repo, pr.pr_number, exc)

    paths = [f.path for f in files]
    memory_notes = [
        redact_secrets(memory_rules.format_note(entry))
        for entry in _load_memory_entries(storage, pr.repo, paths)
        if entry.get("note")
    ]

    repo_entries, repo_warnings = _collect_repo_context(gh, pr, files, cfg)

    focus_areas: list[str] = []
    for area in list(getattr(cfg, "focus_areas", None) or []) + list(project_rules.focus):
        if area and area not in focus_areas:
            focus_areas.append(area)

    budget = int(getattr(cfg, "batch_chars", None) or DEFAULT_TOKEN_BUDGET)
    trimmed_files, trim_notes = _apply_context_budget(files, budget)
    memory_notes = memory_notes + trim_notes

    return ReviewContext(
        pr=pr,
        files=trimmed_files,
        project_rules=project_rules,
        previous_findings=previous_findings,
        memory_notes=memory_notes,
        focus_areas=focus_areas,
        token_budget=budget,
        repo_context=repo_entries,
        context_warnings=repo_warnings,
    )
