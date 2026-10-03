"""Context assembly for the AI provider.

``build_context`` is the single seam the rest of the pipeline calls
into: it takes the raw diff + config and hands back one ``ReviewContext``
containing everything ``AIProvider.analyze()`` (in
``ai/provider.py``) needs — changed files, the repo's trusted
``ReviewPolicy``, previous findings, repository memory, and a character
budget that's already been enforced.

Two things this module deliberately does NOT do:
  * fetch other repository files to enrich the diff (there is no content
    fetcher in the review path; a future context stage can add one
    without changing this signature);
  * build a real token-aware optimizer for the budget — a simple greedy
    trim from the end is explicitly called out as good enough.
"""
from __future__ import annotations

import copy
import logging
from dataclasses import dataclass

from .config import Config
from .diff_parser import FileDiff
from .models import Finding, PRContext
from .rules import ReviewPolicy, load_project_rules
from .security import redact_secrets

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


# --------------------------------------------------------------------------- build_context

def build_context(pr: PRContext, files: list[FileDiff], cfg: Config,
                  storage=None) -> ReviewContext:
    """Assemble a :class:`ReviewContext` for this PR.

    Repository memory (``memory_notes``) comes from whatever storage
    backend is configured — in practice the dashboard, where humans write
    it through the feedback/memory API. It is PR-adjacent text, so it is
    secret-redacted here; the providers additionally fence it as untrusted
    data before it reaches a prompt.
    """
    repo_root = getattr(cfg, "repo_root", None) or "."
    rules_file = getattr(cfg, "rules_file", None) or ".ai-pr-reviewer.yml"
    project_rules = load_project_rules(repo_root, filename=rules_file)

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
    memory_getter = getattr(storage, "get_repo_memory", None) if storage is not None else None
    if callable(memory_getter):
        try:
            memory_notes = [
                redact_secrets(str(note))
                for note in (memory_getter(pr.repo, [f.path for f in files]) or [])
                if note
            ]
        except Exception as exc:  # storage must never take the review down
            log.warning("get_repo_memory(%s) failed — continuing without "
                       "repository memory (%s)", pr.repo, exc)
            memory_notes = []

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
    )
