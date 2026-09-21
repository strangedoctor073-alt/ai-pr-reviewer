"""Review identity helpers.

Deliberately thin: the types live in :mod:`ai_pr_reviewer.models`; this module
re-exports them under one import path and adds a few pure helpers for turning a
:class:`~ai_pr_reviewer.models.PRContext` into a stable review identity.
"""
from __future__ import annotations

from .models import FindingState, PRContext, ReviewKey, ReviewState

__all__ = [
    "FindingState",
    "ReviewKey",
    "ReviewState",
    "is_persistable",
    "review_id_for",
    "review_key_for",
]


def review_key_for(pr: PRContext) -> ReviewKey:
    """Build the :class:`ReviewKey` (repo + PR number + head SHA) for a PR."""
    return ReviewKey(repo=pr.repo, pr_number=pr.pr_number, head_sha=pr.head_sha)


def review_id_for(pr: PRContext) -> str:
    """Shortcut for ``review_key_for(pr).as_id()``."""
    return review_key_for(pr).as_id()


def is_persistable(key: ReviewKey) -> bool:
    """True if ``key`` identifies a real commit of a real pull request.

    Local runs (``--diff-file``) have ``pr_number == 0`` and no head SHA, so
    every such run would share one identity (``local/project#0@``). Callers that
    persist state or skip "already reviewed" commits should check this first.
    """
    return bool(key.repo) and key.pr_number > 0 and bool(key.head_sha)
