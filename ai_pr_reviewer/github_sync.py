"""Synchronize the internal finding lifecycle with GitHub review comments
(V3 C5).

The reviewer keeps its own truth — findings with fingerprints and states in
storage — and GitHub is a *view* of that truth. This module is the adapter:

* **stable mapping.** A finding records ``github_comment_id`` the first time
  a comment is posted for it (from the posting response, or by matching the
  comment we just created), and the id survives subsequent reviews, so the
  same finding always points at the same comment.
* **no duplicates.** A finding that already has a comment id is updated,
  never re-posted (``cli`` filters it out of the inline-comment set).
* **state changes are reflected.** When a finding flips to resolved, muted,
  dismissed or reopened, its existing comment is PATCHed with a short
  marker so a reader of the PR sees the current state without a second
  comment being opened.
* **failures never touch the review.** Every GitHub error here degrades to
  a warning (deleted comment, rate limit, missing permission): the internal
  result, the report and the step summary are already written and stay
  intact.

Only ``pull-requests: write`` — the permission the Action already has — is
used. No check runs (they would need ``checks: write``).
"""
from __future__ import annotations

import logging

from .github_client import GitHubError
from .models import Finding

log = logging.getLogger(__name__)

#: Marker prepended to a comment body once the finding reaches that state.
#: States not listed here (new/active) keep their body exactly as posted.
STATE_MARKERS = {
    "resolved": "\u2705 **Resolved**",
    "muted": "\U0001f507 **Muted**",
    "dismissed": "\U0001f6ab **Dismissed**",
    "reopened": "\U0001f501 **Reopened**",
}

MAX_SYNC_ERRORS = 5      # one loud warning per review, not one per comment


def render_finding_comment(f: Finding) -> str:
    """Inline-comment body for ``f``.

    Single source of truth: the same text is used when the comment is first
    posted and when it is later updated, so a state marker can be added
    without ever losing the finding's content.
    """
    body = (f"**\U0001f916 {f.severity.upper()}: {f.title}** `{f.category}`\n\n"
            f"{f.explanation}")
    if f.suggestion:
        body += "\n\n```suggestion\n" + f.suggestion + "\n```"
    return body


def comment_key(f: Finding) -> tuple[str, int | None]:
    """(path, line) anchor a GitHub comment is keyed by."""
    return (f.file, f.line)


def record_comment_ids(findings: list[Finding], post_response) -> int:
    """Take comment ids out of a ``post_review`` response, if it has any.

    The 422-recovery path posts comments one by one and those responses
    carry an ``id``; the grouped-review response normally does not (callers
    fall back to :func:`link_comment_ids`). Returns how many findings
    gained an id.
    """
    if not isinstance(post_response, dict):
        return 0
    ids = post_response.get("comment_ids")
    if not isinstance(ids, dict):
        return 0
    linked = 0
    for f in findings:
        if f.github_comment_id:
            continue
        raw = ids.get(comment_key(f))
        if raw in (None, ""):
            continue
        try:
            f.github_comment_id = int(raw)
            linked += 1
        except (TypeError, ValueError):
            continue
    return linked


def link_comment_ids(gh, pr_number: int, findings: list[Finding],
                     head_sha: str) -> tuple[int, list[str]]:
    """Match freshly posted findings to the comments GitHub just created.

    One bounded read of the PR's recent review comments, matched on
    (path, line) + commit + the exact first line of the body we rendered —
    so a comment written by a human (or an older review) is never claimed
    as ours.

    Degrades to a warning: without ids the only cost is that the next
    review cannot update that comment.
    """
    warnings: list[str] = []
    pending = [f for f in findings if not f.github_comment_id]
    if not pending or gh is None:
        return 0, warnings

    lister = getattr(gh, "list_review_comments", None)
    if not callable(lister):
        return 0, warnings
    try:
        comments = lister(pr_number)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"could not list GitHub review comments "
                        f"({type(exc).__name__}); findings were left without a "
                        f"comment mapping for this run.")
        return 0, warnings

    by_key: dict[tuple[str, int | None], list[dict]] = {}
    for c in comments:
        if not isinstance(c, dict):
            continue
        by_key.setdefault((str(c.get("path") or ""),
                           c.get("line") or c.get("original_line")), []).append(c)

    linked = 0
    for f in pending:
        candidates = by_key.get(comment_key(f)) or []
        first_line = render_finding_comment(f).split("\n", 1)[0]
        for c in sorted(candidates, key=lambda c: str(c.get("created_at") or ""),
                        reverse=True):
            if head_sha and c.get("commit_id") and c.get("commit_id") != head_sha:
                continue
            if str(c.get("body") or "").split("\n", 1)[0] != first_line:
                continue
            try:
                f.github_comment_id = int(c["id"])
            except (KeyError, TypeError, ValueError):
                continue
            linked += 1
            break
    return linked, warnings


def sync_finding_states(gh, findings: list[Finding]) -> tuple[int, list[str]]:
    """Update existing GitHub comments for findings that reached a closed
    (or reopened) state.

    ``gh`` may be None (local mode) and every failure becomes a warning —
    never an exception. Returns ``(comments updated, warnings)``.
    """
    if gh is None:
        return 0, []
    updater = getattr(gh, "update_review_comment", None)
    if not callable(updater):
        return 0, []          # client too old / test double: nothing to sync

    warnings: list[str] = []
    updated = 0
    errors = 0

    for f in findings:
        marker = STATE_MARKERS.get(str(getattr(f, "state", "") or ""))
        if not marker or not f.github_comment_id:
            continue
        body = f"{marker}\n\n{render_finding_comment(f)}"
        try:
            updater(int(f.github_comment_id), body)
            updated += 1
        except GitHubError as exc:
            errors += 1
            if errors > MAX_SYNC_ERRORS:
                continue
            if exc.status_code == 404:
                warnings.append(
                    f"GitHub comment {f.github_comment_id} for '{f.title}' no longer "
                    f"exists (deleted?); kept the internal state "
                    f"({getattr(f, 'state', '?')}) without touching GitHub."
                )
            else:
                warnings.append(
                    f"could not update GitHub comment {f.github_comment_id} "
                    f"({type(exc).__name__}"
                    f"{f', {exc.status_code}' if exc.status_code else ''}); "
                    f"the internal review result is unchanged."
                )
        except Exception as exc:  # noqa: BLE001 — one bad comment must not lose a review
            errors += 1
            if errors <= MAX_SYNC_ERRORS:
                warnings.append(
                    f"could not update GitHub comment {f.github_comment_id} "
                    f"({type(exc).__name__}); the internal review result is unchanged."
                )
        log.debug("sync: %s -> %s", f.fingerprint, f.state)

    if errors > MAX_SYNC_ERRORS:
        warnings.append(f"... {errors - MAX_SYNC_ERRORS} more GitHub comment "
                        f"update(s) skipped this run.")
    return updated, warnings


__all__ = [
    "MAX_SYNC_ERRORS", "STATE_MARKERS", "comment_key", "link_comment_ids",
    "record_comment_ids", "render_finding_comment", "sync_finding_states",
]
