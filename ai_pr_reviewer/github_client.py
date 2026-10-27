"""Thin GitHub REST client covering exactly what the reviewer needs:
fetch PR metadata + diff (whole PR or just the commits since the last
review), read repository files for context, post a review with inline
comments, fall back to a regular PR comment when inline anchoring fails."""
from __future__ import annotations

import base64
import json
import os
import sys
from typing import TYPE_CHECKING
from urllib.parse import quote

from .github_ratelimit import RateLimitBlocked, RateLimiter
from .models import PRContext

if TYPE_CHECKING:  # annotation-only; the runtime import stays lazy in __init__
    from .retry import RetryPolicy

# GitHub returns at most 100 items per page from /pulls/{n}/files (and 3000 in
# total). Stop after 10 pages so a pathological PR can't loop us forever.
_FILES_PER_PAGE = 100
_MAX_FILE_PAGES = 10


class GitHubError(RuntimeError):
    """A GitHub call failed (or was refused before being sent).

    ``status_code`` is the HTTP status when the error came from a response, so
    callers can tell "file not found" (404) or "diff too large" (406/422) from
    a rate limit or an auth failure without parsing the message. It is ``None``
    for client-side refusals.
    """

    def __init__(self, message: str = "", status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class GitHubRateLimited(GitHubError):
    """A GitHub read was refused or withheld because of a rate limit
    (V4.6-E01-T01).

    ``reason`` is one of the ``github_ratelimit.REASON_*`` values and
    ``retry_after`` the seconds GitHub (or our default) says to wait. Callers
    that poll optional data catch this and degrade with a label; it is never
    a reason to fail a review.
    """

    def __init__(self, message: str = "", reason: str = "",
                 retry_after: float = 0.0, status_code: int | None = 429):
        super().__init__(message, status_code=status_code)
        self.reason = reason
        self.retry_after = retry_after


def _api_error(what: str, r) -> GitHubError:
    return GitHubError(f"{what} failed ({r.status_code}): {r.text[:300]}",
                       status_code=r.status_code)


def _safe_repo_path(path: str) -> str:
    """Validate a repo-relative path before it is spliced into an API URL.

    Candidate paths can be derived from untrusted PR content (imports, file
    names), and the request carries our token, so never let one climb out of
    the /contents/ route with ``..`` or smuggle in empty/absolute segments.
    """
    if not path or any(seg in ("", ".", "..") for seg in path.split("/")):
        raise GitHubError(f"refusing unsafe repository path: {path!r}")
    return path


class GitHubClient:
    def __init__(self, token: str, repo: str, api_url: str = "https://api.github.com",
                 retry: "RetryPolicy | None" = None,
                 rate_limiter: RateLimiter | None = None):
        import httpx

        from .retry import RetryPolicy

        self.repo = repo.strip("/")
        self._retry = retry or RetryPolicy()
        self._limiter = rate_limiter or RateLimiter()
        self._http = httpx.Client(
            base_url=api_url.rstrip("/"),
            timeout=60.0,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ai-pr-reviewer",
            },
        )

    # ---------------------------------------------------------------- metadata
    def get_pr(self, number: int) -> tuple[PRContext, str]:
        """Return (PRContext, unified diff text)."""
        r = self._http.get(f"/repos/{self.repo}/pulls/{number}")
        if r.status_code != 200:
            raise _api_error("GET pull request", r)
        pr = r.json()

        ctx = PRContext(
            repo=self.repo,
            pr_number=number,
            pr_title=pr.get("title", ""),
            author=(pr.get("user") or {}).get("login", ""),
            branch=(pr.get("head") or {}).get("ref", ""),
            base=(pr.get("base") or {}).get("ref", ""),
            head_sha=(pr.get("head") or {}).get("sha", ""),
            url=pr.get("html_url", ""),
            # D1 fix: repository context must be fetched at the *base*
            # revision — a PR must never choose what its own review reads.
            base_sha=(pr.get("base") or {}).get("sha", ""),
        )

        r2 = self._http.get(
            f"/repos/{self.repo}/pulls/{number}",
            headers={"Accept": "application/vnd.github.v3.diff"},
        )
        if r2.status_code != 200:
            raise _api_error("GET diff", r2)
        return ctx, r2.text

    def get_event_context(self) -> PRContext | None:
        """Build PRContext from GITHUB_EVENT_PATH when running inside Actions."""
        path = os.environ.get("GITHUB_EVENT_PATH")
        if not path or not os.path.exists(path):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                event = json.load(fh)
            pr = event.get("pull_request") or event.get("workflow_run", {})
            if not pr:
                return None
            repo_full = os.environ.get("GITHUB_REPOSITORY", self.repo)
            return PRContext(
                repo=repo_full,
                pr_number=pr.get("number", 0),
                pr_title=pr.get("title", ""),
                author=(pr.get("user") or {}).get("login", ""),
                branch=(pr.get("head") or {}).get("ref", ""),
                base=(pr.get("base") or {}).get("ref", ""),
                head_sha=(pr.get("head") or {}).get("sha", ""),
                url=pr.get("html_url", ""),
                # D1 fix: same base-revision invariant as get_pr() — the
                # event payload carries base.sha alongside head.sha.
                base_sha=(pr.get("base") or {}).get("sha", ""),
            )
        except Exception:
            return None

    # ------------------------------------------------- incremental / repo reads
    def compare_commits(self, base_sha: str, head_sha: str) -> str:
        """Unified diff of what changed between two commits.

        Used for incremental review: pass the last-reviewed SHA as ``base_sha``
        and the PR's current head as ``head_sha``. The response is the same
        git-format diff ``get_pr`` returns, so ``parse_unified_diff`` consumes
        it unchanged. Uses GitHub's three-dot form (``base...head``), i.e. the
        diff from the merge base of the two commits to ``head``.

        Raises GitHubError on any non-200 (unknown SHA -> 404, diff over
        GitHub's size limits -> 406/422, ...); callers can fall back to the
        full PR diff.
        """
        if not base_sha or not head_sha:
            raise GitHubError("compare_commits needs both base_sha and head_sha")
        base, head = quote(base_sha, safe=""), quote(head_sha, safe="")
        r = self._http.get(
            f"/repos/{self.repo}/compare/{base}...{head}",
            headers={"Accept": "application/vnd.github.v3.diff"},
        )
        if r.status_code != 200:
            raise _api_error("GET compare", r)
        return r.text

    def get_pr_files(self, number: int) -> list[dict]:
        """Every file entry of the PR (GET /pulls/{n}/files), across pages.

        Pages are requested until an empty one comes back, capped at
        ``_MAX_FILE_PAGES`` pages (1000 files); if the cap is hit a warning is
        printed and the list may be incomplete.
        """
        out: list[dict] = []
        for page in range(1, _MAX_FILE_PAGES + 1):
            r = self._http.get(
                f"/repos/{self.repo}/pulls/{int(number)}/files",
                params={"per_page": _FILES_PER_PAGE, "page": page},
            )
            if r.status_code != 200:
                raise _api_error("GET pull request files", r)
            batch = r.json()
            if not isinstance(batch, list):
                raise GitHubError("GET pull request files returned an unexpected payload")
            if not batch:
                break
            out.extend(batch)
        else:
            print(f"[ai-pr-reviewer] warning: PR #{number} has more than "
                  f"{_MAX_FILE_PAGES * _FILES_PER_PAGE} changed files; file list truncated",
                  file=sys.stderr)
        return out

    def get_file(self, path: str, ref: str) -> str:
        """Text of ``path`` at commit/branch ``ref`` (contents API, so <= 1 MB).

        Raises GitHubError if the file is missing (``status_code == 404``), is
        a directory/symlink/submodule, is too large to be returned inline, or
        if ``path`` isn't a plain repo-relative path.
        """
        clean = _safe_repo_path(path)
        r = self._http.get(
            f"/repos/{self.repo}/contents/{quote(clean, safe='/')}",
            params={"ref": ref} if ref else None,
        )
        if r.status_code != 200:
            raise _api_error("GET file", r)
        data = r.json()
        if not isinstance(data, dict) or data.get("type") != "file":
            raise GitHubError(f"{clean} is not a regular file")
        if data.get("encoding") != "base64":
            # Files over 1 MB come back with encoding "none" and no content.
            raise GitHubError(f"{clean} is too large to fetch through the contents API")
        return base64.b64decode(data.get("content") or "").decode("utf-8", errors="replace")

    # ------------------------------------------------------------------ review
    def post_review(self, number: int, commit_id: str, body: str,
                    comments: list[dict]) -> dict:
        """Post a grouped review, recovering valid inline comments after a 422."""
        payload = {
            "commit_id": commit_id,
            "event": "COMMENT",
            "body": body,
            "comments": comments,
        }
        r = self._http.post(f"/repos/{self.repo}/pulls/{number}/reviews", json=payload)
        if r.status_code in (200, 201):
            return {"ok": True, "status": r.status_code, "body": r.json()}
        if r.status_code != 422 or not comments:
            raise _api_error("POST review", r)

        summary_payload = {**payload, "comments": []}
        summary = self._http.post(f"/repos/{self.repo}/pulls/{number}/reviews",
                                  json=summary_payload)
        if summary.status_code not in (200, 201):
            raise _api_error("POST review fallback", summary)

        dropped = 0
        comment_ids: dict[tuple, int] = {}
        for comment in comments:
            inline = self._http.post(
                f"/repos/{self.repo}/pulls/{number}/comments",
                json={"commit_id": commit_id, **comment},
            )
            if inline.status_code in (200, 201):
                # Capture the id now: it is the only response in this flow
                # that carries one, and it is what lets the next review
                # update this comment instead of opening a duplicate.
                try:
                    created = inline.json()
                    if isinstance(created, dict) and created.get("id") is not None:
                        comment_ids[(comment.get("path"), comment.get("line"))] = \
                            created["id"]
                except Exception:  # noqa: BLE001 — ids are a bonus, never a failure
                    pass
                continue
            if inline.status_code == 422:
                dropped += 1
                continue
            raise _api_error("POST inline comment fallback", inline)
        return {
            "ok": True,
            "status": summary.status_code,
            "body": summary.json(),
            "dropped": dropped,
            "recovered": True,
            "comment_ids": comment_ids,
        }

    def create_comment(self, number: int, body: str) -> dict:
        r = self._http.post(f"/repos/{self.repo}/issues/{number}/comments",
                            json={"body": body})
        if r.status_code in (200, 201):
            return {"ok": True}
        raise _api_error("POST comment", r)

    # ------------------------------------------------- comment sync (V3 C5)
    def list_review_comments(self, number: int, limit: int = 100) -> list[dict]:
        """The PR's inline review comments, newest first, capped at ``limit``.

        One bounded page — used only to attach ids to comments this run just
        posted, never to enumerate a whole PR's history.
        """
        r = self._http.get(f"/repos/{self.repo}/pulls/{number}/comments",
                           params={"sort": "created", "direction": "desc",
                                   "per_page": min(int(limit), 100)})
        if r.status_code != 200:
            raise _api_error("GET review comments", r)
        data = r.json()
        return list(data)[:limit] if isinstance(data, list) else []

    def update_review_comment(self, comment_id: int, body: str) -> dict:
        """Edit an existing inline review comment (state markers, updates).

        Bounded retries on transient failures (429/5xx/timeouts) through the
        shared ``RetryPolicy``; permanent ones — notably 404 for a comment
        the author deleted — raise immediately so callers can skip instead
        of retrying a call that can never succeed.
        """
        r = self._retry.call(
            self._http.patch,
            f"/repos/{self.repo}/pulls/comments/{int(comment_id)}",
            json={"body": body},
        )
        if r.status_code in (200, 201):
            return {"ok": True, "status": r.status_code, "body": r.json()}
        raise _api_error("PATCH review comment", r)

    # ------------------------------ V4.6-E01-T01 · rate-limit-aware reads
    # The one general-purpose, quota-aware read path. Features that poll
    # GitHub (CI runs today; issues and releases later) call ``get_json`` —
    # they never build their own limiter or call ``self._http`` directly for
    # optional reads. Existing methods above are intentionally unchanged.
    def _safe_read_path(self, path: str) -> str:
        """Confine a read to this repository's REST namespace.

        The request carries our token, so a caller-built path must never
        reach another repository, an absolute URL, or climb with ``..``.
        """
        prefix = f"/repos/{self.repo}/"
        rest = path[len(prefix):] if isinstance(path, str) and \
            path.startswith(prefix) else ""
        if (not rest or any(seg in ("", ".", "..") for seg in rest.split("/"))
                or not all(ch.isascii() and (ch.isalnum() or ch in "._-/")
                           for ch in rest)):
            raise GitHubError(f"refusing unsafe read path: {path!r}")
        return path

    def get_json(self, path: str, params: dict | None = None):
        """GET ``path`` (under ``/repos/{repo}/``) and return the parsed JSON.

        Interface contract (reused by later epics — do not fork it):

        * GET only; there is no write twin of this method.
        * Quota-aware: waits inside the ``RateLimitPolicy`` bounds, keeps a
          reserve for the review's own calls, re-sends a throttled request at
          most ``max_throttle_retries`` times, and otherwise raises
          :class:`GitHubRateLimited` (``reason``, ``retry_after``) instead of
          hanging.
        * Any other non-200 raises ``GitHubError`` carrying ``status_code``
          (a bare 403 stays a plain authorization error, not a throttle).
        * Transient 5xx/timeouts are not retried here: optional reads degrade
          with a label rather than spend quota re-asking.
        """
        safe = self._safe_read_path(path)
        policy = self._limiter.policy
        attempt = 0
        while True:
            try:
                self._limiter.before_request()
            except RateLimitBlocked as blocked:
                raise GitHubRateLimited(
                    str(blocked), reason=blocked.reason,
                    retry_after=blocked.retry_after) from None
            r = self._http.get(safe, params=params)
            throttle = self._limiter.observe(
                r.status_code, r.headers,
                r.text if r.status_code == 403 else "")
            if throttle is None:
                break
            attempt += 1
            if attempt > policy.max_throttle_retries:
                raise GitHubRateLimited(
                    f"GET {safe.rsplit('/', 1)[-1]} throttled by GitHub "
                    f"({throttle.kind})", reason=throttle.kind,
                    retry_after=throttle.wait_seconds,
                    status_code=r.status_code)
            try:
                self._limiter.backoff(throttle)
            except RateLimitBlocked as blocked:
                raise GitHubRateLimited(
                    str(blocked), reason=blocked.reason,
                    retry_after=blocked.retry_after,
                    status_code=r.status_code) from None
        if r.status_code != 200:
            raise _api_error(f"GET {safe.rsplit('/', 1)[-1]}", r)
        try:
            return r.json()
        except ValueError:
            raise GitHubError(
                f"GET {safe.rsplit('/', 1)[-1]} returned a non-JSON payload",
                status_code=r.status_code) from None

    def rate_limit_stats(self) -> dict:
        """Counts-only view of quota use for telemetry/reports."""
        return self._limiter.stats()

    # ------------------------------------------------------- helper utilities
    @staticmethod
    def file_url(repo: str, sha: str, path: str, line: int | None) -> str:
        loc = f"#L{line}" if line else ""
        return f"https://github.com/{repo}/blob/{sha}/{path}{loc}"
