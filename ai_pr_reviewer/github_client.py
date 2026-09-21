"""Thin GitHub REST client covering exactly what the reviewer needs:
fetch PR metadata + diff (whole PR or just the commits since the last
review), read repository files for context, post a review with inline
comments, fall back to a regular PR comment when inline anchoring fails,
edit an existing review comment, and publish a check run."""
from __future__ import annotations

import base64
import json
import os
import sys
from urllib.parse import quote

from .models import PRContext

# GitHub returns at most 100 items per page from /pulls/{n}/files (and 3000 in
# total). Stop after 10 pages so a pathological PR can't loop us forever.
_FILES_PER_PAGE = 100
_MAX_FILE_PAGES = 10

# The check-run API rejects output.summary / output.text over 65,535 characters.
_CHECK_TEXT_LIMIT = 65_000
_CHECK_STATUSES = ("in_progress", "completed")
_CHECK_CONCLUSIONS = ("success", "neutral", "failure")


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


def _clip(text: str, limit: int = _CHECK_TEXT_LIMIT) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    return text[: limit - 60].rstrip() + "\n\n... [truncated to fit GitHub's check-run limit]"


class GitHubClient:
    def __init__(self, token: str, repo: str, api_url: str = "https://api.github.com"):
        import httpx

        self.repo = repo.strip("/")
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
        for comment in comments:
            inline = self._http.post(
                f"/repos/{self.repo}/pulls/{number}/comments",
                json={"commit_id": commit_id, **comment},
            )
            if inline.status_code in (200, 201):
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
        }

    def create_comment(self, number: int, body: str) -> dict:
        r = self._http.post(f"/repos/{self.repo}/issues/{number}/comments",
                            json={"body": body})
        if r.status_code in (200, 201):
            return {"ok": True}
        raise _api_error("POST comment", r)

    def update_review_comment(self, comment_id: int, body: str) -> dict:
        """Edit an existing inline review comment in place (returns its JSON)."""
        r = self._http.patch(
            f"/repos/{self.repo}/pulls/comments/{int(comment_id)}", json={"body": body})
        if r.status_code != 200:
            raise _api_error("PATCH review comment", r)
        return r.json()

    # ------------------------------------------------------------- check runs
    def create_check_run(self, head_sha: str, name: str, status: str,
                         conclusion: str | None, summary: str, text: str) -> dict:
        """Create a check run on ``head_sha`` (returns the API response, incl. ``id``).

        ``status`` is "in_progress" or "completed"; ``conclusion`` is required
        when completed ("success" | "neutral" | "failure") and must be None
        otherwise. Bad combinations raise ValueError before anything is sent.
        Needs ``checks: write`` on the token.
        """
        if status not in _CHECK_STATUSES:
            raise ValueError(f"status must be one of {_CHECK_STATUSES}, got {status!r}")
        if status == "completed" and conclusion not in _CHECK_CONCLUSIONS:
            raise ValueError(
                f"a completed check run needs a conclusion in {_CHECK_CONCLUSIONS}, "
                f"got {conclusion!r}")
        if status != "completed" and conclusion is not None:
            raise ValueError("conclusion is only valid when status is 'completed'")

        output = {"title": name, "summary": _clip(summary)}
        if text:
            output["text"] = _clip(text)
        payload = {"name": name, "head_sha": head_sha, "status": status, "output": output}
        if status == "completed":
            payload["conclusion"] = conclusion
        r = self._http.post(f"/repos/{self.repo}/check-runs", json=payload)
        if r.status_code not in (200, 201):
            raise _api_error("POST check run", r)
        return r.json()

    # ------------------------------------------------------- helper utilities
    @staticmethod
    def file_url(repo: str, sha: str, path: str, line: int | None) -> str:
        loc = f"#L{line}" if line else ""
        return f"https://github.com/{repo}/blob/{sha}/{path}{loc}"
