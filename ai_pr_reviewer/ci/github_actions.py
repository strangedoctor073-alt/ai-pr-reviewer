"""GitHub Actions read-only ingestion adapters (V4.6-E01-T02).

Turns ``GET /repos/{repo}/actions/runs`` and ``.../runs/{id}/jobs`` responses
into normalized :class:`CIRunRecord` objects.

Contract:

* **Read-only.** The adapter is handed a :class:`ReadOnlyGitHub`; it can only
  ``get_json`` allowlisted endpoints. (T05.)
* **Never fatal.** A rate limit, a missing ``actions: read`` permission, a
  failed jobs read or a malformed entry degrades with a **label** from a fixed
  vocabulary (``DEGRADED_*``); nothing here raises for a GitHub-side problem.
  Only :class:`ReadOnlyViolation` propagates — it is a bug, not a condition.
* **Bounded.** One runs read (single page, ``MAX_RUNS_PER_INGEST`` kept) and
  jobs reads only for runs that did not pass, at most ``MAX_JOB_READS`` — the
  whole ingestion stays within ``1 + MAX_JOB_READS`` requests, plus the
  optional PR-commit read below.
* **Untrusted data.** Everything goes through ``CIRunRecord`` /
  ``CIJobRecord`` normalization (see ``records``).
* **Logs.** Job logs are NOT fetched by default: GitHub serves them through a
  redirect to another host, which would be new network egress. A caller may
  inject ``log_fetcher(job_id) -> str | None`` (it must itself be read-only);
  its output is redacted, tail-truncated and bounded by
  ``MAX_LOG_EXCERPTS_PER_RUN`` before it is stored.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..github_client import GitHubError, GitHubRateLimited
from .records import (FAILING_CONCLUSIONS, JOBS_FETCHED, JOBS_TRUNCATED,
                      JOBS_UNAVAILABLE, MAX_JOBS_PER_RUN,
                      MAX_LOG_EXCERPTS_PER_RUN, CIJobRecord, CIRunRecord)
from .readonly import ReadOnlyGitHub, ReadOnlyViolation

#: Runs kept from the single page read (GitHub returns up to 100).
MAX_RUNS_PER_INGEST = 50
#: Jobs reads per ingestion (one per non-passing run).
MAX_JOB_READS = 15
#: Pages of PR commits read (100 per page) for history correlation.
MAX_COMMIT_PAGES = 2
MAX_PR_COMMITS = 200

# --------------------------------------------------- degradation vocabulary
DEGRADED_RATE_LIMITED = "rate_limited"
DEGRADED_PERMISSION = "ci_unavailable:permission_or_not_found"
DEGRADED_AUTH = "ci_unavailable:unauthorized"
DEGRADED_HTTP_ERROR = "ci_unavailable:http_error"
DEGRADED_CLIENT_ERROR = "ci_unavailable:client_error"
DEGRADED_MALFORMED_RESPONSE = "malformed_response"
DEGRADED_MALFORMED_RUNS = "malformed_runs_skipped"
DEGRADED_RUNS_TRUNCATED = "runs_truncated"
DEGRADED_JOBS_UNAVAILABLE = "jobs_unavailable"
DEGRADED_JOBS_SKIPPED = "jobs_skipped_budget"
DEGRADED_COMMITS_TRUNCATED = "pr_commits_truncated"


def degrade_label(exc: Exception) -> str:
    """Map a GitHub-side failure to a fixed label. Never echoes the message
    (it can carry response text)."""
    if isinstance(exc, GitHubRateLimited):
        return DEGRADED_RATE_LIMITED
    code = getattr(exc, "status_code", None)
    if code in (403, 404):
        return DEGRADED_PERMISSION
    if code == 401:
        return DEGRADED_AUTH
    if isinstance(code, int):
        return DEGRADED_HTTP_ERROR
    return DEGRADED_CLIENT_ERROR


def _safe_get(reader: ReadOnlyGitHub, path: str, params: dict | None):
    """``(payload, label)`` — exactly one is meaningful.

    A GitHub-side or transport failure becomes a fixed label. A
    ``ReadOnlyViolation`` is a bug in this codebase and always propagates
    (it is checked first: it subclasses ``ValueError``).
    """
    try:
        return reader.get_json(path, params), ""
    except ReadOnlyViolation:
        raise
    except GitHubError as exc:
        return None, degrade_label(exc)
    except Exception:  # noqa: BLE001 — transport errors never fail a review
        return None, DEGRADED_CLIENT_ERROR


@dataclass
class CIIngestResult:
    records: list[CIRunRecord] = field(default_factory=list)
    degraded: list[str] = field(default_factory=list)
    requests_made: int = 0

    def label(self, text: str) -> None:
        if text not in self.degraded:
            self.degraded.append(text)


def _as_list(payload, key: str):
    if isinstance(payload, dict) and isinstance(payload.get(key), list):
        return payload[key]
    return None


def ingest_runs_for_commit(reader: ReadOnlyGitHub, repo: str, head_sha: str,
                           *, log_fetcher: Callable[[str], str | None]
                           | None = None) -> CIIngestResult:
    """Ingest the workflow runs GitHub reports for ``head_sha``."""
    result = CIIngestResult()
    sha = str(head_sha or "").strip().lower()
    if not sha or not all(c in "0123456789abcdef" for c in sha):
        result.label(DEGRADED_MALFORMED_RESPONSE)
        return result

    result.requests_made += 1
    payload, label = _safe_get(reader, f"/repos/{repo}/actions/runs",
                               {"head_sha": sha, "per_page": 100})
    if label:
        result.label(label)
        return result

    runs = _as_list(payload, "workflow_runs")
    if runs is None:
        result.label(DEGRADED_MALFORMED_RESPONSE)
        return result
    if len(runs) > MAX_RUNS_PER_INGEST:
        result.label(DEGRADED_RUNS_TRUNCATED)
    skipped = 0
    for raw in runs[:MAX_RUNS_PER_INGEST]:
        rec = CIRunRecord.from_github_run(raw, repo)
        if rec is None:
            skipped += 1
        else:
            result.records.append(rec)
    if skipped:
        result.label(DEGRADED_MALFORMED_RUNS)

    _attach_jobs(reader, repo, result, log_fetcher)
    return result


def _attach_jobs(reader: ReadOnlyGitHub, repo: str, result: CIIngestResult,
                 log_fetcher) -> None:
    """Read jobs for non-passing runs only, within the request budget."""
    reads = 0
    excerpts = MAX_LOG_EXCERPTS_PER_RUN
    for index, rec in enumerate(result.records):
        if not (rec.status == "completed" and rec.conclusion
                in FAILING_CONCLUSIONS):
            continue
        if reads >= MAX_JOB_READS:
            result.label(DEGRADED_JOBS_SKIPPED)
            break
        reads += 1
        result.requests_made += 1
        payload, label = _safe_get(
            reader, f"/repos/{repo}/actions/runs/{rec.run_id}/jobs",
            {"per_page": 100, "filter": "latest"})
        if label:
            result.label(label)
            result.label(DEGRADED_JOBS_UNAVAILABLE)
            result.records[index] = rec.with_jobs((), JOBS_UNAVAILABLE)
            if label == DEGRADED_RATE_LIMITED:
                # The quota is gone for this run: stop spending requests.
                break
            continue

        raw_jobs = _as_list(payload, "jobs")
        if raw_jobs is None:
            result.label(DEGRADED_MALFORMED_RESPONSE)
            result.label(DEGRADED_JOBS_UNAVAILABLE)
            result.records[index] = rec.with_jobs((), JOBS_UNAVAILABLE)
            continue
        jobs: list[CIJobRecord] = []
        for raw in raw_jobs[:MAX_JOBS_PER_RUN]:
            log_text = None
            failing = isinstance(raw, dict) and str(
                raw.get("conclusion") or "").lower() in FAILING_CONCLUSIONS
            if log_fetcher is not None and failing and excerpts > 0:
                excerpts -= 1
                try:
                    log_text = log_fetcher(str(raw.get("id")))
                except Exception:  # noqa: BLE001 — a log is a bonus
                    log_text = None
            job = CIJobRecord.from_github_job(raw, log_text=log_text)
            if job is not None:
                jobs.append(job)
        state = (JOBS_TRUNCATED if len(raw_jobs) > MAX_JOBS_PER_RUN
                 else JOBS_FETCHED)
        result.records[index] = rec.with_jobs(jobs, state)


def fetch_pr_commit_shas(reader: ReadOnlyGitHub, repo: str, pr_number: int
                         ) -> tuple[list[str], list[str], int]:
    """``(commit_shas, degraded_labels, requests_made)`` for a PR, oldest
    first.

    Bounded to ``MAX_COMMIT_PAGES`` pages / ``MAX_PR_COMMITS`` commits; the
    list is used only to recognize *earlier* commits of the same PR when
    correlating stored runs.
    """
    shas: list[str] = []
    degraded: list[str] = []
    requests = 0
    for page in range(1, MAX_COMMIT_PAGES + 1):
        requests += 1
        payload, label = _safe_get(
            reader, f"/repos/{repo}/pulls/{int(pr_number)}/commits",
            {"per_page": 100, "page": page})
        if label:
            degraded.append(label)
            break
        if not isinstance(payload, list):
            degraded.append(DEGRADED_MALFORMED_RESPONSE)
            break
        for item in payload:
            sha = str(item.get("sha") if isinstance(item, dict) else "")
            sha = sha.strip().lower()
            if sha and all(c in "0123456789abcdef" for c in sha) \
                    and sha not in shas:
                shas.append(sha)
        if len(payload) < 100:
            break
        if page == MAX_COMMIT_PAGES:
            degraded.append(DEGRADED_COMMITS_TRUNCATED)
    return shas[:MAX_PR_COMMITS], degraded, requests
