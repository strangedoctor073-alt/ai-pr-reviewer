"""Normalized CI run records (V4.6-E01-T03) and their sanitization boundary.

A record is what the engine *keeps* about one GitHub Actions workflow run: a
small, closed-vocabulary, bounded summary. Everything GitHub sends is treated
as untrusted — workflow, job and step names come from workflow YAML that a PR
can rewrite, and log text can contain anything the build printed.

Boundary rules (each pinned by ``tests/test_ci_ingestion.py``):

* **Closed vocabularies.** ``status``, ``conclusion`` and ``event`` are mapped
  onto fixed sets; anything else becomes ``"unknown"``. They never carry
  free text.
* **Free text is sanitized on ingest and again on every load.** Names go
  through :func:`sanitize_ci_text` (secret redaction, fence-tag
  neutralization — including this module's own ``untrusted_ci_run`` fence
  family — control/ANSI/bidi stripping, whitespace collapse, loud
  truncation). The sanitizers are idempotent, so re-applying them when a row
  is read back costs nothing and means a tampered database row cannot smuggle
  unsanitized text into a prompt or a report.
* **No people.** Actor/triggering-user logins, commit authors and commit
  messages are never read into a record: authorship is role-only across the
  family and CI data has no use for it.
* **No URLs from the payload.** A run's link is derived from the repository
  and run id, never copied from GitHub's JSON.
* **Bounded.** Every collection and string has a named cap, sized so that the
  worst-case serialized record stays under ``MAX_CI_RUN_PAYLOAD_CHARS``.

When record text is ever placed in a model prompt it must be fenced with
:func:`wrap_untrusted_ci_runs` — same nonce contract as the diff fence.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace

from ..security import (neutralize_fence_tags, new_nonce, redact_secrets,
                        sanitize_warning)
from ..storage_schema import (REPO_RE, feedback_iso, parse_feedback_iso)

RECORD_SCHEMA = "ci_run.v1"
SOURCE_GITHUB_ACTIONS = "github_actions"

#: Prompt-fence family for CI text. Neutralized inside every stored string so
#: a workflow name cannot close or spoof the fence around it.
CI_FENCE_FAMILY = "untrusted_ci_run"

# ------------------------------------------------------------------ caps
MAX_CI_TEXT_CHARS = 200            # workflow name
MAX_JOB_NAME_CHARS = 100
MAX_STEP_NAME_CHARS = 100
MAX_FAILED_STEPS_PER_JOB = 3
MAX_JOBS_PER_RUN = 20
MAX_PR_NUMBERS_PER_RUN = 10
MAX_LOG_EXCERPT_CHARS = 1_200      # tail of a job log, after redaction
MAX_LOG_EXCERPTS_PER_RUN = 3
#: Input bound for log sanitization (the *tail* is kept: failures print last).
MAX_LOG_INPUT_CHARS = 150_000
#: Headroom so redaction growth can never trigger sanitize_warning's
#: head-truncation on a bounded log input.
_LOG_SANITIZE_CEILING = 200_000
MAX_RUN_ATTEMPT = 1_000

# ------------------------------------------------------------ vocabularies
STATUSES = frozenset({"queued", "in_progress", "completed", "waiting",
                      "requested", "pending"})
CONCLUSIONS = frozenset({"success", "failure", "cancelled", "skipped",
                         "timed_out", "neutral", "action_required", "stale",
                         "startup_failure"})
EVENTS = frozenset({"push", "pull_request", "pull_request_target",
                    "workflow_dispatch", "schedule", "workflow_call",
                    "workflow_run", "merge_group", "release", "issue_comment",
                    "repository_dispatch"})
#: Conclusions that mean "this run/job did not pass" (used for job fetching
#: and for the correlation summary).
FAILING_CONCLUSIONS = frozenset({"failure", "timed_out", "startup_failure",
                                 "cancelled", "action_required"})

UNKNOWN = "unknown"

#: ``jobs_state`` — honest account of why a record does or does not list jobs.
JOBS_NOT_FETCHED = "not_fetched"   # not needed (e.g. a passing run) / budget
JOBS_FETCHED = "fetched"
JOBS_UNAVAILABLE = "unavailable"   # the jobs read failed (labelled upstream)
JOBS_TRUNCATED = "truncated"       # more jobs existed than MAX_JOBS_PER_RUN
JOBS_STATES = frozenset({JOBS_NOT_FETCHED, JOBS_FETCHED, JOBS_UNAVAILABLE,
                         JOBS_TRUNCATED})

_ID_RE = re.compile(r"[0-9]{1,20}")
_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")


# ------------------------------------------------------------- sanitizing
def sanitize_ci_text(value, max_chars: int = MAX_CI_TEXT_CHARS) -> str:
    """Bounded, single-line, redacted, fence-neutral text. Idempotent."""
    if value is None:
        return ""
    # Neutralize before AND after: sanitize_warning turns zero-width
    # characters into spaces, which would otherwise let a tag split by them
    # slip past a neutralizer that only ran afterwards.
    text = neutralize_fence_tags(str(value)[: max_chars * 50],
                                 (CI_FENCE_FAMILY,))
    text = sanitize_warning(text, max_chars=max_chars)
    text = neutralize_fence_tags(text, (CI_FENCE_FAMILY,))
    if len(text) > max_chars:
        text = text[: max_chars - 1] + "…"
    return text


def make_log_excerpt(raw) -> tuple[str, bool]:
    """``(excerpt, truncated)`` for a job log obtained by an injected,
    read-only fetcher.

    The whole bounded input is redacted *before* any slicing so a secret
    straddling the cut can never survive as a fragment, then the **tail** is
    kept (build failures print last) and the excerpt is sanitized as CI text.
    """
    if not raw:
        return "", False
    text = neutralize_fence_tags(str(raw)[-MAX_LOG_INPUT_CHARS:],
                                 (CI_FENCE_FAMILY,))
    clean = sanitize_warning(redact_secrets(text),
                             max_chars=_LOG_SANITIZE_CEILING)
    truncated = len(clean) > MAX_LOG_EXCERPT_CHARS or len(str(raw)) > len(text)
    if len(clean) > MAX_LOG_EXCERPT_CHARS:
        clean = "… " + clean[-(MAX_LOG_EXCERPT_CHARS - 2):]
    clean = neutralize_fence_tags(redact_secrets(clean), (CI_FENCE_FAMILY,))
    return clean[:MAX_LOG_EXCERPT_CHARS], truncated


# --------------------------------------------------------------- coercion
def _clean_id(value) -> str | None:
    text = str(value).strip() if isinstance(value, (int, str)) \
        and not isinstance(value, bool) else ""
    return text if _ID_RE.fullmatch(text) else None


def _clean_sha(value) -> str | None:
    text = str(value or "").strip().lower()
    return text if _SHA_RE.fullmatch(text) else None


def _clean_ts(value) -> str:
    moment = parse_feedback_iso(value)
    return feedback_iso(moment) if moment is not None else ""


def _vocab(value, allowed: frozenset, empty_ok: bool = False) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return "" if empty_ok else UNKNOWN
    return text if text in allowed else UNKNOWN


def _clean_int(value, low: int, high: int, default: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if low <= number <= high else default


def _pr_numbers(value) -> tuple[int, ...]:
    out: list[int] = []
    if isinstance(value, (list, tuple)):
        for item in value:
            raw = item.get("number") if isinstance(item, dict) else item
            if isinstance(raw, bool) or not isinstance(raw, int):
                continue
            if raw > 0 and raw not in out:
                out.append(raw)
            if len(out) >= MAX_PR_NUMBERS_PER_RUN:
                break
    return tuple(sorted(out))


def _cap_excerpts(jobs) -> tuple:
    """Keep log excerpts on at most ``MAX_LOG_EXCERPTS_PER_RUN`` jobs."""
    kept, budget = [], MAX_LOG_EXCERPTS_PER_RUN
    for job in jobs:
        if job.log_excerpt:
            if budget <= 0:
                job = replace(job, log_excerpt="", log_truncated=False)
            else:
                budget -= 1
        kept.append(job)
    return tuple(kept)


# ----------------------------------------------------------------- records
@dataclass(frozen=True)
class CIJobRecord:
    job_id: str
    name: str
    status: str
    conclusion: str
    started_at: str = ""
    completed_at: str = ""
    failed_steps: tuple[str, ...] = ()
    step_count: int = 0
    log_excerpt: str = ""
    log_truncated: bool = False

    def to_dict(self) -> dict:
        return {
            "job_id": self.job_id, "name": self.name, "status": self.status,
            "conclusion": self.conclusion, "started_at": self.started_at,
            "completed_at": self.completed_at,
            "failed_steps": list(self.failed_steps),
            "step_count": self.step_count,
            "log_excerpt": self.log_excerpt,
            "log_truncated": self.log_truncated,
        }

    @classmethod
    def from_dict(cls, raw) -> "CIJobRecord | None":
        """Rebuild from a stored/untrusted dict, re-sanitizing every field.
        Returns None for anything that is not a usable job."""
        if not isinstance(raw, dict):
            return None
        job_id = _clean_id(raw.get("job_id"))
        if job_id is None:
            return None
        steps = raw.get("failed_steps")
        failed = tuple(
            s for s in (sanitize_ci_text(x, MAX_STEP_NAME_CHARS)
                        for x in (steps if isinstance(steps, (list, tuple))
                                  else ())) if s
        )[:MAX_FAILED_STEPS_PER_JOB]
        excerpt = sanitize_ci_text(raw.get("log_excerpt"),
                                   MAX_LOG_EXCERPT_CHARS)
        return cls(
            job_id=job_id,
            name=sanitize_ci_text(raw.get("name"), MAX_JOB_NAME_CHARS),
            status=_vocab(raw.get("status"), STATUSES),
            conclusion=_vocab(raw.get("conclusion"), CONCLUSIONS, True),
            started_at=_clean_ts(raw.get("started_at")),
            completed_at=_clean_ts(raw.get("completed_at")),
            failed_steps=failed,
            step_count=_clean_int(raw.get("step_count"), 0, 10_000, 0),
            log_excerpt=excerpt,
            log_truncated=bool(raw.get("log_truncated")) and bool(excerpt),
        )

    @classmethod
    def from_github_job(cls, raw, *, log_text=None) -> "CIJobRecord | None":
        """Normalize one entry of ``GET .../actions/runs/{id}/jobs``."""
        if not isinstance(raw, dict):
            return None
        steps = raw.get("steps") if isinstance(raw.get("steps"), list) else []
        failed = [
            s.get("name") for s in steps
            if isinstance(s, dict) and str(s.get("conclusion") or "").lower()
            in FAILING_CONCLUSIONS
        ]
        excerpt, truncated = make_log_excerpt(log_text)
        candidate = {
            "job_id": raw.get("id"), "name": raw.get("name"),
            "status": raw.get("status"), "conclusion": raw.get("conclusion"),
            "started_at": raw.get("started_at"),
            "completed_at": raw.get("completed_at"),
            "failed_steps": failed, "step_count": len(steps),
            "log_excerpt": excerpt, "log_truncated": truncated,
        }
        return cls.from_dict(candidate)


@dataclass(frozen=True)
class CIRunRecord:
    repo: str
    run_id: str
    run_attempt: int
    workflow_name: str
    event: str
    status: str
    conclusion: str
    head_sha: str
    pr_numbers: tuple[int, ...] = ()
    created_at: str = ""
    updated_at: str = ""
    jobs: tuple[CIJobRecord, ...] = ()
    jobs_state: str = JOBS_NOT_FETCHED
    source: str = SOURCE_GITHUB_ACTIONS
    schema: str = RECORD_SCHEMA

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.repo, self.run_id, self.run_attempt)

    @property
    def url(self) -> str:
        """Derived, never copied from the payload."""
        return f"https://github.com/{self.repo}/actions/runs/{self.run_id}"

    @property
    def is_failing(self) -> bool:
        return self.conclusion in FAILING_CONCLUSIONS

    def with_jobs(self, jobs, state: str) -> "CIRunRecord":
        return replace(self, jobs=_cap_excerpts(tuple(jobs)[:MAX_JOBS_PER_RUN]),
                       jobs_state=state if state in JOBS_STATES
                       else JOBS_NOT_FETCHED)

    def to_dict(self) -> dict:
        return {
            "schema": self.schema, "source": self.source, "repo": self.repo,
            "run_id": self.run_id, "run_attempt": self.run_attempt,
            "workflow_name": self.workflow_name, "event": self.event,
            "status": self.status, "conclusion": self.conclusion,
            "head_sha": self.head_sha, "pr_numbers": list(self.pr_numbers),
            "created_at": self.created_at, "updated_at": self.updated_at,
            "jobs": [j.to_dict() for j in self.jobs],
            "jobs_state": self.jobs_state,
        }

    def to_payload(self) -> str:
        """Canonical JSON stored in ``ci_runs.payload`` (deterministic)."""
        return json.dumps(self.to_dict(), ensure_ascii=False,
                          sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_dict(cls, raw, repo: str | None = None) -> "CIRunRecord | None":
        """Rebuild from a stored/untrusted dict; None when unusable.

        ``repo`` (when given) must match the record's own repo — a row for
        another repository is rejected, never re-labelled.
        """
        if not isinstance(raw, dict):
            return None
        rec_repo = str(raw.get("repo") or "")
        if not REPO_RE.fullmatch(rec_repo) or (repo is not None
                                               and rec_repo != repo):
            return None
        run_id = _clean_id(raw.get("run_id"))
        head_sha = _clean_sha(raw.get("head_sha"))
        if run_id is None or head_sha is None:
            return None
        raw_jobs = raw.get("jobs")
        jobs = tuple(
            j for j in (CIJobRecord.from_dict(x) for x in
                        (raw_jobs if isinstance(raw_jobs, list) else []))
            if j is not None
        )[:MAX_JOBS_PER_RUN]
        state = str(raw.get("jobs_state") or JOBS_NOT_FETCHED)
        return cls(
            repo=rec_repo, run_id=run_id,
            run_attempt=_clean_int(raw.get("run_attempt"), 1,
                                   MAX_RUN_ATTEMPT, 1),
            workflow_name=sanitize_ci_text(raw.get("workflow_name"),
                                           MAX_CI_TEXT_CHARS),
            event=_vocab(raw.get("event"), EVENTS),
            status=_vocab(raw.get("status"), STATUSES),
            conclusion=_vocab(raw.get("conclusion"), CONCLUSIONS, True),
            head_sha=head_sha,
            pr_numbers=_pr_numbers(raw.get("pr_numbers")),
            created_at=_clean_ts(raw.get("created_at")),
            updated_at=_clean_ts(raw.get("updated_at")),
            jobs=_cap_excerpts(jobs),
            jobs_state=state if state in JOBS_STATES else JOBS_NOT_FETCHED,
        )

    @classmethod
    def from_github_run(cls, raw, repo: str) -> "CIRunRecord | None":
        """Normalize one entry of ``GET .../actions/runs``.

        ``repo`` is the repository the read was made against (never taken
        from the payload). Returns None for a malformed entry; the caller
        counts and labels it.
        """
        if not isinstance(raw, dict):
            return None
        candidate = {
            "repo": repo, "run_id": raw.get("id"),
            "run_attempt": raw.get("run_attempt", 1),
            "workflow_name": raw.get("name"), "event": raw.get("event"),
            "status": raw.get("status"), "conclusion": raw.get("conclusion"),
            "head_sha": raw.get("head_sha"),
            "pr_numbers": raw.get("pull_requests"),
            "created_at": raw.get("created_at"),
            "updated_at": raw.get("updated_at"),
        }
        return cls.from_dict(candidate, repo=repo)


# ------------------------------------------------------------------ fencing
def wrap_untrusted_ci_runs(records, nonce: str | None = None
                           ) -> tuple[str, str]:
    """Fence records for embedding in an LLM prompt; returns (text, nonce).

    Record strings are already neutralized, but the nonce stays the
    authoritative boundary: the block is rebuilt from sanitized fields only
    and any residual look-alike tag is neutralized again before the single
    closing tag carrying our nonce is appended.
    """
    nonce = nonce or new_nonce()
    lines = []
    for rec in records:
        row = rec.to_dict() if isinstance(rec, CIRunRecord) else rec
        lines.append(json.dumps(row, ensure_ascii=False, sort_keys=True))
    body = neutralize_fence_tags("\n".join(lines), (CI_FENCE_FAMILY,))
    return (f'<{CI_FENCE_FAMILY} id="{nonce}">\n{body}\n'
            f'</{CI_FENCE_FAMILY} id="{nonce}">'), nonce
