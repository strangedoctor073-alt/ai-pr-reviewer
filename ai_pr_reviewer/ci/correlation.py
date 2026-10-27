"""Run <-> commit/PR correlation (V4.6-E01-T04).

Answers one narrow question honestly: *which ingested CI runs are associated
with this pull request, and on what evidence?*

Honesty rules (pinned by ``tests/test_ci_ingestion.py``):

* **Association, never causation.** The output says a run is *associated*
  with the PR's current head or with an earlier commit of it. It never says a
  run failed *because of* a change; that judgement belongs to later epics and
  needs evidence this module does not have.
* **Only hard evidence links a run.** The basis is one of
  ``BASIS_PR_LISTED`` (GitHub's own ``pull_requests`` list on the run),
  ``BASIS_HEAD_SHA`` (the run is for the PR's current head commit) or
  ``BASIS_EARLIER_COMMIT`` (the run is for another commit of the same PR).
  Branch names, workflow names, titles and timestamp proximity are never
  evidence, so a lookalike run for an unrelated commit is not linked.
* **Fork PRs are not over-claimed.** GitHub leaves ``pull_requests`` empty for
  runs triggered from forks; such a run can only be linked by commit SHA and
  is reported with that (weaker) basis — it is never promoted to "listed".
* **Unlinked runs are counted, not described.** ``unrelated`` is a number; the
  runs themselves are not returned as if they mattered to the PR.
* **Stale is stated.** A run for an earlier commit is flagged
  ``is_current_head = False`` so a green run for an old commit can never read
  as "CI passed" for the head under review.
"""
from __future__ import annotations

from dataclasses import dataclass

from .records import (FAILING_CONCLUSIONS, CIRunRecord)

BASIS_PR_LISTED = "pr_listed"
BASIS_HEAD_SHA = "head_sha"
BASIS_EARLIER_COMMIT = "earlier_commit"
BASES = (BASIS_PR_LISTED, BASIS_HEAD_SHA, BASIS_EARLIER_COMMIT)

#: The fixed sentence attached to every pipeline summary.
PIPELINE_NOTE = ("CI runs are associated with this pull request by commit or "
                 "by GitHub's own pull-request list; association is not "
                 "causation.")


@dataclass(frozen=True)
class RunCorrelation:
    run_id: str
    run_attempt: int
    workflow_name: str
    status: str
    conclusion: str
    head_sha: str
    bases: tuple[str, ...]
    is_current_head: bool
    is_latest_attempt: bool

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id, "run_attempt": self.run_attempt,
            "workflow_name": self.workflow_name, "status": self.status,
            "conclusion": self.conclusion, "head_sha": self.head_sha,
            "bases": list(self.bases),
            "is_current_head": self.is_current_head,
            "is_latest_attempt": self.is_latest_attempt,
        }


@dataclass(frozen=True)
class CorrelationResult:
    correlations: tuple[RunCorrelation, ...]
    unrelated: int


def _unique(records) -> list[CIRunRecord]:
    """One record per (repo, run_id, attempt); the later one in the input wins
    (callers pass stored history first, fresh ingestion last)."""
    by_key: dict = {}
    for rec in records:
        if isinstance(rec, CIRunRecord):
            by_key[rec.key] = rec
    return list(by_key.values())


def correlate_runs(records, *, repo: str, pr_number: int, head_sha: str,
                   pr_commit_shas=()) -> CorrelationResult:
    """Link ``records`` to the PR by hard evidence only (see module docs)."""
    head = str(head_sha or "").strip().lower()
    commits = {str(s).strip().lower() for s in pr_commit_shas or ()}
    commits.discard("")
    unique = [r for r in _unique(records) if r.repo == repo]

    latest_attempt: dict[tuple[str, str], int] = {}
    for rec in unique:
        k = (rec.repo, rec.run_id)
        latest_attempt[k] = max(latest_attempt.get(k, 0), rec.run_attempt)

    linked: list[RunCorrelation] = []
    unrelated = 0
    for rec in unique:
        bases: list[str] = []
        if pr_number and pr_number in rec.pr_numbers:
            bases.append(BASIS_PR_LISTED)
        if head and rec.head_sha == head:
            bases.append(BASIS_HEAD_SHA)
        elif rec.head_sha in commits:
            bases.append(BASIS_EARLIER_COMMIT)
        if not bases:
            unrelated += 1
            continue
        linked.append(RunCorrelation(
            run_id=rec.run_id, run_attempt=rec.run_attempt,
            workflow_name=rec.workflow_name, status=rec.status,
            conclusion=rec.conclusion, head_sha=rec.head_sha,
            bases=tuple(bases),
            is_current_head=bool(head) and rec.head_sha == head,
            is_latest_attempt=rec.run_attempt
            == latest_attempt[(rec.repo, rec.run_id)],
        ))
    linked.sort(key=lambda c: (not c.is_current_head, c.run_id,
                               c.run_attempt))
    return CorrelationResult(tuple(linked), unrelated)


def summarize_pipeline(result: CorrelationResult, degraded=()) -> dict:
    """Plain-data ``pipeline`` summary (ints and fixed strings only).

    Counts use each run's *latest attempt* so a retried run is not double
    counted. Current-head runs and stale runs are reported separately.
    """
    current = {"success": 0, "failing": 0, "other": 0, "in_progress": 0}
    stale = 0
    for corr in result.correlations:
        if not corr.is_latest_attempt:
            continue
        if not corr.is_current_head:
            stale += 1
        elif corr.status != "completed":
            current["in_progress"] += 1
        elif corr.conclusion == "success":
            current["success"] += 1
        elif corr.conclusion in FAILING_CONCLUSIONS:
            current["failing"] += 1
        else:
            current["other"] += 1
    return {
        "runs_associated": len(result.correlations),
        "current_head": current,
        "stale_runs": stale,
        "unrelated_runs_ignored": result.unrelated,
        "degraded": sorted({str(label) for label in degraded}),
        "claims": "association_only",
        "note": PIPELINE_NOTE,
    }
