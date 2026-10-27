"""One call that ingests, stores and correlates CI data for a PR
(V4.6-E01, T02–T04 wired together).

This is the single entry point a future orchestrator hook calls; nothing in
the engine calls it yet (wiring is a merge-pass decision — see the patch
notes). Absent CI data, absent permission or an exhausted quota all produce a
labelled, partial outcome — never an exception and never a changed review.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..storage import has_capability
from ..storage_schema import CAP_CI_RUNS
from .correlation import (CorrelationResult, correlate_runs,
                          summarize_pipeline)
from .github_actions import (CIIngestResult, fetch_pr_commit_shas,
                             ingest_runs_for_commit)
from .readonly import ReadOnlyGitHub
from .records import CIRunRecord

#: Labels added by this module (the adapter's own live in ``github_actions``).
DEGRADED_STORAGE_UNAVAILABLE = "storage_unavailable"
DEGRADED_STORE_FAILED = "storage_write_failed"
DEGRADED_HISTORY_UNAVAILABLE = "history_unavailable"


@dataclass
class CIPipelineOutcome:
    records: list[CIRunRecord] = field(default_factory=list)
    correlation: CorrelationResult = field(
        default_factory=lambda: CorrelationResult((), 0))
    pipeline: dict = field(default_factory=dict)
    degraded: list[str] = field(default_factory=list)
    requests_made: int = 0


def collect_ci_pipeline(client, *, repo: str, pr_number: int, head_sha: str,
                        storage=None, use_history: bool = True,
                        log_fetcher=None, now=None) -> CIPipelineOutcome:
    """Ingest runs for ``head_sha``, persist them, correlate with the PR.

    ``client`` is a ``GitHubClient`` (or anything with ``get_json``); it is
    wrapped in :class:`ReadOnlyGitHub` here so the ingestion code can only
    read. ``storage`` is optional: with a CI-capable backend the runs are
    saved and — when ``use_history`` — runs stored by *earlier* reviews of
    the same PR are correlated as stale. Without storage the outcome covers
    the current head only, labelled ``storage_unavailable``.
    """
    reader = ReadOnlyGitHub(client)
    ingest: CIIngestResult = ingest_runs_for_commit(
        reader, repo, head_sha, log_fetcher=log_fetcher)
    degraded = list(ingest.degraded)
    requests_made = ingest.requests_made
    records = list(ingest.records)

    history: list[dict] = []
    pr_commits: list[str] = []
    capable = has_capability(storage, CAP_CI_RUNS)
    if not capable:
        degraded.append(DEGRADED_STORAGE_UNAVAILABLE)
    else:
        if records:
            try:
                storage.save_ci_runs(repo, records, now=now)
            except Exception:  # noqa: BLE001 — storage is best-effort
                degraded.append(DEGRADED_STORE_FAILED)
        if use_history:
            pr_commits, commit_labels, commit_requests = \
                fetch_pr_commit_shas(reader, repo, pr_number)
            requests_made += commit_requests
            degraded.extend(commit_labels)
            if pr_commits:
                try:
                    history = storage.get_ci_runs(repo, head_shas=pr_commits)
                except Exception:  # noqa: BLE001
                    degraded.append(DEGRADED_HISTORY_UNAVAILABLE)

    # Stored history first, fresh ingestion last: the fresh record wins.
    merged = [r for r in (CIRunRecord.from_dict(h, repo=repo)
                          for h in history) if r is not None] + records
    result = correlate_runs(merged, repo=repo, pr_number=pr_number,
                            head_sha=head_sha, pr_commit_shas=pr_commits)
    unique_labels = list(dict.fromkeys(degraded))
    return CIPipelineOutcome(
        records=records, correlation=result,
        pipeline=summarize_pipeline(result, unique_labels),
        degraded=unique_labels, requests_made=requests_made)
