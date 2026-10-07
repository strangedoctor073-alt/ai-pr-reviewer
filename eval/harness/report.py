"""V3-E03-T05 — machine-readable evaluation results.

``python -m eval.harness --json PATH`` writes a JSON report that a CI
job (or a reviewer) can archive and diff:

* **score** — the full scorecard: metrics (``null`` when a ratio is
  undefined — no data, never a fabricated number), counts next to every
  ratio, and per-case verdicts with their failure/violation diagnostics;
* **case count** — ``run.case_count`` and ``scorecard.counts.cases``;
* **run metadata** — ``corpus_hash`` (identity of the corpus that was
  evaluated, same digest the gate compares) plus git identity:

  - ``git_commit`` — HEAD sha of the evaluated tree, or ``null`` when
    git is unavailable (honest absence over a fabricated identity);
  - ``git_dirty``  — whether the tracked/untracked tree differs from
    HEAD (untracked files count: a new corpus case that was never
    committed *is* a dirty run), or ``null`` without git.

The report contains **no timestamp, duration, hostname or path** — two
runs over the same commit and corpus are byte-identical, so a report
diff between two CI runs always means a real change (§5.3
reproducibility). Reading git metadata is a local, offline operation;
nothing here touches the network or needs API keys.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .score import Scorecard, scorecard_to_dict

REPORT_SCHEMA_VERSION = 1


def git_metadata(repo_root: Path | str) -> dict:
    """HEAD sha + dirty flag for ``repo_root``; ``null``s without git."""

    def _git(*args: str) -> str | None:
        try:
            proc = subprocess.run(
                ["git", *args], cwd=str(repo_root),
                capture_output=True, text=True, timeout=15,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return proc.stdout if proc.returncode == 0 else None

    head = _git("rev-parse", "HEAD")
    sha = head.strip() if head else None
    dirty: bool | None = None
    if sha is not None:
        status = _git("status", "--porcelain")
        if status is not None:
            dirty = bool(status.strip())
    return {"git_commit": sha, "git_dirty": dirty}


def build_report(card: Scorecard, corpus_digest: str,
                 repo_root: Path | str) -> dict:
    """Fixed-shape report projection (stable key set → diffable)."""
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "run": {
            **git_metadata(repo_root),
            "corpus_hash": corpus_digest,
            "case_count": card.counts["cases"],
        },
        "scorecard": scorecard_to_dict(card),
    }


def dumps_report(report: dict) -> str:
    """Canonical serialization: sorted keys, 2-space indent, LF newline
    at EOF — byte-stable for identical inputs."""
    return json.dumps(report, sort_keys=True, indent=2,
                      ensure_ascii=True) + "\n"


__all__ = ["REPORT_SCHEMA_VERSION", "build_report", "dumps_report",
           "git_metadata"]
