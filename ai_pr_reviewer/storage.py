"""Review storage subsystem and client implementations.

Provides:
- ``ReviewStorage``: Protocol defining the interface expected by ``ReviewOrchestrator``
  and ``ReviewContext``.
- ``DashboardStorageClient``: Remote HTTP client communicating review state, findings,
  and repository memory to the Dashboard REST API.
- ``LocalReviewStorage``: Zero-dependency SQLite-backed storage for local execution
  and CI step caching.
- ``resolve_storage(cfg)``: Factory to resolve the active storage strategy.
"""
from __future__ import annotations

import fnmatch
import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .findings import fingerprint_finding
from .models import Finding

log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@runtime_checkable
class ReviewStorage(Protocol):
    """Storage contract expected by ReviewOrchestrator and build_context."""

    def get_last_reviewed_sha(self, repo: str, pr_number: int) -> str | None:
        """Return the head commit SHA from the most recent completed review, or None."""
        ...

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        """Advance the last reviewed commit SHA for this pull request."""
        ...

    def get_previous_findings(self, repo: str, pr_number: int) -> list[Finding]:
        """Load findings recorded for this pull request by earlier review runs."""
        ...

    def save_findings(self, review_id: str, findings: list[dict | Finding]) -> None:
        """Persist findings and their lifecycle states for this review run."""
        ...

    def get_repo_memory(self, repo: str, paths: list[str]) -> list[str]:
        """Fetch past review memory notes or dismissed pattern feedback for paths."""
        ...


class DashboardStorageClient:
    """Remote HTTP client connecting to the AI PR Reviewer Dashboard."""

    def __init__(self, base_url: str, token: str, timeout: float = 15.0,
                 client: Any = None):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._client = client

    def _get_client(self):
        if self._client is not None:
            return self._client
        import httpx

        return httpx.Client(
            base_url=self.base_url,
            headers={"X-Dashboard-Token": self.token},
            timeout=self.timeout,
        )

    def get_last_reviewed_sha(self, repo: str, pr_number: int) -> str | None:
        url = f"/api/reviews/{repo}/{pr_number}/state"
        try:
            client = self._get_client()
            r = client.get(url)
            if r.status_code == 404:
                return None
            r.raise_for_status()
            data = r.json()
            return data.get("last_reviewed_sha")
        except Exception as exc:
            log.warning("DashboardStorageClient: get_last_reviewed_sha failed: %s", exc)
            return None

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        url = f"/api/reviews/{repo}/{pr_number}/state"
        payload = {"last_reviewed_sha": sha, "base_sha": base_sha}
        try:
            client = self._get_client()
            r = client.put(url, json=payload)
            r.raise_for_status()
        except Exception as exc:
            log.warning("DashboardStorageClient: set_last_reviewed_sha failed: %s", exc)

    def get_previous_findings(self, repo: str, pr_number: int) -> list[Finding]:
        url = f"/api/reviews/{repo}/{pr_number}/findings"
        try:
            client = self._get_client()
            r = client.get(url)
            if r.status_code == 404:
                return []
            r.raise_for_status()
            data = r.json()
            raw_list = data.get("findings", [])
            out: list[Finding] = []
            for item in raw_list:
                if isinstance(item, Finding):
                    out.append(item)
                elif isinstance(item, dict):
                    out.append(Finding.from_dict(item))
            return out
        except Exception as exc:
            log.warning("DashboardStorageClient: get_previous_findings failed: %s", exc)
            return []

    def save_findings(self, review_id: str, findings: list[dict | Finding]) -> None:
        # Extract repo and pr_number from review_id (format: owner/repo#number@sha)
        repo = ""
        pr_number = 0
        if "#" in review_id and "@" in review_id:
            try:
                repo_part, rest = review_id.split("#", 1)
                pr_str = rest.split("@", 1)[0]
                repo = repo_part
                pr_number = int(pr_str)
            except Exception:
                pass

        url = f"/api/reviews/{repo}/{pr_number}/findings" if (repo and pr_number) else "/api/reviews/findings"
        serialized = [
            f.to_dict() if isinstance(f, Finding) else dict(f)
            for f in findings
        ]
        payload = {
            "review_id": review_id,
            "repo": repo,
            "pr_number": pr_number,
            "findings": serialized,
        }
        try:
            client = self._get_client()
            r = client.post(url, json=payload)
            r.raise_for_status()
        except Exception as exc:
            log.warning("DashboardStorageClient: save_findings failed: %s", exc)

    def get_repo_memory(self, repo: str, paths: list[str]) -> list[str]:
        url = f"/api/repos/{repo}/memory"
        try:
            client = self._get_client()
            r = client.get(url)
            if r.status_code == 404:
                return []
            r.raise_for_status()
            items = r.json().get("memory", [])
            notes = []
            for item in items:
                pattern = item.get("path_pattern", "*")
                note = item.get("note", "")
                if any(fnmatch.fnmatch(p, pattern) for p in paths):
                    notes.append(note)
            return notes
        except Exception as exc:
            log.warning("DashboardStorageClient: get_repo_memory failed: %s", exc)
            return []


class LocalReviewStorage:
    """SQLite-backed local storage requiring no third-party libraries."""

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
            CREATE TABLE IF NOT EXISTS review_state (
                repo TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                last_reviewed_sha TEXT,
                base_sha TEXT,
                updated_at TEXT,
                PRIMARY KEY (repo, pr_number)
            );
            CREATE TABLE IF NOT EXISTS finding_history (
                repo TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                fingerprint TEXT NOT NULL,
                state TEXT,
                first_seen_sha TEXT,
                last_seen_sha TEXT,
                resolved_at TEXT,
                payload TEXT,
                updated_at TEXT,
                PRIMARY KEY (repo, pr_number, fingerprint)
            );
            CREATE TABLE IF NOT EXISTS repo_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                repo TEXT NOT NULL,
                path_pattern TEXT NOT NULL,
                note TEXT NOT NULL,
                created_at TEXT
            );
            """)

    def get_last_reviewed_sha(self, repo: str, pr_number: int) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT last_reviewed_sha FROM review_state WHERE repo = ? AND pr_number = ?",
                (repo, pr_number),
            ).fetchone()
            return row["last_reviewed_sha"] if row else None

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        now = _now_iso()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO review_state(repo, pr_number, last_reviewed_sha, base_sha, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(repo, pr_number) DO UPDATE SET
                    last_reviewed_sha = excluded.last_reviewed_sha,
                    base_sha = excluded.base_sha,
                    updated_at = excluded.updated_at
                """,
                (repo, pr_number, sha, base_sha, now),
            )

    def get_previous_findings(self, repo: str, pr_number: int) -> list[Finding]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM finding_history WHERE repo = ? AND pr_number = ?",
                (repo, pr_number),
            ).fetchall()
            findings: list[Finding] = []
            for row in rows:
                try:
                    data = json.loads(row["payload"])
                    findings.append(Finding.from_dict(data))
                except Exception:
                    continue
            return findings

    def save_findings(self, review_id: str, findings: list[dict | Finding]) -> None:
        repo = ""
        pr_number = 0
        if "#" in review_id and "@" in review_id:
            try:
                repo_part, rest = review_id.split("#", 1)
                pr_str = rest.split("@", 1)[0]
                repo = repo_part
                pr_number = int(pr_str)
            except Exception:
                pass

        now = _now_iso()
        with self._connect() as conn:
            for item in findings:
                f_obj = item if isinstance(item, Finding) else Finding.from_dict(item)
                fp = f_obj.fingerprint or fingerprint_finding(f_obj)
                item_dict = item if isinstance(item, dict) else f_obj.to_dict()
                item_dict["fingerprint"] = fp
                item_repo = repo or item_dict.get("repo", "")
                item_pr = pr_number or int(item_dict.get("pr_number", 0))

                conn.execute(
                    """
                    INSERT INTO finding_history(
                        repo, pr_number, fingerprint, state,
                        first_seen_sha, last_seen_sha, resolved_at, payload, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(repo, pr_number, fingerprint) DO UPDATE SET
                        state = excluded.state,
                        last_seen_sha = excluded.last_seen_sha,
                        resolved_at = excluded.resolved_at,
                        payload = excluded.payload,
                        updated_at = excluded.updated_at
                    """,
                    (
                        item_repo,
                        item_pr,
                        fp,
                        getattr(f_obj, "state", "new"),
                        getattr(f_obj, "first_seen_sha", None),
                        getattr(f_obj, "last_seen_sha", None),
                        getattr(f_obj, "resolved_at", None),
                        json.dumps(item_dict),
                        now,
                    ),
                )

    def get_repo_memory(self, repo: str, paths: list[str]) -> list[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT path_pattern, note FROM repo_memory WHERE repo = ?",
                (repo,),
            ).fetchall()
            notes: list[str] = []
            for row in rows:
                pattern = row["path_pattern"]
                note = row["note"]
                if any(fnmatch.fnmatch(p, pattern) for p in paths):
                    notes.append(note)
            return notes

    def add_repo_memory(self, repo: str, path_pattern: str, note: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO repo_memory(repo, path_pattern, note, created_at) VALUES (?, ?, ?, ?)",
                (repo, path_pattern, note, _now_iso()),
            )


def resolve_storage(cfg: Any) -> ReviewStorage | None:
    """Resolve the storage implementation based on configuration."""
    if getattr(cfg, "dashboard_url", None) and getattr(cfg, "dashboard_token", None):
        return DashboardStorageClient(cfg.dashboard_url, cfg.dashboard_token)

    storage_file = getattr(cfg, "storage_file", None)
    if storage_file:
        return LocalReviewStorage(storage_file)

    import os
    env_file = os.environ.get("REVIEW_STORAGE_FILE")
    if env_file:
        return LocalReviewStorage(env_file)

    return None
