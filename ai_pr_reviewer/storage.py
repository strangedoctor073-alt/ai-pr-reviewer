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
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from .findings import fingerprint_finding
from .models import Finding
from .storage_schema import (CAP_DISMISSED_FINGERPRINTS, CAP_LIST_REPO_MEMORY,
                             CAP_PREVIOUS_FINDINGS, CAP_PRUNE, CAP_REPO_MEMORY,
                             CAP_TELEMETRY, CORE_CAPABILITIES,
                             is_mute_pattern, mute_fingerprint, parse_review_id,
                             retention_cutoff)
from .telemetry import sanitize_telemetry

log = logging.getLogger(__name__)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def has_capability(storage: Any, capability: str) -> bool:
    """True when ``storage`` provides ``capability`` (V3-E04-T04).

    Backends declare ``capabilities`` (a frozenset of method names — the
    ``storage_schema.CAP_*`` names), so callers branch on a *declared*
    flag instead of probing with getattr. A duck-typed backend that
    predates the declaration (test fakes, embedders) falls back to
    method-presence probing **here** — the single chokepoint — so no
    call site needs getattr and nothing that worked before stops
    working. ``None`` storage is never capable: a stateless run is
    normal, not a degradation.
    """
    if storage is None:
        return False
    declared = getattr(storage, "capabilities", None)
    if isinstance(declared, (set, frozenset)):
        return capability in declared
    return callable(getattr(storage, capability, None))


@runtime_checkable
class ReviewStorage(Protocol):
    """Storage contract expected by ReviewOrchestrator and build_context.

    V3-E04-T04: the two capabilities that used to live outside the
    contract (``get_dismissed_fingerprints``, ``list_repo_memory``) are
    now declared protocol members, and every backend states what it
    provides in ``capabilities`` (a frozenset of method names — the
    ``storage_schema.CAP_*`` vocabulary). Callers must branch with
    :func:`has_capability` and follow the documented fallback instead
    of probing with getattr. A backend may legitimately omit a
    capability — the HTTP client declares no telemetry or pruning — in
    which case ``has_capability`` is False and the caller degrades with
    a logged warning rather than silently varying.
    """

    # Declared method-name set (V3-E04-T04). Absence is explicit, never
    # inferred at the call site.
    capabilities: frozenset[str]

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
        """Fetch past review memory notes matching ``paths``.

        Mute decisions (``fingerprint:<fp>`` rows) are deliberately not
        notes: they are read via ``get_dismissed_fingerprints`` instead.
        """
        ...

    def get_dismissed_fingerprints(self, repo: str) -> set[str]:
        """Fingerprints muted for ``repo``; callers must use
        ``has_capability(CAP_DISMISSED_FINGERPRINTS)`` first and skip
        the mute step with a logged warning when the backend lacks it."""
        ...

    def list_repo_memory(self, repo: str) -> list[dict]:
        """Every memory row for ``repo`` with metadata; callers fall back
        to ``get_repo_memory`` (plain notes) with a logged warning when
        the backend lacks this richer view."""
        ...


class DashboardStorageClient:
    """Remote HTTP client connecting to the AI PR Reviewer Dashboard.

    Declared capabilities (V3-E04-T04): the core protocol plus the two
    formerly-undeclared capabilities. Telemetry and pruning are
    *explicitly absent* — this client has no engine→dashboard telemetry
    route, and the engine must never delete dashboard data remotely, so
    callers see a declared absence (warning-logged) instead of a
    silently-varying getattr miss.
    """

    capabilities: frozenset[str] = CORE_CAPABILITIES | {
        CAP_LIST_REPO_MEMORY,
        CAP_DISMISSED_FINGERPRINTS,
    }

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
        # repo/pr come from the review id (owner/repo#number@sha) — parsed
        # by the single shared reader (V3-E04-T03), not re-derived here.
        repo, pr_number = parse_review_id(review_id)

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
                # "fingerprint:<fp>" rows are mute decisions, not review
                # memory — they are read by get_dismissed_fingerprints.
                if is_mute_pattern(pattern):
                    continue
                if any(fnmatch.fnmatch(p, pattern) for p in paths):
                    notes.append(note)
            return notes
        except Exception as exc:
            log.warning("DashboardStorageClient: get_repo_memory failed: %s", exc)
            return []

    def list_repo_memory(self, repo: str) -> list[dict]:
        """Every memory row for ``repo`` *with* its metadata (V3 C7).

        Unlike ``get_repo_memory`` this returns rows verbatim — mute rows,
        disabled rows and categories included — so ``ai_pr_reviewer.memory``
        can decide what is project advice and what is a dismissal. Rows are
        returned without path filtering: the caller knows which paths matter.
        """
        url = f"/api/repos/{repo}/memory"
        try:
            client = self._get_client()
            r = client.get(url)
            if r.status_code == 404:
                return []
            r.raise_for_status()
            rows = r.json().get("memory", [])
            return [row for row in rows if isinstance(row, dict)]
        except Exception as exc:
            log.warning("DashboardStorageClient: list_repo_memory failed: %s", exc)
            return []

    def get_dismissed_fingerprints(self, repo: str) -> set[str]:
        """Fingerprints the dashboard user muted for ``repo``.

        Feedback with kind="mute" is stored as a memory row whose
        ``path_pattern`` is ``fingerprint:<fp>``; this reads them back so
        the orchestrator can park matching findings instead of
        re-reporting them. Declared capability (V3-E04-T04): callers
        branch with ``has_capability(CAP_DISMISSED_FINGERPRINTS)``, and
        failures degrade to "nothing muted" like every other read here.
        """
        url = f"/api/repos/{repo}/memory"
        try:
            client = self._get_client()
            r = client.get(url)
            if r.status_code == 404:
                return set()
            r.raise_for_status()
            out: set[str] = set()
            for item in r.json().get("memory", []):
                fp = mute_fingerprint(item.get("path_pattern"))
                if fp:
                    out.add(fp)
            return out
        except Exception as exc:
            log.warning("DashboardStorageClient: get_dismissed_fingerprints failed: %s", exc)
            return set()


class LocalReviewStorage:
    """SQLite-backed local storage requiring no third-party libraries.

    Read-only with respect to ``repo_memory``: this engine never writes
    memory (it would turn PR-derived text into future prompt input), so
    notes here are seeded by tooling/tests directly.
    """

    capabilities: frozenset[str] = CORE_CAPABILITIES | {
        CAP_LIST_REPO_MEMORY,
        CAP_DISMISSED_FINGERPRINTS,
        CAP_TELEMETRY,
        CAP_PRUNE,
    }

    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @contextmanager
    def _connection(self):
        """One connection per call: commit (or roll back) **and** close.

        V3-E04-T01: ``with sqlite3.Connection`` only commits — it never
        closes, so every call used to leak a handle (and on Windows keep
        the database file locked until GC). This is the single
        open/commit/close chokepoint: the transaction semantics of
        ``with conn`` are unchanged, the handle is always released, and
        WAL/locking behavior stays exactly as it was (no pooling).
        """
        conn = self._connect()
        try:
            with conn:            # commits on success, rolls back on error
                yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connection() as conn:
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
                created_at TEXT,
                category TEXT,
                enabled INTEGER DEFAULT 1,
                updated_at TEXT
            );
            -- V3-E02-T04: additive telemetry table. CREATE IF NOT EXISTS
            -- means a database from an earlier build gains it on open
            -- without touching a single existing row. Token columns are
            -- NULL (not 0) when usage was unavailable — absence is a
            -- typed state end to end.
            CREATE TABLE IF NOT EXISTS telemetry (
                review_id TEXT PRIMARY KEY,
                repo TEXT NOT NULL,
                pr_number INTEGER NOT NULL,
                provider TEXT,
                model TEXT,
                input_tokens INTEGER,
                output_tokens INTEGER,
                usage_state TEXT,
                batch_count INTEGER,
                fallback_used INTEGER,
                updated_at TEXT,
                payload TEXT
            );
            """)
            # V3 C7: memory rows gained category/enabled/updated_at. A table
            # created by an older build lacks them, and SQLite has no
            # "ADD COLUMN IF NOT EXISTS", so each statement is allowed to
            # fail silently while a fresh database gets them twice (once
            # from CREATE TABLE, once as a no-op).
            for ddl in (
                "ALTER TABLE repo_memory ADD COLUMN category TEXT",
                "ALTER TABLE repo_memory ADD COLUMN enabled INTEGER DEFAULT 1",
                "ALTER TABLE repo_memory ADD COLUMN updated_at TEXT",
            ):
                try:
                    conn.execute(ddl)
                except sqlite3.OperationalError:
                    pass

    def get_last_reviewed_sha(self, repo: str, pr_number: int) -> str | None:
        with self._connection() as conn:
            row = conn.execute(
                "SELECT last_reviewed_sha FROM review_state WHERE repo = ? AND pr_number = ?",
                (repo, pr_number),
            ).fetchone()
            return row["last_reviewed_sha"] if row else None

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        now = _now_iso()
        with self._connection() as conn:
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
        with self._connection() as conn:
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
        repo, pr_number = parse_review_id(review_id)

        now = _now_iso()
        with self._connection() as conn:
            for item in findings:
                f_obj = item if isinstance(item, Finding) else Finding.from_dict(item)
                fp = f_obj.fingerprint or fingerprint_finding(f_obj)
                # Copy the dict before writing the fingerprint back: a
                # storage write must not mutate the caller's data (the
                # dashboard backends copy too — V3-E04-T07 parity).
                item_dict = dict(item) if isinstance(item, dict) else f_obj.to_dict()
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

    # ----------------------------------------------------- V3-E02-T04 telemetry
    @staticmethod
    def _split_review_id(review_id: str) -> tuple[str, int]:
        """``repo#pr@sha`` -> ``(repo, pr)`` — the shared reader (V3-E04-T03)."""
        return parse_review_id(review_id)

    def save_telemetry(self, review_id: str, telemetry: dict) -> None:
        """Store one run's allowlisted telemetry row.

        Additive: a new table only (see ``_init_db``), so databases from
        earlier builds gain it on open and existing rows are never
        touched. Upserts by review id — re-posting a review replaces its
        row rather than stacking duplicates. Token columns stay NULL
        unless usage state is ``ok``: an unavailable count must not read
        back as a measured 0.

        V3-E02-T06: the payload is re-sanitized *at this boundary* — the
        allowlist + redaction chokepoint applies even when a caller
        hands in a raw dict, so arbitrary content can never reach the
        database. Non-dict input is not persisted at all.
        """
        data = sanitize_telemetry(telemetry)
        if data is None:
            return
        repo, pr_number = self._split_review_id(review_id)
        usage = data.get("usage") or {}
        reported = usage.get("state") == "ok"
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO telemetry(
                    review_id, repo, pr_number, provider, model,
                    input_tokens, output_tokens, usage_state, batch_count,
                    fallback_used, updated_at, payload
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(review_id) DO UPDATE SET
                    provider = excluded.provider,
                    model = excluded.model,
                    input_tokens = excluded.input_tokens,
                    output_tokens = excluded.output_tokens,
                    usage_state = excluded.usage_state,
                    batch_count = excluded.batch_count,
                    fallback_used = excluded.fallback_used,
                    updated_at = excluded.updated_at,
                    payload = excluded.payload
                """,
                (
                    review_id,
                    repo,
                    pr_number,
                    data.get("provider", ""),
                    data.get("model", ""),
                    usage.get("input_tokens") if reported else None,
                    usage.get("output_tokens") if reported else None,
                    usage.get("state", "n/a"),
                    data.get("batch_count", 0),
                    1 if data.get("fallback_used") else 0,
                    _now_iso(),
                    json.dumps(data),
                ),
            )

    def get_telemetry(self, review_id: str) -> dict | None:
        """The stored row for ``review_id``, or None (missing rows must
        never break reads)."""
        with self._connection() as conn:
            row = conn.execute(
                "SELECT payload FROM telemetry WHERE review_id = ?",
                (review_id,),
            ).fetchone()
            if not row or not row["payload"]:
                return None
            try:
                return json.loads(row["payload"])
            except Exception:
                return None

    def get_repo_memory(self, repo: str, paths: list[str]) -> list[str]:
        with self._connection() as conn:
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

    def list_repo_memory(self, repo: str) -> list[dict]:
        """Every memory row for ``repo`` *with* its metadata (V3 C7).

        Returned verbatim (mute rows, disabled rows and categories included)
        so ``ai_pr_reviewer.memory`` can decide what is project advice and
        what is a dismissal decision. Read-only: this engine never writes
        memory — see the class docstring and D10.
        """
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT path_pattern, note, category, enabled FROM repo_memory "
                "WHERE repo = ? ORDER BY id",
                (repo,),
            ).fetchall()
            out: list[dict] = []
            for row in rows:
                out.append({
                    "path_pattern": row["path_pattern"],
                    "note": row["note"],
                    "category": row["category"],
                    "enabled": row["enabled"],
                })
            return out

    def get_dismissed_fingerprints(self, repo: str) -> set[str]:
        """Fingerprints muted for ``repo`` (V3-E04-T04).

        Mute rows live in ``repo_memory`` as ``fingerprint:<fp>`` path
        patterns — the engine never writes them (D10), but tooling and
        tests seed them exactly like notes. Declared here so the local
        backend honors seeded mutes exactly like the dashboard does,
        instead of the orchestrator silently skipping the step.
        """
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT path_pattern FROM repo_memory WHERE repo = ?",
                (repo,),
            ).fetchall()
            out: set[str] = set()
            for row in rows:
                fp = mute_fingerprint(row["path_pattern"])
                if fp:
                    out.add(fp)
            return out

    def prune(self, retention_days: int, *, dry_run: bool = False,
              now: datetime | None = None) -> dict:
        """Delete aged finding-history and telemetry rows (V3-E04-T02).

        Policy (cutoff shared with the dashboard backends through
        ``storage_schema.retention_cutoff``):

        * ``retention_days <= 0`` — retention disabled (the default):
          a no-op, keep everything.
        * A ``finding_history`` row is pruned only when it is older than
          the cutoff **and** its PR's ``review_state`` row exists and is
          itself older than the cutoff — a PR reviewed inside the window
          ("active" state) keeps its history so ``apply_lifecycle`` can
          never resurrect a pruned finding as new (the DATA_MODEL §6
          hazard). Missing or unknown-age state protects its history.
        * ``telemetry`` rows age out on their own ``updated_at`` (raw
          measurement data, DATA_MODEL §6: disposable once past the
          window).
        * Never pruned: ``repo_memory`` (human-authored knowledge),
          ``review_state`` rows (the incremental-diff anchor), reports,
          and the audit trail (``audit.jsonl`` is not a storage row).
        * Rows with a NULL ``updated_at`` are never pruned — unknown age
          is always treated as "keep".

        Idempotent and resumable by construction: rows only ever
        disappear, so a rerun after an interruption finishes the job and
        a second run counts 0. ``dry_run=True`` reports the same counts
        without deleting — observe that metric before enabling retention
        (DATA_MODEL §6 requires exactly this gate).

        Returns ``{"enabled", "cutoff", "dry_run", "finding_history",
        "telemetry"}``.
        """
        cutoff = retention_cutoff(retention_days, now=now)
        outcome: dict = {"enabled": cutoff is not None, "cutoff": cutoff,
                         "dry_run": bool(dry_run), "finding_history": 0,
                         "telemetry": 0}
        if cutoff is None:
            return outcome
        # Prune history only when we positively know the PR's review state
        # exists and is stale: EXISTS(old state) is false for a missing,
        # fresh or NULL/empty-timestamped state row, so those all keep
        # their rows (storage_schema.is_stale is the Python twin).
        history_where = (
            "updated_at IS NOT NULL AND updated_at <> '' "
            "AND updated_at < ? AND EXISTS ("
            "SELECT 1 FROM review_state rs "
            "WHERE rs.repo = finding_history.repo "
            "AND rs.pr_number = finding_history.pr_number "
            "AND rs.updated_at IS NOT NULL AND rs.updated_at <> '' "
            "AND rs.updated_at < ?)")
        telemetry_where = (
            "updated_at IS NOT NULL AND updated_at <> '' AND updated_at < ?")
        with self._connection() as conn:
            if dry_run:
                outcome["finding_history"] = conn.execute(
                    "SELECT COUNT(*) FROM finding_history WHERE " + history_where,
                    (cutoff, cutoff)).fetchone()[0]
                outcome["telemetry"] = conn.execute(
                    "SELECT COUNT(*) FROM telemetry WHERE " + telemetry_where,
                    (cutoff,)).fetchone()[0]
            else:
                outcome["finding_history"] = conn.execute(
                    "DELETE FROM finding_history WHERE " + history_where,
                    (cutoff, cutoff)).rowcount
                outcome["telemetry"] = conn.execute(
                    "DELETE FROM telemetry WHERE " + telemetry_where,
                    (cutoff,)).rowcount
        return outcome


def resolve_storage(cfg: Any) -> ReviewStorage | None:
    """Resolve the storage implementation based on configuration.

    When retention is configured (``retention_days > 0``) and the
    resolved backend declares the prune capability, exactly one
    retention pass runs here — best-effort, logged, never fatal
    (V3-E04-T02). The dashboard process prunes its own backends at
    startup instead, and the HTTP client declares no prune capability,
    so the engine never deletes dashboard data remotely.
    """
    storage: ReviewStorage | None = None
    if getattr(cfg, "dashboard_url", None) and getattr(cfg, "dashboard_token", None):
        storage = DashboardStorageClient(cfg.dashboard_url, cfg.dashboard_token)
    else:
        storage_file = getattr(cfg, "storage_file", None)
        if not storage_file:
            import os
            storage_file = os.environ.get("REVIEW_STORAGE_FILE")
        if storage_file:
            storage = LocalReviewStorage(storage_file)

    if storage is None:
        return None

    retention_days = getattr(cfg, "retention_days", 0) or 0
    if retention_days > 0 and has_capability(storage, CAP_PRUNE):
        try:
            outcome = storage.prune(retention_days)
            if outcome.get("finding_history") or outcome.get("telemetry"):
                log.warning("retention: pruned %d finding-history row(s) and "
                            "%d telemetry row(s) (retention_days=%d)",
                            outcome["finding_history"],
                            outcome["telemetry"], retention_days)
        except Exception as exc:  # noqa: BLE001 — retention must not fail a review
            log.warning("retention prune failed (%s); continuing without pruning",
                        exc)
    return storage
