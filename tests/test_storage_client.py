"""Tests for ai_pr_reviewer.storage: DashboardStorageClient, LocalReviewStorage,
and resolve_storage factory.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.config import Config
from ai_pr_reviewer.models import Finding
from ai_pr_reviewer.storage import (
    DashboardStorageClient,
    LocalReviewStorage,
    resolve_storage,
)


# ----------------------------------------------------------- LocalReviewStorage
def test_local_review_storage_crud(tmp_path):
    db_file = tmp_path / "state.db"
    storage = LocalReviewStorage(db_file)

    repo = "acme/repo"
    pr = 10

    # Initial state
    assert storage.get_last_reviewed_sha(repo, pr) is None
    assert storage.get_previous_findings(repo, pr) == []

    # Advance SHA
    storage.set_last_reviewed_sha(repo, pr, "sha123", "base000")
    assert storage.get_last_reviewed_sha(repo, pr) == "sha123"

    # Save findings
    f1 = Finding(file="main.py", line=4, severity="high", category="bug",
                 title="Null pointer", fingerprint="fp_null", state="new")
    f2 = Finding(file="utils.py", line=12, severity="medium", category="style",
                 title="Unused import", fingerprint="fp_import", state="active")
    storage.save_findings(f"{repo}#{pr}@sha123", [f1, f2])

    loaded = storage.get_previous_findings(repo, pr)
    assert len(loaded) == 2
    titles = {f.title for f in loaded}
    assert titles == {"Null pointer", "Unused import"}

    # Repo memory — the engine never writes this (see D10), so seed the
    # row the way external tooling would: straight SQL into the table.
    import sqlite3

    with sqlite3.connect(db_file) as conn:
        conn.execute(
            "INSERT INTO repo_memory(repo, path_pattern, note, created_at) "
            "VALUES (?, ?, ?, ?)",
            (repo, "*.py", "Always check None", "2026-01-01T00:00:00+00:00"),
        )
    notes = storage.get_repo_memory(repo, ["main.py"])
    assert notes == ["Always check None"]
    assert storage.get_repo_memory(repo, ["styles.css"]) == []


# ------------------------------------------------------- DashboardStorageClient
def test_dashboard_storage_client_success():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        assert request.headers.get("X-Dashboard-Token") == "secret-token"

        if request.method == "GET" and "/state" in str(request.url):
            return httpx.Response(200, json={"last_reviewed_sha": "sha_remote", "base_sha": "base_remote"})
        if request.method == "PUT" and "/state" in str(request.url):
            return httpx.Response(200, json={"ok": True})
        if request.method == "GET" and "/findings" in str(request.url):
            return httpx.Response(200, json={"findings": [
                {"file": "app.py", "line": 5, "severity": "critical", "category": "security",
                 "title": "RCE", "fingerprint": "fp_rce", "state": "active"}
            ]})
        if request.method == "POST" and "/findings" in str(request.url):
            return httpx.Response(200, json={"ok": True})
        if request.method == "GET" and "/memory" in str(request.url):
            return httpx.Response(200, json={"memory": [{"path_pattern": "*.py", "note": "Safe eval only"}]})

        return httpx.Response(404, json={"detail": "not found"})

    transport = httpx.MockTransport(handler)
    mock_client = httpx.Client(transport=transport, base_url="https://dashboard.example.com",
                               headers={"X-Dashboard-Token": "secret-token"})

    client = DashboardStorageClient("https://dashboard.example.com", "secret-token", client=mock_client)

    # 1. get_last_reviewed_sha
    sha = client.get_last_reviewed_sha("acme/api", 42)
    assert sha == "sha_remote"

    # 2. set_last_reviewed_sha
    client.set_last_reviewed_sha("acme/api", 42, "new_sha", "base_sha")

    # 3. get_previous_findings
    findings = client.get_previous_findings("acme/api", 42)
    assert len(findings) == 1
    assert findings[0].title == "RCE"

    # 4. save_findings
    client.save_findings("acme/api#42@new_sha", findings)

    # 5. get_repo_memory
    notes = client.get_repo_memory("acme/api", ["app.py"])
    assert notes == ["Safe eval only"]


def test_dashboard_storage_client_resilience_on_errors():
    def broken_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "internal error"})

    mock_client = httpx.Client(transport=httpx.MockTransport(broken_handler),
                               base_url="https://down.example.com")
    client = DashboardStorageClient("https://down.example.com", "token", client=mock_client)

    # All calls degrade gracefully instead of raising
    assert client.get_last_reviewed_sha("a/b", 1) is None
    client.set_last_reviewed_sha("a/b", 1, "sha")  # does not raise
    assert client.get_previous_findings("a/b", 1) == []
    client.save_findings("a/b#1@sha", [])  # does not raise
    assert client.get_repo_memory("a/b", ["file.py"]) == []
    assert client.get_dismissed_fingerprints("a/b") == set()  # does not raise


# ------------------------------------------------- dismissed fingerprints (D3/D4)
def _memory_client(rows: list[dict]) -> DashboardStorageClient:
    """A client whose dashboard returns exactly ``rows`` for /memory."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/memory" in str(request.url):
            return httpx.Response(200, json={"memory": rows})
        return httpx.Response(404, json={"detail": "not found"})

    mock_client = httpx.Client(transport=httpx.MockTransport(handler),
                               base_url="https://dashboard.example.com")
    return DashboardStorageClient("https://dashboard.example.com", "tok",
                                  client=mock_client)


def test_dismissed_fingerprints_come_back_from_fingerprint_rows():
    client = _memory_client([
        {"path_pattern": "*.py", "note": "Safe eval only"},
        {"path_pattern": "fingerprint:0123456789abcdef", "note": "Muted finding 0123456789abcdef"},
        {"path_pattern": "fingerprint:fedcba9876543210", "note": "Muted finding fedcba9876543210"},
        {"path_pattern": "fingerprint:", "note": "Muted finding "},   # malformed
    ])

    assert client.get_dismissed_fingerprints("acme/api") == {
        "0123456789abcdef", "fedcba9876543210"}


def test_mute_rows_never_surface_as_repository_memory_notes():
    client = _memory_client([
        {"path_pattern": "*.py", "note": "Safe eval only"},
        {"path_pattern": "fingerprint:0123456789abcdef", "note": "Muted finding 0123456789abcdef"},
    ])

    assert client.get_repo_memory("acme/api", ["app.py"]) == ["Safe eval only"]


def test_dismissed_fingerprints_missing_endpoint_returns_empty_set():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"detail": "not found"})

    mock_client = httpx.Client(transport=httpx.MockTransport(handler),
                               base_url="https://dashboard.example.com")
    client = DashboardStorageClient("https://dashboard.example.com", "tok",
                                    client=mock_client)
    assert client.get_dismissed_fingerprints("acme/api") == set()


# -------------------------------------------------------------- resolve_storage
def test_resolve_storage(tmp_path, monkeypatch):
    # 1. Dashboard takes precedence
    cfg1 = Config(dashboard_url="http://dash.local", dashboard_token="tok")
    s1 = resolve_storage(cfg1)
    assert isinstance(s1, DashboardStorageClient)

    # 2. Local storage file
    cfg2 = Config()
    cfg2.storage_file = str(tmp_path / "local.db")
    s2 = resolve_storage(cfg2)
    assert isinstance(s2, LocalReviewStorage)

    # 3. Environment variable fallback
    monkeypatch.setenv("REVIEW_STORAGE_FILE", str(tmp_path / "env.db"))
    cfg3 = Config()
    s3 = resolve_storage(cfg3)
    assert isinstance(s3, LocalReviewStorage)

    # 4. Default: stateless None
    monkeypatch.delenv("REVIEW_STORAGE_FILE", raising=False)
    cfg4 = Config()
    assert resolve_storage(cfg4) is None


# -------------------------------------------------- V3-E02-T04 · telemetry
def _telemetry_row(state="ok", in_tok=120, out_tok=30, call_ms=1500):
    return {
        "schema": 1, "provider": "claude", "model": "claude-sonnet-4-6",
        "batch_count": 2, "fallback_used": False,
        "usage": {"provider": "claude", "model": "claude-sonnet-4-6",
                  "input_tokens": in_tok, "output_tokens": out_tok,
                  "duration_ms": call_ms, "state": state},
        "calls": [], "events": [],
    }


def test_t04_local_storage_telemetry_round_trip(tmp_path):
    """T04 acceptance: telemetry round-trips through the engine backend —
    save then get returns the row; a re-save upserts instead of stacking."""
    storage = LocalReviewStorage(tmp_path / "state.db")
    rid = "acme/api#10@sha123"

    storage.save_telemetry(rid, _telemetry_row())
    got = storage.get_telemetry(rid)

    assert got is not None
    assert got["usage"]["input_tokens"] == 120
    assert got["provider"] == "claude"

    updated = _telemetry_row(in_tok=999)
    storage.save_telemetry(rid, updated)
    assert storage.get_telemetry(rid)["usage"]["input_tokens"] == 999


def test_t04_missing_telemetry_row_reads_none(tmp_path):
    """T04 acceptance: missing-telemetry rows don't break reads."""
    storage = LocalReviewStorage(tmp_path / "state.db")
    assert storage.get_telemetry("acme/api#10@absent") is None


def test_t04_telemetry_table_gains_without_touching_old_rows(tmp_path):
    """T04 acceptance: migration on an existing DB leaves old rows intact —
    a database created before telemetry existed gains the table on open,
    and its findings/state rows still read back unchanged."""
    import sqlite3

    db = tmp_path / "old.db"
    with sqlite3.connect(db) as conn:
        conn.executescript("""
            CREATE TABLE review_state (
                repo TEXT NOT NULL, pr_number INTEGER NOT NULL,
                last_reviewed_sha TEXT, base_sha TEXT, updated_at TEXT,
                PRIMARY KEY (repo, pr_number));
            CREATE TABLE finding_history (
                repo TEXT NOT NULL, pr_number INTEGER NOT NULL,
                fingerprint TEXT NOT NULL, state TEXT, first_seen_sha TEXT,
                last_seen_sha TEXT, resolved_at TEXT, payload TEXT,
                updated_at TEXT, PRIMARY KEY (repo, pr_number, fingerprint));
            CREATE TABLE repo_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT, repo TEXT NOT NULL,
                path_pattern TEXT NOT NULL, note TEXT NOT NULL, created_at TEXT,
                category TEXT, enabled INTEGER DEFAULT 1, updated_at TEXT);
        """)
        conn.execute(
            "INSERT INTO finding_history(repo, pr_number, fingerprint, payload) "
            "VALUES (?, ?, ?, ?)",
            ("acme/api", 10, "fp_old",
             json.dumps({"file": "old.py", "severity": "high"})))
        conn.execute(
            "INSERT INTO review_state(repo, pr_number, last_reviewed_sha) "
            "VALUES (?, ?, ?)", ("acme/api", 10, "sha_old"))

    storage = LocalReviewStorage(db)              # opens -> additive migration

    assert storage.get_last_reviewed_sha("acme/api", 10) == "sha_old"
    previous = storage.get_previous_findings("acme/api", 10)
    assert len(previous) == 1 and previous[0].file == "old.py"
    # and the new table works on the migrated database
    storage.save_telemetry("acme/api#10@sha_new", _telemetry_row())
    assert storage.get_telemetry("acme/api#10@sha_new")["batch_count"] == 2


def test_t04_unavailable_tokens_store_as_null_never_zero(tmp_path):
    """T04 key requirement: typed absence survives storage — an unavailable
    usage state writes SQL NULL, not a fake 0; an ok state stores integers."""
    import sqlite3

    storage = LocalReviewStorage(tmp_path / "state.db")
    storage.save_telemetry("acme/api#10@bad",
                           _telemetry_row(state="unavailable",
                                          in_tok=None, out_tok=None,
                                          call_ms=None))
    storage.save_telemetry("acme/api#11@good", _telemetry_row())

    with sqlite3.connect(tmp_path / "state.db") as conn:
        conn.row_factory = sqlite3.Row
        rows = {r["review_id"]: r for r in
                conn.execute("SELECT review_id, input_tokens, output_tokens, "
                             "usage_state FROM telemetry")}
    bad, good = rows["acme/api#10@bad"], rows["acme/api#11@good"]
    assert bad["input_tokens"] is None and bad["output_tokens"] is None
    assert bad["usage_state"] == "unavailable"
    assert good["input_tokens"] == 120 and good["usage_state"] == "ok"


# --------------------------------------------------- V3-E04-T01 · connections
def _tracking_storage(db_path, monkeypatch, opened):
    """A LocalReviewStorage that records every handle ``_connect`` opens."""
    original = LocalReviewStorage._connect

    def tracking(self):
        conn = original(self)
        opened.append(conn)
        return conn

    monkeypatch.setattr(LocalReviewStorage, "_connect", tracking)
    return LocalReviewStorage(db_path)


def test_t01_every_call_uses_exactly_one_connection_and_closes_it(
        tmp_path, monkeypatch):
    """One connection per call — no pooling, no reuse — and every one of
    them is closed by the time the call returns (V3-E04-T01 acceptance:
    connections are asserted closed, not merely committed)."""
    import sqlite3

    opened: list = []
    storage = _tracking_storage(tmp_path / "state.db", monkeypatch, opened)
    repo, pr = "acme/api", 7

    storage.set_last_reviewed_sha(repo, pr, "sha1", "base1")
    assert storage.get_last_reviewed_sha(repo, pr) == "sha1"
    storage.save_findings(f"{repo}#{pr}@sha1", [
        Finding(file="a.py", line=1, severity="high", category="bug",
                title="t", fingerprint="fp1", state="new")])
    assert len(storage.get_previous_findings(repo, pr)) == 1
    storage.save_telemetry(f"{repo}#{pr}@sha1", {"provider": "static"})
    assert storage.get_telemetry(f"{repo}#{pr}@sha1") is not None
    storage.get_repo_memory(repo, ["a.py"])
    storage.list_repo_memory(repo)

    # init (_init_db) + 8 public calls = 9 handles, all from separate opens
    assert len(opened) == 9
    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")     # sqlite3 rejects closed databases


def test_t01_failed_call_rolls_back_and_still_closes(tmp_path, monkeypatch):
    """A raising call keeps ``with conn``'s rollback semantics *and*
    releases the handle — the new chokepoint changes neither."""
    import sqlite3

    opened: list = []
    storage = _tracking_storage(tmp_path / "state.db", monkeypatch, opened)
    storage.set_last_reviewed_sha("a/b", 1, "sha")

    with pytest.raises(RuntimeError):
        with storage._connection() as conn:
            conn.execute(
                "INSERT INTO review_state(repo, pr_number, last_reviewed_sha) "
                "VALUES ('a/b', 2, 'doomed')")
            raise RuntimeError("boom")

    assert storage.get_last_reviewed_sha("a/b", 2) is None   # rolled back
    for conn in opened:
        with pytest.raises(sqlite3.ProgrammingError):
            conn.execute("SELECT 1")


def test_t01_db_file_released_without_forcing_gc(tmp_path):
    """Regression for the debt-13 root cause: finished calls leave no open
    handle, so the database file can be replaced with no gc.collect().
    (On Windows an unclosed handle here raises PermissionError.)"""
    import os
    import shutil

    db = tmp_path / "state.db"
    storage = LocalReviewStorage(db)
    storage.set_last_reviewed_sha("a/b", 1, "sha")

    copy = tmp_path / "copy.db"
    shutil.copyfile(db, copy)
    os.replace(copy, db)                      # needs every handle closed

    fresh = LocalReviewStorage(db)
    assert fresh.get_last_reviewed_sha("a/b", 1) == "sha"


def test_t01_interleaved_backends_on_one_file_keep_working(tmp_path):
    """Per-call open/close must not change today's concurrency guarantees:
    two LocalReviewStorage instances sharing a file still interleave."""
    db = tmp_path / "state.db"
    a = LocalReviewStorage(db)
    b = LocalReviewStorage(db)

    a.set_last_reviewed_sha("x/y", 3, "sha_a")
    b.save_findings("x/y#3@sha_a", [
        Finding(file="m.py", line=2, severity="low", category="style",
                title="t", fingerprint="fp1", state="active")])
    assert b.get_last_reviewed_sha("x/y", 3) == "sha_a"
    assert [f.fingerprint for f in a.get_previous_findings("x/y", 3)] == ["fp1"]


# --------------------------------------------- V3-E04-T04 · capability flags
def test_t04_has_capability_declared_inferred_and_none():
    """Branch on the declared flag; legacy duck-typed backends still infer
    (method presence) at the single chokepoint; None is never capable."""
    from ai_pr_reviewer.storage import has_capability
    from ai_pr_reviewer.storage_schema import (CAP_PRUNE, CAP_TELEMETRY,
                                               CORE_CAPABILITIES)

    assert not has_capability(None, CAP_TELEMETRY)

    class Declared:
        capabilities = frozenset({CAP_TELEMETRY})

    class DeclaredEmpty:
        capabilities = frozenset()

    class Legacy:                       # predates the declaration
        def save_telemetry(self, review_id, telemetry):  # noqa: B027
            ...

    assert has_capability(Declared(), CAP_TELEMETRY)
    assert not has_capability(Declared(), CAP_PRUNE)
    assert not has_capability(DeclaredEmpty(), CAP_TELEMETRY)
    assert has_capability(Legacy(), CAP_TELEMETRY)      # legacy inference
    assert not has_capability(Legacy(), CAP_PRUNE)


def test_t04_backends_declare_full_capability_set():
    """Both real engine backends declare the full contract — including the
    two formerly-undeclared capabilities — and the HTTP client's absences
    (telemetry, pruning) are explicit, not silent."""
    from ai_pr_reviewer.storage import has_capability
    from ai_pr_reviewer.storage_schema import (CAP_DISMISSED_FINGERPRINTS,
                                               CAP_LIST_REPO_MEMORY,
                                               CAP_PRUNE, CAP_TELEMETRY,
                                               CORE_CAPABILITIES)

    for cls in (LocalReviewStorage, DashboardStorageClient):
        assert CORE_CAPABILITIES <= cls.capabilities, cls
        assert CAP_LIST_REPO_MEMORY in cls.capabilities, cls
        assert CAP_DISMISSED_FINGERPRINTS in cls.capabilities, cls

    assert CAP_TELEMETRY not in DashboardStorageClient.capabilities
    assert CAP_PRUNE not in DashboardStorageClient.capabilities
    assert has_capability(LocalReviewStorage(":memory:"), CAP_TELEMETRY)
    assert has_capability(LocalReviewStorage(":memory:"), CAP_PRUNE)


def test_t04_local_storage_reads_seeded_mute_rows(tmp_path):
    """The local backend gains the dismissal reader, matching what the
    dashboard's mute rows mean: fingerprint rows become dismissals and
    are never notes; other repos and malformed rows are ignored."""
    import sqlite3

    storage = LocalReviewStorage(tmp_path / "state.db")
    assert storage.get_dismissed_fingerprints("a/b") == set()

    conn = sqlite3.connect(tmp_path / "state.db")
    conn.executemany(
        "INSERT INTO repo_memory(repo, path_pattern, note) VALUES (?, ?, ?)",
        [("a/b", "fingerprint:fp_a", "Muted finding fp_a"),
         ("a/b", "fingerprint:fp_b", "Muted finding fp_b"),
         ("a/b", "fingerprint:", "malformed — no fingerprint"),
         ("a/b", "*.py", "a plain note"),
         ("c/d", "fingerprint:fp_other", "other repo")])
    conn.commit()
    conn.close()

    assert storage.get_dismissed_fingerprints("a/b") == {"fp_a", "fp_b"}
    assert storage.get_dismissed_fingerprints("c/d") == {"fp_other"}
    assert storage.get_dismissed_fingerprints("e/f") == set()


def test_t04_no_getattr_capability_guards_at_call_sites():
    """Acceptance: context.py and orchestrator.py branch on declared
    capability flags through the shared chokepoint — no getattr guards,
    no literal capability-name probes at the call sites."""
    for rel in ("ai_pr_reviewer/context.py", "ai_pr_reviewer/orchestrator.py"):
        source = (ROOT / rel).read_text(encoding="utf-8")
        assert "getattr(storage" not in source, rel
        assert "getattr(self.storage" not in source, rel
        assert 'getattr(storage, "' not in source, rel


def test_t04_backend_without_capability_degrades_with_warning(caplog):
    """A backend that declares no dismissal capability skips the mute step
    *with a logged warning* — never a crash, never silently-varying."""
    import logging

    from ai_pr_reviewer.orchestrator import ReviewOrchestrator

    class Stub:
        storage = None
        cfg = None

    class NoDismissals:
        capabilities = frozenset({"get_last_reviewed_sha"})

    finding = Finding(file="a.py", line=1, severity="high", category="bug",
                      title="t", fingerprint="fp1", state="new")

    stub = Stub()
    stub.storage = NoDismissals()
    with caplog.at_level(logging.WARNING, logger="ai_pr_reviewer.orchestrator"):
        out = ReviewOrchestrator._apply_dismissals(
            stub, "a/b", [finding], warnings=[])
    assert out == [finding]                      # unchanged, no crash
    assert "get_dismissed_fingerprints" in caplog.text
    assert "no findings were muted" in caplog.text


def test_t04_memory_falls_back_with_warning_when_capability_absent(caplog):
    """Documented fallback: no list_repo_memory → plain get_repo_memory
    (logged as a degradation); no memory capability at all → [] (logged)."""
    import logging

    from ai_pr_reviewer.context import _load_memory_entries
    from ai_pr_reviewer.storage_schema import CAP_LIST_REPO_MEMORY

    class PlainNotesOnly:
        capabilities = frozenset({"get_repo_memory"})

        def get_repo_memory(self, repo, paths):
            return ["use pathlib here"]

    class NoMemoryAtAll:
        capabilities = frozenset()

    with caplog.at_level(logging.WARNING, logger="ai_pr_reviewer.context"):
        entries = _load_memory_entries(PlainNotesOnly(), "a/b", ["x.py"])
    assert len(entries) == 1
    assert entries[0]["note"] == "use pathlib here"
    assert entries[0]["path_pattern"] == "*"
    assert "lacks list_repo_memory" in caplog.text

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="ai_pr_reviewer.context"):
        assert _load_memory_entries(NoMemoryAtAll(), "a/b", ["x.py"]) == []
    assert "no repository-memory capability" in caplog.text

    # None storage stays the silent stateless path (not a degradation)
    caplog.clear()
    assert _load_memory_entries(None, "a/b", ["x.py"]) == []
    assert caplog.text == ""


def test_t04_duck_typed_fakes_without_capabilities_keep_working():
    """Legacy inference at the chokepoint: a fake that has the method but
    no declared set is still reachable, so no existing embedder breaks."""
    from ai_pr_reviewer.context import _load_memory_entries
    from ai_pr_reviewer.storage import has_capability
    from ai_pr_reviewer.storage_schema import CAP_LIST_REPO_MEMORY

    class LegacyWithMethod:
        def list_repo_memory(self, repo):
            return [{"note": "legacy", "path_pattern": "src/*.py"}]

    assert has_capability(LegacyWithMethod(), CAP_LIST_REPO_MEMORY)
    entries = _load_memory_entries(LegacyWithMethod(), "a/b", ["src/x.py"])
    assert [e["note"] for e in entries] == ["legacy"]


# ----------------------------------------------------- V3-E04-T02 · retention
_OLD = "2020-01-01T00:00:00+00:00"
_NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)


def _finding(fp: str) -> dict:
    return {"file": "a.py", "line": 1, "severity": "high", "category": "bug",
            "title": "t", "state": "new", "fingerprint": fp}


def _sql(db, stmt: str, params: tuple = ()):
    import sqlite3

    conn = sqlite3.connect(db)
    conn.execute(stmt, params)
    conn.commit()
    conn.close()


def _history_fps(db) -> set:
    import sqlite3

    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT repo, pr_number, fingerprint FROM finding_history").fetchall()
    conn.close()
    return set(rows)


def test_t02_retention_disabled_by_default_is_a_pure_noop(tmp_path):
    """Default-off is the contract: retention_days defaults to 0 (keep
    everything), prune(0)/prune(<0) are no-ops, and aged rows survive."""
    db = tmp_path / "state.db"
    storage = LocalReviewStorage(db)
    assert Config().retention_days == 0

    storage.set_last_reviewed_sha("a/b", 1, "sha1")
    storage.save_findings("a/b#1@sha1", [_finding("fp1")])
    storage.save_telemetry("a/b#1@sha1", _telemetry_row())
    _sql(db, "UPDATE finding_history SET updated_at=?", (_OLD,))
    _sql(db, "UPDATE review_state SET updated_at=?", (_OLD,))
    _sql(db, "UPDATE telemetry SET updated_at=?", (_OLD,))

    for days in (0, -1):
        assert storage.prune(days, now=_NOW) == {
            "enabled": False, "cutoff": None, "dry_run": False,
            "finding_history": 0, "telemetry": 0}
    assert _history_fps(db) == {("a/b", 1, "fp1")}
    assert storage.get_telemetry("a/b#1@sha1") is not None


def test_t02_prune_keeps_active_unknown_and_fresh_rows(tmp_path):
    """The full policy: aged history goes only when its PR's review_state
    exists and is itself stale. Active PRs (fresh state), stateless
    history (unknown → keep), fresh rows, NULL timestamps, repo memory
    and the review_state rows themselves all survive. Dry-run reports the
    same counts without deleting; a rerun finds nothing (idempotent)."""
    db = tmp_path / "state.db"
    storage = LocalReviewStorage(db)

    storage.set_last_reviewed_sha("a/b", 1, "sha1")     # stale state
    storage.save_findings("a/b#1@sha1", [_finding("fp_stale")])
    storage.set_last_reviewed_sha("a/b", 2, "sha2")     # fresh state
    storage.save_findings("a/b#2@sha2", [_finding("fp_active")])
    storage.save_findings("a/b#3@sha3", [_finding("fp_orphan")])   # no state
    storage.set_last_reviewed_sha("a/b", 4, "sha4")     # stale state
    storage.save_findings("a/b#4@sha4", [_finding("fp_fresh")])    # fresh row
    storage.save_findings("a/b#9@sha9", [_finding("fp_null")])     # NULL age
    storage.save_telemetry("a/b#1@sha1", _telemetry_row())         # stale
    storage.save_telemetry("a/b#4@sha4", _telemetry_row())         # fresh
    _sql(db, "INSERT INTO repo_memory(repo, path_pattern, note, updated_at) "
             "VALUES (?, ?, ?, ?)",
         ("a/b", "*.py", "a note", _OLD))                # aged human memory

    _sql(db, "UPDATE finding_history SET updated_at=? WHERE pr_number IN (1,2,3)",
         (_OLD,))
    _sql(db, "UPDATE finding_history SET updated_at=NULL WHERE pr_number=9")
    _sql(db, "UPDATE review_state SET updated_at=? WHERE pr_number IN (1,4)",
         (_OLD,))
    _sql(db, "UPDATE telemetry SET updated_at=? WHERE review_id=?",
         (_OLD, "a/b#1@sha1"))

    dry = storage.prune(30, now=_NOW, dry_run=True)     # observe before enable
    assert dry == {"enabled": True, "cutoff": "2026-09-06T12:00:00+00:00",
                   "dry_run": True, "finding_history": 1, "telemetry": 1}
    assert len(_history_fps(db)) == 5                   # nothing deleted

    out = storage.prune(30, now=_NOW)
    assert (out["finding_history"], out["telemetry"]) == (1, 1)
    assert _history_fps(db) == {
        ("a/b", 2, "fp_active"), ("a/b", 3, "fp_orphan"),
        ("a/b", 4, "fp_fresh"), ("a/b", 9, "fp_null")}
    assert storage.get_telemetry("a/b#1@sha1") is None
    assert storage.get_telemetry("a/b#4@sha4") is not None

    import sqlite3
    conn = sqlite3.connect(db)
    assert conn.execute("SELECT COUNT(*) FROM repo_memory").fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM review_state").fetchone()[0] == 3
    conn.close()

    again = storage.prune(30, now=_NOW)                 # idempotent
    assert again["finding_history"] == 0 and again["telemetry"] == 0


def test_t02_resolve_storage_runs_one_retention_pass(tmp_path, monkeypatch):
    """resolve_storage is the engine's retention trigger: off by default,
    exactly one prune pass when retention_days > 0."""
    monkeypatch.delenv("REVIEW_STORAGE_FILE", raising=False)
    db = tmp_path / "state.db"
    storage = LocalReviewStorage(db)
    storage.set_last_reviewed_sha("a/b", 1, "sha1")
    storage.save_findings("a/b#1@sha1", [_finding("fp1")])
    storage.save_telemetry("a/b#1@sha1", _telemetry_row())
    _sql(db, "UPDATE finding_history SET updated_at=?", (_OLD,))
    _sql(db, "UPDATE review_state SET updated_at=?", (_OLD,))
    _sql(db, "UPDATE telemetry SET updated_at=?", (_OLD,))

    assert resolve_storage(Config(storage_file=str(db))) is not None
    assert _history_fps(db) == {("a/b", 1, "fp1")}       # default: untouched

    resolved = resolve_storage(Config(storage_file=str(db), retention_days=30))
    assert isinstance(resolved, LocalReviewStorage)
    assert _history_fps(db) == set()
    assert resolved.get_telemetry("a/b#1@sha1") is None


def test_t02_resolve_storage_never_deletes_remotely(tmp_path):
    """The HTTP client declares no prune capability, so a configured
    retention window never turns the engine into a remote deleter — the
    dashboard prunes its own data at startup instead."""
    from ai_pr_reviewer.storage import has_capability
    from ai_pr_reviewer.storage_schema import CAP_PRUNE

    client = resolve_storage(Config(dashboard_url="http://dash.local",
                                    dashboard_token="tok",
                                    retention_days=30))
    assert isinstance(client, DashboardStorageClient)
    assert not has_capability(client, CAP_PRUNE)


def test_t02_resolve_storage_survives_a_failing_prune(tmp_path, monkeypatch):
    """Retention is best-effort: a broken prune logs and lets the review
    proceed with storage intact."""
    def boom(self, *args, **kwargs):
        raise RuntimeError("disk on fire")

    monkeypatch.setattr(LocalReviewStorage, "prune", boom)
    resolved = resolve_storage(Config(storage_file=str(tmp_path / "x.db"),
                                      retention_days=30))
    assert isinstance(resolved, LocalReviewStorage)      # no exception escaped
