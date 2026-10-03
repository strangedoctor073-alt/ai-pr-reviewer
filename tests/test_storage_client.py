"""Tests for ai_pr_reviewer.storage: DashboardStorageClient, LocalReviewStorage,
and resolve_storage factory.
"""
from __future__ import annotations

import json
import sys
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
