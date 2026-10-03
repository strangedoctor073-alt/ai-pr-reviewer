"""V3 C7 — project memory: human-authored notes, read-only for the engine.

The contract under test: memory is *informed* by humans, never *written* by
the reviewer; mute rows (dismissal decisions) and disabled rows never reach a
prompt; every row is path-scoped, bounded and category-normalised; the notes
are redacted and fenced as untrusted data like everything else; and storage
failures degrade to "no memory", never to a failed review.
"""
from __future__ import annotations

import sqlite3
from urllib.parse import quote

import httpx
import pytest
from fastapi.testclient import TestClient

import dashboard.app as dashboard_app
from ai_pr_reviewer import memory as memory_rules
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.context import build_context
from ai_pr_reviewer.diff_parser import FileDiff
from ai_pr_reviewer.models import PRContext
from ai_pr_reviewer.storage import DashboardStorageClient, LocalReviewStorage
from dashboard.storage import JsonStorage

PR = PRContext(repo="acme/api", pr_number=7)
FILES = [FileDiff(old_path="payments/refund.py", new_path="payments/refund.py")]


def _context(storage, gh=None):
    return build_context(PR, FILES, Config(), storage=storage, gh=gh)


# ---------------------------------------------------------------- selection

def test_mute_rows_are_dismissals_not_project_memory():
    rows = [{"note": "dismissed as a false positive", "path_pattern": "fingerprint:abc",
             "category": "project-rule", "enabled": True}]

    assert memory_rules.select_memory(rows, ["payments/refund.py"]) == []


def test_disabled_rows_stay_on_the_dashboard_but_never_reach_a_prompt():
    rows = [{"note": "outdated rule", "path_pattern": "*",
             "category": "project-rule", "enabled": False}]

    assert memory_rules.select_memory(rows, ["payments/refund.py"]) == []


def test_path_scoped_memory_only_applies_where_it_matches():
    rows = [{"note": "refunds are idempotent", "path_pattern": "payments/*.py"}]

    assert memory_rules.select_memory(rows, ["other/module.py"]) == []
    assert len(memory_rules.select_memory(rows, ["payments/refund.py"])) == 1
    assert len(memory_rules.select_memory(
        rows, ["payments/refund.py", "other/module.py"])) == 1


def test_a_glob_pattern_applies_to_every_reviewed_path():
    rows = [{"note": "always check None", "path_pattern": "*"}]

    assert len(memory_rules.select_memory(rows, ["a/b.py"])) == 1


def test_empty_notes_are_dropped():
    rows = [{"note": "   ", "path_pattern": "*"}]

    assert memory_rules.select_memory(rows, ["a.py"]) == []


def test_memory_is_bounded_sixty_rows_cannot_drown_the_prompt():
    rows = [{"note": f"rule {i}", "path_pattern": "*"} for i in range(60)]

    assert len(memory_rules.select_memory(rows, ["a.py"])) == \
        memory_rules.MAX_MEMORY_ENTRIES


def test_each_note_is_capped():
    rows = [{"note": "x" * 5_000, "path_pattern": "*"}]

    assert len(memory_rules.select_memory(rows, ["a.py"])[0]["note"]) == \
        memory_rules.MAX_NOTE_CHARS


def test_the_default_category_is_omitted_but_others_are_prefixed():
    assert memory_rules.format_note({"note": "check None"}) == "check None"
    assert memory_rules.format_note({"note": "check None",
                                     "category": "project-rule"}) == "check None"
    assert memory_rules.format_note({"note": "refunds retry",
                                     "category": "known-exception"}) == \
        "[known-exception] refunds retry"


def test_categories_are_normalised_to_the_known_set():
    assert memory_rules.normalize_category("Known Exception") == "known-exception"
    assert memory_rules.normalize_category("review_preference") == "review-preference"
    assert memory_rules.normalize_category("anything-else") == "project-rule"
    assert memory_rules.normalize_category(None) == "project-rule"
    assert memory_rules.normalize_category(42) == "project-rule"


def test_attribute_style_rows_and_plain_dicts_are_both_accepted():
    class Row:
        note = "note"
        path_pattern = "*.py"
        category = "preferred-pattern"
        enabled = True

    selected = memory_rules.select_memory([Row(), {"note": "other",
                                                   "path_pattern": "*.py"}],
                                          ["a.py"])
    assert [r["category"] for r in selected] == ["preferred-pattern",
                                                 "project-rule"]


# ------------------------------------------------------------ build_context

class ListStorage:
    """Backend exposing the rich C7 row."""

    def __init__(self, rows):
        self.rows = rows

    def list_repo_memory(self, repo):
        return list(self.rows)


class NoteStorage:
    """Backend that only knows plain notes (older/local)."""

    def __init__(self, notes):
        self.notes = notes

    def get_repo_memory(self, repo, paths):
        return list(self.notes)


class BothStorage:
    def list_repo_memory(self, repo):
        return [{"note": "from the lister", "path_pattern": "*",
                 "category": "known-exception", "enabled": True}]

    def get_repo_memory(self, repo, paths):
        return ["from the getter"]


def test_build_context_prefers_the_rich_memory_read():
    storage = BothStorage()

    assert _context(storage).memory_notes == ["[known-exception] from the lister"]


def test_build_context_falls_back_to_plain_notes():
    storage = NoteStorage(["always check None"])

    assert _context(storage).memory_notes == ["always check None"]


def test_no_storage_means_no_memory_notes():
    assert _context(None).memory_notes == []


def test_disabled_and_mute_rows_never_reach_the_context():
    storage = ListStorage([
        {"note": "good rule", "path_pattern": "*", "category": "project-rule",
         "enabled": True},
        {"note": "outdated", "path_pattern": "*", "category": "project-rule",
         "enabled": False},
        {"note": "dismissed", "path_pattern": "fingerprint:abc",
         "category": "project-rule", "enabled": True},
        {"note": "other dir", "path_pattern": "elsewhere/*.py",
         "category": "project-rule", "enabled": True},
    ])

    assert _context(storage).memory_notes == ["good rule"]


def test_memory_notes_are_secret_redacted():
    token = "ghp_" + "B" * 30
    storage = ListStorage([{"note": f"deploy token is {token}",
                            "path_pattern": "*", "category": "project-rule",
                            "enabled": True}])

    notes = _context(storage).memory_notes

    assert token not in notes[0]
    assert "[REDACTED]" in notes[0]


def test_a_broken_memory_backend_is_no_memory_not_a_failed_review():
    class Broken:
        def list_repo_memory(self, repo):
            raise RuntimeError("database is down")

    assert _context(Broken()).memory_notes == []


def test_a_broken_note_only_backend_also_degrades_quietly():
    class Broken:
        def get_repo_memory(self, repo, paths):
            raise RuntimeError("database is down")

    assert _context(Broken()).memory_notes == []


# -------------------------------------------------------------- local storage

def _seed(storage, repo: str) -> None:
    """Seed rows the way external tooling would: straight SQL (D10 — the
    engine has no write path for repo memory)."""
    with sqlite3.connect(str(storage.db_path)) as conn:
        conn.execute(
            "INSERT INTO repo_memory(repo, path_pattern, note, created_at) "
            "VALUES (?, ?, ?, ?)",
            (repo, "*.py", "Always check None", "2026-01-01T00:00:00+00:00"))
        conn.execute(
            "INSERT INTO repo_memory(repo, path_pattern, note, created_at, "
            "category, enabled) VALUES (?, ?, ?, ?, ?, ?)",
            (repo, "*", "refunds retry on purpose", "2026-01-02T00:00:00+00:00",
             "known-exception", 0))


def test_local_storage_exposes_memory_metadata(tmp_path):
    storage = LocalReviewStorage(tmp_path / "state.db")
    _seed(storage, "acme/api")

    rows = storage.list_repo_memory("acme/api")
    assert len(rows) == 2
    assert rows[0]["note"] == "Always check None"
    assert rows[1]["category"] == "known-exception"
    assert rows[1]["enabled"] == 0
    assert storage.list_repo_memory("acme/other") == []

    # the metadata is what the reviewer acts on
    selected = memory_rules.select_memory(rows, ["payments/refund.py"])
    assert [r["category"] for r in selected] == ["project-rule"]


def test_local_storage_has_no_write_path_for_project_memory(tmp_path):
    storage = LocalReviewStorage(tmp_path / "state.db")

    for method in ("add_repo_memory", "update_repo_memory", "delete_repo_memory"):
        assert not hasattr(storage, method), f"the engine must not write {method}"


def test_older_databases_gain_the_c7_columns_in_place(tmp_path):
    """A database created before C3/C7 keeps working: the columns are added
    on open, not required to already exist."""
    db = tmp_path / "old.db"
    with sqlite3.connect(db) as conn:
        conn.execute("CREATE TABLE repo_memory (id INTEGER PRIMARY KEY "
                     "AUTOINCREMENT, repo TEXT NOT NULL, path_pattern TEXT "
                     "NOT NULL, note TEXT NOT NULL, created_at TEXT)")
        conn.execute("INSERT INTO repo_memory(repo, path_pattern, note, created_at)"
                     " VALUES ('acme/api', '*', 'old note', '2026-01-01')")

    storage = LocalReviewStorage(db)

    rows = storage.list_repo_memory("acme/api")
    assert [r["note"] for r in rows] == ["old note"]
    assert rows[0]["enabled"] in (1, True)


# --------------------------------------------------------- dashboard API

def _memory_app(monkeypatch, tmp_path, storage):
    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dashboard_app, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(dashboard_app, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(dashboard_app, "_storage", storage)
    monkeypatch.setattr(dashboard_app, "_api_token", "test-token")
    return {"X-Dashboard-Token": "test-token"}


def _json_storage(tmp_path) -> JsonStorage:
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    return storage


def test_memory_rows_can_be_added_edited_and_deleted(monkeypatch, tmp_path):
    storage = _json_storage(tmp_path)
    headers = _memory_app(monkeypatch, tmp_path, storage)
    url = "/api/repos/acme/widgets/memory"

    with TestClient(dashboard_app.app) as client:
        posted = client.post(url, json={"path_pattern": "*.py",
                                        "note": "Always check None",
                                        "category": "known-exception"},
                             headers=headers)
        assert posted.status_code == 200

        rows = client.get(url, headers=headers).json()["memory"]
        assert rows[0]["category"] == "known-exception"
        assert rows[0]["enabled"] is True
        target = f"{url}?id={quote(rows[0]['id'])}"

        edited = client.put(target, json={"note": "Updated", "enabled": False},
                            headers=headers)
        assert edited.status_code == 200

        rows = client.get(url, headers=headers).json()["memory"]
        assert rows[0]["note"] == "Updated"
        assert rows[0]["enabled"] is False

        deleted = client.delete(target, headers=headers)
        assert deleted.status_code == 200
        assert client.get(url, headers=headers).json()["memory"] == []


def test_memory_writes_require_the_dashboard_token(monkeypatch, tmp_path):
    storage = _json_storage(tmp_path)
    _memory_app(monkeypatch, tmp_path, storage)
    url = "/api/repos/acme/widgets/memory"

    with TestClient(dashboard_app.app) as client:
        assert client.post(url, json={"note": "x"}).status_code == 401
        assert client.put(f"{url}?id=anything", json={"note": "x"}).status_code == 401
        assert client.delete(f"{url}?id=anything").status_code == 401


def test_memory_input_is_capped_server_side(monkeypatch, tmp_path):
    storage = _json_storage(tmp_path)
    headers = _memory_app(monkeypatch, tmp_path, storage)
    url = "/api/repos/acme/widgets/memory"

    with TestClient(dashboard_app.app) as client:
        assert client.post(url, json={"note": ""}, headers=headers).status_code == 400
        client.post(url, json={"note": "n" * 5_000,
                               "path_pattern": "p" * 500}, headers=headers)

        rows = client.get(url, headers=headers).json()["memory"]
        assert len(rows[0]["note"]) == 1000
        assert len(rows[0]["path_pattern"]) == 255


def test_dismissal_rows_cannot_be_edited_through_the_memory_api(monkeypatch, tmp_path):
    """``fingerprint:`` rows are mute decisions owned by the feedback API —
    a memory edit must never silently un-mute a finding."""
    storage = _json_storage(tmp_path)
    storage.record_feedback("fp123", "mute", repo="acme/widgets")
    headers = _memory_app(monkeypatch, tmp_path, storage)
    url = "/api/repos/acme/widgets/memory"

    with TestClient(dashboard_app.app) as client:
        rows = client.get(url, headers=headers).json()["memory"]
        mute_id = quote(next(r["id"] for r in rows
                             if r["path_pattern"].startswith("fingerprint:")))

        assert client.put(f"{url}?id={mute_id}", json={"note": "sneaky edit"},
                          headers=headers).status_code == 403
        assert client.delete(f"{url}?id={mute_id}",
                             headers=headers).status_code == 403
        assert len(client.get(url, headers=headers).json()["memory"]) == len(rows)


def test_editing_an_unknown_memory_row_is_404(monkeypatch, tmp_path):
    storage = _json_storage(tmp_path)
    headers = _memory_app(monkeypatch, tmp_path, storage)
    url = "/api/repos/acme/widgets/memory"

    with TestClient(dashboard_app.app) as client:
        assert client.put(f"{url}?id=does-not-exist", json={"note": "x"},
                          headers=headers).status_code == 404
        assert client.delete(f"{url}?id=does-not-exist",
                             headers=headers).status_code == 404
        assert client.put(url, json={"note": "x"},
                          headers=headers).status_code == 400


def test_an_unknown_category_is_normalised_on_write(monkeypatch, tmp_path):
    storage = _json_storage(tmp_path)
    headers = _memory_app(monkeypatch, tmp_path, storage)
    url = "/api/repos/acme/widgets/memory"

    with TestClient(dashboard_app.app) as client:
        client.post(url, json={"note": "x", "category": "not-a-category"},
                    headers=headers)
        rows = client.get(url, headers=headers).json()["memory"]
        assert rows[0]["category"] == "project-rule"


# ------------------------------------------------------------ remote client

def _memory_client(rows: list[dict]) -> DashboardStorageClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and "/memory" in str(request.url):
            return httpx.Response(200, json={"repo": "acme/api", "memory": rows})
        return httpx.Response(404, json={"detail": "not found"})

    mock = httpx.Client(transport=httpx.MockTransport(handler),
                        base_url="https://dashboard.example.com")
    return DashboardStorageClient("https://dashboard.example.com", "tok",
                                  client=mock)


def test_the_remote_client_returns_rows_verbatim_including_mute_rows():
    """``list_repo_memory`` is the *whole* truth (the reviewer splits it);
    ``get_repo_memory`` is the path-filtered notes-only view."""
    client = _memory_client([
        {"id": "1", "path_pattern": "*.py", "note": "Safe eval only",
         "category": "project-rule", "enabled": True},
        {"id": "2", "path_pattern": "fingerprint:0123456789abcdef",
         "note": "Muted finding 0123456789abcdef", "category": "project-rule",
         "enabled": True},
    ])

    rows = client.list_repo_memory("acme/api")
    assert len(rows) == 2
    assert client.get_repo_memory("acme/api", ["app.py"]) == ["Safe eval only"]
    assert memory_rules.select_memory(rows, ["app.py"]) == \
        [{"note": "Safe eval only", "path_pattern": "*.py",
          "category": "project-rule"}]


def test_a_failing_remote_client_returns_no_memory_instead_of_raising():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"detail": "boom"})

    mock = httpx.Client(transport=httpx.MockTransport(handler),
                        base_url="https://dashboard.example.com")
    client = DashboardStorageClient("https://dashboard.example.com", "tok",
                                    client=mock)

    assert client.list_repo_memory("acme/api") == []
    assert client.get_repo_memory("acme/api", ["a.py"]) == []
