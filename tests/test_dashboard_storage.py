"""Tests for dashboard storage backends and the rate limiter."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard.app as dashboard_app
from dashboard.app import SlidingWindowLimiter
from dashboard.storage import JsonStorage, choose_storage, summarize


def _report(repo="acme/widgets", number=7, n_findings=3):
    findings = [
        {"file": "a.py", "line": 1, "severity": "critical", "category": "security",
         "title": "t1", "explanation": "e1", "confidence": "high"},
        {"file": "a.py", "line": 2, "severity": "high", "category": "bug",
         "title": "t2", "explanation": "e2", "confidence": "medium"},
        {"file": "b.py", "line": 3, "severity": "low", "category": "style",
         "title": "t3", "explanation": "e3", "confidence": "low"},
    ][:n_findings]
    return {
        "id": f"{repo.replace('/', '-')}-pr{number}-test",
        "pr": {"repo": repo, "number": number, "title": "Fix things",
               "author": "dev", "branch": "feat/x"},
        "mode": "static", "model": "static-rules-v1",
        "reviewed_at": "2026-09-19T00:00:00Z", "duration_ms": 12,
        "summary": "s", "findings": findings,
        "stats": {"files": 2, "additions": 10, "deletions": 1, "hunks": 2},
    }


# ----------------------------------------------------------------- rate limiter
def test_rate_limiter_windows():
    lim = SlidingWindowLimiter()
    for _ in range(3):
        assert lim.check("ip:write", limit=3, window_seconds=60)
    assert not lim.check("ip:write", limit=3, window_seconds=60)
    assert lim.check("other:write", limit=3, window_seconds=60)


def test_dashboard_lifespan_initializes_storage(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dashboard_app, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(dashboard_app, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(dashboard_app, "_storage", None)
    monkeypatch.setattr(dashboard_app, "_api_token", None)

    with TestClient(dashboard_app.app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["ok"] is True


# ------------------------------------------------------------------- db storage
@pytest.fixture()
def db_storage(tmp_path):
    storage = choose_storage(tmp_path, f"sqlite:///{tmp_path/'t.db'}")
    storage.init()
    return storage


def test_db_round_trip(db_storage):
    r = _report()
    assert db_storage.upsert(r) == r["id"]

    got = db_storage.get(r["id"])
    assert got["pr"]["repo"] == "acme/widgets"
    assert len(got["findings"]) == 3

    listing = db_storage.list()
    assert len(listing) == 1
    assert listing[0]["findings_count"] == 3
    assert listing[0]["severity_counts"]["critical"] == 1

    assert db_storage.stats()["findings"] == 3
    assert db_storage.stats()["by_severity"]["high"] == 1

    assert db_storage.delete(r["id"])
    assert db_storage.get(r["id"]) is None


def test_db_upsert_is_idempotent(db_storage):
    r = _report()
    db_storage.upsert(r)
    r["summary"] = "updated"
    db_storage.upsert(r)
    assert len(db_storage.list()) == 1
    assert db_storage.get(r["id"])["summary"] == "updated"


def test_db_caps_findings_on_abuse(db_storage):
    r = _report()
    r["findings"] = [{"file": "f.py", "line": i, "severity": "info",
                      "category": "style", "title": f"f{i}",
                      "explanation": "x"} for i in range(800)]
    db_storage.upsert(r)
    stored = db_storage.get(r["id"])
    assert len(stored["findings"]) <= 500
    assert stored.get("truncated_findings") is True


def test_json_migration_into_db(tmp_path):
    legacy = tmp_path / "data" / "reports"
    legacy.mkdir(parents=True)
    (legacy / "old-report.json").write_text(
        json_dumps(_report(repo="legacy/one", number=1)), encoding="utf-8")

    storage = choose_storage(tmp_path / "data",
                             f"sqlite:///{tmp_path/'data'/'m.db'}")
    storage.init()                     # should import the legacy file once
    assert storage.stats()["reports"] == 1
    storage.init()                     # second init must not duplicate
    assert storage.stats()["reports"] == 1


def json_dumps(obj):
    import json
    return json.dumps(obj)


def test_json_fallback_backend(tmp_path):
    storage = JsonStorage(tmp_path / "reports")
    storage.init()
    r = _report()
    storage.upsert(r)
    assert storage.get(r["id"])["pr"]["number"] == 7
    assert storage.list()[0]["repo"] == "acme/widgets"
    assert storage.stats()["reports"] == 1
    storage.delete(r["id"])
    assert storage.stats()["reports"] == 0


def test_summarize_shape():
    s = summarize(_report())
    assert set(s) >= {"id", "repo", "pr_number", "severity_counts",
                      "findings_count", "stats"}
    assert s["severity_counts"]["critical"] == 1


def test_db_storage_review_state_and_lifecycle(db_storage):
    repo = "acme/payments"
    pr = 42

    # Initially None
    assert db_storage.get_last_reviewed_sha(repo, pr) is None

    # Advance SHA
    db_storage.set_last_reviewed_sha(repo, pr, "sha_111", "base_000")
    assert db_storage.get_last_reviewed_sha(repo, pr) == "sha_111"

    # Save findings
    findings = [
        {"file": "pay.py", "line": 10, "severity": "high", "category": "security",
         "title": "SQLi", "explanation": "bad", "fingerprint": "fp1", "state": "new"},
        {"file": "refund.py", "line": 20, "severity": "medium", "category": "bug",
         "title": "Bug", "explanation": "bad", "fingerprint": "fp2", "state": "active"},
    ]
    db_storage.save_findings(f"{repo}#{pr}@sha_111", findings)

    prev = db_storage.get_previous_findings(repo, pr)
    assert len(prev) == 2
    fps = {f["fingerprint"] for f in prev}
    assert fps == {"fp1", "fp2"}

    # Memory
    db_storage.add_repo_memory(repo, "pay*.py", "Note on payments")
    notes = db_storage.get_repo_memory(repo, ["pay.py"])
    assert notes == ["Note on payments"]
    assert db_storage.get_repo_memory(repo, ["other.py"]) == []


def test_json_storage_review_state_and_lifecycle(tmp_path):
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    repo = "acme/orders"
    pr = 99

    assert storage.get_last_reviewed_sha(repo, pr) is None
    storage.set_last_reviewed_sha(repo, pr, "sha_abc", "base_xyz")
    assert storage.get_last_reviewed_sha(repo, pr) == "sha_abc"

    findings = [
        {"file": "order.py", "line": 5, "severity": "high", "category": "security",
         "title": "XSS", "fingerprint": "fp_xss", "state": "new"}
    ]
    storage.save_findings(f"{repo}#{pr}@sha_abc", findings)
    prev = storage.get_previous_findings(repo, pr)
    assert len(prev) == 1
    assert prev[0]["fingerprint"] == "fp_xss"

    storage.add_repo_memory(repo, "*.py", "Python best practice")
    notes = storage.get_repo_memory(repo, ["src/order.py"])
    assert notes == ["Python best practice"]


# ------------------------------------------------------ privacy baseline (settings)
def test_validated_rules_preserves_sensitive_baseline_and_custom_glob():
    body = {"severity_threshold": "high", "max_comments": 10,
            "exclude_globs": ["**/my-custom-thing/**"], "focus_areas": ["tests"]}
    clean = dashboard_app._validated_rules(body)
    assert set(dashboard_app.SENSITIVE_EXCLUDE_GLOBS) <= set(clean["exclude_globs"])
    assert "**/my-custom-thing/**" in clean["exclude_globs"]


def test_validated_rules_rejects_attempt_to_shrink_exclude_globs():
    """A caller can't narrow exclude_globs down to just their own list —
    the sensitive baseline is always re-merged in server-side."""
    body = {"exclude_globs": ["not-a-secret-path/**"]}
    clean = dashboard_app._validated_rules(body)
    for pattern in dashboard_app.SENSITIVE_EXCLUDE_GLOBS:
        assert pattern in clean["exclude_globs"]


def test_load_settings_cannot_remove_baseline_from_existing_file(monkeypatch, tmp_path):
    """Simulates an existing settings.json (from before the privacy baseline
    existed, or hand-edited) that has no sensitive globs in it at all — the
    baseline must still be present once load_settings() returns."""
    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    settings_path = tmp_path / "settings.json"
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", settings_path)
    settings_path.write_text(
        '{"severity_threshold": "medium", "max_comments": 20, '
        '"exclude_globs": ["**/*.lock"], "focus_areas": []}',
        encoding="utf-8")

    settings = dashboard_app.load_settings()
    assert set(dashboard_app.SENSITIVE_EXCLUDE_GLOBS) <= set(settings["exclude_globs"])
    assert "**/*.lock" in settings["exclude_globs"]

