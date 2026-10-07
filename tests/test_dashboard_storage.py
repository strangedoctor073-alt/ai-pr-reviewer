"""Tests for dashboard storage backends and the rate limiter."""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard.app as dashboard_app
from dashboard.app import SlidingWindowLimiter
from dashboard.storage import DbStorage, JsonStorage, choose_storage, summarize


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


# ----------------------------------------------------- repo memory (D3)
def test_db_list_repo_memory_returns_rows_verbatim(db_storage):
    repo = "acme/payments"
    db_storage.add_repo_memory(repo, "pay*.py", "Note on payments")
    db_storage.add_repo_memory(repo, "*", "Repo-wide note")

    rows = {r["path_pattern"]: r["note"] for r in db_storage.list_repo_memory(repo)}

    assert rows == {"pay*.py": "Note on payments", "*": "Repo-wide note"}
    assert db_storage.list_repo_memory("acme/other") == []


def test_json_list_repo_memory_returns_rows_verbatim(tmp_path):
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    repo = "acme/orders"
    storage.add_repo_memory(repo, "*.py", "Python best practice")

    rows = storage.list_repo_memory(repo)
    # C7: rows now also carry the metadata the reviewer needs (id, category,
    # enabled) — the original columns still come back byte-identical.
    assert [{k: r[k] for k in ("path_pattern", "note", "category", "enabled")}
            for r in rows] == [
        {"path_pattern": "*.py", "note": "Python best practice",
         "category": "project-rule", "enabled": True}]
    assert rows[0]["id"]                       # editable/deletable identity
    assert storage.list_repo_memory("acme/other") == []


def test_db_record_feedback_only_mute_writes_repo_memory(db_storage):
    repo = "acme/payments"

    db_storage.record_feedback("fp_down", "down", repo=repo)
    db_storage.record_feedback("fp_up", "up", repo=repo)
    assert db_storage.list_repo_memory(repo) == []     # a vote is not a mute

    db_storage.record_feedback("fp_mute", "mute", repo=repo)
    assert [(r["path_pattern"], r["note"]) for r in
            db_storage.list_repo_memory(repo)] == [
        ("fingerprint:fp_mute", "Muted finding fp_mute")]
    # ...and the mute row is not a path-scoped note
    assert db_storage.get_repo_memory(repo, ["pay.py"]) == []


def test_json_record_feedback_only_mute_writes_repo_memory(tmp_path):
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    repo = "acme/orders"

    storage.record_feedback("fp_down", "down", repo=repo)
    assert storage.list_repo_memory(repo) == []

    storage.record_feedback("fp_mute", "mute", repo=repo, note="not useful")
    assert [(r["path_pattern"], r["note"]) for r in
            storage.list_repo_memory(repo)] == [
        ("fingerprint:fp_mute", "not useful")]


# ------------------------------------------------- D7 — mute idempotency (V3-E01-T07)
def test_repeated_mute_on_db_backend_leaves_exactly_one_row(db_storage):
    """D7: a mute is identified by repo + fingerprint, not by the repo string
    (which is never a RepoMemoryRow primary key). N mute requests must leave
    exactly one row — the old lookup minted a duplicate per click."""
    repo = "acme/payments"

    for i in range(5):
        db_storage.record_feedback("fp_same", "mute", repo=repo, note=f"click {i}")

    rows = db_storage.list_repo_memory(repo)
    assert len(rows) == 1
    assert rows[0]["path_pattern"] == "fingerprint:fp_same"
    assert rows[0]["note"] == "click 4"           # upsert: latest note wins
    assert db_storage.get_repo_memory(repo, ["pay.py"]) == []   # not a path note

    # a different fingerprint still gets its own row
    db_storage.record_feedback("fp_other", "mute", repo=repo)
    assert len(db_storage.list_repo_memory(repo)) == 2


def test_repeated_mute_on_json_backend_leaves_exactly_one_row(tmp_path):
    """D7 parity: the JSON backend must be idempotent on mute too."""
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    repo = "acme/orders"

    for _ in range(5):
        storage.record_feedback("fp_same", "mute", repo=repo)

    rows = storage.list_repo_memory(repo)
    assert len(rows) == 1
    assert rows[0]["path_pattern"] == "fingerprint:fp_same"
    assert rows[0]["note"] == "Muted finding fp_same"


# ------------------------------------------------------- memory endpoint (D3)
def _memory_app(monkeypatch, tmp_path, storage):
    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dashboard_app, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(dashboard_app, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(dashboard_app, "_storage", storage)
    monkeypatch.setattr(dashboard_app, "_api_token", "test-token")
    return {"X-Dashboard-Token": "test-token"}


def test_memory_endpoint_returns_real_path_patterns(monkeypatch, tmp_path):
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    storage.add_repo_memory("acme/widgets", "src/*.py", "scoped note")
    storage.record_feedback("fp123", "mute", repo="acme/widgets")
    headers = _memory_app(monkeypatch, tmp_path, storage)

    with TestClient(dashboard_app.app) as client:
        rows = client.get("/api/repos/acme/widgets/memory",
                          headers=headers).json()["memory"]
        filtered = client.get("/api/repos/acme/widgets/memory",
                              params=[("paths", "src/app.py")],
                              headers=headers).json()["memory"]

    by_pattern = {r["path_pattern"]: r["note"] for r in rows}
    assert by_pattern == {"src/*.py": "scoped note",
                          "fingerprint:fp123": "Muted finding fp123"}
    # ?paths= filters on each row's own pattern — the reviewer's client
    # splits note rows from mute rows itself.
    assert [r["path_pattern"] for r in filtered] == ["src/*.py"]


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


# ------------------------------------------------- V3-E02-T04 · telemetry rows
def _tel_row(state="ok", in_tok=100, out_tok=50, call_ms=1000,
             provider="claude"):
    return {
        "schema": 1, "provider": provider, "model": "claude-sonnet-4-6",
        "batch_count": 1, "fallback_used": False,
        "usage": {"provider": provider, "model": "claude-sonnet-4-6",
                  "input_tokens": in_tok, "output_tokens": out_tok,
                  "duration_ms": call_ms, "state": state},
        "calls": [], "events": [],
    }


def test_t04_db_telemetry_round_trip(db_storage):
    """T04 acceptance: telemetry round-trips through DbStorage — save then
    get returns the row; re-saving the same review id upserts."""
    rid = "acme/widgets#7@sha_1"
    db_storage.save_telemetry(rid, _tel_row())

    got = db_storage.get_telemetry(rid)
    assert got is not None and got["usage"]["input_tokens"] == 100
    assert got["provider"] == "claude"

    db_storage.save_telemetry(rid, _tel_row(in_tok=42))
    assert db_storage.get_telemetry(rid)["usage"]["input_tokens"] == 42
    # upsert, not stack: metrics sees one run for this review
    assert db_storage.metrics()["telemetry"]["runs"] == 1


def test_t04_json_telemetry_round_trip(tmp_path):
    """T04 acceptance: same round-trip on the JSON backend."""
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    rid = "acme/orders#99@sha_9"
    storage.save_telemetry(rid, _tel_row())

    got = storage.get_telemetry(rid)
    assert got is not None and got["usage"]["input_tokens"] == 100
    assert got["repo"] == "acme/orders"          # id parsed for aggregates

    storage.save_telemetry(rid, _tel_row(in_tok=42))
    assert storage.get_telemetry(rid)["usage"]["input_tokens"] == 42


def test_t04_missing_telemetry_reads_none_on_both_backends(db_storage, tmp_path):
    """T04 acceptance: missing-telemetry rows don't break reads."""
    json_storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    json_storage.init()

    assert db_storage.get_telemetry("acme/widgets#7@absent") is None
    assert json_storage.get_telemetry("acme/widgets#7@absent") is None


# ------------------------------------------------- V3-E02-T05 · metrics API
_LEGACY_METRIC_KEYS = {"reviews_total", "fallback_rate", "avg_duration_s",
                       "avg_health_score", "severity_distribution",
                       "engine_distribution"}


def _seed_telemetry(storage):
    storage.save_telemetry("acme/widgets#7@a", _tel_row(in_tok=100, out_tok=50,
                                                        call_ms=1000))
    storage.save_telemetry("acme/widgets#8@b", _tel_row(in_tok=200, out_tok=25,
                                                        call_ms=3000))
    storage.save_telemetry("acme/other#1@c",
                           _tel_row(state="unavailable", in_tok=None,
                                    out_tok=None, call_ms=500))


def _assert_telemetry_series(m):
    tel = m["telemetry"]
    assert tel["runs"] == 3
    assert tel["tokens"] == {"input": 300, "output": 75}
    assert tel["usage_states"] == {"ok": 2, "unavailable": 1, "n/a": 0}
    assert tel["avg_call_ms"] == 1500.0
    assert tel["by_repo"]["acme/widgets"] == {"runs": 2, "input_tokens": 300,
                                              "output_tokens": 75,
                                              "call_ms": 4000}
    assert tel["by_repo"]["acme/other"]["runs"] == 1
    assert tel["by_repo"]["acme/other"]["input_tokens"] == 0   # unavailable


def test_t05_db_metrics_expose_telemetry_series_additively(db_storage):
    """T05 acceptance: telemetry series from seeded data, and the legacy
    metric fields are unchanged — the block is purely additive."""
    db_storage.upsert(_report())
    _seed_telemetry(db_storage)

    m = db_storage.metrics()

    assert set(m) == _LEGACY_METRIC_KEYS | {"telemetry"}   # no old key lost
    assert m["reviews_total"] == 1                          # old values intact
    assert m["severity_distribution"]["critical"] == 1
    _assert_telemetry_series(m)


def test_t05_json_metrics_expose_telemetry_series_additively(tmp_path):
    """T05 acceptance: parity for the JSON backend."""
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    storage.upsert(_report())
    _seed_telemetry(storage)

    m = storage.metrics()

    assert set(m) == _LEGACY_METRIC_KEYS | {"telemetry"}
    assert m["reviews_total"] == 1
    _assert_telemetry_series(m)


def test_t05_metrics_without_telemetry_keep_every_old_field(db_storage):
    """T05 acceptance: old consumers see unchanged old fields — a database
    with reports but zero telemetry rows yields a zero series, not an
    error, and all legacy keys are present with their normal values."""
    db_storage.upsert(_report())

    m = db_storage.metrics()

    assert set(m) == _LEGACY_METRIC_KEYS | {"telemetry"}
    assert m["reviews_total"] == 1
    tel = m["telemetry"]
    assert tel["runs"] == 0
    assert tel["tokens"] == {"input": 0, "output": 0}
    assert tel["usage_states"] == {"ok": 0, "unavailable": 0, "n/a": 0}
    assert tel["avg_call_ms"] == 0.0 and tel["by_repo"] == {}


def test_t05_metrics_endpoint_serves_telemetry_series(monkeypatch, tmp_path, db_storage):
    """T05 acceptance: GET /api/metrics returns the telemetry series from
    seeded data under the endpoint's existing auth posture (rate-limit and
    token handling untouched)."""
    db_storage.upsert(_report())
    _seed_telemetry(db_storage)
    headers = _memory_app(monkeypatch, tmp_path, db_storage)

    with TestClient(dashboard_app.app) as client:
        response = client.get("/api/metrics", headers=headers)

    assert response.status_code == 200
    m = response.json()
    assert set(m) == _LEGACY_METRIC_KEYS | {"telemetry"}
    _assert_telemetry_series(m)


# -------------------------------------- V3-E04-T04 · declared capabilities
def test_e04_t04_dashboard_backends_declare_full_capability_set(db_storage, tmp_path):
    """Both dashboard storage backends declare the full engine-facing
    contract: core protocol + both formerly-undeclared capabilities +
    telemetry + pruning."""
    from ai_pr_reviewer.storage_schema import (CAP_DISMISSED_FINGERPRINTS,
                                               CAP_LIST_REPO_MEMORY,
                                               CAP_PRUNE, CAP_TELEMETRY,
                                               CORE_CAPABILITIES)

    json_storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    for storage in (db_storage, json_storage):
        assert CORE_CAPABILITIES <= storage.capabilities, storage
        assert CAP_LIST_REPO_MEMORY in storage.capabilities, storage
        assert CAP_DISMISSED_FINGERPRINTS in storage.capabilities, storage
        assert CAP_TELEMETRY in storage.capabilities, storage
        assert CAP_PRUNE in storage.capabilities, storage


def test_e04_t04_db_get_dismissed_fingerprints_reads_mute_rows(db_storage):
    """The new reader pairs with record_feedback: mute rows come back as
    fingerprints; plain notes, disabled rows and other repos never do."""
    db_storage.add_repo_memory("acme/widgets", "*.py", "a plain note")
    db_storage.add_repo_memory("acme/widgets", "src/*", "disabled note",
                               enabled=False)
    db_storage.record_feedback("fp_a", "mute", repo="acme/widgets")
    db_storage.record_feedback("fp_b", "mute", repo="acme/widgets")
    db_storage.record_feedback("fp_other", "mute", repo="acme/other")
    db_storage.record_feedback("fp_up", "up", repo="acme/widgets")  # not a mute

    assert db_storage.get_dismissed_fingerprints("acme/widgets") == {"fp_a", "fp_b"}
    assert db_storage.get_dismissed_fingerprints("acme/other") == {"fp_other"}
    assert db_storage.get_dismissed_fingerprints("acme/none") == set()


def test_e04_t04_json_get_dismissed_fingerprints_reads_mute_rows(tmp_path):
    """Identical behavior on the JSON backend (T07 parity seeds)."""
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.add_repo_memory("acme/widgets", "*.py", "a plain note")
    storage.record_feedback("fp_a", "mute", repo="acme/widgets")
    storage.record_feedback("fp_b", "mute", repo="acme/widgets")
    storage.record_feedback("fp_other", "mute", repo="acme/other")
    storage.record_feedback("fp_up", "up", repo="acme/widgets")  # not a mute

    assert storage.get_dismissed_fingerprints("acme/widgets") == {"fp_a", "fp_b"}
    assert storage.get_dismissed_fingerprints("acme/other") == {"fp_other"}
    assert storage.get_dismissed_fingerprints("acme/none") == set()


# -------------------------------------- V3-E04-T02 · retention (dashboard)
_T02_OLD = "2020-01-01T00:00:00+00:00"
_T02_NOW = datetime(2026, 10, 6, 12, 0, 0, tzinfo=timezone.utc)


def _hist(fp: str) -> dict:
    return {"fingerprint": fp, "file": "a.py", "line": 1, "severity": "high",
            "category": "bug", "title": "t", "state": "new"}


def test_e04_t02_db_prune_follows_shared_policy(db_storage):
    """The SQL backend enforces the engine's exact policy: aged history
    goes only when its PR's review state exists and is itself stale;
    stateless history, fresh rows, memory, review states and reports all
    survive; dry-run counts match the real pass; a rerun finds nothing."""
    from sqlalchemy import text

    st = db_storage
    st.set_last_reviewed_sha("a/b", 1, "sha1")            # stale below
    st.save_findings("a/b#1@sha1", [_hist("fp_stale")])
    st.set_last_reviewed_sha("a/b", 2, "sha2")            # fresh state
    st.save_findings("a/b#2@sha2", [_hist("fp_active")])
    st.save_findings("a/b#3@sha3", [_hist("fp_orphan")])  # no state row
    st.save_telemetry("a/b#1@sha1", _tel_row())           # stale below
    st.save_telemetry("a/b#4@sha4", _tel_row())           # fresh
    st.add_repo_memory("a/b", "*.py", "a note")
    st.upsert(_report())

    with st.engine.begin() as conn:
        conn.execute(text("UPDATE finding_histories SET updated_at=:t "
                          "WHERE pr_number IN (1, 3)"), {"t": _T02_OLD})
        conn.execute(text("UPDATE review_states SET updated_at=:t "
                          "WHERE pr_number = 1"), {"t": _T02_OLD})
        conn.execute(text("UPDATE telemetry SET updated_at=:t "
                          "WHERE id = 'a/b#1@sha1'"), {"t": _T02_OLD})
        conn.execute(text("UPDATE repo_memories SET updated_at=:t "
                          "WHERE repo = 'a/b'"), {"t": _T02_OLD})

    dry = st.prune(30, now=_T02_NOW, dry_run=True)
    assert dry["enabled"] is True and dry["dry_run"] is True
    assert dry["cutoff"] == "2026-09-06T12:00:00+00:00"
    assert (dry["finding_history"], dry["telemetry"]) == (1, 1)
    assert len(st.get_previous_findings("a/b", 1)) == 1   # nothing deleted

    out = st.prune(30, now=_T02_NOW)
    assert (out["finding_history"], out["telemetry"]) == (1, 1)
    assert st.get_previous_findings("a/b", 1) == []       # stale history gone
    assert len(st.get_previous_findings("a/b", 2)) == 1   # active state keeps
    assert len(st.get_previous_findings("a/b", 3)) == 1   # unknown state keeps
    assert st.get_telemetry("a/b#1@sha1") is None
    assert st.get_telemetry("a/b#4@sha4") is not None
    assert len(st.list_repo_memory("a/b")) == 1           # memory never pruned

    with st.engine.connect() as conn:
        states = conn.execute(text("SELECT COUNT(*) FROM review_states")
                              ).scalar()
    assert states == 2                                     # states never pruned
    assert st.get(_report()["id"]) is not None             # reports untouched

    again = st.prune(30, now=_T02_NOW)                     # idempotent
    assert again["finding_history"] == 0 and again["telemetry"] == 0


def test_e04_t02_db_prune_disabled_keeps_everything(db_storage):
    """Default-off parity: prune(0) and prune(<0) delete nothing."""
    from sqlalchemy import text

    st = db_storage
    st.set_last_reviewed_sha("a/b", 1, "sha1")
    st.save_findings("a/b#1@sha1", [_hist("fp1")])
    st.save_telemetry("a/b#1@sha1", _tel_row())
    with st.engine.begin() as conn:
        conn.execute(text("UPDATE finding_histories SET updated_at=:t"),
                     {"t": _T02_OLD})
        conn.execute(text("UPDATE telemetry SET updated_at=:t"),
                     {"t": _T02_OLD})

    for days in (0, -1):
        out = st.prune(days, now=_T02_NOW)
        assert out == {"enabled": False, "cutoff": None, "dry_run": False,
                       "finding_history": 0, "telemetry": 0}
    assert len(st.get_previous_findings("a/b", 1)) == 1
    assert st.get_telemetry("a/b#1@sha1") is not None


def test_e04_t02_json_prune_follows_shared_policy(tmp_path):
    """The JSON backend applies the same policy at file granularity:
    a findings file goes only when the file and its PR's review state are
    both positively-known-stale; memory, states, reports and fresh
    telemetry survive; rerun finds nothing."""
    import json
    import os

    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()

    storage.set_last_reviewed_sha("a/b", 1, "sha1")            # stale below
    storage.save_findings("a/b#1@sha1", [_hist("fp_stale")])
    storage.set_last_reviewed_sha("a/b", 2, "sha2")            # fresh state
    storage.save_findings("a/b#2@sha2", [_hist("fp_active")])
    storage.save_findings("a/b#3@sha3", [_hist("fp_orphan")])  # no state row
    storage.save_telemetry("a/b#1@sha1", _tel_row())           # stale below
    storage.save_telemetry("a/b#4@sha4", _tel_row())           # fresh
    storage.add_repo_memory("a/b", "*.py", "a note")
    storage.upsert(_report())

    # age PR 1's state, PR 1's telemetry row, and every findings file
    state_path = tmp_path / "reviews_state.json"
    states = json.loads(state_path.read_text(encoding="utf-8"))
    states["a/b#1"]["updated_at"] = _T02_OLD
    state_path.write_text(json.dumps(states), encoding="utf-8")

    tel_path = tmp_path / "telemetry.json"
    tel = json.loads(tel_path.read_text(encoding="utf-8"))
    for row in tel:
        if row.get("id") == "a/b#1@sha1":
            row["updated_at"] = _T02_OLD
    tel_path.write_text(json.dumps(tel), encoding="utf-8")

    old_epoch = datetime(2020, 1, 1, tzinfo=timezone.utc).timestamp()
    findings_dir = tmp_path / "findings"
    for name in ("a-b_1.json", "a-b_2.json", "a-b_3.json"):
        os.utime(findings_dir / name, (old_epoch, old_epoch))

    dry = storage.prune(30, now=_T02_NOW, dry_run=True)
    assert (dry["finding_history"], dry["telemetry"]) == (1, 1)
    assert (findings_dir / "a-b_1.json").exists()            # dry run keeps
    assert storage.get_telemetry("a/b#1@sha1") is not None

    out = storage.prune(30, now=_T02_NOW)
    assert (out["finding_history"], out["telemetry"]) == (1, 1)
    assert not (findings_dir / "a-b_1.json").exists()        # stale, known
    assert (findings_dir / "a-b_2.json").exists()            # active state
    assert (findings_dir / "a-b_3.json").exists()            # unknown state
    assert storage.get_telemetry("a/b#1@sha1") is None
    assert storage.get_telemetry("a/b#4@sha4") is not None
    assert len(storage.list_repo_memory("a/b")) == 1         # memory kept
    assert storage.get(_report()["id"]) is not None          # reports kept
    kept_states = json.loads(state_path.read_text(encoding="utf-8"))
    assert set(kept_states) == {"a/b#1", "a/b#2"}            # states kept

    again = storage.prune(30, now=_T02_NOW)                  # idempotent
    assert again["finding_history"] == 0 and again["telemetry"] == 0


def test_e04_t02_retention_env_parsing(monkeypatch):
    """DASHBOARD_RETENTION_DAYS overrides the plain env var; garbage
    disables retention with a notice instead of crashing a dashboard."""
    monkeypatch.delenv("DASHBOARD_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("RETENTION_DAYS", raising=False)
    assert dashboard_app._retention_days() == 0

    monkeypatch.setenv("RETENTION_DAYS", "30")
    assert dashboard_app._retention_days() == 30

    monkeypatch.setenv("DASHBOARD_RETENTION_DAYS", "7")
    assert dashboard_app._retention_days() == 7

    monkeypatch.setenv("DASHBOARD_RETENTION_DAYS", "soon")
    assert dashboard_app._retention_days() == 0


def test_e04_t02_startup_hook_prunes_when_configured(monkeypatch, db_storage):
    """The lifespan retention pass: silent when unconfigured, one pass
    over the active storage when the env knob is set."""
    from sqlalchemy import text

    monkeypatch.setattr(dashboard_app, "_storage", db_storage)
    monkeypatch.delenv("DASHBOARD_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("RETENTION_DAYS", raising=False)
    dashboard_app._retention_prune()                        # unconfigured → no-op

    db_storage.set_last_reviewed_sha("a/b", 1, "sha1")
    db_storage.save_findings("a/b#1@sha1", [_hist("fp1")])
    with db_storage.engine.begin() as conn:
        conn.execute(text("UPDATE finding_histories SET updated_at=:t"),
                     {"t": _T02_OLD})
        conn.execute(text("UPDATE review_states SET updated_at=:t"),
                     {"t": _T02_OLD})
    assert len(db_storage.get_previous_findings("a/b", 1)) == 1

    monkeypatch.setenv("DASHBOARD_RETENTION_DAYS", "30")
    dashboard_app._retention_prune()

    assert db_storage.get_previous_findings("a/b", 1) == []  # pruned once


# -------------------------------------- V3-E04-T05 · bounded dashboard reads
def _t05_reports() -> list[dict]:
    """Two reports spanning both backends' aggregate paths: distinct
    engines, a fallback run, two health scores, and category/severity
    ties whose order the golden pins to the deterministic rule."""
    r1 = {**_report(repo="acme/widgets", number=7), "duration_ms": 4000,
          "engine": "static", "health_score": 95}
    r2 = {**_report(repo="acme/other", number=1), "duration_ms": 2000,
          "reviewed_at": "2026-09-20T00:00:00Z",
          "engine": "claude", "fallback_used": True, "health_score": 88,
          "stats": {"files": 1, "additions": 5, "deletions": 0, "hunks": 1},
          "findings": [
              {"file": "c.py", "line": 1, "severity": "medium",
               "category": "bug", "title": "t4", "explanation": "e",
               "confidence": "medium"},
              {"file": "d.py", "line": 2, "severity": "medium",
               "category": "bug", "title": "t5", "explanation": "e",
               "confidence": "low"},
          ]}
    return [r1, r2]


def _t05_seed_telemetry(storage):
    storage.save_telemetry("acme/widgets#7@a",
                           _tel_row(in_tok=100, out_tok=50, call_ms=1000))
    storage.save_telemetry("acme/other#1@c",
                           _tel_row(state="unavailable", in_tok=None,
                                    out_tok=None, call_ms=500))


def _t05_golden_stats() -> dict:
    return {
        "reports": 2, "findings": 5,
        "by_severity": {"critical": 1, "high": 1, "medium": 2,
                        "low": 1, "info": 0},
        # bug(3) first; security/style tie broken key-ascending — the
        # deterministic rule both backends now share (was: first-seen).
        "by_category": {"bug": 3, "security": 1, "style": 1},
        # widgets/other tie broken key-ascending as well
        "top_repos": {"acme/other": 1, "acme/widgets": 1},
        "files_analyzed": 3,
    }


def _t05_golden_metrics() -> dict:
    return {
        "reviews_total": 2,
        "fallback_rate": 50.0,          # 1 of 2 runs fell back
        "avg_duration_s": 3.0,          # (4000 + 2000) / 2
        "avg_health_score": 91.5,       # (95 + 88) / 2
        "severity_distribution": {"critical": 1, "high": 1, "medium": 2,
                                  "low": 1, "info": 0},
        "engine_distribution": {"claude": 1, "static": 1},  # key-asc tie
        "telemetry": {
            "runs": 2,
            "tokens": {"input": 100, "output": 50},
            "usage_states": {"ok": 1, "unavailable": 1, "n/a": 0},
            "avg_call_ms": 750.0,       # (1000 + 500) / 2
            "by_repo": {
                "acme/widgets": {"runs": 1, "input_tokens": 100,
                                 "output_tokens": 50, "call_ms": 1000},
                "acme/other": {"runs": 1, "input_tokens": 0,
                               "output_tokens": 0, "call_ms": 500},
            },
        },
    }


def test_t05_backends_aggregate_identically_with_pinned_golden(db_storage,
                                                                tmp_path):
    """T05 snapshot: SQL aggregation returns the exact pre-T05 values
    (pinned golden) and matches the JSON backend dict-for-dict — stats,
    metrics and the additive telemetry block alike."""
    json_storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    json_storage.init()
    for report in _t05_reports():
        db_storage.upsert(report)
        json_storage.upsert(report)
    _t05_seed_telemetry(db_storage)
    _t05_seed_telemetry(json_storage)

    assert db_storage.stats() == _t05_golden_stats()
    assert json_storage.stats() == _t05_golden_stats()
    assert db_storage.stats() == json_storage.stats()

    assert db_storage.metrics() == _t05_golden_metrics()
    assert json_storage.metrics() == _t05_golden_metrics()
    assert db_storage.metrics() == json_storage.metrics()


def test_t05_db_list_findings_pages_match_single_window(db_storage):
    """Paging is additive: page requests concatenate to the single
    unbounded window, the repo pushdown equals a client-side filter of
    it, and degenerate windows (limit 0, negative offset) are clamped."""
    for i in range(6):
        db_storage.upsert(_report(
            repo="acme/widgets" if i % 2 else "acme/other",
            number=100 + i))

    full = db_storage.list_findings(limit=100, offset=0)
    assert len(full) == 18                      # 6 reports x 3 findings

    pages = [db_storage.list_findings(limit=7, offset=o)
             for o in (0, 7, 14)]
    assert pages[0] + pages[1] + pages[2] == full

    only = db_storage.list_findings(repo="acme/widgets", limit=100)
    assert only == [f for f in full if f["repo"] == "acme/widgets"]
    assert only and all(f["repo"] == "acme/widgets" for f in only)

    assert db_storage.list_findings(severity="critical",
                                    limit=100) == [
        f for f in full if f.get("severity") == "critical"]
    assert db_storage.list_findings(state="new", limit=100) == full
    assert db_storage.list_findings(limit=0) == []
    assert db_storage.list_findings(limit=5, offset=-3) == full[:5]


def test_t05_json_list_findings_pages_match_single_window(tmp_path):
    """The JSON backend keeps the same window semantics after its
    early-stop optimization (file granularity accepted deviation)."""
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    for i in range(6):
        storage.upsert(_report(
            repo="acme/widgets" if i % 2 else "acme/other",
            number=100 + i))

    # mtime ordering differs from the DB's reviewed_at ordering, so the
    # invariants asserted here are the window properties, not a specific
    # report order: page concatenation and filter consistency.
    full = storage.list_findings(limit=100, offset=0)
    assert len(full) == 18
    pages = [storage.list_findings(limit=7, offset=o) for o in (0, 7, 14)]
    assert pages[0] + pages[1] + pages[2] == full

    only = storage.list_findings(repo="acme/widgets", limit=100)
    assert only == [f for f in full if f["repo"] == "acme/widgets"]
    assert storage.list_findings(limit=0) == []
    assert storage.list_findings(limit=5, offset=-3) == full[:5]


def test_t05_aggregate_reads_load_no_report_objects(db_storage):
    """Row-count acceptance: stats() and metrics() materialize zero
    ReportRow instances; list()/list_findings() load at most the window
    they were asked for — never the whole table."""
    from sqlalchemy import event

    from dashboard.models_db import ReportRow

    for i in range(50):
        db_storage.upsert(_report(repo="acme/widgets" if i else "acme/other",
                                  number=1000 + i))
    _t05_seed_telemetry(db_storage)

    loads: list = []

    def _on_load(instance, context):
        loads.append(1)

    event.listen(ReportRow, "load", _on_load)
    try:
        loads.clear()
        db_storage.stats()
        stats_loads = len(loads)
        loads.clear()
        db_storage.metrics()
        metrics_loads = len(loads)
        loads.clear()
        db_storage.list(limit=10, offset=0)
        list_loads = len(loads)
        loads.clear()
        db_storage.list_findings(limit=20, offset=0, repo="acme/widgets")
        findings_loads = len(loads)
    finally:
        event.remove(ReportRow, "load", _on_load)

    assert stats_loads == 0        # aggregates never touch an object
    assert metrics_loads == 0
    assert list_loads <= 10        # paged reads touch the page only
    # bounded by the window (20 findings => 7 reports scanned, fetched in
    # one yield_per batch of min(need, 64) = 20 rows), not by the 49
    # stored reports the old implementation loaded.
    assert 0 < findings_loads <= 20


def test_t05_50k_rows_serve_paged_queries_under_proposed_baseline(tmp_path):
    """T05 acceptance: a 50k-row fixture answers paged reads within the
    proposed baseline (< 500 ms per call — proposed, not a contractual
    SLA); aggregates are gated on materializing zero rows (see below)
    plus a gross-regression ceiling. Seeds via bulk INSERT, not upsert,
    to keep fixture build out of the measurement."""
    import time

    from sqlalchemy import insert, text

    from dashboard.models_db import ReportRow, TelemetryRow

    storage = DbStorage(f"sqlite:///{tmp_path / 'big.db'}")
    storage.init()

    findings_payload = [
        {"file": f"f{i}.py", "line": i, "severity": "medium",
         "category": "bug", "title": f"t{i}", "state": "new",
         "explanation": "e"} for i in range(5)]
    report_rows = [{
        "id": f"r{i}", "repo": f"acme/pkg{i % 7}", "pr_number": i,
        "pr_title": "t", "author": "a", "branch": "b", "mode": "static",
        "model": "static-rules-v1",
        "reviewed_at": f"2026-09-{1 + (i % 28):02d}T00:00:00Z",
        "duration_ms": 100, "files": 1, "additions": 1, "deletions": 0,
        "findings_count": 5, "truncated": False,
        # sparse, as upsert now writes it (V3-E04-T05)
        "severity_counts": {"medium": 5},
        "categories": {"bug": 5}, "engine": "static", "fallback_used": 0,
        "health_score": 100, "payload": {"findings": findings_payload},
    } for i in range(50_000)]
    tel_rows = [{
        "id": f"t{i}", "repo": f"acme/pkg{i % 7}", "pr_number": i,
        "provider": "static", "model": "static-rules-v1",
        "input_tokens": 100 if i % 3 else None,
        "output_tokens": 20 if i % 3 else None,
        "usage_state": "ok" if i % 3 else "unavailable",
        "batch_count": 1, "fallback_used": 0,
        "call_ms": 500 if i % 3 else None,
        "updated_at": "2026-09-01T00:00:00+00:00", "payload": {},
    } for i in range(5_000)]
    with storage.engine.begin() as conn:
        # Fixture durability is irrelevant — dropping the commit fsync
        # keeps the seed out of the test's critical path on slow disks
        # (18 s -> ~7 s here); production init() leaves synchronous alone.
        conn.execute(text("PRAGMA synchronous=OFF"))
        conn.execute(insert(ReportRow), report_rows)
        conn.execute(insert(TelemetryRow), tel_rows)

    import gc
    gc.collect()                          # fixture churn out of the timing

    def timed(label, fn, baseline, runs=3):
        """Min-of-N wall time: the minimum suppresses scheduler noise on
        loaded machines (a single shot can spike 5-10x), while any
        algorithmic regression shows up in every run."""
        best, out = None, None
        for _ in range(runs):
            t0 = time.perf_counter()
            result = fn()
            ms = (time.perf_counter() - t0) * 1000
            best = ms if best is None else min(best, ms)
            out = result
        print(f"    {label}: {best:.0f} ms (baseline {baseline})")
        assert best < baseline, \
            f"{label} took {best:.0f} ms (baseline <{baseline} ms)"
        return out

    # Paged queries carry the ticket's proposed baseline (proposed, not a
    # contractual SLA): pages stay far under 500 ms at 50k rows.
    page = timed("list(offset=1000)",
                 lambda: storage.list(limit=20, offset=1000), 500)
    assert len(page) == 20
    findings_page = timed("list_findings(limit=100)",
                          lambda: storage.list_findings(limit=100, offset=0),
                          500)
    assert len(findings_page) == 100

    # Aggregates do one table walk per count-map (bounded, DB-side). The
    # ticket sets no time baseline for them — the row-count assertion
    # below is the acceptance gate ("aggregation moves into the DB"), and
    # this generous ceiling is only a gross-regression detector: the
    # pre-T05 pass materialized every report (>4 s at 50k rows), which
    # trips it and the loads assertion alike. Runs=2 keeps the test fast.
    from sqlalchemy import event
    from dashboard.models_db import ReportRow as _ReportRow

    loads: list = []

    def _on_load(instance, context):
        loads.append(1)

    event.listen(_ReportRow, "load", _on_load)
    try:
        stats = timed("stats", storage.stats, 3000, runs=2)
        metrics = timed("metrics", storage.metrics, 3000, runs=2)
    finally:
        event.remove(_ReportRow, "load", _on_load)
    # row-count test: aggregates materialize nothing
    assert len(loads) == 0

    assert stats["reports"] == 50_000 and stats["findings"] == 250_000
    assert metrics["reviews_total"] == 50_000
    assert metrics["telemetry"]["runs"] == 5_000


def test_t05_report_metric_columns_backfilled_from_legacy_payload(tmp_path):
    """A pre-T05 database gains the metric columns and a one-time
    payload-derived backfill — so metrics() reports exactly what the
    payload-based implementation reported before the upgrade (an old
    claude/fallback run does not become static/0/100). Re-init is a
    no-op: the columns exist, so nothing is re-derived."""
    import json

    from sqlalchemy import create_engine, text

    dsn = f"sqlite:///{tmp_path / 'legacy.db'}"
    engine = create_engine(dsn)
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE reports (
            id VARCHAR(140) NOT NULL PRIMARY KEY,
            repo VARCHAR(200), pr_number INTEGER, pr_title VARCHAR(300),
            author VARCHAR(100), branch VARCHAR(200), mode VARCHAR(40),
            model VARCHAR(100), reviewed_at VARCHAR(32), duration_ms INTEGER,
            files INTEGER, additions INTEGER, deletions INTEGER,
            findings_count INTEGER, truncated BOOLEAN,
            severity_counts JSON, categories JSON, payload JSON)"""))
        conn.execute(text(
            "INSERT INTO reports (id, repo, pr_number, duration_ms,"
            " findings_count, payload) VALUES"
            " ('legacy-1', 'acme/old', 3, 4000, 1, :payload)"),
            {"payload": json.dumps({
                "engine": "claude", "fallback_used": True,
                "health_score": 88, "findings": [
                    {"file": "a.py", "line": 1, "severity": "high",
                     "category": "bug", "title": "t"}]})})
    engine.dispose()

    storage = DbStorage(dsn)
    storage.init()

    with storage.engine.connect() as conn:
        row = conn.execute(text(
            "SELECT engine, fallback_used, health_score FROM reports"
            " WHERE id = 'legacy-1'")).fetchone()
    assert (row.engine, row.fallback_used, row.health_score) == \
        ("claude", 1, 88.0)              # derived, not the ALTER defaults

    metrics = storage.metrics()
    assert metrics["engine_distribution"] == {"claude": 1}
    assert metrics["fallback_rate"] == 100.0
    assert metrics["avg_health_score"] == 88.0
    assert metrics["avg_duration_s"] == 4.0

    storage.init()                        # second run: no ALTER, no rewrite
    with storage.engine.connect() as conn:
        again = conn.execute(text(
            "SELECT engine, health_score FROM reports"
            " WHERE id = 'legacy-1'")).fetchone()
    assert (again.engine, again.health_score) == ("claude", 88.0)


def test_t05_composite_history_index_created_on_fresh_and_legacy_dbs(tmp_path):
    """The (repo, pr_number) index exists on a fresh database (model
    declaration) and is added to a database that predates it."""
    from sqlalchemy import create_engine, inspect, text

    fresh = DbStorage(f"sqlite:///{tmp_path / 'fresh.db'}")
    fresh.init()

    legacy_dsn = f"sqlite:///{tmp_path / 'legacy_ix.db'}"
    engine = create_engine(legacy_dsn)
    with engine.begin() as conn:
        conn.execute(text("""CREATE TABLE finding_histories (
            id VARCHAR(300) NOT NULL PRIMARY KEY,
            repo VARCHAR(200), pr_number INTEGER, fingerprint VARCHAR(64),
            state VARCHAR(32), first_seen_sha VARCHAR(40),
            last_seen_sha VARCHAR(40), resolved_at VARCHAR(32),
            payload JSON, updated_at VARCHAR(32))"""))
        conn.execute(text(
            "INSERT INTO finding_histories (id, repo, pr_number,"
            " fingerprint) VALUES ('k', 'acme/x', 1, 'fp')"))
    engine.dispose()
    legacy = DbStorage(legacy_dsn)
    legacy.init()

    for storage in (fresh, legacy):
        indexes = inspect(storage.engine).get_indexes("finding_histories")
        assert any(ix["column_names"] == ["repo", "pr_number"]
                   for ix in indexes), storage.backend


def test_t05_json_expansion_falls_back_to_light_column(db_storage,
                                                        monkeypatch):
    """A dialect without server-side JSON expansion (or a failing
    json_each) degrades to reading only the light count-map column —
    aggregates stay byte-identical either way."""
    from dashboard import storage as dash_storage

    for report in _t05_reports():
        db_storage.upsert(report)
    _t05_seed_telemetry(db_storage)
    with_expansion = {"stats": db_storage.stats(),
                      "metrics": db_storage.metrics()}

    calls: list = []

    def _no_expansion(dialect, table, column):
        calls.append((dialect, table, column))
        return None

    monkeypatch.setattr(dash_storage, "_json_sum_sql", _no_expansion)

    assert db_storage.stats() == with_expansion["stats"]
    assert db_storage.metrics() == with_expansion["metrics"]
    assert calls, "the fallback path was never exercised (vacuous test)"
    assert {c[1] for c in calls} == {"reports"}

