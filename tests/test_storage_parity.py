"""V3-E04-T07 — backend parity: one suite, every storage backend.

Drives the same lifecycle through ``LocalReviewStorage`` (engine SQLite),
``DbStorage`` (dashboard SQL), ``JsonStorage`` (dashboard JSON files) and
``DashboardStorageClient`` (the engine's HTTP client against the real
FastAPI app over ASGI — offline, no sockets), and asserts the results are
identical. The HTTP param is the previously third-path: an engine
configured with ``dashboard_url`` must observe the same protocol contract
as a local file, or reviews silently diverge depending on deployment.

Accepted deviations (parity compares past these, on purpose):

* **Return types** — ``get_previous_findings`` yields ``Finding`` objects
  through the engine paths (local, HTTP) and raw payload dicts through the
  dashboard backends (the HTTP wire format is JSON). Parity compares
  engine-normalized views: ``Finding.from_dict(d).to_dict()``.
* **Row order is not part of the contract** — the SQL backends issue no
  ``ORDER BY`` on memory/finding lists (Postgres would happily reorder);
  every comparison here is order-independent.
* **``id`` on dashboard memory rows** — the local backend's rows carry no
  row id; the id is dashboard-UI metadata. Parity projects
  ``{path_pattern, note, category, enabled}`` for every row.
* **Json telemetry rows** wrap the sanitized payload in storage metadata
  (``id``/``repo``/``pr_number``/``updated_at``); parity compares payload
  fields.
* **HTTP declares no ``save_telemetry``/``prune`` capability** — the
  engine never writes telemetry to, or deletes data from, the dashboard
  remotely (T04). It also adds token auth: without a token, reads degrade
  to empty with a logged warning (fail-closed) instead of raising.
* **Mute rows are written by tests through the same row shape on every
  backend** (``record_feedback``'s production path is covered by
  ``test_dashboard_storage.py``); here both the note and the category are
  seeded explicitly so projections compare byte-for-byte.

Two parity gaps this suite caught during implementation (both fixed, in
the spirit of "file real bugs separately"): the local backend mutated the
caller's dict when injecting a computed fingerprint, and the JSON backend
stored fingerprint-less findings without a fingerprint at all while the DB
backend computed one.
"""
from __future__ import annotations

import contextlib
import sqlite3
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard.app as dashboard_app
from ai_pr_reviewer.models import Finding
from ai_pr_reviewer.storage import (
    DashboardStorageClient,
    LocalReviewStorage,
    has_capability,
)
from ai_pr_reviewer.storage_schema import (
    CAP_DISMISSED_FINGERPRINTS,
    CAP_LIST_REPO_MEMORY,
    CAP_PRUNE,
    CAP_TELEMETRY,
    CORE_CAPABILITIES,
    format_review_id,
    mute_pattern,
)
from dashboard.storage import DbStorage, JsonStorage

BACKENDS = ["local", "db", "json", "http"]
REPO = "acme/widgets"
PR = 42
REVIEW_ID = format_review_id(REPO, PR, "abc123456789")


class Backend:
    """The storage under test plus the handle that owns its bytes."""

    def __init__(self, name: str, storage, raw, db_path=None):
        self.name = name
        self.storage = storage   # protocol surface under test
        self.raw = raw           # bytes owner, used only for seeding
        self.db_path = db_path   # SQLite path (local only; None otherwise)


@contextlib.contextmanager
def _open_backend(name: str, tmp_path: Path, monkeypatch):
    """Yield one backend; owns the HTTP client's lifecycle for ``http``."""
    tmp_path.mkdir(parents=True, exist_ok=True)
    if name == "local":
        db_path = tmp_path / "state.db"
        yield Backend(name, LocalReviewStorage(db_path), None, db_path=db_path)
        return
    if name == "db":
        storage = DbStorage(f"sqlite:///{tmp_path / 'd.db'}")
        storage.init()
        yield Backend(name, storage, storage)
        return
    if name == "json":
        storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
        storage.init()
        yield Backend(name, storage, storage)
        return

    # http: the real dashboard app served in-process over ASGI (offline),
    # with the engine's HTTP client pointed at it — the exact path an
    # engine uses when REVIEW_DASHBOARD_URL is configured.
    raw = DbStorage(f"sqlite:///{tmp_path / 'd.db'}")
    raw.init()
    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dashboard_app, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(dashboard_app, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(dashboard_app, "_storage", raw)
    monkeypatch.setattr(dashboard_app, "_api_token", "test-token")
    with TestClient(dashboard_app.app) as http:
        http.headers.update({"X-Dashboard-Token": "test-token"})
        client = DashboardStorageClient("http://testserver", "test-token",
                                        client=http)
        yield Backend(name, client, raw)


@pytest.fixture(params=BACKENDS)
def backend(request, tmp_path, monkeypatch):
    with _open_backend(request.param, tmp_path, monkeypatch) as opened:
        yield opened


# ------------------------------------------------------------------ seed data
def _seed_findings() -> list[dict]:
    """Two engine-normalized findings — exactly what the orchestrator saves."""
    return [
        Finding(file="src/app.py", line=10, severity="high",
                category="security", title="Hardcoded key",
                explanation="secret in source", suggestion="use env",
                confidence="high", fingerprint="fp-alpha", state="new",
                first_seen_sha="aaaa1111", last_seen_sha="bbbb2222",
                provenance_engine="static", provenance_model="static-rules-v1",
                ).to_dict(),
        Finding(file="src/util.py", line=4, severity="low", category="style",
                title="Long line", explanation="over 120 chars",
                confidence="medium", fingerprint="fp-beta", state="new",
                ).to_dict(),
    ]


def _telemetry_row(in_tok: int = 120) -> dict:
    return {
        "schema": 1, "provider": "claude", "model": "claude-sonnet-4-6",
        "batch_count": 2, "fallback_used": False,
        "usage": {"provider": "claude", "model": "claude-sonnet-4-6",
                  "input_tokens": in_tok, "output_tokens": 30,
                  "duration_ms": 1500, "state": "ok"},
        "calls": [], "events": [],
    }


def _seed_memory(backend: Backend, pattern: str, note: str, *,
                 category: str = "project-rule", enabled: bool = True) -> None:
    if backend.raw is not None:
        backend.raw.add_repo_memory(REPO, pattern, note,
                                    category=category, enabled=enabled)
        return
    # D10: the engine has no repo-memory write path at all — tests seed
    # its table directly, exactly like the engine's own tests do.
    with sqlite3.connect(backend.db_path) as conn:
        conn.execute(
            "INSERT INTO repo_memory(repo, path_pattern, note, category, enabled) "
            "VALUES (?, ?, ?, ?, ?)",
            (REPO, pattern, note, category, 1 if enabled else 0))


def _seed_mute(backend: Backend, fingerprint: str, *, enabled: bool = True) -> None:
    _seed_memory(backend, mute_pattern(fingerprint),
                 f"Muted finding {fingerprint}", enabled=enabled)


def _finding_view(items) -> list[dict]:
    """Engine-normalized, fingerprint-ordered view of get_previous_findings."""
    view = []
    for item in items:
        d = item.to_dict() if isinstance(item, Finding) else dict(item)
        view.append(Finding.from_dict(d).to_dict())
    return sorted(view, key=lambda d: d.get("fingerprint") or "")


def _memory_view(rows: list[dict]) -> dict:
    """Order-independent projection: pattern -> (note, category, enabled).

    ``id`` is deliberately dropped — dashboard-only metadata the local
    backend has no counterpart for (documented deviation above).
    """
    return {
        r["path_pattern"]: (r.get("note", ""), r.get("category") or "",
                            bool(r.get("enabled", True)))
        for r in rows if isinstance(r, dict) and r.get("path_pattern")
    }


# ------------------------------------------------------------------ capability
def test_t07_capabilities_are_core_superset_with_callable_methods(backend):
    """Declared capabilities are a real, callable superset of the core —
    and the two members T04 pulled into the contract are declared by
    every backend, while telemetry/prune stay absent over HTTP (T04)."""
    caps = backend.storage.capabilities
    assert isinstance(caps, frozenset)
    assert CORE_CAPABILITIES <= caps
    for name in caps:
        assert callable(getattr(backend.storage, name, None)), (
            f"{backend.name} declares {name} but does not provide it")
    assert CAP_LIST_REPO_MEMORY in caps
    assert CAP_DISMISSED_FINGERPRINTS in caps
    if backend.name == "http":
        assert CAP_TELEMETRY not in caps
        assert CAP_PRUNE not in caps
    else:
        assert CAP_TELEMETRY in caps
        assert CAP_PRUNE in caps


def test_t07_empty_backend_reads_are_empty(backend):
    """Fresh storage: every protocol read answers its empty value, never
    raises — the same shape on a local file and over authenticated HTTP."""
    st = backend.storage
    assert st.get_last_reviewed_sha(REPO, PR) is None
    assert st.get_previous_findings(REPO, PR) == []
    assert st.get_repo_memory(REPO, ["src/app.py"]) == []
    assert st.list_repo_memory(REPO) == []
    assert st.get_dismissed_fingerprints(REPO) == set()


# ------------------------------------------------------------------ review state
def test_t07_review_state_lifecycle(backend):
    """Missing -> None; set -> read back; overwrite wins; other PRs isolated."""
    st = backend.storage
    assert st.get_last_reviewed_sha(REPO, PR) is None

    st.set_last_reviewed_sha(REPO, PR, "sha-0001", "sha-base-0")
    assert st.get_last_reviewed_sha(REPO, PR) == "sha-0001"

    st.set_last_reviewed_sha(REPO, PR, "sha-0002", "sha-base-1")
    assert st.get_last_reviewed_sha(REPO, PR) == "sha-0002"

    assert st.get_last_reviewed_sha(REPO, PR + 1) is None
    assert st.get_last_reviewed_sha("acme/other", PR) is None


# -------------------------------------------------------------------- findings
def test_t07_findings_round_trip_and_upsert(backend):
    """Save -> read is lossless for engine-normalized findings; re-saving a
    fingerprint updates in place instead of stacking a duplicate; other
    PRs stay isolated."""
    st = backend.storage
    seeds = _seed_findings()

    st.save_findings(REVIEW_ID, seeds)
    assert _finding_view(st.get_previous_findings(REPO, PR)) == \
        sorted(seeds, key=lambda d: d["fingerprint"])

    revised = dict(seeds[0], state="active", last_seen_sha="cccc3333")
    st.save_findings(REVIEW_ID, [revised])

    after = _finding_view(st.get_previous_findings(REPO, PR))
    assert len(after) == 2  # upsert, not append
    alpha = next(d for d in after if d["fingerprint"] == "fp-alpha")
    assert alpha["state"] == "active"
    assert alpha["last_seen_sha"] == "cccc3333"

    assert st.get_previous_findings(REPO, PR + 1) == []


def test_t07_findings_without_fingerprint_gain_one_on_save(backend):
    """A finding saved without a fingerprint comes back with a computed one
    on every backend — the reviewer's state machine keys on it."""
    st = backend.storage
    bare = {"file": "a.py", "line": 1, "severity": "low", "category": "bug",
            "title": "T", "explanation": "e", "confidence": "low"}

    st.save_findings(REVIEW_ID, [bare])

    items = st.get_previous_findings(REPO, PR)
    assert len(items) == 1
    d = items[0].to_dict() if isinstance(items[0], Finding) else dict(items[0])
    assert Finding.from_dict(d).fingerprint, (
        f"{backend.name} returned a finding without a fingerprint")


def test_t07_save_findings_leaves_caller_data_untouched(backend):
    """A storage write never mutates the caller's dicts — the local
    backend used to inject the computed fingerprint into the input."""
    st = backend.storage
    bare = {"file": "a.py", "line": 1, "severity": "low", "category": "bug",
            "title": "T", "explanation": "e", "confidence": "low"}
    before = dict(bare)

    st.save_findings(REVIEW_ID, [bare])

    assert bare == before
    assert st.get_previous_findings(REPO, PR)  # the row was still stored


# ----------------------------------------------------------------- repo memory
def test_t07_repo_memory_notes_filter_by_pattern(backend):
    """Notes match by glob against the queried paths; other repos, other
    patterns and mute rows never surface as notes."""
    st = backend.storage
    _seed_memory(backend, "src/*.py", "src advice")
    _seed_memory(backend, "tests/*.py", "test advice",
                 category="preferred-pattern")
    _seed_memory(backend, "docs/*.md", "docs advice")
    _seed_mute(backend, "fp-x")

    assert sorted(st.get_repo_memory(REPO, ["src/app.py"])) == ["src advice"]
    assert sorted(st.get_repo_memory(REPO, ["tests/test_a.py"])) == \
        ["test advice"]
    assert st.get_repo_memory(REPO, ["README.md"]) == []
    assert st.get_repo_memory(REPO, ["src/app.py", "tests/test_a.py"]) == \
        ["src advice", "test advice"]
    assert st.get_repo_memory("acme/other", ["src/app.py"]) == []


def test_t07_list_repo_memory_verbatim_contract(backend):
    """list_repo_memory returns rows verbatim — mute rows, disabled rows
    and categories included (V3 C7 contract) — with the common key set
    every backend guarantees."""
    st = backend.storage
    _seed_memory(backend, "src/*.py", "src advice", category="project-rule")
    _seed_memory(backend, "legacy/**", "known exception",
                 category="known-exception", enabled=False)
    _seed_mute(backend, "fp-x")

    rows = st.list_repo_memory(REPO)
    assert len(rows) == 3
    for row in rows:
        assert {"path_pattern", "note", "category", "enabled"} <= set(row), \
            f"{backend.name} row lacks the common key set: {row}"

    by_pattern = {r["path_pattern"]: r for r in rows}
    assert by_pattern["src/*.py"]["note"] == "src advice"
    assert by_pattern["src/*.py"]["category"] == "project-rule"
    assert bool(by_pattern["src/*.py"]["enabled"]) is True
    assert bool(by_pattern["legacy/**"]["enabled"]) is False
    assert by_pattern["legacy/**"]["category"] == "known-exception"
    assert by_pattern[mute_pattern("fp-x")]["note"] == "Muted finding fp-x"

    assert st.list_repo_memory("acme/other") == []


# ------------------------------------------------------------------- dismissed
def test_t07_dismissed_fingerprints_lifecycle(backend):
    """No mutes -> empty set; mute rows read back as fingerprints; plain
    notes never count as dismissals; other repos stay isolated. Disabled
    mute rows still dismiss — shared behavior across all four backends."""
    st = backend.storage
    assert st.get_dismissed_fingerprints(REPO) == set()

    _seed_memory(backend, "src/*.py", "plain note")
    _seed_mute(backend, "fp-a")
    _seed_mute(backend, "fp-b", enabled=False)

    assert st.get_dismissed_fingerprints(REPO) == {"fp-a", "fp-b"}
    assert st.get_dismissed_fingerprints("acme/other") == set()


# -------------------------------------------------- capability-gated lifecycles
def test_t07_telemetry_round_trip_when_capability_declared(backend):
    """Backends declaring CAP_TELEMETRY round-trip the sanitized row; the
    HTTP client (no capability) skips with an explicit reason."""
    if not has_capability(backend.storage, CAP_TELEMETRY):
        pytest.skip(f"{backend.name} declares no telemetry capability")

    st = backend.storage
    assert st.get_telemetry(REVIEW_ID) is None

    st.save_telemetry(REVIEW_ID, _telemetry_row())
    got = st.get_telemetry(REVIEW_ID)
    assert got is not None
    assert got["provider"] == "claude"
    assert got["model"] == "claude-sonnet-4-6"
    assert got["usage"]["input_tokens"] == 120
    assert got["usage"]["state"] == "ok"

    st.save_telemetry(REVIEW_ID, _telemetry_row(in_tok=999))
    assert st.get_telemetry(REVIEW_ID)["usage"]["input_tokens"] == 999


def test_t07_prune_disabled_is_identical_noop(backend):
    """retention_days=0 (the default policy) is the same no-op dict on
    every pruning backend, and removes nothing; the HTTP client never
    prunes remotely, so it skips."""
    if not has_capability(backend.storage, CAP_PRUNE):
        pytest.skip(f"{backend.name} declares no prune capability")

    st = backend.storage
    st.save_findings(REVIEW_ID, _seed_findings())

    outcome = st.prune(0)

    assert set(outcome) == {"enabled", "cutoff", "dry_run",
                            "finding_history", "telemetry"}
    assert outcome["enabled"] is False
    assert outcome["cutoff"] is None
    assert outcome["finding_history"] == 0
    assert outcome["telemetry"] == 0
    assert len(_finding_view(st.get_previous_findings(REPO, PR))) == 2


# ----------------------------------------------------------- cross-backend pass
def test_t07_cross_backend_views_agree(tmp_path, monkeypatch):
    """The literal parity assertion: drive all four backends with the same
    operations in one process and compare their observable views
    byte-for-byte (normalized)."""
    with contextlib.ExitStack() as stack:
        backends = [
            stack.enter_context(_open_backend(name, tmp_path / name, monkeypatch))
            for name in BACKENDS
        ]
        for b in backends:
            b.storage.set_last_reviewed_sha(REPO, PR, "sha-head", "sha-base")
            b.storage.save_findings(REVIEW_ID, _seed_findings())
            _seed_memory(b, "src/*.py", "src advice", category="project-rule")
            _seed_memory(b, "legacy/**", "old exception",
                         category="known-exception", enabled=False)
            _seed_mute(b, "fp-a")

        ref = backends[0]
        ref_state = ref.storage.get_last_reviewed_sha(REPO, PR)
        ref_findings = _finding_view(ref.storage.get_previous_findings(REPO, PR))
        ref_notes = sorted(ref.storage.get_repo_memory(REPO, ["src/app.py"]))
        ref_rows = _memory_view(ref.storage.list_repo_memory(REPO))
        ref_dismissed = ref.storage.get_dismissed_fingerprints(REPO)

        assert ref_state == "sha-head"
        assert len(ref_findings) == 2
        assert ref_notes == ["src advice"]
        assert set(ref_rows) == {"src/*.py", "legacy/**",
                                 mute_pattern("fp-a")}
        assert ref_dismissed == {"fp-a"}

        for b in backends[1:]:
            assert b.storage.get_last_reviewed_sha(REPO, PR) == ref_state, \
                f"{b.name} state view differs"
            assert _finding_view(b.storage.get_previous_findings(REPO, PR)) == \
                ref_findings, f"{b.name} findings view differs"
            assert sorted(b.storage.get_repo_memory(REPO, ["src/app.py"])) == \
                ref_notes, f"{b.name} memory notes differ"
            assert _memory_view(b.storage.list_repo_memory(REPO)) == ref_rows, \
                f"{b.name} memory rows differ"
            assert b.storage.get_dismissed_fingerprints(REPO) == ref_dismissed, \
                f"{b.name} dismissed set differs"


# ------------------------------------------------------------- HTTP-only edges
def test_t07_http_without_token_reads_as_empty(tmp_path, monkeypatch, caplog):
    """Fail-closed auth: with data present but no token, the HTTP client
    degrades every read to its empty value with a logged warning —
    never an exception, never a partial leak."""
    raw = DbStorage(f"sqlite:///{tmp_path / 'd.db'}")
    raw.init()
    raw.set_last_reviewed_sha(REPO, PR, "sha-head")
    raw.save_findings(REVIEW_ID, _seed_findings())
    raw.add_repo_memory(REPO, "src/*.py", "src advice",
                        category="project-rule", enabled=True)

    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dashboard_app, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(dashboard_app, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(dashboard_app, "_storage", raw)
    monkeypatch.setattr(dashboard_app, "_api_token", "test-token")

    with TestClient(dashboard_app.app) as http:   # no auth header attached
        client = DashboardStorageClient("http://testserver", "", client=http)

        assert client.get_last_reviewed_sha(REPO, PR) is None
        assert client.get_previous_findings(REPO, PR) == []
        assert client.get_repo_memory(REPO, ["src/app.py"]) == []
        assert client.list_repo_memory(REPO) == []
        assert client.get_dismissed_fingerprints(REPO) == set()

    assert "DashboardStorageClient" in caplog.text
