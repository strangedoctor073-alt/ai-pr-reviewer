"""V4.0-E07-T04 — dashboard cost views (spend per run / per backend).

The additive ``GET /api/cost/views`` read plus the shared ``_cost_views``
aggregation both storage backends must shape identically. Absence is the
core invariant here: a run that never reported usage, or carried no
estimated cost, yields ``None`` — never a measured 0.
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard.app as dashboard_app                                  # noqa: E402
from dashboard.storage import (MAX_COST_RUNS, JsonStorage,             # noqa: E402
                               _cost_views, choose_storage)

from test_dashboard_storage import _memory_app, _tel_row                # noqa: E402

_RIDS = ("acme/widgets#1@s1", "acme/widgets#2@s2",
         "acme/other#3@s3", "acme/other#4@s4")

# carried through by sanitize_telemetry (well-formed + usage-consistent)
_PRICED = {"state": "estimated", "currency": "USD",
           "low": 0.0042, "high": 0.0061, "display_only": True}


@pytest.fixture()
def db_storage(tmp_path):
    storage = choose_storage(tmp_path, f"sqlite:///{tmp_path / 't.db'}")
    storage.init()
    return storage


@pytest.fixture()
def json_storage(tmp_path):
    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    return storage


def _seed(storage):
    """Four runs: reported+priced, reported+unpriced, unavailable, n/a."""
    storage.save_telemetry("acme/widgets#1@s1",
                           _tel_row(in_tok=100, out_tok=50, cost=_PRICED))
    storage.save_telemetry("acme/widgets#2@s2",
                           _tel_row(in_tok=200, out_tok=25, provider="openai"))
    storage.save_telemetry("acme/other#3@s3",
                           _tel_row(state="unavailable", in_tok=None,
                                    out_tok=None, call_ms=500))
    storage.save_telemetry("acme/other#4@s4",
                           _tel_row(state="n/a", in_tok=None, out_tok=None,
                                    provider="static"))


def _stamp(i: int) -> str:
    """Deterministic, strictly increasing ``updated_at`` value (minute
    steps keep the fixed-width ISO string order == recency order)."""
    return (datetime(2026, 1, 1, tzinfo=timezone.utc)
            + timedelta(minutes=i)).isoformat()


def _stamps_for(ids: list[str]) -> dict[str, str]:
    return {rid: _stamp(pos) for pos, rid in enumerate(ids)}


# ------------------------------------------------------------------ shaping
def test_backends_shape_the_identical_cost_views(db_storage, json_storage):
    _seed(db_storage)
    _seed(json_storage)

    db_v, js_v = db_storage.cost_views(), json_storage.cost_views()
    assert set(db_v) == {"spend_per_run", "spend_by_backend", "totals"}
    assert len(db_v["spend_per_run"]) == len(_RIDS)

    # Row order across two backends can only differ if a wall-clock second
    # ticked between their saves, so parity is pinned id-keyed (rows) and
    # order-free (aggregates); the ORDER itself is pinned deterministically
    # in the rewritten-timestamp test below.
    assert ({r["id"]: r for r in db_v["spend_per_run"]}
            == {r["id"]: r for r in js_v["spend_per_run"]})
    assert db_v["spend_by_backend"] == js_v["spend_by_backend"]
    assert db_v["totals"] == js_v["totals"]
    for row in db_v["spend_per_run"]:
        assert set(row) == {"id", "repo", "pr_number", "provider", "model",
                            "usage_state", "input_tokens", "output_tokens",
                            "cost_low", "cost_high"}


def test_sql_and_python_cut_the_same_window_ordered_identically(
        db_storage, json_storage):
    """SQL's ``ORDER BY ... LIMIT`` cut must equal Python's cut: both
    backends return the same newest-100 rows in the same order, and the
    aggregates cover exactly that window — including at a boundary where
    every timestamp ties and only the id tiebreak can agree."""
    ids = [f"acme/widgets#{i:03d}@s" for i in range(1, MAX_COST_RUNS + 6)]
    stamps = _stamps_for(ids)
    for rid in ids:
        db_storage.save_telemetry(rid, _tel_row())
        json_storage.save_telemetry(rid, _tel_row())

    # pin the clock on both backends (save_telemetry stamps "now")
    from sqlalchemy import update as sa_update

    from dashboard.models_db import TelemetryRow

    with db_storage.Session() as session:
        for rid in ids:
            session.execute(sa_update(TelemetryRow)
                            .where(TelemetryRow.id == rid)
                            .values(updated_at=stamps[rid]))
        session.commit()
    jpath = json_storage._telemetry_file()
    items = json_storage._read_memory_rows(jpath)
    for item in items:
        item["updated_at"] = stamps[item["id"]]
    json_storage._write_memory_rows(jpath, items)

    db_v, js_v = db_storage.cost_views(), json_storage.cost_views()
    assert db_v == js_v                                  # exact, order included
    assert MAX_COST_RUNS == 100
    assert len(db_v["spend_per_run"]) == MAX_COST_RUNS
    assert db_v["spend_per_run"][0]["id"] == ids[-1]     # newest first
    assert db_v["spend_per_run"][-1]["id"] == ids[5]     # 5 oldest cut away
    assert {r["id"] for r in db_v["spend_per_run"]} == set(ids[5:])
    assert db_v["totals"]["runs"] == MAX_COST_RUNS       # window, not all 105
    assert db_v["totals"]["reported_runs"] == MAX_COST_RUNS
    assert db_v["totals"]["input_tokens"] == 100 * MAX_COST_RUNS

    # Boundary ties: every row shares one timestamp, so the selected
    # window can only match Python's rule if SQL tie-breaks by id
    # descending as well (otherwise the two backends keep different rows
    # once the table grows past the bound).
    tied = _stamp(0)
    with db_storage.Session() as session:
        session.execute(sa_update(TelemetryRow).values(updated_at=tied))
        session.commit()
    items = json_storage._read_memory_rows(jpath)
    for item in items:
        item["updated_at"] = tied
    json_storage._write_memory_rows(jpath, items)

    db_t, js_t = db_storage.cost_views(), json_storage.cost_views()
    assert db_t == js_t
    assert [r["id"] for r in db_t["spend_per_run"]] \
        == list(reversed(ids))[:MAX_COST_RUNS]           # #105 .. #006
    assert db_t["totals"]["runs"] == MAX_COST_RUNS


# ------------------------------------------------------------------- absence
def test_absence_stays_absence_never_a_measured_zero(db_storage,
                                                     json_storage):
    _seed(db_storage)
    _seed(json_storage)

    for storage in (db_storage, json_storage):
        v = storage.cost_views()
        by_id = {r["id"]: r for r in v["spend_per_run"]}

        unavailable = by_id["acme/other#3@s3"]
        assert unavailable["usage_state"] == "unavailable"
        assert unavailable["input_tokens"] is None
        assert unavailable["output_tokens"] is None
        assert unavailable["cost_low"] is None and unavailable["cost_high"] is None

        na = by_id["acme/other#4@s4"]
        assert na["usage_state"] == "n/a"
        assert na["input_tokens"] is None and na["output_tokens"] is None

        priced = by_id["acme/widgets#1@s1"]
        assert priced["input_tokens"] == 100 and priced["output_tokens"] == 50
        assert priced["cost_low"] == pytest.approx(0.0042)
        assert priced["cost_high"] == pytest.approx(0.0061)

        # reported but unpriced: counts present, dollars still absent
        unpriced = by_id["acme/widgets#2@s2"]
        assert unpriced["input_tokens"] == 200 and unpriced["output_tokens"] == 25
        assert unpriced["cost_low"] is None and unpriced["cost_high"] is None

        totals = v["totals"]
        assert totals["runs"] == 4 and totals["reported_runs"] == 2
        assert totals["priced_runs"] == 1
        assert totals["input_tokens"] == 300 and totals["output_tokens"] == 75
        assert totals["cost_low"] == pytest.approx(0.0042)

        # a bucket nothing reported into says so — it never claims 0
        static = v["spend_by_backend"]["static"]
        assert static["runs"] == 1 and static["reported_runs"] == 0
        assert static["input_tokens"] is None
        assert static["output_tokens"] is None
        assert static["priced_runs"] == 0 and static["cost_low"] is None


def test_crafted_rows_never_claim_unreported_measurements(json_storage):
    """Rows that never passed ``save_telemetry`` (hand-edited
    telemetry.json, rows predating the NULL invariant) are read back as
    untrusted: the usage state wins over planted token counts, and a
    non-int count is never coerced into a measurement."""
    jpath = json_storage._telemetry_file()
    json_storage._write_memory_rows(jpath, [
        {"id": "acme/other#9@s9", "repo": "acme/other", "pr_number": 9,
         "updated_at": _stamp(0), "provider": "claude", "model": "m",
         "usage": {"state": "unavailable", "input_tokens": 100,
                   "output_tokens": 50}},          # state says: nothing reported
        {"id": "acme/other#10@s10", "repo": "acme/other",
         "pr_number": "not-a-number",         # crafted: must not raise
         "updated_at": _stamp(1), "provider": "claude", "model": "m",
         "usage": {"state": "ok", "input_tokens": "lots",
                   "output_tokens": 50}},          # not an int => not a count
    ])

    v = json_storage.cost_views()
    by_id = {r["id"]: r for r in v["spend_per_run"]}
    assert len(v["spend_per_run"]) == 2

    hostile = by_id["acme/other#9@s9"]
    assert hostile["usage_state"] == "unavailable"
    assert hostile["input_tokens"] is None
    assert hostile["output_tokens"] is None

    partial = by_id["acme/other#10@s10"]
    assert partial["pr_number"] == 0              # unparsable coerced, no 500
    assert partial["input_tokens"] is None
    assert partial["output_tokens"] == 50

    # aggregates never fabricate a measured 0 for a side nothing reported
    totals = v["totals"]
    assert totals["reported_runs"] == 1
    assert totals["input_tokens"] is None
    assert totals["output_tokens"] == 50
    bucket = v["spend_by_backend"]["claude"]
    assert bucket["input_tokens"] is None
    assert bucket["output_tokens"] == 50


# -------------------------------------------------------------- window rule
def _row(i: int, updated_at: str) -> dict:
    return {"id": f"r{i:03d}", "repo": "acme/widgets", "pr_number": i,
            "provider": "claude", "model": "m", "usage_state": "ok",
            "input_tokens": 1, "output_tokens": 1,
            "updated_at": updated_at, "cost": None}


def test_cost_views_window_is_newest_first_and_bounded():
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rows = [_row(i, (base + timedelta(minutes=i)).isoformat())
            for i in range(MAX_COST_RUNS + 20)]

    out = _cost_views(rows)
    assert len(out["spend_per_run"]) == MAX_COST_RUNS
    assert out["spend_per_run"][0]["id"] == "r119"      # newest kept first
    assert out["spend_per_run"][-1]["id"] == "r020"     # oldest 20 cut away
    # aggregates cover exactly the window, never the rows that were cut
    assert out["totals"]["runs"] == MAX_COST_RUNS
    assert out["totals"]["input_tokens"] == MAX_COST_RUNS
    assert out["spend_by_backend"]["claude"]["runs"] == MAX_COST_RUNS

    assert len(_cost_views(rows, limit=5)["spend_per_run"]) == 5
    empty = _cost_views(rows, limit=0)
    assert empty["spend_per_run"] == [] and empty["spend_by_backend"] == {}
    assert empty["totals"]["runs"] == 0
    assert empty["totals"]["input_tokens"] is None       # absence, not 0


def test_cost_views_breaks_timestamp_ties_by_id_descending():
    tied = [_row(i, "2026-01-01T00:00:00+00:00") for i in range(10)]
    order = [r["id"] for r in _cost_views(tied, limit=4)["spend_per_run"]]
    assert order == ["r009", "r008", "r007", "r006"]


# ------------------------------------------------------------------ endpoint
@pytest.mark.parametrize("kind", ["db", "json"])
def test_endpoint_serves_the_storage_views_read_only(monkeypatch, tmp_path,
                                                     kind):
    if kind == "db":
        storage = choose_storage(tmp_path, f"sqlite:///{tmp_path / 't.db'}")
    else:
        storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    _seed(storage)
    headers = _memory_app(monkeypatch, tmp_path, storage)
    rows_before = {rid: storage.get_telemetry(rid) for rid in _RIDS}
    blob = (storage._telemetry_file().read_bytes() if kind == "json"
            else None)

    with TestClient(dashboard_app.app) as client:
        resp = client.get("/api/cost/views", headers=headers)
        assert resp.status_code == 200
        assert resp.json() == storage.cost_views()
        # identical auth posture to the pre-existing metrics read
        assert (client.get("/api/cost/views").status_code
                == client.get("/api/metrics").status_code)

    # read-only: stored rows untouched, JSON blob byte-identical
    assert {rid: storage.get_telemetry(rid) for rid in _RIDS} == rows_before
    if blob is not None:
        assert storage._telemetry_file().read_bytes() == blob


def test_endpoint_degrades_to_501_without_the_telemetry_capability(
        monkeypatch, tmp_path):
    class DeclaredWithoutTelemetry:
        capabilities = frozenset()      # declared: no legacy method inference
        backend = "no-telemetry"        # startup notice reads this attribute

    headers = _memory_app(monkeypatch, tmp_path,
                          DeclaredWithoutTelemetry())
    with TestClient(dashboard_app.app) as client:
        resp = client.get("/api/cost/views", headers=headers)
    assert resp.status_code == 501


def test_route_is_additive_and_existing_routes_still_exist():
    paths = {getattr(r, "path", "") for r in dashboard_app.app.routes}
    assert "/api/cost/views" in paths
    for existing in ("/api/reports", "/api/metrics", "/api/health",
                     "/api/findings", "/api/settings", "/api/config",
                     "/api/telemetry"):
        assert existing in paths


# ------------------------------------------------------------------ frontend
def test_metrics_page_fetches_and_renders_cost_views_defensively():
    src = (ROOT / "dashboard" / "static" / "app.js").read_text(
        encoding="utf-8")
    # an older server (404) or a backend without the capability (501)
    # degrades to an empty object — the page never fails on this fetch
    assert 'try { costViews = await api("/api/cost/views"); }' in src
    assert "catch (e) { costViews = {}; }" in src
    # both blocks render only when they have data
    assert "Object.keys(byBackend).length ?" in src
    assert "perRun.length ?" in src
    # unreported counts are labelled, never drawn as a measured 0
    assert '"not reported"' in src
    # barRows' formatter is optional: pre-existing call sites unchanged
    assert "fmt ? fmt(v) : v" in src
    # identifiers and labels are escaped before reaching innerHTML
    assert 'title="${esc(String(row.id || ""))}"' in src
    assert 'esc(row.provider || "unknown")' in src
