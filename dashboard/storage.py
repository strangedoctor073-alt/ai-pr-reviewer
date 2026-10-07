"""Storage backends for review reports.

Production path  : SQLAlchemy — PostgreSQL (or any SQLAlchemy DSN) via
                   ``DATABASE_URL``, SQLite out-of-the-box. Handles concurrent
                   writes through the DB, WAL mode on SQLite.
Prototype path   : JSON files (zero dependencies) — kept explicitly as a demo
                   fallback, never as the recommended setup.

Both backends implement the same small interface, selected by
:func:`choose_storage`.
"""
from __future__ import annotations

import datetime as _dt
import fnmatch
import re
import json
import logging
import os
import threading
from collections import Counter
from pathlib import Path

log = logging.getLogger(__name__)

SEV_KEYS = ("critical", "high", "medium", "low", "info")
MAX_FINDINGS_STORED = 500          # hard cap per report, defense against abuse


def _normalize_category(raw) -> str:
    """Memory row category, restricted to the reviewer's known set.

    Lives here (rather than being reimplemented) so the dashboard and the
    engine agree on what a category is; imported lazily in the style of the
    other ``ai_pr_reviewer`` uses in this package, because the dependency-free
    JSON fallback must keep working without the engine installed.
    """
    try:
        from ai_pr_reviewer.memory import normalize_category
        return normalize_category(raw)
    except Exception:
        pass
    value = str(raw or "").strip().lower().replace("_", "-").replace(" ", "-")
    known = ("project-rule", "preferred-pattern", "known-exception",
             "review-preference")
    return value if value in known else "project-rule"


def _schema():
    """The engine's shared cross-store schema module (V3-E04-T03).

    Key formats, the ``fingerprint:`` prefix and review-id parsing have
    exactly one owner (``ai_pr_reviewer.storage_schema``), shared with
    the engine. Imported at call time in the style of this package's
    other engine uses, so importing this module alone still works
    without the engine package present.
    """
    from ai_pr_reviewer import storage_schema

    return storage_schema


def _max_note_chars() -> int:
    """Per-note length bound, single-sourced from ``ai_pr_reviewer.memory``
    (V3-E05-T02, D13): dashboard memory writes must truncate at exactly the
    cap the engine applies, so the value cannot drift between the two.

    Imported at call time in the style of this package's other engine uses;
    the literal fallback keeps the dependency-free JSON path working when the
    engine package is absent and must stay equal to
    ``ai_pr_reviewer.memory.MAX_NOTE_CHARS`` (asserted by
    ``tests/test_cap_constants.py``).
    """
    try:
        from ai_pr_reviewer.memory import MAX_NOTE_CHARS
        return MAX_NOTE_CHARS
    except Exception:
        return 1_000


def _telemetry_assemble(runs: int, in_sum: int, out_sum: int,
                        call_sum: int, call_n: int, state_counts,
                        by_repo: dict) -> dict:
    """Assemble the telemetry summary from raw aggregates (V3-E04-T05).

    Single owner of the output shape: ``_telemetry_summary`` computes the
    aggregates row-by-row (JSON backend), DbStorage.metrics computes them
    in SQL, and both call this — so the two paths cannot drift apart.
    """
    return {
        "runs": runs,
        "tokens": {"input": in_sum, "output": out_sum},
        "usage_states": {s: state_counts.get(s, 0)
                         for s in ("ok", "unavailable", "n/a")},
        "avg_call_ms": round(call_sum / call_n, 1) if call_n else 0.0,
        "by_repo": by_repo,
    }


def _telemetry_summary(rows: list[dict]) -> dict:
    """Aggregate normalized telemetry rows for ``/api/metrics`` (V3-E02-T05).

    ``rows`` are ``{"repo", "usage_state", "input_tokens", "output_tokens",
    "call_ms"}`` — token fields ``None`` unless the run's usage state was
    ``ok``, so an unavailable count never inflates a sum as a fake 0.
    Additive block: both backends return it beside the unchanged legacy
    metric keys. V3-E04-T05: the assembly moved to
    ``_telemetry_assemble`` so the SQL path shares this exact logic; the
    row-loop below is unchanged.
    """
    runs = len(rows)
    in_sum = out_sum = 0
    call_sum = call_n = 0
    states: Counter = Counter()
    by_repo: dict[str, dict] = {}
    for row in rows:
        state = str(row.get("usage_state") or "n/a")
        states[state] += 1
        repo = str(row.get("repo") or "")
        entry = by_repo.setdefault(repo, {"runs": 0, "input_tokens": 0,
                                          "output_tokens": 0, "call_ms": 0})
        entry["runs"] += 1
        if state == "ok":
            in_tok = row.get("input_tokens")
            out_tok = row.get("output_tokens")
            if type(in_tok) is int:
                in_sum += in_tok
                entry["input_tokens"] += in_tok
            if type(out_tok) is int:
                out_sum += out_tok
                entry["output_tokens"] += out_tok
        call_ms = row.get("call_ms")
        if type(call_ms) is int:
            call_sum += call_ms
            entry["call_ms"] += call_ms
            call_n += 1
    return _telemetry_assemble(runs, in_sum, out_sum, call_sum, call_n,
                               states, by_repo)


def _top_counter(pairs, n: int | None = None) -> dict:
    """Deterministic stand-in for ``Counter.most_common`` (V3-E04-T05).

    Count descending, then key ascending on ties — the DB backend can't
    reproduce Python's first-seen tie order from a ``GROUP BY``, so both
    backends use this rule and aggregates are reproducible run to run.
    """
    ordered = sorted(pairs, key=lambda kv: (-kv[1], kv[0]))
    return dict(ordered if n is None else ordered[:n])


def _json_sum_sql(dialect: str, table: str, column: str) -> str | None:
    """Server-side ``key -> SUM(value)`` SQL for a JSON count-map column.

    Returns None when this dialect has no JSON expansion — callers then
    fall back to aggregating just that one light column in Python.
    """
    if dialect == "sqlite":
        return (f"SELECT je.key AS k, SUM(CAST(je.value AS INTEGER)) AS n "
                f"FROM {table} r, json_each(r.{column}) je GROUP BY je.key")
    if dialect == "postgresql":
        return (f"SELECT je.key AS k, SUM((je.value #>> '{{}}')::bigint) AS n "
                f"FROM {table} r, json_each(r.{column}) je GROUP BY je.key")
    return None


def _count_map_pairs(session, table: str, column: str) -> dict:
    """``key -> total`` across all reports for a JSON count-map column.

    Aggregated without loading report objects (V3-E04-T05): server-side
    JSON expansion where the dialect has it, otherwise a Python pass over
    this single light column only (payload stays in the database).
    """
    from sqlalchemy import text

    sql = _json_sum_sql(session.get_bind().dialect.name, table, column)
    if sql:
        try:
            return {k: int(n or 0)
                    for k, n in session.execute(text(sql)).all()}
        except Exception as exc:  # noqa: BLE001 — dialect quirks
            log.warning("server-side JSON aggregation of %s.%s failed (%s); "
                        "reading the light column instead", table, column, exc)
    from sqlalchemy import select

    from .models_db import ReportRow

    counter: Counter = Counter()
    for (mapping,) in session.execute(select(getattr(ReportRow, column))).all():
        counter.update(mapping or {})
    return dict(counter)


def summarize(report: dict) -> dict:
    """Summary form used by list endpoints and stats."""
    from collections import Counter as _C

    pr = report.get("pr", {})
    counts = _C(f.get("severity") for f in report.get("findings", []))
    stats = report.get("stats") or {}
    return {
        "id": report.get("id", ""),
        "repo": pr.get("repo", ""),
        "pr_number": pr.get("number", 0),
        "pr_title": pr.get("title", ""),
        "author": pr.get("author", ""),
        "branch": pr.get("branch", ""),
        "mode": report.get("mode", ""),
        "model": report.get("model", ""),
        "reviewed_at": report.get("reviewed_at", ""),
        "duration_ms": report.get("duration_ms", 0),
        "stats": {"files": stats.get("files", 0),
                  "additions": stats.get("additions", 0),
                  "deletions": stats.get("deletions", 0)},
        "severity_counts": {s: counts.get(s, 0) for s in SEV_KEYS},
        "findings_count": sum(counts.values()),
    }


class DbStorage:
    """SQLAlchemy-backed storage (PostgreSQL / SQLite)."""

    def __init__(self, dsn: str, json_dir: Path | None = None):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        kwargs: dict = {"pool_pre_ping": True}
        if dsn.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 15}
        self.engine = create_engine(dsn, **kwargs)
        self.Session = sessionmaker(self.engine, expire_on_commit=False)
        self.json_dir = json_dir          # legacy dir, used by one-time migration
        self.backend = "sqlite" if dsn.startswith("sqlite") else \
            self.engine.dialect.name
        # V3-E04-T04: declared capability set — the core protocol plus the
        # full optional set (both formerly-undeclared capabilities, telemetry,
        # pruning). Resolved through the lazy schema helper so importing
        # this module still works without the engine package present.
        schema = _schema()
        self.capabilities = schema.CORE_CAPABILITIES | {
            schema.CAP_LIST_REPO_MEMORY,
            schema.CAP_DISMISSED_FINGERPRINTS,
            schema.CAP_TELEMETRY,
            schema.CAP_PRUNE,
        }

    def init(self) -> None:
        from sqlalchemy import text

        from .models_db import Base, ReportRow

        Base.metadata.create_all(self.engine)
        self._add_missing_columns()
        # V3-E04-T05: the composite (repo, pr_number) index is declared on
        # the model for fresh databases; this creates it for databases that
        # predate it (IF NOT EXISTS makes a fresh database a no-op).
        with self.engine.begin() as conn:
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_finding_histories_repo_pr "
                "ON finding_histories (repo, pr_number)"))
        if self.engine.dialect.name == "sqlite":
            with self.engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA busy_timeout=5000"))
        self._migrate_json_once()

    # V3 C7: columns added to existing tables. ``create_all`` only creates
    # missing tables, so a dashboard database from a previous build has to
    # gain columns the same way LocalReviewStorage does it: inspect, then add.
    # V3-E04-T05: reports gained its metric columns the same way; because
    # SQLite/PG reads synthesize the DEFAULT for legacy rows (hiding any
    # physical NULL), the backfill below re-derives every row from its
    # payload in the same transaction rather than probing ``WHERE ... IS NULL``.
    _COLUMN_UPGRADES = {
        "repo_memories": {
            "category": "VARCHAR(64)",
            "enabled": "INTEGER DEFAULT 1",
            "updated_at": "VARCHAR(32)",
        },
        "reports": {
            "engine": "VARCHAR(40) DEFAULT 'static'",
            "fallback_used": "INTEGER DEFAULT 0",
            "health_score": "FLOAT DEFAULT 100",
        },
    }

    def _add_missing_columns(self) -> None:
        from sqlalchemy import inspect, text

        inspector = inspect(self.engine)
        existing_tables = set(inspector.get_table_names())
        added: list[str] = []
        with self.engine.begin() as conn:
            for table, columns in self._COLUMN_UPGRADES.items():
                if table not in existing_tables:
                    continue
                present = {c["name"] for c in inspector.get_columns(table)}
                for name, ddl in columns.items():
                    if name in present:
                        continue
                    try:
                        conn.execute(text(
                            f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
                        added.append(name)
                    except Exception as exc:  # noqa: BLE001 — dialect quirks
                        log.warning("DbStorage: could not add %s.%s (%s)",
                                    table, name, exc)
            if any(name in added for name in
                   ("engine", "fallback_used", "health_score")):
                self._backfill_report_metrics(conn)

    def _backfill_report_metrics(self, conn) -> None:
        """Derive the V3-E04-T05 metric columns from existing payloads.

        One-time (runs only in the transaction that added the columns) and
        unconditional: a legacy row *reads back its ALTER default*, so a
        ``WHERE ... IS NULL`` probe would match nothing and silently reset
        every historic metric to ``static``/0/100. Deriving from the
        payload preserves what ``metrics()`` reported before the
        migration — an old ``engine: "claude"`` review still counts as
        claude. Unknown dialects or a failing JSON function fall back to
        the same derivation computed row by row in Python.
        """
        from sqlalchemy import select, text

        from .models_db import ReportRow

        dialect = self.engine.dialect.name
        if dialect == "sqlite":
            try:
                conn.execute(text(
                    "UPDATE reports SET"
                    " engine = COALESCE(json_extract(payload, '$.engine'), 'static'),"
                    " fallback_used = CASE WHEN json_extract(payload,"
                    " '$.fallback_used') THEN 1 ELSE 0 END,"
                    " health_score = COALESCE(json_extract(payload,"
                    " '$.health_score'), 100)"))
                return
            except Exception as exc:  # noqa: BLE001 — e.g. JSON1 missing
                log.warning("DbStorage: SQL report-metric backfill failed "
                            "(%s); deriving in Python", exc)
        elif dialect == "postgresql":
            try:
                conn.execute(text(
                    "UPDATE reports SET"
                    " engine = COALESCE(payload->>'engine', 'static'),"
                    " fallback_used = CASE WHEN payload->>'fallback_used'"
                    " IN ('true', '1') THEN 1 ELSE 0 END,"
                    " health_score = COALESCE((payload->>'health_score')"
                    "::double precision, 100)"))
                return
            except Exception as exc:  # noqa: BLE001 — dialect quirks
                log.warning("DbStorage: SQL report-metric backfill failed "
                            "(%s); deriving in Python", exc)
        try:
            rows = conn.execute(
                select(ReportRow.id, ReportRow.payload)).all()
            conn.execute(
                text("UPDATE reports SET engine = :engine,"
                     " fallback_used = :fallback, health_score = :health"
                     " WHERE id = :id"),
                [{"id": rid, "engine": str((p or {}).get("engine", "static")),
                  "fallback": 1 if (p or {}).get("fallback_used") else 0,
                  "health": float((p or {}).get("health_score", 100)),
                  } for rid, p in rows])
        except Exception as exc:  # noqa: BLE001 — dialect quirks
            log.warning("DbStorage: report metric backfill failed (%s)", exc)

    # ----------------------------------------------------------------- writes
    def upsert(self, report: dict) -> str:
        from .models_db import ReportRow

        findings = report.get("findings", [])
        truncated = len(findings) > MAX_FINDINGS_STORED
        if truncated:  # keep the worst findings, drop the tail
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            findings = sorted(
                findings, key=lambda f: order.get(f.get("severity"), 9)
            )[:MAX_FINDINGS_STORED]
            report = {**report, "findings": findings,
                      "truncated_findings": True}

        counts = Counter(f.get("severity") for f in findings)
        cats = Counter(f.get("category", "bug") for f in findings)
        pr = report.get("pr", {})
        stats = report.get("stats") or {}
        rid = report.get("id", "")

        from .models_db import ReportRow

        with self.Session() as session:
            row = session.get(ReportRow, rid) or ReportRow(id=rid)
            row.repo = pr.get("repo", "")
            row.pr_number = int(pr.get("number") or 0)
            row.pr_title = pr.get("title", "")[:300]
            row.author = pr.get("author", "")[:100]
            row.branch = pr.get("branch", "")[:200]
            row.mode = report.get("mode", "")
            row.model = report.get("model", "")
            row.reviewed_at = report.get("reviewed_at", "")
            row.duration_ms = int(report.get("duration_ms") or 0)
            row.files = int(stats.get("files") or 0)
            row.additions = int(stats.get("additions") or 0)
            row.deletions = int(stats.get("deletions") or 0)
            row.findings_count = len(findings)
            row.truncated = truncated
            # Sparse on purpose (V3-E04-T05): only non-zero severities are
            # stored, so stats()' json_each expansion visits one virtual
            # row per *observed* severity instead of five per report.
            # Every reader is .get(s, 0) / range(c) based, so a missing
            # key and a zero entry are indistinguishable downstream.
            row.severity_counts = {s: counts[s] for s in SEV_KEYS
                                   if counts.get(s)}
            row.categories = dict(cats)
            # V3-E04-T05: mirror the metric fields metrics() used to pull
            # from payload JSON, so aggregation stays column-side. health
            # keeps only numeric values (the pre-T05 read crashed on a
            # non-numeric one anyway); everything else mirrors payload
            # truthiness/defaults exactly.
            row.engine = str(report.get("engine", "static"))
            row.fallback_used = 1 if report.get("fallback_used") else 0
            health = report.get("health_score", 100)
            row.health_score = (float(health)
                                if isinstance(health, (int, float)) else 100.0)
            row.payload = report
            session.add(row)
            session.commit()
        return rid

    def get(self, rid: str) -> dict | None:
        from .models_db import ReportRow

        with self.Session() as session:
            row = session.get(ReportRow, rid)
            if row is None:
                return None
            payload = dict(row.payload or {})
        payload.setdefault("id", rid)
        return payload

    def delete(self, rid: str) -> bool:
        from sqlalchemy import delete as sa_delete

        from .models_db import ReportRow

        with self.Session() as session:
            res = session.execute(sa_delete(ReportRow).where(ReportRow.id == rid))
            session.commit()
            return res.rowcount > 0

    # ------------------------------------------------------------------ reads
    def list(self, limit: int = 50, offset: int = 0) -> list[dict]:
        from sqlalchemy import select

        from .models_db import ReportRow

        with self.Session() as session:
            rows = session.execute(
                select(ReportRow).order_by(ReportRow.reviewed_at.desc(),
                                           ReportRow.id.desc())
                .limit(limit).offset(offset)).scalars().all()
            out = []
            for row in rows:
                s = summarize({"id": row.id, "pr": {
                    "repo": row.repo, "number": row.pr_number,
                    "title": row.pr_title, "author": row.author,
                    "branch": row.branch,
                }, "mode": row.mode, "model": row.model,
                    "reviewed_at": row.reviewed_at,
                    "duration_ms": row.duration_ms,
                    "stats": {"files": row.files, "additions": row.additions,
                              "deletions": row.deletions},
                    "findings": [{"severity": s, "n": c}
                                 for s, c in (row.severity_counts or {}).items()
                                 for _ in range(c)],
                })
                out.append(s)
            return out

    def stats(self) -> dict:
        """Aggregated entirely in SQL (V3-E04-T05).

        Scalar sums, one ``GROUP BY`` for repos and a server-side JSON
        expansion for the count maps — no ``ReportRow`` object is loaded,
        while the response keeps the exact shape and values of the old
        Python pass (snapshot-tested against the JSON backend).
        """
        from sqlalchemy import func, select

        from .models_db import ReportRow

        with self.Session() as session:
            # One grouped scan yields the per-repo counts *and* the global
            # totals (globals = sums over the disjoint repo groups), which
            # replaces the separate COUNT/SUM scan the old plan paid for.
            repo_expr = func.coalesce(func.nullif(ReportRow.repo, ""), "?")
            repo_groups = session.execute(
                select(repo_expr, func.count(),
                       func.coalesce(func.sum(ReportRow.findings_count), 0),
                       func.coalesce(func.sum(ReportRow.files), 0))
                .group_by(repo_expr)).all()
            reports = sum(n for _, n, _, _ in repo_groups)
            findings = sum(sf for _, _, sf, _ in repo_groups)
            files = sum(sfl for _, _, _, sfl in repo_groups)
            top_repos = _top_counter([(r, n) for r, n, _, _ in repo_groups], 5)

            sev = _count_map_pairs(session, "reports", "severity_counts")
            cats = _count_map_pairs(session, "reports", "categories")

        return {
            "reports": reports, "findings": findings,
            "by_severity": {s: sev.get(s, 0) for s in SEV_KEYS},
            "by_category": _top_counter(cats.items(), 8),
            "top_repos": top_repos,
            "files_analyzed": files,
        }

    def list_findings(self, state: str = "", severity: str = "",
                      repo: str = "", limit: int = 100, offset: int = 0) -> list[dict]:
        """Return stored findings across all reports, with optional filtering.

        V3-E04-T05: ``repo`` is pushed into SQL (indexed column), rows
        arrive in the same deterministic order as ``list()``, and the
        scan stops once the requested window is full. The final slice is
        unchanged, so responses are identical to the old load-everything
        pass — only the work is bounded.
        """
        from sqlalchemy import select
        from .models_db import ReportRow

        offset = max(0, int(offset))
        limit = max(0, int(limit))
        if limit == 0:
            return []
        need = offset + limit

        results = []
        with self.Session() as session:
            query = select(ReportRow).order_by(
                ReportRow.reviewed_at.desc(), ReportRow.id.desc())
            if repo:
                query = query.where(ReportRow.repo == repo)
            # True streaming: without yield_per the Result builds every
            # matched ORM object at execute time — which would make the
            # early break below stop iteration but not materialization
            # (the very cost this ticket removes). Batches stay small
            # relative to the window, so at most a window's worth of rows
            # is ever constructed.
            query = query.execution_options(yield_per=min(need, 64))
            for row in session.execute(query).scalars():
                payload = row.payload or {}
                for f in payload.get("findings", [])[:MAX_FINDINGS_STORED]:
                    f_state = f.get("state", "new")
                    f_sev = f.get("severity", "medium")
                    if state and f_state != state:
                        continue
                    if severity and f_sev != severity:
                        continue
                    results.append({
                        **f,
                        "repo": row.repo,
                        "pr_number": row.pr_number,
                        "pr_title": row.pr_title,
                        "reviewed_at": row.reviewed_at,
                        "report_id": row.id,
                    })
                if len(results) >= need:
                    break
        return results[offset:offset + limit]

    def metrics(self) -> dict:
        """Live metrics, aggregated in SQL (V3-E04-T05).

        Scalar sums over the light metric columns, one ``GROUP BY`` per
        distribution and a server-side JSON expansion for severities —
        no report payload is ever parsed in Python. The telemetry block
        is likewise computed from scalar ``telemetry`` columns; the
        values are asserted equal to the row-loop path by the backend
        parity tests.
        """
        from sqlalchemy import func, select
        from .models_db import ReportRow, TelemetryRow

        with self.Session() as session:
            # One grouped scan gives both engine_distribution and the
            # global sums (fallback/duration/health = sums over the
            # disjoint engine groups) — replaces the separate scalar
            # aggregate scan the old plan paid for.
            engine_expr = func.coalesce(ReportRow.engine, "static")
            engine_groups = session.execute(
                select(engine_expr, func.count(),
                       func.coalesce(func.sum(ReportRow.fallback_used), 0),
                       func.coalesce(func.sum(ReportRow.duration_ms), 0),
                       func.coalesce(
                           func.sum(func.coalesce(ReportRow.health_score,
                                                  100.0)), 0.0))
                .group_by(engine_expr)
                .order_by(func.count().desc(), engine_expr)).all()
            engine_counts: dict = {}
            total = fallback_count = duration_sum = 0
            health_sum = 0.0
            for eng, n, fb, dur, hl in engine_groups:
                engine_counts[eng] = n
                total += n
                fallback_count += fb
                duration_sum += dur
                health_sum += hl

            sev_counts = _count_map_pairs(session, "reports",
                                          "severity_counts")

            # V3-E02-T05 telemetry series, now column-side: token columns
            # are NULL unless usage state was ok (the invariant
            # save_telemetry writes), so SUMs skip non-ok runs exactly like
            # the row loop does; COUNT(call_ms) excludes NULL durations.
            runs, in_sum, out_sum, call_sum, call_n = session.execute(
                select(func.count(),
                       func.coalesce(func.sum(TelemetryRow.input_tokens), 0),
                       func.coalesce(func.sum(TelemetryRow.output_tokens), 0),
                       func.coalesce(func.sum(TelemetryRow.call_ms), 0),
                       func.count(TelemetryRow.call_ms))
                .select_from(TelemetryRow)).one()

            state_expr = func.coalesce(func.nullif(TelemetryRow.usage_state,
                                                   ""), "n/a")
            state_counts = dict(session.execute(
                select(state_expr, func.count())
                .group_by(state_expr)).all())

            by_repo: dict[str, dict] = {}
            for rrepo, n, tin, tout, tcall in session.execute(
                    select(func.coalesce(TelemetryRow.repo, ""),
                           func.count(),
                           func.coalesce(func.sum(TelemetryRow.input_tokens), 0),
                           func.coalesce(func.sum(TelemetryRow.output_tokens), 0),
                           func.coalesce(func.sum(TelemetryRow.call_ms), 0))
                    .group_by(TelemetryRow.repo)
                    .order_by(TelemetryRow.repo)).all():
                by_repo[rrepo] = {"runs": n, "input_tokens": int(tin),
                                  "output_tokens": int(tout),
                                  "call_ms": int(tcall)}

        return {
            "reviews_total": total,
            "fallback_rate": round(fallback_count / total * 100, 1) if total else 0.0,
            "avg_duration_s": round(duration_sum / total / 1000, 2) if total else 0.0,
            "avg_health_score": round(health_sum / total, 1) if total else 100.0,
            "severity_distribution": {s: sev_counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
            "engine_distribution": engine_counts,
            "telemetry": _telemetry_assemble(
                runs, int(in_sum), int(out_sum), int(call_sum), call_n,
                state_counts, by_repo),
        }

    def record_feedback(self, fingerprint: str, kind: str, repo: str = "", note: str = "") -> dict:
        """Persist feedback. Only 'mute' writes to repo memory (as a
        ``fingerprint:<fp>`` row the reviewer reads back as a dismissal);
        'up'/'down' are votes, not a request to stop reporting."""
        from .models_db import RepoMemoryRow
        
        entry = {
            "fingerprint": fingerprint,
            "kind": kind,
            "repo": repo,
            "note": note,
            "recorded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        }
        
        if kind == "mute" and repo:
            from sqlalchemy import select

            # D7 fix: a mute row is identified by repo + its
            # ``fingerprint:<fp>`` path pattern — never by the repo string,
            # which is not a RepoMemoryRow primary key (ids are "repo#uuid").
            # Look the existing row up by its real identity and reuse it, so
            # N mute requests for one fingerprint leave exactly one row.
            pattern = _schema().mute_pattern(fingerprint)
            with self.Session() as session:
                mem_row = session.execute(
                    select(RepoMemoryRow).where(RepoMemoryRow.repo == repo,
                                                RepoMemoryRow.path_pattern == pattern)
                ).scalars().first()
                if mem_row is None:
                    mem_row = RepoMemoryRow(id=_schema().memory_row_key(repo),
                                            repo=repo, path_pattern=pattern,
                                            note=note or f"Muted finding {fingerprint}")
                elif note:
                    mem_row.note = note      # upsert: a repeated mute may update its note
                session.add(mem_row)
                session.commit()
        return entry

    def get_repo_badge_stats(self, repo: str) -> dict:
        """Return latest health score and review count for badge generation."""
        from sqlalchemy import select
        from .models_db import ReportRow
        
        with self.Session() as session:
            rows = session.execute(
                select(ReportRow)
                .where(ReportRow.repo == repo)
                .order_by(ReportRow.reviewed_at.desc())
                .limit(10)
            ).scalars().all()
        
        if not rows:
            return {"repo": repo, "reviews": 0, "avg_health_score": 100, "grade": "A+"}
        
        scores = [r.payload.get("health_score", 100) if r.payload else 100 for r in rows]
        avg = round(sum(scores) / len(scores)) if scores else 100
        
        if avg >= 90:
            grade = "A+"
        elif avg >= 80:
            grade = "A"
        elif avg >= 70:
            grade = "B"
        elif avg >= 55:
            grade = "C"
        else:
            grade = "D"
        
        return {"repo": repo, "reviews": len(rows), "avg_health_score": avg, "grade": grade}

    # ------------------------------------------------------------- review state
    def get_last_reviewed_sha(self, repo: str, pr_number: int) -> str | None:
        from .models_db import ReviewStateRow

        state_id = _schema().repo_pr_key(repo, pr_number)
        with self.Session() as session:
            row = session.get(ReviewStateRow, state_id)
            return row.last_reviewed_sha if row and row.last_reviewed_sha else None

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        from .models_db import ReviewStateRow

        state_id = _schema().repo_pr_key(repo, pr_number)
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        with self.Session() as session:
            row = session.get(ReviewStateRow, state_id) or ReviewStateRow(
                id=state_id, repo=repo, pr_number=pr_number
            )
            row.last_reviewed_sha = sha
            row.base_sha = base_sha
            row.updated_at = now
            session.add(row)
            session.commit()

    def get_previous_findings(self, repo: str, pr_number: int) -> list[dict]:
        from sqlalchemy import select
        from .models_db import FindingHistoryRow

        with self.Session() as session:
            rows = session.execute(
                select(FindingHistoryRow).where(
                    FindingHistoryRow.repo == repo,
                    FindingHistoryRow.pr_number == pr_number,
                )
            ).scalars().all()
            return [dict(r.payload or {}) for r in rows]

    def save_findings(self, review_id: str, findings: list[dict]) -> None:
        from .models_db import FindingHistoryRow

        repo, pr_number = _schema().parse_review_id(review_id)

        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        with self.Session() as session:
            for item in findings:
                f_dict = dict(item)
                item_repo = repo or f_dict.get("repo", "")
                item_pr = pr_number or int(f_dict.get("pr_number", 0))
                fp = f_dict.get("fingerprint") or ""
                if not fp:
                    try:
                        from ai_pr_reviewer.findings import fingerprint_finding
                        from ai_pr_reviewer.models import Finding
                        fp = fingerprint_finding(Finding.from_dict(f_dict))
                        f_dict["fingerprint"] = fp
                    except Exception:
                        fp = str(f_dict.get("title", ""))[:64]
                row_id = _schema().finding_history_key(item_repo, item_pr, fp)
                row = session.get(FindingHistoryRow, row_id) or FindingHistoryRow(
                    id=row_id, repo=item_repo, pr_number=item_pr, fingerprint=fp
                )
                row.state = f_dict.get("state", "new")
                row.first_seen_sha = f_dict.get("first_seen_sha", "") or ""
                row.last_seen_sha = f_dict.get("last_seen_sha", "") or ""
                row.resolved_at = f_dict.get("resolved_at", "") or ""
                row.payload = f_dict
                row.updated_at = now
                session.add(row)
            session.commit()

    # ----------------------------------------------------- V3-E02-T04 telemetry
    def save_telemetry(self, review_id: str, telemetry: dict) -> None:
        """Upsert one run's telemetry row.

        Additive table (``init()``'s ``create_all`` only adds it), so an
        existing dashboard database keeps every old report untouched.
        Token columns stay ``NULL`` unless usage state is ``ok`` — an
        unavailable count must not read back as a measured 0.

        V3-E02-T06: the payload is re-sanitized *at this boundary* —
        nothing arbitrary can be persisted by handing save_telemetry a
        raw dict; non-dict input is not persisted at all.
        """
        from ai_pr_reviewer.telemetry import sanitize_telemetry

        from .models_db import TelemetryRow

        data = sanitize_telemetry(telemetry)
        if data is None:
            return
        repo, pr_number = _schema().parse_review_id(review_id)
        usage = data.get("usage") or {}
        reported = usage.get("state") == "ok"
        duration = usage.get("duration_ms")
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        with self.Session() as session:
            row = session.get(TelemetryRow, review_id)
            if row is None:
                row = TelemetryRow(id=review_id, repo=repo, pr_number=pr_number)
            row.repo = row.repo or repo
            row.pr_number = row.pr_number or pr_number
            row.provider = str(data.get("provider", ""))
            row.model = str(data.get("model", ""))
            row.input_tokens = usage.get("input_tokens") if reported else None
            row.output_tokens = usage.get("output_tokens") if reported else None
            row.usage_state = str(usage.get("state", "n/a"))
            row.batch_count = int(data.get("batch_count", 0) or 0)
            row.fallback_used = 1 if data.get("fallback_used") else 0
            row.call_ms = duration if type(duration) is int else None
            row.updated_at = now
            row.payload = dict(data)
            session.add(row)
            session.commit()

    def get_telemetry(self, review_id: str) -> dict | None:
        """The stored row for ``review_id``, or None (missing rows must
        never break reads)."""
        from .models_db import TelemetryRow

        with self.Session() as session:
            row = session.get(TelemetryRow, review_id)
            if row is None or not row.payload:
                return None
            return dict(row.payload)

    def get_repo_memory(self, repo: str, paths: list[str]) -> list[str]:
        from sqlalchemy import select
        from .models_db import RepoMemoryRow

        with self.Session() as session:
            rows = session.execute(
                select(RepoMemoryRow).where(RepoMemoryRow.repo == repo)
            ).scalars().all()
            notes: list[str] = []
            for r in rows:
                pat = r.path_pattern or "*"
                if any(fnmatch.fnmatch(p, pat) for p in paths):
                    notes.append(r.note)
            return notes

    def list_repo_memory(self, repo: str) -> list[dict]:
        """Every memory row for ``repo``, verbatim.

        Includes ``fingerprint:<fp>`` mute rows, disabled rows, the id and
        the category — callers decide which ones they want (the API returns
        them; the reviewer splits them with ``ai_pr_reviewer.memory``).
        """
        from sqlalchemy import select
        from .models_db import RepoMemoryRow

        with self.Session() as session:
            rows = session.execute(
                select(RepoMemoryRow).where(RepoMemoryRow.repo == repo)
            ).scalars().all()
            return [{"id": r.id,
                     "note": r.note,
                     "path_pattern": r.path_pattern or "*",
                     "category": getattr(r, "category", "") or "",
                     "enabled": bool(getattr(r, "enabled", 1))}
                    for r in rows]

    def get_dismissed_fingerprints(self, repo: str) -> set[str]:
        """Fingerprints muted for ``repo`` (V3-E04-T04).

        The direct reader for ``record_feedback``'s mute rows — the same
        rows the engine's HTTP client reads back, so both paths produce
        identical sets (enforced by the T07 parity suite).
        """
        from sqlalchemy import select

        from .models_db import RepoMemoryRow

        with self.Session() as session:
            patterns = session.execute(
                select(RepoMemoryRow.path_pattern).where(
                    RepoMemoryRow.repo == repo)
            ).scalars().all()
        out: set[str] = set()
        for pattern in patterns:
            fp = _schema().mute_fingerprint(pattern)
            if fp:
                out.add(fp)
        return out

    def prune(self, retention_days: int, *, dry_run: bool = False,
              now=None) -> dict:
        """Delete aged finding-history and telemetry rows (V3-E04-T02).

        Same policy, cutoff and safety rules as the engine's
        ``LocalReviewStorage.prune`` (one shared ``retention_cutoff``):
        retention off (``retention_days <= 0``) is a no-op; history goes
        only when its PR's review state exists and is itself older than
        the cutoff; telemetry ages out alone; repo memory, review states,
        reports and the audit trail are never touched; unknown
        timestamps are never pruned. Idempotent and resumable;
        ``dry_run`` reports counts without deleting — observe it before
        enabling (DATA_MODEL §6).
        """
        from sqlalchemy import text

        cutoff = _schema().retention_cutoff(retention_days, now=now)
        outcome: dict = {"enabled": cutoff is not None, "cutoff": cutoff,
                         "dry_run": bool(dry_run), "finding_history": 0,
                         "telemetry": 0}
        if cutoff is None:
            return outcome
        history_where = (
            "updated_at IS NOT NULL AND updated_at <> '' "
            "AND updated_at < :cutoff AND EXISTS ("
            "SELECT 1 FROM review_states rs "
            "WHERE rs.repo = finding_histories.repo "
            "AND rs.pr_number = finding_histories.pr_number "
            "AND rs.updated_at IS NOT NULL AND rs.updated_at <> '' "
            "AND rs.updated_at < :cutoff)")
        telemetry_where = (
            "updated_at IS NOT NULL AND updated_at <> '' AND updated_at < :cutoff")
        verb = "SELECT COUNT(*) FROM" if dry_run else "DELETE FROM"
        with self.engine.begin() as conn:
            hist = conn.execute(text(
                f"{verb} finding_histories WHERE {history_where}"),
                {"cutoff": cutoff})
            outcome["finding_history"] = (hist.scalar() if dry_run
                                          else hist.rowcount) or 0
            tel = conn.execute(text(
                f"{verb} telemetry WHERE {telemetry_where}"),
                {"cutoff": cutoff})
            outcome["telemetry"] = (tel.scalar() if dry_run
                                    else tel.rowcount) or 0
        return outcome

    def add_repo_memory(self, repo: str, path_pattern: str, note: str,
                        category: str = "", enabled: bool = True) -> None:
        from .models_db import RepoMemoryRow

        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        mid = _schema().memory_row_key(repo)
        with self.Session() as session:
            row = RepoMemoryRow(
                id=mid, repo=repo, path_pattern=path_pattern, note=note,
                created_at=now, updated_at=now,
                category=_normalize_category(category),
                enabled=1 if enabled else 0,
            )
            session.add(row)
            session.commit()

    def update_repo_memory(self, repo: str, memory_id: str,
                           fields: dict) -> dict | None:
        """Edit one memory row; returns it, or None when it isn't this repo's.

        Only the editable columns are accepted (an id or a created_at in the
        payload is ignored), and the category is normalized so the reviewer
        can rely on a small known set.
        """
        from sqlalchemy import select
        from .models_db import RepoMemoryRow

        editable = {k: v for k, v in fields.items()
                    if k in ("path_pattern", "note", "category", "enabled")}
        if not editable:
            return None
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        with self.Session() as session:
            row = session.execute(
                select(RepoMemoryRow).where(RepoMemoryRow.id == memory_id,
                                            RepoMemoryRow.repo == repo)
            ).scalars().first()
            if row is None:
                return None
            for key, value in editable.items():
                if key == "enabled":
                    row.enabled = 1 if value else 0
                elif key == "category":
                    row.category = _normalize_category(value)
                elif key == "path_pattern":
                    row.path_pattern = str(value)[:255] or "*"
                else:
                    row.note = str(value)[:_max_note_chars()]
            row.updated_at = now
            session.commit()
            return {"id": row.id, "note": row.note,
                    "path_pattern": row.path_pattern or "*",
                    "category": row.category or "",
                    "enabled": bool(row.enabled)}

    def delete_repo_memory(self, repo: str, memory_id: str) -> bool:
        from sqlalchemy import delete as sa_delete
        from .models_db import RepoMemoryRow

        with self.Session() as session:
            res = session.execute(sa_delete(RepoMemoryRow)
                                  .where(RepoMemoryRow.id == memory_id,
                                         RepoMemoryRow.repo == repo))
            session.commit()
            return bool(res.rowcount)

    # -------------------------------------------------------------- migration
    def _migrate_json_once(self) -> None:
        """One-time import of legacy JSON-file reports (prototype era)."""
        if self.json_dir is None or not self.json_dir.exists():
            return
        marker = self.json_dir.parent / ".migrated"
        if marker.exists():
            return
        imported = 0
        for path in sorted(self.json_dir.glob("*.json")):
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(report, dict) and report.get("id"):
                    self.upsert(report)
                    imported += 1
            except Exception:
                continue
        marker.write_text(
            f"migrated {imported} report(s) from {self.json_dir} "
            f"at {os.environ.get('MIGRATED_AT', '')}\n", encoding="utf-8")


class JsonStorage:
    """Prototype JSON-file storage — zero dependencies, demo only.

    Writes are atomic (tmp file + os.replace) and serialized by a process-wide
    lock, but this backend does NOT support multiple workers or hosts. Use
    ``DATABASE_URL`` for anything real.
    """

    def __init__(self, reports_dir: Path, data_dir: Path | None = None):
        self.reports_dir = reports_dir
        self.data_dir = data_dir or reports_dir.parent
        self.backend = "json-files (prototype)"
        self._lock = threading.Lock()
        # V3-E04-T04: same declared capability set as the SQL backend;
        # resolved lazily so importing this module works without the engine.
        schema = _schema()
        self.capabilities = schema.CORE_CAPABILITIES | {
            schema.CAP_LIST_REPO_MEMORY,
            schema.CAP_DISMISSED_FINGERPRINTS,
            schema.CAP_TELEMETRY,
            schema.CAP_PRUNE,
        }

    def _path(self, rid: str) -> Path:
        return self.reports_dir / f"{rid}.json"

    def _state_file(self) -> Path:
        return self.data_dir / "reviews_state.json"

    @staticmethod
    def _slug(repo: str) -> str:
        # Defense in depth to match the DB backend's parameterized-query
        # safety: repo comes straight from the API's path params, so collapse
        # anything other than [a-z0-9._-] rather than relying solely on the
        # "/" -> "-" swap below to keep this a single path component.
        return re.sub(r"[^a-z0-9._-]", "-", repo.replace("/", "-").lower())

    def _findings_file(self, repo: str, pr_number: int) -> Path:
        slug = self._slug(repo)
        d = self.data_dir / "findings"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{slug}_{int(pr_number)}.json"

    def _memory_file(self) -> Path:
        return self.data_dir / "repo_memory.json"

    def _telemetry_file(self) -> Path:
        return self.data_dir / "telemetry.json"

    def init(self) -> None:
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)

    def upsert(self, report: dict) -> str:
        findings = report.get("findings", [])
        if len(findings) > MAX_FINDINGS_STORED:
            report = {**report, "findings": findings[:MAX_FINDINGS_STORED],
                      "truncated_findings": True}
        rid = report["id"]
        with self._lock:
            self.reports_dir.mkdir(parents=True, exist_ok=True)
            tmp = self._path(rid).with_suffix(".tmp")
            tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
            os.replace(tmp, self._path(rid))
        return rid

    def get(self, rid: str) -> dict | None:
        path = self._path(rid)
        if not path.exists():
            return None
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload.setdefault("id", rid)
        return payload

    def delete(self, rid: str) -> bool:
        path = self._path(rid)
        if not path.exists():
            return False
        path.unlink()
        return True

    def list(self, limit: int = 50, offset: int = 0) -> list[dict]:
        items = []
        for path in self.reports_dir.glob("*.json"):
            try:
                items.append(summarize(json.loads(path.read_text("utf-8"))))
            except Exception:
                continue
        items.sort(key=lambda r: (r["reviewed_at"], r["id"]), reverse=True)
        return items[offset:offset + limit]

    def stats(self) -> dict:
        sev, cats, repos = Counter(), Counter(), Counter()
        reports = findings = files = 0
        for path in self.reports_dir.glob("*.json"):
            try:
                report = json.loads(path.read_text("utf-8"))
            except Exception:
                continue
            reports += 1
            files += (report.get("stats") or {}).get("files", 0)
            # V3-E04-T05: "" maps to "?" exactly like the SQL backend's
            # COALESCE(NULLIF(repo, ''), '?') so top_repos matches.
            repos[(report.get("pr") or {}).get("repo") or "?"] += 1
            for f in report.get("findings", []):
                sev[f.get("severity")] += 1
                cats[f.get("category")] += 1
                findings += 1
        return {
            "reports": reports, "findings": findings,
            "by_severity": {s: sev.get(s, 0) for s in SEV_KEYS},
            # V3-E04-T05: _top_counter (count desc, key asc) replaces
            # most_common so this matches the SQL backend on ties.
            "by_category": _top_counter(cats.items(), 8),
            "top_repos": _top_counter(repos.items(), 5),
            "files_analyzed": files,
        }

    def list_findings(self, state: str = "", severity: str = "",
                      repo: str = "", limit: int = 100, offset: int = 0) -> list[dict]:
        # V3-E04-T05: bounded scan — stop once the window is full; the
        # slice below keeps page semantics identical. (File granularity:
        # the repo filter can only apply after a file is read.)
        offset = max(0, int(offset))
        limit = max(0, int(limit))
        if limit == 0:
            return []
        need = offset + limit
        results = []
        for path in sorted(self.reports_dir.glob("*.json"), key=os.path.getmtime, reverse=True):
            try:
                report = json.loads(path.read_text("utf-8"))
            except Exception:
                continue
            
            r_repo = (report.get("pr") or {}).get("repo", "")
            if repo and r_repo != repo:
                continue
                
            for f in report.get("findings", [])[:MAX_FINDINGS_STORED]:
                f_state = f.get("state", "new")
                f_sev = f.get("severity", "medium")
                if state and f_state != state:
                    continue
                if severity and f_sev != severity:
                    continue
                results.append({
                    **f,
                    "repo": r_repo,
                    "pr_number": (report.get("pr") or {}).get("number", 0),
                    "pr_title": (report.get("pr") or {}).get("title", ""),
                    "reviewed_at": report.get("reviewed_at", ""),
                    "report_id": report.get("id"),
                })
            if len(results) >= need:
                break
        return results[offset:offset + limit]

    def metrics(self) -> dict:
        total = 0
        fallback_count = 0
        duration_sum = 0
        health_sum = 0
        engine_counts: Counter = Counter()
        sev_counts: Counter = Counter()
        
        for path in self.reports_dir.glob("*.json"):
            try:
                report = json.loads(path.read_text("utf-8"))
            except Exception:
                continue
            total += 1
            if report.get("fallback_used"):
                fallback_count += 1
            duration_sum += report.get("duration_ms", 0)
            health_sum += report.get("health_score", 100)
            engine = report.get("engine", "static")
            engine_counts[engine] += 1
            for f in report.get("findings", []):
                sev_counts[f.get("severity", "medium")] += 1

        # V3-E02-T05: additive telemetry series from telemetry.json —
        # legacy keys above untouched; no telemetry file yields a zero
        # series rather than an error.
        telemetry_rows: list[dict] = []
        for item in self._read_memory_rows(self._telemetry_file()) or []:
            usage = item.get("usage") or {}
            state = str(usage.get("state") or "n/a")
            reported = state == "ok"
            duration = usage.get("duration_ms")
            telemetry_rows.append({
                "repo": str(item.get("repo") or ""),
                "usage_state": state,
                "input_tokens": usage.get("input_tokens") if reported else None,
                "output_tokens": usage.get("output_tokens") if reported else None,
                "call_ms": duration if type(duration) is int else None,
            })

        return {
            "reviews_total": total,
            "fallback_rate": round(fallback_count / total * 100, 1) if total else 0.0,
            "avg_duration_s": round(duration_sum / total / 1000, 2) if total else 0.0,
            "avg_health_score": round(health_sum / total, 1) if total else 100.0,
            "severity_distribution": {s: sev_counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
            # V3-E04-T05: _top_counter matches the SQL backend's
            # ORDER BY count DESC, engine on ties.
            "engine_distribution": _top_counter(engine_counts.items()),
            "telemetry": _telemetry_summary(telemetry_rows),
        }

    def record_feedback(self, fingerprint: str, kind: str, repo: str = "", note: str = "") -> dict:
        entry = {
            "fingerprint": fingerprint,
            "kind": kind,
            "repo": repo,
            "note": note,
            "recorded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        }
        
        if kind == "mute" and repo:
            # D7 fix (parity with DbStorage): a mute is keyed by repo +
            # its "fingerprint:<fp>" pattern — repeat requests reuse the
            # single row instead of minting a duplicate per click.
            pattern = _schema().mute_pattern(fingerprint)
            now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
            with self._lock:
                p = self._memory_file()
                items: list = []
                if p.exists():
                    try:
                        items = json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        items = []
                existing = next((r for r in items
                                 if r.get("repo") == repo
                                 and r.get("path_pattern") == pattern), None)
                if existing is None:
                    items.append({
                        "id": _schema().memory_row_key(repo),
                        "repo": repo,
                        "path_pattern": pattern,
                        "note": note or f"Muted finding {fingerprint}",
                        "created_at": now,
                        "updated_at": now,
                        "category": _normalize_category(""),
                        "enabled": True,
                    })
                elif note:
                    existing["note"] = note      # upsert: update the note
                    existing["updated_at"] = now
                self._write_memory_rows(p, items)

        return entry

    def get_repo_badge_stats(self, repo: str) -> dict:
        reports = []
        for path in sorted(self.reports_dir.glob("*.json"), key=os.path.getmtime, reverse=True):
            try:
                report = json.loads(path.read_text("utf-8"))
                if (report.get("pr") or {}).get("repo") == repo:
                    reports.append(report)
                    if len(reports) >= 10:
                        break
            except Exception:
                continue
                
        if not reports:
            return {"repo": repo, "reviews": 0, "avg_health_score": 100, "grade": "A+"}
            
        scores = [r.get("health_score", 100) for r in reports]
        avg = round(sum(scores) / len(scores)) if scores else 100
        
        if avg >= 90:
            grade = "A+"
        elif avg >= 80:
            grade = "A"
        elif avg >= 70:
            grade = "B"
        elif avg >= 55:
            grade = "C"
        else:
            grade = "D"
        
        return {"repo": repo, "reviews": len(reports), "avg_health_score": avg, "grade": grade}

    # ------------------------------------------------------------- review state
    def get_last_reviewed_sha(self, repo: str, pr_number: int) -> str | None:
        with self._lock:
            p = self._state_file()
            if not p.exists():
                return None
            try:
                states = json.loads(p.read_text(encoding="utf-8"))
                return states.get(_schema().repo_pr_key(repo, pr_number), {}).get("last_reviewed_sha")
            except Exception:
                return None

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        key = _schema().repo_pr_key(repo, pr_number)
        with self._lock:
            p = self._state_file()
            states = {}
            if p.exists():
                try:
                    states = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    states = {}
            states[key] = {"last_reviewed_sha": sha, "base_sha": base_sha, "updated_at": now}
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(states, indent=2), encoding="utf-8")
            os.replace(tmp, p)

    def get_previous_findings(self, repo: str, pr_number: int) -> list[dict]:
        with self._lock:
            p = self._findings_file(repo, pr_number)
            if not p.exists():
                return []
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                return list(data.values()) if isinstance(data, dict) else []
            except Exception:
                return []

    def save_findings(self, review_id: str, findings: list[dict]) -> None:
        repo, pr_number = _schema().parse_review_id(review_id)

        if not (repo and pr_number) and findings:
            first = findings[0] if isinstance(findings[0], dict) else dict(findings[0])
            repo = first.get("repo", repo)
            pr_number = int(first.get("pr_number", pr_number or 0))

        if not (repo and pr_number):
            return

        with self._lock:
            p = self._findings_file(repo, pr_number)
            existing = {}
            if p.exists():
                try:
                    existing = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    existing = {}
            for item in findings:
                f_dict = dict(item)
                # Compute a missing fingerprint exactly like the DB
                # backend does, so both dashboard backends hand the same
                # payload back — the reviewer's state machine keys on it
                # (V3-E04-T07 parity).
                fp = f_dict.get("fingerprint") or ""
                if not fp:
                    try:
                        from ai_pr_reviewer.findings import fingerprint_finding
                        from ai_pr_reviewer.models import Finding
                        fp = fingerprint_finding(Finding.from_dict(f_dict))
                        f_dict["fingerprint"] = fp
                    except Exception:
                        fp = str(f_dict.get("title", ""))[:64]
                existing[fp] = f_dict
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(existing, indent=2), encoding="utf-8")
            os.replace(tmp, p)

    def get_repo_memory(self, repo: str, paths: list[str]) -> list[str]:
        with self._lock:
            p = self._memory_file()
            if not p.exists():
                return []
            try:
                items = json.loads(p.read_text(encoding="utf-8"))
                notes = []
                for item in items:
                    if item.get("repo") == repo:
                        pat = item.get("path_pattern", "*")
                        if any(fnmatch.fnmatch(path, pat) for path in paths):
                            notes.append(item.get("note", ""))
                return notes
            except Exception:
                return []

    def list_repo_memory(self, repo: str) -> list[dict]:
        """Every memory row for ``repo``, verbatim — including
        ``fingerprint:<fp>`` mute rows, disabled rows, id and category."""
        with self._lock:
            p = self._memory_file()
            if not p.exists():
                return []
            try:
                items = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return []
            return [{"id": item.get("id", ""),
                     "note": item.get("note", ""),
                     "path_pattern": item.get("path_pattern", "*"),
                     "category": item.get("category", "") or "",
                     "enabled": bool(item.get("enabled", True))}
                    for item in items if item.get("repo") == repo]

    def get_dismissed_fingerprints(self, repo: str) -> set[str]:
        """Fingerprints muted for ``repo`` (V3-E04-T04).

        Mute rows in ``repo_memory.json``, filtered exactly like the DB
        backend filters ``RepoMemoryRow`` (T07 parity).
        """
        with self._lock:
            p = self._memory_file()
            if not p.exists():
                return set()
            try:
                items = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                return set()
        out: set[str] = set()
        for item in items:
            if item.get("repo") == repo:
                fp = _schema().mute_fingerprint(item.get("path_pattern"))
                if fp:
                    out.add(fp)
        return out

    def prune(self, retention_days: int, *, dry_run: bool = False,
              now=None) -> dict:
        """Same retention policy as the DB backend, at file granularity.

        A ``findings`` file holds one PR's whole history, so it is
        pruned only when the file itself predates the cutoff **and** that
        PR's review state exists and is older than the cutoff — missing
        or unknown-age state protects the file (the same conservative
        rule the SQL DELETE applies to rows). Telemetry rows are filtered
        by their own ``updated_at`` like everywhere else; repo memory,
        review states, reports and the audit trail are never touched.
        ``finding_history`` counts *files* here (this backend's row
        granularity), ``telemetry`` counts rows. Idempotent and
        resumable; dry-run first (DATA_MODEL §6).
        """
        schema = _schema()
        cutoff = schema.retention_cutoff(retention_days, now=now)
        outcome: dict = {"enabled": cutoff is not None, "cutoff": cutoff,
                         "dry_run": bool(dry_run), "finding_history": 0,
                         "telemetry": 0}
        if cutoff is None:
            return outcome
        cutoff_epoch = _dt.datetime.fromisoformat(cutoff).timestamp()

        # Positively-known-stale review states make their PR's history
        # file prunable; everything else (missing/fresh/unknown state) is
        # protected by staying out of this set.
        pruneable: set[str] = set()
        with self._lock:
            states: dict = {}
            state_path = self._state_file()
            if state_path.exists():
                try:
                    loaded = json.loads(state_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        states = loaded
                except Exception:
                    states = {}
        for key, entry in states.items():
            updated = entry.get("updated_at") if isinstance(entry, dict) else None
            if schema.is_stale(updated, cutoff):
                repo, _, pr = str(key).partition("#")
                if pr.isdigit():
                    pruneable.add(f"{self._slug(repo)}_{int(pr)}")

        findings_dir = self.data_dir / "findings"
        if pruneable and findings_dir.is_dir():
            for path in sorted(findings_dir.glob("*.json")):
                if path.stem not in pruneable:
                    continue                       # unknown/active state → keep
                try:
                    if path.stat().st_mtime >= cutoff_epoch:
                        continue                   # touched inside the window
                except OSError:
                    continue                       # vanished or unreadable → keep
                outcome["finding_history"] += 1
                if not dry_run:
                    try:
                        path.unlink()
                    except OSError:
                        pass                       # rerun resumes this file

        def _stale(item) -> bool:
            return (isinstance(item, dict)
                    and schema.is_stale(item.get("updated_at"), cutoff))

        with self._lock:
            items = self._read_memory_rows(self._telemetry_file()) or []
            stale = [it for it in items if _stale(it)]
            outcome["telemetry"] = len(stale)
            if stale and not dry_run:
                self._write_memory_rows(
                    self._telemetry_file(), [it for it in items if not _stale(it)])
        return outcome

    def add_repo_memory(self, repo: str, path_pattern: str, note: str,
                        category: str = "", enabled: bool = True) -> None:
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            p = self._memory_file()
            items = []
            if p.exists():
                try:
                    items = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    items = []
            items.append({
                "id": _schema().memory_row_key(repo),
                "repo": repo,
                "path_pattern": path_pattern,
                "note": note,
                "created_at": now,
                "updated_at": now,
                "category": _normalize_category(category),
                "enabled": bool(enabled),
            })
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
            os.replace(tmp, p)

    # ----------------------------------------------------- V3-E02-T04 telemetry
    def save_telemetry(self, review_id: str, telemetry: dict) -> None:
        """Upsert one run's telemetry row into ``telemetry.json``.

        One row per review id (re-posts replace, they don't stack), same
        NULL-not-0 token semantics as the DB backend — the blob format
        carries no schema, so absence rides in the typed usage state.

        V3-E02-T06: the payload is re-sanitized *at this boundary*, and
        it is spread AFTER the storage metadata keys — a planted
        ``id``/``repo``/``updated_at`` in the payload cannot overwrite
        the row's own metadata. Non-dict input is not persisted at all.
        """
        from ai_pr_reviewer.telemetry import sanitize_telemetry

        data = sanitize_telemetry(telemetry)
        if data is None:
            return
        repo, pr_number = _schema().parse_review_id(review_id)
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            p = self._telemetry_file()
            items = self._read_memory_rows(p) or []
            row = {"id": review_id, "repo": repo, "pr_number": pr_number,
                   "updated_at": now, **data}
            items = [i for i in items if i.get("id") != review_id]
            items.append(row)
            self._write_memory_rows(p, items)

    def get_telemetry(self, review_id: str) -> dict | None:
        """The stored row for ``review_id``, or None (missing rows must
        never break reads)."""
        with self._lock:
            items = self._read_memory_rows(self._telemetry_file()) or []
        for item in items:
            if item.get("id") == review_id:
                return dict(item)
        return None

    def _write_memory_rows(self, p: Path, items: list) -> None:
        tmp = p.with_suffix(".tmp")
        tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
        os.replace(tmp, p)

    def _read_memory_rows(self, p: Path) -> list | None:
        if not p.exists():
            return None
        try:
            items = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
        return items if isinstance(items, list) else None

    def update_repo_memory(self, repo: str, memory_id: str,
                           fields: dict) -> dict | None:
        editable = {k: v for k, v in fields.items()
                    if k in ("path_pattern", "note", "category", "enabled")}
        if not editable:
            return None
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        with self._lock:
            p = self._memory_file()
            items = self._read_memory_rows(p)
            if items is None:
                return None
            updated_row: dict | None = None
            for index, item in enumerate(items):
                if item.get("repo") != repo or item.get("id") != memory_id:
                    continue
                updated = dict(item)
                for key, value in editable.items():
                    if key == "enabled":
                        updated["enabled"] = bool(value)
                    elif key == "category":
                        updated["category"] = _normalize_category(value)
                    elif key == "path_pattern":
                        updated["path_pattern"] = str(value)[:255] or "*"
                    else:
                        updated["note"] = str(value)[:_max_note_chars()]
                updated["updated_at"] = now
                items[index] = updated
                updated_row = {
                    "id": updated.get("id", ""),
                    "note": updated.get("note", ""),
                    "path_pattern": updated.get("path_pattern", "*"),
                    "category": updated.get("category", ""),
                    "enabled": bool(updated.get("enabled", True)),
                }
                break
            if updated_row is None:
                return None
            self._write_memory_rows(p, items)
            return updated_row

    def delete_repo_memory(self, repo: str, memory_id: str) -> bool:
        with self._lock:
            p = self._memory_file()
            items = self._read_memory_rows(p)
            if items is None:
                return False
            kept = [item for item in items
                    if not (item.get("repo") == repo
                            and item.get("id") == memory_id)]
            if len(kept) == len(items):
                return False
            self._write_memory_rows(p, kept)
            return True


def choose_storage(data_dir: Path, database_url: str | None):
    """Pick a backend: explicit DATABASE_URL > SQLite (default) > JSON files
    (only if SQLAlchemy is unavailable)."""
    database_url = (database_url or os.environ.get("DATABASE_URL") or "").strip()
    try:
        import sqlalchemy  # noqa: F401
    except ImportError:
        return JsonStorage(data_dir / "reports", data_dir=data_dir)

    if database_url:
        storage = DbStorage(database_url, json_dir=data_dir / "reports")
    else:
        storage = DbStorage(f"sqlite:///{(data_dir / 'reviews.db').resolve()}",
                            json_dir=data_dir / "reports")
    return storage
