"""V4-E09 — persistence of feedback votes and suppression rules.

Two mixins, one per dashboard backend, that ``dashboard.storage`` attaches
to ``DbStorage`` (SQLAlchemy) and ``JsonStorage`` (zero-dependency files).
They live in their own module — rather than inside the 1.7k-line storage
file — so this epic adds methods *alongside* the existing ones without
editing any of them, and so merging with the other V4 epics that also touch
``storage.py`` cannot collide.

Every rule in :mod:`ai_pr_reviewer.feedback_admin` is shared: these classes
only do I/O. The planners decide (caps, expiry, redaction, origin); the
stores load a repository's rows, call a planner, and apply its result. So
the SQL and JSON backends cannot drift on any policy.

Isolation: every query and every JSON filter is scoped by ``repo``; the
planners re-assert it; a rule id is only ever looked up *together with* its
repository. There is deliberately no method that lists rules or events
across repositories.

The rule writers take an ``AdminAuthority`` and check it *themselves*
(``feedback_admin.require_authority`` inside the planner) — a caller
cannot forget the check, because it is not the caller's to make.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

# One process-wide lock around check-then-write sections, so the caps hold
# under concurrent requests in a single dashboard process. (Multiple
# worker processes sharing one database can overshoot a cap by at most the
# number of racing writers.)
_FEEDBACK_LOCK = threading.RLock()


def _schema():
    """Engine's shared schema contract, imported at call time (the same
    pattern as the rest of this package)."""
    from ai_pr_reviewer import storage_schema

    return storage_schema


def _admin():
    """The shared write-side planners (dashboard-only importer)."""
    from ai_pr_reviewer import feedback_admin

    return feedback_admin


def _rule_dict(row) -> dict:
    cols = _schema().SUPPRESSION_RULE_COLUMNS
    return {c: getattr(row, c) for c in cols}


def _event_dict(row) -> dict:
    cols = _schema().FEEDBACK_EVENT_COLUMNS
    return {c: getattr(row, c) for c in cols}


def _sort_rules(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda r: (r.get("created_at", ""), r.get("id", "")))


def _filter_rules(rows: list[dict], include_inactive: bool,
                  now: datetime) -> list[dict]:
    admin = _admin()
    if include_inactive:
        return _sort_rules(rows)
    return _sort_rules([r for r in rows if admin.row_is_active(r, now)])


# ===================================================================== SQL
class DbFeedbackMixin:
    """Feedback persistence for ``DbStorage`` (SQLite / PostgreSQL)."""

    # ---------------------------------------------------------------- events
    def record_feedback_event(self, repo: str, spec, origin: str,
                              now: datetime | None = None) -> dict:
        """Persist one vote. Redaction, caps and the ring-buffer prune all
        happen here, in the write path every caller shares."""
        from sqlalchemy import delete, func, select

        from .models_db import FeedbackEventRow

        s, admin = _schema(), _admin()
        moment = s.feedback_now(now)
        with _FEEDBACK_LOCK, self.Session() as session:
            repo = admin.validate_repo(repo)
            total = session.execute(
                select(func.count()).select_from(FeedbackEventRow)
                .where(FeedbackEventRow.repo == repo)).scalar_one()
            recent = session.execute(
                select(func.count()).select_from(FeedbackEventRow)
                .where(FeedbackEventRow.repo == repo,
                       FeedbackEventRow.created_at >= admin.hour_cutoff(moment))
            ).scalar_one()
            drop = admin.check_event_caps(int(total), int(recent))
            row = admin.build_event_row(repo, spec, origin, moment)
            session.add(FeedbackEventRow(**row))
            if drop:
                oldest = session.execute(
                    select(FeedbackEventRow.id)
                    .where(FeedbackEventRow.repo == repo)
                    .order_by(FeedbackEventRow.created_at.asc(),
                              FeedbackEventRow.id.asc())
                    .limit(drop)).scalars().all()
                if oldest:
                    session.execute(delete(FeedbackEventRow).where(
                        FeedbackEventRow.repo == repo,
                        FeedbackEventRow.id.in_(oldest)))
            session.commit()
        return row

    def list_feedback_events(self, repo: str, limit: int = 100,
                             offset: int = 0) -> list[dict]:
        from sqlalchemy import select

        from .models_db import FeedbackEventRow

        repo = _admin().validate_repo(repo)
        limit = max(0, min(int(limit), _schema().MAX_EVENTS_PER_REPO))
        with self.Session() as session:
            rows = session.execute(
                select(FeedbackEventRow)
                .where(FeedbackEventRow.repo == repo)
                .order_by(FeedbackEventRow.created_at.desc(),
                          FeedbackEventRow.id.desc())
                .limit(limit).offset(max(0, int(offset)))).scalars().all()
            return [_event_dict(r) for r in rows]

    # ----------------------------------------------------------------- rules
    def get_suppression_rules(self, repo: str, include_inactive: bool = False,
                              now: datetime | None = None) -> list[dict]:
        """Rules of exactly ``repo``; in-force only unless asked. The
        ``repo`` filter is in the SQL, never applied after the fact."""
        from sqlalchemy import select

        from .models_db import SuppressionRuleRow

        s = _schema()
        repo = _admin().validate_repo(repo)
        moment = s.feedback_now(now)
        with self.Session() as session:
            query = select(SuppressionRuleRow).where(
                SuppressionRuleRow.repo == repo)
            if not include_inactive:
                query = query.where(
                    SuppressionRuleRow.disabled_at == "",
                    SuppressionRuleRow.expires_at > s.feedback_iso(moment))
            rows = session.execute(
                query.order_by(SuppressionRuleRow.created_at.asc(),
                               SuppressionRuleRow.id.asc())
                .limit(s.MAX_STORED_RULES_PER_REPO)).scalars().all()
            return _filter_rules([_rule_dict(r) for r in rows],
                                 include_inactive, moment)

    def _all_rule_rows(self, session, repo: str) -> list[dict]:
        from sqlalchemy import select

        from .models_db import SuppressionRuleRow

        rows = session.execute(select(SuppressionRuleRow).where(
            SuppressionRuleRow.repo == repo)).scalars().all()
        return [_rule_dict(r) for r in rows]

    def create_suppression_rule(self, authority, repo: str, spec,
                                now: datetime | None = None
                                ) -> tuple[dict, bool]:
        """Create one rule -> ``(row, created)``. ``created`` is False when
        an identical in-force rule already existed (idempotent)."""
        from sqlalchemy import delete

        from .models_db import SuppressionRuleRow

        admin = _admin()
        with _FEEDBACK_LOCK, self.Session() as session:
            repo = admin.validate_repo(repo)
            plan = admin.plan_rule_creation(
                self._all_rule_rows(session, repo), repo, spec, authority, now)
            if plan.action == "exists":
                return plan.row, False
            if plan.purge_ids:
                session.execute(delete(SuppressionRuleRow).where(
                    SuppressionRuleRow.repo == repo,
                    SuppressionRuleRow.id.in_(plan.purge_ids)))
            session.add(SuppressionRuleRow(**plan.row))
            session.commit()
            return plan.row, True

    def disable_suppression_rule(self, authority, repo: str, rule_id: str,
                                 now: datetime | None = None
                                 ) -> tuple[dict | None, bool]:
        """Disable one rule of ``repo`` -> ``(row | None, changed)``."""
        from sqlalchemy import update

        from .models_db import SuppressionRuleRow

        admin = _admin()
        with _FEEDBACK_LOCK, self.Session() as session:
            repo = admin.validate_repo(repo)
            row, changed = admin.plan_disable(
                self._all_rule_rows(session, repo), repo, rule_id,
                authority, now)
            if row is not None and changed:
                session.execute(update(SuppressionRuleRow).where(
                    SuppressionRuleRow.repo == repo,          # id AND repo
                    SuppressionRuleRow.id == rule_id
                ).values(disabled_at=row["disabled_at"],
                         updated_at=row["updated_at"]))
                session.commit()
            return row, changed

    def disable_all_suppression_rules(self, authority, repo: str,
                                      now: datetime | None = None) -> int:
        """Disable every in-force rule of ``repo``; returns how many."""
        from sqlalchemy import update

        from .models_db import SuppressionRuleRow

        admin = _admin()
        with _FEEDBACK_LOCK, self.Session() as session:
            repo = admin.validate_repo(repo)
            changed = admin.plan_disable_all(
                self._all_rule_rows(session, repo), repo, authority, now)
            for row in changed:
                session.execute(update(SuppressionRuleRow).where(
                    SuppressionRuleRow.repo == repo,
                    SuppressionRuleRow.id == row["id"]
                ).values(disabled_at=row["disabled_at"],
                         updated_at=row["updated_at"]))
            session.commit()
            return len(changed)


# ==================================================================== JSON
class JsonFeedbackMixin:
    """Feedback persistence for ``JsonStorage`` (prototype file backend).

    Two files under the data dir (``feedback_events.json``,
    ``suppression_rules.json``), each a JSON list of the same row dicts the
    SQL backend stores. Same planners, same caps, same scoping.
    """

    def _feedback_events_file(self) -> Path:
        return self.data_dir / "feedback_events.json"

    def _suppression_rules_file(self) -> Path:
        return self.data_dir / "suppression_rules.json"

    @staticmethod
    def _read_rows(path: Path) -> list[dict]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        return [r for r in data if isinstance(r, dict)] \
            if isinstance(data, list) else []

    @staticmethod
    def _write_rows(path: Path, rows: list[dict]) -> None:
        """Write ``rows`` atomically (tmp file + ``os.replace``).

        Windows can transiently deny the rename while another process (an
        antivirus scanner, an indexer) holds a handle on either side of it,
        so a brief bounded retry absorbs it; any other error — and a
        permission problem that outlasts the retries — still propagates
        unchanged.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        payload = json.dumps(rows, indent=2)
        for attempt in range(4):
            tmp.write_text(payload, encoding="utf-8")
            try:
                os.replace(tmp, path)
                return
            except PermissionError:
                if attempt == 3:
                    raise
                time.sleep(0.05 * (attempt + 1))

    # ---------------------------------------------------------------- events
    def record_feedback_event(self, repo: str, spec, origin: str,
                              now: datetime | None = None) -> dict:
        s, admin = _schema(), _admin()
        moment = s.feedback_now(now)
        with _FEEDBACK_LOCK:
            repo = admin.validate_repo(repo)
            path = self._feedback_events_file()
            rows = self._read_rows(path)
            mine = [r for r in rows if r.get("repo") == repo]
            cutoff = admin.hour_cutoff(moment)
            drop = admin.check_event_caps(
                len(mine),
                sum(1 for r in mine if str(r.get("created_at", "")) >= cutoff))
            row = admin.build_event_row(repo, spec, origin, moment)
            doomed = {r["id"] for r in sorted(
                mine, key=lambda r: (r.get("created_at", ""), r.get("id", "")))[:drop]}
            kept = [r for r in rows if r.get("id") not in doomed]
            kept.append(row)
            self._write_rows(path, kept)
        return row

    def list_feedback_events(self, repo: str, limit: int = 100,
                             offset: int = 0) -> list[dict]:
        repo = _admin().validate_repo(repo)
        limit = max(0, min(int(limit), _schema().MAX_EVENTS_PER_REPO))
        rows = [r for r in self._read_rows(self._feedback_events_file())
                if r.get("repo") == repo]
        rows.sort(key=lambda r: (r.get("created_at", ""), r.get("id", "")),
                  reverse=True)
        return rows[max(0, int(offset)):max(0, int(offset)) + limit]

    # ----------------------------------------------------------------- rules
    def _repo_rules(self, rows: list[dict], repo: str) -> list[dict]:
        return [r for r in rows if r.get("repo") == repo]

    def get_suppression_rules(self, repo: str, include_inactive: bool = False,
                              now: datetime | None = None) -> list[dict]:
        repo = _admin().validate_repo(repo)
        moment = _schema().feedback_now(now)
        with _FEEDBACK_LOCK:
            rows = self._repo_rules(
                self._read_rows(self._suppression_rules_file()), repo)
        return _filter_rules(rows, include_inactive, moment)

    def create_suppression_rule(self, authority, repo: str, spec,
                                now: datetime | None = None
                                ) -> tuple[dict, bool]:
        admin = _admin()
        with _FEEDBACK_LOCK:
            repo = admin.validate_repo(repo)
            path = self._suppression_rules_file()
            rows = self._read_rows(path)
            plan = admin.plan_rule_creation(
                self._repo_rules(rows, repo), repo, spec, authority, now)
            if plan.action == "exists":
                return plan.row, False
            doomed = set(plan.purge_ids)
            kept = [r for r in rows
                    if not (r.get("repo") == repo and r.get("id") in doomed)]
            kept.append(plan.row)
            self._write_rows(path, kept)
            return plan.row, True

    def disable_suppression_rule(self, authority, repo: str, rule_id: str,
                                 now: datetime | None = None
                                 ) -> tuple[dict | None, bool]:
        admin = _admin()
        with _FEEDBACK_LOCK:
            repo = admin.validate_repo(repo)
            path = self._suppression_rules_file()
            rows = self._read_rows(path)
            row, changed = admin.plan_disable(
                self._repo_rules(rows, repo), repo, rule_id, authority, now)
            if row is not None and changed:
                self._write_rows(path, [
                    row if (r.get("repo") == repo and r.get("id") == rule_id)
                    else r for r in rows])
            return row, changed

    def disable_all_suppression_rules(self, authority, repo: str,
                                      now: datetime | None = None) -> int:
        admin = _admin()
        with _FEEDBACK_LOCK:
            repo = admin.validate_repo(repo)
            path = self._suppression_rules_file()
            rows = self._read_rows(path)
            changed = {r["id"]: r for r in admin.plan_disable_all(
                self._repo_rules(rows, repo), repo, authority, now)}
            if changed:
                self._write_rows(path, [
                    changed[r["id"]] if (r.get("repo") == repo
                                         and r.get("id") in changed) else r
                    for r in rows])
            return len(changed)
