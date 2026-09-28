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
import os
import threading
import uuid
from collections import Counter
from pathlib import Path

SEV_KEYS = ("critical", "high", "medium", "low", "info")
MAX_FINDINGS_STORED = 500          # hard cap per report, defense against abuse


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

    def init(self) -> None:
        from .models_db import Base, ReportRow

        Base.metadata.create_all(self.engine)
        if self.engine.dialect.name == "sqlite":
            from sqlalchemy import text

            with self.engine.connect() as conn:
                conn.execute(text("PRAGMA journal_mode=WAL"))
                conn.execute(text("PRAGMA busy_timeout=5000"))
        self._migrate_json_once()

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
            row.severity_counts = {s: counts.get(s, 0) for s in SEV_KEYS}
            row.categories = dict(cats)
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
        from sqlalchemy import select

        from .models_db import ReportRow

        sev = Counter()
        cats = Counter()
        repos = Counter()
        reports = findings = files = 0
        with self.Session() as session:
            for row in session.execute(select(ReportRow)).scalars():
                reports += 1
                findings += row.findings_count
                files += row.files
                sev.update(row.severity_counts or {})
                cats.update(row.categories or {})
                repos[row.repo or "?"] += 1
        return {
            "reports": reports, "findings": findings,
            "by_severity": {s: sev.get(s, 0) for s in SEV_KEYS},
            "by_category": dict(cats.most_common(8)),
            "top_repos": dict(repos.most_common(5)),
            "files_analyzed": files,
        }

    def list_findings(self, state: str = "", severity: str = "",
                      repo: str = "", limit: int = 100, offset: int = 0) -> list[dict]:
        """Return stored findings across all reports, with optional filtering."""
        from sqlalchemy import select
        from .models_db import ReportRow
        
        results = []
        with self.Session() as session:
            query = select(ReportRow).order_by(ReportRow.reviewed_at.desc())
            rows = session.execute(query).scalars().all()
            for row in rows:
                if repo and row.repo != repo:
                    continue
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
        return results[offset:offset + limit]

    def metrics(self) -> dict:
        """Return live computed metrics from all stored reviews."""
        from sqlalchemy import select
        from .models_db import ReportRow
        
        total = 0
        fallback_count = 0
        duration_sum = 0
        health_sum = 0
        engine_counts: Counter = Counter()
        sev_counts: Counter = Counter()
        
        with self.Session() as session:
            for row in session.execute(select(ReportRow)).scalars():
                total += 1
                payload = row.payload or {}
                if payload.get("fallback_used"):
                    fallback_count += 1
                duration_sum += row.duration_ms or 0
                health_sum += payload.get("health_score", 100)
                engine = payload.get("engine", "static")
                engine_counts[engine] += 1
                for sev, cnt in (row.severity_counts or {}).items():
                    sev_counts[sev] += cnt
        
        return {
            "reviews_total": total,
            "fallback_rate": round(fallback_count / total * 100, 1) if total else 0.0,
            "avg_duration_s": round(duration_sum / total / 1000, 2) if total else 0.0,
            "avg_health_score": round(health_sum / total, 1) if total else 100.0,
            "severity_distribution": {s: sev_counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
            "engine_distribution": dict(engine_counts.most_common()),
        }

    def record_feedback(self, fingerprint: str, kind: str, repo: str = "", note: str = "") -> dict:
        """Persist feedback. 'down' or 'mute' writes to repo memory for future reviews."""
        from .models_db import RepoMemoryRow
        
        entry = {
            "fingerprint": fingerprint,
            "kind": kind,
            "repo": repo,
            "note": note,
            "recorded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        }
        
        if kind in ("down", "mute") and repo:
            with self.Session() as session:
                mem_row = session.get(RepoMemoryRow, repo)
                if mem_row is None:
                    mem_row = RepoMemoryRow(id=f"{repo}#{uuid.uuid4().hex[:8]}", repo=repo)
                # Ensure memory property is handled (it's not natively on RepoMemoryRow in models_db,
                # actually it is note and path_pattern)
                # Instead of adding muted_fingerprints, let's just add it as a new memory entry for that fingerprint
                mem_row.path_pattern = f"fingerprint:{fingerprint}"
                mem_row.note = note or f"Muted finding {fingerprint}"
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

        state_id = f"{repo}#{pr_number}"
        with self.Session() as session:
            row = session.get(ReviewStateRow, state_id)
            return row.last_reviewed_sha if row and row.last_reviewed_sha else None

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        from .models_db import ReviewStateRow

        state_id = f"{repo}#{pr_number}"
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

        repo = ""
        pr_number = 0
        if "#" in review_id and "@" in review_id:
            try:
                repo_part, rest = review_id.split("#", 1)
                pr_str = rest.split("@", 1)[0]
                repo = repo_part
                pr_number = int(pr_str)
            except Exception:
                pass

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
                row_id = f"{item_repo}#{item_pr}#{fp}"
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

    def add_repo_memory(self, repo: str, path_pattern: str, note: str) -> None:
        from .models_db import RepoMemoryRow

        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        mid = f"{repo}#{uuid.uuid4().hex[:8]}"
        with self.Session() as session:
            row = RepoMemoryRow(
                id=mid, repo=repo, path_pattern=path_pattern, note=note, created_at=now
            )
            session.add(row)
            session.commit()

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

    def _path(self, rid: str) -> Path:
        return self.reports_dir / f"{rid}.json"

    def _state_file(self) -> Path:
        return self.data_dir / "reviews_state.json"

    def _findings_file(self, repo: str, pr_number: int) -> Path:
        # Defense in depth to match the DB backend's parameterized-query
        # safety: repo comes straight from the API's path params, so collapse
        # anything other than [a-z0-9._-] rather than relying solely on the
        # "/" -> "-" swap below to keep this a single path component.
        slug = re.sub(r"[^a-z0-9._-]", "-", repo.replace("/", "-").lower())
        d = self.data_dir / "findings"
        d.mkdir(parents=True, exist_ok=True)
        return d / f"{slug}_{int(pr_number)}.json"

    def _memory_file(self) -> Path:
        return self.data_dir / "repo_memory.json"

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
            repos[(report.get("pr") or {}).get("repo", "?")] += 1
            for f in report.get("findings", []):
                sev[f.get("severity")] += 1
                cats[f.get("category")] += 1
                findings += 1
        return {
            "reports": reports, "findings": findings,
            "by_severity": {s: sev.get(s, 0) for s in SEV_KEYS},
            "by_category": dict(cats.most_common(8)),
            "top_repos": dict(repos.most_common(5)),
            "files_analyzed": files,
        }

    def list_findings(self, state: str = "", severity: str = "",
                      repo: str = "", limit: int = 100, offset: int = 0) -> list[dict]:
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
        
        return {
            "reviews_total": total,
            "fallback_rate": round(fallback_count / total * 100, 1) if total else 0.0,
            "avg_duration_s": round(duration_sum / total / 1000, 2) if total else 0.0,
            "avg_health_score": round(health_sum / total, 1) if total else 100.0,
            "severity_distribution": {s: sev_counts.get(s, 0) for s in ("critical", "high", "medium", "low", "info")},
            "engine_distribution": dict(engine_counts.most_common()),
        }

    def record_feedback(self, fingerprint: str, kind: str, repo: str = "", note: str = "") -> dict:
        entry = {
            "fingerprint": fingerprint,
            "kind": kind,
            "repo": repo,
            "note": note,
            "recorded_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        }
        
        if kind in ("down", "mute") and repo:
            self.add_repo_memory(repo, f"fingerprint:{fingerprint}", note or f"Muted finding {fingerprint}")
            
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
                return states.get(f"{repo}#{pr_number}", {}).get("last_reviewed_sha")
            except Exception:
                return None

    def set_last_reviewed_sha(self, repo: str, pr_number: int, sha: str,
                             base_sha: str = "") -> None:
        now = _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds")
        key = f"{repo}#{pr_number}"
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
        repo = ""
        pr_number = 0
        if "#" in review_id and "@" in review_id:
            try:
                repo_part, rest = review_id.split("#", 1)
                pr_str = rest.split("@", 1)[0]
                repo = repo_part
                pr_number = int(pr_str)
            except Exception:
                pass

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
                fp = f_dict.get("fingerprint") or f_dict.get("title", "")
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

    def add_repo_memory(self, repo: str, path_pattern: str, note: str) -> None:
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
                "id": f"{repo}#{uuid.uuid4().hex[:8]}",
                "repo": repo,
                "path_pattern": path_pattern,
                "note": note,
                "created_at": now,
            })
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(items, indent=2), encoding="utf-8")
            os.replace(tmp, p)


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
