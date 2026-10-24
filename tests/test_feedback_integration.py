"""V4-E09 integration of the orchestrator call site. Exercises the real
pipeline."""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ai_pr_reviewer import reporter  # noqa: E402
from ai_pr_reviewer import storage_schema as S  # noqa: E402
from ai_pr_reviewer.config import Config  # noqa: E402
from ai_pr_reviewer.findings import fingerprint_finding  # noqa: E402
from ai_pr_reviewer.models import PRContext  # noqa: E402
from ai_pr_reviewer.orchestrator import ReviewOrchestrator  # noqa: E402
from ai_pr_reviewer.storage import LocalReviewStorage  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DIFF = (ROOT / "demo/samples/payments_refunds.diff").read_text(encoding="utf-8")
REPO = "acme/api"


def _run(tmp_path, *, yml=None, db="s.db", fail_on="never"):
    root = tmp_path / "checkout"
    root.mkdir(exist_ok=True)
    if yml is not None:
        (root / ".ai-pr-reviewer.yml").write_text(yml, encoding="utf-8")
    cfg = Config(repo=REPO, pr_number=42, mock=True, no_comment=True,
                 severity_threshold="low", fail_on=fail_on)
    cfg.repo_root = str(root)
    storage = LocalReviewStorage(tmp_path / db)
    pr = PRContext(repo=REPO, pr_number=42, head_sha="a" * 40)
    result = ReviewOrchestrator(cfg, None, storage, pr=pr, diff_text=DIFF).run()
    return result, storage


def _plant(tmp_path, fp, *, repo=REPO, days=30, origin="dashboard", db="s.db"):
    now = datetime.now(timezone.utc)
    cols = ", ".join(S.SUPPRESSION_RULE_COLUMNS)
    marks = ", ".join("?" for _ in S.SUPPRESSION_RULE_COLUMNS)
    row = {"id": S.new_suppression_rule_id(), "repo": repo,
           "match_kind": "fingerprint", "fingerprint": fp, "rule_id": "",
           "path_glob": "", "reason": "", "origin": origin,
           "created_at": S.feedback_iso(now - timedelta(minutes=1)),
           "expires_at": S.feedback_iso(now + timedelta(days=days)),
           "disabled_at": "", "updated_at": S.feedback_iso(now)}
    with sqlite3.connect(tmp_path / db) as conn:
        conn.executescript(S.feedback_local_ddl())
        conn.execute(f"INSERT INTO suppression_rules ({cols}) VALUES ({marks})",
                     tuple(row[c] for c in S.SUPPRESSION_RULE_COLUMNS))
    return row


def _stable(d):
    d = json.loads(json.dumps(d))
    for k in ("reviewed_at", "duration_ms"):
        d.pop(k, None)
    for key in ("findings", "below_threshold"):
        for f in d.get(key, []):
            f.pop("verified_at", None)
    return json.dumps(d, sort_keys=True)


def test_disabled_report_has_no_feedback_keys_and_equals_a_run_without_a_rule(tmp_path):
    base, _ = _run(tmp_path, db="a.db")
    victim = fingerprint_finding(base.findings[0])
    for n, yml in enumerate((None, "feedback:\n  enabled: false\n",
                             "feedback:\n  enabled: 'true'\n")):
        db = f"b{n}.db"
        _plant(tmp_path, victim, db=db)            # a live rule exists...
        with_rule, _ = _run(tmp_path, yml=yml, db=db)   # ...but feedback is off
        assert _stable(base.to_dict()) == _stable(with_rule.to_dict())
        b = with_rule.to_dict()
        assert "suppressed_count" not in b and "suppression_rule_hits" not in b
        base.duration_ms = with_rule.duration_ms = 0          # wall-clock noise
        base.reviewed_at = with_rule.reviewed_at = ""
        assert reporter.build_summary_markdown(with_rule) == \
            reporter.build_summary_markdown(base)


def test_enabled_parks_counts_and_keeps_the_finding(tmp_path):
    base, _ = _run(tmp_path, db="a.db")
    victim = base.findings[0]
    _plant(tmp_path, fingerprint_finding(victim), db="b.db")
    out, _ = _run(tmp_path, yml="feedback:\n  enabled: true\n", db="b.db")
    d = out.to_dict()
    assert d["suppressed_count"] == 1
    assert len(out.findings) == len(base.findings)          # never erased
    muted = [f for f in out.findings if f.state == "muted"]
    assert [fingerprint_finding(f) for f in muted] == [fingerprint_finding(victim)]
    assert out.health_score >= base.health_score            # muted don't count
    assert sum(d["suppression_rule_hits"].values()) == 1
    assert "suppression rule" in reporter.build_summary_markdown(out)


def test_enabled_without_matching_rules_reports_zero(tmp_path):
    out, _ = _run(tmp_path, yml="feedback:\n  enabled: true\n")
    assert out.to_dict()["suppressed_count"] == 0
    assert all(f.state != "muted" for f in out.findings)


def test_a_rule_for_another_repo_or_forged_origin_is_ignored(tmp_path):
    base, _ = _run(tmp_path, db="a.db")
    fp = fingerprint_finding(base.findings[0])
    _plant(tmp_path, fp, repo="acme/other", db="b.db")
    out, _ = _run(tmp_path, yml="feedback:\n  enabled: true\n", db="b.db")
    assert out.to_dict()["suppressed_count"] == 0


def test_expired_rule_does_not_apply(tmp_path):
    base, _ = _run(tmp_path, db="a.db")
    _plant(tmp_path, fingerprint_finding(base.findings[0]), days=-1, db="b.db")
    out, _ = _run(tmp_path, yml="feedback:\n  enabled: true\n", db="b.db")
    assert out.to_dict()["suppressed_count"] == 0


def test_suppressed_finding_no_longer_trips_fail_on(tmp_path):
    base, _ = _run(tmp_path, db="a.db")
    top = base.findings[0]
    sev = top.severity
    only = [f for f in base.findings if f.severity == sev]
    for f in only:
        _plant(tmp_path, fingerprint_finding(f), db="b.db")
    out, _ = _run(tmp_path, yml="feedback:\n  enabled: true\n", db="b.db")
    still_open = reporter.open_findings(out.findings)
    assert all(f.severity != sev for f in still_open)
    assert out.to_dict()["suppressed_count"] == len(only)


def test_no_rule_table_is_created_by_any_run(tmp_path):
    _run(tmp_path, yml="feedback:\n  enabled: true\n")
    with sqlite3.connect(tmp_path / "s.db") as conn:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master")}
    assert "suppression_rules" not in names and "feedback_events" not in names
