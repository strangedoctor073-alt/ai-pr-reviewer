"""V3-E01-T08 — defect regression matrix for D1–D7.

One pinned test per defect in the ``CURRENT_ARCHITECTURE.md`` defect ledger.
Each test fails against the pre-fix code and passes now; every test is fully
offline (fake HTTP transport / fakes, no API keys, no network) and the file
contains no secrets, real PR diffs or dashboard data.

D1 base_sha never set · D2 verification gets the capped list · D3
below-threshold findings dropped · D4 max_comments caps the whole report ·
D5 no severity sort before caps · D6 raw ValueError on numeric INPUT_* ·
D7 mute not idempotent.
"""
from __future__ import annotations

import functools
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import reporter                        # noqa: E402
from ai_pr_reviewer import orchestrator as orch           # noqa: E402
from ai_pr_reviewer.cli import parse_args                 # noqa: E402
from ai_pr_reviewer.config import Config, load_config     # noqa: E402
from ai_pr_reviewer.diff_parser import parse_unified_diff  # noqa: E402
from ai_pr_reviewer.github_client import GitHubClient     # noqa: E402
from ai_pr_reviewer.models import Finding                 # noqa: E402
from test_orchestrator import Wired, _finding             # noqa: E402

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40


# --------------------------------------------------------------------- D1
def test_d1_get_pr_populates_base_sha(monkeypatch):
    """D1 — base_sha was never set, so repo context was fetched at the PR
    head (a PR choosing the text its own review reads)."""

    def handler(request):
        if request.headers["accept"] == "application/vnd.github.v3.diff":
            return httpx.Response(200, text="diff --git a/x b/x\n")
        return httpx.Response(200, json={
            "title": "t", "user": {"login": "dev"}, "html_url": "https://x/pr/1",
            "head": {"ref": "feat", "sha": HEAD_SHA},
            "base": {"ref": "main", "sha": BASE_SHA}})

    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", functools.partial(
        real_client, transport=httpx.MockTransport(handler)))

    ctx, _diff = GitHubClient(token="t0ken", repo="acme/x").get_pr(1)

    assert ctx.base_sha == BASE_SHA          # was "" before the fix
    assert ctx.head_sha == HEAD_SHA


# --------------------------------------------------------------------- D2
def test_d2_still_present_finding_beyond_the_cap_stays_active(monkeypatch):
    """D2 — verification/lifecycle received the max_comments-capped list, so
    a still-present finding outside the top-20 closed itself as resolved."""
    findings = [_finding(title=f"t{i}", severity="high") for i in range(20)]
    findings.append(_finding(title="still there", severity="low"))   # rank 21
    previous = [_finding(title="still there", severity="low", state="active")]

    w = Wired(monkeypatch, findings=findings, previous=previous)
    w.cfg.max_comments = 20

    result = w.run()

    states = {f.title: f.state for f in result.findings}
    assert states["still there"] == "active"                # was "resolved"
    assert all(s != "resolved" for s in states.values())    # nothing falsely closed
    # the lifecycle was fed the UNCAPPED current set
    assert "still there" in [f.title for f in w.lifecycle_calls[0][1]]


# --------------------------------------------------------------------- D3
def test_d3_below_threshold_findings_are_retained(monkeypatch):
    """D3 — findings under the severity threshold vanished entirely (absent
    from report, counts and health score) while the summary claimed they
    were suppressed."""
    w = Wired(monkeypatch, findings=[_finding(title="real issue", severity="high"),
                                     _finding(title="minor nit", severity="info")])
    w.cfg.severity_threshold = "medium"

    result = w.run()

    assert [f.title for f in result.findings] == ["real issue"]
    assert [f.title for f in result.below_threshold] == ["minor nit"]   # was []

    report = reporter.finalize_report(result)
    assert [f["title"] for f in report["below_threshold"]] == ["minor nit"]
    assert report["below_threshold_count"] == 1


# --------------------------------------------------------------------- D4
def _thirty():
    return [_finding(title=f"issue {i}", severity="high") for i in range(30)]


def test_d4_max_comments_caps_only_inline_comments(monkeypatch):
    """D4 — max_comments silently capped the whole report and health score,
    contradicting action.yml ('extra findings go in the summary')."""
    w5 = Wired(monkeypatch, findings=_thirty())
    w5.cfg.max_comments = 5
    r5 = w5.run()

    w30 = Wired(monkeypatch, findings=_thirty())
    w30.cfg.max_comments = 30
    r30 = w30.run()

    assert len(r5.findings) == 30             # report was 5 before the fix
    assert r5.suppressed == 25                # only inline slots are "over cap"
    assert r5.health_score == r30.health_score  # cap never moved the score


# --------------------------------------------------------------------- D5
def test_d5_caps_spend_slots_on_the_most_severe_findings():
    """D5 — AI findings were never severity-sorted, so a cap could prefer a
    mild finding over a critical one (providers are not trusted to sort)."""
    diff = (
        "--- a/x.py\n+++ b/x.py\n@@ -1,8 +1,8 @@\n"
        " l1\n l2\n-old\n+n1\n+n2\n+n3\n+n4\n+n5\n l8\n")
    files = parse_unified_diff(diff)
    mk = lambda line, sev, title: Finding(  # noqa: E731
        file="x.py", line=line, severity=sev, title=title, explanation="e")
    adversarial = [mk(7, "info", "i"), mk(6, "low", "l"), mk(3, "critical", "c"),
                   mk(5, "high", "h"), mk(4, "medium", "m")]
    cfg = Config(severity_threshold="info", max_comments=2)

    inline, reported, _below, _suppressed, _dropped = orch.validate_findings(
        adversarial, files, cfg)

    assert [f.severity for f in inline] == ["critical", "high"]   # was input-order


# --------------------------------------------------------------------- D6
def test_d6_garbage_numeric_input_is_a_clean_config_error(monkeypatch):
    """D6 — numeric INPUT_* parsing raised a raw ValueError (traceback, no
    exit 1). It must be a config error naming the field and the value."""
    monkeypatch.setenv("INPUT_MAX_COMMENTS", "abc")

    with pytest.raises(SystemExit) as exc:
        load_config(parse_args([]))

    message = str(exc.value.code)
    assert isinstance(message, str)          # string SystemExit ⇒ exit 1, no traceback
    assert "max_comments" in message
    assert "abc" in message


# --------------------------------------------------------------------- D7
def test_d7_repeat_mute_creates_exactly_one_row(tmp_path):
    """D7 — each repeated mute minted a new RepoMemoryRow (lookup by the repo
    string never matches the 'repo#uuid' primary key)."""
    from dashboard.storage import JsonStorage, choose_storage

    json_store = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    json_store.init()
    db_store = choose_storage(tmp_path, f"sqlite:///{tmp_path / 't.db'}")
    db_store.init()

    for store in (json_store, db_store):
        for _ in range(5):
            store.record_feedback("fp_same", "mute", repo="acme/x")
        rows = store.list_repo_memory("acme/x")
        assert len(rows) == 1, f"{type(store).__name__}: repeated mute duplicated rows"
        assert rows[0]["path_pattern"] == "fingerprint:fp_same"
        assert store.get_repo_memory("acme/x", ["any.py"]) == []
