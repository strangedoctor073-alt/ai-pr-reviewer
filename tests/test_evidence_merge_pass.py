"""V4-E04 merge-pass tests for the reporter.py / orchestrator.py / dashboard
provenance wiring (all applied in this tree). They pin the behaviors it
introduced: blended-run provenance attribution, the redacted provenance
suffix, dashboard read-time redaction and the dashboard JS provenance
block."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from ai_pr_reviewer import orchestrator as orch, reporter
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.model_router import reset_circuits
from ai_pr_reviewer.models import (AnalysisOutcome, EvidenceRecord, Finding,
                                   PRContext, ProvenanceSource)

PLANT = "sk-abc123def456ghi789jkl012mno345pqr"
ROOT = Path(__file__).resolve().parents[1]


# ------------------------------------------------ orchestrator: blended runs
class _BlendedEngine:
    """A provider that fell back to the rule engine for some batches."""
    backend = "claude"

    def analyze(self, context):
        ai = Finding.from_untrusted_dict({
            "file": "app/service.py", "line": 2, "severity": "high",
            "category": "security", "title": "AI says hardcoded token",
            "explanation": "e", "rule_id": "SEC002"})       # model-forged rule_id
        static = Finding(
            file="app/service.py", line=3, severity="high", category="security",
            title="Static: eval used", explanation="e", rule_id="SEC001",
            evidence=(EvidenceRecord.create(
                kind="rule_ref", locator="rule:SEC001", summary="SEC001"),))
        return AnalysisOutcome(findings=[ai, static], summary="s",
                               mode="claude", model="claude-test",
                               engine="claude+static", fallback_used=True,
                               batch_count=2)


def test_blended_run_attributes_each_finding_to_its_real_producer(monkeypatch):
    reset_circuits()
    monkeypatch.setattr(orch, "build_context",
                        lambda pr, files, cfg, storage=None, gh=None:
                        SimpleNamespace(pr=pr, files=files, previous_findings=[]))
    monkeypatch.setattr(orch, "get_provider", lambda cfg, ctx: _BlendedEngine())
    cfg = Config(repo="acme/api", pr_number=7, severity_threshold="low",
                 max_comments=20)
    diff = ("diff --git a/app/service.py b/app/service.py\n"
            "--- a/app/service.py\n+++ b/app/service.py\n"
            "@@ -1,2 +1,4 @@\n ctx\n+    a = 1\n+    b = 2\n ctx2\n")
    result = orch.ReviewOrchestrator(
        cfg, None, None, pr=PRContext(repo="acme/api", pr_number=7,
                                      head_sha="h" * 40), diff_text=diff).run()
    rows = {r["title"]: r for r in
            reporter.finalize_report(result, report_id="x")["findings"]}
    ai, st = rows["AI says hardcoded token"], rows["Static: eval used"]
    assert (ai["provenance_engine"], ai["provenance_model"],
            ai["provenance_origin"]) == ("claude", "claude-test", "ai")
    assert (st["provenance_engine"], st["provenance_model"],
            st["provenance_origin"]) == ("static", "static-rules-v1", "static")
    assert [s["engine"] for s in st["provenance_sources"]] == ["static"]
    assert "+" not in json.dumps([ai["provenance_sources"], st["provenance_sources"]])


# --------------------------------------------------------- reporter snippet
def test_markdown_never_leaks_through_provenance():
    f = Finding(file="a.py", line=1, title="t",
                evidence=(EvidenceRecord(kind="diff_hunk",
                                         locator=f"a`.py {PLANT}:1",
                                         summary=PLANT, content_hash="0" * 16),))
    f.provenance_engine, f.provenance_model = "claude", f"m-{PLANT}"
    s = reporter._provenance_suffix(f)
    assert PLANT not in s and "source: claude" in s
    assert s.count("`") == 2                     # exactly one code span, no escape


def test_markdown_names_every_source_of_a_merged_finding():
    f = Finding(file="a.py", line=1, title="t", provenance_engine="claude",
                provenance_model="m1",
                provenance_sources=(
                    ProvenanceSource(engine="claude", model="m1", origin="ai"),
                    ProvenanceSource(engine="static", model="static-rules-v1",
                                     origin="static")))
    s = reporter._provenance_suffix(f)
    assert "claude (m1)" in s and "static (static-rules-v1)" in s


def test_markdown_for_pre_v4_findings_is_unchanged():
    assert reporter._provenance_suffix(Finding(file="a.py", line=1)) == ""


# ------------------------------------------------------- dashboard snippet
def _client(tmp_path, monkeypatch, row):
    import dashboard.app as dashboard_app
    from dashboard.storage import JsonStorage
    from fastapi.testclient import TestClient
    from ai_pr_reviewer.storage_schema import format_review_id

    st = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    st.init()
    st.upsert({"id": "r1", "pr": {"repo": "acme/api", "number": 7},
               "summary": "s", "findings": [row]})
    st.save_findings(format_review_id("acme/api", 7, "h" * 40),
                     [{**row, "repo": "acme/api", "pr_number": 7}])
    for name, val in (("DATA_DIR", tmp_path), ("REPORTS_DIR", tmp_path / "reports"),
                      ("SETTINGS_PATH", tmp_path / "settings.json"),
                      ("AUDIT_PATH", tmp_path / "audit.jsonl"),
                      ("_storage", st), ("_api_token", "tok")):
        monkeypatch.setattr(dashboard_app, name, val)
    http = TestClient(dashboard_app.app)
    http.headers.update({"X-Dashboard-Token": "tok"})
    return http


_BASE = {"file": "a.py", "line": 1, "severity": "high", "category": "security",
         "title": "t", "explanation": "e", "suggestion": None}


def test_dashboard_reads_redact_tainted_evidence_and_provenance(tmp_path, monkeypatch):
    row = {**_BASE,
           "evidence": [{"kind": "diff_hunk", "locator": f"a.py:{PLANT}",
                         "summary": f'k = "{PLANT}"', "content_hash": "h",
                         "check_type": PLANT}],
           "provenance_engine": "claude", "provenance_model": f"m-{PLANT}",
           "provenance_sources": [{"engine": "claude", "model": f"m-{PLANT}",
                                   "origin": "ai", "agent": None}]}
    with _client(tmp_path, monkeypatch, row) as http:
        for path in ("/api/reports/r1", "/api/reviews/acme/api/7/findings",
                     "/api/findings"):
            assert PLANT not in http.get(path).text, path


def test_dashboard_serves_clean_evidence_unchanged_and_old_rows_untouched(
        tmp_path, monkeypatch):
    e = EvidenceRecord.create(kind="rule_ref", locator="rule:SEC001",
                              summary="SEC001: eval", check_type="security")
    new = {**_BASE, "evidence": [e.to_dict()], "provenance_engine": "static"}
    with _client(tmp_path, monkeypatch, new) as http:
        got = http.get("/api/reports/r1").json()["findings"][0]
        assert got["evidence"] == [e.to_dict()]          # byte-identical
        assert got["provenance_engine"] == "static"
    with _client(tmp_path / "old", monkeypatch, dict(_BASE)) as http:
        got = http.get("/api/reports/r1").json()["findings"][0]
        assert "evidence" not in got                     # no keys invented
        assert "provenance_engine" not in got


# ---------------------------------------------------------- dashboard JS
@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_provenance_block_js_escapes_and_says_unavailable(tmp_path):
    src = (ROOT / "dashboard" / "static" / "app.js").read_text(encoding="utf-8")
    start = src.index("function provenanceBlock(")
    end = src.index("\n}\n", start) + 3
    harness = (
        "function esc(s){return String(s??'').replace(/[&<>\"']/g,"
        "c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',\"'\":'&#39;'}[c]));}\n"
        + src[start:end] +
        "\nconst out={old:provenanceBlock({}),"
        "bad:provenanceBlock({provenance_engine:'<img src=x onerror=1>',"
        "evidence:[{kind:'k',locator:'<script>',summary:'<b>'}]}),"
        "junk:provenanceBlock({provenance_sources:'x',evidence:5})};"
        "console.log(JSON.stringify(out));")
    f = tmp_path / "h.js"
    f.write_text(harness, encoding="utf-8")
    out = json.loads(subprocess.run(["node", str(f)], capture_output=True,
                                    text=True, check=True).stdout)
    assert "unavailable" in out["old"].lower()
    assert "<img" not in out["bad"] and "<script" not in out["bad"]
    assert "unavailable" in out["junk"].lower()          # never throws
