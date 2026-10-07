"""End-to-end tests for the review pipeline (no network, no API keys)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.config import Config, sev_rank
from ai_pr_reviewer.diff_parser import chunk_files, parse_unified_diff
from ai_pr_reviewer.analyzer import MockAnalyzer
from ai_pr_reviewer.cli import filter_files, validate_findings
from ai_pr_reviewer.models import Finding


def _files(diff_text):
    p = Path(diff_text)
    if p.exists():                       # fixtures carry diff file paths
        diff_text = p.read_text(encoding="utf-8")
    return parse_unified_diff(diff_text)


# ------------------------------------------------------------------ diff parser
def test_parses_all_files(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    paths = {f.path for f in files}
    assert "payments/refunds.py" in paths
    assert "payments/api.py" in paths
    assert len(files) == 2


def test_new_file_line_numbers_are_correct(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    refunds = next(f for f in files if f.path == "payments/refunds.py")
    assert refunds.is_new
    lines = refunds.added_lines()
    nums = [n for n, _ in lines]
    assert nums == sorted(nums)                       # ascending
    assert nums[0] == 1                               # new file starts at line 1
    texts = {t for _, t in lines}
    assert any("sqlite3.connect" in t for t in texts)


def test_modified_file_tracks_hunks(fixtures):
    files = _files(fixtures["frontend_checkout"]["diff"])
    js = next(f for f in files if f.path == "src/checkout.js")
    assert not js.is_new
    assert js.hunks, "modified file should have at least one hunk"
    added = js.added_lines()
    assert all(n is not None for n, _ in added)
    # every added line number is inside the file's new-line set
    known = js.new_line_numbers()
    assert {n for n, _ in added} <= known


def test_binary_and_rename_safety(fixtures):
    diff = (
        "diff --git a/logo.png b/logo.png\n"
        "new file mode 100644\n"
        "index 0000000..abcd123\n"
        "Binary files /dev/null and b/logo.png differ\n"
    )
    files = parse_unified_diff(diff)
    assert files[0].is_binary and files[0].is_new
    assert files[0].additions == 0


def test_chunking_respects_budget(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    batches = chunk_files(files, max_chars=500)
    assert len(batches) > 1
    # Each batch is either under budget or a single oversized file.
    for b in batches:
        assert len(b) <= 500 or b.count("diff --git") == 0 or b.count("+++ ") == 1


# ---------------------------------------------------------------- mock analyzer
def test_mock_analyzer_finds_expected_bugs(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    outcome = MockAnalyzer().analyze(files)
    severities = {f.severity for f in outcome.findings}
    titles = [f.title for f in outcome.findings]

    assert "critical" in severities                      # SQL injection
    assert any("SQL injection" in t for t in titles)
    assert any("Bare `except:`" in t for t in titles)    # error handling
    assert any("Mutable default" in t for t in titles)   # classic py bug
    assert any("print()" in t for t in titles)           # hygiene


def test_mock_analyzer_js_and_bash(fixtures):
    js_files = _files(fixtures["frontend_checkout"]["diff"])
    js_findings = MockAnalyzer().analyze(js_files).findings
    js_titles = " | ".join(f.title for f in js_findings)
    assert "XSS" in js_titles
    assert "localStorage" in js_titles
    assert "Loose equality" in js_titles

    sh_files = _files(fixtures["infra_deploy"]["diff"])
    sh_findings = MockAnalyzer().analyze(sh_files).findings
    sh_titles = " | ".join(f.title for f in sh_findings)
    assert "rm -rf" in sh_titles
    assert "Hardcoded credential" in sh_titles
    assert "777" in sh_titles


# ---------------------------------------------------------------- cli filtering
def _cfg(**kw):
    base = dict(severity_threshold="medium", max_comments=2, exclude=[])
    base.update(kw)
    return Config(**base)


def test_validate_findings_threshold_and_cap(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    findings = MockAnalyzer().analyze(files).findings
    cfg = _cfg(severity_threshold="high", max_comments=2)

    inline, reported, below, suppressed, dropped = validate_findings(findings, files, cfg)
    # D4: ``reported`` is the full anchored set at/above the threshold — the
    # inline cap shrinks only ``inline``, never what the review saw.
    assert all(sev_rank(f.severity) >= sev_rank("high") for f in reported)
    assert len(reported) == sum(1 for f in findings
                                if sev_rank(f.severity) >= sev_rank("high"))
    # D5: both lists arrive severity-sorted (critical → info), cap picks the
    # top of that order.
    assert [sev_rank(f.severity) for f in reported] == sorted(
        (sev_rank(f.severity) for f in reported), reverse=True)
    assert inline == reported[:2]
    assert len(inline) <= 2
    assert suppressed == len(reported) - len(inline)
    # D3: below-threshold findings are kept, not dropped.
    assert below and all(sev_rank(f.severity) < sev_rank("high") for f in below)
    assert not dropped


_MULTI_LINE_DIFF = (
    "--- a/x.py\n"
    "+++ b/x.py\n"
    "@@ -1,8 +1,8 @@\n"
    " l1\n"
    " l2\n"
    "-old\n"
    "+n1\n"
    "+n2\n"
    "+n3\n"
    "+n4\n"
    "+n5\n"
    " l8\n"
)


def test_inline_cap_follows_severity_not_provider_order():
    """D5 (V3-E01-T05): providers are not trusted to arrive sorted — the cap
    must spend its slots on the most severe findings, deterministically."""
    files = parse_unified_diff(_MULTI_LINE_DIFF)

    def _f(line, sev, title):
        return Finding(file="x.py", line=line, severity=sev, title=title,
                       explanation="e")

    # adversarial provider order: mild findings first, critical buried last
    adversarial = [_f(7, "info", "i"), _f(6, "low", "l"), _f(3, "critical", "c"),
                   _f(5, "high", "h"), _f(4, "medium", "m")]
    cfg = _cfg(severity_threshold="info", max_comments=2)

    inline, reported, below, suppressed, dropped = validate_findings(
        adversarial, files, cfg)

    assert [f.severity for f in inline] == ["critical", "high"]
    assert [f.severity for f in reported] == ["critical", "high", "medium",
                                              "low", "info"]
    assert below == [] and dropped == []
    assert suppressed == 3                    # reported minus the inline slots

    # determinism: any other provider ordering yields identical results
    again = validate_findings(list(reversed(adversarial)), files, cfg)
    assert [f.title for f in again[1]] == [f.title for f in reported]
    assert [f.title for f in again[0]] == [f.title for f in inline]


def test_exclude_globs_drop_files(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    cfg = _cfg(exclude=["payments/refunds.py"])
    keep = filter_files(files, cfg)
    assert {f.path for f in keep} == {"payments/api.py"}


def test_findings_outside_diff_are_dropped_not_snapped():
    """Findings on lines outside the diff must not be snapped to innocent code;
    they are kept out of inline comments and returned in dropped."""
    fd = parse_unified_diff(
        "--- a/x.py\n+++ b/x.py\n@@ -1,2 +1,3 @@\n context\n+bad = 1\n context2\n")
    f = Finding(file="x.py", line=99, severity="high", title="t", explanation="e")
    inline, reported, _below, _suppressed, dropped = validate_findings([f], fd, _cfg())
    assert len(inline) == 0
    assert len(reported) == 0
    assert len(dropped) == 1
    assert dropped[0].line == 99  # original line preserved, not snapped


# ---------------------------------------------------------------- report shape
def test_report_round_trip(fixtures):
    from ai_pr_reviewer.models import PRContext, ReviewResult
    from ai_pr_reviewer import reporter

    files = _files(fixtures["payments_refunds"]["diff"])
    outcome = MockAnalyzer().analyze(files)
    result = ReviewResult(
        pr=PRContext(repo="acme/payments", pr_number=42, pr_title="t"),
        mode=outcome.mode, model=outcome.model,
        reviewed_at=reporter.now_iso(), summary=outcome.summary,
        findings=outcome.findings,
    )
    data = reporter.finalize_report(result)
    assert data["pr"]["repo"] == "acme/payments"
    assert data["findings"][0]["severity"] in {"critical", "high", "medium", "low", "info"}

    md = reporter.build_summary_markdown(result)
    assert "AI PR Review" in md
