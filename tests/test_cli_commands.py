"""Tests for V4.10-E04 CLI ecosystem (explain, query, eval subparsers).

Covers:
- V4.10-E04-T01: CLI subparsers for explain/query/eval commands while preserving review default
- V4.10-E04-T02: explain command (rule / finding details & remediation)
- V4.10-E04-T03: query command (filtering report findings by severity / file)
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from pathlib import Path

from ai_pr_reviewer.cli import main, run


def test_cli_explain_command():
    """T01/T02: explain subcommand explains a security rule."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = main(["explain", "SEC001"])
    out = buf.getvalue()
    assert exit_code == 0
    assert "SEC001" in out
    assert "Rule Explanation" in out


def test_cli_query_command_filters_report(tmp_path: Path):
    """T01/T03: query subcommand filters findings from report JSON."""
    report_file = tmp_path / "report.json"
    report_data = {
        "findings": [
            {"file": "src/auth.py", "line": 10, "severity": "critical", "title": "SQLi"},
            {"file": "src/calc.py", "line": 5, "severity": "low", "title": "Typo"},
        ]
    }
    report_file.write_text(json.dumps(report_data), encoding="utf-8")

    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = main(["query", "--report", str(report_file), "--severity", "critical"])
    out = buf.getvalue()
    assert exit_code == 0
    assert "SQLi" in out
    assert "Typo" not in out


def test_cli_review_mode_remains_backward_compatible():
    """T01: Running without a subcommand still executes a review."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        exit_code = main([
            "--diff-file", "demo/samples/payments_refunds.diff",
            "--repo", "acme/payments",
            "--pr", "42",
            "--mock",
            "--no-comment",
            "--output", "demo/out/test_cli_out.json",
        ])
    out = buf.getvalue()
    assert exit_code == 0
    assert "acme/payments#42" in out
