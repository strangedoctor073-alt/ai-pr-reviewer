"""V3-E05-T04 — additive-only guard over `review-report.json`.

Freezes the report's required top-level fields and every
``Finding.to_dict()`` key as the machine-checkable half of the
compatibility contract (``docs/planning/MIGRATION_PLAN.md`` §1):

* **required keys are frozen** — removing or renaming one fails here;
* **additive keys are allowed** — the dashboard and future consumers rely
  on extra fields (V3-E01/E02 additions must pass without touching the
  required lists below);
* **the report must stay JSON-round-trippable** — nothing non-serializable
  may sneak into the artifact.

Mutation-checked during implementation: deleting ``health_score`` from
``ReviewResult.to_dict()`` turns this suite red.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import reporter
from ai_pr_reviewer.models import Finding, PRContext, ReviewResult

# Required top-level fields of review-report.json:
# ReviewResult.to_dict() + what finalize_report() adds.
REQUIRED_REPORT_KEYS = {
    # ReviewResult.to_dict()
    "pr", "mode", "model", "reviewed_at", "duration_ms", "summary",
    "findings", "below_threshold", "stats", "posted_inline", "suppressed",
    "warnings", "health_score", "health_grade", "telemetry",
    # reporter.finalize_report()
    "id", "review_state", "engine", "fallback_used",
    "new_findings_count", "resolved_findings_count", "below_threshold_count",
    "active_findings_count",
}

# Required keys of every finding row: Finding.to_dict().
REQUIRED_FINDING_KEYS = {
    "file", "line", "end_line", "severity", "category", "title",
    "explanation", "suggestion", "confidence", "rule_id", "fingerprint",
    "state", "first_seen_sha", "last_seen_sha", "resolved_at",
    "github_comment_id", "verification_status", "verification_reason",
    "verified_at", "provenance_engine", "provenance_model",
    "provenance_agent", "provenance_origin",
}


def _report() -> dict:
    """A report built by the real pipeline (models + reporter), not a mock."""
    pr = PRContext(repo="acme/api", pr_number=7, head_sha="h" * 40)
    finding = Finding(file="app/main.py", line=5, severity="high",
                      title="SQL injection", explanation="query built from input")
    result = ReviewResult(pr=pr, mode="static", model="static-rules-v1",
                          findings=[finding])
    return reporter.finalize_report(result, report_id="test-report-1")


def test_required_top_level_fields_are_frozen():
    report = _report()
    assert REQUIRED_REPORT_KEYS <= set(report), (
        "report field(s) removed/renamed — that is a breaking change for "
        f"consumers: missing {sorted(REQUIRED_REPORT_KEYS - set(report))}")


def test_required_finding_fields_are_frozen():
    report = _report()
    assert report["findings"], "fixture must contain a finding"
    for row in report["findings"]:
        assert REQUIRED_FINDING_KEYS <= set(row), (
            "finding field(s) removed/renamed: missing "
            f"{sorted(REQUIRED_FINDING_KEYS - set(row))}")


def test_additive_fields_are_allowed_at_both_levels():
    """Unknown/additive fields must NOT trip the guard — consumers are
    allowed to grow the report (this is what keeps V3-E01/E02 additive
    fields from needing a snapshot edit)."""
    report = _report()
    grown = {**report, "future_top_level": {"nested": True}}
    grown["findings"] = [{**row, "future_finding_field": 1}
                         for row in report["findings"]]

    assert REQUIRED_REPORT_KEYS <= set(grown)
    assert REQUIRED_FINDING_KEYS <= set(grown["findings"][0])


def test_report_is_json_round_trippable():
    """The artifact contract: whatever the pipeline emits must survive
    json.dump/load unchanged (no datetimes, no custom objects)."""
    report = _report()
    assert json.loads(json.dumps(report)) == report
