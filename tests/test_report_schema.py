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
    # V4-E04-T04 (D10): risk + verification ship in every report (None
    # when the orchestrator did not compute them) — removing them later is
    # a breaking change, exactly like provenance/evidence above/below.
    "risk", "verification",
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
    # V4-E04 (T02/T03): frozen the same way provenance was in V3 — once a
    # field ships in every report, removing it is a breaking change.
    "provenance_sources", "evidence", "merged_fingerprints",
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


def test_d10_risk_and_verification_absent_is_explicit_null():
    """V4-E04-T04 (D10): a result the orchestrator never labelled carries
    both keys as explicit nulls — the null-with-reason rule (E04-T01),
    never a missing key and never a crash."""
    report = _report()
    assert "risk" in report and report["risk"] is None
    assert "verification" in report and report["verification"] is None


def test_d10_risk_and_verification_surface_bounded_blocks():
    """V4-E04-T04 (D10): computed values surface as bounded, closed-vocab
    blocks — the same data the markdown rows render.

    * level folds to {"low","high"} (markdown's not-high-is-green rule);
    * reasons pass redact_secrets() and are list/length bounded;
    * verification keeps exactly the three C4 keys as non-negative ints —
      unknown keys dropped, malformed values coerced to 0.
    """
    from ai_pr_reviewer.model_router import ReviewRisk

    pr = PRContext(repo="acme/api", pr_number=8, head_sha="b" * 40)
    result = ReviewResult(pr=pr, mode="static", model="static-rules-v1")
    result.risk = ReviewRisk(
        level="medium",                             # out of vocab -> "low"
        reasons=["touches auth/payment/db-looking path(s): src/auth.py",
                 "   ",                             # blanks are dropped
                 "x" * 600])                        # length-bounded
    result.verification = {"resolved": 2, "still_present": 1,
                           "unable_to_verify": 0,
                           "smuggled": 99,           # unknown key dropped
                           "active_findings": -7}    # unknown key dropped
    report = reporter.finalize_report(result, report_id="test-report-d10")

    risk = report["risk"]
    assert risk["level"] == "low"
    assert risk["reasons"][0].startswith("touches auth/payment/db-looking")
    assert all(len(r) <= 500 for r in risk["reasons"])

    # non-dict junk can never masquerade as verification counts
    result.verification = {"resolved": "many", "still_present": -4}
    report = reporter.finalize_report(result, report_id="test-report-d10b")
    assert report["verification"] == {"resolved": 0, "still_present": 0,
                                      "unable_to_verify": 0}
    assert json.loads(json.dumps(report)) == report


def test_d10_high_risk_level_survives_and_reasons_redact():
    """The in-vocab "high" level round-trips untouched; free-text reasons
    run through the same redaction every stored warning gets."""
    from ai_pr_reviewer.model_router import ReviewRisk

    pr = PRContext(repo="acme/api", pr_number=9, head_sha="c" * 40)
    result = ReviewResult(pr=pr, mode="static", model="static-rules-v1")
    result.risk = ReviewRisk(level="high", reasons=[
        "token ghp_" + "a" * 36 + " leaked in diff"])
    result.verification = {"resolved": 1, "still_present": 0,
                           "unable_to_verify": 0}
    report = reporter.finalize_report(result, report_id="test-report-d10c")

    assert report["risk"]["level"] == "high"
    assert report["risk"]["reasons"], "reason must not vanish, only redact"
    assert "ghp_" + "a" * 36 not in report["risk"]["reasons"][0]
    assert report["verification"] == {"resolved": 1, "still_present": 0,
                                      "unable_to_verify": 0}
