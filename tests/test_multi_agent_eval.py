"""Tests for V4.0-E08 Multi-Agent Evaluation Harness.

Covers:
- V4.0-E08-T01: Multi-agent corpus scenarios
- V4.0-E08-T02: Merge precision & recall scoring
- V4.0-E08-T03: Disagreement and conflict accuracy scoring
- V4.0-E08-T04: A/B comparison report (single vs multi-agent council)
"""
from __future__ import annotations

import json
from ai_pr_reviewer.models import AnalysisOutcome, Finding, ProvenanceSource
from ai_pr_reviewer.orchestration.merger import ConflictRecord, MergeResult
from eval.harness.multi_agent import (
    CouncilABReport,
    MultiAgentScenario,
    MultiAgentScore,
    run_council_ab_comparison,
    score_multi_agent_merge,
)


def test_multi_agent_scenario_and_score():
    """T01/T02/T03: Score multi-agent merge against expected scenario."""
    f1 = Finding(
        file="src/auth.py",
        line=10,
        severity="critical",
        title="SQL injection",
        explanation="detail",
        provenance_agent="sec",
    )
    f2 = Finding(
        file="src/auth.py",
        line=10,
        severity="medium",
        title="SQL injection",
        explanation="detail",
        provenance_agent="qa",
    )
    f3 = Finding(
        file="src/perf.py",
        line=5,
        severity="low",
        title="Unindexed query",
        explanation="detail",
        provenance_agent="perf",
    )

    conflict = ConflictRecord(
        fingerprint="fp1",
        file="src/auth.py",
        line=10,
        conflict_type="severity",
        specialists=("sec", "qa"),
        values=("critical", "medium"),
        resolved_value="critical",
    )

    merge_result = MergeResult(
        findings=[f1, f3],
        conflicts=[conflict],
        merged_count=1,
    )

    scenario = MultiAgentScenario(
        name="auth_and_perf",
        expected_findings_count=2,
        expected_conflicts_count=1,
        expected_severities={"src/auth.py:10": "critical", "src/perf.py:5": "low"},
    )

    score = score_multi_agent_merge(merge_result, scenario)
    assert score.passed is True
    assert score.merge_recall == 1.0
    assert score.conflict_accuracy == 1.0
    assert score.severity_accuracy == 1.0


def test_council_ab_comparison_generation():
    """T04: Generate A/B comparison report between baseline and council."""
    baseline = AnalysisOutcome(
        findings=[
            Finding(file="src/api.py", line=1, severity="medium", title="Generic bug"),
        ],
        summary="Single generalist review.",
        mode="claude",
        model="claude-sonnet-4-6",
    )

    council = AnalysisOutcome(
        findings=[
            Finding(file="src/api.py", line=1, severity="critical", title="Auth bypass", provenance_agent="sec"),
            Finding(file="src/api.py", line=20, severity="high", title="Leak", provenance_agent="qa"),
        ],
        summary="Council synthesis review.",
        mode="claude",
        model="claude-sonnet-4-6",
    )
    council.conflicts = [
        ConflictRecord(
            fingerprint="fp1",
            file="src/api.py",
            line=1,
            conflict_type="severity",
            specialists=("sec", "qa"),
            values=("critical", "medium"),
            resolved_value="critical",
        )
    ]

    report = run_council_ab_comparison(baseline, council)
    assert isinstance(report, CouncilABReport)
    assert report.baseline_findings_count == 1
    assert report.council_findings_count == 2
    assert report.findings_delta == 1
    assert report.conflicts_count == 1
    assert "A/B Comparison" in report.summary

    # JSON serializable
    d = report.to_dict()
    assert d["baseline_findings_count"] == 1
    assert d["council_findings_count"] == 2
    assert json.loads(json.dumps(d)) == d
