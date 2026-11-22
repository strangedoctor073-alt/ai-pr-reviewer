"""Tests for V4.0-E03 Finding Merger.

Covers:
- V4.0-E03-T01: Cross-specialist dedup module on identity v2
- V4.0-E03-T02: Severity reconciliation rules (deterministic)
- V4.0-E03-T03: ConflictRecord type (disagreements recorded, never silent winners)
- V4.0-E03-T04: Determinism under task order permutations
"""
from __future__ import annotations

import json
import random
from ai_pr_reviewer.models import EvidenceRecord, Finding, ProvenanceSource
from ai_pr_reviewer.orchestration.merger import (
    ConflictRecord,
    MergeResult,
    merge_findings,
    reconcile_severity,
)


def test_conflict_record_creation_and_to_dict():
    conflict = ConflictRecord(
        fingerprint="fp1234567890abcd",
        file="src/auth.py",
        line=42,
        conflict_type="severity",
        specialists=("security", "generalist"),
        values=("critical", "medium"),
        resolved_value="critical",
        description="Specialists disagreed on severity: security=critical, generalist=medium",
    )
    d = conflict.to_dict()
    assert d["fingerprint"] == "fp1234567890abcd"
    assert d["file"] == "src/auth.py"
    assert d["line"] == 42
    assert d["conflict_type"] == "severity"
    assert d["specialists"] == ["security", "generalist"]
    assert d["values"] == ["critical", "medium"]
    assert d["resolved_value"] == "critical"
    # JSON round-trip
    assert json.loads(json.dumps(d)) == d


def test_conflict_record_redacts_secrets_in_description():
    conflict = ConflictRecord(
        fingerprint="fp1234567890abcd",
        file="src/auth.py",
        line=42,
        conflict_type="suggestion",
        specialists=("security", "generalist"),
        values=("val1", "val2"),
        resolved_value="val1",
        description="Leaked token ghp_111111111111111111111111111111111111 in review",
    )
    assert "ghp_1111" not in conflict.description
    assert "[REDACTED]" in conflict.description


def test_severity_reconciliation_highest_wins():
    # critical vs medium -> critical, conflict=True
    sev, has_conflict = reconcile_severity(["medium", "critical"])
    assert sev == "critical"
    assert has_conflict is True

    # high vs info -> high, conflict=True
    sev, has_conflict = reconcile_severity(["info", "high"])
    assert sev == "high"
    assert has_conflict is True

    # medium vs medium -> medium, conflict=False
    sev, has_conflict = reconcile_severity(["medium", "medium"])
    assert sev == "medium"
    assert has_conflict is False


def test_merge_identical_findings_from_two_specialists():
    f1 = Finding(
        file="src/payments.py",
        line=10,
        severity="high",
        category="security",
        title="SQL injection via formatted query",
        explanation="Untrusted input passed to execute()",
        provenance_engine="claude",
        provenance_model="claude-sonnet-4-6",
        provenance_agent="security-reviewer",
        provenance_sources=(
            ProvenanceSource(engine="claude", model="claude-sonnet-4-6", agent="security-reviewer"),
        ),
        evidence=(EvidenceRecord.create(kind="file_excerpt", locator="src/payments.py:10", summary="call to execute()"),),
    )
    f2 = Finding(
        file="src/payments.py",
        line=10,
        severity="high",
        category="security",
        title="SQL injection via formatted query",
        explanation="Untrusted input passed to execute()",
        provenance_engine="openai",
        provenance_model="gpt-4o",
        provenance_agent="generalist",
        provenance_sources=(
            ProvenanceSource(engine="openai", model="gpt-4o", agent="generalist"),
        ),
        evidence=(EvidenceRecord.create(kind="diff_hunk", locator="src/payments.py:10", summary="diff line"),),
    )

    result = merge_findings([f1, f2])
    assert len(result.findings) == 1
    merged = result.findings[0]

    # Merged provenance sources should contain both
    assert len(merged.provenance_sources) == 2
    agents = {s.agent for s in merged.provenance_sources}
    assert agents == {"security-reviewer", "generalist"}

    # Merged evidence should contain both kinds
    assert len(merged.evidence) == 2
    kinds = {e.kind for e in merged.evidence}
    assert kinds == {"file_excerpt", "diff_hunk"}

    # No severity conflict
    assert len(result.conflicts) == 0
    assert result.merged_count == 1


def test_merge_conflicting_severity_generates_conflict_record():
    f1 = Finding(
        file="src/api.py",
        line=25,
        severity="critical",
        category="security",
        title="Hardcoded credentials",
        explanation="Secret key in source code",
        provenance_agent="security-specialist",
    )
    f2 = Finding(
        file="src/api.py",
        line=25,
        severity="medium",
        category="security",
        title="Hardcoded credentials",
        explanation="Secret key in source code",
        provenance_agent="code-quality-specialist",
    )

    result = merge_findings([f1, f2])
    assert len(result.findings) == 1
    merged = result.findings[0]

    # Reconciled to highest severity
    assert merged.severity == "critical"

    # Explicit conflict record generated
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.conflict_type == "severity"
    assert conflict.file == "src/api.py"
    assert conflict.line == 25
    assert conflict.resolved_value == "critical"
    assert "security-specialist" in conflict.specialists
    assert "code-quality-specialist" in conflict.specialists


def test_merge_determinism_under_task_order_permutations():
    """T04: Determinism - completion order cannot change merged output."""
    def make_finding(file, line, sev, agent):
        return Finding(
            file=file,
            line=line,
            severity=sev,
            title=f"Issue at {file}:{line}",
            explanation="detail",
            provenance_agent=agent,
        )

    f_list = [
        make_finding("src/b.py", 20, "high", "sec"),
        make_finding("src/a.py", 10, "critical", "qa"),
        make_finding("src/b.py", 20, "critical", "arch"),  # conflict on b.py:20
        make_finding("src/c.py", 5, "info", "perf"),
    ]

    res1 = merge_findings(f_list)

    # Shuffle 10 times and verify identical result
    rng = random.Random(42)
    for _ in range(10):
        shuffled = list(f_list)
        rng.shuffle(shuffled)
        res_shuffled = merge_findings(shuffled)

        assert len(res_shuffled.findings) == len(res1.findings)
        for expected, actual in zip(res1.findings, res_shuffled.findings):
            assert expected.file == actual.file
            assert expected.line == actual.line
            assert expected.severity == actual.severity
            assert expected.title == actual.title

        assert len(res_shuffled.conflicts) == len(res1.conflicts)
        for expected_c, actual_c in zip(res1.conflicts, res_shuffled.conflicts):
            assert expected_c.conflict_type == actual_c.conflict_type
            assert expected_c.resolved_value == actual_c.resolved_value


def test_merge_cross_engine_reworded_findings_via_occurrence_key():
    """T01/T04: Two findings with quote variation merge via occurrence key."""
    f1 = Finding(
        file="src/calculator.py",
        line=15,
        severity="high",
        category="security",
        title="Remote code execution in eval()",
        explanation="eval called on untrusted parameter",
        rule_id="SEC001",
        provenance_engine="claude",
        provenance_agent="security-reviewer",
    )
    f2 = Finding(
        file="src/calculator.py",
        line=15,
        severity="medium",
        category="security",
        title="Remote code execution in `eval()`",
        explanation="Use of eval() function",
        rule_id="SEC001",
        provenance_engine="static",
        provenance_agent="ast-specialist",
    )

    result = merge_findings([f1, f2])
    assert len(result.findings) == 1
    merged = result.findings[0]
    assert merged.severity == "high"
    assert result.merged_count == 1
    assert len(result.conflicts) == 1
    assert result.conflicts[0].conflict_type == "severity"


def test_outcome_and_reporter_surfaces_conflicts():
    """T03: Reporter attaches conflicts additively when present."""
    from ai_pr_reviewer import reporter
    from ai_pr_reviewer.models import AnalysisOutcome, PRContext, ReviewResult
    from ai_pr_reviewer.orchestration.executor import FanOutTask, run_fanout
    from ai_pr_reviewer.orchestration.outcome import combine_outcomes

    f_sec = Finding(
        file="src/auth.py",
        line=30,
        severity="critical",
        title="Missing authentication check",
        explanation="Endpoint accessible without token",
        provenance_agent="sec-specialist",
    )
    f_qa = Finding(
        file="src/auth.py",
        line=30,
        severity="medium",
        title="Missing authentication check",
        explanation="Endpoint accessible without token",
        provenance_agent="qa-specialist",
    )

    o1 = AnalysisOutcome(findings=[f_sec], summary="sec", mode="claude", model="c1")
    o2 = AnalysisOutcome(findings=[f_qa], summary="qa", mode="openai", model="o1")

    t1 = FanOutTask("t1", lambda scope: o1, token_budget=100)
    t2 = FanOutTask("t2", lambda scope: o2, token_budget=100)

    report = run_fanout([t1, t2])
    combined = combine_outcomes(report, static_fallback=lambda: o1)

    assert len(combined.findings) == 1
    assert combined.findings[0].severity == "critical"
    assert hasattr(combined, "conflicts")
    assert len(combined.conflicts) == 1

    pr = PRContext(repo="acme/repo", pr_number=10)
    result = ReviewResult(
        pr=pr,
        mode="claude",
        model="c1+o1",
        findings=combined.findings,
        conflicts=combined.conflicts,
    )
    final = reporter.finalize_report(result)
    assert "conflicts" in final
    assert len(final["conflicts"]) == 1
    assert final["conflicts"][0]["conflict_type"] == "severity"
    assert final["conflicts"][0]["resolved_value"] == "critical"
    assert json.loads(json.dumps(final)) == final
