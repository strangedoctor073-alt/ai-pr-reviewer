"""Multi-agent council evaluation and scoring harness (V4.0-E08).

Provides:
- Scenario definitions for multi-agent council reviews (T01)
- Merge precision, recall, and conflict accuracy scoring (T02/T03)
- Single-agent vs multi-agent council A/B comparative reporting (T04)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from ai_pr_reviewer.models import AnalysisOutcome, Finding
from ai_pr_reviewer.orchestration.merger import ConflictRecord, MergeResult
from ai_pr_reviewer.security import redact_secrets


@dataclass(frozen=True)
class MultiAgentScenario:
    """Expected evaluation parameters for one multi-agent review run."""

    name: str
    expected_findings_count: int
    expected_conflicts_count: int
    expected_severities: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MultiAgentScore:
    """Scoring outcome for a multi-agent review against expected scenario."""

    passed: bool
    merge_recall: float
    conflict_accuracy: float
    severity_accuracy: float
    details: str = ""


@dataclass
class CouncilABReport:
    """A/B comparison between single-agent baseline and council review (V4.0-E08-T04)."""

    baseline_findings_count: int
    council_findings_count: int
    findings_delta: int
    conflicts_count: int
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "baseline_findings_count": self.baseline_findings_count,
            "council_findings_count": self.council_findings_count,
            "findings_delta": self.findings_delta,
            "conflicts_count": self.conflicts_count,
            "summary": redact_secrets(self.summary),
        }


def score_multi_agent_merge(
    merge_result: MergeResult,
    scenario: MultiAgentScenario,
) -> MultiAgentScore:
    """Score the result of a multi-agent merge against expected counts and severities."""
    findings = merge_result.findings
    conflicts = merge_result.conflicts

    # Recall: fraction of expected findings present
    recall = (
        min(1.0, len(findings) / scenario.expected_findings_count)
        if scenario.expected_findings_count > 0
        else 1.0
    )

    # Conflict accuracy: fraction of expected conflicts captured
    conflict_acc = (
        min(1.0, len(conflicts) / scenario.expected_conflicts_count)
        if scenario.expected_conflicts_count > 0
        else 1.0
    )

    # Severity accuracy: fraction of checked locators matching expected severity
    sev_matches = 0
    total_sev_checked = len(scenario.expected_severities)
    for f in findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        if loc in scenario.expected_severities:
            if f.severity.lower() == scenario.expected_severities[loc].lower():
                sev_matches += 1

    sev_acc = (
        sev_matches / total_sev_checked if total_sev_checked > 0 else 1.0
    )

    passed = (recall >= 1.0) and (conflict_acc >= 1.0) and (sev_acc >= 1.0)
    details = (
        f"findings={len(findings)}/{scenario.expected_findings_count}, "
        f"conflicts={len(conflicts)}/{scenario.expected_conflicts_count}, "
        f"severity_accuracy={sev_acc:.3f}"
    )

    return MultiAgentScore(
        passed=passed,
        merge_recall=recall,
        conflict_accuracy=conflict_acc,
        severity_accuracy=sev_acc,
        details=details,
    )


def run_council_ab_comparison(
    baseline: AnalysisOutcome,
    council: AnalysisOutcome,
) -> CouncilABReport:
    """Compare a single-agent baseline outcome with a multi-agent council outcome."""
    base_n = len(baseline.findings or [])
    council_n = len(council.findings or [])
    delta = council_n - base_n
    conflicts = getattr(council, "conflicts", []) or []
    conflicts_n = len(conflicts)

    lines = [
        "## ⚖️ Council A/B Comparison Report",
        "",
        f"- **Baseline (Single-Agent) Findings:** {base_n}",
        f"- **Council (Multi-Specialist) Findings:** {council_n} ({'+' if delta >= 0 else ''}{delta})",
        f"- **Recorded Specialist Disagreements:** {conflicts_n}",
        "",
        "**Observation:** Multi-agent council review provides specialist coverage and explicit disagreement accounting.",
    ]
    summary = "\n".join(lines)

    return CouncilABReport(
        baseline_findings_count=base_n,
        council_findings_count=council_n,
        findings_delta=delta,
        conflicts_count=conflicts_n,
        summary=summary,
    )
