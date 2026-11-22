"""Org-Scale Analytics & Metrics Engine (V4.10-E05).

Implements:
- V4.10-E05-T01: Org-wide review metric aggregations
- V4.10-E05-T02: Velocity and duration rollups
- V4.10-E05-T03: Cost and token usage attribution
- V4.10-E05-T04: Cross-repository summary reports
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ReviewMetricRow:
    org_id: str
    repo_name: str
    findings_count: int
    duration_ms: float
    tokens_used: int = 0
    cost_usd: float = 0.0


class OrgAnalyticsEngine:
    """Aggregates review velocity, findings, and costs across repositories in an org."""

    def __init__(self) -> None:
        self._rows: list[ReviewMetricRow] = []

    def record_review(self, row: ReviewMetricRow) -> None:
        self._rows.append(row)

    def get_org_summary(self, org_id: str) -> dict[str, Any]:
        clean_org = org_id.strip().lower()
        org_rows = [r for r in self._rows if r.org_id == clean_org]
        total_reviews = len(org_rows)
        if total_reviews == 0:
            return {
                "org_id": clean_org,
                "total_reviews": 0,
                "total_findings": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "avg_duration_ms": 0.0,
            }

        total_findings = sum(r.findings_count for r in org_rows)
        total_tokens = sum(r.tokens_used for r in org_rows)
        total_cost = sum(r.cost_usd for r in org_rows)
        avg_duration = sum(r.duration_ms for r in org_rows) / total_reviews

        return {
            "org_id": clean_org,
            "total_reviews": total_reviews,
            "total_findings": total_findings,
            "total_tokens": total_tokens,
            "total_cost_usd": round(total_cost, 4),
            "avg_duration_ms": round(avg_duration, 2),
        }
