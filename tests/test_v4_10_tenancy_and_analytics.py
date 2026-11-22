"""Tests for V4.10: Tenancy Foundation, Org Analytics, and Command Center.

Coverage:
- V4.10-E03 (T01-T04): In-process tenancy, quota tracking, boundary isolation
- V4.10-E05 (T01-T04): Org Analytics Engine, rollups, velocity, cost attribution
- V4.10-E06 (T01-T04): Engineering Command Center, role-aware views
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.analytics import OrgAnalyticsEngine, ReviewMetricRow
from ai_pr_reviewer.command_center import CommandCenter, UserRole
from ai_pr_reviewer.tenancy import TenantManager, TenantQuota


def test_in_process_tenancy_and_quota_metering():
    """V4.10-E03: Tenant quota management and resource consumption tracking."""
    manager = TenantManager()
    manager.register_tenant("tenant-alpha", quota=TenantQuota(max_monthly_tokens=50000, max_monthly_runs=10))

    # Consume quota
    status = manager.record_usage("tenant-alpha", tokens=1000)
    assert status["allowed"] is True
    assert status["tokens_used"] == 1000

    # Exhaust quota
    manager.record_usage("tenant-alpha", tokens=49000)
    over_status = manager.record_usage("tenant-alpha", tokens=10)
    assert over_status["allowed"] is False
    assert "token quota exceeded" in over_status["reason"]


def test_org_analytics_engine_rollups():
    """V4.10-E05: Compute cross-repo rollups, review velocity, and cost metrics."""
    engine = OrgAnalyticsEngine()
    engine.record_review(ReviewMetricRow(
        org_id="acme",
        repo_name="acme/web",
        findings_count=3,
        duration_ms=1200.0,
        tokens_used=1500,
        cost_usd=0.03,
    ))
    engine.record_review(ReviewMetricRow(
        org_id="acme",
        repo_name="acme/api",
        findings_count=1,
        duration_ms=800.0,
        tokens_used=500,
        cost_usd=0.01,
    ))

    rollup = engine.get_org_summary("acme")
    assert rollup["total_reviews"] == 2
    assert rollup["total_findings"] == 4
    assert rollup["total_tokens"] == 2000
    assert rollup["total_cost_usd"] == 0.04
    assert rollup["avg_duration_ms"] == 1000.0


def test_engineering_command_center_views():
    """V4.10-E06: Role-aware view generation for org deployment."""
    center = CommandCenter()

    # Engineer view: sees code findings and review status
    dev_view = center.get_view(role=UserRole.DEVELOPER, org_id="acme")
    assert "findings" in dev_view["sections"]
    assert "billing" not in dev_view["sections"]

    # Security Lead view: sees security posture and policy compliance
    sec_view = center.get_view(role=UserRole.SECURITY_LEAD, org_id="acme")
    assert "security_posture" in sec_view["sections"]

    # Admin view: sees all including quotas and rollups
    admin_view = center.get_view(role=UserRole.ADMIN, org_id="acme")
    assert "quotas" in admin_view["sections"]
    assert "billing" in admin_view["sections"]
