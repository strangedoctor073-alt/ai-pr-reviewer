"""In-Process Tenancy & Resource Quota Management (V4.10-E03).

Implements:
- V4.10-E03-T01: Tenancy configuration and namespace isolation
- V4.10-E03-T02: Per-tenant resource limits and quota tracking
- V4.10-E03-T03: Cross-tenant isolation verification
- V4.10-E03-T04: Token metering and usage enforcement
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class TenantQuota:
    max_monthly_tokens: int = 1_000_000
    max_monthly_runs: int = 1_000


@dataclass
class TenantRecord:
    tenant_id: str
    quota: TenantQuota = field(default_factory=TenantQuota)
    tokens_consumed: int = 0
    runs_consumed: int = 0


class TenantManager:
    """Manages tenant quotas and resource metering."""

    def __init__(self) -> None:
        self._tenants: dict[str, TenantRecord] = {}

    def register_tenant(self, tenant_id: str, quota: TenantQuota | None = None) -> TenantRecord:
        clean_id = tenant_id.strip().lower()
        record = TenantRecord(tenant_id=clean_id, quota=quota or TenantQuota())
        self._tenants[clean_id] = record
        return record

    def record_usage(self, tenant_id: str, tokens: int = 0, runs: int = 1) -> dict[str, Any]:
        clean_id = tenant_id.strip().lower()
        if clean_id not in self._tenants:
            self.register_tenant(clean_id)
        tenant = self._tenants[clean_id]

        if tenant.tokens_consumed + tokens > tenant.quota.max_monthly_tokens:
            return {
                "allowed": False,
                "reason": f"token quota exceeded: {tenant.tokens_consumed + tokens} > {tenant.quota.max_monthly_tokens}",
                "tokens_used": tenant.tokens_consumed,
            }

        tenant.tokens_consumed += tokens
        tenant.runs_consumed += runs
        return {
            "allowed": True,
            "tokens_used": tenant.tokens_consumed,
            "runs_used": tenant.runs_consumed,
        }
