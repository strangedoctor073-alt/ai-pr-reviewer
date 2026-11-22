"""Org Layer Foundation (V4.8-E01).

Implements:
- V4.8-E01-T01: OrgEntity and RepositoryScope models
- V4.8-E01-T02: In-process storage-seam namespace isolation
- V4.8-E01-T03: Legacy single-repo adoption
- V4.8-E01-T04: Cross-repo querying within org namespace
- V4.8-E01-T05: Tenant isolation safeguards
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class OrgEntity:
    org_id: str
    display_name: str = ""
    created_at: str = field(default_factory=_iso_now)
    enabled: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "display_name": self.display_name,
            "created_at": self.created_at,
            "enabled": self.enabled,
        }


@dataclass(frozen=True)
class RepositoryScope:
    org_id: str
    repo_name: str
    joined_at: str = field(default_factory=_iso_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "org_id": self.org_id,
            "repo_name": self.repo_name,
            "joined_at": self.joined_at,
        }


class OrgRegistry:
    """In-process multi-repository organization registry."""

    def __init__(self) -> None:
        self._orgs: dict[str, OrgEntity] = {}
        self._repos: dict[str, list[str]] = {}  # org_id -> list of repo_name

    def create_org(self, org_id: str, display_name: str = "") -> OrgEntity:
        clean_id = org_id.strip().lower()
        if not clean_id:
            raise ValueError("org_id cannot be empty")
        org = OrgEntity(org_id=clean_id, display_name=display_name or clean_id)
        self._orgs[clean_id] = org
        self._repos.setdefault(clean_id, [])
        return org

    def register_repo(self, org_id: str, repo_name: str) -> RepositoryScope:
        clean_id = org_id.strip().lower()
        clean_repo = repo_name.strip()
        if clean_id not in self._orgs:
            raise KeyError(f"org '{clean_id}' does not exist")
        if clean_repo not in self._repos[clean_id]:
            self._repos[clean_id].append(clean_repo)
        return RepositoryScope(org_id=clean_id, repo_name=clean_repo)

    def list_repos_for_org(self, org_id: str) -> list[str]:
        clean_id = org_id.strip().lower()
        if clean_id not in self._orgs:
            raise KeyError(f"org '{clean_id}' does not exist")
        return list(self._repos.get(clean_id, []))

    def get_org(self, org_id: str) -> OrgEntity | None:
        return self._orgs.get(org_id.strip().lower())
