"""Org Policy Hierarchy & Inheritance (V4.8-E02).

Implements:
- V4.8-E02-T01: OrgPolicy document model (.ai-pr-reviewer.org.yml)
- V4.8-E02-T02: Inheritance precedence resolver (enforced org rules override repo)
- V4.8-E02-T03: Clause provenance tracking across scopes
- V4.8-E02-T04: Baseline integrity tests
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass
class OrgPolicy:
    org_id: str
    rules: dict[str, Any] = field(default_factory=dict)
    enforced_rules: set[str] = field(default_factory=set)


@dataclass
class RepoPolicy:
    repo_name: str
    rules: dict[str, Any] = field(default_factory=dict)


def resolve_policy_hierarchy(org_policy: OrgPolicy | None, repo_policy: RepoPolicy | None) -> dict[str, Any]:
    """Resolve effective policy with strict org enforcement and clause provenance."""
    effective: dict[str, Any] = {}
    provenance: dict[str, str] = {}

    # Layer 1: Org defaults
    if org_policy:
        for k, v in org_policy.rules.items():
            effective[k] = v
            provenance[k] = f"org:{org_policy.org_id}"

    # Layer 2: Repo customizations (if not in org_policy.enforced_rules)
    if repo_policy:
        enforced = org_policy.enforced_rules if org_policy else set()
        for k, v in repo_policy.rules.items():
            if k in enforced:
                continue  # Repo cannot override org enforced rules
            effective[k] = v
            provenance[k] = f"repo:{repo_policy.repo_name}"

    effective["_provenance"] = provenance
    return effective
