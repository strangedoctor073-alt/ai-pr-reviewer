"""Tests for V4.8: Org Layer, Policy Hierarchy, and Org Memory.

Coverage:
- V4.8-E01 (T01-T05): Org Layer Foundation, namespace isolation, cross-repo query
- V4.8-E02 (T01-T04): Org Policy Hierarchy, inheritance precedence, clause provenance
- V4.8-E05 (T01-T04): Org-scope memory, human-gated promotion, cross-repo retrieval
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.org import OrgEntity, OrgRegistry, RepositoryScope
from ai_pr_reviewer.org_memory import OrgMemoryStore
from ai_pr_reviewer.policy_hierarchy import (
    OrgPolicy,
    RepoPolicy,
    resolve_policy_hierarchy,
)


def test_org_layer_and_namespace_isolation():
    """V4.8-E01: Org entity model and cross-repo namespace query."""
    registry = OrgRegistry()
    org = registry.create_org("acme-corp", display_name="Acme Corporation")
    assert org.org_id == "acme-corp"

    repo1 = registry.register_repo(org_id="acme-corp", repo_name="acme/web")
    repo2 = registry.register_repo(org_id="acme-corp", repo_name="acme/api")

    # Another org
    registry.create_org("other-org")
    registry.register_repo(org_id="other-org", repo_name="other/service")

    # Query repos under acme-corp
    acme_repos = registry.list_repos_for_org("acme-corp")
    assert set(acme_repos) == {"acme/web", "acme/api"}
    assert "other/service" not in acme_repos

    # Cross-tenant isolation: querying invalid org fails
    with pytest.raises(KeyError):
        registry.list_repos_for_org("non-existent-org")


def test_org_policy_hierarchy_and_inheritance():
    """V4.8-E02: Org policy cannot be overridden by repo unless permitted."""
    org_policy = OrgPolicy(
        org_id="acme-corp",
        rules={
            "fail_on": "high",  # Org mandatory rule
            "max_comments": 25,
        },
        enforced_rules={"fail_on"},  # repo cannot relax fail_on
    )

    # Repo attempts to relax fail_on to critical
    repo_policy = RepoPolicy(
        repo_name="acme/web",
        rules={
            "fail_on": "critical",
            "max_comments": 15,  # permitted customization
        },
    )

    effective = resolve_policy_hierarchy(org_policy, repo_policy)
    # fail_on remains "high" because org enforced it
    assert effective["fail_on"] == "high"
    assert effective["max_comments"] == 15
    assert effective["_provenance"]["fail_on"] == "org:acme-corp"
    assert effective["_provenance"]["max_comments"] == "repo:acme/web"


def test_org_scope_shared_memory_and_authorization():
    """V4.8-E05: Org-wide memory with human promotion and cross-repo access."""
    store = OrgMemoryStore()

    # Add note at org level
    rec = store.add_org_rule(
        org_id="acme-corp",
        note="Use Acme internal OAuth provider for all services",
        promoted_by="security-lead (human)",
    )
    assert rec.org_id == "acme-corp"
    assert rec.authority == "human"

    # Authorized repo in same org can retrieve note
    notes = store.get_notes_for_repo("acme-corp", "acme/api")
    assert len(notes) == 1
    assert "OAuth provider" in notes[0].note

    # Unauthorized access from outside org gets empty list
    notes_foreign = store.get_notes_for_repo("other-corp", "other/repo")
    assert len(notes_foreign) == 0
