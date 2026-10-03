"""Tests for lifecycle enums, Finding/PRContext additions,
ReviewKey identity, moved AnalysisOutcome, review_state helpers, .gitignore."""
from __future__ import annotations

import dataclasses
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import models, review_state
from ai_pr_reviewer.models import (AnalysisOutcome, Finding, FindingState,
                                   PRContext, ReviewKey, ReviewState)
from ai_pr_reviewer.review_state import (is_persistable, review_id_for,
                                         review_key_for)

LEGACY_FINDING_FIELDS = [
    "file", "line", "end_line", "severity", "category", "title",
    "explanation", "suggestion", "confidence", "rule_id",
]
NEW_FINDING_FIELDS = [
    "fingerprint", "state", "first_seen_sha", "last_seen_sha",
    "resolved_at", "github_comment_id",
    # V3 C4: fix verification, appended last and pipeline-owned.
    "verification_status", "verification_reason", "verified_at",
]


def _names(cls) -> list[str]:
    return [f.name for f in dataclasses.fields(cls)]


# ------------------------------------------------------------------ enums

def test_review_state_values():
    assert {s.value for s in ReviewState} == {
        "pending", "running", "completed", "failed", "fallback"}


def test_finding_state_values():
    assert {s.value for s in FindingState} == {
        "new", "active", "resolved", "reopened", "dismissed", "muted"}


def test_enums_are_str_compatible():
    assert FindingState.NEW == "new"
    assert ReviewState.FALLBACK == "fallback"
    assert json.dumps({"s": FindingState.ACTIVE}) == '{"s": "active"}'


# ---------------------------------------------------------------- Finding

def test_finding_field_order_is_append_only():
    assert _names(Finding) == LEGACY_FINDING_FIELDS + NEW_FINDING_FIELDS


def test_finding_new_field_defaults():
    f = Finding(file="a.py", line=1)
    assert f.fingerprint is None
    assert f.state == "new"
    assert f.first_seen_sha is None and f.last_seen_sha is None
    assert f.resolved_at is None
    assert f.github_comment_id is None


def test_finding_legacy_construction_still_works():
    f = Finding(file="x.py", line=99, severity="high", title="t", explanation="e")
    assert (f.file, f.line, f.severity, f.title) == ("x.py", 99, "high", "t")


def test_to_dict_keeps_legacy_keys_and_adds_new_ones():
    d = Finding(file="a.py", line=3, severity="high", title="T").to_dict()
    for key in LEGACY_FINDING_FIELDS + NEW_FINDING_FIELDS:
        assert key in d
    assert d["severity"] == "high" and d["state"] == "new"
    assert d["fingerprint"] is None and d["github_comment_id"] is None


def test_to_dict_emits_plain_string_state_for_enum_members():
    f = Finding(file="a.py", line=1, state=FindingState.ACTIVE)  # type: ignore[arg-type]
    state = f.to_dict()["state"]
    assert state == "active" and type(state) is str


def test_round_trip_preserves_lifecycle_fields():
    f = Finding(
        file="a.py", line=10, end_line=12, severity="critical", category="security",
        title="SQL injection", explanation="e", suggestion="s", confidence="high",
        rule_id="SEC001", fingerprint="abc123", state="resolved",
        first_seen_sha="1" * 40, last_seen_sha="2" * 40,
        resolved_at="2026-09-19T10:00:00Z", github_comment_id=987654321,
    )
    assert Finding.from_dict(f.to_dict()) == f


def test_from_dict_legacy_payload_gets_defaults():
    legacy = {"file": "a.py", "line": 5, "severity": "low", "title": "old"}
    f = Finding.from_dict(legacy)
    assert f.state == "new"
    assert f.fingerprint is None and f.github_comment_id is None
    assert f.first_seen_sha is None and f.resolved_at is None


@pytest.mark.parametrize("raw", ["bogus", "", None, 42])
def test_from_dict_unknown_state_falls_back_to_new(raw):
    assert Finding.from_dict({"file": "a.py", "line": 1, "state": raw}).state == "new"


def test_from_dict_normalises_state_case_and_enum():
    assert Finding.from_dict({"file": "a", "line": 1, "state": " Muted "}).state == "muted"
    assert Finding.from_dict(
        {"file": "a", "line": 1, "state": FindingState.REOPENED}).state == "reopened"


def test_from_dict_blank_optionals_become_none_and_comment_id_is_int():
    f = Finding.from_dict({"file": "a", "line": 1, "fingerprint": "  ",
                           "resolved_at": "", "github_comment_id": "123"})
    assert f.fingerprint is None and f.resolved_at is None
    assert f.github_comment_id == 123
    assert Finding.from_dict({"file": "a", "line": 1,
                              "github_comment_id": ""}).github_comment_id is None


def test_from_untrusted_dict_drops_pipeline_owned_fields():
    hostile = {
        "file": "a.py", "line": 7, "severity": "high", "title": "Real title",
        "fingerprint": "forged", "state": "muted", "first_seen_sha": "deadbeef",
        "last_seen_sha": "deadbeef", "resolved_at": "2026-01-01T00:00:00Z",
        "github_comment_id": 1,
    }
    f = Finding.from_untrusted_dict(hostile)
    assert (f.file, f.line, f.severity, f.title) == ("a.py", 7, "high", "Real title")
    assert f.fingerprint is None and f.state == "new"
    assert f.first_seen_sha is None and f.last_seen_sha is None
    assert f.resolved_at is None and f.github_comment_id is None
    assert set(models.LIFECYCLE_FIELDS) == set(NEW_FINDING_FIELDS)


# ---------------------------------------------------------------- PRContext

def test_prcontext_base_sha_appended_last_with_empty_default():
    assert _names(PRContext) == [
        "repo", "pr_number", "pr_title", "author", "branch", "base",
        "head_sha", "url", "base_sha"]
    assert PRContext(repo="a/b", pr_number=1).base_sha == ""


# ---------------------------------------------------------------- ReviewKey

def test_review_key_as_id_truncates_sha_to_12():
    key = ReviewKey(repo="acme/payments", pr_number=42, head_sha="0123456789abcdef" * 2)
    assert key.as_id() == "acme/payments#42@0123456789ab"


def test_review_key_short_sha_is_kept_whole():
    assert ReviewKey("a/b", 1, "abc123").as_id() == "a/b#1@abc123"


def test_review_key_is_deterministic_and_commit_specific():
    a = ReviewKey("a/b", 1, "a" * 40)
    assert a.as_id() == ReviewKey("a/b", 1, "a" * 40).as_id()
    assert a == ReviewKey("a/b", 1, "a" * 40)
    assert a.as_id() != ReviewKey("a/b", 1, "b" * 40).as_id()
    assert a.as_id() != ReviewKey("a/b", 2, "a" * 40).as_id()
    assert a.as_id() != ReviewKey("a/c", 1, "a" * 40).as_id()


# ---------------------------------------------------------- AnalysisOutcome

def test_analysis_outcome_defaults_and_field_order():
    assert _names(AnalysisOutcome) == [
        "findings", "summary", "mode", "model", "warnings",
        "engine", "fallback_used", "batch_count"]
    o = AnalysisOutcome([], "s", mode="static", model="static-rules-v1")
    assert o.warnings == [] and o.engine == ""
    assert o.fallback_used is False and o.batch_count == 0


def test_analysis_outcome_positional_construction_matches_v1_usage():
    f = Finding(file="a.py", line=1)
    o = AnalysisOutcome([f], "sum", mode="claude", model="m", warnings=["w"])
    assert o.findings == [f] and o.mode == "claude" and o.warnings == ["w"]


def test_analysis_outcome_warnings_not_shared_between_instances():
    a = AnalysisOutcome([], "", mode="x", model="y")
    b = AnalysisOutcome([], "", mode="x", model="y")
    a.warnings.append("only a")
    assert b.warnings == []


def test_analysis_outcome_carries_v2_fields():
    o = AnalysisOutcome([], "s", mode="claude", model="m",
                        engine="claude+static", fallback_used=True, batch_count=4)
    assert (o.engine, o.fallback_used, o.batch_count) == ("claude+static", True, 4)


# ---------------------------------------------------- review_state helpers

def test_review_state_reexports_are_the_models_objects():
    assert review_state.ReviewKey is models.ReviewKey
    assert review_state.ReviewState is models.ReviewState
    assert review_state.FindingState is models.FindingState


def test_review_key_for_and_review_id_for():
    pr = PRContext(repo="acme/payments", pr_number=42, head_sha="f" * 40)
    assert review_key_for(pr) == ReviewKey("acme/payments", 42, "f" * 40)
    assert review_id_for(pr) == "acme/payments#42@ffffffffffff"


def test_is_persistable():
    assert is_persistable(ReviewKey("a/b", 1, "abc123"))
    # local --diff-file runs: pr_number 0, no head SHA
    assert not is_persistable(ReviewKey("local/project", 0, ""))
    assert not is_persistable(ReviewKey("a/b", 1, ""))
    assert not is_persistable(ReviewKey("a/b", 0, "abc123"))
    assert not is_persistable(ReviewKey("", 1, "abc123"))


# ------------------------------------------------------------- .gitignore

def test_gitkeep_placeholder_exists():
    assert (ROOT / "dashboard" / "data" / ".gitkeep").is_file()


def test_gitignore_lists_required_patterns():
    lines = {ln.strip() for ln in (ROOT / ".gitignore").read_text().splitlines()}
    for pattern in ("dashboard/data/*", "!dashboard/data/.gitkeep", "*.db",
                    "*.db-shm", "*.db-wal", "*.jsonl", ".env", ".env.*",
                    "!.env.example"):
        assert pattern in lines, pattern
    # The example file must be re-included AFTER the .env.* wildcard.
    text = (ROOT / ".gitignore").read_text().splitlines()
    assert text.index("!.env.example") > text.index(".env.*")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_gitignore_behaviour_with_real_git(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / ".gitignore").write_text((ROOT / ".gitignore").read_text())

    ignored = [
        "dashboard/data/settings.json", "dashboard/data/reviews.db",
        "dashboard/data/reviews.db-shm", "dashboard/data/reviews.db-wal",
        "dashboard/data/audit.jsonl", "dashboard/data/.migrated",
        "dashboard/data/reports/acme-payments-pr42.json",
        "other/place/local.db", ".env", ".env.local",
    ]
    tracked = [
        "dashboard/data/.gitkeep", ".env.example", "dashboard/app.py",
        "ai_pr_reviewer/models.py", "tests/test_review_state.py",
    ]
    for rel in ignored + tracked:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x")

    def is_ignored(rel: str) -> bool:
        r = subprocess.run(["git", "-C", str(tmp_path), "check-ignore", "-q", rel])
        return r.returncode == 0

    for rel in ignored:
        assert is_ignored(rel), f"{rel} should be ignored"
    for rel in tracked:
        assert not is_ignored(rel), f"{rel} should NOT be ignored"
