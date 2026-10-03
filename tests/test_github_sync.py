"""V3 C5 — GitHub finding synchronization: one comment per finding, always
current.

GitHub is a *view* of the reviewer's own state. What is under test here:
a finding's comment id is captured once and reused, a comment is never
posted twice for the same finding, a state change edits the existing
comment with a marker instead of opening a new one, a human's comment (or
one on another commit) is never claimed as ours, and *every* GitHub failure
degrades to a warning — the review result is already written.
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer import cli
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.findings import apply_lifecycle
from ai_pr_reviewer.github_client import GitHubError
from ai_pr_reviewer.github_sync import (MAX_SYNC_ERRORS, STATE_MARKERS,
                                        comment_key, link_comment_ids,
                                        record_comment_ids,
                                        render_finding_comment,
                                        sync_finding_states)
from ai_pr_reviewer.models import Finding, PRContext, ReviewResult

HEAD = "h" * 40
PR = PRContext(repo="acme/api", pr_number=7, head_sha=HEAD)


def _finding(title: str = "SQL injection", line: int | None = 5,
             state: str | None = None) -> Finding:
    f = Finding(file="app/main.py", line=line, severity="high", title=title,
                explanation="because", suggestion="cursor.execute(p)")
    if state:
        f.state = state
    return f


def _result(findings) -> ReviewResult:
    return ReviewResult(pr=PR, findings=list(findings))


class FakeGH:
    def __init__(self, comments=None, update_error=None, list_error=None):
        self.comments = list(comments or [])
        self.updates: list[tuple[int, str]] = []
        self.update_error = update_error
        self.list_error = list_error
        self.posted: list[dict] = []

    def list_review_comments(self, number, limit=100):
        if self.list_error:
            raise self.list_error
        return list(self.comments)

    def update_review_comment(self, comment_id, body):
        if self.update_error:
            raise self.update_error
        self.updates.append((int(comment_id), body))
        return {"ok": True}

    def post_review(self, number, commit_id, body, comments):
        self.posted.append({"number": number, "commit_id": commit_id,
                            "body": body, "comments": comments})
        return {"ok": True}

    def create_comment(self, number, body):
        self.posted.append({"number": number, "body": body, "comments": []})


# ----------------------------------------------------------------- rendering

def test_render_finding_comment_is_the_whole_comment():
    body = render_finding_comment(_finding())

    assert "SQL injection" in body and "HIGH" in body and "because" in body
    assert "```suggestion" in body and "cursor.execute(p)" in body


def test_post_review_uses_the_same_renderer_as_the_state_updates():
    """Posting and later PATCHing must never drift: same body, plus marker."""
    f = _finding()
    gh = FakeGH()

    posted, res = cli._post_review(gh, Config(), _result([f]), [f])

    assert posted == 1 and res is not None
    assert gh.posted[0]["comments"][0]["body"] == render_finding_comment(f)
    assert gh.posted[0]["comments"][0]["path"] == "app/main.py"
    assert gh.posted[0]["comments"][0]["line"] == 5


def test_a_file_level_finding_is_posted_without_a_line():
    f = _finding(line=None)
    gh = FakeGH()

    cli._post_review(gh, Config(), _result([f]), [f])

    comment = gh.posted[0]["comments"][0]
    assert "line" not in comment and comment["path"] == "app/main.py"
    assert comment_key(f) == ("app/main.py", None)


def test_every_closed_or_reopened_state_has_a_marker_but_new_and_active_do_not():
    assert set(STATE_MARKERS) == {"resolved", "muted", "dismissed", "reopened"}
    assert "new" not in STATE_MARKERS and "active" not in STATE_MARKERS


# ----------------------------------------------------------------- id capture

def test_comment_ids_from_the_422_recovery_response_are_recorded():
    f = _finding()
    response = {"ok": True, "recovered": True,
                "comment_ids": {("app/main.py", 5): 987654}}

    assert record_comment_ids([f], response) == 1
    assert f.github_comment_id == 987654


def test_an_absent_or_malformed_post_response_records_nothing():
    f = _finding()

    assert record_comment_ids([f], {"ok": True}) == 0
    assert record_comment_ids([f], None) == 0
    assert record_comment_ids([f], {"comment_ids": "nonsense"}) == 0
    assert record_comment_ids([f], {"comment_ids": {("app/main.py", 5): "x"}}) == 0
    assert f.github_comment_id is None


def test_a_finding_that_already_has_an_id_is_not_reassigned():
    f = _finding()
    f.github_comment_id = 4242

    assert record_comment_ids([f], {"comment_ids": {("app/main.py", 5): 7}}) == 0
    assert f.github_comment_id == 4242


# ------------------------------------------------------------------- linking

def test_link_comment_ids_matches_path_line_commit_and_exact_first_line():
    f = _finding()
    gh = FakeGH(comments=[{
        "id": 555, "path": "app/main.py", "line": 5, "commit_id": HEAD,
        "body": render_finding_comment(f), "created_at": "2026-01-01T00:00:00Z",
    }])

    linked, warnings = link_comment_ids(gh, 7, [f], HEAD)

    assert linked == 1 and f.github_comment_id == 555
    assert warnings == []


def test_a_humans_comment_on_the_same_line_is_never_claimed():
    f = _finding()
    gh = FakeGH(comments=[{
        "id": 555, "path": "app/main.py", "line": 5, "commit_id": HEAD,
        "body": "LGTM — can you add a test?", "created_at": "2026-01-01T00:00:00Z",
    }])

    linked, _ = link_comment_ids(gh, 7, [f], HEAD)

    assert linked == 0 and f.github_comment_id is None


def test_a_comment_on_another_commit_is_never_claimed():
    f = _finding()
    gh = FakeGH(comments=[{
        "id": 555, "path": "app/main.py", "line": 5, "commit_id": "other" * 8,
        "body": render_finding_comment(f), "created_at": "2026-01-01T00:00:00Z",
    }])

    linked, _ = link_comment_ids(gh, 7, [f], HEAD)

    assert linked == 0 and f.github_comment_id is None


def test_linking_never_claims_a_comment_at_another_location():
    f = _finding()
    gh = FakeGH(comments=[{
        "id": 555, "path": "app/main.py", "line": 99, "commit_id": HEAD,
        "body": render_finding_comment(f), "created_at": "2026-01-01T00:00:00Z",
    }])

    linked, _ = link_comment_ids(gh, 7, [f], HEAD)

    assert linked == 0 and f.github_comment_id is None


def test_linking_is_a_no_op_when_there_is_nothing_pending():
    f = _finding()
    f.github_comment_id = 11

    assert link_comment_ids(None, 7, [f], HEAD) == (0, [])
    assert link_comment_ids(FakeGH(), 7, [], HEAD) == (0, [])


def test_a_client_that_cannot_list_comments_silently_skips_linking():
    class OldGH:
        pass

    f = _finding()
    assert link_comment_ids(OldGH(), 7, [f], HEAD) == (0, [])


def test_linking_failure_becomes_a_warning_not_an_exception():
    f = _finding()
    gh = FakeGH(list_error=GitHubError("forbidden", status_code=403))

    linked, warnings = link_comment_ids(gh, 7, [f], HEAD)

    assert linked == 0
    assert warnings and "could not list GitHub review comments" in warnings[0]


# --------------------------------------------------------------------- sync

def test_a_closed_finding_updates_its_existing_comment_with_a_marker():
    f = _finding(state="resolved")
    f.github_comment_id = 4242
    gh = FakeGH()

    updated, warnings = sync_finding_states(gh, [f])

    assert updated == 1 and warnings == []
    comment_id, body = gh.updates[0]
    assert comment_id == 4242
    assert body.startswith(STATE_MARKERS["resolved"])
    assert "SQL injection" in body           # content survives the marker


def test_new_and_active_findings_keep_their_comment_body_untouched():
    gh = FakeGH()
    assert sync_finding_states(gh, [_finding(), _finding(state="active")]) == (0, [])
    assert gh.updates == []


def test_a_finding_without_a_comment_id_is_not_updated():
    gh = FakeGH()
    assert sync_finding_states(gh, [_finding(state="resolved")]) == (0, [])


@pytest.mark.parametrize("state", ["resolved", "muted", "dismissed", "reopened"])
def test_every_closed_state_is_reflected_on_github(state):
    f = _finding(state=state)
    f.github_comment_id = 7
    gh = FakeGH()

    sync_finding_states(gh, [f])

    assert gh.updates[0][1].startswith(STATE_MARKERS[state])


def test_a_deleted_comment_is_a_warning_and_the_internal_state_survives():
    f = _finding(state="resolved")
    f.github_comment_id = 9
    gh = FakeGH(update_error=GitHubError("gone", status_code=404))

    updated, warnings = sync_finding_states(gh, [f])

    assert updated == 0
    assert warnings and "no longer exists" in warnings[0]
    assert f.state == "resolved"


def test_a_transient_github_failure_is_a_warning_not_a_crash():
    f = _finding(state="resolved")
    f.github_comment_id = 9
    gh = FakeGH(update_error=GitHubError("boom", status_code=503))

    updated, warnings = sync_finding_states(gh, [f])

    assert updated == 0
    assert warnings and "could not update GitHub comment" in warnings[0]


def test_unexpected_errors_are_caught_and_named_by_type_only():
    f = _finding(state="resolved")
    f.github_comment_id = 9
    gh = FakeGH(update_error=RuntimeError("secret detail in the message"))

    updated, warnings = sync_finding_states(gh, [f])

    assert updated == 0
    assert warnings and "RuntimeError" in warnings[0]
    assert "secret detail" not in warnings[0]


def test_sync_failures_are_capped_at_one_loud_warning_plus_a_carry_over():
    gh = FakeGH(update_error=GitHubError("boom", status_code=500))
    findings = []
    for i in range(MAX_SYNC_ERRORS + 3):
        f = _finding(title=f"issue {i}", state="resolved")
        f.github_comment_id = 100 + i
        findings.append(f)

    updated, warnings = sync_finding_states(gh, findings)

    assert updated == 0
    assert len(warnings) == MAX_SYNC_ERRORS + 1
    assert "more GitHub comment update(s) skipped" in warnings[-1]


def test_sync_without_a_client_or_without_the_capability_is_a_no_op():
    f = _finding(state="resolved")
    f.github_comment_id = 9

    assert sync_finding_states(None, [f]) == (0, [])
    assert sync_finding_states(object(), [f]) == (0, [])


# ------------------------------------------------------------------ lifecycle

def test_apply_lifecycle_carries_the_comment_id_forward():
    prev = _finding(state="active")
    prev.github_comment_id = 999

    still_open = apply_lifecycle([prev], [_finding()])
    assert still_open[0].github_comment_id == 999

    closed = apply_lifecycle([prev], [])
    assert closed[0].state == "resolved"
    assert closed[0].github_comment_id == 999     # the comment to mark ✅


def test_model_output_cannot_supply_a_comment_id():
    """Providers parse model output with ``from_untrusted_dict``: a model can
    describe a finding but never point it at someone else's comment."""
    f = Finding.from_untrusted_dict({
        "file": "app/main.py", "line": 5, "severity": "high",
        "title": "SQL injection", "explanation": "",
        "github_comment_id": 123456, "state": "resolved",
    })

    assert f.github_comment_id is None
    assert f.state == "new"
