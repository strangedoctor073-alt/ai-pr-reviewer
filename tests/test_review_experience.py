"""V3 C8 — the developer experience of the review itself.

What a developer reads on GitHub must be *accurate* and *non-repetitive*:

* the summary says which engine actually ran (static output never reads as an
  an AI review), and — when the orchestrator computed them — the PR's risk and
  the outcome of fix verification;
* resolved findings are listed without a severity label, so a closed issue is
  never counted among the issues still to act on;
* a follow-up review that found nothing new posts **no** duplicate review
  comment, while a lifecycle transition (resolved / reopened / muted / …) is
  always worth confirming;
* a finding's GitHub comment id means "update that comment", never "post it
  again";
* every new input reaches Config through the same CLI > INPUT_* > env layering
  as every other input.
"""
from __future__ import annotations

from ai_pr_reviewer import cli, reporter
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.github_client import GitHubError
from ai_pr_reviewer.github_sync import render_finding_comment
from ai_pr_reviewer.model_router import ReviewRisk
from ai_pr_reviewer.models import Finding, PRContext, ReviewResult

PR = PRContext(repo="acme/api", pr_number=7, head_sha="h" * 40)


def _finding(title="SQL injection", severity="high", state=None,
             verification=None) -> Finding:
    f = Finding(file="app/main.py", line=5, severity=severity, title=title,
                explanation="because")
    if state:
        f.state = state
    if verification:
        f.verification_status = verification
        f.verification_reason = "checked"
        f.verified_at = "2026-01-02T00:00:00Z"
    return f


def _result(findings=(), engine="static", **attrs) -> ReviewResult:
    r = ReviewResult(pr=PR, mode=engine, model="static-rules-v1",
                     findings=list(findings))
    for key, value in attrs.items():
        setattr(r, key, value)
    return r


class FakeGH:
    def __init__(self, comments=None):
        self.comments = list(comments or [])
        self.posted: list[dict] = []
        self.updates: list[tuple[int, str]] = []

    def post_review(self, number, commit_id, body, comments):
        self.posted.append({"number": number, "commit_id": commit_id,
                            "body": body, "comments": comments})
        return {"ok": True}

    def create_comment(self, number, body):
        self.posted.append({"number": number, "body": body, "comments": []})

    def list_review_comments(self, number, limit=100):
        return list(self.comments)

    def update_review_comment(self, comment_id, body):
        self.updates.append((int(comment_id), body))
        return {"ok": True}


# --------------------------------------------------------------- summary rows

def test_risk_is_shown_only_when_the_orchestrator_computed_one():
    plain = reporter.build_summary_markdown(_result())
    assert "**Risk**" not in plain

    risky = _result()
    risky.risk = ReviewRisk(level="high",
                            reasons=["touches auth/payment paths",
                                     "adds new subprocess/exec usage"])
    md = reporter.build_summary_markdown(risky)

    assert "| **Risk** | ⚠️ high — touches auth/payment paths; " \
           "adds new subprocess/exec usage |" in md


def test_risk_with_no_reasons_still_renders_a_readable_row():
    risky = _result()
    risky.risk = ReviewRisk(level="low", reasons=[])

    md = reporter.build_summary_markdown(risky)

    assert "| **Risk** | 🟢 low — no sensitive paths detected |" in md


def test_risk_cannot_break_the_summary_table_with_a_pipe_character():
    risky = _result()
    risky.risk = ReviewRisk(level="high", reasons=["a | b"])

    md = reporter.build_summary_markdown(risky)

    row = next(line for line in md.splitlines() if "**Risk**" in line)
    assert row.count("|") == 3            # header, cell, cell — no injection
    assert "a / b" in row


def test_verification_row_lists_only_the_counts_that_are_non_zero():
    r = _result(verification={"resolved": 2, "still_present": 1,
                              "unable_to_verify": 3})

    md = reporter.build_summary_markdown(r)

    assert ("| **Verification** | 2 ✅ fixed & verified · 1 🔍 re-reported · "
            "3 ❓ unable to verify |") in md


def test_verification_row_is_absent_when_nothing_was_verified():
    r = _result(verification={"resolved": 0, "still_present": 0,
                              "unable_to_verify": 0})

    assert "**Verification**" not in reporter.build_summary_markdown(r)

    # ...and for summaries built without the counts at all (hand-built reports)
    assert "**Verification**" not in reporter.build_summary_markdown(_result())


def test_static_output_never_reads_as_an_ai_review():
    md = reporter.build_summary_markdown(_result(engine="static"))

    assert "— not an AI review" in md
    assert reporter._engine_note("static") == " — not an AI review"


def test_an_ai_engine_is_labelled_by_its_real_name_without_the_static_note():
    r = _result(engine="claude")
    r.model = "claude-sonnet-4-6"

    md = reporter.build_summary_markdown(r)

    assert "— not an AI review" not in md
    assert "`claude-sonnet-4-6`" in md
    assert reporter._engine_note("claude") == ""


def test_a_partly_degraded_run_says_so_instead_of_claiming_a_full_ai_review():
    assert reporter._engine_note("claude+static") == " (partly static fallback)"
    assert reporter._engine_note("static") == " — not an AI review"


def test_resolved_findings_are_listed_without_a_severity_label():
    """A closed finding must never be counted (or labelled) among the issues a
    developer still has to act on."""
    r = _result([_finding(title="real bug", severity="critical", state="resolved",
                          verification="resolved"),
                 _finding(title="open one", severity="critical")])

    md = reporter.build_summary_markdown(r)

    assert "> ✅ 1 previously reported finding(s) resolved." in md
    block = md.split("<summary><strong>Resolved findings")[1]
    assert "`app/main.py:5` — real bug · ✅ verified fixed" in block
    # the severity word appears only for the still-open finding
    assert md.count("critical") == 1


def test_the_first_details_block_is_still_the_open_findings_one():
    """`test_cli_leaves_dismissed_and_muted_findings_out` depends on the first
    `<details>` being the actionable list."""
    r = _result([_finding(state="resolved"), _finding(title="open one")])

    md = reporter.build_summary_markdown(r)
    first = md.split("<details>")[1]

    assert "Top findings" in first
    assert "**open one**" in first
    assert "`app/main.py:5`" in first
    assert "Resolved findings" not in first


def test_the_report_json_carries_per_finding_verification_metadata():
    f = _finding(state="resolved", verification="resolved")
    data = reporter.finalize_report(_result([f]))

    row = data["findings"][0]
    assert row["verification_status"] == "resolved"
    assert row["verification_reason"] == "checked"
    assert row["verified_at"] == "2026-01-02T00:00:00Z"
    assert row["state"] == "resolved"


# ------------------------------------------------------------- input layering

def test_new_inputs_layer_cli_over_action_inputs_over_defaults(monkeypatch):
    monkeypatch.setenv("INPUT_PROVIDER_ORDER", "gemini")
    monkeypatch.setenv("INPUT_REPO_CONTEXT_CHARS", "4000")

    from_env = cli.load_config(cli.parse_args([]))
    assert (from_env.provider_order, from_env.repo_context_chars) == ("gemini", 4000)

    from_cli = cli.load_config(cli.parse_args(
        ["--provider-order", "claude,openai", "--repo-context-chars", "0"]))
    assert (from_cli.provider_order, from_cli.repo_context_chars) == ("claude,openai", 0)


def test_repo_context_budget_defaults_when_unconfigured(monkeypatch):
    monkeypatch.delenv("INPUT_REPO_CONTEXT_CHARS", raising=False)
    monkeypatch.delenv("REPO_CONTEXT_CHARS", raising=False)

    cfg = cli.load_config(cli.parse_args([]))

    assert cfg.repo_context_chars == 12_000


# ------------------------------------------------- duplicate-review suppression

def test_the_first_review_of_a_pr_is_always_posted():
    r = _result()

    assert cli._review_is_worth_posting(r, []) is True


def test_an_unchanged_follow_up_review_does_not_post_a_duplicate_comment():
    r = _result()
    r.previous_findings_count = 4

    assert cli._review_is_worth_posting(r, []) is False


def test_anything_new_inline_is_always_posted():
    r = _result()
    r.previous_findings_count = 4

    assert cli._review_is_worth_posting(r, [_finding()]) is True


def test_a_lifecycle_transition_alone_justifies_a_post():
    r = _result()
    r.previous_findings_count = 4
    r.state_transition_count = 1

    assert cli._review_is_worth_posting(r, []) is True

    r.state_transition_count = 0
    assert cli._review_is_worth_posting(r, []) is False


def test_post_and_sync_skips_the_whole_review_when_nothing_changed(capsys):
    known = _finding(state="active")
    known.github_comment_id = 42
    r = _result([known])
    r.previous_findings_count = 4
    gh = FakeGH()

    posted = cli._post_and_sync(gh, Config(), None, r, [known])

    assert posted == 0
    assert gh.posted == []          # no duplicate review, no duplicate comment
    assert "skipping a duplicate review comment" in capsys.readouterr().out
    assert gh.updates == []         # 'active' has no marker


def test_a_finding_that_already_has_a_comment_is_not_posted_a_second_time():
    known = _finding(title="known issue", state="active")
    known.github_comment_id = 42
    fresh = _finding(title="brand new")
    r = _result([known, fresh])
    r.previous_findings_count = 1
    gh = FakeGH()

    posted = cli._post_and_sync(gh, Config(), None, r, [known, fresh])

    assert posted == 1
    bodies = [c["body"] for c in gh.posted[0]["comments"]]
    assert len(bodies) == 1
    assert "brand new" in bodies[0]
    assert all("known issue" not in b for b in bodies)


def test_a_state_flip_updates_the_existing_comment_and_still_confirms_it():
    known = _finding(title="known issue", state="resolved")
    known.github_comment_id = 42
    r = _result([known])
    r.previous_findings_count = 1
    r.state_transition_count = 1
    gh = FakeGH()

    posted = cli._post_and_sync(gh, Config(), None, r, [known])

    # nothing to say inline — but the transition still lands as a summary-only
    # review, and the existing comment is marked rather than duplicated.
    assert posted == 0
    assert gh.posted[0]["comments"] == []
    assert gh.updates == [(42, "✅ **Resolved**\n\n"
                              + render_finding_comment(known))]


def test_a_comment_that_cannot_be_updated_is_a_warning_never_an_exception():
    known = _finding(state="resolved")
    known.github_comment_id = 7
    r = _result([known])
    r.previous_findings_count = 1
    r.state_transition_count = 1

    class FailingGH(FakeGH):
        def update_review_comment(self, comment_id, body):
            raise RuntimeError("permission denied for this repo")

    cli._post_and_sync(FailingGH(), Config(), None, r, [known])

    assert any("could not update GitHub comment 7 (RuntimeError)" in w
               for w in r.warnings)
    assert all("permission denied" not in w for w in r.warnings)
    assert known.state == "resolved"          # internal state is untouched


def test_a_failed_grouped_review_lands_as_a_plain_pr_comment():
    fresh = _finding(title="brand new")
    r = _result([fresh])
    r.previous_findings_count = 1

    class GroupedFail(FakeGH):
        def post_review(self, number, commit_id, body, comments):
            raise GitHubError("malformed inline comments", status_code=422)

    gh = GroupedFail()
    posted = cli._post_and_sync(gh, Config(), None, r, [fresh])

    assert posted == 0
    assert gh.posted[0]["comments"] == []          # fallback carries no lines
    assert gh.posted[0]["body"]                    # the summary still landed
    assert any("posted as PR comment" in w for w in r.warnings)


def test_a_read_only_token_keeps_the_review_going_and_says_why():
    fresh = _finding(title="brand new")
    r = _result([fresh])
    r.previous_findings_count = 1

    class ReadOnlyGH(FakeGH):
        def post_review(self, number, commit_id, body, comments):
            raise GitHubError("read-only token", status_code=403)

        def create_comment(self, number, body):
            raise GitHubError("read-only token", status_code=403)

    gh = ReadOnlyGH()
    posted = cli._post_and_sync(gh, Config(), None, r, [fresh])

    assert posted == 0
    assert gh.posted == []
    assert any("pull-requests: write" in w for w in r.warnings)
    assert fresh.verification_status is None


def test_comment_id_persistence_without_storage_is_a_silent_no_op():
    r = _result([_finding()])
    r.pr.head_sha = ""

    cli._persist_comment_ids(None, r)
    cli._persist_comment_ids(object(), r)      # no storage: nothing to write

    assert r.warnings == []


# ------------------------------------------------------------------ state markers

def test_a_reopened_finding_is_postable_and_marked_on_its_old_comment():
    known = _finding(title="known issue", state="reopened")
    known.github_comment_id = 99
    r = _result([known])
    r.previous_findings_count = 2
    r.state_transition_count = 1
    gh = FakeGH()

    posted = cli._post_and_sync(gh, Config(), None, r, [known])

    # 'reopened' already has a comment -> updated, not re-posted
    assert posted == 0
    assert gh.posted[0]["comments"] == []
    assert gh.updates and gh.updates[0][0] == 99
    assert gh.updates[0][1].startswith("🔁 **Reopened**")
