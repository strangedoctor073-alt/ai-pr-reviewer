"""Tests for ReviewOrchestrator, the cli.run() wiring around it, and the v2
reporter output (header labels, report schema).

The orchestrator depends on context.py, model_router.py, and findings.py.
Every test swaps those real seams for fakes with monkeypatch, so this file
exercises the orchestrator and CLI wiring in isolation.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ai_pr_reviewer  # noqa: E402
from ai_pr_reviewer import models  # noqa: E402
from ai_pr_reviewer import cli, orchestrator as orch, reporter  # noqa: E402
from ai_pr_reviewer.config import Config  # noqa: E402
from ai_pr_reviewer.github_client import GitHubError  # noqa: E402
from ai_pr_reviewer.models import Finding, PRContext, ReviewResult  # noqa: E402


# ------------------------------------------------------------------- fixtures
def _diff(path: str, line: str = "x = 1") -> str:
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,2 +1,3 @@\n ctx\n+{line}\n ctx2\n")


FULL_DIFF = _diff("a.py") + _diff("b.py")          # whole PR: two files
INCR_DIFF = _diff("a.py", "y = 2")                 # since last review: a.py only


def _finding(file="a.py", line=2, title="SQL injection", severity="high",
             state=None) -> Finding:
    f = Finding(file=file, line=line, severity=severity, title=title,
                explanation="because")
    if state:
        f.state = state
    return f


class FakeGH:
    def __init__(self, log, head_sha="new222", compare_error=None):
        self.log = log
        self.head_sha = head_sha
        self.compare_error = compare_error
        self.compare_args = []
        self.posted = []
        self.comments = []

    def get_event_context(self):
        return None

    def get_pr(self, number):
        self.log.append("get_pr")
        ctx = PRContext(repo="acme/api", pr_number=number, pr_title="Add refunds",
                        author="dev", branch="feat", base="main",
                        head_sha=self.head_sha, url="https://example/pr/7")
        ctx.base_sha = "base000"
        return ctx, FULL_DIFF

    def compare_commits(self, base_sha, head_sha):
        self.log.append("compare_commits")
        self.compare_args.append((base_sha, head_sha))
        if self.compare_error:
            raise self.compare_error
        return INCR_DIFF

    def post_review(self, number, commit_id, body, comments):
        self.log.append("post_review")
        self.posted.append({"number": number, "commit_id": commit_id,
                            "body": body, "comments": comments})
        return {"ok": True}

    def create_comment(self, number, body):
        self.comments.append(body)


class FakeStorage:
    def __init__(self, log, last_sha=None, previous=(), fail_save=False):
        self.log = log
        self.last_sha = last_sha
        self.previous = list(previous)
        self.fail_save = fail_save
        self.set_calls = []
        self.saved = []

    def get_last_reviewed_sha(self, repo, pr_number):
        self.log.append("get_last_reviewed_sha")
        return self.last_sha

    def get_previous_findings(self, repo, pr_number):
        return list(self.previous)

    def save_findings(self, review_id, findings):
        self.log.append("save_findings")
        if self.fail_save:
            raise RuntimeError("db down")
        self.saved.append((review_id, findings))

    def set_last_reviewed_sha(self, repo, pr_number, sha, base_sha):
        self.log.append("set_last_reviewed_sha")
        self.set_calls.append((repo, pr_number, sha, base_sha))


class Wired:
    """Replaces the four contract seams with fakes and records how they ran."""

    def __init__(self, monkeypatch, *, findings=(), last_sha=None, previous=(),
                 incremental=True, with_storage=True, compare_error=None,
                 fail_save=False, provider_error=None, lifecycle=None,
                 outcome_extra=None, storage=None, dedupe=None):
        self.log: list[str] = []
        self.gh = FakeGH(self.log, compare_error=compare_error)
        self.storage = storage or (FakeStorage(self.log, last_sha, previous, fail_save)
                                   if with_storage else None)
        if storage is not None:
            storage.log = self.log
        self.cfg = Config(repo="acme/api", pr_number=7, severity_threshold="low",
                          max_comments=20)
        self.cfg.incremental_enabled = incremental
        self.contexts = []
        self.lifecycle_calls = []
        self._findings = list(findings)
        self._lifecycle = lifecycle
        self._dedupe = dedupe
        self._provider_error = provider_error
        self._outcome_extra = dict(engine="claude", fallback_used=False, batch_count=3)
        self._outcome_extra.update(outcome_extra or {})
        monkeypatch.setattr(orch, "build_context", self._build_context)
        monkeypatch.setattr(orch, "get_provider", self._get_provider)
        monkeypatch.setattr(orch, "deduplicate", self._deduplicate)
        monkeypatch.setattr(orch, "apply_lifecycle", self._apply_lifecycle)

    # -- seams
    def _build_context(self, pr, files, cfg, storage=None, gh=None):
        self.log.append("build_context")
        ctx = SimpleNamespace(pr=pr, files=files, previous_findings=[])
        self.contexts.append(ctx)
        return ctx

    def _get_provider(self, cfg, context):
        self.log.append("get_provider")
        return self

    def analyze(self, context):
        self.log.append("analyze")
        if self._provider_error:
            raise self._provider_error
        return SimpleNamespace(findings=list(self._findings), summary="all good",
                               mode="claude", model="claude-test", warnings=["w1"],
                               **self._outcome_extra)

    def _deduplicate(self, findings):
        self.log.append("deduplicate")
        return self._dedupe(findings) if self._dedupe else list(findings)

    def _apply_lifecycle(self, previous, current):
        self.log.append("apply_lifecycle")
        self.lifecycle_calls.append((list(previous), list(current)))
        if self._lifecycle:
            return self._lifecycle(previous, current)
        keys = {(p.file, p.title) for p in previous}
        out = []
        for c in current:
            c.state = "active" if (c.file, c.title) in keys else "new"
            c.fingerprint = f"fp-{c.file}-{c.title}"
            out.append(c)
        now = {(c.file, c.title) for c in current}
        for p in previous:
            if (p.file, p.title) not in now:
                p.state = "resolved"
                out.append(p)
        return out

    def run(self) -> ReviewResult:
        return orch.ReviewOrchestrator(self.cfg, self.gh, self.storage).run()


def _reviewed_paths(w: Wired) -> set[str]:
    return {f.path for f in w.contexts[0].files}


# ----------------------------------------------- incremental / state handling
def test_first_review_uses_full_pr_diff(monkeypatch):
    w = Wired(monkeypatch, last_sha=None)
    w.run()

    assert w.gh.compare_args == []                       # never asked for a compare
    assert _reviewed_paths(w) == {"a.py", "b.py"}        # whole PR reviewed
    assert w.storage.set_calls == [("acme/api", 7, "new222", "base000")]


def test_subsequent_review_uses_compare_commits(monkeypatch):
    w = Wired(monkeypatch, last_sha="old111")
    result = w.run()

    assert w.gh.compare_args == [("old111", "new222")]
    assert _reviewed_paths(w) == {"a.py"}                # only what changed since
    assert result.stats.files == 1
    assert w.storage.set_calls == [("acme/api", 7, "new222", "base000")]


def test_last_sha_recorded_exactly_once_per_successful_run(monkeypatch):
    for last_sha in (None, "old111"):
        w = Wired(monkeypatch, last_sha=last_sha)
        w.run()
        assert len(w.storage.set_calls) == 1


def test_incremental_disabled_ignores_stored_sha(monkeypatch):
    w = Wired(monkeypatch, last_sha="old111", incremental=False)
    w.run()

    assert "get_last_reviewed_sha" not in w.log
    assert w.gh.compare_args == []
    assert _reviewed_paths(w) == {"a.py", "b.py"}
    assert len(w.storage.set_calls) == 1                 # state still advances


def test_config_without_incremental_flag_behaves_like_v1(monkeypatch):
    w = Wired(monkeypatch, last_sha="old111")
    del w.cfg.incremental_enabled                        # Config from before v2
    w.run()
    assert "get_last_reviewed_sha" not in w.log
    assert w.gh.compare_args == []
    assert _reviewed_paths(w) == {"a.py", "b.py"}


def test_compare_failure_falls_back_to_full_diff(monkeypatch):
    w = Wired(monkeypatch, last_sha="old111",
              compare_error=GitHubError("compare failed (404)"))
    result = w.run()

    assert _reviewed_paths(w) == {"a.py", "b.py"}
    assert any("incremental diff unavailable" in x for x in result.warnings)
    assert len(w.storage.set_calls) == 1


def test_pipeline_order(monkeypatch):
    w = Wired(monkeypatch, last_sha="old111", findings=[_finding()])
    w.run()
    assert w.log == [
        "get_pr", "get_last_reviewed_sha", "compare_commits", "build_context",
        "get_provider", "analyze", "deduplicate", "apply_lifecycle",
        "save_findings", "set_last_reviewed_sha",
    ]


def test_project_policy_excludes_matching_files(monkeypatch):
    from ai_pr_reviewer.rules import ReviewPolicy

    w = Wired(monkeypatch)
    monkeypatch.setattr(orch, "load_project_rules",
                        lambda *_args, **_kwargs: ReviewPolicy(exclude=["b.py"]))

    result = w.run()

    assert _reviewed_paths(w) == {"a.py"}
    assert result.stats.files == 1


def test_project_policy_sets_threshold_when_workflow_uses_default(monkeypatch):
    from ai_pr_reviewer.rules import ReviewPolicy

    w = Wired(monkeypatch, findings=[_finding(severity="medium")])
    w.cfg.severity_threshold = "medium"
    monkeypatch.setattr(orch, "load_project_rules", lambda *_args, **_kwargs: ReviewPolicy(
        severity_threshold="high"))

    result = w.run()

    assert result.findings == []


def test_no_storage_is_stateless(monkeypatch):
    w = Wired(monkeypatch, findings=[_finding()], with_storage=False)
    result = w.run()

    assert w.lifecycle_calls[0][0] == []                 # no previous findings
    assert [f.state for f in result.findings] == ["new"]
    assert "get_last_reviewed_sha" not in w.log


def test_failed_analysis_does_not_advance_last_sha(monkeypatch):
    """A dying provider no longer takes the run down (V3 C6): the rule engine
    stands in with an honest warning instead of raising.

    The invariants the original test protected are kept where they still
    matter — nothing claims success for work that did not happen:
    ``set_calls`` stays empty so the next run re-reviews these commits once a
    provider works again, while the findings *are* stored (and their comment
    ids with them) so the re-review matches them instead of duplicating the
    comments this run already posted.
    """
    w = Wired(monkeypatch, last_sha="old111", provider_error=RuntimeError("boom"))

    result = w.run()

    assert (result.engine, result.fallback_used, result.review_state) == \
        ("static", True, "fallback")
    assert any("provider review failed (RuntimeError)" in x
               for x in result.warnings)
    assert any("not from an AI review" in x for x in result.warnings)
    assert any("not advanced" in x for x in result.warnings)
    assert w.storage.set_calls == []
    assert w.storage.saved


def test_storage_failure_is_a_warning_and_sha_is_not_advanced(monkeypatch):
    w = Wired(monkeypatch, findings=[_finding()], fail_save=True)
    result = w.run()

    assert len(result.findings) == 1                     # review still returned
    assert any("review state not saved" in x for x in result.warnings)
    assert w.storage.set_calls == []


# ------------------------------------------------------------ lifecycle scope
def test_incremental_review_does_not_resolve_untouched_files(monkeypatch):
    in_a = _finding("a.py", title="Bug in a", state="active")
    in_b = _finding("b.py", title="Bug in b", state="new")
    w = Wired(monkeypatch, last_sha="old111", previous=[in_a, in_b], findings=[])
    result = w.run()

    # only the finding in the re-reviewed file went through the lifecycle
    assert w.lifecycle_calls[0][0] == [in_a]
    by_title = {f.title: f.state for f in result.findings}
    assert by_title == {"Bug in a": "resolved", "Bug in b": "active"}


def test_full_review_sends_every_previous_finding_through_lifecycle(monkeypatch):
    in_a = _finding("a.py", title="Bug in a", state="active")
    in_b = _finding("b.py", title="Bug in b", state="active")
    w = Wired(monkeypatch, last_sha=None, previous=[in_a, in_b], findings=[])
    result = w.run()

    assert w.lifecycle_calls[0][0] == [in_a, in_b]
    assert {f.state for f in result.findings} == {"resolved"}


def test_same_sha_rerun_keeps_open_findings_open(monkeypatch):
    old = _finding("a.py", state="active")
    w = Wired(monkeypatch, last_sha="new222", previous=[old], findings=[])
    w.gh.compare_commits = lambda b, h: ""               # nothing new since
    result = w.run()

    assert [f.state for f in result.findings] == ["active"]


# --------------------------------------------------- dashboard muting (D4)
class MutedStorage(FakeStorage):
    """Storage that also has the optional dashboard feedback capability
    (``get_dismissed_fingerprints``)."""

    def __init__(self, dismissed):
        super().__init__(log=[])
        self.dismissed = set(dismissed)

    def get_dismissed_fingerprints(self, repo):
        self.log.append("get_dismissed_fingerprints")
        return set(self.dismissed)


def test_dismissed_fingerprints_are_muted_after_the_lifecycle(monkeypatch):
    from ai_pr_reviewer.findings import fingerprint_finding

    f = _finding()
    w = Wired(monkeypatch, storage=MutedStorage([fingerprint_finding(f)]),
              findings=[_finding()])

    result = w.run()

    assert [x.state for x in result.findings] == ["muted"]
    # muting happens after the lifecycle pass, never before it
    assert w.log.index("apply_lifecycle") < w.log.index("get_dismissed_fingerprints")


def test_stale_mute_does_not_overwrite_a_resolved_finding(monkeypatch):
    from ai_pr_reviewer.findings import fingerprint_finding

    def lifecycle(previous, current):
        return [_finding(title="still open", state="new"),
                _finding(title="fixed already", state="resolved")]

    storage = MutedStorage({fingerprint_finding(_finding(title="still open")),
                            fingerprint_finding(_finding(title="fixed already",
                                                         state="resolved"))})
    w = Wired(monkeypatch, storage=storage, lifecycle=lifecycle,
              findings=[_finding()])

    result = w.run()

    by_title = {x.title: x.state for x in result.findings}
    assert by_title == {"still open": "muted", "fixed already": "resolved"}


def test_dismissed_fingerprint_lookup_failure_degrades_to_a_warning(monkeypatch):
    class BrokenStorage(FakeStorage):
        def get_dismissed_fingerprints(self, repo):
            raise RuntimeError("dashboard down")

    w = Wired(monkeypatch, storage=BrokenStorage([]), findings=[_finding()])

    result = w.run()

    assert len(result.findings) == 1                     # review still returned
    assert any("muted-fingerprint lookup failed" in x for x in result.warnings)


# --------------------------------------------------------------- result shape
def test_result_shape_matches_v1_and_carries_provider_metadata(monkeypatch):
    w = Wired(monkeypatch, findings=[_finding(), _finding(severity="info", title="nit")],
              outcome_extra=dict(engine="claude+static", fallback_used=True,
                                 batch_count=4))
    w.cfg.severity_threshold = "medium"                  # drops the info finding
    result = w.run()

    assert isinstance(result, ReviewResult)
    assert (result.mode, result.model, result.summary) == ("claude", "claude-test", "all good")
    assert result.pr.head_sha == "new222" and result.pr.pr_title == "Add refunds"
    assert result.warnings == ["w1"]
    assert result.suppressed == 0
    assert result.stats.files == 2 and result.stats.batches == 4
    assert result.stats.additions == 2 and result.stats.hunks == 2
    assert [f.title for f in result.findings] == ["SQL injection"]
    assert result.posted_inline == 0
    assert (result.engine, result.fallback_used, result.review_state) == \
        ("claude+static", True, "fallback")


def test_legacy_outcome_without_v2_fields(monkeypatch):
    w = Wired(monkeypatch)
    w._outcome_extra = {}                                # pre-v2 AnalysisOutcome
    result = w.run()
    assert (result.engine, result.fallback_used, result.review_state) == \
        ("claude", False, "completed")
    assert result.stats.batches == 1                     # v1 behaviour


def test_no_reviewable_files_warns(monkeypatch):
    w = Wired(monkeypatch)
    w.cfg.exclude = ["*.py"]
    result = w.run()
    assert any("No reviewable code changes" in x for x in result.warnings)


def test_unanchorable_findings_are_reported_not_posted(monkeypatch):
    w = Wired(monkeypatch, findings=[_finding(file="ghost.py")])
    result = w.run()
    assert result.findings == []
    assert any("could not be anchored" in x for x in result.warnings)


def test_findings_are_persisted_with_lifecycle_fields(monkeypatch):
    w = Wired(monkeypatch, findings=[_finding()])
    w.run()

    review_id, rows = w.storage.saved[0]
    assert review_id == "acme/api#7@new222"
    assert rows[0]["title"] == "SQL injection"
    assert rows[0]["state"] == "new"
    assert rows[0]["fingerprint"] == "fp-a.py-SQL injection"
    assert rows[0]["first_seen_sha"] == rows[0]["last_seen_sha"] == "new222"


def test_resolved_findings_get_resolved_at(monkeypatch):
    old = _finding("a.py", state="active")
    w = Wired(monkeypatch, previous=[old], findings=[])
    result = w.run()
    assert result.findings[0].state == "resolved"
    assert result.findings[0].resolved_at


def test_local_diff_mode_needs_no_github_or_storage(monkeypatch):
    w = Wired(monkeypatch, findings=[_finding()])
    pr = PRContext(repo="local/project", pr_number=0, pr_title="local")
    result = orch.ReviewOrchestrator(w.cfg, None, storage=w.storage,
                                     pr=pr, diff_text=FULL_DIFF).run()

    assert len(result.findings) == 1
    assert w.storage.set_calls == []                     # no head SHA to record
    assert "get_pr" not in w.log


def test_orchestrator_needs_a_diff_source():
    cfg = Config(repo="acme/api", pr_number=7)
    with pytest.raises(ValueError):
        orch.ReviewOrchestrator(cfg, None).run()


# ------------------------------------------- multi-push incremental flow
class StatefulStorage(FakeStorage):
    """Behaves like real storage across runs: remembers the last SHA and the
    findings of the previous review."""

    def __init__(self):
        super().__init__(log=[])
        self.rows = []

    def save_findings(self, review_id, findings):
        super().save_findings(review_id, findings)
        self.rows = list(findings)

    def set_last_reviewed_sha(self, repo, pr_number, sha, base_sha):
        super().set_last_reviewed_sha(repo, pr_number, sha, base_sha)
        self.last_sha = sha

    def get_previous_findings(self, repo, pr_number):
        out = []
        for row in self.rows:
            f = Finding.from_dict(row)
            f.state = row["state"]
            out.append(f)
        return out


def _keyed_lifecycle(previous, current):
    """new / active / reopened / resolved by (file, title) — test double."""
    prev = {(p.file, p.title): p for p in previous}
    out = []
    for c in current:
        p = prev.get((c.file, c.title))
        c.state = ("new" if p is None else
                   "reopened" if p.state == "resolved" else "active")
        out.append(c)
    seen = {(c.file, c.title) for c in current}
    for p in previous:
        if (p.file, p.title) not in seen and p.state != "resolved":
            p.state = "resolved"
            out.append(p)
    return out


def test_three_pushes_walk_a_finding_through_its_lifecycle(monkeypatch):
    storage = StatefulStorage()
    w = Wired(monkeypatch, storage=storage, lifecycle=_keyed_lifecycle)
    bug = lambda: [_finding("a.py", title="SQL injection")]   # noqa: E731

    # push 1 — first review: full diff, finding is new
    w.gh.head_sha, w._findings = "sha1", bug()
    r1 = w.run()
    assert w.gh.compare_args == []
    assert [f.state for f in r1.findings] == ["new"]

    # push 2 — developer fixes it: incremental diff, finding resolved
    w.gh.head_sha, w._findings = "sha2", []
    r2 = w.run()
    assert w.gh.compare_args == [("sha1", "sha2")]
    assert [f.state for f in r2.findings] == ["resolved"]

    # push 3 — regression: incremental from sha2, finding reopened
    w.gh.head_sha, w._findings = "sha3", bug()
    r3 = w.run()
    assert w.gh.compare_args == [("sha1", "sha2"), ("sha2", "sha3")]
    assert [f.state for f in r3.findings] == ["reopened"]

    assert [call[2] for call in storage.set_calls] == ["sha1", "sha2", "sha3"]
    assert [rid for rid, _ in storage.saved] == [
        "acme/api#7@sha1", "acme/api#7@sha2", "acme/api#7@sha3"]


def test_empty_incremental_diff_keeps_findings_and_still_advances_sha(monkeypatch):
    old = _finding("a.py", state="active")
    w = Wired(monkeypatch, last_sha="old111", previous=[old], findings=[])
    w.gh.compare_commits = lambda b, h: ""               # e.g. an empty merge commit
    result = w.run()

    assert result.stats.files == 0
    assert any("No reviewable code changes" in x for x in result.warnings)
    assert [f.state for f in result.findings] == ["active"]
    assert w.storage.set_calls == [("acme/api", 7, "new222", "base000")]


# ------------------------------------------------ findings handling
def test_duplicates_are_collapsed_before_the_comment_cap(monkeypatch):
    dupes = [_finding(title="SQL injection", line=2) for _ in range(3)]

    def by_title(findings):
        return list({(f.file, f.title): f for f in findings}.values())

    w = Wired(monkeypatch, findings=dupes, dedupe=by_title)
    w.cfg.max_comments = 1
    result = w.run()
    assert len(w.lifecycle_calls[0][1]) == 1
    assert (len(result.findings), result.suppressed) == (1, 0)

    # without a working dedupe the same batch would burn the cap
    w2 = Wired(monkeypatch, findings=[_finding(title="SQL injection") for _ in range(3)])
    w2.cfg.max_comments = 1
    assert w2.run().suppressed == 2


def test_cli_leaves_dismissed_and_muted_findings_out(monkeypatch, tmp_path):
    def lifecycle(previous, current):
        return [_finding(title="open", state="new"),
                _finding(title="dismissed", state="dismissed"),
                _finding(title="muted", state="muted")]

    w = Wired(monkeypatch, lifecycle=lifecycle, with_storage=False)
    monkeypatch.setattr(cli, "GitHubClient", lambda token, repo: w.gh)
    out_file = tmp_path / "gh_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    w.cfg.github_token = "t"
    w.cfg.output = str(tmp_path / "r.json")

    cli.run(w.cfg)

    assert len(w.gh.posted[0]["comments"]) == 1
    assert "findings_count=1" in out_file.read_text(encoding="utf-8")
    body = w.gh.posted[0]["body"]
    assert "Issues Flagged** | 1" in body and "dismissed" not in body.split("<details>")[0]


# ------------------------------------------------- moved helpers stay importable
def test_filter_files_and_validate_findings_still_import_from_cli():
    assert cli.filter_files is orch.filter_files
    assert cli.validate_findings is orch.validate_findings


# ----------------------------------------------------------- cli.run() wiring
def test_cli_run_posts_only_new_findings_and_reports_state(monkeypatch, tmp_path):
    def lifecycle(previous, current):
        new = _finding("a.py", title="new one", state="new")
        active = _finding("b.py", title="still open", state="active")
        gone = _finding("a.py", title="fixed", state="resolved")
        return [new, active, gone]

    w = Wired(monkeypatch, findings=[_finding()], lifecycle=lifecycle,
              with_storage=False)
    monkeypatch.setattr(cli, "GitHubClient", lambda token, repo: w.gh)
    out_file = tmp_path / "gh_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    w.cfg.github_token = "t"
    w.cfg.output = str(tmp_path / "report.json")

    result = cli.run(w.cfg)

    posted = w.gh.posted[0]
    assert [c["body"].split("**")[1] for c in posted["comments"]] == ["\U0001f916 HIGH: new one"]
    assert result.posted_inline == 1

    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert (report["new_findings_count"], report["active_findings_count"],
            report["resolved_findings_count"]) == (1, 1, 1)
    assert report["engine"] == "claude" and report["review_state"] == "completed"

    outputs = out_file.read_text(encoding="utf-8")
    assert "findings_count=2" in outputs                 # resolved doesn't count
    assert "report_path=" in outputs
    assert "## \U0001f916 AI PR Review" in posted["body"]


def test_cli_run_survives_a_token_that_cannot_write(monkeypatch, tmp_path):
    """Read-only token (fork / Dependabot PRs): both the grouped review and the
    plain-comment fallback are refused with 403. The run must still finish,
    write its report, and say why nothing was posted."""
    w = Wired(monkeypatch, findings=[_finding()], with_storage=False)

    def refuse(*_a, **_k):
        raise GitHubError("POST failed (403): Resource not accessible by integration",
                          status_code=403)

    w.gh.post_review = refuse
    w.gh.create_comment = refuse
    monkeypatch.setattr(cli, "GitHubClient", lambda token, repo: w.gh)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    w.cfg.github_token = "t"
    w.cfg.output = str(tmp_path / "report.json")

    result = cli.run(w.cfg)

    assert result.posted_inline == 0
    assert any("could not post the review" in msg and "pull-requests: write" in msg
               for msg in result.warnings)
    report = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert len(report["findings"]) == 1


def test_cli_local_mode_defaults_title_and_branch_when_not_given(monkeypatch, tmp_path):
    w = Wired(monkeypatch, findings=[_finding()], with_storage=False)
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(FULL_DIFF, encoding="utf-8")
    w.cfg.diff_file = str(diff_path)
    w.cfg.output = str(tmp_path / "r.json")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    # what main() passes when --pr-title / --pr-branch are omitted
    result = cli.run(w.cfg, pr_overrides={"pr_title": "", "pr_author": "", "pr_branch": ""})

    assert result.pr.pr_title == str(diff_path)
    assert result.pr.branch == "feature/branch"


def test_cli_run_local_mode_uses_overrides(monkeypatch, tmp_path):
    w = Wired(monkeypatch, findings=[_finding()], with_storage=False)
    diff_path = tmp_path / "change.diff"
    diff_path.write_text(FULL_DIFF, encoding="utf-8")
    w.cfg.diff_file = str(diff_path)
    w.cfg.output = str(tmp_path / "r.json")
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)

    result = cli.run(w.cfg, pr_overrides={"pr_title": "Local", "pr_author": "me",
                                          "pr_branch": "topic"})

    assert (result.pr.pr_title, result.pr.author, result.pr.branch) == ("Local", "me", "topic")
    assert result.pr.repo == "acme/api" and result.pr.base == "main"
    assert "get_pr" not in w.log


def test_cli_fail_on_ignores_resolved_findings(monkeypatch, tmp_path):
    def lifecycle(previous, current):
        return [_finding(severity="critical", state="resolved")]

    w = Wired(monkeypatch, lifecycle=lifecycle, with_storage=False)
    monkeypatch.setattr(cli, "GitHubClient", lambda token, repo: w.gh)
    monkeypatch.setattr(cli, "load_config", lambda args: w.cfg)
    monkeypatch.setattr(cli, "merge_dashboard_rules", lambda cfg: None)
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    w.cfg.github_token = "t"
    w.cfg.no_comment = True
    w.cfg.fail_on = "high"
    w.cfg.anthropic_api_key = "sk-test"
    w.cfg.output = str(tmp_path / "r.json")

    assert cli.main(["--repo", "acme/api", "--pr", "7"]) == 0


# ------------------------------------------------------------ reporter output
def _result(mode="static", engine=None, findings=(), **attrs) -> ReviewResult:
    r = ReviewResult(pr=PRContext(repo="acme/api", pr_number=7, head_sha="abc123"),
                     mode=mode, model="m", findings=list(findings), summary="s")
    if engine:
        r.engine = engine
    for key, value in attrs.items():
        setattr(r, key, value)
    return r


def test_write_report_creates_missing_parent_directories(tmp_path):
    target = tmp_path / "not" / "there" / "yet" / "report.json"

    assert reporter.write_report(str(target), {"ok": True}) == str(target)
    assert json.loads(target.read_text(encoding="utf-8")) == {"ok": True}


def test_header_is_labelled_by_engine_and_static_is_never_ai():
    cases = [
        ("claude", "claude", "Claude"),
        ("static", "static", "Static Fallback"),
        ("claude", "claude+static", "Claude + Static Fallback"),
        ("mock", None, "Static Fallback"),            # legacy v1 mode value
        ("claude", None, "Claude"),
    ]
    for mode, engine, label in cases:
        md = reporter.build_summary_markdown(_result(mode=mode, engine=engine))
        first = md.splitlines()[0]
        assert "## \U0001f916 AI PR Review" in first
        if label == "Static Fallback":
            assert "not an AI review" in md


def test_summary_keeps_product_name_for_existing_consumers():
    md = reporter.build_summary_markdown(_result(mode="mock"))
    assert "AI PR Review" in md                         # tests/test_pipeline.py


def test_summary_counts_only_open_findings():
    findings = [_finding(state="new"), _finding(title="b", state="active"),
                _finding(title="c", state="resolved", severity="critical"),
                _finding(title="d", state="muted")]
    md = reporter.build_summary_markdown(_result(mode="claude", findings=findings))
    assert "Issues Flagged** | 2" in md
    assert "1 previously reported finding(s) resolved" in md
    assert "2 high" in md and "critical" not in md


def test_finalize_report_v2_fields():
    findings = [_finding(state="new"), _finding(title="b", state="new"),
                _finding(title="c", state="active"), _finding(title="d", state="reopened"),
                _finding(title="e", state="resolved"), _finding(title="f", state="dismissed")]
    data = reporter.finalize_report(_result(mode="claude", engine="claude+static",
                                            findings=findings, fallback_used=True))
    assert data["engine"] == "claude+static"
    assert data["fallback_used"] is True
    assert data["review_state"] == "fallback"
    assert data["new_findings_count"] == 2
    assert data["active_findings_count"] == 2            # active + reopened
    assert data["resolved_findings_count"] == 1
    json.dumps(data)                                     # stays serialisable


def test_finalize_report_defaults_for_a_v1_style_result():
    r = _result(mode="mock", findings=[_finding()])
    data = reporter.finalize_report(r)
    assert (data["engine"], data["fallback_used"], data["review_state"]) == \
        ("static", False, "completed")
    assert data["new_findings_count"] == 1
    assert {"pr", "mode", "model", "findings", "stats", "id"} <= set(data)


def test_finalize_report_passes_suggestion_metadata_through():
    f = _finding()
    f.suggestion_type = "replace"
    f.start_line = 3
    f.end_line = 5
    data = reporter.finalize_report(_result(mode="claude", findings=[f]))
    row = data["findings"][0]
    assert (row["suggestion_type"], row["start_line"], row["end_line"]) == ("replace", 3, 5)


# ==================================================================
# V3-E01 — defect regressions D2 / D3 / D4 (pipeline-level semantics)
# ==================================================================
def test_verification_receives_the_uncapped_finding_list(monkeypatch):
    """D2 (V3-E01-T02): a previous finding that is still reported but sits
    outside the max_comments top-20 must never close itself — both the
    lifecycle and verify_findings() must receive the UNCAPPED current set."""
    from ai_pr_reviewer import verification as ver

    findings = [_finding(title=f"t{i}", severity="high") for i in range(20)]
    findings.append(_finding(title="still there", severity="low"))   # rank 21
    previous = [_finding(title="still there", severity="low", state="active")]
    # stored previous findings carry their fingerprint, as storage rows do;
    # the Wired lifecycle re-uses this exact fp convention for current ones
    previous[0].fingerprint = "fp-a.py-still there"

    seen: dict[str, list] = {}
    real_verify = orch.verify_findings

    def spy(findings_, previous_, current, files):
        seen["current"] = list(current)
        return real_verify(findings_, previous_, current, files)

    monkeypatch.setattr(orch, "verify_findings", spy)
    w = Wired(monkeypatch, findings=findings, previous=previous)
    w.cfg.max_comments = 20                      # low finding falls outside the cap

    result = w.run()

    # the wiring: lifecycle AND verification both got the uncapped set
    assert any(f.title == "still there" for f in w.lifecycle_calls[0][1])
    assert "still there" in [f.title for f in seen["current"]]
    # the outcome: no cap-induced false "resolved"
    by_title = {f.title: f for f in result.findings}
    assert by_title["still there"].state == "active"
    assert by_title["still there"].verification_status == ver.VERIFICATION_PRESENT


def test_below_threshold_findings_stay_visible_in_the_report(monkeypatch):
    """D3 (V3-E01-T03): findings under the severity threshold are recorded —
    counted and listed under a distinguishing key — instead of vanishing,
    while findings_count/open-issue semantics stay threshold-based."""
    w = Wired(monkeypatch, findings=[_finding(title="real issue", severity="high"),
                                     _finding(title="minor nit", severity="info")])
    w.cfg.severity_threshold = "medium"

    result = w.run()

    assert [f.title for f in result.findings] == ["real issue"]
    assert [f.title for f in result.below_threshold] == ["minor nit"]

    data = reporter.finalize_report(result)
    assert [f["title"] for f in data["findings"]] == ["real issue"]
    assert [f["title"] for f in data["below_threshold"]] == ["minor nit"]
    assert data["below_threshold_count"] == 1

    # below-threshold findings are NOT open issues (findings_count unchanged)
    assert [f.title for f in reporter.open_findings(result.findings)] == ["real issue"]

    md = reporter.build_summary_markdown(result)
    assert "below the severity threshold" in md


def _thirty_findings():
    return [_finding(title=f"issue {i}", severity="high") for i in range(30)]


def test_report_and_health_ignore_the_inline_comment_cap(monkeypatch):
    """D4 (V3-E01-T04): max_comments=5 on a 30-finding run still reports all
    30 and scores exactly like a max_comments=30 run."""
    w5 = Wired(monkeypatch, findings=_thirty_findings())
    w5.cfg.max_comments = 5
    r5 = w5.run()

    w30 = Wired(monkeypatch, findings=_thirty_findings())
    w30.cfg.max_comments = 30
    r30 = w30.run()

    assert len(r5.findings) == 30                # report carries every finding
    assert r5.suppressed == 25                   # only the inline slots are "over cap"
    assert len(r30.findings) == 30
    assert r30.suppressed == 0
    assert r5.health_score == r30.health_score   # cap never moves the score


def test_max_comments_caps_inline_posting_but_not_the_report(monkeypatch, tmp_path):
    """D4 (V3-E01-T04): end-to-end through cli.run — 10 findings with
    max_comments=5 posts 5 inline comments while the report and
    findings_count still carry all 10."""
    n = 10

    def lifecycle(previous, current):
        return [_finding(title=f"issue {i}", state="new") for i in range(n)]

    w = Wired(monkeypatch, findings=[_finding(title=f"issue {i}") for i in range(n)],
              lifecycle=lifecycle, with_storage=False)
    monkeypatch.setattr(cli, "GitHubClient", lambda token, repo: w.gh)
    out_file = tmp_path / "gh_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out_file))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    w.cfg.github_token = "t"
    w.cfg.max_comments = 5
    w.cfg.output = str(tmp_path / "report.json")

    result = cli.run(w.cfg)

    assert len(w.gh.posted[0]["comments"]) == 5  # inline cap: only 5 annotations
    assert result.posted_inline == 5
    report = json.loads(Path(w.cfg.output).read_text(encoding="utf-8"))
    assert len(report["findings"]) == n          # report: all 10
    assert "findings_count=10" in out_file.read_text(encoding="utf-8")


# ==================================================================
# V3-E02 — telemetry through the orchestrator (T02 report copy, T04 persist)
# ==================================================================
from ai_pr_reviewer.telemetry import RunTelemetry, to_telemetry_row  # noqa: E402


class _TelemetryStorage(FakeStorage):
    """FakeStorage + the optional save_telemetry capability (V3-E02-T04)."""

    def __init__(self, log=None):
        super().__init__(log or [])
        self.telemetry_calls = []

    def save_telemetry(self, review_id, telemetry):
        self.telemetry_calls.append((review_id, telemetry))


class _FailingTelemetryStorage(_TelemetryStorage):
    def save_telemetry(self, review_id, telemetry):
        raise RuntimeError("telemetry down")


def _run_tel():
    return RunTelemetry(provider="claude", model="claude-test", batch_count=3,
                        events=[{"type": "retry", "attempt": 1,
                                 "planted": "DROP ME"}])


def test_result_telemetry_is_none_when_the_backend_reports_none(monkeypatch):
    """T02 (additive): the Wired double carries no telemetry block, so the
    result and report say null — absence is never invented as numbers."""
    w = Wired(monkeypatch)
    result = w.run()

    assert result.telemetry is None
    assert reporter.finalize_report(result)["telemetry"] is None


def test_result_telemetry_is_serialized_through_the_chokepoint(monkeypatch):
    """T02: the outcome's RunTelemetry reaches the result only as the
    allowlisted, redacted row — planted event keys are gone."""
    w = Wired(monkeypatch, outcome_extra={"telemetry": _run_tel()})
    result = w.run()

    row = result.telemetry
    assert isinstance(row, dict)
    assert row["provider"] == "claude" and row["batch_count"] == 3
    assert list(row["events"][0]) == ["type", "attempt"]
    assert "DROP ME" not in json.dumps(row)
    assert set(row) == {"schema", "provider", "model", "batch_count",
                        "fallback_used", "usage", "calls", "events"}


def test_persist_saves_telemetry_when_storage_supports_it(monkeypatch):
    """T04: the getattr-guarded save_telemetry call rides the same review
    id as findings."""
    storage = _TelemetryStorage()
    w = Wired(monkeypatch, storage=storage,
              outcome_extra={"telemetry": _run_tel()})

    w.run()

    assert len(storage.telemetry_calls) == 1
    review_id, row = storage.telemetry_calls[0]
    assert review_id == "acme/api#7@new222"
    assert row["provider"] == "claude"
    assert storage.saved and storage.set_calls                  # review intact


def test_persist_skips_telemetry_for_storages_without_the_capability(monkeypatch):
    """T04: a storage that predates the capability (plain FakeStorage, the
    dashboard client, …) is simply skipped — no crash, no warning."""
    w = Wired(monkeypatch)                       # default FakeStorage, no method

    result = w.run()

    assert not any("telemetry" in warning for warning in result.warnings)
    assert w.storage.saved                      # findings unaffected


def test_telemetry_failure_warns_but_never_blocks_the_review(monkeypatch):
    """T04 (drop-safe): telemetry is best-effort — a failing save warns,
    while findings persistence and the SHA advance both still happen."""
    storage = _FailingTelemetryStorage()
    w = Wired(monkeypatch, storage=storage,
              outcome_extra={"telemetry": _run_tel()})

    result = w.run()

    assert any("telemetry not saved" in warning for warning in result.warnings)
    assert storage.saved                        # save_findings still ran
    assert storage.set_calls                    # SHA still advanced
    assert result.telemetry is not None         # report keeps its block
