"""CLI entry point: set up (local file vs GitHub) → ReviewOrchestrator → review
posted → report stored → Action outputs.

The review pipeline itself lives in ``orchestrator.py``; this module keeps the
CLI/Action plumbing. Run modes:
  GitHub Action / manual against GitHub:
      python -m ai_pr_reviewer --repo owner/name --pr 123
  Local file (no GitHub needed):
      python -m ai_pr_reviewer --diff-file change.diff --repo owner/name --pr 42
"""
from __future__ import annotations

import argparse
import sys
import time

from .config import Config, load_config, merge_dashboard_rules, sev_rank
from .github_client import GitHubClient, GitHubError
from .github_sync import (link_comment_ids, record_comment_ids,  # C5
                          render_finding_comment, sync_finding_states)
from .models import PRContext, ReviewKey, ReviewResult, SEVERITY_ORDER
from . import reporter
# filter_files / validate_findings / _is_excluded / _finding_row moved to
# orchestrator.py; re-exported so `from ai_pr_reviewer.cli import filter_files`
# keeps working.
from .orchestrator import (ReviewOrchestrator, _finding_row,  # noqa: F401
                            _is_excluded, filter_files, validate_findings)
from .security import redact_secrets  # noqa: F401
from .storage import resolve_storage


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="ai-pr-reviewer",
        description="Review a GitHub pull request with Claude and flag potential bugs.")
    p.add_argument("--repo", help="owner/name (defaults to GITHUB_REPOSITORY)")
    p.add_argument("--pr", type=int, help="pull request number")
    p.add_argument("--diff-file", help="review a local unified diff instead of GitHub")
    p.add_argument("--github-token")
    p.add_argument("--anthropic-api-key")
    p.add_argument("--openai-api-key", default=None)
    p.add_argument("--gemini-api-key", default=None)
    p.add_argument("--openai-base-url", default=None)
    p.add_argument("--mock", "--static", dest="mock", action="store_true",
                   help="use the deterministic static-analysis fallback (rule "
                        "engine — NOT AI) instead of Claude; no API key needed")
    p.add_argument("--model", help="model id (Claude default: claude-sonnet-4-6; required for OpenAI/Gemini/custom endpoints)")
    p.add_argument("--severity-threshold",
                   choices=SEVERITY_ORDER, help="minimum severity to comment inline")
    p.add_argument("--max-comments", type=int)
    p.add_argument("--exclude", action="append",
                   help="glob to skip (repeatable, or INPUT_EXCLUDE newline list)")
    p.add_argument("--focus", action="append", help="extra review focus hint (repeatable)")
    p.add_argument("--fail-on", choices=("never", *SEVERITY_ORDER))
    p.add_argument("--no-comment", action="store_true",
                   help="do not post to GitHub; only write the report")
    p.add_argument("--dashboard-url")
    p.add_argument("--dashboard-token")
    p.add_argument("--storage-file",
                   help="local SQLite file for stateful reviews (default: stateless)")
    p.add_argument("--output", help="path for review-report.json")
    p.add_argument("--pr-title", help="(local mode) PR title for the report")
    p.add_argument("--pr-author", help="(local mode) author login for the report")
    p.add_argument("--pr-branch", help="(local mode) branch name for the report")
    p.add_argument("--provider-order",
                   help="comma-separated AI failover order, e.g. 'claude,openai' "
                        "(also INPUT_PROVIDER_ORDER); the static rule engine is "
                        "always the last fallback and is never listed")
    p.add_argument("--repo-context-chars", type=int, default=None,
                   help="character budget for extra repository context pulled in "
                        "for the reviewer (<=0 disables; also "
                        "INPUT_REPO_CONTEXT_CHARS, default 12000)")
    return p.parse_args(argv)


def run(cfg: Config, pr_overrides: dict | None = None) -> ReviewResult:
    t0 = time.monotonic()
    pr_overrides = pr_overrides or {}

    # ------------------------------------------------- CLI-specific setup
    gh: GitHubClient | None = None
    pr: PRContext | None = None
    diff_text: str | None = None
    if cfg.diff_file:                       # local mode: no GitHub involved
        try:
            with open(cfg.diff_file, encoding="utf-8") as fh:
                diff_text = fh.read()
        except OSError as exc:
            raise SystemExit(f"error: cannot read --diff-file {cfg.diff_file!r}: {exc}")
        pr = PRContext(repo=cfg.repo or "local/project",
                       pr_number=cfg.pr_number or 0,
                       pr_title=pr_overrides.get("pr_title") or cfg.diff_file,
                       author=pr_overrides.get("pr_author", ""),
                       branch=pr_overrides.get("pr_branch") or "feature/branch",
                       base="main")
    else:
        if not cfg.repo or not cfg.pr_number:
            raise SystemExit("error: need --repo and --pr (or --diff-file for local mode)")
        if not cfg.github_token:
            raise SystemExit("error: GitHub token required (set --github-token / "
                             "INPUT_GITHUB_TOKEN / GITHUB_TOKEN)")
        gh = GitHubClient(cfg.github_token, cfg.repo)

    # ------------------------------------------------------------ review
    storage = resolve_storage(cfg)
    result = ReviewOrchestrator(cfg, gh, storage=storage, pr=pr,
                                diff_text=diff_text).run()
    open_ = reporter.open_findings(result.findings)

    # ------------------------------------------------------------ post review
    if gh and not cfg.no_comment:
        result.posted_inline = _post_and_sync(gh, cfg, storage, result, open_)

    # ---------------------------------------------------------------- outputs
    result.duration_ms = int((time.monotonic() - t0) * 1000)
    report = reporter.finalize_report(result)
    if cfg.output:
        reporter.write_report(cfg.output, report)
    reporter.write_step_summary(result)
    if cfg.dashboard_url and cfg.dashboard_token:
        ok, msg = reporter.push_to_dashboard(cfg.dashboard_url, cfg.dashboard_token,
                                             report)
        if ok:
            print(f"[dashboard] {msg}")
        else:
            result.warnings.append(msg)

    _set_github_output("findings_count", str(len(open_)))
    _set_github_output("critical_count",
                       str(reporter.severity_counts(open_).get("critical", 0)))
    _set_github_output("health_score", str(getattr(result, "health_score", 100)))
    _set_github_output("health_grade", str(getattr(result, "health_grade", "A+")))
    if cfg.output:
        _set_github_output("report_path", cfg.output)

    _print_console(result, report["id"])
    return result


def _review_is_worth_posting(result: ReviewResult, to_post: list) -> bool:
    """V3 C8: an unchanged follow-up review must not post a duplicate comment.

    Posts when this is the first review of the PR, when there is something new
    to say inline, or when at least one finding changed lifecycle state this
    run (opened, resolved, muted, dismissed or reopened). Otherwise the PR has
    seen everything we have — the report and step summary are still written.
    """
    if getattr(result, "previous_findings_count", 0) == 0:
        return True
    if to_post:
        return True
    return getattr(result, "state_transition_count", 0) > 0


def _post_and_sync(gh: GitHubClient, cfg: Config, storage, result: ReviewResult,
                   open_) -> int:
    """Post this run's review, then keep GitHub in sync with our state (C5).

    Three things happen in order: the new/reopened findings that don't already
    have a GitHub comment get inline comments, the comments we posted in an
    *earlier* run are updated when their finding changed state, and any comment
    ids we learned are written back so the next review can reuse them.
    Nothing here can lose the review: every GitHub failure is a warning.
    """
    # Findings the PR hasn't seen yet get inline comments; a finding that
    # already carries a GitHub comment id is updated below instead of being
    # posted a second time (C5 — no duplicate comments).
    to_post = [f for f in open_
               if reporter.finding_state(f) in ("new", "reopened")
               and not getattr(f, "github_comment_id", None)]

    posted = 0
    linked = 0
    if _review_is_worth_posting(result, to_post):
        posted, res = _post_review(gh, cfg, result, to_post)
        if res is not None:
            linked += record_comment_ids(result.findings, res)
            n_linked, link_warnings = link_comment_ids(
                gh, result.pr.pr_number, to_post, result.pr.head_sha)
            linked += n_linked
            result.warnings.extend(link_warnings)
    else:
        print("[ai-pr-reviewer] nothing changed since the previous review — "
              "skipping a duplicate review comment.")

    # Reflect resolved/muted/dismissed/reopened on the comments already on
    # the PR. Deletions, rate limits and missing permissions all degrade to
    # warnings; the report has already been produced and is unaffected.
    _updated, sync_warnings = sync_finding_states(gh, result.findings)
    result.warnings.extend(sync_warnings)

    if linked:
        _persist_comment_ids(storage, result)
    return posted


def _persist_comment_ids(storage, result: ReviewResult) -> None:
    """Save the GitHub comment ids learned while posting.

    The orchestrator already stored this review's findings before the post;
    this second write only adds ids, and its failure only costs us a possible
    duplicate comment on the next run.
    """
    if storage is None or not result.pr.head_sha:
        return
    review_id = ReviewKey(repo=result.pr.repo, pr_number=result.pr.pr_number,
                          head_sha=result.pr.head_sha).as_id()
    try:
        storage.save_findings(review_id, [_finding_row(f) for f in result.findings])
    except Exception as exc:  # noqa: BLE001 — ids are an optimisation, not data
        result.warnings.append(f"GitHub comment ids not saved ({exc}); the next "
                               f"review may open a duplicate comment.")


def _post_review(gh: GitHubClient, cfg: Config, result: ReviewResult,
                 findings) -> tuple[int, dict | None]:
    """Post a COMMENT review with inline comments + markdown summary.

    Returns ``(inline comments posted, raw response | None)`` — the response
    carries the comment ids when GitHub returned them (see
    ``github_sync.record_comment_ids``).
    """
    comments = []
    for f in findings:
        comment: dict = {"path": f.file, "side": "RIGHT",
                         "body": render_finding_comment(f)}
        if f.line is not None:
            comment["line"] = f.line
        comments.append(comment)

    body_md = reporter.build_summary_markdown(result)
    try:
        res = gh.post_review(result.pr.pr_number, result.pr.head_sha, body_md, comments)
        if res.get("recovered"):
            result.warnings.append(
                "GitHub rejected the grouped inline review; valid findings were posted "
                "as individual inline comments."
            )
        return len(comments) - res.get("dropped", 0), res
    except GitHubError as exc:
        # Last resort: land the whole review as a regular PR comment. If that
        # is refused too (typically a read-only token: fork and Dependabot PRs),
        # keep going -- the report, step summary and outputs are still written.
        try:
            gh.create_comment(result.pr.pr_number, body_md)
            result.warnings.append(f"inline review failed ({exc}); posted as PR comment")
        except GitHubError as exc2:
            result.warnings.append(
                f"could not post the review to GitHub ({exc2}). The report was still "
                f"written. Check that the token has pull-requests: write; fork and "
                f"Dependabot PRs only get a read-only token.")
        return 0, None


def _set_github_output(name: str, value: str) -> None:
    import os

    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


def _print_console(result: ReviewResult, report_id: str) -> None:
    open_ = reporter.open_findings(result.findings)
    counts = reporter.severity_counts(open_)
    bits = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium",
                                                  "low", "info") if counts.get(s))
    print(f"[ai-pr-reviewer] {result.pr.repo}#{result.pr.pr_number} "
          f"({result.pr.pr_title[:60]}) — {len(open_)} finding(s)"
          f"{': ' + bits if bits else ''}")
    print(f"[ai-pr-reviewer] engine={result.model} mode={result.mode} "
          f"duration={result.duration_ms}ms report_id={report_id}")
    for w in result.warnings:
        print(f"[ai-pr-reviewer] warning: {w}")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_config(args)
    merge_dashboard_rules(cfg)
    if not cfg.mock and not (cfg.anthropic_api_key or cfg.openai_api_key or cfg.gemini_api_key or cfg.openai_base_url):
        print("[ai-pr-reviewer] no AI API key set — falling back to the "
              "heuristic rule engine (mock mode).")
        cfg.mock = True

    from .model_router import provider_config_error
    config_error = provider_config_error(cfg)
    if config_error:
        print(f"error: {config_error}", file=sys.stderr)
        return 1

    result = run(cfg, pr_overrides={
        "pr_title": args.pr_title or "",
        "pr_author": args.pr_author or "",
        "pr_branch": args.pr_branch or "",
    })

    open_ = reporter.open_findings(result.findings)
    if cfg.fail_on != "never" and open_:
        worst = max(sev_rank(f.severity) for f in open_)
        if worst >= sev_rank(cfg.fail_on):
            print(f"[ai-pr-reviewer] FAIL_ON={cfg.fail_on} threshold reached — "
                  f"failing the check.")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
