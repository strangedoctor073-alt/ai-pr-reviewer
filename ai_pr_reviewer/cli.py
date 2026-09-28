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
from .models import PRContext, ReviewResult, SEVERITY_ORDER
from . import reporter
# filter_files / validate_findings / _is_excluded moved to orchestrator.py;
# re-exported so `from ai_pr_reviewer.cli import filter_files` keeps working.
from .orchestrator import (ReviewOrchestrator, _is_excluded,  # noqa: F401
                            filter_files, validate_findings)
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
        # Only findings the PR hasn't seen yet get inline comments; with no
        # stored state that is every finding, exactly as in v1.
        to_post = [f for f in open_ if reporter.finding_state(f) in ("new", "reopened")]
        result.posted_inline = _post_review(gh, cfg, result, to_post)

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


def _post_review(gh: GitHubClient, cfg: Config, result: ReviewResult,
                 findings) -> int:
    """Post a COMMENT review with inline comments + markdown summary."""
    comments = []
    for f in findings:
        body = (f"**\U0001f916 {f.severity.upper()}: {f.title}** `{f.category}`\n\n"
                f"{f.explanation}")
        if f.suggestion:
            body += "\n\n```suggestion\n" + f.suggestion + "\n```"
        comment: dict = {"path": f.file, "side": "RIGHT", "body": body}
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
        return len(comments) - res.get("dropped", 0)
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
        return 0


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
