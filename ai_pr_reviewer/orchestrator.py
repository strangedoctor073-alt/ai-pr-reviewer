"""Review orchestrator: diff in -> findings out.

Everything that used to live inline in ``cli.run()`` up to (and including)
"build the ReviewResult" lives here, plus the v2 state handling:

    last reviewed SHA -> (incremental) diff -> filter -> context -> provider
    -> deduplicate -> validate -> finding lifecycle -> ReviewResult -> persist

What stays in ``cli.py`` because it is CLI/Action plumbing: argument parsing,
local-file vs GitHub setup, posting the review to GitHub, writing reports,
pushing to the dashboard and setting Action outputs.

``filter_files`` and ``validate_findings`` moved here unchanged from cli.py;
cli.py re-imports them so ``from ai_pr_reviewer.cli import filter_files`` keeps
working.
"""
from __future__ import annotations

import fnmatch
import time

from . import reporter
from .config import Config, sev_rank
from .diff_parser import FileDiff, parse_unified_diff
from .github_client import GitHubClient, GitHubError
from .models import Finding, PRContext, ReviewKey, ReviewResult, ReviewStats
from .rules import DEFAULT_SEVERITY, load_project_rules

# --- Pipeline stages (each lives in its own module) -------------------------
from .context import build_context                   # provided by context.py
from .findings import (apply_lifecycle, deduplicate,  # provided by findings.py
                       fingerprint_finding, mark_dismissed)
from .model_router import (classify_risk, get_provider,  # model_router.py
                           run_analysis)
from .verification import verification_counts, verify_findings  # C4

# Lifecycle fields persisted with each finding (Finding.to_dict() may or may
# not emit them yet — see _finding_row).
_LIFECYCLE_FIELDS = ("fingerprint", "state", "first_seen_sha", "last_seen_sha",
                     "resolved_at", "github_comment_id",
                     "verification_status", "verification_reason", "verified_at")


# ----------------------------------------------------- moved out of cli.py ----

def _is_excluded(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pat.strip()) for pat in patterns if pat.strip())


def filter_files(files: list[FileDiff], cfg: Config,
                 extra_exclude: list[str] | None = None) -> list[FileDiff]:
    patterns = [*cfg.exclude, *(extra_exclude or [])]
    keep = []
    for f in files:
        if f.is_binary or not f.hunks:
            continue
        if _is_excluded(f.path, patterns):
            continue
        keep.append(f)
    return keep


def validate_findings(findings, files: list[FileDiff], cfg: Config,
                      severity_threshold: str | None = None):
    """Drop findings that can't be anchored, apply the severity threshold and
    the inline-comment cap. Returns (inline_ok, suppressed_count, dropped)."""
    line_maps = {f.path: f.new_line_numbers() for f in files}
    valid: list = []
    dropped: list = []
    for f in findings:
        if f.file not in line_maps:
            dropped.append(f)
            continue
        if f.line is not None and f.line not in line_maps[f.file]:
            # Finding references a line outside the diff — keep it out of inline
            # comments so it never points at innocent code.
            dropped.append(f)
            continue
        if sev_rank(f.severity) < sev_rank(severity_threshold or cfg.severity_threshold):
            continue
        valid.append(f)
    # Already sorted high→low by analyzers; cap what gets posted inline.
    inline = valid[:cfg.max_comments]
    suppressed = len(valid) - len(inline)
    return inline, suppressed, dropped


def _scrub(text: str, cfg: Config) -> str:
    """Remove pattern-matched secrets AND the exact credentials this run was
    configured with, so no provider/HTTP error can echo them into a report,
    step summary, console line or PR comment."""
    from .security import redact_secrets

    text = redact_secrets(text)
    for name in ("github_token", "anthropic_api_key", "openai_api_key",
                 "gemini_api_key", "dashboard_token"):
        secret = getattr(cfg, name, "") or ""
        if len(secret) >= 6:
            text = text.replace(secret, "[REDACTED]")
    return text


def _project_policy(cfg: Config):
    repo_root = getattr(cfg, "repo_root", None) or "."
    rules_file = getattr(cfg, "rules_file", None) or ".ai-pr-reviewer.yml"
    return load_project_rules(repo_root, filename=rules_file)


def _effective_severity_threshold(cfg: Config, policy) -> str:
    if (not getattr(cfg, "severity_threshold_explicit", False)
            and policy.severity_threshold != DEFAULT_SEVERITY):
        return policy.severity_threshold
    return cfg.severity_threshold


# ------------------------------------------------------------ orchestrator ----

class ReviewOrchestrator:
    """Runs one review and returns a :class:`ReviewResult`.

    ``gh`` is the GitHub client (None for local ``--diff-file`` mode).
    ``storage`` is optional review-state storage; without it every run is a
    full, stateless review, exactly like v1.

    ``pr`` / ``diff_text`` are optional, additive keyword arguments used by
    local-file mode, where cli.py has already read the diff and built the
    PRContext. In GitHub mode leave both unset and the orchestrator fetches
    them through ``gh``.
    """

    def __init__(self, cfg: Config, gh: GitHubClient | None, storage=None, *,
                 pr: PRContext | None = None, diff_text: str | None = None):
        self.cfg = cfg
        self.gh = gh
        self.storage = storage
        self._pr = pr
        self._diff_text = diff_text

    # ------------------------------------------------------------------ run
    def run(self) -> ReviewResult:
        t0 = time.monotonic()
        cfg = self.cfg
        warnings: list[str] = []

        # a. diff: full PR diff, or only what changed since the last review
        pr, diff_text, incremental = self._load_diff(warnings)
        repo = cfg.repo or pr.repo

        # b. files
        policy = _project_policy(cfg)
        parsed = parse_unified_diff(diff_text)
        rules_file = getattr(cfg, "rules_file", None) or ".ai-pr-reviewer.yml"
        if any(f.path == rules_file for f in parsed):
            warnings.append(
                f"This PR modifies {rules_file}. Repository policy must come "
                f"from the trusted base revision (check out the PR base, not "
                f"the merge commit) — treat this PR's policy change as untrusted.")
        files = filter_files(parsed, cfg, policy.exclude)
        if not files:
            warnings.append("No reviewable code changes found after filtering.")

        # c-e. context -> provider -> analysis
        context = build_context(pr, files, cfg, self.storage, gh=self.gh)
        # Repository-context problems (budget reached, GitHub unavailable)
        # are surfaced as run warnings; the review continues either way.
        warnings.extend(_scrub(w, cfg) for w in
                        (getattr(context, "context_warnings", None) or []))
        provider = get_provider(cfg, context)
        outcome = run_analysis(cfg, context, provider)
        warnings.extend(_scrub(w, cfg) for w in outcome.warnings)

        # f. dedupe (before the cap, so duplicates can't eat the comment
        #    budget), then anchor / threshold / cap
        findings = deduplicate(outcome.findings)
        inline, suppressed, dropped = validate_findings(
            findings, files, cfg, _effective_severity_threshold(cfg, policy))
        if dropped:
            warnings.append(f"{len(dropped)} finding(s) could not be anchored to a "
                            f"changed line and were kept out of the inline comments.")

        # g. lifecycle against what earlier reviews reported
        previous = self._previous_findings(repo, pr, context)
        lifecycle_findings = self._apply_lifecycle(previous, inline, files,
                                                   incremental, pr.head_sha)
        # ... then verify the "resolved" transitions the lifecycle inferred
        # (C4): anything we cannot actually confirm goes back to active,
        # so a finding never closes itself without evidence.
        lifecycle_findings = verify_findings(lifecycle_findings, previous,
                                             inline, files)
        # ... then park anything the dashboard user muted (see
        # _apply_dismissals) — after the lifecycle so a mute can never
        # overwrite a "resolved" transition, and before the health score
        # so muted findings don't count against it.
        lifecycle_findings = self._apply_dismissals(repo, lifecycle_findings,
                                                    warnings)

        from .models import calculate_health_score
        score, grade = calculate_health_score(lifecycle_findings)
        risk = classify_risk(context)
        transitions = _state_transitions(previous, lifecycle_findings)

        # h. result — same shape as v1, plus what the provider told us
        engine = reporter.resolve_engine(outcome)
        fallback_used = bool(getattr(outcome, "fallback_used", False))
        result = ReviewResult(
            pr=pr, mode=outcome.mode, model=outcome.model,
            reviewed_at=reporter.now_iso(),
            duration_ms=int((time.monotonic() - t0) * 1000),
            summary=outcome.summary, findings=lifecycle_findings,
            suppressed=suppressed, warnings=warnings,
            stats=ReviewStats(
                files=len(files),
                additions=sum(f.additions for f in files),
                deletions=sum(f.deletions for f in files),
                hunks=sum(len(f.hunks) for f in files),
                batches=getattr(outcome, "batch_count", 0) or 1,
            ),
        )
        result.health_score = score
        result.health_grade = grade
        # ReviewResult does not declare these (yet); reporter reads them with
        # getattr, so they work as plain attributes and as real fields alike.
        result.engine = engine
        result.fallback_used = fallback_used
        result.review_state = "fallback" if fallback_used else "completed"
        # V3: additive, read with getattr by the reporter / cli.
        result.risk = risk                          # ReviewRisk (C8 summary)
        result.previous_findings_count = len(previous)
        result.state_transition_count = transitions  # (C8: skip duplicate posts)
        result.verification = verification_counts(lifecycle_findings)  # (C4)

        # i. persist (last: only a fully successful run advances the SHA)
        # ``engine == "static"`` + ``fallback_used`` is the forced-fallback
        # outcome: no AI backend completed and the rule engine stood in.
        result.analysis_degraded = (engine == "static" and fallback_used)
        self._persist(result, repo, pr)
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    # ------------------------------------------------------------ diff intake
    def _load_diff(self, warnings: list[str]) -> tuple[PRContext, str, bool]:
        """Return (PRContext, diff text, incremental?)."""
        cfg, gh = self.cfg, self.gh

        if self._diff_text is not None:            # local --diff-file mode
            pr = self._pr or PRContext(repo=cfg.repo or "local/project",
                                       pr_number=cfg.pr_number or 0)
            return pr, self._diff_text, False

        if gh is None:
            raise ValueError("ReviewOrchestrator needs a GitHub client or an "
                             "explicit diff_text")

        pr = self._pr or self._seed_pr_context()
        full, full_diff = gh.get_pr(cfg.pr_number)
        pr.pr_title = full.pr_title
        pr.author = full.author
        pr.branch = full.branch
        pr.base = full.base
        pr.head_sha = full.head_sha
        pr.url = full.url
        pr.base_sha = getattr(full, "base_sha", "") or ""

        # get_pr() is still needed for metadata and the current head SHA, so
        # the full diff has already been fetched; incremental mode just
        # prefers the smaller compare diff below.
        diff_text, incremental = full_diff, False
        incremental_enabled = vars(cfg).get("incremental_enabled", False)
        if incremental_enabled and self.storage is not None and pr.head_sha:
            last_sha = self._last_reviewed_sha(cfg.repo or pr.repo, pr, warnings)
            if last_sha:
                try:
                    diff_text = gh.compare_commits(last_sha, pr.head_sha)
                    incremental = True
                except GitHubError as exc:
                    # e.g. force-push: last_sha is no longer reachable.
                    warnings.append(f"incremental diff unavailable ({exc}); "
                                    f"reviewed the full PR diff instead.")
        return pr, diff_text, incremental

    def _seed_pr_context(self) -> PRContext:
        event_ctx = self.gh.get_event_context()
        if event_ctx and event_ctx.pr_number == self.cfg.pr_number:
            return event_ctx
        return PRContext(repo=self.cfg.repo, pr_number=self.cfg.pr_number)

    def _last_reviewed_sha(self, repo: str, pr: PRContext,
                           warnings: list[str]) -> str | None:
        try:
            return self.storage.get_last_reviewed_sha(repo, pr.pr_number)
        except Exception as exc:  # noqa: BLE001 — never lose a review to storage
            warnings.append(f"review state unavailable ({exc}); doing a full review.")
            return None

    # -------------------------------------------------------------- lifecycle
    def _previous_findings(self, repo: str, pr: PRContext, context) -> list[Finding]:
        if self.storage is None:
            return []
        # NOTE: get_previous_findings isn't guaranteed on every storage
        # backend; fall back to what build_context loaded.
        getter = getattr(self.storage, "get_previous_findings", None)
        if callable(getter):
            return list(getter(repo, pr.pr_number) or [])
        return list(getattr(context, "previous_findings", None) or [])

    @staticmethod
    def _apply_lifecycle(previous: list[Finding], current: list[Finding],
                         files: list[FileDiff], incremental: bool,
                         head_sha: str) -> list[Finding]:
        """apply_lifecycle() resolves every previous finding that is missing
        from ``current``. After an *incremental* review that would wrongly
        "resolve" findings in files this push never touched, so only findings
        in re-reviewed files go through the lifecycle; the rest are carried
        over as still active."""
        if incremental:
            reviewed = {p for f in files for p in (f.path, f.old_path) if p}
            in_scope = [p for p in previous if p.file in reviewed]
            untouched = [p for p in previous if p.file not in reviewed]
        else:
            in_scope, untouched = previous, []

        updated = list(apply_lifecycle(in_scope, current))
        _stamp_shas(updated, head_sha)

        for p in untouched:                       # not re-reviewed: unchanged
            if getattr(p, "state", "new") in ("new", "reopened"):
                p.state = "active"
        return updated + untouched

    def _apply_dismissals(self, repo: str, findings: list[Finding],
                          warnings: list[str]) -> list[Finding]:
        """Mute findings the dashboard user dismissed (fingerprint match).

        ``get_dismissed_fingerprints`` is an optional storage capability —
        only the dashboard feedback store has it — so backends without it
        (local SQLite, fakes, no storage at all) simply skip this step. A
        failing lookup downgrades to a warning rather than losing the
        review, same policy as every other storage read here.
        """
        getter = getattr(self.storage, "get_dismissed_fingerprints", None) \
            if self.storage is not None else None
        if not callable(getter):
            return findings
        try:
            dismissed = set(getter(repo) or [])
        except Exception as exc:  # noqa: BLE001 — storage must never lose a review
            warnings.append(_scrub(
                f"muted-fingerprint lookup failed ({exc}); no findings were "
                f"muted this run.", self.cfg))
            return findings
        if not dismissed:
            return findings
        return mark_dismissed(findings, dismissed)

    # ------------------------------------------------------------ persistence
    def _persist(self, result: ReviewResult, repo: str, pr: PRContext) -> None:
        """Store findings, then advance last-reviewed SHA. Advancing the SHA is
        the commit point, so it only happens once the findings are saved. A
        storage failure never loses the review — it becomes a warning.

        A *degraded* analysis (``engine == "static"`` with ``fallback_used``,
        i.e. every AI backend failed and the rule engine covered for them —
        see ``model_router.run_analysis``) still stores its findings and its
        report, but deliberately does NOT advance the SHA: the analysis that
        should have covered these commits didn't happen, so the next run
        re-reviews them and gives the providers another try.
        """
        if self.storage is None or not pr.head_sha:
            return
        review_id = ReviewKey(repo=repo, pr_number=pr.pr_number,
                              head_sha=pr.head_sha).as_id()
        try:
            self.storage.save_findings(review_id,
                                       [_finding_row(f) for f in result.findings])
            if getattr(result, "analysis_degraded", False):
                result.warnings.append(
                    "last-reviewed SHA not advanced: no AI provider completed "
                    "this review, so the next run re-reviews these commits.")
                return
            self.storage.set_last_reviewed_sha(repo, pr.pr_number, pr.head_sha,
                                               getattr(pr, "base_sha", "") or "")
        except Exception as exc:  # noqa: BLE001
            result.warnings.append(f"review state not saved ({exc}); the next run "
                                   f"will not be incremental.")


def _state_transitions(previous: list[Finding], findings: list[Finding]) -> int:
    """How many findings changed lifecycle state compared with the stored
    baseline (0 when nothing new happened this run).

    Used by ``cli`` to decide whether a follow-up review is worth posting:
    an unchanged PR must not produce another identical summary comment.
    """
    if not previous:
        return 0
    before: dict[str, str] = {}
    for p in previous:
        before[p.fingerprint or fingerprint_finding(p)] = str(getattr(p, "state", "") or "")
    changed = 0
    for f in findings:
        fp = f.fingerprint or fingerprint_finding(f)
        old = before.get(fp)
        if old is not None and old != str(getattr(f, "state", "") or ""):
            changed += 1
    return changed


def _stamp_shas(findings: list[Finding], head_sha: str) -> None:
    """apply_lifecycle() has no SHA to work with, so record here when each
    finding was first/last seen or resolved (only where nobody set it)."""
    if not head_sha:
        return
    now = reporter.now_iso()
    for f in findings:
        if reporter.finding_state(f) == "resolved":
            if not getattr(f, "resolved_at", None):
                f.resolved_at = now
        else:
            f.last_seen_sha = head_sha
            if not getattr(f, "first_seen_sha", None):
                f.first_seen_sha = head_sha


def _finding_row(f: Finding) -> dict:
    """Finding.to_dict() plus lifecycle fields, whether or not to_dict() has
    learned to emit them."""
    row = f.to_dict()
    for key in _LIFECYCLE_FIELDS:
        if key not in row and hasattr(f, key):
            value = getattr(f, key)
            row[key] = getattr(value, "value", value)
    return row
