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
import logging
import time
from typing import Callable

from . import reporter
from .config import Config, sev_rank
from .diff_parser import FileDiff, parse_unified_diff
from .github_client import GitHubClient, GitHubError
from .models import (LIFECYCLE_FIELDS as _MODEL_LIFECYCLE_FIELDS,  # models.py
                     EvidenceRecord, Finding, PRContext,
                     ReviewKey, ReviewResult, ReviewStats,
                     derive_provenance_source)
from .rules import DEFAULT_SEVERITY, load_project_rules
from .feedback import apply_feedback_suppression, load_feedback_config  # V4-E09
from .storage import has_capability
from .storage_schema import (CAP_DISMISSED_FINGERPRINTS,
                             CAP_PREVIOUS_FINDINGS, CAP_TELEMETRY)

# --- Pipeline stages (each lives in its own module) -------------------------
from .context import build_context                   # provided by context.py
from .findings import (apply_lifecycle, deduplicate,  # provided by findings.py
                       fingerprint_finding, mark_dismissed)
from .model_router import (classify_risk, get_provider,  # model_router.py
                           run_analysis)
from .telemetry import to_telemetry_row                 # V3-E02-T02/T04
from .verification import verification_counts, verify_findings  # C4

# Lifecycle fields persisted with each finding (Finding.to_dict() may or may
# not emit them yet — see _finding_row). V4-E04: derived from the single
# models.LIFECYCLE_FIELDS definition so the two can never drift apart again
# (the old hardcoded copy was missing the provenance fields).
_LIFECYCLE_FIELDS = _MODEL_LIFECYCLE_FIELDS

log = logging.getLogger(__name__)


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


def severity_sort_key(f):
    """Deterministic pipeline ordering: severity descending, then file, then
    line (missing lines sort first). Providers are NOT trusted to arrive
    sorted — D5 showed the old "already sorted by analyzers" assumption let a
    cap prefer a mild finding over a critical one. Every truncation point
    (inline cap, summary top-N, report listing) cuts along this one key."""
    return (-sev_rank(f.severity), f.file or "", f.line or 0)


def validate_findings(findings, files: list[FileDiff], cfg: Config,
                      severity_threshold: str | None = None):
    """Drop findings that can't be anchored, apply the severity threshold and
    split the report set from the inline-comment set.

    Returns ``(inline, reported, below_threshold, suppressed, dropped)``:

    * ``inline``          — the top ``max_comments`` findings after the
                            severity sort (what may be annotated inline on
                            GitHub);
    * ``reported``        — every anchored finding at/above the severity
                            threshold, severity-sorted (the full set the
                            report, health score, lifecycle and verification
                            must see — D2/D4: the cap must never shrink
                            "what this review found");
    * ``below_threshold`` — anchored findings *under* the severity threshold:
                            kept (D3 — they used to vanish entirely), listed
                            separately in the report, never counted towards
                            ``findings_count``/inline comments;
    * ``suppressed``      — how many reported findings fell over the inline
                            cap (they are still reported, just not annotated
                            inline);
    * ``dropped``         — findings that could not be anchored to a changed
                            line.
    """
    line_maps = {f.path: f.new_line_numbers() for f in files}
    valid: list = []
    below: list = []
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
            # D3: record instead of dropping — a suppressed finding must stay
            # visible in the report (and truthful counts) even though it is
            # not reported as an issue or annotated inline.
            below.append(f)
            continue
        valid.append(f)
    # D5: sort at the pipeline level before any cap applies (see
    # severity_sort_key) — never trust provider ordering.
    valid.sort(key=severity_sort_key)
    below.sort(key=severity_sort_key)
    inline = valid[:cfg.max_comments]
    suppressed = len(valid) - len(inline)
    return inline, valid, below, suppressed, dropped


def _scrub(text: str, cfg: Config) -> str:
    """Remove pattern-matched secrets AND the exact credentials this run was
    configured with, so no provider/HTTP error can echo them into a report,
    step summary, console line or PR comment.

    Thin delegate to :func:`ai_pr_reviewer.security.scrub_with_config` —
    the shared policy every redaction boundary uses (kept under this name
    because tests and internal callers import ``orchestrator._scrub``)."""
    from .security import scrub_with_config

    return scrub_with_config(text, cfg)


def _scrub_evidence_records(records, scrub) -> tuple:
    """Re-create evidence records through ``EvidenceRecord.create`` with an
    extra scrub layer (V4-E08-T05 follow-up).

    ``create`` re-applies pattern redaction (idempotent), re-bounds (already
    bounded on read) and recomputes ``content_hash`` over the FINAL stored
    text — so a clean record round-trips byte-identically (same hash), a
    tainted one is rewritten text+hash together (``integrity_ok`` stays
    True), and no stored hash is ever invalidated without its text moving
    with it. Records that cannot be re-created (shouldn't happen: every
    record here came through ``create`` or the validating ``from_dict``)
    are kept as-is rather than dropped — evidence is a bonus, never fatal.
    """
    out = []
    for e in records:
        try:
            out.append(EvidenceRecord.create(
                kind=e.kind, locator=scrub(e.locator), summary=scrub(e.summary),
                check_type=e.check_type))
        except (AttributeError, TypeError, ValueError):
            out.append(e)
    return tuple(out)


def _redact_previous_findings(findings: list, cfg: Config) -> list:
    """V4-E08-T05 follow-up (audit P2-1): findings loaded from storage were
    written by releases *before* the output redaction chokepoint and can
    carry raw credential-shaped text. Redact them at the load boundary —
    before lifecycle processing, fingerprint matching, verification or any
    sink (comments, PATCH sync, report rows, warnings, re-persisted rows)
    can see them.

    Evidence records are rewritten ONLY when the scrub actually changes
    their text (text and ``content_hash`` move together — see
    ``_scrub_evidence_records``); untouched records keep their stored hash
    bytes so the tamper-detection contract survives. Idempotent; a
    non-Finding entry is skipped rather than losing the whole review.
    """
    def scrub(text: str) -> str:
        return _scrub(text, cfg)

    for f in findings:
        if not isinstance(f, Finding):
            continue
        f.redact_text(scrub)
        if f.evidence:
            f.evidence = _scrub_evidence_records(f.evidence, scrub)
    return findings


def _redact_engine_output(outcome, cfg: Config) -> None:
    """V4-E08-T05 — THE output redaction chokepoint.

    Engine text (every finding's ``title``/``explanation``/``suggestion``
    and the review ``summary``) is redacted here, at the single point
    where model output crosses from the provider into the pipeline —
    before provenance stamping, evidence attachment, dedup, lifecycle or
    any sink. Everything downstream (inline comment bodies, the markdown
    summary comment, JSON/markdown report artifacts, GitHub step
    summaries, dashboard uploads and persisted finding rows) reads these
    same fields, so one boundary covers all of them instead of each sink
    re-implementing the policy (AGENTS.md security invariant: "the
    finding→comment/report chokepoint").

    ``_scrub`` layers exact configured-credential removal on top of the
    pattern redaction: the model never sees those values, but a quoted
    diff might contain one. Idempotent; only text values change — the
    report schema and field types are untouched.
    """

    def scrub(text: str) -> str:
        return _scrub(text, cfg)

    for f in getattr(outcome, "findings", None) or ():
        f.redact_text(scrub)          # Finding-like or it fails loudly here
        # V4-E08-T05 follow-up: engine-attached evidence (the static
        # engine quotes diff lines at the engine, before this chokepoint)
        # gets the same configured-credential layer, re-created through
        # ``create`` so the content hash keeps committing to the stored
        # text. Clean records round-trip byte-identically.
        if getattr(f, "evidence", None):
            f.evidence = _scrub_evidence_records(f.evidence, scrub)
    summary = getattr(outcome, "summary", None)
    if isinstance(summary, str) and summary:
        outcome.summary = scrub(summary)


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
        # V4-E08-T05: THE output redaction chokepoint. Engine text crosses
        # from the provider into the pipeline right here — before
        # provenance, dedup, lifecycle or any sink — so every downstream
        # consumer (comments, reports, step summaries, dashboard uploads,
        # stored rows) reads already-redacted fields.
        _redact_engine_output(outcome, cfg)

        # f. provenance + evidence first (V4-E04-T03: attribution must be
        #    recorded *before* dedup so merging two engines' renderings of
        #    one issue keeps both attributions instead of destroying them),
        #    then dedupe (before the cap, so duplicates can't eat the
        #    comment budget), then anchor / threshold / cap.
        _stamp_provenance(outcome.findings, outcome)
        _attach_diff_evidence(
            outcome.findings, files,
            scrub=lambda t: _scrub(t, cfg))
        findings = deduplicate(outcome.findings)
        # D4: ``max_comments`` is a *posting* limit only. ``reported`` is
        # every anchored finding this review found — the report, the health
        # score, the lifecycle and the verification must all see the full
        # set. The severity-sorted top ``max_comments`` (``_inline``) is
        # enforced where comments are actually posted (cli._post_and_sync),
        # never by shrinking what the review claims to have found.
        _inline, reported, below_threshold, suppressed, dropped = validate_findings(
            findings, files, cfg, _effective_severity_threshold(cfg, policy))
        if dropped:
            warnings.append(f"{len(dropped)} finding(s) could not be anchored to a "
                            f"changed line and were kept out of the inline comments.")

        # g. lifecycle against what earlier reviews reported
        previous = self._previous_findings(repo, pr, context)
        lifecycle_findings = self._apply_lifecycle(previous, reported, files,
                                                   incremental, pr.head_sha)
        # ... then verify the "resolved" transitions the lifecycle inferred
        # (C4): anything we cannot actually confirm goes back to active,
        # so a finding never closes itself without evidence.
        # D2: verification must receive the UNCAPPED ``current`` set — fed the
        # max_comments-capped list, a still-present finding beyond the cap
        # looked absent and closed itself as "resolved".
        lifecycle_findings = verify_findings(lifecycle_findings, previous,
                                             reported, files)
        # ... then park anything the dashboard user muted (see
        # _apply_dismissals) — after the lifecycle so a mute can never
        # overwrite a "resolved" transition, and before the health score
        # so muted findings don't count against it.
        lifecycle_findings = self._apply_dismissals(repo, lifecycle_findings,
                                                    warnings)
        # V4-E09: apply HUMAN-created suppression rules (feedback.enabled,
        # default off -> same list back, no storage access, no fields). Read
        # side only; the engine cannot create or change a rule.
        lifecycle_findings, feedback_fields = apply_feedback_suppression(
            enabled=load_feedback_config(
                getattr(cfg, "repo_root", None) or ".",
                getattr(cfg, "rules_file", None) or ".ai-pr-reviewer.yml").enabled,
            storage=self.storage, repo=repo, findings=lifecycle_findings,
            warnings=warnings, scrub=lambda m: _scrub(m, cfg))

        # D5: one authoritative severity ordering for the whole result —
        # deterministic report JSON, and every downstream truncation (summary
        # top-N, inline comment cap) cuts severity-first instead of trusting
        # provider ordering.
        lifecycle_findings.sort(key=severity_sort_key)

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
            below_threshold=below_threshold,
            stats=ReviewStats(
                files=len(files),
                additions=sum(f.additions for f in files),
                deletions=sum(f.deletions for f in files),
                hunks=sum(len(f.hunks) for f in files),
                batches=getattr(outcome, "batch_count", 0) or 1,
            ),
        )
        result.health_score = score
        result.feedback_report_fields = feedback_fields   # V4-E09 ({} when off)
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
        # V3-E02-T02: run telemetry, serialized exactly once through the
        # allowlist+redaction chokepoint. Backends without a telemetry
        # block (test doubles) report null — additive, never invented.
        outcome_telemetry = getattr(outcome, "telemetry", None)
        result.telemetry = to_telemetry_row(outcome_telemetry) \
            if outcome_telemetry is not None else None

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
        # Declared-capability branch (V3-E04-T04): a backend without the
        # previous-findings capability falls back to what build_context
        # loaded — same behavior as the old getattr guard, no probing.
        # Both branches pass through the legacy-redaction boundary first
        # (V4-E08-T05 follow-up, audit P2-1): stored rows from the
        # pre-chokepoint era are re-redacted before lifecycle or any sink
        # sees them. (The context branch is already redacted at its own
        # load site; redaction is idempotent.)
        if has_capability(self.storage, CAP_PREVIOUS_FINDINGS):
            return _redact_previous_findings(
                list(self.storage.get_previous_findings(repo, pr.pr_number) or []),
                self.cfg)
        return _redact_previous_findings(
            list(getattr(context, "previous_findings", None) or []), self.cfg)

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

        ``get_dismissed_fingerprints`` is a declared optional capability
        (V3-E04-T04): every real backend provides it, backends that
        don't (stateless runs, minimal fakes) skip the step with a
        logged warning instead of silently varying. A failing lookup
        downgrades to a report warning rather than losing the review,
        same policy as every other storage read here.
        """
        if self.storage is None:
            return findings
        if not has_capability(self.storage, CAP_DISMISSED_FINGERPRINTS):
            log.warning("storage backend %s lacks get_dismissed_fingerprints "
                        "— no findings were muted this run",
                        type(self.storage).__name__)
            return findings
        try:
            dismissed = set(self.storage.get_dismissed_fingerprints(repo) or [])
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
        # Telemetry is drop-safe (V3-E02-T04 · ADR-014): it rides the same
        # review id, behind the declared telemetry capability (V3-E04-T04)
        # instead of a getattr probe — a backend without the capability
        # (the HTTP client, a pre-telemetry fake) drops the row with a
        # logged warning, and a storage failure only ever warns.
        if getattr(result, "telemetry", None):
            if has_capability(self.storage, CAP_TELEMETRY):
                try:
                    self.storage.save_telemetry(review_id, result.telemetry)
                except Exception as exc:  # noqa: BLE001 — telemetry must not fail a review
                    result.warnings.append(f"telemetry not saved ({exc})")
            else:
                log.warning("storage backend %s cannot store telemetry "
                            "— dropping this run's row (drop-safe)",
                            type(self.storage).__name__)
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


def _stamp_provenance(findings: list[Finding], outcome) -> None:
    """V4-E04: populate provenance on every finding *before* dedup.

    Pipeline-owned, from AnalysisOutcome -- never from model output (these
    fields are in LIFECYCLE_FIELDS, so from_untrusted_dict strips any
    model-supplied value). Both the scalar fields (authoritative first
    source, backward compatible) and the additive provenance_sources list
    are set, so a later merge can preserve every engine's attribution.
    """
    engine = getattr(outcome, "engine", "") or ""
    model = getattr(outcome, "model", "") or ""
    for f in findings:
        # Per finding, not per outcome: a blended "claude+static" outcome
        # holds both AI and rule-engine findings (models.derive_provenance_source).
        src = derive_provenance_source(f, outcome_engine=engine,
                                       outcome_model=model)
        f.provenance_engine = src.engine
        f.provenance_model = src.model
        f.provenance_agent = None  # V5+ specialist agents
        f.provenance_origin = src.origin
        if not f.provenance_sources:
            f.provenance_sources = (src,)


def _attach_diff_evidence(findings: list[Finding],
                          files: list[FileDiff],
                          scrub: Callable[[str], str] | None = None) -> None:
    """V4-E04: attach diff-hunk evidence to findings that don't already
    carry records (the static engine attaches its own rule_ref/diff_hunk
    evidence at the engine, V4-E04-T05).

    The record quotes the exact added line the finding is anchored to --
    the machine-checkable "here is the code we flagged" backing ADR-004's
    "no unsupported certainty". Construction goes through
    EvidenceRecord.create, so quoted code is redacted and bounded inside
    the write path, not at callers. ``scrub`` (V4-E08-T05 follow-up) adds
    the run's configured-credential removal on top: the quoted line comes
    from the untrusted diff and might contain one. Unanchored (file-level)
    findings honestly carry no evidence rather than a fabricated one.
    """
    by_path = {fd.path: fd for fd in files if not fd.is_binary}
    for f in findings:
        if f.evidence or f.line is None:
            continue
        fd = by_path.get(f.file)
        if fd is None:
            continue
        for line_no, text in fd.added_lines():
            if line_no == f.line:
                end = f.end_line or f.line
                f.evidence = (EvidenceRecord.create(
                    kind="diff_hunk",
                    locator=f"{fd.path}:{f.line}-{end}",
                    summary=text,
                    check_type=f.category,
                    scrub=scrub,
                ),)
                break
