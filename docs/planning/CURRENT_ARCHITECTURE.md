# CURRENT ARCHITECTURE — Ground Truth (V3)

> Status: verified against source on 2026-10-03 at commit `2841b23` (working tree).
> Suite: `python -m pytest tests/ -q` → **464 passed, 1 warning** (CI: py3.11/3.12/3.13 + docker build).
> This document is the source of truth for all other planning docs in `docs/planning/`.
> If a planning document disagrees with this one, this one wins — until re-verified.

---

## 1. System overview

An open-source, composite GitHub Action (`action.yml`) that runs a Python review
engine (`ai_pr_reviewer/`) plus an optional FastAPI dashboard (`dashboard/`).
No build step; pip only. Two operational modes:

- **GitHub mode**: Action runs on `pull_request`, checks out the PR **base**
  revision, engine reads PR metadata/diff via GitHub API, posts a review with
  inline comments.
- **Local mode**: `python -m ai_pr_reviewer --diff-file … --mock` — fully
  offline, deterministic static engine ("not AI", labelled honestly).

Config layering: **CLI args > `INPUT_*` env (Action inputs) > plain env > defaults**,
plus two orthogonal merges (dashboard rules, `.ai-pr-reviewer.yml` project policy).

## 2. Current architecture diagram

```
                         ┌────────────────────────────────────────────┐
 GitHub Event            │                ENGINE PROCESS              │
 (pull_request)          │  cli.py  ── load_config ── merge_dashboard  │
      │                  │    │                                        │
      ▼                  │    ▼                                        │
 github_client.py ◄──────┼─ orchestrator.py (ReviewOrchestrator.run)   │
  get_pr / get_event     │    │                                        │
  compare_commits        │    │ a. _load_diff (full or incremental)    │
  get_file (base ref?)   │    │ b. rules.py load_project_rules (policy)│
  post_review            │    │ c. context.py build_context            │
      ▲                  │    │      ├ memory.py (repo memory, fenced) │
      │                  │    │      ├ repo_context.py (bounded fetch) │
      │                  │    │      ├ storage.get_previous_findings   │
      │                  │    │      └ _apply_context_budget (80k ch)  │
      │                  │    │ d. model_router.get_provider           │
      │                  │    │      circuit.py per-backend breaker    │
      │                  │    │ e. model_router.run_analysis           │
      │                  │    │      retry.py → provider.analyze()     │
      │                  │    │      primary → secondary → static      │
      │                  │    │      ┌─────────────────────────────┐   │
      │                  │    │      │ ai/claude · ai/openai ·      │   │
      │                  │    │      │ ai/gemini · static/engine    │   │
      │                  │    │      └─────────────────────────────┘   │
      │                  │    │ f. findings.deduplicate → validate     │
      │                  │    │ g. lifecycle → verification → mutes    │
      │                  │    │ h. health score / risk / review_state  │
      │                  │    │ i. storage._persist (findings, then    │
      │                  │    │       last_reviewed_sha = commit point)│
      │                  │    ▼                                        │
      └──────────────────┼─ cli: post/sync (github_sync.py)            │
                         │    reporter.py → report JSON + step summary │
                         │    storage: SQLite file or dashboard HTTP   │
                         └────────────────────────────────────────────┘
                                        │ (optional, X-Dashboard-Token)
                                        ▼
                      dashboard/app.py (FastAPI, token, rate limit, audit)
                        ├ dashboard/storage.py: DbStorage (SQLAlchemy:
                        │   SQLite WAL / Postgres) or JsonStorage fallback
                        └ dashboard/static/: dependency-free SPA
```

## 3. Current dependency graph (import-level)

```
cli ─► config ─► (env/INPUT_* )
cli ─► orchestrator ─► diff_parser ─► models (FileDiff, Finding, …)
                    ─► rules (ReviewPolicy, non-removable exclude baseline)
                    ─► context ─► memory, repo_context, storage, security
                    ─► model_router ─► circuit, retry
                    │              ─► ai.claude / ai.openai / ai.gemini
                    │              ─► static.engine (StaticProvider)
                    ─► findings (fingerprint, dedup, lifecycle, mutes)
                    ─► verification (deterministic, no I/O)
                    ─► reporter
                    ─► storage (ReviewStorage protocol)
                         ├ LocalReviewStorage (sqlite3, stdlib)
                         └ DashboardStorageClient (httpx → dashboard API)
cli ─► github_client (httpx) ─► github_sync (comment posting/sync)
analyzer.py / heuristics.py = legacy facades over static/ + ai.claude
                              (no production caller; stale docstrings)
dashboard.app ─► dashboard.storage ─► models_db (SQLAlchemy ORM)
              ─► (runtime sys.path insert to reach engine for sandbox)
```

Dependency direction is clean: `models`/`security`/`retry`/`circuit` are leaves;
`orchestrator` is the composition root; `dashboard` depends on the engine only
lazily (sandbox, memory category constants).

## 4. Current data-flow diagram

```
FileDiff[] ─► ReviewContext{pr, files, project_rules, previous_findings,
                            memory_notes, focus, repo_context, budget}
   ─► provider.analyze(context) ─► AnalysisOutcome{findings, summary,
                            mode, model, engine, fallback_used, batch_count}
   ─► deduplicate (fingerprint = sha256(category|file|title)[:16])
   ─► validate_findings (anchor → severity threshold → max_comments=20 cap)
   ─► apply_lifecycle (new/active/reopened/resolved-carried)
   ─► verify_findings (resolved | still_present | unable_to_verify)
   ─► mark_dismissed (mute fingerprints, never overwrites resolved)
   ─► ReviewResult (+ runtime attrs: engine, fallback_used, review_state,
                    risk, verification, …)
   ─► reporter.finalize_report → review-report.json (+ $GITHUB_OUTPUT,
                    $GITHUB_STEP_SUMMARY, dashboard POST /api/reports)
   ─► storage.save_findings (payload JSON per fingerprint) → set_last_reviewed_sha
```

**Finding identity**: 16-hex fingerprint over `category|file|normalized_title`
(line deliberately excluded so churn keeps identity). Model output is parsed via
`Finding.from_untrusted_dict`, which strips all `LIFECYCLE_FIELDS` — model output
can never own state/fingerprint/comment ids/verification.

## 5. Current review lifecycle

States (`FindingState`): `new → active → resolved | reopened | muted`
(`dismissed` is declared but never produced by engine code — vestigial).

1. **Incremental gate**: if storage has `last_reviewed_sha` and
   `incremental_enabled`, diff = `compare_commits(last_sha, head_sha)`; force-push
   error → fall back to full diff.
2. **Dedup** first occurrence wins (title-based; cross-engine wording differences
   are documented to not dedup).
3. **Validation**: anchoring → `severity_threshold` (effective order CLI/env >
   project policy > dashboard > `medium`) → `max_comments` cap.
   ⚠ Below-threshold findings are dropped entirely (not counted, not in report).
   ⚠ The cap applies to the *whole* report + health score, not just inline comments.
4. **Lifecycle**: only previous findings in re-reviewed files are transitioned;
   untouched ones carried over (prevents false resolution on partial diffs).
5. **Verification**: purely deterministic — coverage of the flagged line range in
   the current diff (`all|partial|none|file-missing`); `_unverify()` reverts a
   premature `resolved → active`. ⚠ Verification receives the *capped* list as
   "current", so a still-present finding pushed out of the top-20 can be
   synthesized as resolved.
6. **Mutes**: dashboard-authored `fingerprint:<fp>` memory rows → `muted`, applied
   after lifecycle, before health score.
7. **Persist**: findings saved first, then `last_reviewed_sha` advanced (commit
   point). Degraded static-only runs store findings but **withhold** the SHA
   advance so the next run retries AI providers.
8. **Post/sync**: post only `new`/`reopened` without `github_comment_id`;
   grouped review with summary; 422 → individual comments recovery; bounded
   comment-id harvesting; state markers PATCHed onto existing comments
   (`MAX_SYNC_ERRORS = 5`); never re-post when no transitions occurred.

## 6. Current security boundary diagram

```
UNTRUSTED                                TRUSTED
──────────                               ───────
PR diff, PR title/author,            .ai-pr-reviewer.yml (read from base
repository files @ PR,               revision; PR modification = warning),
issue/comment text,                  dashboard settings (token-auth),
model output (from_untrusted_dict,   CLI/env config, human-authored memory,
lifecycle fields stripped),          focus areas
memory notes (fenced), repo
context files (fenced)
        │
        │  wrap_untrusted_diff: nonce-fenced <untrusted_diff id=…>,
        │  spoofed fence tags neutralized
        │  scan_prompt_injection: 8 patterns → warnings only (forensic)
        │  redact_secrets: 12 patterns on everything stored/posted
        │  _safe_repo_path: no ../ or absolute paths into token-bearing URLs
        ▼
   MODEL PROMPT ──► model output ──► validation/anchoring ──► GitHub POST
        │                                                (redacted, capped)
        └── secrets/credentials never echoed in warnings (type name only)
```

Documented invariants (tests enforce): no `pull_request_target`, base-revision
checkout in the example workflow, minimal permissions (`contents: read`,
`pull-requests: write`, **no `checks: write`**), non-removable privacy exclusion
baseline (repo config can only *add* exclusions), constant-time token compare,
weak-token refusal, rate limiting, body/finding caps (2 MB / 500), CSP, no
automatic code modification, no retired model IDs hardcoded, primary-provider
config error is fatal (exit 1) while secondary is a warning.

⚠ **Verified gap**: `github_client.get_pr()` (lines 80-89) and
`get_event_context()` (111-120) **never populate `PRContext.base_sha`**, so
`repo_context.py:238` falls back to `head_sha`. Repository context is therefore
fetched at the **PR head**, not the base revision — contradicting the module's
own documented invariant (`repo_context.py:26-27`). Tests mask this by
constructing `PRContext(base_sha=…)` manually. See `V3-E01`.

## 7. Current storage model

| Store | Owner | Contents | Notes |
|---|---|---|---|
| SQLite (engine, `LocalReviewStorage`) | engine | `review_state` (repo#pr → last_reviewed_sha, base_sha), `finding_history` (repo#pr#fp → state + JSON payload), `repo_memory` (human notes, engine read-only) | connections opened per call, **never closed** (`with conn` commits but doesn't close); no retention/pruning |
| Dashboard `DbStorage` (SQLAlchemy) | dashboard | `reports` (payload JSON, 500-finding cap), `review_states`, `finding_histories`, `repo_memories` | SQLite WAL default, Postgres via `DATABASE_URL`; hand-rolled `ALTER TABLE` migrations; ISO-string timestamps |
| Dashboard `JsonStorage` | dashboard | same entities as JSON files | zero-dependency fallback; single-worker only |
| Dashboard HTTP API | dashboard | engine ↔ dashboard contract | `X-Dashboard-Token`; every engine call swallows errors → stateless degrade |
| `dashboard/data/settings.json` + `audit.jsonl` | dashboard | token, rules, append-only audit | token file chmod 0600 best-effort |
| `review-report.json` | run artifact | full report | uncapped finding count |

Same logical schema duplicated in three implementations (engine SQLite, DbStorage,
JsonStorage) + HTTP contract; `review_id` parsing and `"fingerprint:"` literals
duplicated across modules.

## 8. Current provider architecture

- `AIProvider` protocol: single method `analyze(context) → AnalysisOutcome`;
  informal contract adds `backend: str` + `startup_warnings: list[str]`.
- Implementations: `ClaudeProvider`, `OpenAIProvider` (supports `base_url` for
  OpenAI-compatible endpoints), `GeminiProvider`, `StaticProvider`
  (deterministic rules). Feature-identical by construction — shared
  `SYSTEM_PROMPT`, batching, fencing helpers, per-batch static fallback
  (copy-pasted per provider; `_extract_json` triplicated).
- Routing: `select_backend` heuristic precedence (mock → OpenAI-ish model/base_url
  → gemini-* → claude-* / exclusive keys); `provider_order` comma list; failover
  chain primary → secondary → **static last resort** with truthful attribution
  (`engine="static"`, `fallback_used=True`, "not an AI review" footer).
- Only Claude has a default model (`claude-sonnet-4-6`); OpenAI/Gemini require an
  explicit `model` (config error → exit 1). Release test scans engine sources for
  retired model ID substrings.
- Resilience: `RetryPolicy` (3 attempts, 1s base, 30s cap, 25% jitter;
  retryable {408,409,425,429,5xx} ∪ network; permanent {400,401,403,404,422});
  per-backend circuit breaker (threshold 2, recovery 60s, one half-open trial),
  **process-global, sequential-only**.
- Token usage: counted on Claude/OpenAI provider instances, **never surfaced**
  (not in `AnalysisOutcome`, report, storage, or dashboard); Gemini usage not
  parsed (TODO in code). No cost model, no per-batch latency.

## 9. Current dashboard / API architecture

FastAPI, OpenAPI UI disabled, global middleware (per-IP sliding-window rate limit
READ 240/min, WRITE 30/min; 2 MB body check via Content-Length only; CSP/nosniff/
no-referrer). ~24 routes: reports CRUD + push, stats, findings browser, metrics,
settings/rules, review state, findings history, repo memory CRUD (mute rows
write-protected), feedback (up/down/mute), public SVG badge, unauthenticated
static **sandbox** (runs the static engine on pasted diff). Auth: single shared
token (`DASHBOARD_TOKEN` → settings.json → generated), `hmac.compare_digest`,
weak-token refusal, reads optionally unauthenticated
(`DASHBOARD_REQUIRE_TOKEN_FOR_READS=0`). Frontend: dependency-free hash-router SPA
(reviews, report detail, findings, metrics, sandbox, rules + memory).

## 10. Current extension points

1. **Provider**: structural `AIProvider` protocol — but adding a backend touches
   7 hard-coded sites (`AI_BACKENDS`, `select_backend`, `build_provider`,
   `Config`/`load_config`, CLI args, `action.yml`, reporter engine labels).
   No capability declaration, no per-backend retry config, no discovery.
2. **Static rule pack**: module exposing `register(registry)` added to the tuple
   in `static/engine.build_default_registry()` — the single wiring point. Buckets:
   line rules / file rules / diff rules. No config-driven enable/disable
   (`.ai-pr-reviewer.yml` has no rule toggles; `rules:` is free-text prompt guidance).
3. **Storage**: `ReviewStorage` Protocol — but two optional capabilities
   (`get_dismissed_fingerprints`, `list_repo_memory`) are deliberately undeclared
   and reached via `getattr` guards; behavior silently varies by backend.
4. **Config**: layering is stable; project policy schema (`review.mode`,
   `review.severity_threshold`, `rules`, `exclude`, `focus`) is small and stable.
5. **No plugin system, no event bus, no versioned API, no public extension contract.**

## 11. Technical debt & architectural constraints (ranked)

**Verified defects (correctness/security):**

| # | Issue | Where |
|---|---|---|
| D1 | `base_sha` never set → repo context fetched at PR **head**, violating documented base-revision invariant | `github_client.py:80-89,111-120`; `repo_context.py:238` |
| D2 | Verification receives the capped (`max_comments=20`) list as "current" → cap-induced false `resolved` | `orchestrator.py:183-189` vs `verification.py:85-136` |
| D3 | Below-threshold findings dropped entirely (absent from report, counts, health score) while summary claims `suppressed` covers them | `orchestrator.py:79-84`; `reporter.py:316-318` |
| D4 | `max_comments` silently caps the whole report + health score, not just inline comments (contradicts `action.yml:44`) | `orchestrator.py:174-176` |
| D5 | AI findings are never severity-sorted → top-N markdown/comment caps may prefer mild over critical findings | `orchestrator.py:82` assumes sorted; only static sorts |
| D6 | Numeric `INPUT_*` parsing (`pr_number`, `max_comments`, `batch_chars`) raises raw `ValueError` (traceback, no exit 1). **Partially fixed:** `repo_context_chars` now uses safe `_int_field()` (`config.py:140-142`); 3 of 4 fields remain raw. | `config.py:113,119,129` |
| D7 | `DbStorage.record_feedback` looks up mute row by non-PK → every mute mints a duplicate row (no idempotency) | `dashboard/storage.py:337` |

**Structural constraints (block or tax future capabilities):**

| # | Constraint | Consequence |
|---|---|---|
| C1 | One provider per run; failover returns *first success*, no fan-out/merge primitive | multi-agent needs a new orchestration layer |
| C2 | Single shared `SYSTEM_PROMPT`; prompt assembly copy-pasted in 3 providers | specialist reviewers require prompt-builder extraction first |
| C3 | No provenance fields on `Finding` (no engine/model/agent/origin) | cross-engine dedup destroys attribution; council merge impossible |
| C4 | Title-based 16-hex fingerprints; documented cross-engine dedup gap | duplicate comments across engines; relations (caused_by/regression_of) have no identity to attach to |
| C5 | Circuit breakers process-global, one half-open trial, sequential assumption | unsafe for concurrent specialist calls; multi-tenant impossible |
| C6 | No token/cost/latency telemetry surfaced anywhere | no basis for budget arbitration, review-depth control, or cost dashboards |
| C7 | Budgets are characters (`batch_chars=80k`, `repo_context_chars=12k`), independent, never summed; `token_budget` misnamed | no true context-window awareness |
| C8 | GitHub client: no rate-limit handling (`403` classified permanent), retry on 1 endpoint only, `get_pr` = 2 calls, 1000-file cap, 1 MB file cap | scaling to large repos/orgs will hit API pressure early |
| C9 | Storage: no retention, connections never closed, 3 duplicated implementations, O(all) dashboard queries | unbounded growth; single-worker ceiling |
| D10 | `ReviewResult` runtime-attached attributes not declared/serialized (`risk`, `verification` missing from report JSON) | dashboard/artifact never sees them |
| D11 | Legacy facades (`analyzer.py`, `heuristics.py`, `get_analyzer`) with stale docstrings contradicting reality | contributor confusion; doc/code drift |
| D12 | Duplicate security baselines (`rules.py` vs `dashboard/app.py` sensitive globs) synced only by convention | invariant could diverge silently |
| D13 | Sensitive-path caps hard-coded (8 context files, 4 config probes, 50 memory entries, 20 comments, 500 dashboard findings, 8 markdown findings) | silent quality ceilings on large PRs |
| D14 | No lint/type gate in CI (ruff configured, not installed); Python support story split (Action 3.12, CI 3.11–3.13, local 3.14) | drift risk as codebase grows |

## 12. Current scalability limits

- **PR size**: diff cap via `chunk_files` 80k chars/3000 lines per file;
  GitHub files cap 1000; large-PR threshold 30 files only raises a risk label.
- **Concurrency**: one review per process; breakers/state process-global;
  dashboard single-worker (rate limiter + audit file are per-process).
- **GitHub API**: ~2 calls per `get_pr` + ≤16 repo-context probes + paged files
  (≤10 pages) + bounded comment list (1 page); no `X-RateLimit-*` awareness.
- **Storage**: unbounded `finding_history`; dashboard reads load all rows into
  Python (`list_findings`, `stats`, `metrics`).
- **Latency**: sequential batches; HTTP timeout 240s per provider call;
  retries up to 3 attempts; failover multiplies worst-case duration.

## 13. Assumptions that should remain stable

1. GitHub Action + Python engine + optional dashboard; pip-only, no build step.
2. Config layering CLI > `INPUT_*` > env > defaults; small YAML policy schema.
3. Deterministic core: diff parsing, fingerprinting, lifecycle, verification,
   static rules — **stay deterministic**; AI is used for judgment, not identity.
4. Model output is untrusted; lifecycle fields pipeline-owned.
5. Static fallback must always be honestly labelled "not AI".
6. Failure = degrade + warn, never lose a review; storage/GitHub/dashboard
   outages must not fail a run.
7. Privacy baseline exclusions non-removable; redaction everywhere.
8. `pull_request_target` forbidden; base-revision checkout; minimal permissions;
   no `checks: write` unless explicitly re-decided.
9. BYO provider keys; provider-neutral core; free/open-source default path with
   zero API keys (`--mock`) fully functional.
10. `ReviewStorage` Protocol as the storage seam; `AIProvider` Protocol as the
    provider seam (both to be *extended carefully*, not replaced).

## 14. Components: keep / evolve / replace

**Stable core — keep as foundation (do not rewrite):**
`diff_parser`, `findings` (fingerprint/lifecycle/mutes), `verification`
(deterministic model), `security`, `rules` (policy + baseline), `retry`,
`circuit` (semantics), `github_sync` (anchoring/id capture), `reporter`,
`static/` (rules + registry), `models` (Finding/PRContext/ReviewResult),
the config layering, the Action contract, the hermetic test suite.

**Platform foundations — grow deliberately:**
`model_router` (→ provider platform + task routing), `context` (→ context
intelligence engine), `storage.ReviewStorage` (→ data-access contract for all
future entities), `orchestrator` (→ review orchestrator with specialist fan-out),
`dashboard` (→ engineering command center + versioned API), `memory` (→ hierarchy
with authority model), `repo_context` (→ repository intelligence retrieval).

**Replace or retire when safe (low-risk, opportunistic):**
`analyzer.py` / `heuristics.py` facades (dead API, stale docs) — retire behind a
deprecation notice; duplicated `_extract_json`/prompt assembly — consolidate into
a shared prompt/parse layer; hand-rolled dashboard column migrations — move to a
real migration strategy when schema churn accelerates; JSON storage backend —
keep only as long as zero-dependency fallback matters.

**Explicitly not present (must be built, not "extended"):**
repository index/graph, evidence store, policy evaluation engine, event platform,
queue/worker model, versioned public API, plugin contract, multi-repo/org model,
cost accounting, evaluation harness.

---

### Cross-references
Vision & boundaries: `MASTER_VISION.md` · Target design: `TARGET_ARCHITECTURE.md`
· Defect-to-epic mapping: `EPIC_BACKLOG.md` (V3-E01..E06) · Decisions:
`ADR_INDEX.md` · Threat model: `SECURITY_ROADMAP.md` · Do-not-build list:
`DO_NOT_BUILD_YET.md` · Next steps: `MASTER_ROADMAP.md`
