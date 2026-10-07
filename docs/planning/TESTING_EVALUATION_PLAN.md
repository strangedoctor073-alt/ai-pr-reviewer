# TESTING & EVALUATION PLAN — Beyond Unit Tests

> Status: planning document (v1) — grounded in repository state described by
> `CURRENT_ARCHITECTURE.md` at commit `2841b23`. Every number labelled
> "proposed baseline" is a guess to be calibrated after V3-E02/V3-E03 land, not
> a target anyone committed to.

Related: `CURRENT_ARCHITECTURE.md` (§11 defects D1–D14, C1–C14) ·
`MASTER_VISION.md` (§3 principles, §6 boundaries) · `EPIC_BACKLOG.md`
(V3-E02 telemetry, V3-E03 evaluation harness) · `MASTER_ROADMAP.md` ·
`ADR_INDEX.md` (ADR-016 testing gate strategy).

---

## 1. Current baseline (verified)

### 1.1 What runs today

| Fact | Evidence |
|---|---|
| 464 tests passing, 1 warning (verified 2026-10-03) | `CURRENT_ARCHITECTURE.md` header |
| 22 files under `tests/` (21 `test_*.py` + `conftest.py`; ~414 `def test_` before parametrization) | `tests/` directory listing |
| Hermetic: no network, no API keys, no real GitHub | providers monkeypatched/faked (`tests/test_ai_provider.py` uses `FakeResponse`/`httpx` stubs), GitHub client mocked, FastAPI `TestClient` (`tests/test_dashboard_storage.py:55`, `tests/test_project_memory.py:288`) |
| Fixtures generated into pytest temp dirs via `demo/make_fixtures.build_all()` (shells out to `git` in temp dirs; never rewrites committed `demo/samples/*.diff`) | `tests/conftest.py:28-36` |
| CI = `python -m pytest tests/ -q` on py3.11/3.12/3.13 + `docker build` | `.github/workflows/ci.yml:21,31,37` |
| **No lint/type gate in CI**; ruff configured (E9/F63/F7/F82 only, "critical defects", explicitly "not installed locally and not part of CI") | `pyproject.toml:14-31`; defect D14 |
| No coverage measurement configured (no `pytest-cov`, no `addopts`) | `pyproject.toml:7-12` |
| Local invocation must be `python -m pytest` with `PYTHONUTF8=1` on Windows cp1252 | `AGENTS.md` |

### 1.2 Coverage by area (what the unit/integration suite already owns)

| Area | Test files (count) | What is covered |
|---|---|---|
| Orchestrator pipeline | `test_orchestrator.py` (43), `test_pipeline.py` (11) | stage ordering, thresholds, caps, lifecycle, degraded static runs, report finalize |
| Sync / incremental | `test_github_sync.py` (25), `test_github_incremental.py` (42) | comment posting, 422 recovery, comment-id harvesting, `compare_commits` incremental gate, force-push fallback |
| Verification | `test_verification.py` (15) | 3-state coverage model, `_unverify()` revert, counts |
| Security | `test_security.py` (8), `test_release_hardening.py` (16) | fencing, redaction, injection screening, non-removable privacy baseline, no retired model IDs, minimal-permission invariants |
| Failover / resilience | `test_provider_failover.py` (23), `test_multi_provider.py` (11), `test_ai_provider.py` (24) | retry classification, circuit breaker, provider order, static last-resort attribution, JSON parsing |
| Memory / mutes | `test_project_memory.py` (28) | human-authored memory rows, mute application, write-protection |
| Dashboard | `test_dashboard_storage.py` (18) | DbStorage + route-level `TestClient` (auth, rate limit, body caps, CRUD) |
| Static engine | `test_static_engine.py` (27) | deterministic rule packs, registry wiring |
| Identity/lifecycle | `test_findings.py` (15), `test_review_state.py` (28), `test_review_experience.py` (27) | fingerprints, dedup, state transitions, report experience |
| Context | `test_context.py` (9), `test_repo_context.py` (21) | budget trim, bounded fetch, warnings |
| Policy/config/storage misc | `test_rules.py` (14), `test_config.py` (2), `test_storage_client.py` (7) | policy parsing, config layering, HTTP storage client |

### 1.3 What is *not* covered today

- No recorded-contract tests against real GitHub/Anthropic/OpenAI/Gemini API
  shapes beyond hand-written fakes (fakes can drift from real schemas).
- No evaluation corpus (no notion of "expected findings" anywhere — defect-adjacent
  to C6: no telemetry to compare against either).
- No performance/load measurement (C6, §12: sequential batches, 240s timeouts,
  single-worker dashboard).
- No schema-migration tests (hand-rolled `ALTER TABLE` in `dashboard/storage.py`).
- No end-to-end run of the actual Action on a real repository.
- Coverage % unknown; no lint/type gate (D14).

---

## 2. The 17 layers — overview

Cadence vocabulary: **CI** = every PR/push (blocking) · **nightly** = scheduled,
non-blocking · **weekly** = scheduled, non-blocking, costlier models ·
**manual** = on demand / release rehearsal.

| # | Layer | Lands (stage) | Runs | Gates PRs? |
|---|---|---|---|---|
| 1 | Unit | exists (Phase 0) | CI | yes |
| 2 | Integration | exists (Phase 0), formalized | CI | yes |
| 3 | GitHub contract | Phase 0 (recorded) / V8 (live) | CI + nightly live | CI yes |
| 4 | Provider contract | Phase 0 (fake servers) / V5 (live) | CI + weekly live | CI yes |
| 5 | Security | exists (Phase 0), grows every stage | CI | yes |
| 6 | Prompt-injection | Phase 0 corpus → V6-E08 | CI (static) + nightly (AI) | CI yes (static part) |
| 7 | Regression corpus | V3-E03 | CI | yes |
| 8 | Known-bug corpus | V3-E03 | CI | yes |
| 9 | False-positive corpus | V3-E03 → V5-E08 | CI (static) + nightly (AI) | CI yes (static part) |
| 10 | False-negative corpus | V3-E03 → V6-E08 | CI (static) + weekly (AI) | CI yes (static part) |
| 11 | Model evaluation | V3-E03 | nightly/weekly, **never per-PR** | no (trend gate, §5.4) |
| 12 | Review-quality benchmark | V3-E03 + V5-E08 | weekly + manual | no (trend gate) |
| 13 | Performance | Phase 0 (smoke) → V5 (budgets) | CI smoke + nightly profile | smoke yes (proposed) |
| 14 | Load | V9 (C9 single-worker ceiling) | manual + pre-release | no |
| 15 | Failure-injection | Phase 0 (in-process) → V8 (network) | CI + nightly | CI yes |
| 16 | Migration | Phase 0 (schema-copy) → V9 (rehearsal) | CI + manual rehearsal | CI yes |
| 17 | End-to-end GitHub | V8 (real Action run) | nightly/manual on a fixture repo | no |

Cost rule (hard): **layers 11, 12, and the AI portions of 6/9/10 spend real
API tokens and must never run on every PR.** They run from a scheduled workflow
with a fixed token budget fed by V3-E02 telemetry.

---

## 3. The 17 layers — detail

### L1 · Unit
- **Purpose:** deterministic logic, fast feedback.
- **Exercises:** diff parsing, fingerprints (`ai_pr_reviewer/findings.py`),
  lifecycle, verification (`verification.py`), rules/policy, config layering,
  security helpers, retry/circuit math, static rules, reporter.
- **Lands / runs:** exists; CI on 3.11–3.13.
- **Hermetic:** in-process, no I/O; keep it that way (no test may open a socket).

### L2 · Integration
- **Purpose:** stage wiring — orchestrator composition root end-to-end.
- **Exercises:** `ReviewOrchestrator.run` with fake provider + fake GitHub +
  temp SQLite (`tests/test_pipeline.py` already builds fixtures via
  `demo/make_fixtures`).
- **Lands / runs:** exists; CI. Grow with every new pipeline stage (V5 fan-out,
  V6 security branch).
- **Hermetic:** fake provider objects, `tmp_path` storage, monkeypatched
  `github_client`.

### L3 · GitHub contract
- **Purpose:** GitHub REST payload shapes (`get_pr`, `compare_commits`,
  `get_file`, `post_review`, comment listing) drift silently; a schema change
  must break a test, not a production run.
- **Exercises:** `ai_pr_reviewer/github_client.py` + `github_sync.py` against
  **recorded HTTP fixtures** (JSON cassettes of real responses, sanitized).
- **Lands:** Phase 0 — cassette recorder + replay harness (likely module:
  `tests/contract/github_cassettes.py` or `eval/harness/`); live
  contract-smoke (one read-only API call against a public fixture repo) from V8.
- **Runs:** CI replays cassettes (free); nightly live smoke against a dedicated
  public test repository (rate-limit aware — C8 has no `X-RateLimit-*`
  handling yet).
- **Hermetic:** recorded fixtures; recordings must pass `redact_secrets()` and
  carry no real PR content (CONTRIBUTING.md:10).

### L4 · Provider contract
- **Purpose:** provider request/response schemas (Anthropic, OpenAI-compatible,
  Gemini) drift; `_extract_json` is triplicated and can diverge per provider
  (C2-adjacent).
- **Exercises:** `ai/claude.py`, `ai/openai.py`, `ai/gemini.py` against a
  **fake provider server** (in-process HTTP stub speaking each vendor's wire
  format, including usage fields, streaming edge cases, malformed JSON,
  429/5xx).
- **Lands:** Phase 0 (stub servers from today's hand-written `FakeResponse`
  set); live contract smoke (one cheapest-model call per provider) from V5
  alongside the capability registry.
- **Runs:** CI (stubs, free); weekly live smoke with a hard token budget.
- **Hermetic:** stubs are the source of truth for CI; live smoke exists only to
  detect stub-vs-reality drift and reports a trend, never blocks.

### L5 · Security
- **Purpose:** protect the invariants in `CURRENT_ARCHITECTURE.md` §6.
- **Exercises:** fencing, injection screening, redaction (14 patterns),
  `_safe_repo_path`, auth constant-time compare, caps (2 MB / 500), CSP,
  non-removable privacy baseline, no `pull_request_target`, no `checks: write`,
  no retired model IDs (already enforced by
  `tests/test_release_hardening.py::test_no_retired_model_ids_are_hardcoded_in_the_engine`).
- **Lands / runs:** exists; CI. **New invariant added at every stage that adds
  an untrusted input surface** (V4 index, V5 agents, V7 memory writes, V8 CI
  content, V9 webhooks, V10 plugins — `MASTER_VISION.md` §5-T).
- **Hermetic:** pure functions + TestClient.

### L6 · Prompt-injection
- **Purpose:** the model must not be steerable by PR content; today
  `scan_prompt_injection` is warnings-only/forensic.
- **Exercises:** seeded injection corpus (8 current pattern families + new
  ones) injected into diff bodies, PR titles, memory rows, repo-context files;
  assert (a) detection rate, (b) fencing holds, (c) model output in replay mode
  cannot set lifecycle fields.
- **Lands:** static/deterministic half in Phase 0; behavioral half (did the
  model *obey* an injection?) requires V3-E03 replay infrastructure; adversarial
  agent-level tests at V5-E08.
- **Runs:** CI (static); nightly for behavioral runs (AI tokens).
- **Hermetic:** replayed model responses + stubs; no live model needed for the
  deterministic assertions.

### L7 · Regression corpus
- **Purpose:** any bug fixed once never returns.
- **Exercises:** minimized `.diff` + config + expected outcome per historical
  defect. Seed with D1–D7 (e.g. D2 cap-induced false `resolved`
  (`orchestrator.py:183-189`), D3 below-threshold drop, D6 raw `ValueError`
  traceback, D7 duplicate mute rows).
- **Lands:** V3-E03. Every future bug-fix PR must add a case (enforced by
  convention in review; later by CI check that touched `ai_pr_reviewer/` files
  have a corpus delta — proposed, not automated initially).
- **Runs:** CI (deterministic expectations only).
- **Hermetic:** corpus cases run through the static engine or a fake provider
  returning canned model output.

### L8 · Known-bug corpus
- **Purpose:** distinct from L7 — cases encoding *classes* of known defects the
  architecture documents as open (D1 base_sha at head, D4 cap semantics, D5
  unsorted AI findings, D10 unserialized `risk`/`verification`). Each case
  asserts **current-behavior OR fixed-behavior** via an explicit
  `expect: xfail | pass` marker so fixing the defect flips one flag instead of
  hunting broken assertions.
- **Lands:** V3-E03 (D1–D7 are V3 tickets); markers removed as defects close.
- **Runs:** CI. `xfail` cases prevent false greens without hiding regressions.
- **Hermetic:** as L7.

### L9 · False-positive corpus
- **Purpose:** measure how often we annoy developers — the primary adoption
  killer for a reviewer.
- **Exercises:** synthetic PRs containing **known-benign patterns** (dead-code
  removal, generated code, test fixtures, intentional `# type: ignore`,
  deliberate `except: pass` in tests, feature flags) with
  `expected: no_findings` labels; scored against static + AI engines.
- **Lands:** V3-E03 (static first), V5-E08 (per-agent and council FP rate).
- **Runs:** CI static portion; nightly AI portion (tokens).
- **Hermetic:** corpus is synthetic (no real PRs — CONTRIBUTING.md:10); AI runs
  use recorded/canned responses for CI, live models only in scheduled runs.

### L10 · False-negative corpus
- **Purpose:** recall — seeded defects that *must* be reported.
- **Exercises:** synthetic code with planted issues (injection sinks, unbounded
  loops, obvious race, missing null check) each with
  `expected_findings: [{file, line_hint, category, severity_min}]`.
- **Lands:** V3-E03 (general), **V6-E08 security evaluation corpus** (security
  class: OWASP-style seeded vulnerabilities, detection recall is the headline
  metric).
- **Runs:** CI static; weekly for AI (tokens budgeted).
- **Hermetic:** as L9; seeded code is hand-authored/generated, no proprietary
  snippets.

### L11 · Model evaluation
- **Purpose:** compare models/modes/review depths on the same corpus before
  changing defaults (feeds V5-E04 adaptive depth, V5-E07 cost arbitration).
- **Exercises:** whole corpus run through a specific `(provider, model,
  review_mode, batch strategy)` tuple; outputs scored by deterministic matcher
  (L9/L10 labels) — judge models are *not* required for the core metrics.
- **Lands:** V3-E03 harness; model registry sweeps from V5 (capability
  registry).
- **Runs:** **nightly/weekly scheduled workflow with a fixed token budget;
  never on PRs.** Manual runs via `python -m eval.harness --layer model
  --model <id>`.
- **Hermetic:** corpus input is fixed; results recorded as trend artifacts keyed
  by model id (models are non-deterministic → run N≥3 reps for rate metrics;
  N and the "proposed baseline" for N are in §5.3).

### L12 · Review-quality benchmark
- **Purpose:** the holistic "is this review *good*" number: ordering, severity
  calibration, explanation quality, comment politeness, summary accuracy —
  things label matching alone can't score.
- **Exercises:** full-size synthetic PRs (50–300 files max, realistic docs);
  scored by (a) deterministic measures (severity ordering vs planted severity,
  cap behavior D5, comment correctness), (b) LLM-judge with a fixed rubric,
  (c) human spot-check sample (monthly, manual).
- **Lands:** V3-E03 (deterministic scores) + V5-E08 (multi-agent variants).
- **Runs:** weekly (judge tokens) + manual before model/default changes.
- **Hermetic:** input hermetic; judge runs are budgeted and their prompts are
  versioned in-repo. Judge disagreement with humans is itself tracked (judge
  calibration set).

### L13 · Performance
- **Purpose:** latency is a product feature (§12: sequential batches, 240s
  HTTP timeout, retries ×3, failover multiplies worst case).
- **Exercises:** wall-clock of pipeline stages on fixed synthetic PRs
  (small/medium/large), dashboard query latency with seeded row counts
  (1k/10k/100k — C9 says dashboard reads are O(all) rows).
- **Lands:** Phase 0 smoke (assert stage budgets on synthetic PRs, provider
  stubbed so only our code is measured); V5 adds per-batch/per-agent latency
  telemetry (V3-E02 fields).
- **Runs:** CI smoke (thresholds **proposed baseline**: e.g. pipeline (stubbed)
  p95 < 5 s on a medium synthetic PR; dashboard `/api/metrics` < 500 ms at 10k
  reports — calibrate on the first real CI numbers, expect to revise).
- **Hermetic:** stubbed providers; timing thresholds must be generous or flaky
  CI results will train people to ignore them.

### L14 · Load
- **Purpose:** find the single-worker ceilings *before* they bite: concurrent
  dashboard readers (per-IP limiter is per-process), storage growth (unbounded
  `finding_history`), engine one-review-per-process.
- **Exercises:** N concurrent API clients against a seeded dashboard; M
  sequential engine runs against one SQLite file; memory/fd growth (C9:
  connections opened per call, never closed).
- **Lands:** V9 (with `V9-E07` observability platform and storage evolution,
  ADR-011) — nothing to load-test meaningfully before then.
- **Runs:** manual + pre-release; not CI.
- **Hermetic:** local process only, no external services; seeds are synthetic.

### L15 · Failure-injection
- **Purpose:** "failure = degrade + warn, never lose a review" (§13.6) must be
  proven under every failure mode, not just the two currently tested.
- **Exercises:** extends `test_provider_failover.py` — inject 429 storms,
  mid-stream disconnects, malformed JSON, circuit open/half-open races; GitHub
  500/timeout on each endpoint (`get_pr`, `compare_commits`, `post_review`);
  storage disk-full / locked DB; dashboard unreachable (stateless degrade);
  later (V8): network-level fault proxy for batch worker paths.
- **Lands:** Phase 0 (in-process injection — most of it exists); network-level
  variants as V8 event paths land.
- **Runs:** CI (in-process); nightly for proxy-based variants.
- **Hermetic:** fake servers and monkeypatched transports; fault schedules are
  seeded and deterministic.

### L16 · Migration
- **Purpose:** `dashboard/storage.py` hand-rolled `ALTER TABLE` migrations +
  three duplicated schema implementations (§7) will break someone's data one
  day; JSON-storage fallback users need a downgrade story.
- **Exercises:** create DB at schema version N → run migration → assert
  constraints/indices/data preserved; engine `LocalReviewStorage` file from an
  older release; report JSON (`review-report.json`) accepted by newer dashboard
  (forward compat) and vice versa (documented limits).
- **Lands:** Phase 0 (golden schema files + migration test harness, cheap);
  full rehearsal-on-copy at V9 (ADR-011 storage evolution).
- **Runs:** CI for golden-file migrations; manual for rehearsal.
- **Hermetic:** temp SQLite files; golden copies committed (no real data —
  CONTRIBUTING.md:10).

### L17 · End-to-end GitHub
- **Purpose:** the one test that exercises the real thing: `action.yml`, base
  revision checkout, permissions, GitHub API for real, comment posting on a
  real PR.
- **Exercises:** push a synthetic branch to a dedicated public fixture repo →
  open PR → run the Action (`--mock`/static mode by default; AI mode weekly
  with a repo secret key) → assert review posted, inline comment anchored,
  state markers, incremental re-run on second push.
- **Lands:** V8 (CI/release intelligence stage owns Actions maturity); a
  manual `workflow_dispatch` smoke can exist earlier if someone feels brave —
  not a Phase 0 commitment.
- **Runs:** nightly on `--mock` (free) + weekly with a real provider key
  (budgeted); never blocks contributor PRs.
- **Hermetic:** not hermetic by nature — isolate it in a dedicated repo so a
  flake can never redden the main CI; never store real secrets in fixtures.

---

## 4. Metrics — precise definitions

Two systems feed all metrics: **V3-E02 telemetry** (per-run operational data:
tokens, latency, failures — see `COST_TOKEN_ARCHITECTURE.md` §3) and the
**V3-E03 evaluation harness** (corpus labels — §5). Metrics that need gold
labels only exist where a corpus case exists; metrics that need operational
data only exist after V3-E02. Do not report a metric from a run where its
inputs are missing — "no data" beats a fabricated number (vision §3.1).

| Metric | Numerator | Denominator | Source | Proposed baseline |
|---|---|---|---|---|
| **Precision** | corpus findings posted by the engine that match an `expected_findings` label (file + line within tolerance + category overlap) | all findings the engine posted on corpus cases | harness L9/L10/L11 | ≥ 0.70 on synthetic corpus — **proposed baseline, uncalibrated** |
| **Recall** | expected labels matched by a posted finding | all expected labels in corpus cases | harness L10/L11 | ≥ 0.75 general / ≥ 0.60 security (V6-E08) — **proposed baselines** |
| **False-positive rate** (project definition) | posted findings adjudicated wrong (corpus mismatch, or human "down" feedback, or muted as bogus) | findings actually posted | harness + dashboard feedback (`POST /api/findings/{fp}/feedback`) | ≤ 0.15 — **proposed baseline**. Note: classic FP/(FP+TN) is *undefined* for us — true negatives (correctly not-reported issues) cannot be enumerated; do not cite "FPR" without this definition |
| **Verification accuracy** | findings whose `verification_status` matches manual adjudication of the current diff | findings that went through `verify_findings` | harness replay + human sample | ≥ 0.95; **premature-resolved rate** (D2 class) ≤ 0.01 — **proposed baselines** |
| **Duplicate rate** | posted comments sharing a fingerprint, or (cross-engine) a normalized title+file pair already posted this run | comments posted | telemetry/report (`github_sync` counters) | ≤ 0.02 — **proposed baseline**; current cross-engine dedup gap is C4, expect worse pre-V4-E05 |
| **Comment correctness** | inline comments that (a) anchor to a real line, (b) survive redaction, (c) appear under the cap without error | comments attempted (422-recovery path counts attempts) | GitHub contract tests L3 + sync logs | 100% anchor/redaction (deterministic — hard gate); **proposed baseline** |
| **Latency** | wall-clock ms per phase (diff load, context build, provider call(s), verify, post) | per run; report p50/p95 across runs | V3-E02 telemetry (`duration_ms` already exists on `ReviewResult`, `models.py:248` — phase-level split is new) | stubbed pipeline p95 < 5 s medium PR — **proposed baseline** |
| **Token usage** | provider-reported input + output tokens | per review / per batch / per model | V3-E02 — today counted but dead: `ai/claude.py:328-329`, `ai/openai.py:158-159`; Gemini unparsed (`ai/gemini.py:159`) | no target until measured — **proposed baseline: set after first month of data** |
| **Provider failure rate** | `analyze()` attempts that exhausted retry (`retry.py` gives up) | total `analyze()` attempts | V3-E02 (attempt-level counters) | ≤ 0.05 raw; **final** (post-retry) failure ≤ 0.01 — **proposed baselines** |
| **Fallback rate** | runs ending `engine == "static"` with `fallback_used=True` (truthful static attribution, `reporter.py:145-146`) | total runs | report JSON → storage → `/api/metrics` | ≤ 0.05 — **proposed baseline** |

Supporting counters (needed to make the above explainable, not headline
metrics): batches per review, below-threshold drops (D3 currently hides these —
V3 fix must surface them before they can be measured), cap evictions (D4),
context-budget omissions, circuit-open events, muted-finding rate.

---

## 5. Evaluation harness design (V3-E03)

### 5.1 Corpus format

One directory per case; machine-readable expectation file + input diff:

```
eval/
  corpus/
    <layer>/                      # regression | known-bug | false-positive |
                                  # false-negative | injection | quality
      <case-id>/
        case.yaml                 # metadata + expectations
        pr.diff                   # the synthetic PR diff
        files/                    # optional repo snapshot (trusted side)
  harness/                        # likely module: runner + scorers
  results/                        # git-ignored trend artifacts (local/CI)
```

`case.yaml` (schema sketch):

```yaml
id: FN-SEC-014                       # stable, layer-prefixed
layer: false-negative
title: "SSRF via user-controlled URL in webhook dispatch"
provenance: hand-authored            # synthetic only — no real PRs
diff: pr.diff
context:                             # optional trusted inputs
  files: [files/webhook.py]
expect:
  findings:
    - file: src/webhook.py
      line_hint: 42                  # tolerance ±N lines, configurable
      tolerance: 5
      category: security
      severity_min: high
      title_match: "server.side request"   # regex, case-insensitive
  no_findings: []                    # FP corpus: explicit benign list
  must_not_report:                   # FN/FP: trap expectations
    - {file: tests/test_webhook.py, reason: "test fixture, privacy baseline"}
engine_matrix: [static, claude]      # which engines the case applies to
xfail: false                         # known-bug corpus: open defect marker
notes: "encodes D2-class cap interaction"
```

Storage constraint: **synthetic or hand-authored content only** — no secrets,
no real PR diffs, no dashboard data (`CONTRIBUTING.md:10`). Where a case is
derived from a real incident, reduce it to a minimal hand-written pattern.

### 5.2 Scoring — likely modules

| Likely module | Responsibility |
|---|---|
| `eval/harness/runner.py` | load cases → build `ReviewContext` → run engine (static or AI via fake/live provider) → collect findings |
| `eval/harness/match.py` | label matching: file + line tolerance + category + title regex; one-to-one matching (greedy by distance) to prevent double-counting |
| `eval/harness/score.py` | per-layer metric computation (§4 definitions) → JSON result with `engine_matrix`, model id, corpus hash |
| `eval/harness/report.py` | trend table (metric × model × date), regression detection vs rolling baseline |
| CLI | `python -m eval.harness --layer <l> [--engine static|claude|…] [--live] [--budget-tokens N]` |

Not shipped in the Action image: `eval/` stays out of
`requirements-action.txt` consumers' path (dependency-free runner preferred;
live mode may import httpx which the Action already has).

### 5.3 Determinism rules

- Static-engine and canned-response runs must be **byte-identical** across
  runs → these gate CI.
- Live-model runs are stochastic: evaluate over **N repetitions** (N = 3 —
  **proposed baseline**) and score rates, not single outcomes; record model id
  + prompt version with every result.
- Prompt text used in canned mode is versioned in-repo; changing it is a
  corpus-visible event (regression L7 expectations may legitimately shift —
  require the PR to update the affected expectations explicitly).

### 5.4 Gate strategy (summary; detail in ADR-016)

```
PR pipeline (blocking)              Scheduled pipelines (non-blocking trends)
─────────────────────────           ─────────────────────────────────────────
L1 unit                             L11 model evaluation      (nightly/weekly)
L2 integration                      L12 quality benchmark     (weekly)
L3 GitHub contract (cassettes)      L6/L9/L10 AI portions     (nightly/weekly)
L4 provider contract (stubs)        L3/L4 live contract smokes
L5 security                         L15 network fault proxy   (nightly)
L6/L9/L10 static portions           L17 e2e on fixture repo   (nightly --mock,
L7 regression corpus                                           weekly AI)
L8 known-bug corpus
L13 perf smoke (proposed thresholds)
L15 failure-injection (in-process)
L16 migration (golden files)
```

Trend gate (AI layers): scheduled results update a rolling baseline; a drop
beyond the **proposed baseline** threshold — precision/recall regression
**> 10 percentage points** vs 7-day rolling median on the same model — posts an
issue/label for human triage. It **never blocks an individual contributor PR**
unless the regression originates from a PR (attribution via corpus-delta check)
and the owning human confirms. Rationale: model-vendor drift must not make this
repo's CI red for reasons unrelated to the change under review.

### 5.5 As implemented (V3-E03) — the authoritative metric definitions

The harness exists: `eval/harness/` (loader → runner → match → score →
gate/report), corpus in `eval/corpus/<layer>/<case-id>/`, one command
`python -m eval.harness`, CI job `evaluation` (Tier A, deterministic,
no network/API keys), `--json PATH` for a byte-stable machine-readable
report (score, case count, corpus hash, git identity), contributor guide
in `CONTRIBUTING.md`. The executable definitions below are normative;
the §4 table is their design intent.

- **Matching** (`eval/harness/match.py`): label ↔ finding matches iff file
  (slash-normalized) + line within `tolerance` (no `line_hint` = any line;
  a line-less finding never satisfies a line-scoped label) + category
  (optional) + `severity_min` as a floor + case-insensitive `title_match`
  regex search. Assignment is one-to-one greedy by (line distance, label
  order, finding order) — a duplicated finding cannot inflate recall.
- **precision** = matched posted-bucket labels ÷ posted findings
  (micro-averaged). **Null when nothing was posted.**
- **recall** = satisfied labels ÷ all expected labels, where a label is
  satisfied *in the bucket it declares* (`reported` against posted
  findings, `below_threshold` against the retained D3 bucket). **Null when
  no labels.**
- **false_positive_rate** = unmatched posted findings ÷ posted findings —
  the project FP definition from §4 (the classic specificity-based FPR is
  undefined without a true-negative population and is never reported).
  **Null when nothing was posted.**
- **recall_critical_high** = satisfied ÷ all labels declaring
  `severity_min` high/critical — the blocking guard (§5.4 Tier A).
  **Null when no such label.**
- Errored/skipped runs and `xfail` known-bug cases contribute nothing to
  the ratios (visible in `counts` instead); every ratio ships with its
  counts so no number floats without a denominator.

---

## 6. Extending the harness

### 6.1 Multi-agent (V5, V5-E08)
- **Per-agent corpora:** each specialist (security, correctness, style, perf…)
  gets its own recall expectation — a security agent scored against the style
  corpus is meaningless. `case.yaml.engine_matrix` becomes `agent_matrix`.
- **Council scoring:** new metrics — *attribution accuracy* (finding credited to
  the right agent; requires provenance fields, V4-E04/E05 / defect C3),
  *merge precision* (dedup correctness across agents — C4 fingerprints are
  title-based and documented to not dedup across engines), *fan-out cost*
  (tokens per agent vs quality delta → feeds V5-E07 arbitration).
- **Budget-ablation runs:** same corpus under depth/budget variants to prove
  V5-E04 adaptive depth loses nothing measurable on low-risk PRs
  (**proposed baseline**: quality delta ≤ 3 pp — uncalibrated).
- **Concurrency safety:** failure-injection L15 gains parallel-agent fault
  schedules (C5: breakers are process-global and sequential-assumption — tests
  must expose that before V5 ships).

### 6.2 Security engine (V6-E08)
- **Security evaluation corpus:** hand-authored seeded vulnerabilities across
  the agreed classes (injection, path traversal, SSRF, authz bypass, secrets,
  unsafe deserialization, race, crypto misuse), each with `severity_min` and
  `must_not_report` neighbors (benign twins — e.g. a string that *looks* like a
  secret but is a test placeholder) to score precision, not just recall.
- **Headline metrics:** security recall (§4 proposed baseline ≥ 0.60),
  security FP rate on benign twins, redaction leak rate (**hard gate: 0**).
- **Every new untrusted surface adds injection cases** (V4 index rows, V5
  agent-to-agent messages, V7 ingested history, V8 CI logs, V9 webhook payloads,
  V10 plugin output) — the corpus is the security regression contract.
- **Adversarial model runs** (weekly, budgeted): live models seeded with
  maximally hostile diffs; scored on lifecycle-field integrity (pipeline-owned
  fields must never move — `Finding.from_untrusted_dict`) and fence survival.

### 6.3 Memory poisoning & memory security (V7-E07)
- **Poisoning corpus:** memory notes containing injection patterns, secrets, and
  authority-escalation attempts (e.g. a note claiming `authority=human` for an
  AI-observed pattern). Scored on: injection screening catches the pattern,
  redaction removes the secret, authority model rejects the escalation.
- **Authority matrix test:** every (category, authority) pair is asserted —
  human-authored rules are applied; AI-observed patterns are never auto-promoted;
  mute rows are write-protected.
- **Isolation test:** memory entries from repo A must not leak into repo B's
  context (path-scoped and global patterns both tested).
- **Invariant test:** the engine has no `add_repo_memory` path — a code-level
  assertion (grep or import check) that no engine module writes to memory.

### 6.4 Change impact analysis (V4-E03)
- **Impact corpus:** fixture PRs with known import/reference graphs; each fixture
  has an expected impact set (files, symbols, APIs). Scored on: impact recall
  (did we find all affected files?) and impact precision (did we avoid false
  positives?).
- **Determinism test:** same repo state → same impact set (byte-stable).
- **Budget-exhaustion test:** a repo with a pathological import graph (deep
  chains, circular refs) must terminate within budget caps (V4-E08).

### 6.5 Finding relations (V7-E03)
- **Relations corpus:** fixture finding sets with known relations (duplicate,
  caused_by, fixed_by, regression_of). Scored on: relation precision/recall.
- **Identity continuity test:** a finding that moves files or changes line
  numbers must retain its identity (v1 fingerprint unchanged) and its relations
  must follow.
- **Regression detection test:** a previously-resolved finding that reappears
  must be classified as `regression_of` the original, not as a new finding.

### 6.6 Team/repository analytics (V7-E05)
- **No-individual-rankings invariant:** a code-level test that no analytics
  query groups by author or produces per-author scores. This is a **hard gate**
  — the invariant is architectural, not aspirational.
- **Aggregation correctness test:** known fixture data → known aggregate counts
  (hotspots, churn, finding resolution rates). Scored on exact match.
- **Privacy test:** analytics output must not contain individual author names
  or identifiers (only aggregate counts and trends).

### 6.7 Provider failover for capability registry (V5-E05)
- **Routing fail-closed test:** if the registry cannot select a provider for a
  task (no capability match, all breakers open), the router falls back to static
  with honest attribution — never to an error.
- **Per-task breaker test:** a security-review failure must not block a general
  review (per-task breakers are independent).
- **Capability negotiation test:** a provider advertising a capability it does
  not support must be detected (contract test against the capability manifest).
- **Cost-aware routing test:** given two capable providers, the router selects
  the cheaper one unless latency/ reliability overrides (scored on selection
  correctness against the cost model).

---

## 7. Sequencing (what lands when)

```
Phase 0 (V3.x)   L7/L8/L9/L10 static scaffolding + L16 golden schemas + L15 in-process
                 (mostly exists) ──► V3-E03 harness core ──► V3-E02 telemetry fields
V4               corpus grows with repository-intelligence features; L3 cassettes
V5               L11/L12 AI evaluation cadence starts; V5-E08; V5-E07 cost scoring;
                 L13 per-agent latency budgets
V6               V6-E08 security corpus + adversarial runs; injection corpus expansion
V7               memory-write evaluation (authority tests, ADR-003) as corpus layer
V8               L17 e2e on fixture repo; L3/L4 live smokes promoted; L15 network faults
V9               L14 load; L16 rehearsal; V9-E07 dashboards the metric trends
V10              plugin conformance tests (ADR-009) become an 18th layer
```

No layer may ship without: a hermetic CI path (even if the interesting part is
scheduled), explicit cost accounting for its non-hermetic part (V3-E02), and a
documented owner for its thresholds.

---

## 8. V4 metrics (approved — C0-T04, 2026-10-07)

Frozen for V4. This section **extends** §4, does not replace it. Every V4
feature maps to ≥ 1 metric here; a feature whose metric cannot be named does
not start.

| # | Metric | Definition (V4 delta vs §4) | Source | Gate |
|---|---|---|---|---|
| 1 | Precision | §4 unchanged | harness | **≥ 0.90 at V4 release** |
| 2 | Recall | §4; **re-baseline when the corpus grows 8 → ≥ 16** — 1.000 is an 8-case number; record the new baseline explicitly instead of silently requiring it forever | harness | no material regression vs the recorded new baseline |
| 3 | False-positive rate | §4 project definition (classic FP/TN stays undefined) | harness + dashboard feedback | reported + trended |
| 4 | Severity accuracy | predicted severity == labeled severity ÷ findings with severity labels | new corpus labels | reported only — **never auto-regrades severity** (debt 14) |
| 5 | **relevance@10** | relevant files inside the selection contract's top 10 ÷ labeled relevant files (`case.context.files` finally read) | harness (`V4-E02-T04`/`V4-E11-T01`) | **≥ 0.70** |
| 6 | Verification accuracy | §4 plus explicit **misverify** (wrongly confirmed) and **missverify** (missed) counters | harness replay | **0 known misverification** |
| 7 | Fix usefulness | posted findings carrying an applicable `suggestion` ÷ cases labeled fix-expected | harness labels | reported |
| 8 | Latency p50/p95 | index build, per-provider call, end-to-end duration | telemetry (`V4-E11-T06`) | budgets reported; index p95 < 2 s on fixture repos |
| 9 | Index build time/size | wall-clock + bytes per build; budget-exhaustion counts | telemetry | budgets enforced — exhaustion is a loud state, never a crash |
| 10 | Cost estimate | price table × usage → estimated cost band per review (**display only**, debt 9) | `V4-E11-T07` | present in every report; no cost-based routing |
| 11 | Feedback effectiveness | repeat-FP rate of adjudicated findings before vs after suppression rules (`feedback.enabled=false` ⇒ no data, stated as such) | dashboard feedback + report | reported at release; no automatic success claim |

Also frozen at C0: Tier-B provider precision floor **≥ 0.80** at release —
reporting-only until a provider environment is available; never a hard CI
dependency for offline contributors. Coverage **≥ 70%** is a quality signal,
not a substitute for behavioral tests (ADR-016 still governs).

Feature → metric mapping of record lives in the V4 ticket manifest
(`EPIC_BACKLOG.md`, V4 scope record).

---

### Cross-references
Cost of running all this: `COST_TOKEN_ARCHITECTURE.md` (§6 stage budgets) ·
Decisions: `ADR_INDEX.md` (ADR-016 gate strategy, ADR-014 telemetry) ·
Epics: `EPIC_BACKLOG.md` (V3-E02, V3-E03, V5-E07, V5-E08, V6-E08, V9-E07) ·
What we refuse to build first: `DO_NOT_BUILD_YET.md` · Order: `MASTER_ROADMAP.md`
