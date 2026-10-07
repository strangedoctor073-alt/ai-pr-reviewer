# V4–V10 ROADMAP — Stage-by-Stage Architecture Plan

> Status: planning document (v1) — describes Phase 0 ("V3.x") through V10 against
> the verified repository state in `CURRENT_ARCHITECTURE.md` at commit `2841b23`.
> Scope: *how and in what order* each generation is built. What/why: `MASTER_VISION.md`.
> Executive summary & build-next: `MASTER_ROADMAP.md`. Epic detail: `EPIC_BACKLOG.md`.
> Every numeric target below is a **proposed baseline** unless marked as verified.

---

## 0. Generation boundary rationale — deviations from the naive V4–V10 hypothesis

The brief's starting stage structure is largely correct. Where this document
deviates or hardens a boundary, it says so explicitly.

| # | Question | Verdict | Justification |
|---|---|---|---|
| 1 | Must evidence/provenance (V4-E04, V4-E05) land **before** multi-agent V5? | **Yes — hard gate, not a preference.** Structure confirmed. | C3: `Finding` has no engine/model/agent/origin fields; C4: title-based 16-hex fingerprints. A V5 merger without provenance produces findings that *cannot later be attributed* — attribution is lost data, not backfillable data (you cannot re-derive which agent said what after dedup collapsed it). Comment identity also cannot be retrofitted onto already-posted GitHub comments (state markers in `github_sync.py` key off fingerprints). Naive hypothesis "build multi-agent first, provenance later" is rejected. |
| 2 | Must telemetry (V3-E02) precede risk/cost control? | **Yes.** | C6: token/usage counted on Claude/OpenAI instances but never surfaced; Gemini usage not parsed. V5-E04 (risk engine) and V5-E07 (cost arbitration) consume token/latency distributions. Without V3-E02 their thresholds are invented numbers; with it they are fitted to observed data. Confirmed as stated. |
| 3 | Must the evaluation harness (V3-E03) precede multi-agent? | **Yes.** | N specialist calls multiply every existing defect (D2 false-`resolved`, D5 unsorted severity) and shift output distribution. Without a golden-set harness you cannot tell whether a council improved or degraded review quality — you only see that it cost more. Confirmed. |
| 4 | Should the event platform (V8-E07) precede queue/worker separation (V9-E04)? | **Yes — but with a carve-out.** | Full queue separation is correctly deferred to V9 (workers justify queues, not vice versa). **Deviation:** C5 (process-global breakers, sequential-only) is a *concurrency-safety* problem that V5 fan-out hits in-process, years before any queue exists. V5-E01 must therefore include an in-process slice of C5 — per-call breaker state or a lock — but must **not** build queues, workers, or a message bus. Queues remain V9-E04. |
| 5 | Should the triplicated storage schema (C9) be consolidated in Phase 0? | **No rewrite in Phase 0; ADR gate before V7.** | Phase 0 fixes D7 (dashboard mute idempotency) and connection lifecycle but must not touch the `ReviewStorage` protocol shape beyond bug fixes — the stable core is keep-list. However V4-E01 (index storage), V7-E02 (memory hierarchy) and V9-E01 (org model) all add tables; three duplicated implementations cannot absorb that thrice. **Deviation:** a single data-access/schema consolidation decision (ADR) becomes a *hard prerequisite of V7*, drafted during V4-E01, implemented incrementally — never as a big-bang rewrite. |
| 6 | Should the policy engine be one system from V6? | **No — repo/team scope in V6, org scope in V9 (staged).** | Inheritance/authority (ADR-003) requires the multi-repo model (V9-E01) to exist; a single-shot policy engine in V6 would guess at org semantics. Confirmed as staged. |
| 7 | Does the digital twin need its own subsystem? | **No.** | V4-E06 is a *seed projection* over the index (layered view), never a separate CQRS/graph system. Confirmed per `MASTER_VISION.md` capability D and ADR-002. |
| 8 | Security upgrades: one security stage (V6)? | **V6 is the engine, but screening upgrades are continuous.** | Per `MASTER_VISION.md` capability T, every stage that adds an untrusted input (V4 index, V5 agents, V7 memory, V8 CI logs, V9 webhooks, V10 plugins) must upgrade injection screening/redaction *in that stage*. V6-E01/E02 do not absorb later stages' security work. Each stage below lists its own "Security implications". |

**Net result:** the stage order V4→V10 stands. Three refinements are adopted:
(a) C5 gets an in-process concurrency fix inside V5-E01, queues stay V9-E04;
(b) storage schema consolidation is an ADR-gated soft dependency of V7, not a
Phase 0 rewrite; (c) security is continuous-per-stage with V6 as the deep engine
stage. No epic was moved between stages.

---

## Phase 0 — "V3.x": Validation & hardening

### Objective
Make the verified V3 system *correct and measurable* before any intelligence or
multi-agent work: close defects D1–D7, establish telemetry (token/cost/latency),
stand up the evaluation harness, retire storage/dashboard debt, harden config
parsing, and clean docs/release hygiene. Zero new features; the Action contract
and report schema only gain fields, never lose or repurpose any.

### User value
- Reviews stop lying: repository context is fetched at the PR **base** revision
  (D1) so a PR cannot shape the "trusted" repo context it is reviewed against;
  still-present findings are no longer marked `resolved` because of the 20-comment
  cap (D2); below-threshold and capped findings are honestly counted (D3/D4);
  critical findings are no longer displaced by mild ones (D5).
- Maintainers see *why a run cost what it cost*: tokens, model, latency, and
  fallback events land in `review-report.json` and the dashboard.
- `INPUT_*` misconfiguration fails with a clean exit-1 config error instead of a
  traceback (D6); muting a finding in the dashboard is idempotent (D7).

### Major capabilities
- Correctness defect triage for D1–D5 (V3-E01)
- Telemetry foundation: token/cost/latency/fallback counters end-to-end (V3-E02)
- Evaluation harness foundation: golden PR fixtures + scored runs in CI (V3-E03)
- Storage & dashboard debt: D7, connection lifecycle, retention/pruning hooks,
  report-field gaps (D10) (V3-E04)
- Config & contract hardening: numeric parsing (D6), `action.yml` input/output
  contract tests, exit-code guarantees (V3-E05)
- Documentation & release hygiene: D11 legacy facade deprecation notice, D12
  duplicate security-baseline dedup, D14 lint/type gate in CI, README/doc drift
  (V3-E06)

### Architecture changes
- `ai_pr_reviewer/github_client.py` (`get_pr`, `get_event_context`) populates
  `PRContext.base_sha` (field already exists, `models.py:225`); `repo_context.py:238`
  fallback to `head_sha` becomes dead path, guarded by a test asserting the
  documented invariant `repo_context.py:26-27`.
- `orchestrator.py` separates *report population* from *inline-comment capping*:
  verification receives the **uncapped** current-finding set (fix D2 at
  `orchestrator.py:183-189`), caps apply only at comment/posting time (fix D4),
  below-threshold findings are counted and reported (fix D3), AI output is
  severity-sorted before any top-N cut (fix D5). `reporter.py:316-318` suppressed
  accounting updated to match.
- `config.py:113,119,129` numeric parsing routed through a raising helper →
  `ConfigError` → exit 1 (fix D6); same helper used for all `INPUT_*` numbers.
- `dashboard/storage.py:337` `record_feedback` looks up mute row by primary key
  (fix D7).
- New subsystem (likely module): `ai_pr_reviewer/telemetry.py` — usage records
  attached to `AnalysisOutcome` (`models.py:292`), serialized by `reporter.py`,
  persisted by `storage.py`/`dashboard/storage.py` as additive report fields;
  Gemini usage parsing closes the code TODO.
- New subsystem (likely module): evaluation harness under `evals/` (runner +
  fixture corpus + scorer), invoked by CI as a separate job; scores gate V4+.
- `storage.py` / `dashboard/storage.py`: close connections deterministically,
  add retention/pruning entry points (no schema migration beyond additive
  columns); `ReviewStorage` protocol gains *declared* optional capabilities,
  replacing the `getattr` guards (constraint C9 partial fix, backward compatible).

### Prerequisites & dependencies
- Hard: none (this *is* the prerequisite for everything). Verified suite green
  (464 passed, `CURRENT_ARCHITECTURE.md`).
- Soft: none. D12 dedup and D14 lint gate may trail the rest by days.

### Risks
- **Behavior-visible fixes**: D3/D4 change report counts, health score inputs,
  and `fail_on` thresholds for existing users — a run that previously passed may
  now fail (correctly). Mitigation: document deltas in `MIGRATION_PLAN.md`,
  bump minor version, keep field names.
- D1 fix changes *which files* are fetched into repo context → context content
  shifts; eval harness must run before/after to detect quality movement.
- Telemetry must not become a second reporting path (single schema, one writer).
- Harness fixtures drift from real PR shapes → harness proves nothing. Budget
  periodic fixture refresh (proposed baseline: ≥ 20 golden PRs, refreshed each stage).

### Security implications
- No new untrusted inputs. D1 fix *restores* the base-revision trust boundary
  (`repo_context` content is untrusted-but-fenced either way; the fix removes a
  documented-invariant violation exploitable by PR authors).
- Telemetry inherits the existing invariant: everything persisted/posted passes
  through `redact_secrets()` (`security.py`); token/cost counts are numeric,
  prompts/bodies are never stored.
- Regression tests must re-assert existing invariants (no `pull_request_target`,
  non-removable exclusion baseline, minimal permissions) so Phase 0 churn cannot
  silently relax them — already covered by `test_release_hardening.py`, keep green.

### Testing requirements
- One regression test per defect: end-to-end `base_sha` population (not
  hand-constructed `PRContext`); cap-independent verification; suppressed/dropped
  counts in report JSON; uncapped health-score input set; severity ordering of AI
  findings; `INPUT_MAX_COMMENTS=abc` → exit 1; double mute → one row.
- Telemetry: report JSON contains token/latency/cost fields for every provider
  path (mock, Claude, OpenAI, Gemini, static-without-usage).
- Harness: CI job runs `evals/` over the golden corpus, publishes a score
  delta; deterministic static engine must score identically run-to-run.
- Full suite remains the CI gate: `python -m pytest tests/ -q` (never bare
  `pytest`), `PYTHONUTF8=1` on Windows checkouts.

### Migration requirements
- Action inputs/outputs: **no changes** (V3-E05 only adds contract tests).
- Report JSON: additive fields only (`usage`, refined `suppressed`/`dropped`
  semantics — D3/D4 fix changes *values*, not names). Downstream consumers of
  `findings_count`, `health_score` may see different numbers; this is a
  correctness fix, documented as a behavior change in `MIGRATION_PLAN.md`.
- Storage: additive columns only; existing SQLite files open without migration
  steps; dashboard `ALTER TABLE` pattern continues until the V7-gated ADR.
- GitHub comments: no identity/fingerprint changes; existing state markers keep
  matching.

### Performance implications
- Telemetry adds O(1) per provider call; serialization overhead negligible.
- Uncapped verification set: findings lists are already bounded by validation
  caps in memory (max ~hundreds); no measurable latency change (proposed
  baseline: < 1% wall-clock overhead per run).
- Harness runtime added to CI (proposed baseline: < 5 min on the golden corpus).

### Token/cost implications
- No prompt/context changes → token consumption unchanged.
- First *visibility*: per-run token and estimated-cost figures appear in report
  and dashboard. This is the measurement baseline all later cost work
  (V5-E07 arbitration, `COST_TOKEN_ARCHITECTURE.md`) consumes.

### What MUST NOT be built yet in this stage
- No new review modes, providers, rule packs, or Action inputs.
- No repository index, retrieval, provenance fields, or fingerprint changes.
- No multi-agent/fan-out code, no concurrency beyond current sequential model.
- No storage rewrite/schema redesign, no queues/events, no API versioning.
- No dependency upgrades "while we're here"; no dead-code deletion beyond
  deprecation notices (D11).

### Exit criteria
1. Each of D1–D7 has a failing-then-passing regression test; `grep` for the D1
   pattern (`getattr(pr, "base_sha"...) or head_sha` fallback path in
   `repo_context.py:238`) shows the fallback unreachable from production paths.
2. Report JSON schema documents `usage` (tokens, est. cost, latency, model) and
   validated `suppressed`/`dropped` counts; a test asserts they are populated in
   mock and AI runs.
3. `INPUT_*` numeric garbage → exit code 1 with config-error message; zero
   tracebacks in config tests.
4. Dashboard double-mute idempotency test passes; no engine-storage connection
   leaks under a 1000-call loop test.
5. `evals/` runs in CI and reports a score for the golden corpus; score is
   reproducible (same seed/corpus → identical score).
6. `python -m pytest tests/ -q` green on CI matrix + docker build; lint/type
   gate (D14) added and green; no retired model IDs (existing scan keeps passing).
7. README/`action.yml`/`example-workflow.yml` match observed behavior (D11/D12
   hygiene items resolved or explicitly ticketed in V3-E06 with dates).

---

## V4 — Deep repository intelligence

> **Status note (2026-10-07, V4-C0-T01):** this section's V4 sketch is
> superseded on these material points by the approved V4 plan — the index is
> **ephemeral per-run** (no `repo_index` SQLite tables, no cross-run
> hash-sealed cache in V4); evidence ships **embedded on findings** (no
> `evidence`/`finding_provenance` tables in V4); **V4-E06 (twin) and V4-E07
> (read contracts) are deferred** (IDs reserved); the context-quality gate is
> **relevance@10 ≥ 0.70** on the expanded corpus (the 0.8 figure in the exit
> criteria re-baselines when the corpus grows from 8 to ≥ 16 cases). Epic
> order, security-per-stage, and the must-not-build list stand. Authority:
> `EPIC_BACKLOG.md` V4 scope record + `ADR_INDEX.md` (ADR-004/005/017/022,
> ratified 2026-10-07) + `V4_THREAT_MODEL.md`.

### Objective
Give the engine a deterministic, queryable understanding of the repository: a
base-revision repo index, a context engine that retrieves/ranks/budgets with
provenance, change-impact analysis, an evidence store, versioned finding
identity, the seed digital-twin projection, read APIs over all of it, and the
security/budget envelope that keeps untrusted repository content fenced. Still
one review pass — intelligence feeds the single provider, it does not yet
multiply it.

### User value
- Reviews cite *why* something matters: "this changes `payments/refunds.py`,
  which is called by `checkout/settle.py` (impact), last incident-touched
  3 commits ago (history seed), here is the exact symbol and lines (evidence)".
- Context stops being a fixed 8-file/12k-char guess (`repo_context.py`): the
  right files are retrieved within a real token budget, each chunk labelled with
  where it came from and why it was included.
- Findings keep stable identity across wording/engine changes → far fewer
  duplicate GitHub comments on re-review; silent identity breaks stop resetting
  mute/lifecycle state.

### Major capabilities
- Deterministic repository index: symbols, call/import edges, file roles,
  layered by code/test/config/docs (V4-E01)
- Context engine v2: retrieval, ranking, unified token budgets, per-chunk
  provenance (V4-E02)
- Change impact analysis: reverse-dependency closure over the index, bounded
  (V4-E03)
- Evidence engine: immutable evidence records (code excerpt, rule hit, API
  shape) with locators + hashes (V4-E04)
- Finding identity v2: origin/agent/model provenance fields + stronger
  fingerprint with deterministic migration from v1 (V4-E05)
- Digital twin seed: layered projection over the index (read model, no new
  system) (V4-E06)
- Intelligence read contracts: query API used by engine + dashboard
  (V4-E07)
- Intelligence security & budgets: fence/index-poisoning defenses, retrieval
  injection screening, hard budget caps (V4-E08)

### Architecture changes
- New subsystem (likely module): `ai_pr_reviewer/index/` — walker (via
  `github_client.get_file`/git tree at `base_sha` — *starting point*:
  `repo_context.py` bounded fetch), builder, schema (SQLite tables through
  `storage.py`), invalidation on `last_reviewed_sha` advance. Deterministic:
  same tree + same version → byte-identical index (hash-sealed).
- `context.py` evolves from bag-of-bounded-fetches to context engine v2:
  retrieval calls into the index, ranking is pure code, `_apply_context_budget`
  becomes token-aware (constraint C7 fix) and records provenance per chunk.
- `findings.py` + `models.py`: `Finding` gains pipeline-owned provenance fields
  (engine, model, agent id, origin, evidence refs) added to `LIFECYCLE_FIELDS`
  so model output still cannot own them; `fingerprint_finding` gains a v2
  algorithm (file + symbol anchor + normalized category, line still excluded)
  with dual-compute of v1 during migration.
- New subsystem (likely module): `ai_pr_reviewer/evidence.py` — append-only
  evidence records referenced by findings; redacted at write.
- `reporter.py` / `dashboard/app.py`: additive report fields + read-only
  intelligence endpoints (no versioning yet — that is V9-E03).
- `storage.py` and `dashboard/storage.py`: additive tables
  (`repo_index`, `evidence`, `finding_provenance`) following the V7-gated
  consolidation ADR drafted in this stage (see §0 #5).

### Prerequisites & dependencies
- Hard: Phase 0 complete — specifically V3-E01 (D1: index/context must be built
  at `base_sha`, D2/D3/D4/D5: eval baseline must be trustworthy), V3-E02
  (telemetry drives budgets), V3-E03 (harness detects retrieval quality
  regressions), V3-E04 (storage seams for new tables).
- Hard: V4 internal order — V4-E01 → (V4-E02, V4-E03) → V4-E04 → V4-E05 →
  V4-E06 → V4-E07; V4-E08 runs continuous from V4-E01 (security with the
  surface, not after it).
- Soft: V3-E05/E06 may finish in parallel.

### Risks
- **Index staleness** on force-push/large PRs → wrong impact claims. Mitigation:
  hash-sealed index + rebuild-on-mismatch, impact degrades to "unknown".
- **Fingerprint migration breaks identity** → duplicate comments, resurrected
  mutes. Mitigation: dual-compute v1+v2, `finding_history` mapping table,
  state-marker migration in `github_sync.py`, staged rollout flag.
- Retrieval quality regressions invisible without the harness → V4-E02 changes
  must be harness-gated.
- Index build cost on large repos (1000-file cap C8 still applies) → index may
  be partial; partial index must be labelled as such in provenance.
- Scope creep into "build the whole digital twin" — V4-E06 is a seed
  projection only.

### Security implications
- **New untrusted input**: full repository content at base revision (index
  build) — a hostile PR can plant prompt-injection payloads in files the index
  later retrieves. Mitigations: index built only from `base_sha` (trusted
  revision, D1 fix is the enabler); every retrieved chunk passes through the
  existing `wrap_untrusted_diff`-style fencing and `scan_prompt_injection`
  (upgraded from warnings-only to *exclusion* for retrieved chunks — proposed
  baseline); `_safe_repo_path` extended to every index-derived path.
- Evidence records are persisted → `redact_secrets()` on write, non-removable
  privacy exclusion baseline still filters what may be *read* from the index.
- Provenance fields are pipeline-owned (added to `LIFECYCLE_FIELDS`) — model
  output must not forge "evidence: X" claims.
- Budget caps (V4-E08) are a security control: retrieval cannot be tricked into
  unbounded GitHub API calls (constraint C8) or unbounded context.

### Testing requirements
- Index determinism: same fixture tree → identical index hash; tampered file →
  hash mismatch → rebuild.
- Retrieval golden tests: query → expected file/symbol set within budget;
  harness scores context quality (relevance@k on annotated fixtures, proposed
  baseline: ≥ 0.8 relevance@10 before V4 exit).
- Impact analysis: fixture repos with known call graphs; bounded-closure tests
  (depth cap, node cap) with explicit "truncated" provenance flag.
- Fingerprint v2: cross-engine wording variation dedups; migration test from v1
  rows; mute rows resolve under both keys; regression: churn on other lines does
  not change identity.
- Security: index-poisoning corpus (files containing fence/injection payloads)
  → retrieved chunks neutralized or excluded; budget-exhaustion test (hostile
  repo tree) → capped API calls, run still completes.
- Performance: index build wall-clock and incremental update on fixture repos
  (proposed baseline: full build ≤ 30 s for 1k files — proposed baseline).

### Migration requirements
- Action inputs: **no removals**; possible additive input later (e.g. index
  toggle) must default to current behavior.
- Findings: v1 fingerprints remain resolvable for ≥ 1 full stage (mapping
  table); `fingerprint:<fp>` mute rows dual-resolved; GitHub comment state
  markers re-anchor during transition — no mass duplicate-comment incident
  (explicit migration test).
- Report JSON: additive fields (`provenance`, `evidence_refs`, `impact`);
  existing fields unchanged.
- Storage: additive tables; dashboard hand-rolled `ALTER TABLE` continues;
  JsonStorage fallback gains the entities or explicitly reports "not supported"
  (never silently different behavior — fix the C9 `getattr` pattern).
- Static/mock path: index and intelligence features must work offline (zero-key
  path stays fully functional) — index built from `--diff-file` sibling checkout
  or fixture; if unavailable, features degrade with truthful labels.

### Performance implications
- Index build: cold-start cost per repo; incremental per-commit update required
  (proposed baseline: incremental ≤ 2 s for ≤ 50 changed files — proposed
  baseline). Cached across runs via storage keyed by repo+tree-hash.
- Retrieval adds bounded latency to `build_context` (proposed baseline:
  ≤ 500 ms — proposed baseline); no extra provider calls.
- GitHub API pressure: index build must page lazily and honor `X-RateLimit-*`
  (first increment of C8 work: backoff on 403 rate-limit, else the index will
  fail exactly where C8 predicts).

### Token/cost implications
- Context quality up, waste down: token-aware budgets should *reduce* prompt
  size versus the current flat 80k/12k character cuts on small PRs (proposed
  baseline: ≥ 15% median prompt-token reduction at equal-or-better relevance —
  proposed baseline). Telemetry from Phase 0 proves or disproves it.
- Impact/evidence/provenance metadata adds small structured overhead
  (proposed baseline: < 3% of prompt tokens — proposed baseline).
- Zero-key path unchanged: static engine does full index locally, no model cost.

### What MUST NOT be built yet in this stage
- No multi-agent fan-out, specialists, councils, or merger (V5).
- No vector database / embedding service / graph database (ADR-002) — retrieval
  is lexical/symbolic and deterministic first; embeddings, if ever, are an
  implementation detail behind V4-E02's contract, not new infrastructure.
- No standalone "digital twin" service, CQRS, or separate store.
- No security scanning engine, test intelligence, or dependency intelligence
  (V6) — the index *stores* structure, it does not *judge* it.
- No history/memory/issues (V7), no CI/events (V8), no org model/API versioning
  (V9), no plugins (V10).
- No change to review modes or number of provider passes.

### Exit criteria
1. Index built from `base_sha` on every GitHub-mode run; hash-sealed; test
   proves a PR-modified file cannot alter the index of its own review.
2. Context chunks in report provenance carry `{source ref, reason, tokens}`;
   harness context-quality score ≥ 0.8 relevance@10 (proposed baseline) and
   does not regress vs Phase 0 baseline on the golden corpus.
3. Impact analysis returns bounded, truncation-flagged dependency closures for
   fixture repos; failure mode degrades to "impact unknown", never to a crash.
4. Every AI finding in report JSON carries provenance (engine, model, agent id
   slot, evidence refs); no provenance field settable via
   `Finding.from_untrusted_dict`.
5. Fingerprint v2 active with dual-compute; migration test: 100% state
   continuity on fixture PR series (zero duplicate re-posts, zero mute breaks).
6. Injection/ poisoning corpus passes (100% neutralized or excluded);
   budget-cap tests prove bounded GitHub API calls per run.
7. Golden-corpus harness score ≥ Phase 0 score (no quality regression), full
   suite green, zero-key `--mock` path exercises index + retrieval end-to-end.

---

## V5 — Multi-agent engineering review

### Objective
Turn one monolithic provider pass into a bounded council of specialist
reviewers: a fan-out orchestrator with hard concurrency/budget limits, typed
specialist contracts over a shared prompt-builder, a provenance-aware merger,
an explainable v1 risk engine that adapts review depth, provider capability
routing, single-shot council synthesis, token/cost arbitration, and a
multi-agent evaluation harness. Output must remain one coherent GitHub review.

### User value
- A PR gets *specialized* attention — correctness, API-shape, tests, security
  glance — instead of one generic pass; deep-dive effort concentrates where risk
  is (large/complex/risky PRs get more reviewers; trivial docs PRs get one).
- Fewer duplicate/contradictory comments: the merger reconciles specialist
  findings under one identity with per-agent provenance visible in the report.
- Teams see cost per review before it happens: arbitration enforces a budget
  cap; degraded/budget-capped runs are labelled honestly.

### Major capabilities
- Bounded fan-out orchestration (in-process concurrency + in-process slice of
  C5 breaker safety; no queues) (V5-E01)
- Specialist reviewer contracts: typed spec (role, scope, input contract,
  output schema) over extracted shared prompt-builder (V5-E02)
- Provenance-aware finding merger (V5-E03)
- Risk engine v1 + adaptive review depth (V5-E04)
- Provider capability registry + task routing (replaces 7 hard-coded wiring
  sites) (V5-E05)
- Council synthesis: one summary from specialist outputs (V5-E06)
- Cost/token arbitration: budgets from Phase 0 telemetry (V5-E07)
- Multi-agent evaluation harness extension (V5-E08)

### Architecture changes
- `orchestrator.py` splits into a thin composition root + new subsystem (likely
  module): `ai_pr_reviewer/orchestration/` — planner (risk → depth → specialist
  set), executor (bounded task map), merger, synthesizer. Current single-pass
  path remains as the `depth=low` degenerate case.
- `ai/provider.py` + `ai/claude.py`/`openai.py`/`gemini.py`: extract the
  copy-pasted shared `SYSTEM_PROMPT`/batching/`_extract_json` into a shared
  prompt-builder + parser (constraint C2) — prerequisite for per-specialist
  prompts. Provider protocol gains optional `capabilities()` (informal
  contract today → declared).
- `model_router.py`: evolve to capability registry + task routing
  (V5-E05) — selecting provider/model *per task* (synthesis vs specialist vs
  static) instead of one backend per run; `select_backend`/`build_provider`/
  `AI_BACKENDS` collapse into registry data.
- `circuit.py`: per-backend-per-task breaker instances (or lock-guarded state)
  replacing process-global singletons — in-process slice of C5; **no** queue or
  worker infrastructure.
- New: risk scoring module (likely `ai_pr_reviewer/risk.py`) — deterministic
  features (diff size, files, churn from index, impact fan-out, surface
  criticality) → explainable score + depth decision; consumed by planner.
- `findings.py`: merger — cross-specialist dedup by fingerprint v2 + title
  similarity, severity reconciliation, provenance union.
- `reporter.py`/dashboard: per-specialist attribution, budget/usage breakdown
  per task (extends Phase 0 telemetry schema additively).

### Prerequisites & dependencies
- Hard: V4-E04 (evidence) + V4-E05 (provenance & identity) — merger and
  attribution are impossible on v1 findings (C3/C4); rationale: §0 #1.
- Hard: V3-E02 telemetry + V3-E03 harness; V5-E08 extends the harness —
  multi-agent cannot ship without before/after quality + cost comparison.
- Hard: V4-E02 budgets (token-aware) for arbitration to be more than guessing.
- Soft: V4-E03 impact feeds risk features; V4-E01 index feeds depth decisions —
  planner must degrade gracefully if index absent.
- Soft: V4-E07 read contracts for dashboard surfacing of council details.

### Risks
- **Cost multiplication**: N specialists × M batches vs one pass — worst-case
  latency/cost explosion if arbitration fails. Mitigation: hard caps (parallel
  specialists ≤ 4 — proposed baseline), circuit + budget pre-flight, static
  degradation.
- **Merge quality**: contradictions between specialists surface as confusing
  reviews → harness must score merger output, not just union.
- **Prompt leakage across specialists**: shared context containing one
  specialist's untrusted interpretation reaching another as if trusted —
  specialists' outputs are model output (untrusted) and must pass
  `from_untrusted_dict`-equivalent validation before entering any other
  specialist's context.
- Risk engine misclassifies trivial PRs as low-risk → under-review. Mitigation:
  floor: minimum one generalist + full static ruleset always run.
- C5 in-process slice insufficient under very high parallelism → reentrancy
  bugs; concurrency stress tests mandatory before exit.

### Security implications
- **New untrusted input**: specialist-to-specialist data flow (cross-agent
  messages) — every agent output re-enters validation, fencing, and redaction
  exactly like raw provider output; agent ids are pipeline-owned.
- Blast radius: N provider calls each receive fenced untrusted diff; injection
  screening runs per prompt, not once per run (upgraded screening for this
  stage per §0 #8).
- Prompt-builder extraction must not regress the nonce-fencing invariants
  (`security.py`) — fencing tests re-run against every specialist template.
- Budgets are a security control: pre-flight token budget check rejects
  configurations that cannot fit the untrusted diff within context
  (bounded-everything principle).
- No new write capabilities: specialists still cannot post comments — only the
  merged, validated, capped result reaches `github_sync.py`.

### Testing requirements
- Concurrency: stress test with mock providers (proposed baseline: 200 runs ×
  4 parallel specialists) — no shared-state corruption, breaker behaves, zero
  leaked threads; hermetic (no network).
- Merger: golden cases — same finding from 2 agents (one row, both provenances),
  contradictory severities (documented reconciliation rule), non-overlapping
  findings (both kept), v1/v2 fingerprint cross-walk.
- Risk/depth: fixture PRs → expected depth decisions with feature attribution
  asserted; explainability test (score = deterministic function of features).
- Routing: capability registry drives provider/model choice per task; unknown
  capability → config error, not silent fallback; retired-model scan still
  green.
- Evaluation: V5-E08 harness compares single-pass vs council on golden corpus —
  quality delta (finding precision/recall vs reference set), cost delta, latency
  delta; exit gate is quality-not-worse at bounded cost.
- Degradation: budget exhausted mid-council → partial specialist set +
  truthful label; all providers down → static path unchanged.

### Migration requirements
- Default behavior: existing V3 users with unchanged inputs must get
  **equivalent or better** output; new council activates only via config
  (proposed: `review_mode` extension or `specialists` input, default keeps
  current depth semantics — exact input shape decided in `MIGRATION_PLAN.md`).
- Report JSON: additive blocks (`council`, `per_task_usage`, `risk`); `engine`,
  `fallback_used` semantics extended (multi-engine runs need an engine-set
  representation — document, do not break existing consumers).
- Findings: no fingerprint change from V4-E05; comment style unchanged
  (merged result posts through existing sync path).
- Cost: default depth must not increase median spend on small PRs beyond
  budget guard (proposed baseline: ≤ 1.2× Phase 0 median on the golden corpus —
  proposed baseline), enforced by V5-E08 regression check.
- Storage: additive usage/attribution tables; no schema break before the
  storage consolidation ADR (§0 #5).

### Performance implications
- Latency: parallel fan-out means wall-clock ≈ slowest specialist + merge +
  synthesis, not the sum (proposed baseline: p95 ≤ 1.5× single-pass latency at
  depth=full — proposed baseline).
- Sequential fallback when concurrency unavailable (local/mock) must be
  functionally identical.
- GitHub API: no increase (comments posted once, merged).
- Dashboard: council detail views must paginate; report size grows
  (proposed baseline: < 2× report JSON bytes — proposed baseline).

### Token/cost implications
- This is the stage where cost goes wrong: arbitration (V5-E07) enforces
  per-run token budget (from Phase 0 measured baselines), per-task allocation
  (synthesis reserved share — proposed baseline: 10% of budget reserved for
  synthesis — proposed baseline), and hard stop → static degradation.
- Capability routing (V5-E05) sends cheap tasks to cheap models where
  configured; BYO-key users control which models specialists may use.
- Zero-key path: static specialists (rule packs scoped per role) — council
  architecture must work with zero API cost, honestly labelled.

### What MUST NOT be built yet in this stage
- No queues, workers, message bus, or cross-process coordination (V9-E04) —
  in-process bounded fan-out only.
- No autonomous actions: specialists suggest; only existing comment posting
  writes anything.
- No self-improving/memory-writing agents; no agent that edits its own prompts
  at runtime.
- No multi-repo/org awareness, no per-repo learned preferences (V7/V9).
- No new provider adapters beyond registry refactor of existing three + static
  (V10-E02 ecosystem).
- No policy engine (V6-E07), no security deep scan (V6-E01) — a security
  *specialist* may exist only as thin scope over existing static SEC rules, the
  engine stage is V6.

### Exit criteria
1. Planner→executor→merger→synthesizer pipeline runs in tests with mock
   providers; concurrency stress suite green; no global mutable breaker state
   on the multi-agent path.
2. Registry: adding a fake provider in tests touches zero production wiring
   sites outside registry data (assert by test that inspects wiring).
3. Merger golden suite green; report shows unioned findings with complete
   per-agent provenance and single merged GitHub comments.
4. V5-E08 harness report exists in CI: council vs single-pass quality/cost/
   latency deltas on golden corpus; gate: quality ≥ baseline, cost ≤ cap.
5. Budget-exhaustion and provider-failure drills produce correctly labelled
   degraded runs; `fail_on` and exit codes unchanged for equivalent findings.
6. Risk engine explainability test green; depth decisions reproducible from
   features alone.
7. Existing V3 test suite passes unmodified except tests that encode the old
   single-wiring assumption (updated with rationale); README documents the
   registry.

---

## V6 — Security + testing + architecture intelligence

### Objective
Add the judgment engines that need repository structure but must not wait for
history/org data: a real security analysis engine (deterministic + AI with
evidence), AI-security hardening v2, test intelligence (what a change does to
the test suite), architecture intelligence (layer/rule conformance), advanced
verification tiers (including test evidence), dependency intelligence, the v1
policy engine (repo/team scope), and a security evaluation corpus. Reviews start
making *evidence-backed* claims about risk, not pattern hits alone.

### User value
- Security findings cite the data-flow/shape that makes them real, with
  confidence and evidence — fewer regex false positives, no "looks suspicious"
  noise.
- PRs show test impact: "this change touches `refunds.py` but no test covering
  lines 40–60 runs in CI-configured suite" → reviewers catch missing coverage
  before merge.
- Architecture violations ("controller imports repository directly") are caught
  with file/line evidence against team-authored rules.
- Dependency alerts arrive with actual transitive-path evidence and a policy
  decision (allowed/forbidden/violation), not a raw CVE dump.
- Verification upgrades from line-coverage-only to tiers incl. test evidence
  (`still_present` → `verified_by_test` where legitimate).

### Major capabilities
- Security engine: deterministic checks (SAST-lite: taint-ish flow over index,
  secrets, injection shapes) + AI analysis scoped by the engine (V6-E01)
- AI security v2: adversarial/jailbreak/injection regression corpus feeding
  prompt hardening (V6-E02)
- Test intelligence: test→code mapping, changed-line coverage inference,
  flaky/stale test signals from diff history within repo scope (V6-E03)
- Architecture intelligence: layer/dependency rule checker over index
  (V6-E04)
- Advanced verification tiers: deterministic tiers T1 coverage → T2 static
  confirmation → T3 test-run evidence (V6-E05)
- Dependency intelligence: manifest parse, advisory matching, transitive path
  evidence (V6-E06)
- Policy engine v1: deterministic evaluation of repo/team policy over findings
  and changes (V6-E07)
- Security evaluation corpus: labeled fixtures, false-positive/negative gates
  (V6-E08)

### Architecture changes
- New subsystem (likely module): `ai_pr_reviewer/security_eng/` (name TBD) —
  composes existing `static/security_rules.py` (SEC001–008 stay the floor) with
  index-based flow analysis and scoped AI passes; outputs evidence records from
  V4-E04. `security.py` (fencing/redaction) stays a leaf — do not merge the two.
- `verification.py` evolves to tiered model: current deterministic coverage
  check becomes T1; T2/T3 additive, per-finding `verification_tier` field;
  `_unverify()` semantics preserved; **verification stays deterministic** —
  T3 consumes *observed* test results, never model claims about tests.
- New: test-mapping module (likely `ai_pr_reviewer/test_intel.py`) over index +
  test file parsing; arch-rule module (likely `ai_pr_reviewer/arch_rules.py`)
  with rule schema stored as project policy (`.ai-pr-reviewer.yml` extension).
- `rules.py` evolves: `ReviewPolicy` gains structured `policy:` section → new
  subsystem (likely `ai_pr_reviewer/policy/`) — deterministic evaluator;
  privacy exclusion baseline remains inside `rules.py` untouched and
  non-removable.
- New: dependency parsing (likely `ai_pr_reviewer/deps.py`) — manifests
  (requirements/pyproject/package.json/lockfiles) read at `base_sha`.
- Advisory data: bundled snapshot + optional fetch — snapshot is trusted
  input versioned with the release; fetching adds an outbound network surface
  with pinned host allowlist.
- `orchestrator`/planner: security/arch/test specialists become first-class
  scopes in V5 contracts (V5-E02), not new wiring.

### Prerequisites & dependencies
- Hard: V4-E01 (index) + V4-E03 (impact) + V4-E04 (evidence) — flow analysis,
  test mapping, arch rules, and evidence-backed findings all read the index and
  write evidence.
- Hard: V5-E02 (specialist contracts) for scoped AI passes; V4-E05 provenance
  for attributed security findings.
- Hard: V3-E03/V5-E08 harness for corpus scoring.
- Soft: V5-E04 risk feeds severity calibration; V4-E02 budgets bound AI scans.
- Soft (deferred): V7 history would improve flaky/stale-test signals — V6 ships
  diff-local inference only; V8 CI data would improve test truth — V6 uses
  static inference only. Document as known limits.

### Risks
- False-positive flood destroying trust (classic SAST failure) — corpus gates
  (V6-E08) with explicit precision floor before default-on.
- Advisory data staleness → wrong claims; snapshot freshness must be labelled
  in output ("advisories as of <date>").
- Verification tier creep: model claim about a test run accepted as evidence →
  violates determinism; T3 requires *observed* results only.
- AI security v2 corpus rot against evolving models; corpus is versioned
  assets, refreshed per stage.
- Policy engine scope creep into org semantics before V9 model exists.

### Security implications
- Security engine *reads more untrusted code* → its own prompt surfaces are new
  injection vectors: security findings' evidence excerpts pass through fencing;
  an attacker-authored file cannot make the security engine emit a "safe"
  verdict by prompt injection (verdicts from deterministic checks; AI output is
  advisory with confidence).
- **New untrusted input**: lockfile/manifest content (attacker-controllable in
  PR) — parsed by strict schema readers, no code execution, no `eval`, no
  dynamic import (dependency confusion is an *intelligence* claim, not an
  action).
- Advisory fetch: outbound HTTPS to pinned hosts only, TLS verified, size/time
  capped, failure → degrade with label (never block a review).
- Policy file `.ai-pr-reviewer.yml` remains trusted (base revision); policy
  engine must keep the non-removable exclusion baseline un-overridable —
  repository config can only add exclusions (existing invariant, now enforced
  by a second, tested evaluator).
- AI security v2 upgrades `scan_prompt_injection` patterns; regressions run in
  CI.

### Testing requirements
- V6-E08 corpus: labeled fixtures with gates — proposed baseline: precision
  ≥ 0.7, recall ≥ 0.6 on the seeded corpus before security engine default-on
  (proposed baseline), static SEC rules keep 100% recall on their existing
  fixtures.
- Test intelligence: fixture repos with known test→module mappings; changed-
  line coverage inference assertions; "no test evidence" honesty test.
- Arch rules: pass/fail fixtures per rule type; deterministic (same input →
  same findings).
- Verification tiers: tier escalation only with observed evidence; `_unverify`
  regression tests extended; D2-style cap independence re-asserted.
- Dependency: manifest parse fixtures incl. malformed files (fuzz-lite); no
  crash, labelled unknown; advisory snapshot match tests offline (no network
  in CI).
- Policy: evaluator truth table tests; baseline-exclusion non-overridability
  re-tested at the evaluator layer.
- Harness: security corpus integrated into CI score; no regression of golden
  PR scores.

### Migration requirements
- Config: `.ai-pr-reviewer.yml` gains new optional keys (`policy`, arch rules);
  absent keys → behavior identical to V5. Privacy `exclude` semantics unchanged.
- Findings: new categories may appear (security/test/arch) — severity
  threshold behavior unchanged; users with `severity_threshold: high` see no
  new comments by default. Findings appear in report (visible) even when below
  comment threshold — consistent with Phase 0 D3 fix.
- Verification: new optional `verification_tier` field; existing three states
  preserved; dashboard renders tier without breaking old records.
- Action inputs: no removals; any new input (e.g. `security_scan`) defaults
  off-or-safe with migration note.
- Report JSON additive; dashboard additive views.

### Performance implications
- Index-based flow/arch analysis is local CPU — must be bounded: node/edge
  traversal caps (proposed baseline: ≤ 50k nodes traversed per rule — proposed
  baseline), timeout budget in-run (proposed baseline: ≤ 10 s total static
  analysis — proposed baseline), truncated → "partial analysis" label.
- AI security passes reuse V5 bounded fan-out; incremental cost on top of
  council (proposed baseline: security scope adds ≤ 40% tokens on security-
  relevant PRs — proposed baseline), zero extra calls on pure-docs PRs.
- Advisory fetch is lazy + cached (proposed baseline: 24 h cache — proposed
  baseline).

### Token/cost implications
- Deterministic-first design keeps most security/arch/test value at zero token
  cost; AI only for judgment on candidate findings (pre-filtered).
- Corpus gates double as cost gates: precision floor means fewer spurious AI
  follow-ups.
- Per-scope budgets from V5 arbitration; report breaks out security-scope spend.

### What MUST NOT be built yet in this stage
- No autonomous remediation, no auto-generated patches applied anywhere, no
  autofix commits (V3 invariant: no code modification).
- No penetration testing, no runtime/DAST execution, no exploit verification.
- No compliance/certification claims (SOC2/PCI "pass/fail") — policy engine
  reports evidence-backed violations only.
- No org-level policy inheritance or multi-repo policy (V9-E02).
- No secrets *vaulting*, no secret rotation, no outbound scanning of registries
  beyond pinned advisory fetch.
- No incident automation, no CI/CD control (V8 is read-only intelligence).
- No dependency auto-upgrade PRs.

### Exit criteria
1. Security engine runs on golden corpus with precision/recall at or above the
   V6-E08 floor; every emitted finding carries ≥ 1 evidence record with a
   resolvable locator (file@sha:line range) or it is dropped.
2. Arch rules + test intel fixtures green in CI; partial-analysis labelling
   proven by cap-exhaustion test.
3. Verification tier tests green incl. "model cannot claim test evidence"
   negative test; report/dashboard show tiers.
4. Policy evaluator passes truth-table suite; exclusion-baseline
   non-overridability proven by evaluator-level test; repo-config-adding-
   exclusions works.
5. Dependency analysis fully offline in CI (snapshot) with freshness label;
   malformed-manifest fuzz suite green.
6. AI security corpus regression green; `scan_prompt_injection` pattern set
   versioned with corpus.
7. Golden-corpus harness shows no quality regression vs V5; cost within
   proposed caps; full suite + docker build green.

---

## V7 — Historical / project / team intelligence

### Objective
Make the platform remember and learn from the project's own past: git history
intelligence (churn, ownership of areas, past incidents-in-code), a memory
hierarchy with an explicit authority model, finding-to-finding relations
(regression_of, caused_by), issue/requirement linkage, team/repository analytics
(trends and hotspots — never individual rankings), historical evidence injected
into reviews, and the security model for memory. Reviews become aware of what
changed before, what was decided, and what keeps breaking.

### User value
- "This file is in the 95th percentile of churn and was touched by 4 of the
  last 5 hotfixes" — reviewers prioritize the risky region of a large PR.
- Recurring findings don't nag: a muted/resolved-with-rationale finding stays
  quiet, and the *rationale* (human-approved memory) is cited in the report.
- PR description references `PROJ-1234` → review pulls the issue context and
  flags requirement-shaped gaps as *evidence-backed signals*, never compliance
  claims.
- Team leads see repository health trends (flaky areas, review latency,
  finding-class movement) — explicitly no individual developer rankings or
  quality scores.

### Major capabilities
- Git history intelligence: churn, blast radius, revert/fix patterns, hot-spot
  decay over time (V7-E01)
- Memory hierarchy: org→team→repo→component→PR→finding levels with authority
  model (human-approved > observed > inferred) (V7-E02)
- Finding relations: regression_of / caused_by / duplicates / fixed_by edges
  over fingerprint v2 identities (V7-E03)
- Issue/requirement linkage: PR↔issue↔requirement association with evidence
  (V7-E04)
- Team/repository analytics: aggregate trends, hotspots, class movement —
  **no individual rankings** (V7-E05)
- Historical evidence in review: history + relations + linked issues flow into
  context and finding verdicts (V7-E06)
- Memory security: authority enforcement, poisoning defenses, provenance on
  every memory read (V7-E07)

### Architecture changes
- New subsystem (likely module): `ai_pr_reviewer/history/` — git log/blame/
  diffstat analysis. Requires local git history: extend the checkout step
  (`fetch-depth: 0` guidance in example workflow, additive input for shallow
  repos) or bounded GitHub compare API fallback (C8 aware); work read-only.
- `memory.py` evolves from flat notes to hierarchy + authority model
  (ADR-003): schema gains `level`, `authority` (human|approved|observed|
  inferred), `source`, `approved_by`; engine writes remain **human-only for
  approved levels** — observed/inferred material may be engine-written but is
  labelled and never auto-promoted (vision §6).
- `findings.py`: relations table over fingerprint v2 (hard dependency on
  V4-E05); relation computation is deterministic where possible (same
  normalized signature across time = regression candidate), AI may *suggest*
  relations with confidence, stored as untrusted, promoted only on evidence.
- New: linkage module (likely `ai_pr_reviewer/linkage.py`) — parses
  PR/issue/requirement references from title/body/commits; GitHub issue bodies
  are untrusted input → fenced like diffs.
- `context.py`: historical evidence injection (bounded slice of history digest
  + relations into prompts, provenance-tagged).
- `dashboard/`: analytics endpoints (aggregate SQL, no O(all-rows) Python
  scans — C9/D10 fixes apply) + trends views; `reporter.py` adds history
  section.
- Storage: `finding_relations`, `memory` hierarchy, `history_digests` tables —
  **requires the storage consolidation ADR (§0 #5) decided and its first
  increment landed before schema work starts** (hard gate).

### Prerequisites & dependencies
- Hard: V4-E05 (identity — relations need identity to attach to), V4-E04
  (evidence), storage ADR from V4/V7 gate (§0 #5).
- Hard: V3-E04 (storage debt: retention, connection lifecycle — history data
  grows unbounded).
- Hard: V7-E02 → V7-E07 ordering inside stage (authority model before mass
  memory writes; memory security with the surface).
- Soft: V5-E03 merger (relations across specialist findings), V6-E03 test
  intelligence (flaky-test signals gain history), V6-E07 policy (team-scope
  policy gives memory a consumer).
- Soft: V7-E01 before V7-E06; V7-E03/V7-E04 feed V7-E06.

### Risks
- **Memory poisoning**: hostile PR/issue text landing in approved memory →
  authority model + human approval gates are the control; any auto-write path
  is a defect.
- History data volume on old/large repos → digests must be bounded and cached;
  shallow clones degrade gracefully with label.
- Relations false positives (spamming "regression_of") → deterministic
  preconditions + confidence threshold, capped per run.
- Analytics slowly drifting into individual ranking territory (reputationally
  and ethically toxic) → schema and UI tests assert no per-user dimensions
  exist in V7-E05 outputs.
- Git-history availability in Action runners (shallow clone default) →
  graceful degradation mandatory, documented checkout requirement.

### Security implications
- **New untrusted inputs**: git commit messages, PR/issue/requirement text,
  branch names — commit messages and issue bodies enter prompts only through
  fencing + injection screening (upgraded per §0 #8); history digests pass
  `redact_secrets` (secret in an old commit message must not leak into a new
  review).
- **Memory trust boundary formalized**: read path tags every memory with
  authority + provenance in prompt; inferred content cannot be presented as
  project rule; write path: approved-level writes only from dashboard (existing
  human-only rule), engine writes restricted to labelled observed/inferred
  slots — enforced in storage layer, tested (V7-E07).
- Analytics privacy: aggregate-only outputs; no author-dimension queries
  exposed by API (test asserts query builder has no author group-by — proposed
  baseline design control).
- Local git execution: read-only git subcommands, no shell interpolation of
  untrusted strings (argument arrays only), path allowlist under checkout root.

### Testing requirements
- History: fixture git repos built in temp dirs (existing
  `demo/make_fixtures.build_all()` pattern) → expected churn/hotspot numbers;
  shallow-clone degradation test; read-only assertion (working tree untouched).
- Memory: authority-model matrix tests (who may write what, promotion rules,
  label rendering); poisoning corpus (hostile issue text) → never reaches
  approved level; prompt read-out shows authority tag.
- Relations: deterministic relation fixtures; AI-suggested relations stored
  untrusted; caps respected.
- Linkage: malformed/absent issue refs, private-repo 404 → degrade, no crash;
  issue body fencing tests.
- Analytics: aggregate correctness on seeded data; **regression test that no
  endpoint returns per-individual metrics** (hard invariant test).
- Harness: history-augmented context scored against baseline (must not
  regress relevance; golden corpus gains history-annotated cases).

### Migration requirements
- Checkout requirement changes (fetch-depth) are documented, never enforced
  silently — absent history → features labelled "history unavailable".
- Memory schema: existing `repo_memory` rows migrate to `level=repo,
  authority=human` — one-time backfill, idempotent; mute rows
  (`fingerprint:<fp>`) keep working under fingerprint v2 dual-resolution
  (V4-E05 migration continues).
- Report JSON additive (`history`, `relations`, `linked_issues`); findings
  themselves unchanged unless historical evidence changes verification state —
  state transitions logged with provenance.
- Dashboard: additive views; existing routes untouched (API versioning is V9).
- Action inputs: additive only (e.g. `history_depth`), defaults preserve
  current behavior.

### Performance implications
- History analysis is the heaviest local CPU stage so far: bounded window
  (proposed baseline: last 500 commits or 90 days — proposed baseline),
  digests cached by (repo, head_sha), incremental update.
- Blame on large files capped (proposed baseline: ≤ 200 files deep-blamed per
  run — proposed baseline), sampled beyond with label.
- Issue/compare API calls bounded and rate-limit aware (C8 increment);
  analytics queries indexed/aggregate (no full-table Python scans — C9 exit
  condition).
- Prompt overhead from history slice bounded (proposed baseline: ≤ 5% of
  context budget — proposed baseline).

### Token/cost implications
- History digest is precomputed locally (zero tokens) — only a bounded summary
  enters prompts (small increase, proposed baseline: ≤ 5% median prompt growth).
- Relations/issue context can reduce redundant AI judgment (fewer "is this a
  regression?" passes) — measured via V3-E02 telemetry, claimed only after
  measurement.
- Zero-key path: full history/local analytics features work without any API
  key; GitHub API-dependent linkage degrades with label.

### What MUST NOT be built yet in this stage
- **No individual developer rankings, quality scores, leaderboards, or
  per-author analytics — anywhere, in any shape** (vision §6, hard invariant).
- No org-wide analytics or cross-repo comparison (V10-E05) — repository
  boundary is the unit.
- No autonomous memory writes of AI inference as truth; no auto-promotion; no
  "the platform decided" flows.
- No requirement-compliance certification; gap detection is evidence-backed
  signal only.
- No webhooks/event platform (V8), no CI data (V8), no org model (V9).
- No LLM-based summarization of *all* history — bounded digests only.

### Exit criteria
1. History module runs on fixture repos with deterministic outputs; shallow
   clone → labelled degradation; CI green without network.
2. Memory hierarchy + authority tests green; backfill migration idempotent
   (run twice → same state); every prompt-visible memory carries authority +
   provenance; poisoning corpus cannot reach approved level.
3. Relations table populated by deterministic rules on fixtures; caps and
   untrusted-suggestion handling tested; report shows relations.
4. Linkage resolves PR→issue on fixtures; fencing of issue bodies tested.
5. Analytics endpoints return aggregate trends on seeded data with query-time
   bounds; **invariant test: no API response or query path contains an
   individual-dimension metric**.
6. Golden corpus with history context ≥ baseline score (harness gate).
7. Storage consolidation ADR executed increment #1 (history/relations schemas
   on the agreed layout); retention prunes history digests per policy.

---

## V8 — CI/CD + release + incident intelligence

### Objective
Connect the review to everything around the merge: ingest CI run results and
correlate failures with changes, correlate test failures across PRs, read
release/tag state, extract knowledge from docs, understand infrastructure-as-
code, attach read-only retrospective incident intelligence, and stand up the
**internal** event platform v1 that normalizes these signals into one append-
only stream. Every capability is read-only: the platform observes CI, releases,
and incidents — it never triggers, gates, or rolls back anything.

### User value
- Review comments can say "CI on this PR failed twice in `refund_job` and the
  failing test last failed on the commit that touched `refunds.py`" — the
  reviewer sees the correlation instead of re-deriving it.
- A PR breaking a public API or a documented behavior surfaces docs drift
  ("`docs/api.md` still documents the old signature").
- IaC changes get scoped review ("this IAM rule is wildcard-wide") with
  infrastructure context, not generic diff comments.
- Release awareness: "this PR lands after the v3.2 tag; changelog section
  missing" — release-shaped findings, honestly sourced.
- Incident retrospectives (manually linked, read-only) inform risk: "code
  implicated in INC-14 gets deeper review depth" — as evidence, never as
  automated action.

### Major capabilities
- CI ingestion: GitHub Actions (and later generic) run/job results for the PR
  head and recent base history (V8-E01)
- Test-failure correlation: cluster failures across runs/PRs, link to files via
  V6 test intel + V7 history (V8-E02)
- Release intelligence: tags/releases/changelog state (V8-E03)
- Docs intelligence: docs↔code drift signals with evidence (V8-E04)
- Infrastructure intelligence: IaC parsing + rule checks (V8-E05)
- Incident intelligence: read-only linkage of human-supplied incident records
  to code/areas (V8-E06)
- Internal event platform v1: normalized append-only event stream (in-process
  producer → durable local log) — **no queues/workers yet** (V8-E07)

### Architecture changes
- `github_client.py`: CI/release/issue-event read endpoints with rate-limit
  handling (C8 continues), all classified read-only; polling schedules inside
  a run, no webhooks yet (webhooks = V9).
- New subsystem (likely module): `ai_pr_reviewer/events/` — event schema
  (versioned envelope: type, source, subject, payload, provenance), producer
  API, append-only local log in storage, replay for tests. This is the
  foundation V9 workers consume; V8 writes and reads it only.
- New subsystems (likely modules): `ci_correlation.py`,
  `release_intel.py`, `docs_intel.py`, `infra_intel.py`, `incident_intel.py` —
  each reads index (V4) + history (V7) + test intel (V6), emits evidence
  records, and contributes findings or *context* to the review; none get
  independent provider routing (they ride V5 task contracts).
- `context.py` planner input: CI/incident signals feed risk features
  (V5-E04) as explainable additions.
- `dashboard/`: CI/release/incident views over the event log + stored
  correlations; `reporter.py` gains a "pipeline evidence" section.
- Storage: `events`, `ci_runs`, `test_failures`, `releases`, `incidents`
  tables on the consolidated layout (increment #2 of the §0 #5 ADR).

### Prerequisites & dependencies
- Hard: V4 (index/evidence/read contracts) for every correlation; V6-E03 test
  intelligence for test-failure correlation; V7-E01 history for cross-run
  patterns.
- Hard: V6-E07 policy for release/docs rules to reference.
- Hard: internal ordering — V8-E01 → V8-E02 (correlation needs raw runs);
  V8-E07 event schema early (it is the seam the others publish to), but no
  worker/queue semantics in V8 (§0 #4).
- Soft: V7-E04 linkage patterns reused for incident linkage; V5-E04 risk
  integration.

### Risks
- CI data volume/noise on busy repos → bounded fetch windows, aggregation at
  ingest, retention (proposed baseline: raw CI runs retained 90 days —
  proposed baseline).
- Correlation false confidence ("test failed → PR caused it") → correlation is
  labelled *correlation*, causation requires V7 history evidence; UI/report
  wording gated by honesty tests.
- Event schema churn before consumers exist → schema versioned from day one,
  additive-only rule.
- GitHub API rate-limit pressure from CI polling (C8) → single batching
  ingestion per run, `X-RateLimit` respected, degrade with label.
- Scope creep toward CI *control* (re-run job, block merge) — forbidden.

### Security implications
- **New untrusted inputs**: CI log excerpts, job names, workflow YAML from the
  PR, release/tag names, incident record text, docs content. All are fenced +
  screened before prompts; CI logs are a classic secret-leak channel →
  `redact_secrets` mandatory on ingest *and* on store, plus truncation.
- Workflow YAML in a PR is attacker-controlled: parsing only, no execution, no
  `uses:` resolution, no action-graph execution — V8 reads what CI *reported*,
  it never interprets a workflow as instructions.
- Incident records: human-supplied but third-party text → same fencing,
  authority model from V7 applies (incident linkage is observed-level).
- Event log: append-only, schema-validated, size-capped, redacted at ingest;
  event consumption by future V9 workers re-validates (never trust your own
  past input blindly).
- Read-only scope is the security property: token permission set unchanged
  (contents: read, pull-requests: write for comments only).

### Testing requirements
- CI ingestion: mocked GitHub API fixtures (hermetic) → normalized events;
  missing/partial/failed runs → labelled degradation; rate-limit simulation →
  backoff, no failure.
- Correlation: fixture run histories → expected clusters/links; negative
  tests: coincidental failures on unrelated files produce no causal claim.
- Docs/infra/release: fixture doc pairs and IaC files → expected findings with
  evidence; malformed IaC → parse-error label, no crash.
- Event platform: schema validation, append-only enforcement, replay-equality
  test (replay → identical derived state), size/retention caps.
- Security: log-secret-leak corpus (fake keys in CI logs) → redacted in store
  and report; workflow-YAML-as-prompt-injection corpus → neutralized.
- Harness: golden corpus gains CI-annotated cases; no regression gate.

### Migration requirements
- New features activate only when CI data is available or opted in — default
  V3 behavior unchanged when inputs absent (degrade with labels).
- Action inputs: additive (e.g. `ci_context: auto|off`), default `auto` =
  read-if-available with graceful absence; documented fetch-depth addition from
  V7 remains documented.
- Report JSON additive (`pipeline`, `correlations`, `releases`); event log is
  internal, not part of the public report contract.
- Dashboard additive views; no API versioning yet (V9-E03).
- Storage additive on consolidated layout; retention policies documented in
  `MIGRATION_PLAN.md`.

### Performance implications
- CI ingestion adds API calls: bounded (proposed baseline: ≤ 30 API calls per
  run for CI/release data — proposed baseline), batched, cached by run id.
- Correlation CPU local and bounded (windowed queries, indexed columns).
- Event log writes are append-only (cheap) but retention/pruning runs
  scheduled; dashboard views paginate (no O(all) scans — C9 exit condition
  enforced).
- Latency: CI correlation is context-stage only (before provider), within the
  existing run budget; no second provider pass added by V8 itself.

### Token/cost implications
- CI/release/docs signals enter as *structured summaries computed deterministically
  locally* — token overhead small (proposed baseline: ≤ 10% median prompt growth
  when CI data present — proposed baseline).
- Test-failure correlation replaces AI "guess why red" passes with evidence →
  net token reduction on failing-CI PRs (claimed only after V3-E02 telemetry
  proves it).
- Ingestion/storage cost is local compute + storage only; no new paid services.

### What MUST NOT be built yet in this stage
- **No CI control of any kind**: no triggering/re-running jobs, no merge gates,
  no status writes, no deployment actions (vision §6 hard rule).
- No queue separation, no workers, no broker (V9-E04) — event platform v1 is
  durable log + schema + replay only.
- No external webhook endpoints (V9) — polling only.
- No third-party CI systems beyond GitHub Actions in v1 (contract allows more
  later); no proprietary SaaS dependencies.
- No incident *response* automation; no paging/on-call integration; no root-
  cause AI assertions without evidence.
- No hosted delivery/CD features; no changelog auto-publishing.

### Exit criteria
1. CI runs for PR head ingested into normalized events in fixture tests;
   rate-limit and missing-data drills labelled, never fatal.
2. Test-failure correlation produces cluster + file links on fixture history;
   causation-vs-correlation wording passes honesty tests.
3. Release/docs/infra fixtures produce evidence-backed findings; malformed
   inputs degrade with labels.
4. Event log: append-only + schema-validation + replay-equality tests green;
   retention prunes per policy; zero queue/worker symbols in the codebase
   (negative architecture test).
5. Secret-leak corpus: no secret persists in events/correlations/report.
6. Golden harness ≥ baseline; full suite + docker build green; zero-key path
   exercises everything local (CI features labelled "GitHub data required"
   when absent).
7. Token/cost telemetry shows V8 overhead within proposed caps.

---

## V9 — Organization platform

### Objective
Generalize the single-repo system into an organization platform: a multi-repo/
org model, org-scoped policy with inheritance, a versioned public API,
event-driven workers **only where measurement justifies them**, org-level
memory, the v1 extensibility contract (stable seams for future plugins), and a
real observability platform (metrics, health, audit at org scale). This is the
stage where internal seams become public contracts — versioning discipline
matters more than new intelligence.

### User value
- Platform teams configure policy once at the org level and inherit it down to
  repos, with overrides and audit ("why did this review enforce X?").
- Integrators build against a stable versioned API instead of scraping the
  dashboard; dashboards become an API client like anyone else.
- Busy orgs get scale: CI/history/ingestion load moves to workers so reviews
  don't time out; observability shows per-repo health, error budgets, and cost
  across the org (aggregate, never individual rankings).
- Org memory: shared approved decisions ("we always fence user input in
  handlers") reach every repo's review with authority + provenance.

### Major capabilities
- Multi-repo/org model: org→repo identity, config scope, storage schema
  (V9-E01)
- Org policy engine: inheritance/override of V6 repo/team policy (V9-E02)
- Versioned public API: `/api/v1` contract, authz per scope, deprecation
  policy (V9-E03)
- Event-driven workers: queue + workers **only for measured bottlenecks**
  (CI ingestion, history digests, index build, analytics rollups) (V9-E04)
- Org memory: V7 hierarchy extended to org/team levels with authority
  propagation (V9-E05)
- Extensibility contract v1: declared seams (provider registry, rule packs,
  read contracts, event schema) frozen as documented, tested interfaces
  (V9-E06)
- Observability platform: metrics, structured audit, health/error-budget views
  (V9-E07)

### Architecture changes
- `dashboard/app.py` routes split behind a versioned API layer (likely
  `api/v1/` package) with scope-based authz (today: single shared token →
  per-scope tokens/keys); OpenAPI document generated (UI may stay disabled).
- Storage: org/repo scoping across all tables — consolidated layout increment
  #3; row-level scope filter enforced in the data-access layer (never per-
  route), tested as an invariant.
- `policy/` (V6) gains inheritance resolution (org → repo, local override
  rules, audit trail of effective policy).
- New subsystem (likely module): `ai_pr_reviewer/queue/` — durable job queue
  + worker entrypoints over the V8 event log; **C5 breaker/telemetry design
  must be worker-safe (per-process instances) before this ships**; in-process
  path remains fully functional for single-process/Action deployments.
- `memory.py`/storage: org/team levels, promotion workflow (human approval
  required for org-level entries).
- Observability: metrics registry (counters/histograms from Phase 0 telemetry
  schema), structured audit log (extends dashboard `audit.jsonl`), health
  endpoints per subsystem.
- Engine/Action mode unchanged: the Action still runs one review in-process —
  workers are an *optional deployment* of the dashboard/server side, not a
  requirement for V3 users.

### Prerequisites & dependencies
- Hard: V8-E07 (event platform v1 — workers consume it; §0 #4), V6-E07 (policy
  v1 to inherit), V7-E02/V7-E07 (memory hierarchy + authority to extend),
  V4-E07/V9-E01 ordering (read contracts must be org-scoped before exposure).
- Hard: storage consolidation ADR executed (increment #3) — org scoping on
  triplicated schemas (C9) is untenable.
- Hard: V9-E01 → V9-E02 → V9-E03 (org model precedes policy, both precede
  public API freeze); V9-E06 after the seams it freezes are exercised (V4–V8).
- Soft: V9-E04 workers start only with a measured bottleneck from V9-E07
  observability (workers are evidence-driven, not architecture-driven).
- Soft: V5-E05 registry and V8 event schema feed V9-E06 contract tests.

### Risks
- **Premature queue migration**: rewriting ingestion to workers without
  measurement burns a stage and risks reliability (violates "no rewrite").
  Control: workers gated on V9-E07 metrics showing a real bottleneck.
- API freeze too early → version churn; control: mark v1 endpoints
  experimental until two consumers exist (dashboard + one test client).
- Scope-based authz bug = cross-tenant data leak (when multi-repo orgs share a
  deployment) — authz is tested as invariant matrix, not per-endpoint spot
  checks.
- Org policy override chaos (repo silently exempt) — effective-policy audit
  endpoint mandatory.
- Single shared dashboard token cannot express scopes → migration of existing
  tokens must be seamless (compat layer).

### Security implications
- **New trust boundaries**: multi-repo org deployment (repos from different
  trust levels sharing org policy/memory), scoped API credentials, and — for
  the first time — an *inbound* surface designed for external integrators.
- AuthZ: every API read/write passes a scope check (org/repo/reader/writer);
  constant-time token compare kept; weak-token refusal kept; reads default
  authenticated (the `DASHBOARD_REQUIRE_TOKEN_FOR_READS=0` escape hatch becomes
  a loud, documented risk flag).
- Org memory inherits V7 authority rules; org-level entries require human
  approval; poisoning blast radius is org-wide → approval + provenance +
  audit on every read.
- Event/webhook groundwork: V9 may expose inbound webhooks (if built — see
  "must not" for the conservative stance) → HMAC signature verification,
  replay protection, payload caps; otherwise polling stays.
- Workers process untrusted-derived data (CI logs, diffs) → same fencing in
  worker prompts; queue payloads are references, not prompts (re-materialize
  and re-sanitize at consume time).
- Observability/audit: append-only audit of authz decisions, policy
  evaluations, memory promotions; metrics cardinality must not leak repo/path
  secrets into metric labels.

### Testing requirements
- Scope matrix tests: every route × role → allow/deny expected; cross-org
  access attempts denied; regression-invariant (new routes fail CI without a
  scope declaration).
- Policy inheritance: precedence/override/audit fixtures; effective-policy
  endpoint reflects merges deterministically.
- API v1: contract tests (schema snapshots), deprecation headers, additive-
  change enforcement (breaking change detector in CI).
- Workers: exactly-once-ish semantics on job replay, poison-message handling,
  breaker-per-worker tests, kill-the-worker drill (no lost reviews); in-process
  path parity tests (same result with/without queue).
- Org memory: promotion workflow + authority propagation tests; poisoning
  corpus at org scale.
- Observability: metric presence/completeness tests; audit log tamper-evidence
  (hash chain) test.
- Harness/multi-agent suites continue as gates for everything reachable
  through workers.

### Migration requirements
- **Action contract unchanged** — V3 users see no difference; workers are
  server-side opt-in.
- API: dashboard SPA repointed to `/api/v1`; legacy unversioned routes kept
  with deprecation headers for one stage (sunset documented in
  `MIGRATION_PLAN.md`).
- Auth: existing `DASHBOARD_TOKEN` continues to work as a scope-full legacy
  key; new scoped tokens additive; no forced re-auth for single-repo users.
- Storage: org scoping migration adds `org_id`/`repo_id` columns with default
  `default` org backfill — idempotent, no downtime for SQLite; JsonStorage
  either follows the schema or is explicitly demoted to "dev only" with a
  warning (decision recorded, not silent).
- Config: `.ai-pr-reviewer.yml` unchanged at repo level; org config is a new
  file/scope, never silently overriding repo policy (precedence documented).

### Performance implications
- Org-scale read paths must be indexed/aggregated (C9/D13/D10 exit conditions
  enforced by perf tests): dashboard list endpoints bounded pagination,
  analytics precomputed.
- Workers: parallelism bounded (proposed baseline: ≤ 2 workers per host —
  proposed baseline initially), queue depth alarms via V9-E07.
- API latency budgets (proposed baseline: p95 ≤ 300 ms for read endpoints on
  warm cache — proposed baseline).
- Action-path latency unaffected (no queue in the PR critical path).

### Token/cost implications
- Org memory and policy context can bloat prompts → per-repo context budgets
  remain hard caps; org contributions to prompts bounded (proposed baseline:
  ≤ 10% of context budget — proposed baseline).
- V9-E07 provides cost rollups per org/repo (from Phase 0 telemetry lineage)
  — aggregate only.
- Workers add compute cost only where justified; run-before-build rule: no
  queue without a measured bottleneck (evidence from V9-E07).

### What MUST NOT be built yet in this stage
- **No full multi-tenancy** (V10-E03): org model ≠ tenant isolation product;
  no billing, no per-tenant encryption, no SSO/SAML (unless a concrete
  enterprise requirement reopens it via ADR).
- No plugin marketplace or third-party plugin execution (V10-E01) — only the
  contract (V9-E06).
- No hosted SaaS offering, no control plane, no automatic upgrades of user
  deployments.
- No IDE/CLI ecosystem expansion beyond current CLI (V10-E04).
- No org-wide individual analytics (permanent prohibition) and no developer
  scoring of any kind.
- No event *bus* semantics beyond log + queue: no stream processing framework,
  no exactly-once distributed transactions.
- No autonomous actions (unchanged): still read + comment only.

### Exit criteria
1. Scope-matrix test suite green and wired as CI invariant for all routes;
   cross-org access fixture denied.
2. Policy inheritance fixtures green; effective-policy audit endpoint returns
   deterministic merge results.
3. `/api/v1` contract snapshot tests green; breaking-change detector active;
   dashboard SPA runs entirely on v1; legacy routes emit deprecation headers.
4. Storage org-scoping migration idempotency test green (run twice);
   consolidated layout in use; JsonStorage fate decided and documented.
5. Workers ship **only** with a V9-E07- documented bottleneck; parity tests
   (queue on/off → same review results) green; kill-worker drill green.
6. Org memory promotion + authority tests green; org-level entries all carry
   human-approval provenance.
7. Observability: metrics + audit coverage tests; token/latency/cost rollups
   render per-repo and per-org; no individual dimensions (invariant test).
8. Zero regression on the V3 Action path: full suite green, contract
   unchanged, README migration notes complete.

---

## V10 — Ecosystem / platform

### Objective
Open the stabilized seams to the world (and optionally to hosting): a sandboxed
plugin system executing third-party extensions safely, a provider capability
ecosystem including optional local providers, an *optional* hosted
multi-tenant foundation, an IDE/CLI ecosystem around the same engine, org-scale
analytics, and the engineering command center that pulls org, review,
verification, and cost signals into one operational surface. Everything here
consumes contracts frozen in V9 — this stage ships surfaces, not new
intelligence cores.

### User value
- Teams extend the reviewer with their own rule/analyzers (plugins) without
  forking the engine or running untrusted code with their tokens.
- Users bring any model: cloud or **local** providers (e.g. Ollama-style
  endpoints) through one capability-registered path — privacy-sensitive
  orgs keep code on-prem.
- IDE/CLI: the same review/intelligence available pre-push and locally, not
  only as a CI Action.
- Org leads get the command center: health, cost, policy compliance, review
  quality trends, incident/CI signal in one place (aggregate views only).

### Major capabilities
- Sandboxed plugin system: rule packs / analyzers / report renderers with
  capability-based permissions (V10-E01)
- Provider capability ecosystem: declarative capability manifests, local/offline
  provider adapters, community provider contract (V10-E02)
- Hosted multi-tenant foundation (optional, explicitly labelled future option)
  (V10-E03)
- IDE/CLI ecosystem: LSP-ish/local review UX, CLI parity with Action modes
  (V10-E04)
- Org-scale analytics: longitudinal trends, cost/quality dashboards (no
  individual rankings) (V10-E05)
- Engineering command center: the dashboard becomes the operational surface
  (V10-E06)

### Architecture changes
- New subsystem (likely module): `ai_pr_reviewer/plugins/` — manifest schema
  (id, version, capabilities, API-range), loader, **out-of-process sandbox
  runner** (subprocess with resource/time limits and capability-scoped IPC;
  no `import` of plugin code into the engine process), plugin store/layout on
  disk. Rule packs remain the in-process *first-party* path (existing
  `static/engine.build_default_registry()` wiring) — plugins are the
  third-party path with stricter isolation.
- `model_router.py` capability registry (V5-E05) becomes the plugin/provider
  seam: local provider adapters are registry entries with capability
  manifests (context window, modalities, cost class, offline flag).
- CLI (`cli.py`) and dashboard gain parity surfaces; likely new
  `ai_pr_reviewer/local_review.py` shared core so CLI/IDE/Action run the same
  pipeline (no forked logic).
- Dashboard SPA → command center (V10-E06): aggregated views over org/repo
  analytics (V10-E05), all read-only over `/api/v1`.
- Hosted foundation (V10-E03, if pursued): deployment artifacts, tenant
  isolation primitives, config service — **built on V9 storage/authz scope
  model, never a parallel architecture**; repository ships docs + compose
  files, not a SaaS control plane.

### Prerequisites & dependencies
- Hard: V9-E06 (extensibility contract — plugins target frozen seams),
  V9-E03 (versioned API — command center and IDE are API clients), V9-E01/
  V9-E02 (org model + policy for org analytics and plugin governance).
- Hard: V9-E07 observability (command center consumes it; security monitoring
  of plugin/runtime surfaces).
- Hard: V5-E05 registry for V10-E02; V4 read contracts for local review
  parity.
- Soft: V8 event platform for streaming command-center data (polling over
  events is acceptable v1); V10-E03 strictly optional — never a prerequisite
  for V10-E01/E02/E04/E05/E06.

### Risks
- **Plugin sandbox escape** = arbitrary code with repo/token access — the
  single largest security risk in the roadmap; mitigation: out-of-process,
  least-privilege capabilities (no GitHub token by default), signed/manifested
  plugins, kill-switch, audit; sandbox failure → plugin disabled, review
  continues.
- Provider ecosystem quality variance → capability manifests must be honest;
  unknown capabilities fail closed (config error), never silently degrade.
- Hosted scope creep turns an optional foundation into a maintenance sink →
  ADR gate required before any V10-E03 work starts (decision documented).
- CLI/IDE parity drift (three surfaces, one pipeline) → shared-core invariant
  test (same diff → same findings across modes).
- Org analytics drifting into individual surveillance → invariant test
  carried forward from V7.

### Security implications
- **New untrusted input: plugin code itself** — third-party code is hostile by
  default. Trust boundary: plugin runs in a sandboxed subprocess with
  capability-scoped IPC; it receives only redacted, scoped data slices; its
  output re-enters the pipeline as *untrusted model-equivalent output*
  (validation/anchoring/redaction/lifecycle-stripping — the exact model-output
  treatment); it never gets raw secrets, the dashboard token, or the GitHub
  token by default (explicit capability grant + audit otherwise).
- Local providers: inbound local endpoint trust (localhost/TLS) — config
  treats them like any provider (output untrusted), plus offline-mode
  guarantee ("no network egress" claim must be testable).
- Hosted multi-tenancy (if built): tenant isolation is the whole game —
  row-level scope from V9 becomes tenant-level with dedicated tests, key
  management, and per-tenant encryption decisions via ADR; until then,
  multi-tenancy stays in DO_NOT_BUILD_YET.
- IDE/CLI: local diffs are untrusted input exactly as in CI; local mode never
  weakens fencing because it is "just local".
- Plugin updates: version pinning, manifest signature verification, API-range
  enforcement (plugin built for v1 API cannot load against v2 without
  declaration).

### Testing requirements
- Sandbox: escape-attempt suite (file/network/process access denied;
  capability violations → killed + audit), resource-limit tests (CPU/memory/
  time caps), plugin-crash → review completes unaffected; hermetic, no real
  network.
- Plugin contract: API-range compatibility matrix; malicious-output suite
  (lifecycle-field forging, injection payloads, oversized output) all
  neutralized; first-party rule packs unaffected by plugin failures.
- Provider ecosystem: capability-manifest validation fixtures; local-provider
  adapter against mock local endpoint (offline CI); honest-fallback labels
  (static must still say "not AI").
- Parity: same fixture diff through CLI/Action/dashboard-sandbox → identical
  findings/fingerprints.
- Org analytics/command center: aggregate correctness + the standing
  no-individual-dimensions invariant; API contract tests unchanged.
- Hosted (only if pursued): tenant-isolation matrix, key-handling tests,
  load/soak baselines — separate ADR-gated suite.

### Migration requirements
- Action/CLI/config: fully backward compatible — plugins are opt-in, new
  inputs additive (`plugins: off` default — proposed baseline).
- Provider registry: existing three providers + static keep identical config
  keys; new providers purely additive; retired-model scan extended to plugin
  manifests (deny-list enforced at load).
- Report/dashboard: plugin findings tagged with plugin id + version in
  provenance (V4 fields) — no schema break; dashboard renders unknown plugin
  ids gracefully.
- API: plugins and IDE target `/api/v1` only (no private routes); contract
  tests enforce.
- Hosted (if pursued): zero impact on self-hosted/Action users — separate
  deployment artifacts, documented as optional in README.

### Performance implications
- Sandbox IPC overhead: plugin rules run per-finding/per-file — budgeted
  (proposed baseline: ≤ 100 ms per plugin invocation, aggregate plugin budget
  ≤ 1 s per run — proposed baseline); timeout → plugin skipped, labelled.
- Local providers remove network latency for privacy mode; capability
  registry caches manifests.
- Command center: precomputed rollups (no live O(all) queries); event-driven
  refresh bounded.
- Org analytics queries run precomputed from V9 observability store.

### Token/cost implications
- Local providers → zero token cost option (privacy + cost), honestly labelled
  with their capability class; capability routing (V5-E05) can prefer cheap/
  local models per task type when configured.
- Plugin/context additions bounded by existing V4 budgets — plugins cannot
  allocate their own unlimited context (budget API is the only path).
- Command center cost dashboards are the culmination of V3-E02 telemetry:
  org-level cost/quality trends (aggregate).

### What MUST NOT be built yet in this stage
- **No plugin marketplace**: local/trusted-directory loading only — signing,
  distribution, review process are a separate decision, not implicit in
  V10-E01.
- **No autonomous actions** remain forbidden: plugins cannot commit, merge,
  push, deploy, or modify code — capability system has no such capabilities to
  grant (vision §6, permanent).
- No individual developer analytics (permanent).
- Hosted multi-tenant (V10-E03) stays optional and ADR-gated — not started
  unless explicitly approved; no billing, SSO, or control-plane commitments by
  default.
- No new intelligence domains (V4–V8 scope closed) — V10 ships surfaces on
  existing intelligence; any new analysis capability needs a new stage/ADR.
- No removal of the free/zero-key path — local providers are additive to, not
  replacements for, the deterministic static engine.

### Exit criteria
1. Sandbox escape suite green (100% capability violations denied, resource
   caps enforced, crash-isolation test green); malicious-plugin output corpus
   fully neutralized; plugin disabled → review completes with label.
2. Plugin manifest + API-range matrix green; first-party rule packs run
   through the same pipeline untouched (parity test).
3. Capability registry loads ≥ 1 local provider adapter in offline CI; honest
   labels verified; retired-model deny-list covers manifests.
4. Parity test green: CLI == Action == sandbox findings on fixtures.
5. Command center renders org health/cost/quality from precomputed rollups;
   no-individual-dimensions invariant still green; API consumers use v1 only.
6. If V10-E03 pursued: ADR approved first, tenant-isolation matrix green,
   load baseline met (proposed baseline numbers set in that ADR); if not
   pursued: DO_NOT_BUILD_YET entry remains, explicitly re-affirmed.
7. Full suite + docker build green; README/plugin-author docs published;
   V3 action contract byte-compatible with Phase 0 (contract snapshot test).
