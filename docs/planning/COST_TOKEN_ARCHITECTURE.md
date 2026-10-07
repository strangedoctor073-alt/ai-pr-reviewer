# COST & TOKEN ARCHITECTURE — Measured, Bounded, Cheap by Default

> Status: planning document (v1) — grounded in repository state described by
> `CURRENT_ARCHITECTURE.md` at commit `2841b23`. Every number is a guess marked
> "proposed baseline"; none is a commitment until calibrated by V3-E02 data.

Related: `CURRENT_ARCHITECTURE.md` (defect **C6** no telemetry, **C7**
character budgets) · `MASTER_VISION.md` (§3.7 cost-aware OSS, §5-U/V capability
stances) · `EPIC_BACKLOG.md` (V3-E02 telemetry foundation, V5-E07 cost
arbitration, V9-E07 observability platform) · `TESTING_EVALUATION_PLAN.md` ·
`ADR_INDEX.md` (ADR-014 telemetry/cost accounting).

---

## 1. Current truth — what exists, what is dead, what is missing

### 1.1 Token counters exist but are dead ends

```
provider instance              AnalysisOutcome           report JSON / storage / dashboard
─────────────────              ───────────────           ─────────────────────────────────
ClaudeProvider  total_input_   findings, summary,        engine, fallback_used,
  tokens += usage.input_tokens mode, model, warnings,    review_state, counts…
  (ai/claude.py:328-329)       engine, fallback_used,    (reporter.py:138-153)
  total_output_tokens          batch_count
  (ai/claude.py:200-201)       (models.py:292-307)
        │                             │                          ▲
        │  ── NOT COPIED ──►          │  ── NO TOKEN FIELD ──────┘
        ▼                             ▼
OpenAIProvider  total_*        GeminiProvider: usage NOT PARSED at all
  (ai/openai.py:39-40,158-159) (ai/gemini.py:159 — "could add if needed" TODO)
```

- `AnalysisOutcome` (`models.py:292-307`) has **no** usage/latency/cost fields —
  `findings, summary, mode, model, warnings, engine, fallback_used, batch_count`.
- Report JSON (`reporter.finalize_report`, `reporter.py:138-153`) carries none
  either; storage and `/api/metrics` (`dashboard/app.py:657`) therefore show
  report/finding counts only, never spend.
- The only consumer of the counters is the **legacy facade**
  `analyzer.py:129-134` (`total_input_tokens` passthrough), which has no
  production caller (`CURRENT_ARCHITECTURE.md` §3, D11).
- Consequence: today **no number in this document except §1.2 is measured.**

### 1.2 Budgets are characters, mislabelled as tokens (C7)

| Knob | Value | Where | Unit |
|---|---|---|---|
| `batch_chars` / `DEFAULT_TOKEN_BUDGET` | 80,000 | `config.py:78`, `context.py:33` (name says *token*) | characters |
| `repo_context_chars` | 12,000 | `config.py:99` | characters |
| `review_mode → max_tokens` | economy 2,048 · balanced 4,096 · maximum 8,192 · automatic 4,096 | `model_router.py:57-60` | output tokens (real tokens — completion cap only) |
| Comment/finding caps | 20 comments, 500 dashboard findings, 8 context files, 50 memory rows | D13 | items, not tokens |

The two budgets are independent and **never summed** — context assembly can
send 80k chars of diff + 12k chars of repo context with no global view (C7).
`review_mode` caps output tokens only; input cost is uncontrolled.

### 1.3 No cost model anywhere
No price table, no per-model cost, no per-review total, no budget enforcement,
no hard stop. Failover (primary → secondary → static) has **no cost accounting**:
a run that burns 3 retries on Claude then switches to OpenAI reports nothing.
Constraint C6 states the consequence: no basis for budget arbitration,
review-depth control, or cost dashboards.

---

## 2. Design principles

1. **Measure before you manage** (vision §5-V): nothing gets a cost control
   until V3-E02 telemetry exists. Optimization without measurement is guessing.
2. **Bounded everything** (vision §3.6): every loop that can spend tokens —
   batches, agents, retries, judge runs — takes an explicit budget parameter.
3. **Free path stays free**: `--mock` / static engine / sandbox must never
   acquire a token cost (vision §3.7, §7).
4. **Never silently degrade** (vision §6): no optimization may drop
   security/correctness context without visible attribution (§5 table).
5. **Telemetry contains no code** (privacy): counts, ids, durations — never
   diffs, findings text, or file contents (§3.4).

---

## 3. Telemetry spine — V3-E02 (foundation for everything else)

### 3.1 What to capture (one record per provider call + one per run)

```
ReviewTelemetry (per run)                    CallTelemetry (per provider/batch call)
─────────────────────────                    ──────────────────────────────
run_id, repo, pr_number (no code)            call_index, batch_count_total
engine, backend, model, review_mode          provider, model
depth / risk label (V5-E04)                  input_tokens, output_tokens   ← dead today
duration_ms (exists: models.py:248)          duration_ms                    ← new
batches_total, batches_static                retries, http_status_class     ← new
fallback_used, fallback_reason               circuit_state (open/half/closed) ← new
static_attribution ("not an AI review")      cost_estimate_usd (from price table)
context_chars_sent, context_omitted_files    truncated: bool (attribution §5)
github_calls, github_rate_remaining (C8)     error_class (timeout/429/5xx/parse)
```

Capture points (current code): provider `analyze()` return path
(`ai/claude.py`, `ai/openai.py`, `ai/gemini.py` — parse Gemini usage per its
TODO at `ai/gemini.py:159`), `model_router.run_analysis` (retry/failover
decisions, `model_router.py`), `context.build_context` (chars sent/omitted),
`cli.py` run boundary (review-level rollup).

### 3.2 Where it flows

```
provider.analyze() ──► AnalysisOutcome  (+ NEW: usage, call_telemetry)
      │                     │
      │                     ▼
      │            reporter.finalize_report  ──► review-report.json  (+ "telemetry" block)
      │                     │                            │
      │                     ▼                            ├─► $GITHUB_OUTPUT (cost_summary opt-in)
      │            storage.save_findings /                └─► dashboard POST /api/reports
      │            new: storage.save_telemetry                    │
      │                                                           ▼
      └──────────────────────────────────────► dashboard DbStorage: telemetry rows
                                                     │
                                                     ▼
                                        GET /api/metrics  (+ tokens, cost, latency,
                                        fallback, p50/p95 series) ──► SPA metrics tab
```

Field extension is **backward-compatible**: new keys appended to
`AnalysisOutcome`/report JSON (the way `PRContext.base_sha` was appended —
`models.py:225` keeps it last for JSON-shape reasons); older dashboards ignore
unknown keys. `ReviewStorage` protocol gains an optional `save_telemetry`
capability reached via the same `getattr`-guard pattern used for
`get_dismissed_fingerprints` (§10.3 of CURRENT_ARCHITECTURE) until ADR-011
formalizes it.

### 3.3 Roll-up layers
per batch → per review (JSON `telemetry` block) → per repo (storage rows) →
per dashboard (`/api/metrics` series) → per org (V9-E07, multi-repo).

### 3.4 Privacy note (normative)
Telemetry rows may contain: provider, model, counts, durations, status classes,
booleans, opaque run/report ids, repo slug (already present everywhere).
Telemetry rows **may not** contain: diffs, file contents, finding titles/
explanations, prompt text, memory notes, tokens/secrets. Enforced by a
serialization chokepoint (single `to_telemetry_row()` function — likely module
in a new `ai_pr_reviewer/telemetry.py`) plus a security-layer test (L5) that
scans telemetry fixtures for diff-like content. Redaction
(`security.redact_secrets`) runs before persistence as defense in depth.

---

## 4. Control surfaces (what actually moves the number)

### 4.1 Context budgets (per-source table)

Target: one summed budget per batch instead of independent character knobs (C7).
Estimator: `tokens ≈ chars / 4` — a heuristic, explicitly **not** a tokenizer
(**proposed baseline** until real tokenizer dependency is justified; keep
`requirements-action.txt` lean).

| Source | Today | Proposed per-batch budget | Quality class |
|---|---|---|---|
| System prompt + policy + fences | shared, unmeasured | 4,000 tok | fixed |
| PR diff (trimmed by `batch_chars`) | 80,000 chars | 20,000 tok (≈80k chars — parity) | core |
| Repo context (8 files) | 12,000 chars | 3,000 tok (≈12k chars — parity) | supportive |
| Previous findings / lifecycle | unbounded-ish (cap 500 dashboard / 20 posted) | 3,000 tok | core |
| Memory notes + focus | 50 rows | 2,000 tok | supportive |
| **Total per batch** | not summed (C7) | **32,000 tok input** | — |
| Output cap | economy 2,048 / balanced 4,096 / maximum 8,192 | unchanged (existing tiers) | — |

All figures **proposed baselines**. Rationale for parity-with-today on diff and
repo context: Phase 0 must not change model-visible behavior; only the *summing*
is new. Over-budget resolution order: supportive sources trim first **with
attribution warning** (§5); core sources trim last and only under the hard stop
(§4.7).

### 4.2 Caching
| Cache | Hit condition | Saving | Risk |
|---|---|---|---|
| Repo index cache (V4) | unchanged path since last indexed SHA | re-reads of repo files (C8 GitHub calls + tokens) | stale index → must be SHA-keyed and revalidated per run |
| Stable prompt prefix | system prompt + policy identical | provider cache-read pricing where offered (Claude/OpenAI prompt caching) | policy change must invalidate; cached prefix must stay trusted-side only |
| Report/context memo within a run | same batch re-assembled on retry | retries re-send identical input tokens | invalidate on any context mutation |

No cross-run caching of *model output* — output is a judgment call bound to a
specific diff; reusing it is stale review (vision §3.1).

### 4.3 Deduplication / incremental
- Incremental diff already exists (`orchestrator` gate →
  `compare_commits(last_sha, head_sha)`) and is the single biggest cost cut:
  **only changed hunks are analyzed**. Keep `last_reviewed_sha` semantics.
- Extend the same idea to **context**: skip re-analyzing unchanged hunks within
  a force-push retry (same base, moved head → diff the diffs).
- Prior findings are re-sent as compact identity rows (fingerprint, file, title,
  state) — never full payloads (D13 caps already bound this).

### 4.4 Model routing / capability matching (→ V5 capability registry)
- Right-size model per task: cheap model for style/summarize batches, capable
  model for security/correctness judgment; static rules for anything
  deterministic (vision §3.2 — identity/lifecycle/verification never spend
  tokens at all; they already don't).
- Routing inputs: task kind, PR risk (V5-E04), batch category, provider price,
  circuit state. Router is `model_router` grown in place (keep the
  `AIProvider` seam — ADR-007).
- Guardrail: routing decisions are logged in telemetry (`model`,
  `review_mode`, `reason`) so a "cheap" route can be audited for quality loss
  by the evaluation harness (V5-E08 correlates route → precision/recall).

### 4.5 Review depth (link V5-E04 adaptive depth)
Depth presets (shallow/standard/deep) map to: batch scope, model tier, max
batches, repo-context depth. Depth selection is **explainable** (risk features
listed in telemetry, vision §3.1) and informational until proven — never
auto-deepen (cost runaway) nor auto-shallow on security-relevant surfaces.

### 4.6 Specialist activation gates (V5+)
Specialist agents (security, performance, docs…) activate **only when**
risk/context justifies: e.g. security specialist when touched paths match
sensitive globs or diff contains sinks; perf specialist on algorithmic files.
Gate table lives in config (review policy), default conservative. Each
activation costs tokens → gate decisions are telemetry events so we can measure
"wasted activations" (specialist ran, contributed zero findings).

### 4.7 Failover cost accounting + per-review hard stop
```
per-review budget (tokens in + tokens out)   default: 120,000 tok — proposed baseline
        │
        ├─ call succeeds → account (input, output, retries) → continue
        ├─ 429/5xx → retry ×3 (existing retry.py) → account attempts
        ├─ provider fails over → account spent tokens under
        │    from_provider, attribute remaining work to to_provider
        └─ budget exhausted ──► HARD STOP: no further AI calls
                                remaining batches → StaticProvider
                                report carries static_attribution:
                                "review token budget exhausted after k of n
                                 batches; m analyzed deterministically"
                                (truthful-fallback invariant, §13.5)
```
Hard stop is **per review run**, not per repo; operators raise it via config.
Static fallback attribution already exists (`fallback_used`,
`engine="static"`, "not an AI review" footer — `reporter.py:142-146`); the new
part is *budget* as a first-class `fallback_reason` and per-batch partial
fallback (today static fallback is per-batch inside providers, but has no
cost-reason recorded).

---

## 5. Optimization table (normative)

| Optimization | Safe / quality-risking | Guardrail |
|---|---|---|
| Incremental diff (skip unchanged commits) | **Safe** | force-push → full diff fallback (exists); withhold SHA on degraded runs (exists) |
| Trim supportive sources (repo context, memory, focus) before core diff | Safe *if attributed* | warning emitted: `"context truncated: N files omitted due to budget"` — precedent `repo_context.py:292-296` ("skipped N candidate file(s)") and `context.py:98-99` ("dropped {path} entirely") |
| Summed per-batch budget (C7 fix) | Safe | trim order fixed (§4.1); core last |
| Prompt-prefix caching | Safe | SHA/policy-keyed invalidation; trusted-side prefix only |
| Cheaper model for style/summary batches | **Quality-risking** | routing logged; harness must show recall delta ≤ **proposed 3 pp** on style corpus before defaulting |
| Shallow depth on low-risk PRs (V5-E04) | **Quality-risking** | risk features explicit in report; user override always wins; security surfaces exempt from shallow |
| Fewer repo-context files under budget pressure | **Quality-risking** (could hide a definition the finding needs) | never drop files that *contain flagged symbols* (V4 index makes this checkable); attribution warning mandatory |
| Skip specialist activation when gate says no | **Quality-risking** | gate thresholds config-visible; false-gate rate tracked (§4.6); security specialist gate is conservative-by-default |
| Reduce batch size to fit context window | Safe (more calls, same content) | watch total-call cost — smaller batches can *increase* tokens; telemetry must show net effect |
| Output cap reduction (economy 2,048) | **Quality-risking** (truncated JSON → parse failures → silent static fallback) | count `_extract_json` failures per mode; alarm if economy mode raises parse-fail rate (threshold **proposed**: > 2% of batches) |
| **Silently dropping security/correctness context** | **FORBIDDEN** (vision §6) | never; any omission of flagged-symbol files or security surfaces requires the visible attribution warning above + report `warnings[]` entry |

Partial precedent for attribution already in code: `context_warnings`
(`context.py:217`), `_TRUNCATED_MARKER` (`repo_context.py:76`), budget-skipped
file warnings. What's missing: those warnings reaching the *report JSON /
step summary* consistently (today they ride `memory_notes`/`context_warnings`,
D10-adjacent) — V3-E02 must pipe them into `AnalysisOutcome.warnings`.

---

## 6. Cost budget model per stage — all **proposed baselines**

Per-review ceilings (input+output tokens, AI path only; static/`--mock` = 0).
These are *starting guesses* to be replaced by V3-E02 percentiles after one
month of data.

| Stage | What changes cost | Per-review budget (proposed) | Notes |
|---|---|---|---|
| Phase 0 / V3.x | telemetry only — no behavior change | 120,000 tok | measure first; ship the hard stop (§4.7) with the number above |
| V4 repository intelligence | index build amortized per repo + retrieval context | 150,000 tok/run; index rebuild capped at 300,000 tok/month/repo | index cache (§4.2) is the offset; reindex triggered by SHA delta only |
| V5 multi-agent review | N agents × fan-out | 300,000 tok/run hard cap; per-agent 60,000; V5-E07 arbitrates | bounded fan-out is a *shipping requirement*, not a nicety (C1/C5); council must fit budget or degrade to fewer agents **with attribution** |
| V6 security/testing/architecture intelligence | security specialist + test-evidence runs | 350,000 tok/run | security specialist gate (§4.6) keeps median well below cap |
| V7 historical/team intelligence | git/issue history summarization over time windows | 250,000 tok/run; history queries cached by (repo, window, policy version) | query planner bounds window size |
| V8 CI/release/incident | CI log + release note ingestion | 400,000 tok/run | logs are bulky → deterministic pre-filter before any model call |
| V9 organization platform | org-wide rollups, cross-repo policies | budget moves to **per-org monthly** envelope: 5,000,000 tok/month/org (proposed) with per-run caps still enforced | dashboards (V9-E07) enforce/visualize the envelope |
| V10 ecosystem/platform | plugin-provided agents | plugin declares its budget request; org admin approval required; engine enforces | unbudgeted plugin calls rejected (ADR-009) |

Illustrative USD only (prices change; do not treat as data): 120k tok ≈
$0.30–0.60 on mid-tier models, ≈ $0.03–0.08 on small models — order-of-magnitude
guidance, **proposed baseline**; the price table behind
`cost_estimate_usd` lives in config, not hardcoded per provider (cf. retired-
model-ID discipline: no hardcoded provider-specific constants in engine logic).

Evaluation-harness budgets (`TESTING_EVALUATION_PLAN.md` §2): nightly AI eval ≤
500,000 tok/day, weekly benchmark ≤ 2,000,000 tok/run — **proposed baselines**;
enforced by the harness's own `--budget-tokens` flag (hard stop, not advisory).

---

## 7. OSS / free-path requirements (non-negotiable)

1. **Static engine stays free**: `--mock`, `--static`, sandbox, and the
   deterministic layers of the harness cost zero tokens.
2. **Small defaults**: default budgets above are ceilings, not targets;
   typical small-PR runs should land far below (target: median run ≤ 40,000
   tok — **proposed baseline**).
3. **No telemetry phone-home**: telemetry lands in the user's report JSON,
   their SQLite/dashboard, their artifact — never an endpoint we control
   (vision §7, privacy baseline). Aggregate numbers only exist where the user
   points them (e.g. their own dashboard).
4. **Dashboard shows spend**: metrics tab gains tokens/run, cost/run,
   fallback rate, budget-exhaustion events (V3-E02 fields → `/api/metrics`);
   badge (`/api/badge/...`) may show "cost-aware" state but never spend
   amounts publicly.
5. **Zero-key onboarding path unchanged**: a new user with no API keys gets
   full local functionality (engine + dashboard + all deterministic eval
   layers) — cost features must never become a reason the free path degrades.

---

### Cross-references
Telemetry consumers: `TESTING_EVALUATION_PLAN.md` (§4 metrics) ·
Decisions: `ADR_INDEX.md` (ADR-014, ADR-007 provider abstraction, ADR-011
storage) · What not to build yet: `DO_NOT_BUILD_YET.md` (tracing stack,
multi-tenant billing) · Order: `MASTER_ROADMAP.md`, `EPIC_BACKLOG.md`
(V3-E02 first, V5-E07 second, V9-E07 third).
