# ARCHITECTURE EVOLUTION — V3 → target, without a rewrite

> Status: planning document (v1) — describes repo state at commit `2841b23`
> (`CURRENT_ARCHITECTURE.md`, verified 2026-10-03). This file defines *how the
> current code turns into* `TARGET_ARCHITECTURE.md` stage by stage. It changes
> no code; future modules are named as **likely modules** / **new subsystems**.

---

## 1. Guiding philosophy

**CURRENT V3 CORE → foundation → gradually surrounded by intelligence layers →
migrate only when necessary.**

Concretely, five rules:

1. **The V3 core is not a prototype to discard.** The keep-list in
   `CURRENT_ARCHITECTURE.md` §14 (`diff_parser`, `findings`, `verification`,
   `security`, `rules`, `retry`, `circuit` semantics, `github_sync`,
   `reporter`, `static/`, `models`, config layering, the Action contract, the
   hermetic suite) is the foundation every later stage stands on. Nothing in
   this plan rewrites it.
2. **Grow by surrounding, not by replacing.** New capability = new subsystem
   wired at an existing seam (`ReviewStorage`, `AIProvider`,
   `ReviewOrchestrator.run()`, the report JSON), reached through the contracts
   in `TARGET_ARCHITECTURE.md` §7.
3. **Structure follows measurement.** Phases B/C of `TARGET_ARCHITECTURE.md`
   enter only on the measured triggers §6 there; Phase 0's telemetry spine is
   what makes those measurements possible (constraint C6).
4. **Contracts before components.** When a stage needs two things to agree, the
   contract is written (and versioned additively) in the *same* change that
   introduces the first producer — never retrofitted.
5. **Degrade, don't block.** Every new layer keeps the invariant in
   `CURRENT_ARCHITECTURE.md` §13.6: storage/GitHub/dashboard/provider failures
   produce warnings and fallbacks, never a lost review. A new subsystem that
   can take a review down has been wired wrong.

Anti-rewrite is operationalized as: *strangler moves* (move code, re-export old
import paths until tests and callers are updated), *additive schema change only*
(`TARGET_ARCHITECTURE.md` §7.1), and *dual-read periods* for any contract that
must eventually change shape.

## 2. Stage-by-stage structural deltas

Columns: **New** = subsystem that appears; **Grows from** = the existing module
it is seeded from; **Untouched** = deliberately not modified in that stage;
**Contract changes** = additive-only unless flagged.

### 2.0 Summary table

| Stage | New subsystem (likely module / new) | Grows from (today) | Untouched | Contract changes |
|---|---|---|---|---|
| **Phase 0 / V3.x** | telemetry spine (new, likely `telemetry` package); evaluation harness (new, test-side only) | provider usage counters (`ai_pr_reviewer/ai/claude.py`, `ai/openai.py` `total_input_tokens`/`total_output_tokens`), `/api/metrics`, `dashboard` audit log | all review logic except defect fixes | report JSON gains `schema_version: 1` *(proposed baseline)* + declared `risk`/`verification` fields (constraint D10 serialization) — additive-only; fix D1–D7 are behavioral fixes inside existing contracts; `config.py` numeric parsing gains clean exit-1 (D6) |
| **V4** | deterministic repo index; context engine v2 (provenance); change impact analysis; evidence engine (V4-E04); finding identity v2 (V4-E05); seed digital-twin projection (layered index) | `repo_context.py` (bounded fetch → index queries), `context.py` (budget → artifact system), `findings.py` (fingerprint → identity v2), `storage.py` (payload rows → evidence storage) | `static/` rule packs, `rules.py` baseline, `github_sync.py`, `reporter.py` output shape (beyond additive fields), Action inputs | `Finding` gains provenance fields (additive, pipeline-owned); `ReviewStorage` gains capability set + evidence/context methods (additive); report JSON carries evidence/provenance pointers (additive) |
| **V5** | bounded specialist fan-out; finding merger with provenance-aware dedup; risk engine v1; adaptive review depth; provider capability registry; cost arbitration; council synthesis | `orchestrator.py` (`ReviewOrchestrator.run` gains a fan-out stage), `model_router.py` (routing → registry + task routing), `findings.deduplicate` (title-match → provenance-aware merge), telemetry spine | `diff_parser.py`, `verification.py`, `security.py`, `rules.py`, sync/anchoring, storage schema shape | provider contract declares capabilities + usage reporting (`TARGET_ARCHITECTURE.md` §7.2); `AnalysisOutcome` gains usage/cost/latency fields (additive); `ReviewResult` declares risk/verification formally; breaker semantics become per-instance *before* any concurrency (C5) |
| **V6** | security engine (dedicated); AI security v2; test intelligence; architecture intelligence; advanced verification tiers; dependency intelligence; policy engine v1 | `security.py` + `static/security_rules.py` (fence/redact → engine), `verification.py` (coverage check → tiers), `rules.py` (parser → evaluation), `static/test_rules.py` (seed of test intelligence) | identity/lifecycle core, memory, sync, Action contract | `PolicyEvaluation` record (new data contract, additive); `Verification` gains tier enum (unknown-tolerant); security/architecture findings ride the Finding payload (no schema fork — `DATA_MODEL.md` §3) |
| **V7** | git history intelligence; memory hierarchy with authority model (ADR-003); finding relations (V7-E03); issue/requirement linkage; team analytics (no individual rankings); memory security | `memory.py` + `repo_memory` tables (flat → scoped hierarchy), `findings.py` identity v2 (anchor for relations), `repo_context`-style bounded reads over git history | `static/`, policy evaluation, providers, sync, report shape | `MemoryEntry` gains scope/authority/origin fields (additive, authority model enforced in code); `FindingRelation` new entity + storage method (additive); memory writes require explicit authority class — engine still writes nothing |
| **V8** | CI ingestion/correlation (V8-E01); release risk; docs intelligence; infrastructure intelligence; read-only incident intelligence; **internal event platform v1** (ADR-008) | `github_client.py`/`ingest` (PR events → CI events), telemetry spine (metrics → event envelope), storage (rows → outbox) | inline Action path (default), review pipeline semantics, report contract | event envelope schema fixed (`TARGET_ARCHITECTURE.md` §7.4) — first *versioned* schema; `CIResult` entity + storage methods (additive); no queue required to run |
| **V9** | multi-repo/org model; org policy (ADR-003 inheritance); versioned public API (V9-E03); event-driven workers *where justified*; org memory; extensibility contract v1; observability platform | `dashboard/app.py` routes (dashboard API → versioned public API), `rules.py` (repo policy → org scope), storage (single-repo keys → org-scoped keys) | engine internals, inline Action path, provider contract | API versioning begins (`schema_version` in HTTP responses); org scope added to policy/memory keys (additive with derived defaults — org = `owner/` prefix until then); extensibility contract v1 published (no consumers yet) |
| **V10** | sandboxed plugin system; provider capability ecosystem incl. optional local providers; optional hosted multi-tenant foundation (ADR-010); IDE/CLI ecosystem; org-scale analytics; engineering command center | extensibility contract (V9 → runtime), capability registry (V5 → ecosystem), `static/` rule-pack tuple (internal wiring → community surface) | core lifecycle/identity/verification/security code (stays reviewed-in-house per vision §7) | plugin contract (sandboxed; output enters as evidence, never as state); multi-tenant data scoping (ADR-010); analytics read-only projection contract |

### 2.1 Stage notes (the deltas that carry risk)

**Phase 0 / V3.x — hardening, no features.** Fix verified defects D1–D7
(`github_client.py` base_sha population; verification fed the uncapped finding
set; below-threshold suppression accounting; `max_comments` scope vs
`action.yml`; severity sort for AI findings; `config.py` numeric errors;
`dashboard/storage.py` mute idempotency). Stand up the telemetry spine and the
evaluation harness. This stage touches *behavior inside existing contracts* —
its architectural product is the measurement baseline that all later triggers
(`TARGET_ARCHITECTURE.md` §6) depend on. Nothing is added to `action.yml`.

**V4 — the first real contraction of `repo_context.py`.** The bounded 8-file
fetch and the character budgets (C7) are not deleted; they become the *fallback
path* of the context engine v2, which is the established degradation pattern
(this repo already falls back full-diff → static → empty-context). The repo
index is a **deterministic projection** of repository content — no graph DB
(ADR-002), no separate twin service (vision §4-D: the twin is the accumulating
projection, not a system). Identity v2 (V4-E05) must land *before* V5's merger,
because provenance-aware dedup has nothing to merge without stable identity
(C3/C4) — this is the single hardest sequencing constraint in the plan
(`DEPENDENCY_GRAPH.md`).

**V5 — fan-out only after breakers and usage reporting are per-instance.**
Today's process-global, sequential-only breakers (C5) and unreported token
usage (C6) make concurrent specialist calls unsafe and unaffordable. The
orchestrator's `run()` signature does not change; fan-out is internal, bounded
(a proposed baseline: ≤ 6 specialist calls per review, marked **proposed
baseline**), with static-first determinism preserved for anything that is
cheaper as a rule (vision §5-F).

**V6 — policy engine grows from `rules.py` evaluation, not a new language.**
The `.ai-pr-reviewer.yml` schema stays the authoring surface; the engine adds
explainable `PolicyEvaluation` records. Security, test, architecture and
dependency intelligence all emit **Findings** with categories/provenance — no
parallel finding stores (avoids a fourth storage implementation).

**V7 — memory authority is a code-enforced gate, not metadata decoration.**
`memory.py` today is human-authored and engine-read-only; the hierarchy
(org▸team▸repo▸component▸PR) adds authority classes such that AI-derived
observations can never become permanent truth automatically (vision §3,
ADR-003). Relations (V7-E03) are only possible because identity v2 landed in
V4; team analytics reads projections only and ships **no individual rankings**
(vision §6 — product invariant, not a config option).

**V8 — event *platform* arrives; the event *contract* should already exist.**
The envelope schema (`TARGET_ARCHITECTURE.md` §7.4) is written before the
platform so that V5/V6/V7-era records can already be emitted as event-shaped
documents where cheap. The platform starts as an outbox table + poller inside
the monolith (Phase A), with the queue (Phase B) entering only on triggers
B1–B4. Incident intelligence is retrospective and read-only.

**V9 — versioning becomes public.** The dashboard's ~24 routes are the seed of
the versioned API (V9-E03); versioning rules from `TARGET_ARCHITECTURE.md`
§7.1 apply to HTTP responses from day one of the public API. Org scope enters
as *derived* keys (repository `owner/` prefix) promoted to real rows
(`DATA_MODEL.md` §Organization). Event-driven workers only where the V8/V9
measurement shows inline execution insufficient.

**V10 — contracts ship before runtimes.** The plugin contract (V9) is published
with zero plugins; the plugin host is a new security boundary whose output is
treated exactly like model output (untrusted, screened, evidence-only —
vision §3.3). Optional hosted multi-tenant is explicitly a *future option*
(vision §7), not an obligation.

## 3. Reusable foundations — built once, consumed later

| Foundation | Lands in | First consumer | Later consumers | Current seed |
|---|---|---|---|---|
| **provenance record** (engine, model, agent, revision, evidence pointers per artifact) | V4 (with V4-E04 evidence / V4-E05 identity) | evidence engine + identity v2 | V5 council merge & dedup, V6 evidence tiers, V7 finding relations, audit/observability (V9), plugin output attribution (V10) | none today — `Finding` has no provenance fields (C3); `AnalysisOutcome.engine`/`model` are the partial seed |
| **context artifact + budget system** (bounded, provenance-tracked context pieces) | V4 (context engine v2) | PR context assembly | V5 adaptive depth, V6 verification tiers (test/CI evidence in context), V7 history context, V8 CI context, V9 API context exports | `context.py` budgets (`DEFAULT_TOKEN_BUDGET`, `_apply_context_budget`) + `ReviewContext` |
| **event envelope schema** (versioned, immutable, at-least-once) | spec in Phase 0/V4-era records; platform V8 | `review.completed` / `ci.result` events | V9 webhooks + org events, V10 analytics backbone, plugin events | telemetry spine records (Phase 0) are event-shaped docs |
| **storage migration framework** (single schema + ordered migrations, replaces hand-rolled `ALTER TABLE`) | Phase 0/V4 (first schema additions force it) | evidence/context tables | every entity through V10; Postgres promotion (ADR-011) | `LocalReviewStorage._init_db` tolerated `ALTER TABLE` loop; `dashboard/storage.py` hand-rolled columns |
| **provider capability registry** (declared capabilities, usage reporting, cost table) | V5 | specialist task routing + cost arbitration | V6 context-window awareness, V7–V8 depth/cost controls, V10 local providers & ecosystem | `model_router.AI_BACKENDS`/`select_backend` heuristic + per-provider usage counters |
| **policy evaluation interface** (`evaluate(policy, subject) → explainable result`) | V6 | repo/team policy engine | V9 org inheritance (ADR-003), V10 plugins reading policy, dashboard explainability | `rules.py` `ReviewPolicy` + effective-threshold resolution in `orchestrator.py` |
| **telemetry spine** (usage, latency, fallback events; drop-safe) | **Phase 0** | measurement + defect diagnosis (V3-E02) | all `TARGET_ARCHITECTURE.md` §6 triggers, V5 arbitration, V6+ cost dashboards, V9 observability, V10 command center | provider `total_input_tokens`/`total_output_tokens` counters (unreported), `reporter.py` `duration_ms`, `/api/metrics` |

Reading rule: a stage may not consume a foundation that has not landed. That is
the whole point of the table — it converts "we'll need provenance eventually"
into an ordering constraint with a named owner.

## 4. Sequencing rationale

1. **Phase 0 before everything.** Defects D1–D7 corrupt the very signals later
   stages trust (false resolution from D2, mis-scoped counts from D3/D4, lost
   severity ordering from D5), and telemetry is the measurement base for every
   structural trigger. Building intelligence on top of known-wrong lifecycle
   semantics would bake the errors into the data model.
2. **Identity (V4-E05) before evidence-consuming merge (V5) before relations
   (V7-E03).** Merge without stable identity duplicates comments (the documented
   C4 gap); relations without identity have nothing to anchor to. This chain is
   the spine of `DEPENDENCY_GRAPH.md`.
3. **Evidence (V4-E04) before advanced verification (V6) and CI correlation
   (V8).** Tiers and correlations are *queries over evidence records*; there is
   nothing to query before V4.
4. **Telemetry (Phase 0) before cost arbitration (V5) before cost dashboards
   (V6+)** — nothing can be managed that is not measured (vision §5-V).
5. **Memory hierarchy + authority (V7) before org memory (V9).** Authority
   rules must exist before the blast radius grows to an organization
   (ADR-003).
6. **Event schema before event platform (V8) before queue (Phase B/V9).**
   Schemas are cheap and versioned; transports are operational commitments.
7. **Versioned API (V9) before plugins (V10) before hosted multi-tenant
   (V10, optional).** Extensibility contract must be stable enough that third
   parties can bind to it (`DO_NOT_BUILD_YET.md` gates the runtime).
8. **Storage consolidation before any new storage backend or split**
   (ADR-011): three duplicate implementations must become one logical schema
   before Phase B's shared-storage requirement can hold.

## 5. Anti-patterns — what we explicitly refuse

| Anti-pattern | Why it fails here | The correct move |
|---|---|---|
| Dashboards/widgets before data contracts | renders today's unserialized `risk`/`verification` (D10) and unmeasured usage (C6) as pretty lies | additive report fields + telemetry spine first (Phase 0) |
| Plugins/extension runtime before stable contracts | third parties bind to internals; every refactor breaks them | contract-first at V9, runtime at V10 (`DO_NOT_BUILD_YET.md`) |
| Microservices / queue before measured triggers | destroys hermetic tests, violates "never lose a review", no pain to solve | Phase A until trigger B1–B4 (`TARGET_ARCHITECTURE.md` §6) |
| Event bus before event schema | bus full of unversioned payloads becomes permanent debt | freeze envelope first; transport later (ADR-008) |
| Graph DB / separate twin service before query evidence | aspiration-driven modeling (ADR-002) | deterministic index + projections; revisit graph storage only when a query cannot be served relationally |
| AI-written permanent memory before authority model | model output becomes organizational truth (vision §3 violation) | V7 authority gate (ADR-003); engine keeps write-free memory |
| New finding store per intelligence type (security/test/architecture) | creates storage implementation #4; identity/lifecycle fork | all intelligence emits `Finding` with category + provenance (`DATA_MODEL.md` §3) |
| Parallel rewrite of `orchestrator.py` "while we're at it" | the composition root is where every invariant is enforced; rewrite = regression guarantee | strangler steps at existing seams; keep `run()` contract |
| Cost features before usage telemetry | nothing to arbitrate (C6) | Phase 0 spine → V5 arbitration |
| Org/individual analytics before privacy stance | risk of individual rankings creeping in | analytics are projection-read-only; no rankings is a product invariant (vision §6) |
| Retention added without lifecycle awareness | pruning `finding_history` turns a returning finding from `active` into `new` and can re-post comments | retention windows must exceed open-PR lifetime and be approved against lifecycle behavior (`DATA_MODEL.md` §6) |

---

### Cross-references

Target shape: `TARGET_ARCHITECTURE.md` (phases A–D, contracts §7, triggers §6).
Data consequences: `DATA_MODEL.md` (entity arrival stages, retention). Order:
`DEPENDENCY_GRAPH.md` (esp. identity→evidence→merge→relations chain),
`MIGRATION_PLAN.md` (backward-compat mechanics, Action contract), and
`MASTER_ROADMAP.md` / `V4_V10_ROADMAP.md` / `EPIC_BACKLOG.md` (epic IDs cited:
V3-E01..E06, V4-E04, V4-E05, V7-E02, V7-E03, V8-E01, V9-E03). Decisions:
`ADR_INDEX.md` — ADR-001 (modular monolith), ADR-002 (derived deterministic
index), ADR-003 (memory authority), ADR-006 (bounded fan-out — V5 row),
ADR-008 (events before queues — V8 row), ADR-009 (plugin contract timing —
V10 row), ADR-010 (multi-tenancy as boundary), ADR-011 (storage evolution).
Ground truth: `CURRENT_ARCHITECTURE.md`. Vision/invariants: `MASTER_VISION.md`.
Refusals: `DO_NOT_BUILD_YET.md`.

**Flagged uncertainty:** `EPIC_BACKLOG.md`, `DEPENDENCY_GRAPH.md` and
`MIGRATION_PLAN.md` were not yet in the tree when this document was written
(ADR titles above verified against `ADR_INDEX.md`); epic IDs cited here come
from the engagement brief — verify against `EPIC_BACKLOG.md` when it lands.
