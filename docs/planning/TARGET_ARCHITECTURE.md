# TARGET ARCHITECTURE — Long-term design (Phase A → D)

> Status: planning document (v1) — describes repo state at commit `2841b23`
> (`CURRENT_ARCHITECTURE.md`, verified 2026-10-03). Forward-looking sections
> describe intent, not existing code. Where a future file/path is named it is a
> **likely module** or **new subsystem**, never a committed file structure.
> Companion documents: `ARCHITECTURE_EVOLUTION.md` (stage deltas),
> `DATA_MODEL.md` (entities), `MASTER_VISION.md` (why), `CURRENT_ARCHITECTURE.md`
> (what is true today). ADRs cited are listed in `ADR_INDEX.md`; the do-not-build
> list is `DO_NOT_BUILD_YET.md`.

---

## 0. Scope and reading order

This document answers: *what does the system look like at the end, how is it
decomposed, what contracts hold it together, and what triggers each structural
change?* It does not say **when** — that is `MASTER_ROADMAP.md` /
`V4_V10_ROADMAP.md` — nor in what order code moves — that is
`ARCHITECTURE_EVOLUTION.md`.

Two independent structures must not be confused:

1. **Capability stages** (canonical): Phase 0/"V3.x" → V4 → V5 → V6 → V7 → V8
   → V9 → V10. These are *what the product can do*.
2. **Deployment/architecture phases** (this document): **A** modular monolith →
   **B** worker/queue separation → **C** service separation → **D**
   organization-scale platform. These are *how the code is packaged and run*.

They are intentionally **not 1:1**. Phase A is the home of Phase 0 through most
of V7; B/C/D enter only on measured triggers (§6). A capability stage may be
delivered entirely inside Phase A.

## 1. Design stance

**The default answer is: modular monolith, one Python process, pip-only, no
infrastructure required.** This follows ADR-001 (modular monolith), the
no-rewrite principle (`MASTER_VISION.md` §3.5) and the stable assumptions in
`CURRENT_ARCHITECTURE.md` §13. The current system already has clean dependency
direction (`models`/`security`/`retry`/`circuit` are leaves;
`orchestrator.py` is the composition root) — the work is to *formalize* those
seams as named packages with declared contracts, not to invent new ones.

**Do not jump to microservices.** A distributed version of this system is
strictly worse until measured pain proves otherwise: it multiplies the failure
modes that `CURRENT_ARCHITECTURE.md` §13.6 forbids (a review must never be lost
to I/O failure), it destroys the deterministic test suite's hermeticity, and it
forces the storage/provider contracts to be perfect *before* we have evidence of
what they need to be. Every phase below carries its own entry criteria; the
criteria are measurements, not aspirations (§6).

### Phase overview

| Phase | Home stages | Shape | Enters when |
|---|---|---|---|
| **A** — modular monolith | Phase 0, V4–V7 (default through V8) | one engine process + optional dashboard process; package boundaries with in-process contracts | now (already the current shape) |
| **B** — worker/queue separation | V8–V9 capability work can live in A or B | long-running review jobs move behind a queue; dashboard/API and Action stay responsive; ADR-008 | measured concurrency/latency triggers (§6) |
| **C** — service separation | V9 | ingress/gateway, review workers, intelligence/index builder, API split into separately deployable services over the same contracts | measured scaling/isolation triggers (§6) |
| **D** — organization-scale platform | V10 | org API, event backbone, sandboxed plugin host, observability platform, optional hosted multi-tenant (ADR-010) | org platform is an approved product (V9/V10 gates) |

**Contract rule that spans all phases:** the GitHub Action keeps working
end-to-end with *zero* infrastructure — no queue, no services, no Postgres — in
every phase, including D. Distributed paths are opt-in accelerators, never
prerequisites (`MIGRATION_PLAN.md`).

---

## 2. PHASE A — modular monolith (current architecture formalized)

Phase A takes the verified layout of `CURRENT_ARCHITECTURE.md` §2–§3 and gives
it explicit package boundaries. Nothing is distributed. The "boundaries" are
Python packages with import rules and typed contracts; violating a boundary is
a lint/test problem, not an outage.

### 2.1 Diagram

```
PHASE A — modular monolith (two processes max: engine + optional dashboard)

 GitHub Action (action.yml)   CLI (local mode)        future: webhook/IDE (V9+)
      │  INPUT_* env                │ args                    │
      └────────────┬────────────────┴─────────────────────────┘
                   ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ ENGINE PROCESS — python -m ai_pr_reviewer (cli.py → orchestrator.py)     │
 │                                                                          │
 │  ingest ────────► review ────────► providers ───────► sync                │
 │  (github_client,   (orchestrator,  (model_router,     (github_sync,       │
 │   diff_parser)      verification,   ai/*, circuit,     comment post/      │
 │        │             reporter,      retry, static/)    anchoring)         │
 │        │             static/)           │                                 │
 │        ▼                ▲               │                                 │
 │  intelligence ◄─────────┴── policy ─────┤                                 │
 │  (context, repo_context)  (rules.py)    │                                 │
 │        │                                │                                 │
 │  memory (memory.py, human-authored)     │                                 │
 │  security (security.py — wraps every    │                                 │
 │            untrusted input boundary)    │                                 │
 │                                        ▼                                 │
 │  ┌────────────────────────────┐   ┌────────────────────────────────────┐  │
 │  │ core: models, findings,    │   │ storage contract — ReviewStorage   │  │
 │  │ review_state (pure,        │   │  ├ LocalReviewStorage (SQLite)     │  │
 │  │ deterministic)             │   │  └ DashboardStorageClient (HTTP)   │  │
 │  └────────────────────────────┘   └────────────────────────────────────┘  │
 │  telemetry spine (in-process; counters, timings, usage — Phase 0)         │
 └──────────────────────────────────────────────────────────────────────────┘
                   │ (optional, X-Dashboard-Token — every call degrades to a warning)
                   ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ DASHBOARD PROCESS (optional) — dashboard/app.py (FastAPI)                │
 │   storage: DbStorage (SQLAlchemy: SQLite WAL now / Postgres via          │
 │   DATABASE_URL later — ADR-011) or JsonStorage fallback · static SPA     │
 └──────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Package boundaries — structure and contracts

Starting points are today's files; the package split is a **move-with-reexport**
operation (imports keep working via thin shims until tests are updated), done
incrementally per `ARCHITECTURE_EVOLUTION.md`, never as a flag-day rewrite.

| Boundary (likely package) | Why it exists | What owns the data | Contract crossing it |
|---|---|---|---|
| **core** | shared kernel that every other package may import, and that imports nothing but stdlib: identity, lifecycle, pure models | owns *identity*: `fingerprint_finding` (in `ai_pr_reviewer/findings.py`), `ReviewKey`, `FindingState` (`ai_pr_reviewer/models.py`, `ai_pr_reviewer/review_state.py`) | `Finding`, `PRContext`, `ReviewResult`, `AnalysisOutcome` dataclasses — the data contract of the whole system (`DATA_MODEL.md` §4) |
| **ingest** | everything that turns external events into core types; the only place GitHub event/diff payloads enter | no persistence; produces `FileDiff[]` / `PRContext` from `ai_pr_reviewer/diff_parser.py`, `ai_pr_reviewer/github_client.py` | core types in, `GitHubClient` HTTP out; later CI/git ingestion (`V8`, `V7`) lands here too |
| **intelligence** | retrieval and context assembly, kept separate from judgment so it can be swapped for the V4 context engine v2 without touching review | writes nothing; reads storage via `ReviewStorage` | `ReviewContext` (`ai_pr_reviewer/context.py`), bounded repo-context fetches (`ai_pr_reviewer/repo_context.py`) |
| **review** | the deterministic review pipeline: validate → dedup → lifecycle → verify → score; owns all pipeline state transitions | owns pipeline state *decisions* (states are written only via storage) | `ReviewOrchestrator.run() -> ReviewResult` (`ai_pr_reviewer/orchestrator.py`), `verification.py` pure functions, `reporter.py` report dict |
| **memory** | human-authored knowledge, isolated so no code path can *write* memory implicitly (`ai_pr_reviewer/storage.py` docstring, engine is read-only by design) | `repo_memory` rows (engine SQLite and `dashboard/models_db.py: RepoMemoryRow`) | `get_repo_memory` / `list_repo_memory` reads; dashboard CRUD API; mute rows (`fingerprint:<fp>`) are decisions, not notes |
| **policy** | repository review policy with the non-removable privacy baseline; must stay separable from code review logic | the `.ai-pr-reviewer.yml` document itself (authoritative copy lives in the repo at the base revision) | `ReviewPolicy` from `ai_pr_reviewer/rules.py`; effective-threshold resolution (CLI/env > project > dashboard > default) |
| **security** | one place that defines the untrusted/trusted fence: fencing, injection screening, redaction, path safety | no data; owns *rules* (patterns, non-removable baseline) | `wrap_untrusted_diff`, `scan_prompt_injection`, `redact_secrets`, `_safe_repo_path` (`ai_pr_reviewer/security.py`) — called by every boundary that touches input or output |
| **providers** | AI backends behind one seam, with failover, retry, breaker; static engine is the honest last resort | provider-local counters only (`total_input_tokens`/`total_output_tokens` in `ai_pr_reviewer/ai/claude.py`, `ai/openai.py`); surfaced via telemetry spine | `AIProvider.analyze(context) -> AnalysisOutcome` + `backend` + `startup_warnings` (`ai_pr_reviewer/model_router.py`, `ai_pr_reviewer/ai/provider.py`) — formalized in §7.2 |
| **sync** | posting/updating GitHub comments: id capture, anchoring, 422 recovery, state markers — isolated because it is the only *write* path to GitHub | `github_comment_id` on findings (pipeline-owned, never model-owned) | GitHub REST via `ai_pr_reviewer/github_client.py`; `MAX_SYNC_ERRORS` bounded degradation |
| **storage** | one data-access contract for all current and future entities (ADR-011) | **all** durable state: `review_state`, `finding_history`, `repo_memory` (`ai_pr_reviewer/storage.py`); dashboard mirror tables (`dashboard/models_db.py`) | `ReviewStorage` Protocol (§7.3), mirrored over HTTP with `X-Dashboard-Token` |
| **telemetry** | measure before managing: token usage, latency, fallback events (Phase 0; today usage is counted but never surfaced — `CURRENT_ARCHITECTURE.md` C6) | append-only metrics/usage records (JSONL now → rows later) | in-process emitter API; report JSON fields (additive) |

Dashboard (`dashboard/app.py`) is a *separate process behind HTTP* from day one
— the only pre-existing "service" boundary. It keeps its contract, its token
auth, its rate limits, and its stateless-degrade behavior (every engine call
that fails is swallowed into a warning).

### 2.3 Phase A boundaries — failure, security, scale, migration

| Boundary | Failure behavior | Security boundary | Scalability reason | Migration strategy |
|---|---|---|---|---|
| **core** | cannot fail (pure) | model output enters only via `Finding.from_untrusted_dict`, which strips `LIFECYCLE_FIELDS` | none needed — O(findings) CPU only | freeze: moves are renames with re-export; behavior changes need tests first |
| **ingest** | GitHub outage → run fails *before* review; force-push on incremental diff → full-diff fallback (current behavior) | untrusted: PR diff/title/author; `_safe_repo_path` prevents path escape into token-bearing URLs | bounded: 1000-file/10-page caps (`CURRENT_ARCHITECTURE.md` §12); raising them is a config change, not a structural one | add V7/V8 sources (git history, CI) as sibling modules behind the same "external source" seam |
| **intelligence** | context failure → review proceeds with less context + warning; never blocks | fenced untrusted content (`repo_context`, memory notes) before prompt assembly | character budgets today (`batch_chars=80k`, `repo_context_chars=12k`, `context.py: DEFAULT_TOKEN_BUDGET`); V4 replaces with provenance-tracked budgeting | grow in place: `context.py` → context engine v2 (`ARCHITECTURE_EVOLUTION.md` V4 row) |
| **review** | static fallback keeps the run alive; degraded runs withhold `last_reviewed_sha` so the next run retries AI | deterministic steps never trust provider output; caps (`max_comments`, 500-finding dashboard cap) bound hostile volume | one review per process; this is the *reason* Phase B exists (§3) | evolve: orchestrator gains fan-out (V5) behind the same `run()` contract |
| **memory** | memory read failure → empty notes, review continues | human-authored only; engine never writes; dashboard writes are token-auth + audit-logged; authority model arrives V7 (ADR-003) | 50-entry read cap today (D13); hierarchy replaces flat rows in V7 | additive columns (`category`/`enabled`/`updated_at` precedent in `storage.py:_init_db`) |
| **policy** | policy load failure → defaults + warning; PR that rewrites its own policy = warning (base-revision read) | trusted *only* because it is read from the base revision; privacy baseline is non-removable (`rules.py`) | tiny docs; no scale concern until org scope (V9, ADR-003 inheritance) | file stays authoritative; cached rows are projections (`DATA_MODEL.md` §Policy) |
| **security** | screening is warnings-only (forensic); redaction failure is a hard stop for posting that item | this package *is* the security boundary; untrusted/trusted split per `CURRENT_ARCHITECTURE.md` §6 | pattern scans are O(diff size), linear | extend at every stage that adds an untrusted surface (V4 index, V5 agents, V7 memory, V8 CI, V9 webhooks, V10 plugins) |
| **providers** | retry → circuit breaker → secondary → static; breakers process-global (safe only because runs are sequential — C5) | BYO keys never leave provider modules; no retired model IDs hardcoded | sequential calls, 240s timeout; concurrency is *unsafe today* → this is trigger B2 (§6) | V5 capability registry + per-task routing; breakers become per-instance before any concurrency |
| **sync** | 422 → per-comment recovery; `MAX_SYNC_ERRORS=5`; never re-post without transitions | only outbound write path; every body passes `redact_secrets` + caps | bounded comment harvesting (1 page) | unchanged through V7; V9 adds API-side events, not changes to comment sync |
| **storage** | every read degrades to empty/None with a warning; a run never dies on storage | local file vs token-gated HTTP; audit append-only; token file 0600 best-effort | C9: connections never closed, no retention, O(all) dashboard queries — Phase 0 fix candidates; single-worker ceiling is trigger B1 | consolidation (3 duplicate implementations) *before* any new backend (ADR-011) |
| **telemetry** | telemetry loss must never fail the run (drop + count drops) | usage/cost data is internal; never includes diff content | append-only, batched writes | Phase 0 seeds; consumed by V5 arbitration, V6+ dashboards |
| **dashboard** | engine swallows dashboard errors → stateless degrade; JsonStorage is single-worker only | token auth, constant-time compare, rate limits, CSP; reads optionally open | single worker; O(all) queries — trigger B1 | Postgres via `DATABASE_URL` is already wired (ADR-011); real migrations when schema churn accelerates |

---

## 3. PHASE B — worker/queue separation (where justified)

Splits **long-running review jobs** from **interactive serving** inside the same
codebase, using the storage contract and a queue/event transport per ADR-008.
This is the *only* structural split that has a plausible near-term trigger, and
it still ships as one repo, one image, multiple process roles.

### 3.1 Diagram

```
PHASE B — worker/queue separation (opt-in; Action can always run inline)

                        ┌──────────────────────────────────────────────┐
 GitHub Action ────────►│ INLINE PATH (default, unchanged):            │
 CLI                    │  ingest → review → sync  in one process      │
                        └──────────────────────────────────────────────┘
        │  (opt-in later: a future `review_enqueue` input)
        ▼
 ┌─────────────────┐    ┌──────────────────┐    ┌────────────────────────────┐
 │ ingress role    │───►│ queue / outbox   │───►│ review worker role (1..N)  │
 │ (webhook/API    │    │ (ADR-008; starts │    │ same engine packages:      │
 │  event intake)  │    │  as a table in    │    │ ingest→review→providers    │
 └─────────────────┘    │  the same DB)     │    │ →sync; idempotent on       │
                        └──────────────────┘    │ review_id repo#pr@sha12     │
                                 ▲              └─────────────┬──────────────┘
                                 │                            │
 ┌───────────────────────────────┴────────────────────────────▼──────────────┐
 │ SHARED: storage contract over Postgres (ADR-011) + telemetry spine        │
 │ dashboard/API role: FastAPI (interactive reads/writes, unchanged routes)   │
 └───────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Boundaries

| Boundary | Why it exists | Data owner | Contract crossing it | Failure behavior | Security boundary | Scalability reason | Migration strategy |
|---|---|---|---|---|---|---|---|
| **ingress ↔ queue** | accept events fast without doing work inline | queue/outbox table (same DB as storage contract) | **event envelope** (§7.4): `schema_version`, `event_id`, `type`, `occurred_at`, `source`, `repo`, `payload` | at-least-once; ingress never blocks on review capacity; duplicate delivery is tolerated because workers dedupe on `event_id`/`review_id` | webhook payload is untrusted input — same screening as PR diffs before it reaches prompts | decouples arrival rate from review rate | start as an outbox table read by a poller; a real broker only if the table itself becomes the bottleneck |
| **queue ↔ worker** | run reviews off the interactive path, with retry and concurrency | workers own *writes* through `ReviewStorage` only — no worker-local state | job message = minimal pointer (`review_id`, config snapshot ref), not the diff itself (diff re-fetched at base revision) | crash mid-run → visibility timeout → redelivery; completed `review_id` is a no-op (idempotency); Action inline path unaffected by any queue failure | workers hold GitHub token + provider keys; no interactive endpoint does | N concurrent reviews without N dashboard processes; per-backend breakers become per-worker-instance (removes C5 hazard) | engine keeps `ReviewOrchestrator.run()`; a thin runner wraps it; inline mode remains the default forever |
| **worker ↔ storage** | one durable owner during the transition | Postgres (ADR-011); SQLite remains valid for single-node/local | `ReviewStorage` (§7.3) — identical in inline and queued modes | storage down → worker retries → never a silent state advance (findings-then-SHA ordering preserved) | single credential scope; audit records every queued write | moves writes off the dashboard process (today both read and write share it) | consolidation of the 3 storage implementations lands *before* Phase B — precondition, not a follow-up |
| **dashboard/API ↔ workers** | interactive reads must not wait on reviews | dashboard reads only | HTTP API unchanged (routes + `X-Dashboard-Token`) | dashboard outage degrades workers (swallowed warnings, current semantics) | token boundary unchanged | interactive latency isolated from review load | no code move — only deployment roles |

**Phase B is entered only on triggers B1–B4 (§6).** Until then all V8 event
platform work (internal event platform v1) can be built as *schemas + producers*
with the inline consumer (see `DO_NOT_BUILD_YET.md` for what stays unbuilt).

---

## 4. PHASE C — service separation (where justified)

Only after Phase B has produced measurements showing that *process roles in one
deployment* are not enough. Services = separately deployable/scaleable units
talking the **same** contracts (§7) — if a split requires changing a contract,
the split is wrong; fix the contract first, in Phase A.

### 4.1 Diagram

```
PHASE C — service separation (same contracts, separate deploys)

                 ┌─────────────────────────────────────────────┐
 GitHub ────────►│ gateway / ingress service                   │
 (Action,        │  event intake, authn, dedupe, fan-out       │
  webhooks,      └───────────────┬─────────────────────────────┘
  future API)                    │ event envelope (§7.4)
        │ inline path preserved  ▼
        │        ┌───────────────────────────┐   ┌──────────────────────────┐
        └───────►│ review worker service     │   │ intelligence service      │
                 │ (fan-out, providers, sync)│   │ (index, impact, evidence, │
                 └─────────────┬─────────────┘   │  context engine v2)       │
                               │                 └────────────┬─────────────┘
                               │  ReviewStorage / data        │
                 ┌─────────────▼──────────────────────────────▼─────────────┐
                 │ storage tier: Postgres (ADR-011) · object store for      │
                 │ artifacts · optional search index (only on query evidence)│
                 └─────────────▲──────────────────────────────▲─────────────┘
                               │                              │
                 ┌─────────────┴─────────────┐   ┌────────────┴─────────────┐
                 │ API / dashboard service   │   │ observability service    │
                 │ (versioned public API V9) │   │ (telemetry spine sink)   │
                 └───────────────────────────┘   └──────────────────────────┘
```

### 4.2 Boundaries

| Boundary | Why it exists | Data owner | Contract crossing it | Failure behavior | Security boundary | Scalability reason | Migration strategy |
|---|---|---|---|---|---|---|---|
| **gateway ↔ review workers** | isolate GitHub rate-limit pressure (C8) and event intake from analysis compute | gateway owns idempotency keys/dedupe; workers own nothing durable | event envelope + job pointer | gateway loss = no new reviews (existing inline path unaffected); worker loss = redelivery | single place where GitHub events enter — screening/fencing applied once | independent scaling of intake vs. compute | Phase B roles promoted to deploys; no contract change |
| **review ↔ intelligence** | index/context builds are CPU/IO-heavy and must not delay reviews; independent refresh cadence | intelligence service owns the repository index + `ContextArtifact` store (`DATA_MODEL.md`) | context request/response data contract with **provenance** (what was read, from which revision) | index stale/absent → review falls back to today's bounded `repo_context` fetch (graceful degradation is already the norm) | index content is derived from repo files = untrusted until fenced; base-revision reads only | index rebuilds spike; must not share CPU with live reviews | `repo_context.py`/`context.py` first run in-process behind the contract; service split is a deploy decision |
| **services ↔ storage tier** | one durable owner per datum (no distributed writes) | per-entity ownership table in `DATA_MODEL.md` §2 (Postgres now, ADR-011) | `ReviewStorage` + versioned data contracts | partition → degrade (reads serve stale where safe; writes buffer/retry; never lose a review) | credential scope per service; audit records cross-service writes | read replicas / partitioning become possible; retention jobs run off-path | phase-in per entity group; SQLite single-node path never removed |
| **API/dashboard ↔ everything** | public versioned API (V9-E03) must not be coupled to internal service layout | API owns its own projection/serializations, not the tables | **versioned HTTP API** (`schema_version`, additive-first; §7.5) | API outage affects humans only, never review execution | token/org auth, rate limits, audit; org scoping per ADR-010 when multi-tenant | interactive scale independent of compute scale | dashboard routes are already the seed of the API surface |
| **observability ↔ all** | telemetry becomes a shared service only when volume/retention demand it | telemetry sink owns metrics/log rows | telemetry spine export format | telemetry sink loss → local buffering → drop with counted drops | no diff content in telemetry (redaction first) | high write volume, cheap reads | Phase 0 emitter stays the source; sink swaps behind it |

---

## 5. PHASE D — organization-scale platform (V10)

Phase D is reached only if the V9/V10 gates are approved (org platform, optional
hosted offering per ADR-010). It adds the platform surface; it does not replace
Phase C's services.

```
PHASE D — organization-scale platform

 orgs ──► IDE / CLI / plugins ──► versioned public API (V9-E03)
                    │                      │
                    ▼                      ▼
        ┌───────────────────────────────────────────────────┐
        │ platform gateway: org authn/z (ADR-010), quotas,   │
        │ policy resolution (org ▸ team ▸ repo — ADR-003)    │
        └───────────┬───────────────────────┬───────────────┘
                    ▼                       ▼
        ┌───────────────────┐   ┌────────────────────────────┐
        │ plugin host       │   │ event backbone             │
        │ (V10, sandboxed;  │   │ (ADR-008 matured: fan-out, │
        │  V9 contract only)│   │  org event consumers)      │
        └─────────┬─────────┘   └────────────┬───────────────┘
                  │ untrusted plugin I/O     │
                  ▼ (evidence, never state)  ▼
        ┌───────────────────────────────────────────────────┐
        │ Phase C services + storage tier + org memory +     │
        │ observability platform; analytics (no rankings)    │
        └───────────────────────────────────────────────────┘
```

| Boundary | Why it exists | Data owner | Contract crossing it | Failure behavior | Security boundary | Scalability reason | Migration strategy |
|---|---|---|---|---|---|---|---|
| **gateway ↔ org tenants** | isolation and quota enforcement for multi-tenant (ADR-010) | org/identity tables (`DATA_MODEL.md`) | versioned API + org-scoped policy resolution | tenant quota breach → shed that tenant only | per-tenant credential/data scoping; audit per org | tenant count grows horizontally | org = derived from `owner/` prefix until V9 makes it a real row |
| **plugin host ↔ core** | extensibility without trusting extension code (V9 contract, V10 runtime) | plugins own no core tables; their output enters as *evidence records* | extensibility contract v1 (V9): declared capabilities, no lifecycle-field writes | plugin crash/timeout → finding dropped or static fallback; never blocks a review | **new security boundary**: sandbox, capability-limited I/O, output screened like model output (redaction + injection screening) | plugin load isolated from review workers | contract ships at V9 with zero plugins (contract-first), runtime at V10 |
| **event backbone ↔ consumers** | org-scale fan-out (V9 events → V8/V9 consumers) | event store (retention-bounded) | event envelope, exactly the §7.4 schema (no second schema) | consumer lag → degraded freshness, never lost reviews (reviews are not *driven* by the backbone in the default path) | authenticated producers/consumers; payload redaction at produce time | many consumers per event | grows from Phase B outbox — same schema, better transport |
| **analytics ↔ operational stores** | org analytics (V10) must not load operational rows in Python (today's O(all) pattern, C9) | analytics projections (read-only copies) | read-only projection contract | analytics outage → dashboards only | no individual rankings anywhere (vision §6) | columnar/aggregation-friendly copy | build on `DATA_MODEL.md` projections; search index only when a query needs it |

---

## 6. What justifies Phase B/C — measured triggers, not guesses

**Stated plainly: today, none of these are met.** The correct action is always
Phase 0/V4 hardening first. A trigger must be observed in production metrics
(the Phase 0 telemetry spine is the prerequisite — C6: *nothing can be managed
that isn't measured*) and persist across **two consecutive 30-day measurement
windows (proposed baseline)** before any structural work is scheduled.

| # | Trigger | Measurement source | Proposed baseline threshold | Justifies |
|---|---|---|---|---|
| B1 | dashboard/API interactive reads slow under real data volume | telemetry spine; dashboard query timing | p95 read latency > 1.0 s while loading > 500 k finding rows, and query-time profiling shows O(all) scans (`list_findings`, `stats`, `metrics` in `dashboard/storage.py`) | Phase B + query-side storage work (ADR-011) |
| B2 | more than one review must run concurrently per deployment | telemetry: overlapping `ReviewOrchestrator.run()` intervals | > 4 concurrent reviews sustained, or org onboarding blocked by serialization; breaker/concurrency hazards (C5) reproduced under test | Phase B workers |
| B3 | GitHub API pressure | GitHub response headers/counters | rate-limit headroom < 20 % during normal runs, or > 10 % of runs degraded by 403/rate-limit (today 403 = permanent, C8) | Phase B ingress (single intake point) + client hardening |
| B4 | review job loss/retry pain | failed/interrupted runs | > 1 % of enqueued reviews lost or manually replayed per 30 days | Phase B queue durability |
| C1 | one deployment cannot serve both compute profiles | Phase B metrics | index/context builds consume > 50 % worker time and delay live reviews beyond SLO | Phase C intelligence split |
| C2 | independent release cadence needed | delivery metrics | teams/deployments blocked on shared release; ≥ 2 independently-scaling workloads | Phase C service split |
| C3 | tenant isolation required | product gate | approved multi-tenant offering (ADR-010) | Phase C/D isolation boundaries |
| D1 | org platform approved | product gate | V9/V10 stage approval | Phase D |

Anti-guess rule: **"we might need it" is not a trigger.** Nothing in the
capability stages V4–V7 *requires* B/C/D; if a feature seems to require them,
it is designed wrong (the inline path is the reference implementation).

---

## 7. Contracts that must be stable early

These four contracts (plus the Action contract) are the load-bearing elements.
Everything else may be reorganized freely.

### 7.1 Data contracts (report, finding, review state)

- **Report JSON** (`review-report.json`, produced by
  `ai_pr_reviewer/reporter.py: finalize_report`; mirrored to
  `POST /api/reports` and `dashboard/models_db.py: ReportRow.payload`) is the
  public artifact of every run. Today it carries **no version field**.
  **Proposal (marked: proposed baseline):** add `"schema_version": 1` in Phase 0
  (additive key — old consumers ignore it); absence of the field reads as `1`.
- **Finding payload JSON** — today `Finding.to_dict()` stored verbatim in
  `finding_history.payload` (`ai_pr_reviewer/storage.py`) and
  `FindingHistoryRow.payload` (`dashboard/models_db.py`). Same rule: gains
  `schema_version` at the artifact level; provenance fields arrive additively in
  V4 (`DATA_MODEL.md` §5).
- **Versioning strategy — additive-first JSON:**
  1. within a major version, only *add* optional keys; never rename, retype, or
     remove;
  2. readers ignore unknown keys; writers must not require readers to know new
     keys;
  3. enum-valued fields (severity, state, mode) get unknown-value tolerance —
     an unknown value renders as-is, never crashes a consumer;
  4. a major bump requires: a written migration note, dual-read support for one
     stage, and a `schema_version` bump in both engine and dashboard in the same
     release;
  5. payload JSON payloads are *documents*, not tables: schema drift is cheap
     precisely because nothing joins on them (`DATA_MODEL.md` §3).

### 7.2 Provider contract

- Today: structural `AIProvider` protocol — `analyze(context) ->
  AnalysisOutcome` — with informal extras (`backend`, `startup_warnings`) and
  seven hard-coded wiring sites (`CURRENT_ARCHITECTURE.md` §10.1).
- **Stabilize now:** declare the informal members in the protocol; declare
  token/usage reporting as an **optional capability** (counters exist in
  `ai/claude.py` + `ai/openai.py`, unreported; Gemini TODO) so V5's capability
  registry (`CURRENT_ARCHITECTURE` C6 → cost arbitration) has a contract to
  read.
- **Never break:** `AnalysisOutcome` first five fields keep position and meaning
  (the comment in `models.py` already records this discipline); the static
  provider is always constructible (honest fallback is non-negotiable); no
  retired model IDs hardcoded (release test enforces this).
- New provider features (batching hints, context-window size, cost tables) enter
  as *capability declarations*, not new required methods.

### 7.3 Storage contract

- `ReviewStorage` (`ai_pr_reviewer/storage.py`) is the seam for every future
  entity (`CURRENT_ARCHITECTURE.md` §14). It has two deliberately undeclared
  optional capabilities reached via `getattr` guards
  (`get_dismissed_fingerprints`, `list_repo_memory`).
- **Stabilize now:** formalize optionality as an explicit capability set
  (e.g. `capabilities() -> set[str]`) so behavior stops varying silently by
  backend; keep every existing method signature; keep the HTTP mirror
  (`DashboardStorageClient`) speaking exactly the same semantics — every read
  degrades to empty with a warning.
- **Growth rule:** new entities get contract methods *before* new backends; the
  three duplicated implementations collapse to one logical schema first
  (ADR-011). Additive methods only; a v2 protocol is a last resort with a
  dual-implementation period.
- Data ownership follows `DATA_MODEL.md` §2 — one writer per datum, in every
  phase.

### 7.4 Event schema

- No event bus exists (correctly — `DO_NOT_BUILD_YET.md`; ADR-008 keeps Phase 0
  in-process with typed run-scoped records). The **schema** is nevertheless a
  contract to fix *before* the platform (V8 internal event
  platform v1; transport per ADR-008):
  `{schema_version, event_id (uuid), type (dotted, e.g. "review.completed"),
  occurred_at (ISO-8601 UTC), source (service/role), repo?, subject
  (entity id), payload {…}}`.
- Rules: events are immutable facts (corrections are new events); at-least-once
  delivery assumed, so consumers dedupe on `event_id`; payloads obey §7.1
  additive-first rules; redaction (`security.py`) runs at *produce* time; no
  secrets, no diff bodies (pointers only — diffs are re-fetched at the base
  revision).
- Producers can exist (as logged records) before any queue exists; a consumer
  never assumes ordering across `repo` keys.

### 7.5 GitHub Action contract — backward compatible in every phase

The Action surface (`action.yml`) is the product's public API and must survive
A → D unchanged:

- **Inputs:** existing 21 inputs keep names, meanings, and defaults (including
  `max_comments='20'`, `batch_chars='80000'`, `repo_context_chars='12000'`);
  new capabilities add *new optional inputs with defaults* or read
  `.ai-pr-reviewer.yml`. Config layering CLI > `INPUT_*` > env > defaults is
  frozen (`CURRENT_ARCHITECTURE.md` §13.2).
- **Outputs:** `findings_count`, `critical_count`, `report_path`,
  `health_score`, `health_grade` are never removed or re-typed.
- **Side effects:** `review-report.json` path default stays `review-report.json`;
  exit codes `0/1/2` stay (`AGENTS.md`); `--mock`/`--static` zero-key path stays
  fully functional.
- **Deployment:** the composite action keeps `requirements-action.txt` lean
  (no fastapi/uvicorn/sqlalchemy), keeps Python 3.12, keeps base-revision
  checkout and minimal permissions. In Phases B–D the Action runs the **inline
  path** by default: enqueueing is an opt-in input, and no queue/service/DB is
  ever required for the Action to complete a review.
- **Report compatibility:** consumers of `review-report.json` see additive-only
  change (§7.1) for the whole life of the Action contract.

---

## 8. Platform foundations — built once, reused everywhere

Each foundation is delivered at its earliest *needed* stage and then consumed,
never rebuilt. `ARCHITECTURE_EVOLUTION.md` §3 gives the stage/consumer matrix;
summary of the architectural commitment:

| Foundation | One owner | Reused by |
|---|---|---|
| **provenance record** (who/what produced this: engine, model, agent, revision, evidence pointers) | core data contract | V4 evidence + identity v2 → V5 council merge → V6 evidence tiers → V7 relations → audit/observability |
| **context artifact + budget system** (bounded, provenance-tracked context pieces) | intelligence | V4 context engine v2 → V5 adaptive depth → V6 verification tiers → V8 CI context |
| **event envelope schema** (§7.4) | storage/platform | V8 internal events → V9 webhooks/org events → V10 analytics |
| **storage migration framework** (one schema, one migration path — replaces hand-rolled `ALTER TABLE` in `storage.py` and `dashboard/storage.py`) | storage | every entity added after `DATA_MODEL.md` lands |
| **provider capability registry** | providers | V5 task routing + cost arbitration → V6 context-window awareness → V10 local providers/ecosystem |
| **policy evaluation interface** (evaluate(policy, subject) → explainable result) | policy | V6 repo/team policy engine → V9 org inheritance (ADR-003) → V10 plugins reading policy |
| **telemetry spine** (usage, latency, fallback events; drop-safe) | telemetry | Phase 0 measurement → triggers §6 → V5 arbitration → V6+ cost dashboards → V10 observability platform |

The discipline: **a foundation that is needed twice is designed once, at the
first use, with the second use as a review checklist** — not designed twice and
certainly not deferred until the second use forces a rewrite.

---

### Cross-references

Ground truth: `CURRENT_ARCHITECTURE.md` (§2 current diagram, §6 security
boundary, §11 defects/constraints D1–D14/C1–C14, §13–§14 keep/evolve).
Evolution path: `ARCHITECTURE_EVOLUTION.md`. Data: `DATA_MODEL.md`. Decisions:
`ADR_INDEX.md` — **ADR-001** (modular monolith — Phase A),
**ADR-008** (in-process pipeline first; events before queues — Phase B/D
transport), **ADR-010** (single-tenant now, multi-tenancy as a boundary —
Phase D), **ADR-011** (storage evolution behind `ReviewStorage` — all phases),
**ADR-002** (repository graph as derived deterministic index), **ADR-003**
(memory authority model), **ADR-014** (local-first telemetry — §8 spine),
**ADR-015** (policy evaluation placement — §8 interface). Vision:
`MASTER_VISION.md` (12 planes; planes 11–12 map to Phase C/D surfaces).
Refusal list: `DO_NOT_BUILD_YET.md`. Order and epics: `MASTER_ROADMAP.md`,
`V4_V10_ROADMAP.md`, `EPIC_BACKLOG.md`, `DEPENDENCY_GRAPH.md`,
`MIGRATION_PLAN.md`.

**Flagged uncertainty:** `EPIC_BACKLOG.md`, `DEPENDENCY_GRAPH.md` and
`MIGRATION_PLAN.md` were not yet in the tree when this document was written
(ADR titles above verified against `ADR_INDEX.md`); epic IDs cited elsewhere in
this plan set come from the engagement brief — verify against `EPIC_BACKLOG.md`
when it lands.
