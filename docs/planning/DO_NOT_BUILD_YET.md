# DO NOT BUILD YET — The Refusal List

> Status: planning document (v1) — grounded in repository state described by
> `CURRENT_ARCHITECTURE.md` at commit `2841b23`. Every item below is
> architecture-derived: each names the missing prerequisite (epic IDs from
> `EPIC_BACKLOG.md`, stage order from `MASTER_ROADMAP.md`), the measurable
> trigger that would justify building it, and the interim alternative that
> serves the need today. **Having an idea on this list is not a reason to open
> a PR.** Removing an item requires the trigger to have fired and the
> prerequisite to be green.

Companion documents: `MASTER_ROADMAP.md` (§Out of scope — normative product
boundaries) · `EPIC_BACKLOG.md` (what we *are* building, in order) ·
`MASTER_VISION.md` §6 (platform WILL NOT do automatically) · `ADR_INDEX.md`
(decisions behind each refusal).

How to read a entry:

```
WHAT        the thing being refused
WHY SEXY    why it keeps getting proposed anyway
MISSING     the prerequisite(s) that must land first (epic IDs)
TRIGGER     the measurable event that re-opens the discussion
INTERIM     what serves the need until then
```

---

## Theme A — Distribution & infrastructure theater

### A1 · Microservices
- **WHAT:** split the engine/dashboard/repo-intelligence into separately
  deployed networked services.
- **WHY SEXY:** "scale", parallel team ownership, each plane looks like a
  service boundary on the whiteboard.
- **MISSING:** everything — there is no queue (ADR-008), no per-service data
  contract (ADR-011 consolidation not done), no observability to tell whether
  the split helped (V3-E02 telemetry, V9-E07). C5 global breakers make
  multi-process unsafe *today*.
- **TRIGGER:** load layer (TESTING §L14) shows a single process cannot meet a
  real workload, **and** the bottleneck is unfixable in-process (query,
  memory, GIL) after at least one documented attempt.
- **INTERIM:** the monolith with clean module seams (ADR-001) + the existing
  engine↔dashboard HTTP split, which already covers the only genuine
  cross-process need.

### A2 · Kubernetes (or any orchestrator) deployment
- **WHAT:** k8s manifests/Helm/operators for the engine or dashboard.
- **WHY SEXY:** enterprise credibility, "production-grade" optics.
- **MISSING:** a hosted product to deploy (V10 gated, ADR-010), containers
  beyond the current single `Dockerfile` Action image, and any queue/worker
  model (A3). Nothing in the OSS path needs orchestration — CI is `docker
  build` (`.github/workflows/ci.yml`).
- **TRIGGER:** an approved hosted offering (V10 scope decision) with ≥1 real
  deployment target.
- **INTERIM:** the Action image for users; `docker run` + `uvicorn` for the
  dashboard; a single-process systemd/compose example in docs if asked — docs
  cost nothing.

### A3 · Event-driven queue infrastructure "for scale"
- **WHAT:** Rabbit/Kafka/Redis streams + workers ahead of an actual queue
  workload.
- **WHY SEXY:** looks like the architecture diagram of a "real platform";
  preemptively "future-proofs" V8 CI events.
- **MISSING:** measured need (zero — one review per process, §12), typed
  in-process events first (ADR-008 stage a), webhook volume data (V9,
  ADR-013).
- **TRIGGER:** L14 numbers show sustained work beyond one process **or** V9
  webhook ingestion exceeds single-process handling; queue design then gets
  an ADR, not a default.
- **INTERIM:** run-scoped typed events (ADR-008a) — the same records as
  telemetry (ADR-014) — which all downstream consumers (reporter, dashboard,
  audit) can read today without a broker.

### A4 · Distributed tracing stack (Jaeger/OTel collectors/sampling infra)
- **WHAT:** full tracing backend with spans propagated across services that
  do not exist yet.
- **WHY SEXY:** pretty waterfall graphs; industry buzzword compliance.
- **MISSING:** V3-E02 telemetry (start with flat per-run/per-call records),
  multiple services to trace (A1), a self-hosted backend story that doesn't
  violate the no-phone-home default (ADR-014).
- **TRIGGER:** V9-E07 dashboards exist, and diagnosing a real incident
  requires cross-process spans that per-run records cannot answer — i.e. after
  A1's trigger fired too.
- **INTERIM:** the V3-E02 telemetry spine: run + call records in the report
  JSON/dashboard cover latency, tokens, retries, fallback (`COST_TOKEN_
  ARCHITECTURE.md` §3). If export is ever wanted, an **opt-in OTel sink** is a
  revisit item in ADR-014, not a stack.

### A5 · GraphQL API
- **WHAT:** a GraphQL surface over reports/findings/metrics instead of
  (extending) the existing REST API.
- **WHY SEXY:** flexible client queries, "modern API" talking point.
- **MISSING:** any second client that needs it (there is one SPA, dependency-
  free, consuming plain REST), a versioned REST contract first (listed as
  absent in §10.5; AF API platform is V9), and query-cost controls the
  dashboard's rate limiter doesn't cover.
- **TRIGGER:** ≥2 real external consumers demonstrably cannot compose their
  views from documented REST endpoints, and the cost of adding those endpoints
  is measured higher than a GraphQL layer.
- **INTERIM:** additive REST endpoints (the current pattern — every new
  field has been an append, e.g. `base_sha`, report keys); OpenAPI stays off
  by default but the routes are self-documenting.

### A6 · Real-time collaborative dashboard
- **WHAT:** websockets/live cursors/multi-user editing of rules and memory
  with presence.
- **WHY SEXY:** demos well; feels "enterprise collaboration".
- **MISSING:** single-user reality (one shared token, single-worker
  constraint C9), concurrency semantics for concurrent edits (last-writer-wins
  is a decision no one has made), and ADR-010's boundary — plus ADR-003
  authority model for *who* may promote memory.
- **TRIGGER:** multi-user auth exists (V9/V10 hosted decision) **and** user
  evidence shows stale-page confusion is a top support issue.
- **INTERIM:** the current request/response SPA with a refresh; optimistic
  updates are a frontend-only improvement that doesn't need a socket.

---

## Theme B — Autonomous write actions (refused by vision, not just sequencing)

*These are gated by `MASTER_VISION.md` §6 (WILL NOT automatically) — the
"trigger" is an explicit product re-decision, not an epic going green. Listed
so nobody treats them as schedule slips.*

### B1 · Autonomous code commits (engine pushes code changes)
- **WHAT:** the reviewer applies its own suggested fixes as commits.
- **WHY SEXY:** "AI that fixes what it finds" — the demo everyone wants.
- **MISSING:** fix intelligence that is correct without a human (V5–V6 fix
  planning is *propose-only*), verification of the fix beyond diff coverage
  (ADR-012 — code execution evidence is V6+ and non-trivial), and a signed-off
  trust model for write credentials beyond `pull-requests: write`.
- **TRIGGER:** explicit vision-boundary re-decision + fix-precision on the
  evaluation corpus ≥ **proposed baseline** 0.95 over a sustained window
  (TESTING §4) + dry-run evidence on a fixture repo with zero bad commits.
- **INTERIM:** GitHub's native mechanism already exists for proposals —
  suggestion blocks in review comments (the `suggestion` field on findings is
  already rendered); draft patches as artifacts, never pushed.

### B2 · Autonomous merge
- **WHAT:** the platform merges PRs it has reviewed/approved.
- **WHY SEXY:** the endgame of "AI approval flow".
- **MISSING:** everything that makes merge decisions defensible — ADR-012
  evidence tiers with test results (V6), policy engine completeness (ADR-015;
  org layer V9), CI intelligence (V8) — plus a liability/threat model
  (`SECURITY_ROADMAP.md`) and human accountability for merges.
- **TRIGGER:** a *human* policy explicitly authorizes auto-merge for a defined
  class (docs-only, green-CI, zero-findings) **and** every prerequisite above
  is green; even then it is the platform *honoring GitHub's auto-merge*, not
  inventing its own authority.
- **INTERIM:** label/required-review automation via plain GitHub features;
  the platform keeps posting findings and health score to inform the human
  merger.

### B3 · Autonomous production deployment
- **WHAT:** reviewer/release tooling deploys to production.
- **WHY SEXY:** closes the loop from PR to prod.
- **MISSING:** release intelligence (V8), incident intelligence (V8), and —
  fundamentally — any product boundary allowing write access outside GitHub
  comments (§6). Incident stage is explicitly "retrospective, read-only; no
  autonomous production integration" (`MASTER_VISION.md` §5-AC).
- **TRIGGER:** explicit vision re-decision; nothing less.
- **INTERIM:** evidence for *humans* deploying: release-risk findings, change
  summaries, PR health gate output consumable by the org's existing CD
  pipeline — the platform advises, the pipeline acts.

### B4 · Production incident automation (beyond read-only)
- **WHAT:** auto-remediation on incidents: roll back, gate traffic, open
  fix-PRs during an incident.
- **WHY SEXY:** "AIOps" is a magnet slide.
- **MISSING:** V8 read-only incident ingestion first, evidence quality
  (ADR-004), ADR-012 trust tiers for "this mitigation works", on-call/account
  integration that does not exist.
- **TRIGGER:** vision re-decision **plus** a real operator with real
  accountability asking for it; read-only retrospective must have shipped and
  been used first (V8 trigger).
- **INTERIM:** read-only incident intelligence (V8): correlate regressions
  with recently merged PRs, summarize blast radius, attach evidence — humans
  remediate.

### B5 · Engine auto-mutes / auto-dismisses findings without a human
- **WHAT:** engine decides its own findings were wrong and mutes them (or
  auto-raises its own severity above policy) — "self-tuning".
- **WHY SEXY:** kills false-positive complaints automatically.
- **MISSING:** V3-E03 false-positive corpus + telemetry to *prove* a pattern
  is benign; V3-E02 to measure mute quality; ADR-003 authority model (engine
  writing state it does not own — today mutes are dashboard-authored by
  design, §5.6).
- **TRIGGER:** human-in-loop mute promotion has months of data showing a
  deterministic, evidence-backed pattern (e.g. generated-file globs) worth
  automating — and then only for *baseline additions*, never for removing the
  privacy baseline (non-removable, `rules.py`).
- **INTERIM:** the existing loop: dashboard down-vote/mute (audited) → memory
  row → next review honors it; policy `exclude:` additions for stable globs.

---

## Theme C — Platform scope creep (before the base supports it)

### C1 · Full multi-tenancy / hosted SaaS
- **WHAT:** tenant isolation, billing, per-tenant keys/quotas, a hosted
  control plane.
- **WHY SEXY:** revenue narrative; "real product".
- **MISSING:** single-tenant boundary hygiene (ADR-010's seam), queue (A3),
  observability/envelopes (V3-E02 → V9-E07), storage consolidation + retention
  (ADR-011/C9), webhook posture (ADR-013/V9), load data (L14). It is the
  *last* stage (V10) for a reason.
- **TRIGGER:** explicit V10 scope approval in `MASTER_ROADMAP.md` + named
  demand evidence + all of the above green.
- **INTERIM:** multi-repo single-tenant usage works today (each repo's Action
  run + one dashboard); orgs self-host the dashboard with Postgres
  (`DATABASE_URL`) — already supported.

### C2 · Complex organization analytics / individual engineer rankings
- **WHAT:** per-developer quality scores, velocity league tables, performance
  dashboards.
- **WHY SEXY:** dashboards that rank people get executive attention.
- **MISSING:** V7 historical/team intelligence with an authority model
  (ADR-003), enough signal per team to say anything defensible — and a
  permission the product explicitly does not have: vision §5-AD is
  "**trends and hotspots only; explicitly no individual performance rankings
  or quality scores**" and §6 forbids ranking individuals.
- **TRIGGER:** vision-boundary re-decision (human approval) — prerequisite
  epics staying green is **not** sufficient.
- **INTERIM:** aggregate trend views that V7 does allow: findings per
  component, hotspots by path, verification-rate trends — scoped to
  code/teams-as-structures, never to named individuals.

### C3 · Unbounded repository ingestion
- **WHAT:** index entire monorepo histories, every file, all attachments, all
  forks — "just ingest everything and let retrieval sort it out".
- **WHY SEXY:** no more annoying budget knobs; a bigger context = smarter
  reviews, right?
- **MISSING:** V4 bounded index design (ADR-002: SHA-keyed, regenerable,
  layered), context budget reality (C7 — budgets are *the* cost control),
  GitHub API limits (C8: no rate-limit handling, 1000-file/1MB caps), and
  V3-E02 data on what context actually earns its tokens.
- **TRIGGER:** telemetry shows budget-bound reviews measurably losing recall
  (TESTING §4) *and* the index (V4) proves retrieval can select a bounded
  slice from a large corpus — i.e. ingest-store-anything only after
  select-well is proven.
- **INTERIM:** bounded everything as built: incremental diffs (§12),
  `MAX_CONTEXT_FILES`/`repo_context_chars` (`repo_context.py`), `chunk_files`
  80k-char/3000-line caps, privacy exclusion baseline. Context budget tables
  in `COST_TOKEN_ARCHITECTURE.md` §4.1 make the bounds *visible* instead of
  pretending they don't exist.

### C4 · Data warehouse / analytics lake for reports
- **WHAT:** replicate report/finding history into a warehouse for org BI.
- **WHY SEXY:** "data-driven engineering" decks.
- **MISSING:** any consumer of that data beyond `/api/metrics`, retention
  discipline (C9), and the aggregation work that V9-E07 will do inside the
  dashboard first.
- **TRIGGER:** documented analytics requirements the dashboard's own storage
  cannot serve after query-level fixes (ADR-011 revisit condition).
- **INTERIM:** report JSON artifacts (already written per run) are a
  warehouse-compatible export format — someone can load them into anything
  *today* without us operating anything.

---

## Theme D — Extensibility ahead of contracts

### D1 · IDE plugins (VS Code / JetBrains)
- **WHAT:** run the reviewer inside the editor on unsaved diffs/selections.
- **WHY SEXY:** huge surface expansion; devs live in the IDE.
- **MISSING:** a stable engine contract to call (the engine is a Python
  package with Action-shaped entry; §10 has no versioned API), latency
  expectations (IDE interactivity ≈ <2 s; today provider calls run to
  240 s timeouts — §12), and the positioning decision that IDE review is a
  *client* of the platform gateway (`MASTER_VISION.md` §2), not a fork of the
  engine. Vision: IDE/plugins only after contracts stabilize (§5-A).
- **TRIGGER:** versioned API platform shipped (V9, AF) **and** an evaluation
  showing static/incremental analysis meets interactive latency on the L13
  corpus.
- **INTERIM:** local CLI already gives editor-adjacent workflows
  (`python -m ai_pr_reviewer --diff-file …` — the `--mock` path is free);
  editors can shell out to it. A thin `watch` wrapper is documentation, not a
  plugin.

### D2 · Plugin marketplace (discover, install, rate, monetize third-party
  plugins)
- **WHAT:** an app-store surface for analyzers/providers/reporters.
- **WHY SEXY:** ecosystem story; network effects.
- **MISSING:** the plugin *contract* itself (ADR-009: V9 defines, V10 ships),
  a conformance suite (TESTING §L18 candidate), sandboxing verdicts, signing/
  provenance for third-party code, and abuse/security review processes —
  marketplace without a contract is a supply-chain attack vector (plugin
  output would be untrusted input per §6).
- **TRIGGER:** contract + conformance suite shipped (V9/V10) and real
  third-party plugins exist that users *ask* to discover — never before.
- **INTERIM:** the documented contribution paths that work today: rule packs
  (registered in `static/engine.build_default_registry()`), provider adapters
  (ADR-007 registry direction), and fork-and-PR for core — exactly the
  community surface vision §7 defines.

---

## Theme E — AI scope creep (the "just use AI" anti-patterns)

### E1 · Giant unified prompt / one-model-does-everything
- **WHAT:** replace specialized stages (security, lifecycle, verification,
  static rules) with one prompt on one frontier model.
- **WHY SEXY:** simpler code, one vendor bill, one thing to demo.
- **MISSING:** V3-E03 evidence that a generalist beats the deterministic core
  (it can't — identity/lifecycle/verification are *defined* to be
  deterministic, vision §3.2, §13.3), capability registry for right-sizing
  (V5, ADR-007), cost data (V3-E02) — and it contradicts honest-fallback:
  static rules are free and provable (`static/`), a prompt is neither.
- **TRIGGER:** evaluation corpus shows the unified approach ≥ **proposed
  baseline** parity on recall *and* precision *and* verification accuracy
  *and* ≥30% cheaper across the board — sustained over scheduled evals (L11).
  Given deterministic-first, expect this trigger to never fire for identity/
  lifecycle; only *judgment* scopes are arguable.
- **INTERIM:** what exists: deterministic core + AI judgment + static
  fallback (§13.3-5), with prompt assembly consolidating into one shared
  layer (C2 fix) — one *prompt builder*, not one *prompt*.

### E2 · AI-authored permanent memory
- **WHAT:** the engine writes its observations into repo/org memory that
  later reviews trust permanently.
- **WHY SEXY:** "the tool learns my codebase" — the sticky feature.
- **MISSING:** ADR-003 authority model (this item is literally why it exists),
  V7 memory hierarchy, injection testing for memory writes (V7 untrusted
  surface), human promotion UX.
- **TRIGGER:** ADR-003 accepted and implemented, memory-write injection corpus
  (V7) green, promotion workflow proven in use — then `observed`-authority
  auto-rows may exist as *candidates*, still requiring human promotion before
  influencing anything.
- **INTERIM:** human-authored memory + mutes as built (`memory.py`,
  dashboard rows), plus evidence-backed *suggestions* in the review output
  ("consider adding this to project memory") — the engine proposes, a human
  commits it.

### E3 · Self-modifying prompts
- **WHAT:** the system rewrites its own prompts based on feedback results
  ("prompt evolution loop").
- **WHY SEXY:** sounds like automatic improvement; needs no human tuning.
- **MISSING:** V3-E03 eval harness to measure *any* prompt change (how do you
  know the rewrite helped?), V3-E02 for cost side-effects, prompt-version
  provenance, and an accountability path — an unreviewed self-edit that
  degrades security behavior is invisible by construction. Contradicts
  evidence-driven claims (vision §3.1).
- **TRIGGER:** versioned prompts + trend data (L12) exist, and a *human-*
  authored prompt iteration process has been running long enough to show what
  "measured improvement" looks like — automation of *suggestions* may then be
  proposed, with the same human-approval bar as ADR-003 promotions.
- **INTERIM:** prompt changes are ordinary PRs scored by the evaluation
  harness (TESTING §L12) — nobody has to wait for the loop to improve prompts;
  they just have to measure.

### E4 · Multi-agent loops without budgets
- **WHAT:** agents that spawn agents — re-plan, self-critique, retry until
  "done" — with no ceiling.
- **WHY SEXY:** frontier-model demos do this; looks maximally autonomous.
- **MISSING:** *every* V5 prerequisite: fan-out primitives (C1), shared prompt
  builder (C2), provenance for merge (C3/C4), non-global breakers (C5) — and
  the thing this entry exists for: **cost ceilings** (V5-E07 arbitration,
  V3-E02 telemetry; `COST_TOKEN_ARCHITECTURE.md` §6 gives V5 a 300k-token
  hard cap). Unbounded loops on BYO keys spend a user's money with no
  consent UX.
- **TRIGGER:** bounded fan-out (ADR-006) ships, is evaluated (V5-E08), and
  shows marginal quality gains per token that *justify* additional rounds —
  each round becomes an explicit budget line, not an open loop.
- **INTERIM:** bounded, declared agents per ADR-006: fixed batch count,
  fixed budgets, static fallback attribution when exhausted (§4.7 of the cost
  doc) — plus the existing per-batch static fallback as the pattern for
  "loop ends, truthfully labelled".

---

## Considered and dropped

- **Blockchain-anything** (tokenized review reputation, on-chain audit
  trails): evaluated for this list and dropped as not-architecture-relevant —
  it solves no problem in `MASTER_VISION.md`, introduces a supply-chain and
  cost liability, and no stakeholder proposal has ever mentioned it. Adding it
  would be strawmanning; if such a proposal appears, reject at PR time under
  vision §7 (cost-aware OSS) without needing an ADR.
- **Rewriting the engine in another language / adopting a web framework**
  — dropped because "no rewrite" (vision §3.5) already covers it; noted here
  only so it isn't rediscovered.

---

## Maintenance rules

1. New refusal candidates are added here in the same PR that proposes the
   feature elsewhere — a missing entry is a planning bug.
2. Removing an entry requires: trigger fired + prerequisite epic green +
   ADR (if the decision changes a boundary) — record the removal in
   `MASTER_ROADMAP.md` change log.
3. "We'll need it eventually" is not a trigger; measured need is
   (A3, C3, C4 are the templates).
4. Theme B items additionally require a `MASTER_VISION.md` §6 boundary
   re-decision — epics alone can never unlock them.

---

### Cross-references
Order & scope: `MASTER_ROADMAP.md` · Epics & prerequisites: `EPIC_BACKLOG.md` ·
Decisions: `ADR_INDEX.md` (001 monolith, 002 no graph DB, 006 bounded agents,
007 provider seam, 008 events>queues, 009 plugin contract, 010 tenancy,
014 telemetry) · Why measurement comes first: `COST_TOKEN_ARCHITECTURE.md`,
`TESTING_EVALUATION_PLAN.md` · Boundaries: `MASTER_VISION.md` §6.
