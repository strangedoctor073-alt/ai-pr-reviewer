# ADR INDEX — Architectural Decision Records

> Status: planning document (v1) — grounded in repository state described by
> `CURRENT_ARCHITECTURE.md` at commit `2841b23`. "Accepted (de facto)" = the
> code already embodies the decision; the ADR documents and constrains it.
> "Proposed" = requires human approval before any implementation work.

Conventions: Context cites **current** code (real file paths); forward-looking
statements name *likely modules* or *new subsystems*. "Revisit conditions" are
measurable triggers, not feelings — each names the metric or event that forces
a re-decision. Epics referenced (`V3-E02`, `V5-E07`, …) live in
`EPIC_BACKLOG.md`; stage order lives in `MASTER_ROADMAP.md`.

## Index

| ADR | Title | Status |
|---|---|---|
| ADR-001 | Modular monolith over microservices | Accepted (de facto) |
| ADR-002 | Repository graph as derived deterministic index | Proposed — requires human approval before implementation |
| ADR-003 | Memory authority model (human > evidence > AI observation) | Proposed — requires human approval before implementation |
| ADR-004 | Evidence as first-class records with provenance | Proposed — requires human approval before implementation |
| ADR-005 | Finding identity: v1 fingerprint accepted; identity v2 layered | Accepted (de facto) for v1; Proposed for v2 |
| ADR-006 | Bounded fan-out agent architecture under one orchestrator | Proposed — requires human approval before implementation |
| ADR-007 | Provider abstraction: structural protocol as the seam | Accepted (de facto) |
| ADR-008 | In-process pipeline first; events before queues | Accepted (de facto) / Proposed at the queue boundary |
| ADR-009 | Plugin contract deferred to V9, shipped V10 | Proposed — requires human approval before implementation |
| ADR-010 | Single-tenant now; multi-tenancy as a boundary, not a rewrite | Accepted (de facto) |
| ADR-011 | Storage evolution behind `ReviewStorage` | Accepted (de facto) |
| ADR-012 | Verification trust model: deterministic evidence only | Accepted (de facto) |
| ADR-013 | Event ingestion & webhook security posture | Proposed — requires human approval before implementation |
| ADR-014 | Local-first telemetry & cost accounting | Approved — human ratification 2026-10-06 |
| ADR-015 | Policy evaluation placement (engine, base revision) | Accepted (de facto) / org layer Proposed |
| ADR-016 | Testing gate strategy (deterministic blocks, AI trends) | Approved — human ratification 2026-10-06 |
| ADR-022 | Schema migration strategy: hand-rolled additive DDL until the V4 trigger | Proposed — adoption deferred (trigger stated in ADR-022) |

---

## ADR-001 — Modular monolith over microservices

**Status:** Accepted (de facto)

**Context:** The system is one Python process: `cli.py` →
`orchestrator.py` (composition root) → engine modules; the Action image is
built from `Dockerfile` + `requirements-action.txt`; the dashboard is an
optional second process (`uvicorn dashboard.app:app`) with an HTTP seam
(`X-Dashboard-Token`) that every engine call treats as best-effort
(`CURRENT_ARCHITECTURE.md` §7). No build step, pip only (AGENTS.md).
Dependency direction is already clean — `models`/`security`/`retry`/`circuit`
are leaves (§3).

**Decision:** Stay a modular monolith. Module boundaries are enforced by
import discipline and tests, not by process boundaries. The only sanctioned
process split is engine ↔ dashboard (existing, degrades to stateless).

**Alternatives considered:**
1. *Microservices per plane (repo intelligence, review, security…)* — rejected:
   pip-only/no-build constraint, Action image size, and network seams would
   replace in-process calls that complete in milliseconds.
2. *Async in-process services with message passing* — rejected for now:
   adds concurrency semantics (ordering, backpressure) with no measured need
   (C5 already shows global state is unsafe for concurrency — solve that
   first, not bypass it).

**Reasoning:** The 12 planes (`MASTER_VISION.md` §4) are *design* seams, not
deployment seams. Every plane today shares the same data model (`models.py`)
and lifecycle; splitting processes would duplicate schema (already done three
times for storage, §7 — proof of how costly duplication is).

**Consequences:** + one artifact, trivial OSS onboarding, no distributed
failure modes; + CI is `pytest` + `docker build`. − single-worker ceiling
(C9: per-process rate limiter, audit file, global breakers); − a memory leak
in one plane takes down the run; − org-scale concurrency will eventually force
the split question.

**Revisit conditions:** load layer (TESTING §2-L14) shows sustained need for
>1 engine worker per review **or** dashboard p95 latency fails at realistic
row counts with no query-level fix remaining; V9 organization platform scope
approved with concurrent multi-repo workloads.

**Links:** `CURRENT_ARCHITECTURE.md` §2-§3, §13.1 · `TARGET_ARCHITECTURE.md`
· `DO_NOT_BUILD_YET.md` (microservices) · V9 platform epics.

---

## ADR-002 — Repository graph as derived deterministic index

**Status:** Proposed — requires human approval before implementation

**Context:** Repository intelligence today is an 8-file bounded fetch
(`repo_context.py`, `MAX_CONTEXT_FILES`, 12k-char budget, defect D1: fetched
at PR *head*, not base). There is no symbol table, no dependency edges, no
impact analysis — plane 3 is 🔴/🟡 (`MASTER_VISION.md` §4). The "digital
twin" is defined as an *accumulating projection*, never a separate system
(§5-D).

**Decision:** Represent the repository as a **derived, deterministic,
regenerable index**: layered records (files → symbols → references/imports →
test↔source edges) stored relationally (SQLite/Postgres alongside existing
storage), computed by deterministic parsers, keyed by blob SHA so entries are
cacheable and stale entries are detectable. Traversals (impact set,
callers/callees) are computed in code over adjacency maps at query time.
**No graph database.**

**Alternatives considered:**
1. *Graph database (Neo4j/Neptune)* — rejected: new operational dependency
   violates pip-only/OSS-free defaults; indexes for PR-sized impact queries
   don't need persistent graph storage; the index must be regenerable from
   source anyway (a graph DB is a cache, not a source of truth).
2. *On-the-fly grep/embedding retrieval with no index* — rejected: C8 GitHub
   API pressure (no rate-limit handling) and per-run latency/cost; but pure
   retrieval *without* edges cannot answer "what does this change affect".

**Reasoning:** Deterministic-first (vision §3.2): index construction is code,
not model output; every index row carries provenance (blob SHA, parser,
timestamp) feeding the evidence model (ADR-004). Derivability means a corrupt
or stale index degrades to today's behavior (bounded fetch), never to a wrong
answer presented as right.

**Consequences:** + no new infrastructure; + rebuild-on-demand consistency;
+ index doubles as context retrieval for V4/V5. − first index build costs
tokens/API only insofar as file reads (bounded by `COST_TOKEN_ARCHITECTURE.md`
§6); − hand-rolled adjacency code for future query types; − index freshness
must be SHA-invalidated on every push.

**Revisit conditions:** impact queries at org scale exceed **proposed
baseline** p95 of 500 ms with in-code traversal optimized (L13); index size
exceeds **proposed baseline** 50 MB per medium repo; a query class appears
that needs recursive path queries no adjacency map handles cleanly.

**Links:** `MASTER_VISION.md` §5-C/§5-D · `DEPENDENCY_GRAPH.md` ·
`DO_NOT_BUILD_YET.md` (graph database) · V4 repository-intelligence stage.

---

## ADR-003 — Memory authority model (human > evidence > AI observation)

**Status:** Proposed — requires human approval before implementation

**Context:** Memory today is strictly human-authored: `memory.py` notes (fenced
on ingest into prompts) and dashboard mute rows `fingerprint:<fp>` (write-
protected). Vision is explicit: "AI-derived observations never become
permanent truth automatically" (§5-Q) and the platform "will not convert AI
observations into permanent organizational truth without human approval"
(§6). V7 builds the full hierarchy org→team→repo→component→PR→finding.

**Decision:** Every memory row carries an **authority level** and a provenance
record:

```
authority: human          > curated   > evidence   > observed   > inferred
(authored in UI/CLI/       (human-      (derived     (auto-       (AI model
 YAML/memory file)         approved     from logs/   recorded     hypothesis,
                           promotion)   tests/git)   facts)       never permanent)
```

Rules: (a) only `human` and `curated` rows can *influence* policy-like
decisions (mutes, thresholds); (b) `observed`/`inferred` rows expire or
require human promotion (promote/demote is an audited dashboard action);
(c) engine code never writes `human` authority (vision §3.3 — memory is never
written by the engine automatically); (d) promotions are append-only audited
(`dashboard/data/audit.jsonl` precedent).

**Alternatives considered:**
1. *AI self-writing memory (auto-commit observations)* — rejected: contradicts
   vision §3.3/§6; an injected PR could launder text into permanent truth
   (injection surface, V7 untrusted-input list).
2. *Flat single-tier memory with labels* — rejected: labels without enforced
   influence rules rot; the whole point is that low-authority rows must not
   be able to answer policy questions.

**Reasoning:** Authority must be a *field the pipeline enforces*, not prose in
a docstring — mirrors how lifecycle fields are pipeline-owned
(`Finding.from_untrusted_dict` strips them; memory authority is likewise
engine-owned, never model-owned).

**Consequences:** + promotions become the human-in-loop product surface; +
audit trail for "why did the reviewer do that"; − schema + migration work in
three storage implementations (§7); − more states to test (layer L16);
− curation burden — if promotion UX is poor, authority levels just accumulate
`observed` noise.

**Revisit conditions:** telemetry shows < **proposed baseline** 10% of
`observed` rows ever promoted over 3 months (authority model not pulling its
weight → collapse levels); V7 scope review; any incident where a low-
authority row influenced a policy decision (immediate re-decision).

**Links:** `MASTER_VISION.md` §5-Q, §3.3, §6 · `DATA_MODEL.md` ·
`SECURITY_ROADMAP.md` (V7 injection surface) · ADR-004, ADR-012.

---

## ADR-004 — Evidence as first-class records with provenance

**Status:** Proposed — requires human approval before implementation

**Context:** Vision §3.1: "Every important claim carries evidence (code, rule,
test output, history, tool result) with provenance. No unsupported certainty."
Today findings carry `explanation` prose and nothing machine-checkable;
verification's only evidence is diff coverage computed in code
(`verification.py:67-85`). There is no evidence store (listed under
"explicitly not present", `CURRENT_ARCHITECTURE.md` §14).

**Decision:** Evidence is a **record, not prose**: `{id, kind, locator,
retrieved_at, content_hash, summary}` where `kind ∈ {diff_hunk, file_excerpt,
symbol_def, test_result, log_excerpt, rule_ref, history_event}` and `locator`
is resolvable (path+SHA+line range, API URL, rule id). Findings and
verifications *reference* evidence ids; the record itself is content-addressed
so a claim can be re-validated later. Summaries shown to humans are rendered
from the record; the record itself holds no secrets (redaction on write).

**Alternatives considered:**
1. *Free-text citations inside `explanation`* — rejected: unparseable,
   uncheckable, drifts from the source; cannot support §3.1's "re-validated".
2. *Store full blobs (whole files, full logs)* — rejected: unbounded growth
   (C9 has no retention already) and privacy exposure; records store minimal
   resolvable slices + hashes.

**Reasoning:** Content addressing gives cheap integrity (hash mismatch ⇒
stale evidence ⇒ re-fetch or drop, never silently cite); ids let verification,
memory (ADR-003), and the dashboard point at the same artifact instead of
copying text (§7's duplication lesson).

**Consequences:** + findings become auditable ("show me why") — feeds the
review-quality benchmark (TESTING §L12); + V6 test-evidence tiers have a
storage home. − new subsystem with retention questions (must land with a
retention policy — bounded everything); − storage growth measurable in L14;
− three storage implementations to extend (§7).

**Revisit conditions:** retention policy breach under L14 load (cap needed
before features); evidence rows become dominated by one kind (schema should
specialize); ADR-012 needs to widen "evidence" beyond machine-checkable
kinds (re-decision required — that would be a trust-model change).

**Links:** `MASTER_VISION.md` §3.1, §5-J, §5-M · `DATA_MODEL.md` ·
`EPIC_BACKLOG.md` (V4 evidence records) · ADR-003, ADR-012.

---

## ADR-005 — Finding identity: v1 fingerprint accepted; identity v2 layered

**Status:** Accepted (de facto) for v1 · Proposed for v2 — requires human
approval before implementation

**Context:** Identity today is
`fingerprint = sha256(category|file|normalized_title)[:16]`
(`ai_pr_reviewer/findings.py:40-63`); **line number deliberately excluded** so
churn preserves identity ("line 42 moved to line 48" hashes identically).
Model output cannot set it — lifecycle fields stripped by
`Finding.from_untrusted_dict`. Known limits: title-based → cross-engine
wording differences do not dedup (documented gap, C4); no provenance fields
(C3) so relations (`caused_by`, `regression_of`) have nowhere to attach;
validation is title-normalization-sensitive (`findings.py:34`).

**Decision (v1, accepted):** keep the 16-hex title/file/category fingerprint
as the storage, lifecycle, mute, and comment-sync key. Do **not** change the
hash inputs — every stored `finding_history` row, mute row (`fingerprint:<fp>`
memory), and GitHub comment binding depends on it.

**Decision (v2, proposed):** layer identity instead of widening it:
1. add **provenance** fields to `Finding` (engine, model, agent, origin) —
   prerequisite C3/V4-E04/E05;
2. keep `fingerprint` as primary key; add an **occurrence key** for cross-engine
   matching = fingerprint + normalized anchor context, used only for dedup/merge
   decisions, never as storage key;
3. relations attach to (fingerprint, provenance) pairs, so two engines' renderings
   of one issue link explicitly instead of colliding.

**Alternatives considered:**
1. *Add line/anchor to the hash* — rejected: churn breaks identity exactly as
   `findings.py:44-50` documents; every force-push would mint duplicates.
2. *Content-hash the finding body* — rejected: model rewording on each run
   creates a new identity per run (defeats lifecycle and mutes).
3. *Random UUID per occurrence* — rejected: no cross-run dedup at all;
   lifecycle `new→active→resolved` collapses.

**Reasoning:** Identity must stay deterministic (vision §3.2). The defect is
not the hash — it is missing *attribution* (C3); fixing attribution fixes
council merge and cross-engine dedup without destabilizing stored state.

**Consequences:** + zero migration for existing rows; + relations become
possible at V5. − C4 duplicate comments persist until v2 merge logic ships;
− two identity concepts to explain (documented in the fingerprint docstring);
− title normalization changes remain breaking — treat normalization as frozen
until v2.

**Revisit conditions:** duplicate-rate metric exceeds **proposed baseline**
0.02 in V5 multi-engine runs (TESTING §4); V4-E05 provenance lands (v2 work
may start); any proposal to alter title normalization (auto re-decision —
identity-affecting).

**Links:** `CURRENT_ARCHITECTURE.md` §4 (finding identity), C3/C4 ·
`EPIC_BACKLOG.md` (V4-E04/E05 provenance, identity v2) · ADR-006, ADR-016.

---

## ADR-006 — Bounded fan-out agent architecture under one orchestrator

**Status:** Proposed — requires human approval before implementation

**Context:** One provider per run; failover returns first success; no
fan-out/merge primitive (C1). Shared single `SYSTEM_PROMPT`, prompt assembly
copy-pasted in three providers (C2). Process-global sequential-only circuit
breakers (C5). No provenance on findings (C3). `model_router.run_analysis`
already does per-batch static fallback — the batching seam exists. V5 is
"multi-agent review" in the canonical stage order.

**Decision:** Agents are **declarative descriptors, not autonomous processes**:
`{id, scope(paths/categories), prompt_variant, capability requirements,
budget, output schema}` instantiated by the existing orchestrator, which fans
out **bounded** calls (max agents/batches from config, default within
`COST_TOKEN_ARCHITECTURE.md` §6), then runs the *same* deterministic
post-pipeline for every agent output: parse → dedup → validate → lifecycle →
verify. One shared prompt-builder/prompt-variant layer replaces the
triplicated assembly first (C2). Agents have no tools, no memory writes, no
GitHub access; only the orchestrator posts, once, with provenance-labelled
findings.

**Alternatives considered:**
1. *Autonomous agent loop (plan→act→observe until satisfied)* — rejected:
   unbounded cost (no budget primitive exists), violates bounded-everything
   (vision §3.6) and the no-autonomous-writes boundary (§6); also untestable
   under today's harness.
2. *External workflow engine (Temporal/Celery) for agent orchestration* —
   rejected: infrastructure dependency contradicts the monolith (ADR-001) and
   pip-only OSS posture; premature before fan-out is even proven useful.

**Reasoning:** Multi-agent value is *specialized judgment plus deterministic
merge*, not agency. Deterministic post-pipeline reuse means every new agent
inherits validation/redaction/anchoring for free; provenance (ADR-005 v2)
prevents cross-agent dedup from destroying attribution.

**Consequences:** + parallel recall gains without new trust surface; +
per-agent metrics (precision/cost) fall out of V3-E02/V3-E03; − C5 must be
fixed (per-backend breaker state) before parallel calls — hard prerequisite;
− merge/dedup complexity (C4) concentrates at the council seam; − latency
improves only if calls are truly concurrent (today sequential, §12).

**Revisit conditions:** C1/C3/C5 prerequisites not green → do not start;
V5-E08 evaluation shows council quality delta ≤ **proposed baseline** 3 pp
over single-agent at ≥ 1.5× cost (re-evaluate whether fan-out is worth it);
fan-out budget exhaustion becomes routine (> **proposed baseline** 20% of
runs) → shrink scope or re-decide.

**Links:** `MASTER_VISION.md` §5-E/§5-F · `AI_AGENT_ARCHITECTURE.md` ·
`EPIC_BACKLOG.md` (V5-E07 cost arbitration, V5-E08 evaluation) ·
ADR-005, ADR-007, ADR-014.

---

## ADR-007 — Provider abstraction: structural protocol as the seam

**Status:** Accepted (de facto)

**Context:** `AIProvider` protocol = `analyze(context) → AnalysisOutcome`
plus informal `backend` + `startup_warnings` contract; three AI
implementations + `StaticProvider`, feature-identical by construction but
implemented by copy-paste (shared `SYSTEM_PROMPT`, batching, fencing helpers,
per-batch fallback, triplicated `_extract_json`). Adding a backend touches 7
hard-coded sites (`AI_BACKENDS`, `select_backend`, `build_provider`, `Config`,
CLI, `action.yml`, reporter labels) — §10.1. No capability declaration, no
discovery. Only Claude has a default model; retired IDs are banned
(`tests/test_release_hardening.py`).

**Decision:** Keep the structural protocol as *the* provider seam — extend,
don't replace. Evolution path: (a) consolidate prompt assembly + JSON
extraction into one shared layer (kills the C2 copy-paste); (b) add an
explicit capability/metadata declaration (supported modes, usage parsing,
vision, streaming) consumed by routing; (c) collapse the 7 hard-coded sites
into one registry; (d) leave plugin-grade discovery to ADR-009/V10.

**Alternatives considered:**
1. *Adopt a unified LLM SDK (litellm-style) as the abstraction* — rejected:
   provider-neutral core is an OSS promise (vision §3.7, §7); a third-party
   aggregator becomes a supply-chain and breakage dependency in the Action
   image, and doesn't cover our static/fallback semantics anyway.
2. *Abstract base class with formal inheritance + negotiation* — rejected for
   now: the structural protocol already works; formalizing adds ceremony
   without removing any of the 7 hard-coded sites — the registry does.

**Reasoning:** The seam is proven (`ReviewStorage`/`AIProvider` are the two
things §13.10 says to extend carefully). Cost telemetry (ADR-014) will attach
to `analyze()`'s return — one more reason the protocol stays narrow and its
outcome type carries the data.

**Consequences:** + provider additions become one registry entry after
consolidation; + task routing (V5) has capabilities to route on; − informal
contract (`backend`, `startup_warnings`) stays undocumented-in-types until
formalized; − three providers still drift until the shared layer lands;
− usage parsing asymmetry persists (Gemini TODO, `ai/gemini.py:159`) until
ADR-014.

**Revisit conditions:** a 4th backend still requires > **proposed baseline**
3 code sites after registry consolidation (abstraction leaking → re-decide);
V10 local providers need runtime discovery; capability metadata grows
contradictions (e.g. two providers claiming incompatible mode semantics).

**Links:** `CURRENT_ARCHITECTURE.md` §8, §10.1 · `COST_TOKEN_ARCHITECTURE.md`
§3 · `DO_NOT_BUILD_YET.md` (giant unified model) · ADR-006, ADR-009, ADR-014.

---

## ADR-008 — In-process pipeline first; events before queues

**Status:** Accepted (de facto) for the pipeline · Proposed at the queue
boundary — requires human approval before implementation

**Context:** Everything is synchronous in-process: orchestrator stages run
sequentially, batches are sequential (§12), dashboard single-worker, breakers
process-global (C5). There is no event bus, no queue, no workers (§10.5).
Vision stages internal events at V8, webhooks at V9, and a "queue only where
justified" (§5-AG/AH).

**Decision:** (a) Phase 0: keep the synchronous pipeline; formalize **typed
in-process events** (dataclass records appended to a run-scoped list — review
started, batch done, fallback taken, budget exhausted — the same records as
telemetry, ADR-014) instead of ad-hoc warnings. (b) At V8, events are written
through a small dispatcher interface so subscribers (reporter, telemetry,
audit) stop being hand-wired call sites. (c) An external queue/worker is
allowed **only** when a measured trigger fires — never preemptively.

**Alternatives considered:**
1. *Stand up broker-backed queues now (Rabbit/Redis/Kafka)* — rejected:
   nothing to queue (one review per process), operational cost on the free
   path, ADR-001; `DO_NOT_BUILD_YET.md` (event-driven queue infrastructure).
2. *No events at all, keep scattered callbacks* — rejected: as V5/V8 add
   subscribers, call-site fan-out becomes the next C2-style copy-paste and
   telemetry (V3-E02) needs one canonical stream anyway.

**Reasoning:** Events-first gives the observability spine a stable shape at
near-zero cost (dataclasses), while deferring the only genuinely
distributed-systems decision until load data (L14) exists to justify it.

**Consequences:** + telemetry/audit/reporter share one stream; + queue
adoption later is a swap of the dispatcher back-end, not a rewrite; −
discipline required to keep events synchronous (an event handler must never
block the review — invariant §13.6); − run-scoped event lists must be bounded
(memory ceiling).

**Revisit conditions:** measured trigger — sustained concurrent workloads
beyond one process (L14) **or** webhook ingestion (ADR-013/V9) exceeding
single-process handling with bounded latency; V8 CI-event volume data in hand;
event list growth > **proposed baseline** 1,000 events/run (trim first, queue
never).

**Links:** `COST_TOKEN_ARCHITECTURE.md` §3 · `MASTER_VISION.md` §5-AG/AH ·
`DO_NOT_BUILD_YET.md` (queues, distributed tracing) · ADR-013, ADR-014.

---

## ADR-009 — Plugin contract deferred to V9, shipped V10

**Status:** Proposed — requires human approval before implementation

**Context:** Extension points today are internal only: static rule pack
(`static/engine.build_default_registry()` tuple — the single wiring point),
provider protocol, `ReviewStorage`. "No plugin system, no event bus, no
versioned API, no public extension contract" (§10.5). Vision: "AI Plugin
architecture — V9 defines the contract, V10 ships it" (§5), and community
surface is rule packs + provider adapters until then (§7).

**Decision:** Define the plugin contract **as a document + conformance suite
first (V9)**, ship runtime loading in V10. Contract sketch: three plugin kinds
(rule pack, provider adapter, reporter/exporter), versioned input/output
schemas (finding-shaped data only), **declared resource budget** (enforced
hard-stop, `COST_TOKEN_ARCHITECTURE.md` §6), sandboxed trust level (plugin
output is untrusted input — same fencing/redaction pipeline as model output),
no direct GitHub or memory writes (only the orchestrator posts; authority
model ADR-003 blocks memory writes), deterministic-only plugins may gate CI,
AI plugins never gate PRs (ADR-016).

**Alternatives considered:**
1. *Ship entry-points discovery now* — rejected: contract would be frozen by
   the first third-party adopter with no evaluation harness behind it
   (V3-E03 must prove the finding/evidence schemas first — ADR-004/005).
2. *No contract, "copy a rule pack into the tree"* — rejected as final state,
   acceptable interim: it is exactly today's contribution model (§7), but it
   gives orgs no isolation and us no compatibility guarantee.

**Reasoning:** Contracts are cheap to write and expensive to break; shipping
before the data model (evidence, identity v2, authority) stabilizes would
enshrine pre-V5 shapes.

**Consequences:** + community extensibility without core fork; + conformance
suite doubles as an 18th test layer (TESTING §6); − contributors wait for V9/
V10 — interim path must be documented so it doesn't feel like gatekeeping;
− sandboxing interpreted plugins is hard — worst case is "trusted, reviewed
plugins only", stated honestly.

**Revisit conditions:** first credible external request that a rule pack
cannot satisfy (contract requirements gathering trigger); data-model stability
(evidence/identity/authority schemas unchanged for **proposed baseline** one
minor release) unlocks V9 drafting; a security review of plugin loading
completes before any runtime loading ships.

**Links:** `MASTER_VISION.md` §5 (AI), §7 · `TARGET_ARCHITECTURE.md` ·
`DO_NOT_BUILD_YET.md` (plugin marketplace, IDE plugins) · ADR-003-006, ADR-016.

---

## ADR-010 — Single-tenant now; multi-tenancy as a boundary, not a rewrite

**Status:** Accepted (de facto) for single-tenant · multi-tenant boundary
Proposed — requires human approval before implementation

**Context:** One install = one user/team's GitHub org + optional one dashboard
with a single shared token (`DASHBOARD_TOKEN`, `hmac.compare_digest`, weak-
token refusal). All storage keys are `repo#pr`-namespaced but assumptions are
single-process and single-user: per-IP rate limiter is per-process, audit file
per-process, breakers process-global (C5), "multi-tenant impossible" is the
stated C5 consequence. Vision: hosted multi-tenant is an optional V10 future
option, "never a commitment" (§5-AK).

**Decision:** (a) Stay single-tenant through V9; no tenant columns, no billing,
no per-tenant isolation work. (b) But **maintain the boundary as a code rule**:
all identity/authorization flows through one module seam (dashboard auth +
storage key construction), so a future tenant layer adds scoping there rather
than auditing every query; the Action's repo slug is the natural tenant key.
(c) Any code that would hardcode cross-tenant assumptions (global mutable
per-run state shared across repos in one process) must route through per-run
context instead — C5's fix is a prerequisite for *any* concurrency, tenant or
not.

**Alternatives considered:**
1. *Build full multi-tenancy now (V10 scope creep)* — rejected: no hosting
   product exists, no demand evidence, and it would tax every storage change
   today for a future that may never ship.
2. *Ignore the boundary entirely (hardcode single-user)* — rejected: the
   cheap version of this is the current three-way storage duplication (§7);
   every new query duplicated three times without a scoping seam makes the
   eventual boundary far more expensive.

**Reasoning:** The expensive part of multi-tenancy is retrofit; the cheap part
is keeping identity/scoping centralized while single-tenant. This buys the
option without paying for the product.

**Consequences:** + V10 hosted option remains open without rewrite; + forces
per-run context hygiene now (helps C5 anyway); − small ongoing tax (one seam
to route through); − temptation to half-build tenant fields — explicitly out
of scope until the V10 gate.

**Revisit conditions:** V10 scope review explicitly approves a hosted option;
organizational demand (named design partners) for SaaS; L14 shows one process
cannot serve even single-tenant org load (which is an ADR-001/008 problem
first, not a tenancy problem).

**Links:** `CURRENT_ARCHITECTURE.md` §7, C5 · `MASTER_VISION.md` §5-AJ/AK, §7 ·
`DO_NOT_BUILD_YET.md` (multi-tenancy/hosted SaaS, org rankings) · ADR-001,
ADR-008, ADR-011.

---

## ADR-011 — Storage evolution behind `ReviewStorage`

**Status:** Accepted (de facto) for the seam · evolution steps Proposed —
requires human approval before implementation

**Context:** `ReviewStorage` Protocol with two implementations for the engine
(`LocalReviewStorage` stdlib sqlite3; `DashboardStorageClient` httpx) plus two
dashboard-side (`DbStorage` SQLAlchemy, `JsonStorage` fallback) — the same
logical schema exists three times (§7). Two optional capabilities are
deliberately undeclared and reached via `getattr` guards (§10.3); hand-rolled
`ALTER TABLE` migrations; connections opened per call, never closed; no
retention (C9); dashboard reads load all rows into Python.

**Decision:** (a) `ReviewStorage` stays the data-access seam — §13.10, extend
don't replace. (b) Consolidate schema knowledge: one declarative schema +
migration list consumed by both implementations (engine and dashboard),
replacing divergent hand-rolled DDL. (c) Declare optional capabilities in the
protocol properly (or a runtime-checkable capability set), retiring `getattr`
guards. (d) Add retention/pruning *before* new entity types (evidence,
telemetry) land — bounded storage is a vision §3.6 requirement, not cleanup.
(e) JsonStorage survives only while the zero-dependency fallback matters
(§14).

**Alternatives considered:**
1. *Standardize on SQLAlchemy in the engine too* — rejected for the Action
   path: `requirements-action.txt` must stay lean; stdlib sqlite3 is a
   feature of the free Action image, not an accident.
2. *Rip-and-replace with event-sourced store* — rejected: violates no-rewrite
   (vision §3.5); event sourcing adds ordering/replay semantics with zero
   product requirement today.

**Reasoning:** The pain is duplicated *schema knowledge*, not the protocol.
One schema source removes D12-style convention-syncing (the same failure mode
already documented for security baselines) and makes migration testing (TESTING
§L16) possible at all.

**Consequences:** + one migration story; + capability honesty (no silent
behavior variance per backend); + retention fixes C9's unbounded growth; −
engine/dashboard decoupling effort (HTTP contract must version); − migration
harness must cover three upgrade paths (old SQLite → new, JsonStorage, HTTP
report compat).

**Revisit conditions:** schema change frequency exceeds **proposed baseline**
2 changes/release (harness must exist by then); a third entity family
(telemetry/evidence) lands before consolidation (consolidation becomes
blocking); load layer fails with query-level fixes exhausted (read-model work
triggers re-decision).

**Links:** `CURRENT_ARCHITECTURE.md` §7, §14, C9, D7, D12 ·
`DATA_MODEL.md` · `TESTING_EVALUATION_PLAN.md` §L16 · ADR-004, ADR-010,
ADR-014.

---

## ADR-012 — Verification trust model: deterministic evidence only

**Status:** Accepted (de facto)

**Context:** `verification.py` is pure deterministic, no I/O: for each finding
it computes coverage of the flagged line range in the current diff
(`_coverage`, lines 67-85) and assigns one of three states —
`resolved | still_present | unable_to_verify`
(`verify_findings`, line 85); `_unverify()` (line 139) reverts a premature
`resolved → active` when the revert path detects the finding still present.
Model output can never assert verification status (lifecycle fields stripped
at parse). Known defect D2: verification receives the *capped* (max 20) list
as "current" (`orchestrator.py:183-189` vs `verification.py:85-136`), so a
still-present finding pushed out of the cap can be synthesized as resolved.

**Decision:** The trust rule is invariant: **verification status is computed
by deterministic code from machine-checkable evidence; the model is never an
authority on whether something is fixed** (vision §3.2). Evolution adds
*evidence sources*, not *evidence authorities*: V6 may add test-output
evidence (run artifacts, coverage deltas) and diff-context evidence — each
source must be a record (ADR-004) with a deterministic checker. D2 must be
fixed (verification receives the uncapped current set) **before** any new
evidence tier ships.

**Alternatives considered:**
1. *Model self-verification ("I re-read the diff, it looks fixed")* — rejected:
   non-reproducible, spoofable by prompt injection, contradicts §3.2/§3.3;
   a "resolved" that is wrong erodes the one thing reviewers trust.
2. *No verification until code-execution sandboxing exists* — rejected: the
   coverage model already works and is cheap; waiting discards a proven
   feature for a strictly stronger (and much riskier) one.

**Reasoning:** Verification is the product's honesty anchor ("verified"
claims must mean a check ran). Evidence tiers scale confidence **up** only
when the check itself is deterministic; `unable_to_verify` remains a first-
class, non-shameful answer (§3.1 "we don't know" is valid).

**Consequences:** + every tier upgrade is testable (L1 regression corpus);
+ no new trust surface for attackers; − coverage-only verification is
conservative — many real fixes land as `unable_to_verify` (measure the rate);
− D2 fix changes report semantics (findings once shown resolved may return to
active — a visible behavior change users must be told about in release notes).

**Revisit conditions:** D2 fixed (prerequisite for tier work); premature-
resolved rate exceeds **proposed baseline** 0.01 (TESTING §4) on the
evaluation corpus; V6 proposes an evidence source that is *not*
deterministically checkable → hard re-decision, default no.

**Links:** `CURRENT_ARCHITECTURE.md` §5.5, D2 · `MASTER_VISION.md` §5-M, §3.2 ·
`TESTING_EVALUATION_PLAN.md` (verification accuracy) · ADR-004, ADR-016.

---

## ADR-013 — Event ingestion & webhook security posture

**Status:** Proposed — requires human approval before implementation

**Context:** Today events arrive only through the GitHub Action trigger
(`pull_request`, explicitly never `pull_request_target` — §13.8, enforced by
tests) with base-revision checkout and minimal permissions (`contents: read`,
`pull-requests: write`, no `checks: write`). V9 introduces webhooks (vision
§5-AG) — i.e., the repository's runtime starts accepting **network input
chosen by GitHub (and thus by anyone who can trigger repository events)**,
bypassing the Actions trust framing. V9 is also on the untrusted-surface list
for injection testing (§5-T).

**Decision (design constraints to approve at V9):**
1. Webhook receiver verifies `X-Hub-Signature-256` with a dedicated secret,
   constant-time compare (same primitive as `dashboard` token —
   `hmac.compare_digest` precedent), rejects unsigned/mismatched bodies before
   any parsing.
2. Payload is **untrusted input end-to-end**: nonce-fencing +
   `scan_prompt_injection` + `redact_secrets` exactly like PR diffs
   (`security.py` pipeline) — no new trust category for "events".
3. Ingestion is **read-only**: webhooks enqueue analysis/review work
   (ADR-008 dispatcher) and never grant write scopes beyond the Action's
   existing comment permissions.
4. Idempotency keys (`delivery_id`) and rate limiting on the receiver;
   secret rotation procedure documented; delivery failures fail closed
   (drop + log), never partial-trust retries.

**Alternatives considered:**
1. *Poll the GitHub API instead of receiving webhooks* — rejected: polling
   has no signature problem but multiplies API pressure (C8, already no
   rate-limit handling) and latency; keep polling as the *degraded* mode, not
   the design.
2. *Accept events without signature, rely on IP allowlisting* — rejected:
   GitHub IP ranges change; signatures are the documented mechanism; IP trust
   is spoofable and brittle.

**Reasoning:** The security model is proven for Action-mediated input;
webhooks must reuse it verbatim rather than invent a second ingestion model —
one untrusted-input pipeline is auditable (vision §3.3/§6).

**Consequences:** + no new fencing code paths for events; + idempotency makes
replays harmless; − receiver adds an always-on network surface (new process
concern, tension with ADR-001 — it must be optional and off by default);
− webhook secret management is a user burden → docs deliverable before code.

**Revisit conditions:** V9 scope approval (nothing before then); a security
review + threat model pass (`SECURITY_ROADMAP.md`) before the receiver ships;
any proposal to auto-act on event content (re-decision — default stays
read-only).

**Links:** `CURRENT_ARCHITECTURE.md` §6 (security boundary), §13.8 ·
`SECURITY_ROADMAP.md` · `MASTER_VISION.md` §5-AG/AH, §5-T · ADR-008, ADR-016.

---

## ADR-014 — Local-first telemetry & cost accounting

**Status:** Approved — human ratification 2026-10-06 (telemetry & cost
direction)

**Context:** Token counters exist on Claude/OpenAI providers but are dead —
never copied into `AnalysisOutcome` (`models.py:292-307`), report JSON, or
storage; Gemini usage unparsed (`ai/gemini.py:159`); budgets are characters
(C7); there is no cost model anywhere (C6). Dashboard `/api/metrics`
(`dashboard/app.py:657`) reports counts, not spend. Free/OSS BYO-keys posture
(vision §3.7) means *users* own the API bills — but nothing shows them.

**Decision:** Telemetry is **local-first and content-free**:
- one `telemetry` block in the report JSON + optional storage rows, captured
  at provider/router/context boundaries (design in
  `COST_TOKEN_ARCHITECTURE.md` §3), persisted only where the user already
  persists reports (their SQLite, their dashboard, their artifact);
- **no telemetry egress to any endpoint we operate** — aggregate statistics
  exist only if a user points their dashboard somewhere (and default: nowhere);
- rows carry counts/durations/ids/status classes — **never code, finding
  text, prompts, or memory** — enforced by a single serialization chokepoint
  plus a security-layer scan test;
- cost = tokens × price table kept in config (not hardcoded per provider —
  mirrors the retired-model-ID discipline of `test_release_hardening.py`);
- backward-compatible field additions only (append-only report keys,
  `base_sha` precedent `models.py:225`);
- dashboard is a consumer: metrics tab + optional budget alerts; budget hard
  stop and fallback attribution per `COST_TOKEN_ARCHITECTURE.md` §4.7.

**Alternatives considered:**
1. *Third-party APM (Sentry/Datadog/OTel collector) as source of truth* —
   rejected: phones user code/runtimes home, adds paid deps to the free path,
   contradicts vision §7; OTel *export format* may be offered later as an
   opt-in sink (revisit below), never the default store.
2. *No telemetry (status quo)* — rejected: C6 explicitly blocks cost
   control, depth control, and any evidence that optimizations work; vision
   §5-V makes V3-E02 the precondition for everything downstream.

**Reasoning:** "Nothing can be managed that isn't measured" (vision §5-V),
but the trust boundary says our defaults must never move user data outward —
measurement for the *user's* benefit, in the *user's* stores.

**Consequences:** + C6 unblocked → V5-E07 arbitration, V9-E07 dashboards,
cost visibility for BYO-key users; + evaluation harness gets operational
metrics (TESTING §4); − storage growth (retention required, ADR-011);
− price tables drift → cost figures labeled estimates; − no fleet-wide
aggregate data for our own roadmap decisions (accepted trade-off; see
revisit).

**Revisit conditions:** roadmap decisions would materially benefit from
aggregate usage stats → propose a *separate*, opt-in, counts-only anonymous
rollup (explicit human approval, privacy review — not implicit); export
formats requested (JSON/CSV/OTel) → add as opt-in sinks; price-table update
cadence proves annoying → move table to a versioned external file.

**Links:** `COST_TOKEN_ARCHITECTURE.md` (whole) · `TESTING_EVALUATION_PLAN.md`
§4 · `EPIC_BACKLOG.md` (V3-E02, V5-E07, V9-E07) · ADR-007, ADR-008, ADR-011.

---

## ADR-015 — Policy evaluation placement (engine, base revision)

**Status:** Accepted (de facto) for repo scope · org layer Proposed — requires
human approval before implementation

**Context:** Project policy is `.ai-pr-reviewer.yml` read from the **PR base
revision** (so a PR cannot rewrite its own review rules — enforced by tests
and stated as a security invariant), with the privacy exclusion baseline in
`rules.py` non-removable (repo config may only add exclusions). Dashboard
rules and `INPUT_*`/CLI merge via the config layering (CLI > INPUT_* > env >
defaults, plus two orthogonal merges). Duplicate security baselines exist in
`rules.py` and `dashboard/app.py` (D12) synced only by convention. Policy
evaluation has no engine of its own — `rules.py` parses into `ReviewPolicy`
and the orchestrator applies thresholds inline (D3/D4 show the sharp edges).

**Decision:**
1. **The engine is the single evaluation point**, at review time, with the
   base revision as the source of truth for repo-authored policy. The
   dashboard may *author* settings but never *evaluates* policy for the
   engine — the engine re-reads and re-merges (fail-closed: unreadable policy
   = baseline only + warning).
2. Merge order stays: CLI/env (operator) > `INPUT_*` (workflow) > project
   policy (repo, base revision) > dashboard (operator convenience) > built-in
   defaults — with the privacy baseline **outside** the merge (non-removable,
   only additive).
3. D12 duplicate baselines collapse into one module consumed by both engine
   and dashboard (same consolidation instinct as ADR-011).
4. V9 org policy composes downward (org > team > repo > component) as an
   additional *input* to the same engine-side merge — evaluated where the code
   runs, not by a central service.

**Alternatives considered:**
1. *Dashboard-authoritative policy (evaluate at the dashboard, ship decisions)*
   — rejected: engine must work dashboard-less (free path) and during
   dashboard outages (§13.6 degrade-don't-fail); a remote evaluator becomes a
   single point of failure and a trust hop.
2. *Central org policy service* (V9 shortcut) — rejected: adds network
   dependency to every review, contradicts Action-first posture; inheritance
   logic is pure data merging — it belongs in-process.

**Reasoning:** Policy is deterministic (vision §3.2) and security-relevant
(base-revision rule exists precisely because policy is an attack surface);
one evaluator, fail-closed, offline-capable is the only shape consistent with
the trust boundary.

**Consequences:** + single place to test policy semantics (regression corpus
gets a policy layer); + org inheritance is data, not infrastructure; −
operator-vs-repo precedence subtleties must be documented (current docs lean
on `README.md`); − dashboard edits apply on the *next* review, not instantly —
must be surfaced in UX to avoid "I changed it and nothing happened".

**Revisit conditions:** D12 divergence incident (immediate consolidation
trigger); V9 org scopes approved (inheritance implementation begins);
any request to evaluate policy at post time instead of review time (re-decision
— changes the fail-closed story).

**Links:** `CURRENT_ARCHITECTURE.md` §1 (config layering), §6, D12, D13 ·
`SECURITY_ROADMAP.md` · `MASTER_VISION.md` §5-R · ADR-003, ADR-011, ADR-016.

---

## ADR-016 — Testing gate strategy (deterministic blocks, AI trends)

**Status:** Approved — human ratification 2026-10-06 (deterministic eval
gate)

**Context:** CI is `pytest` on 3.11–3.13 + `docker build` (`.github/workflows/
ci.yml`) — no lint, no types, no coverage (D14); ruff is configured at a
"critical defects only" baseline and explicitly not installed/not in CI
(`pyproject.toml:14-31`). 464 hermetic tests exist; nothing measures *review
quality* (no corpus, no telemetry — C6). The evaluation layers that cost
tokens cannot be PR-blocking without making CI flaky on vendor nondeterminism
and price/behavior drift.

**Decision:** Two-tier gates (design in `TESTING_EVALUATION_PLAN.md` §5.4):
1. **Tier A — blocking every PR:** deterministic layers only: unit,
   integration, contract cassettes/stubs, security, static injection/FP/FN
   corpus, regression + known-bug corpora, in-process failure injection,
   golden-file migrations, performance smoke at generous **proposed**
   thresholds. Plus (cheap, high value) **enable ruff's existing E9/F63/F7/F82
   set in CI as blocking** — it is already configured, installing it is a
   one-line CI change. Type checking deferred until a baseline is clean;
   coverage is *measured* first, thresholds enforced later.
2. **Tier B — scheduled, non-blocking:** all AI/model layers (model eval,
   quality benchmark, live smokes, adversarial injection) with **trend gates**:
   rolling-baseline regression > **proposed baseline** 10 pp opens an issue /
   labels the owner — never a red PR on a contributor's change. `xfail`-marked
   known-bug cases (TESTING §L8) keep open defects visible without blocking.

**Alternatives considered:**
1. *Block PRs on AI evaluation results* — rejected: model vendors change
   behavior under us (nondeterminism + deprecations) → red CI unrelated to
   the change trains people to bypass gates; also violates the cost rule
   (evals on every PR).
2. *No new gates (status quo)* — rejected: D14's drift risk compounds as the
   codebase grows, and quality claims ("better review") would remain
   unfalsifiable — vision §3.1 requires evidence for claims, including ours.

**Reasoning:** A gate is only useful if its failure means "the change is
bad". Deterministic failures mean that; model-quality variance does not.
Trend gates still catch real regressions — they just attribute them to the
change *or* the vendor via corpus deltas and telemetry instead of to whoever
pushed.

**Consequences:** + CI catches the D6-class bugs (raw tracebacks) instantly;
+ quality regressions get owners, not silence; + free contributors keep fast,
free CI; − no type safety yet (deferred deliberately); − trend gates need
someone to read issues (process, not code); − perf-smoke thresholds risk
flakiness → start generous, tighten with data.

**Revisit conditions:** first month of Tier B data collected (calibrate the
10 pp / p95 numbers from measurement, not opinion); a Tier B regression is
caught *late* twice in a quarter → consider promoting that specific metric to
blocking for engine-owning maintainers only; mypy baseline run shows
low-noise adoption (re-decide type gate).

**Links:** `TESTING_EVALUATION_PLAN.md` (whole, esp. §2/§5.4) ·
`CURRENT_ARCHITECTURE.md` D14, §13 · `COST_TOKEN_ARCHITECTURE.md` §6 (eval
budgets) · ADR-005 (corpus identity), ADR-012 (deterministic verification).

---

## ADR-022 — Schema migrations: hand-rolled additive DDL now, real tool at the V4 trigger

**Status:** Proposed — adoption deferred; the trigger review below is itself a
human-approval checkpoint (V3-E04-T06 is proposal-only, no code changed).

**Context:** Every schema change today is hand-rolled, additive-only, and
spread over two sites with no shared ledger:

- **Engine — `LocalReviewStorage` (`ai_pr_reviewer/storage.py`):**
  `CREATE TABLE IF NOT EXISTS` for `review_state`, `finding_history`,
  `repo_memory`, `telemetry`, then a *tolerated-failure* loop of
  `ALTER TABLE repo_memory ADD COLUMN category/enabled/updated_at` — each
  statement may raise `OperationalError` and is swallowed, because SQLite has
  no `ADD COLUMN IF NOT EXISTS`.
- **Dashboard — `DbStorage` (`dashboard/storage.py`):** SQLAlchemy
  `create_all()` for missing tables, `_add_missing_columns()` (inspect the
  table, `ALTER TABLE ... ADD COLUMN` per `_COLUMN_UPGRADES`: three
  `repo_memories` columns, three `reports` metric columns — failures are
  logged and skipped), the V3-E04 payload-derived `reports` backfill, and
  `CREATE INDEX IF NOT EXISTS ix_finding_histories_repo_pr`.
  `JsonStorage` needs no DDL — file layouts evolve by convention.

Inventory as of V3-E04: 2 code sites, 7 columns, 1 index, 0 down-migrations,
0 version table. **Failure modes accepted at this size:** no single answer to
"which migration version is this database at" (correctness comes from
inspect-then-add idempotence plus tests, not from a recorded history); a
statement that fails permanently surfaces later, at query time, as a logged
skip; the two sites can drift (engine SQLite-only, dashboard SQLite +
Postgres — the Postgres branches only ever run where a Postgres instance
exists); there is no mechanism for down-migrations or non-additive rewrites —
only the policy in `MIGRATION_PLAN.md` §3.1 keeps changes safe.

**Decision:** Stay hand-rolled until a trigger fires; at the trigger, adopt a
real migration tool selected against the criteria below.

1. **Mandatory trigger — first non-additive schema change** (column drop /
   retype / rename, or any backfill whose correctness depends on order or
   conditional logic): hand-rolled inspect-then-add cannot express it, so the
   change may not be attempted without a tool.
2. **Scheduled review — first V4 storage addition** (V4-E01's `repo_index`
   and friends per `MIGRATION_PLAN.md` §3.2, proposed baseline): review
   whether adoption starts there; either outcome (adopt / one more stage of
   hand-rolled) must be recorded as an ADR status change.
3. **Review also when** the inventory reaches a third hand-rolled site, or a
   hand-rolled migration needs a second corrective fix — either means the
   pattern is carrying more than inspection can prove.

**Tool evaluation criteria** (applied at the trigger):

- Must support both dashboard backends: **SQLite in WAL mode and PostgreSQL**
  (`DATABASE_URL`); engine SQLite is a bonus, not a requirement.
- Pip-installable with no build step (AGENTS.md), and it must **not** enter
  the Action image (`requirements-action.txt` stays lean) — a dashboard-only
  dependency is acceptable.
- Records an ordered, inspectable migration history (a ledger) and runs
  idempotently beside tables/columns already created by `create_all()` /
  the hand-rolled paths (baseline/autogenerate against the existing metadata
  without rewriting history).
- Testable offline in CI against a SQLite file; upgrade path must keep the
  current startup behavior (migrate-on-open) or ship a documented CLI step.
- Front-runner to evaluate first: **Alembic** (native to the SQLAlchemy
  stack already in `dashboard/`); lightweight alternative: a small
  ordered-script runner (e.g. yoyo) if Alembic's footprint outweighs its
  benefits.

**Alternatives considered:**
1. *Adopt Alembic now* — rejected: seven columns and one index do not yet
   justify a dependency, a migration-authoring workflow, and CI surface; the
   additive policy plus tests has produced zero schema incidents so far.
2. *Stay hand-rolled indefinitely* — rejected: the failure modes above
   compound with every V4+ stage (`MIGRATION_PLAN.md` §3.2 grows to ~15
   tables), and a non-additive change would arrive with no mechanism to
   express it.

**Reasoning:** The cost of a migration tool is fixed (dependency + workflow);
the cost of hand-rolling scales with schema complexity and with how close
changes get to being non-additive. At V3's size the hand-rolled path is
genuinely simpler *and* already carries its dangerous edge (tolerated
failures) inside two small, tested functions — but the roadmap's first
non-trivial schema growth is V4, which is exactly where the trade flips.

**Consequences:** + no dependency or workflow cost this stage; + one document
owns the inventory, the failure modes, and the measurable trigger; + criteria
are fixed *before* the tool decision, so adoption can't be bikeshedded under
schedule pressure; − until the trigger, "which version is this database" has
no answer outside tests; − Postgres branches of the hand-rolled paths stay
under-tested (accepted, recorded as a known gap in `TESTING_EVALUATION_PLAN.md`).

**Revisit conditions:** any mandatory/scheduled trigger above firing;
a schema incident attributable to a hand-rolled migration (immediate review,
regardless of stage); `MIGRATION_PLAN.md` §3.2 changing to require a
non-additive step.

**Links:** `MIGRATION_PLAN.md` §3 (principles, per-stage table) ·
`DATA_MODEL.md` · `CURRENT_ARCHITECTURE.md` (dashboard storage row) ·
`ARCHITECTURE_EVOLUTION.md` (storage migration framework entry) ·
`TESTING_EVALUATION_PLAN.md` §5.4 · ADR-011 (storage evolution behind
`ReviewStorage`).

---

## Planned ADRs (not yet written)

The following decisions have been identified as requiring ADRs but have not yet been written. They are marked **planned ADR** per the remediation instruction "do not create full ADR documents unless the existing planning structure explicitly requires them."

### ADR-017 (planned) — Context retrieval & ranking strategy

- **Status:** Planned ADR — not yet written
- **Decision needed:** How the context engine v2 (V4-E02) retrieves, ranks, and budgets repository content. Hybrid deterministic index lookup + ranked retrieval. No vector database at this stage.
- **Depends on:** V4-E01 (index), V4-E03 (impact analysis for ranking)
- **Consumed by:** V5-E01 (planner context), V6-E01 (security context)
- **Related:** ADR-002 (repository graph), ADR-011 (storage evolution)

### ADR-018 (planned) — Adaptive review depth

- **Status:** Planned ADR — not yet written
- **Decision needed:** Depth levels (lightweight/normal/context-aware/multi-specialist/deep) and the quality/latency/cost trade-offs. How depth is selected (risk features from V5-E04) and how it interacts with cost arbitration (V5-E07).
- **Depends on:** V5-E04 (risk engine), V5-E07 (cost arbitration)
- **Consumed by:** V5-E01 (planner), V9-E04 (workers)
- **Related:** ADR-006 (agent architecture), ADR-014 (cost accounting)

### ADR-019 (planned) — Finding relations model

- **Status:** Planned ADR — not yet written
- **Decision needed:** How relations (duplicate/caused_by/fixed_by/regression_of) attach to identity. Relations attach to (fingerprint, provenance) pairs per ADR-005. Whether relations are stored as edges or derived.
- **Depends on:** V4-E05 (identity v2), V7-E01 (history for regression detection)
- **Consumed by:** V7-E03 (relations), V7-E06 (historical evidence)
- **Related:** ADR-005 (finding identity), ADR-004 (evidence model)

### ADR-020 (planned) — CI correlation methodology

- **Status:** Planned ADR — not yet written
- **Decision needed:** What constitutes correlation vs causation between CI failures and PR changes. How test-failure correlation is computed and presented (evidence, not assertion).
- **Depends on:** V8-E01 (CI ingestion), V6-E03 (test intelligence)
- **Consumed by:** V8-E02 (test-failure correlation), V8-E06 (incident intelligence)
- **Related:** ADR-012 (verification trust), ADR-013 (webhook security)

### ADR-021 (planned) — API versioning strategy

- **Status:** Planned ADR — not yet written
- **Decision needed:** How API versions are introduced, deprecated, and retired. `/api/v1/` is the first versioned API (V9-E03). Deprecation policy (headers, sunset dates, major version triggers).
- **Depends on:** V9-E03 (versioned API), V9-E01 (org model for authz)
- **Consumed by:** V10-E04 (IDE/CLI), V10-E06 (command center)
- **Related:** ADR-009 (plugin contract), ADR-010 (multi-tenant boundary)

---

### Cross-references
Ground truth: `CURRENT_ARCHITECTURE.md` · Vision/boundaries:
`MASTER_VISION.md` · Order: `MASTER_ROADMAP.md`, `V4_V10_ROADMAP.md` ·
Epics: `EPIC_BACKLOG.md` · Refusals: `DO_NOT_BUILD_YET.md` ·
Threat model: `SECURITY_ROADMAP.md` · Data: `DATA_MODEL.md`.
