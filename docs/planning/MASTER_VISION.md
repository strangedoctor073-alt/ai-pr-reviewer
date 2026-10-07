# MASTER VISION — AI Software Engineering Intelligence Platform

> Status: planning document (v1). Repository state it describes:
> `CURRENT_ARCHITECTURE.md` (commit `2841b23`).
> Scope of this file: *what* and *why*. How/when: `V4_V10_ROADMAP.md`,
> `EPIC_BACKLOG.md`, `MASTER_ROADMAP.md`.

## 1. Where we are

An open-source AI GitHub PR Reviewer (V3): repository-aware, verified,
resilient. It parses diffs, assembles bounded trusted/untrusted context, routes
to Claude/OpenAI/Gemini with deterministic static fallback, tracks finding
lifecycle with stable fingerprints, verifies suggested fixes deterministically,
synchronizes GitHub comments, keeps human-authored project memory, and exposes a
dashboard. 464 hermetic tests, green CI, honest-engine labelling.

The PR reviewer is the **entry point**, not the product ceiling.

## 2. Where we are going

**An AI Software Engineering Intelligence Platform** that progressively
understands repositories, code, architecture, dependencies, tests, APIs,
security, infrastructure, CI/CD, issues, requirements, documentation, Git
history, releases, incidents, project rules, team knowledge, organization
policies — and turns that understanding into *evidence* that makes every future
review, decision, and audit better informed.

Conceptual flow:

```
Developer → GitHub / CLI / IDE / Dashboard / API
  → Platform Gateway
  → Repository Intelligence
  → Policy Engine · Security Engine
  → Review Orchestrator → Specialized Reviewers
  → Finding Intelligence → Verification
  → Developer Feedback
  → Project / Team / Organization Memory
  → Analytics / Evidence
  → (loop) future reviews become better informed
```

## 3. Non-negotiable principles

1. **Evidence-driven, never assertion-driven.** Every important claim carries
   evidence (code, rule, test output, history, tool result) with provenance.
   No unsupported certainty; confidence is explicit; "we don't know" is valid.
2. **Deterministic first.** Identity, lifecycle, verification arithmetic,
   redaction, policy evaluation, parsing → deterministic code. AI for judgment,
   summarization, synthesis — never for identity, state, or truth-by-authority.
   "Just use AI" is not an architectural solution.
3. **The model is untrusted.** Output is validated, lifecycle fields are
   pipeline-owned, memory is never written by the engine automatically.
4. **Honest fallback.** Static output must always read as static; degraded runs
   are attributed truthfully; a review is never silently lost to I/O failure.
5. **No rewrite.** V3 is the foundation: grow outward, migrate only when
   necessary, keep the Action contract backward-compatible. (§`MIGRATION_PLAN.md`.)
6. **Bounded everything.** No assumption of infinite tokens, GitHub calls,
   compute, small repos, correct models, or trustworthy memory.
7. **Free/open-source first, BYO keys.** Cost-aware by design; the zero-API-key
   path stays fully functional; provider-neutral core.
8. **No autonomous write actions.** The platform reviews, evidences, and
   suggests — it does not modify code, merge, commit, or deploy by default.

## 4. The 12 system planes — mapped to today

The initial decomposition, validated against the actual repository. **Maturity**
: 🟢 exists & stable · 🟡 exists, needs evolution · 🔴 missing.

| # | Plane | What it will own | Today | Maturity |
|---|---|---|---|---|
| 1 | Developer Experience | PR, issues, CLI, dashboard, API, IDE, CI | PR comments + summary, CLI, SPA dashboard, badge, sandbox | 🟡 |
| 2 | GitHub Intelligence | PR intent, events, review sync, issues/Actions | `github_client`, `github_sync`, incremental diff | 🟡 |
| 3 | Repository Intelligence | repo graph, symbols, impact, digital twin | `repo_context` (8-file bounded fetch) | 🔴/🟡 |
| 4 | Review Intelligence | multi-dim review, council, depth, risk | single-pass provider + static rules | 🟡 |
| 5 | Verification | evidence levels, test evidence | deterministic coverage check (3 states) | 🟡 |
| 6 | Policy & Governance | org/team/repo/component policy | repo YAML policy + baseline excludes | 🔴 |
| 7 | Security Intelligence | dedicated security + AI security | `security.py` (fence/screen/redact) + SEC001-008 static rules | 🟡 |
| 8 | AI Orchestration | providers, routing, cost, agents | `model_router` + 3 providers + breaker/retry | 🟡 |
| 9 | Engineering Memory | org→team→repo→component→PR→finding memory | repo memory + mutes (human-authored only) | 🟡 |
| 10 | Observability & Analytics | metrics, provenance, cost, health | report JSON, `/api/metrics`, audit log | 🔴/🟡 |
| 11 | Extensibility / Plugins | analyzers, providers, reporting plugins | rule-pack tuple + provider protocol (internal only) | 🔴 |
| 12 | Platform Infrastructure | queues, workers, multi-tenant, hosting | single process, SQLite/Postgres dashboard | 🔴 |

Maturity judgment: planes 6, 11, 12 are greenfield; plane 3 has a seed
(`repo_context` + `diff_parser`); everything else has a working core that must be
deepened, not replaced. Sequencing: `DEPENDENCY_GRAPH.md`.

## 5. Capability areas — position statements

Full treatment per generation in `V4_V10_ROADMAP.md`. Summary stance:

- **A Developer Experience** — deepen PR + dashboard first; IDE/plugins only after
  contracts stabilize (see `DO_NOT_BUILD_YET.md`).
- **B PR Intelligence** — V4 (intent, scope, risk, affected surfaces).
- **C Repository Intelligence** — V4: deterministic index + impact analysis;
  no graph DB (ADR-002).
- **D Digital Twin** — V4 creates the *seed projection* (layered index); the twin
  is the accumulating projection, never a separate CQRS/GRAPH system early.
- **E Multi-dimensional Review / F Review Council** — V5, gated on provenance
  (V4-E04/E05) and bounded fan-out; deterministic tooling preferred where it
  wins (regex/AST/API-shape checks stay static).
- **G Risk Engine / H Adaptive Depth** — V5 (v1 risk features → depth routing),
  must stay explainable and cheap; informational until proven.
- **I Context Intelligence / J Evidence Engine / K Finding Intelligence /
  L Fix Intelligence** — V4 core (retrieval+provenance, evidence records,
  identity v2), V5-V6 (fix plans, relations), never auto-apply patches.
- **M Advanced Verification** — V6 (evidence tiers incl. test evidence); the
  current deterministic coverage model remains the floor.
- **N Test Intelligence / O CI Intelligence / P Git History** — N: V6, O: V8,
  P: V7.
- **Q Engineering Memory hierarchy** — V7 (authority model ADR-003; AI-derived
  observations never become permanent truth automatically).
- **R Policy Engine** — V6 repo/team scopes; V9 org scopes (ADR-003/inheritance).
- **S Security Intelligence / T AI Security** — S: V6; T: continuous, upgraded
  at every stage that adds a new untrusted input surface (V4 index, V5 agents,
  V7 memory, V8 CI content, V9 webhooks, V10 plugins).
- **U AI Provider Platform** — V5 (capability registry, task routing), V6-V8
  (context-window/cost awareness), V10 (local providers).
- **V Cost Intelligence** — V3-E02 telemetry first (nothing can be managed that
  isn't measured), then V5 arbitration, V6+ dashboards.
- **W Dependency / X Infrastructure / Y Documentation intelligence** — W: V6,
  X: V8, Y: V8.
- **Z Issue/Requirement Intelligence** — V7 (linkage), long-term gap detection
  only as evidence-backed signals, never asserted compliance.
- **AA Architecture Intelligence** — V6.
- **AB Release / AC Incident intelligence** — V8 (incident = retrospective,
  read-only; no autonomous production integration).
- **AD Developer/Team/Org Intelligence** — V7/V10 — **trends and hotspots only;
  explicitly no individual performance rankings or quality scores.**
- **AE Dashboard command center / AF API platform / AG-AH Events** — AF: V9,
  AG: V8 (internal events) → V9 (webhooks), AH: V9 (queue only where justified).
- **AI Plugin architecture** — V9 defines the contract, V10 ships it.
- **AJ Multi-repo / AK Hosted multi-tenant** — V9 / V10 (optional; labelled
  future option, not a commitment).

## 6. Product boundaries (normative — see also `MASTER_ROADMAP.md` §Out of scope)

**The platform WILL:**
- analyze code changes and repository state and report findings with evidence;
- verify suggestions deterministically against diffs/context/tests where possible;
- enforce human-authored policy and privacy baselines;
- keep human-authored memory, and clearly label observed/inferred material;
- expose explainable provenance for every AI review (what was read, which model,
  which evidence, which policy, what verification).

**The platform MAY (later, explicitly approved stages):**
- propose candidate patches (never apply them), open draft suggestions, ingest
  CI/incident data, offer hosted components, support plugins.

**The platform WILL NOT do automatically (any stage):**
- modify code, merge PRs, push commits, deploy to production, or take any
  write action beyond posting/updating its own review comments (and, later,
  explicitly configured integrations);
- convert AI observations into permanent organizational truth without human
  approval;
- claim compliance, certification, or security guarantees it cannot evidence;
- rank individuals or produce employee performance scores;
- silently drop security/correctness context to save tokens;
- trust model output, repository content, comments, memory, or plugin output.

## 7. Open-source strategy (summary)

Provider-neutral core; BYO keys with graceful static mode; Action-first UX
(one workflow block, sane defaults, small `requirements-action.txt`); dashboard
optional (heavy deps stay out of the Action image — keep it that way);
documentation as a first-class deliverable (README remains the primary doc);
contribution boundaries: rule packs, provider adapters, and later plugins are
the community surface — core lifecycle/security code stays reviewed-in-house.
Hosted/enterprise options are labeled future options, never assumed
(`COST_TOKEN_ARCHITECTURE.md`, `TARGET_ARCHITECTURE.md` §D).

## 8. How to read this plan set

| Question | Document |
|---|---|
| What exactly is true today? | `CURRENT_ARCHITECTURE.md` |
| What are we building toward, and what will we never do? | this file |
| How does the target system look? | `TARGET_ARCHITECTURE.md`, `ARCHITECTURE_EVOLUTION.md` |
| What order, and what do we build **next**? | `MASTER_ROADMAP.md`, `V4_V10_ROADMAP.md` |
| Which epics/tickets? | `EPIC_BACKLOG.md` |
| What depends on what? | `DEPENDENCY_GRAPH.md` |
| How is data modeled? | `DATA_MODEL.md` |
| How do we use AI responsibly? | `AI_AGENT_ARCHITECTURE.md` |
| How do we stay secure? | `SECURITY_ROADMAP.md` |
| How do we test and evaluate? | `TESTING_EVALUATION_PLAN.md` |
| How do we control cost? | `COST_TOKEN_ARCHITECTURE.md` |
| How do we not break V3 users? | `MIGRATION_PLAN.md` |
| What did we decide and why? | `ADR_INDEX.md` |
| What do we refuse to build yet? | `DO_NOT_BUILD_YET.md` |
