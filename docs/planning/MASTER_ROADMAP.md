# MASTER ROADMAP — What exactly do we build next?

> Status: planning document (v1) — grounded in `CURRENT_ARCHITECTURE.md`
> (verified at commit `2841b23`) and `MASTER_VISION.md`. Answers "what next,
> in what order, and when do we know a stage is done". Stage detail:
> `V4_V10_ROADMAP.md`. Epic/ticket detail: `EPIC_BACKLOG.md`.

---

## 1. The chain — Current V3 → Foundation → V4 … → V10

Reading key: **hard** = cannot start without it; *soft* = degrades gracefully
without it. Ticket counts are authoritative in `EPIC_BACKLOG.md` (8 epics per
stage listed here; the backlog owns the ticket breakdown).

| Stage | Capabilities | Key dependencies | Epic IDs (tickets → `EPIC_BACKLOG.md`) | Architecture changes | Security work | Testing work | Migration | Exit criteria (summary) |
|---|---|---|---|---|---|---|---|---|
| **Current V3** | Single-pass review: diff parse, bounded context, Claude/OpenAI/Gemini + static fallback, fingerprints/lifecycle/verification, comment sync, memory, dashboard | — (verified baseline: 464 tests green) | — | `orchestrator.py` composition root; `ReviewStorage`/`AIProvider` seams | fencing/redaction/injection screening; base-revision checkout; non-removable exclusion baseline | hermetic suite, release-hardening scans | — | verified: `CURRENT_ARCHITECTURE.md` |
| **Foundation (Phase 0)** | Fix defects D1–D7, telemetry (tokens/cost/latency), evaluation harness, storage/dashboard debt, config & contract hardening, docs/release hygiene (**no features**) | hard: nothing (it gates everything); soft: none | V3-E01…V3-E06 (6 epics; tickets → `EPIC_BACKLOG.md`) | `github_client.py` populates `base_sha`; `orchestrator.py` decouples report from comment caps; `config.py` exit-1 parsing; `dashboard/storage.py` idempotent mute; new telemetry + `evals/` modules | restores base-revision invariant (D1); telemetry through `redact_secrets()`; no new inputs | 1 regression test per defect; telemetry schema tests; harness CI job | additive report fields only; no input changes; behavior-change notes for D3/D4 counts | D1–D7 regression-tested; harness scores in CI; `INPUT_*` garbage → exit 1; suite + docker green |
| **V4 — Core intelligence** | deterministic repo index, context engine v2 (retrieval/ranking/token budgets/provenance), change impact, evidence engine, finding identity/provenance v2, digital-twin seed, intelligence read APIs, intelligence security/budgets | **hard:** Phase 0 (D1, telemetry, harness, storage seams); internal order E01→(E02,E03)→E04→E05→E06→E07, E08 continuous | V4-E01…V4-E08 (8 epics; tickets → `EPIC_BACKLOG.md`) | new `index/` + `evidence.py` subsystems; `context.py` → token-aware retrieval w/ provenance; `Finding` gains pipeline-owned provenance + fingerprint v2 (layered); additive storage tables | full-repo @ base_sha is a new untrusted surface: retrieval fencing + injection exclusion, path allowlist, budget caps as DoS control, provenance unforgeable via `LIFECYCLE_FIELDS` | index determinism/hash-seal; retrieval relevance@k; fingerprint migration continuity; poisoning/budget-exhaustion corpus | fp v1↔v2 mapping keeps comments/mutes/lives continuous; report additive; zero-key path works | base_sha-only index; chunk provenance everywhere; 100% state continuity on fixture PR series; corpus green; harness ≥ Phase 0 |
| **V5 — Specialist review** | bounded fan-out, specialist reviewer contracts, provenance-aware merger, risk engine v1 + adaptive depth, provider capability registry + task routing, council synthesis, cost/token arbitration, multi-agent evaluation | **hard:** V4-E04+V4-E05 (provenance/identity), Phase 0 telemetry+harness, V4-E02 budgets; *soft:* V4-E03 risk features, V4-E01 planner context | V5-E01…V5-E08 (8 epics; tickets → `EPIC_BACKLOG.md`) | `orchestrator.py` → `orchestration/` (planner/executor/merger/synthesizer); prompt-builder extracted from 3 providers (C2); `model_router.py` → capability registry; per-task breakers (in-process C5 slice) | cross-agent output re-validated as untrusted; per-prompt fencing; budgets as DoS control; agents never post directly (merged+validated only) | concurrency stress; merger goldens; routing fail-closed; harness delta report (quality ≥, cost ≤ cap); degradation drills | default behavior equivalent-or-better; council opt-in; report additive (`council`, `per_task_usage`); ≤ 1.2× median cost (proposed baseline) | stress green; registry wires fake provider w/ zero prod edits; V5-E08 report in CI; honest degradation labels |
| **V6 — Verification intelligence** | security engine, AI security v2, test intelligence, architecture intelligence, advanced verification tiers, dependency intelligence, policy engine v1, security eval corpus | **hard:** V4-E01/E03/E04, V5-E02, harness; *soft:* V5-E04 risk, V4-E02 budgets | V6-E01…V6-E08 (8 epics; tickets → `EPIC_BACKLOG.md`) | new `security_eng/`, `test_intel`, `arch_rules`, `deps`, `policy/`; `verification.py` → tiered (T1 coverage floor; T3 observed-test-evidence only); `rules.py` baseline untouched | strict manifest/lockfile parsing (no exec); pinned-host advisory fetch; deterministic verdicts over AI claims; policy evaluator re-enforces non-overridable baseline | precision/recall corpus gates (≥0.7/≥0.6 proposed baseline); tier honesty tests; offline advisory tests; policy truth table | new optional YAML keys default to current behavior; new categories still honor severity threshold; `verification_tier` field additive | corpus floors met w/ evidence on every finding; tier + policy + fuzz suites green; harness no regression |
| **V7 — Historical intelligence** | git history (churn/hotspots), memory hierarchy + authority model, finding relations, issue/requirement linkage, team/repo analytics (**no individual rankings**), historical evidence in review, memory security | **hard:** V4-E05/E04, storage-consolidation ADR (gated on V4, executed here), V3-E04 retention; *soft:* V5-E03, V6-E03/E07 | V7-E01…V7-E07 (7 epics; tickets → `EPIC_BACKLOG.md`) | new `history/` + `linkage.py`; `memory.py` → hierarchy w/ `authority`/provenance; relations table on fp v2; aggregate analytics queries (kills C9 O(all) scans) | commit msgs/issue bodies fenced; secrets redacted from digests; authority model blocks memory poisoning; git read-only arg-array execution; **no author-dimension queries** (invariant test) | fixture git repos; authority matrix; poisoning corpus; no-individual-metrics invariant; harness with history context | `repo_memory` backfill → `level=repo, authority=human` (idempotent); checkout depth documented not enforced; report additive | history deterministic + shallow-degrade labelled; poisoning can't reach approved; invariant test green; ADR increment #1 landed |
| **V8 — Pipeline intelligence** | CI ingestion, test-failure correlation, release/docs/infrastructure intelligence, read-only incident intelligence, internal event platform v1 (append-only log — **no queues**) | **hard:** V4 index/evidence/reads, V6-E03, V7-E01; **hard:** V8-E01→E02 order, E07 schema early as seam; *soft:* V7-E04, V5-E04 | V8-E01…V8-E07 (7 epics; tickets → `EPIC_BACKLOG.md`) | new `github_client` CI/release reads, `events/` (schema v1 + append-only log + replay), `ci_correlation`/`release_intel`/`docs_intel`/`infra_intel`/`incident_intel`; storage increment #2 | CI logs/workflow YAML/incident text are untrusted: redact-at-ingest, parse-never-execute, no CI control, token perms unchanged | mocked-API ingestion; correlation negatives (no false causation); secret-leak corpus; event replay-equality + **negative architecture test: no queue/worker symbols** | opt-in/graceful-absence defaults; report additive; event log internal, not public contract | ingestion + correlation fixtures green; corpus redacted; replay test green; zero queue symbols; harness ≥ baseline |
| **V9 — Organization platform** | multi-repo/org model, org policy w/ inheritance, versioned public API (`/api/v1`), event-driven workers **only where measured**, org memory, extensibility contract v1, observability platform | **hard:** V8-E07 (events), V6-E07 (policy), V7-E02/E07 (memory), storage ADR increment #3; workers hard-gated on V9-E07 evidence; *soft:* V5-E05, V8 schema | V9-E01…V9-E07 (7 epics; tickets → `EPIC_BACKLOG.md`) | `dashboard/app.py` → versioned `api/v1/` w/ scope authz; row-level scope in data layer; policy inheritance; `queue/` workers (optional deployment); metrics/audit platform | scope matrix as CI invariant (cross-org deny); human approval for org memory; scoped tokens (legacy token compat); queue payloads = refs, re-sanitized at consume | route×role matrix; policy precedence/audit; API contract snapshots + breaking-change detector; worker parity + kill-drill | Action contract byte-unchanged; legacy routes deprecated w/ headers; org backfill idempotent; JSON storage fate documented | scope matrix green; `/api/v1` snapshot enforced; workers only with measured bottleneck; no-individual-dims invariant |
| **V10 — Ecosystem** | sandboxed plugin system, provider ecosystem (incl. optional local providers), **optional** hosted multi-tenant foundation, IDE/CLI ecosystem, org analytics, command center | **hard:** V9-E06 (contract), V9-E03 (API), V9-E01/E02 (org), V9-E07 (observability); V10-E03 strictly optional, ADR-gated; *soft:* V8 events for refresh | V10-E01…V10-E06 (6 epics; tickets → `EPIC_BACKLOG.md`) | `plugins/` out-of-process sandbox (capability IPC); registry = provider seam for local adapters; shared local-review core (CLI=Action parity); SPA → command center | **plugin code is hostile**: sandbox escape suite, output treated as model-untrusted, no tokens by default, manifest signing + API-range; local-provider egress honesty; tenant isolation only if E03 ADR approved | escape/resource/crash suite; malicious-plugin corpus; capability-manifest validation; CLI/Action/sandbox parity; carried-forward no-individual invariant | plugins opt-in default off; registry keys unchanged; plugin id+version in provenance; hosted ships zero impact on self-hosted | escape suite 100% denied; parity test green; command center on v1 only; E03 ADR-gated or re-affirmed as not-built; contract byte-compatible |

---

## 2. Build next — start here

**Start now: Phase 0, in this order.**

| # | Epic | Why this position |
|---|---|---|
| 1 | **V3-E01 correctness defect triage** (D1–D5) | You cannot measure a broken system. D1 (`base_sha` never populated — `github_client.py:80-89,111-120`, fallback at `repo_context.py:238`) is a trust-boundary violation that must die before any index/retrieval work builds on head-revision data. D2–D5 corrupt the *report itself* (false `resolved` from the 20-cap, invisible below-threshold findings, cap shrinking health score vs `action.yml:44`, unsorted AI severity): any harness baseline taken on top of these defects enshrines wrong behavior, and V5's N-way fan-out would multiply all four defects across specialists. |
| 2 | **V3-E05 config & contract hardening** (D6) | Small, parallelizable, high signal: raw `ValueError` tracebacks from `config.py:113,119,129` pollute CI logs and confound harness runs; contract tests over `action.yml` inputs/outputs freeze the public surface before V4/V5 migration work touches it. |
| 3 | **V3-E02 telemetry foundation** (C6) | Nothing can be managed that isn't measured. Token/cost/latency are *never surfaced today* (counted on Claude/OpenAI, absent from `AnalysisOutcome`, Gemini unparsed). V4 budgets (C7 fix), V5 arbitration (V5-E07), V5 risk (V5-E04), and every "proposed baseline" in `V4_V10_ROADMAP.md` consume this data. Building multi-agent spend control on top of C6 = inventing numbers. |
| 4 | **V3-E03 evaluation harness foundation** | Multi-agent changes the output distribution; without a golden corpus scored in CI you cannot distinguish "council improved review quality" from "council produced more confident noise at 4× cost". Harness must exist *before* V4 context changes (retrieval quality is invisible in unit tests) and well before V5. Depends on E01 (correct baseline) and benefits from E02 (cost/latency scoring) — hence position 4. |
| 5 | **V3-E04 storage & dashboard debt** (D7, D10, C9 partial) | V4 adds index/evidence/provenance tables and V7 adds relations/memory/history — all on the `ReviewStorage`/`DbStorage`/`JsonStorage` triplication (C9) with connections never closed and zero retention. Fix mute idempotency (`dashboard/storage.py:337`), connection lifecycle, declared optional capabilities, retention hooks *before* three new stages of schema lands. Also the last cheap moment to draft the storage-consolidation ADR that hard-gates V7. |
| 6 | **V3-E06 documentation & release hygiene** (D11–D14) | Trails the code: deprecation notice for `analyzer.py`/`heuristics.py` facades, dedup the `rules.py` vs `dashboard/app.py` security baselines (D12), lint/type gate in CI (D14) — the gate must exist before codebase growth accelerates in V4, so in practice D14 lands early inside E06 and the doc sweep finishes last. |

**Why telemetry + evaluation harness + identity/provenance must precede multi-agent
work (the three non-negotiable gates):**

1. **Telemetry (V3-E02) → cost control.** C6: usage is counted in two providers,
   surfaced nowhere; Gemini unparsed. V5 multiplies calls per run by the
   specialist count. Arbitration (V5-E07), depth control (V5-E04), and honest
   budget-exhaustion labels are *impossible* without measured baselines — you
   would be capping spend against a guess, and the roadmap's cost gates
   (≤ 1.2× median — proposed baseline) would be unfalsifiable.
2. **Evaluation harness (V3-E03) → quality control.** The only instrument that
   can say whether fan-out helped. Unit tests prove the pipeline runs; only a
   scored golden corpus proves reviews got better. It must exist while the
   system is still single-pass (baseline capture) — after V5 it can only
   measure deltas, never the pre/post comparison that justifies V5's cost.
3. **Identity & provenance (V4-E04/V4-E05) → merge correctness.** C3: `Finding`
   has no engine/model/agent origin fields; C4: title-based 16-hex fingerprints
   with a documented cross-engine dedup gap. A merger (V5-E03) over unattributed,
   ambiguously-identified findings cannot tell "two agents found the same bug"
   from "two similar bugs" — and post-dedup attribution is *lost data*, not
   backfillable (GitHub comment state markers key off fingerprints). This is why
   evidence/provenance lands in V4, before any agent exists — confirmed against
   the naive hypothesis (see `V4_V10_ROADMAP.md` §0 #1).

Everything else in Phase 0 supports these three: D1–D5 give them a correct
baseline, E05 freezes the contract they publish through, E04 gives them storage,
E06 gives CI the quality gate (D14) to run them on.

---

## 3. Critical path

```
                 V3-E01..E06            V4-E01,E04,E05,E02      V5-E01..E08
 FOUNDATION ─────────────────► CORE INTELLIGENCE ──────────► SPECIALIST REVIEW
 (Phase 0)                      (V4: index, evidence,         (V5: fan-out, merger,
                                  identity, budgets)           risk, council, arbitration)
                                                                   │
                          V6-E01..E08                              ▼
      SPECIALIST REVIEW ─────────────────► VERIFICATION ◄── evidence-backed claims
                          (V6: security, test, arch,         from index + impact
                           verification tiers, policy)              │
                                                                   │
        V6-E07 (policy v1) · V7-E01..E07 (history/memory/relations) · V8-E01..E07
        ──────── (hard: V8-E07 event platform v1 precedes V9-E04 workers) ────────
                                                                   │
                                                                   ▼
      VERIFICATION+HISTORY ──────────────────────────────► PLATFORM ──────► ORGANIZATION
                          (V9: org model, org policy,              (V10: plugins, providers,
                           /api/v1, workers-if-justified,           IDE/CLI, org analytics,
                           org memory, extensibility v1,            command center)
                           observability)
                                    ▲                                    ▲
                                    └── V9-E06 contract ─────────────────┘
                                        (hard gate: contract frozen before V10 ships surfaces)
```

Edge semantics — the epic IDs listed on an edge are the **gating epics** that
must exit before crossing:

| Edge | Gating epics (hard) | Soft predecessors |
|---|---|---|
| FOUNDATION → CORE INTELLIGENCE | V3-E01, V3-E02, V3-E03, V3-E04 | V3-E05, V3-E06 |
| CORE INTELLIGENCE → SPECIALIST REVIEW | V4-E04, V4-E05, V4-E02, V4-E01 | V4-E03, V4-E06, V4-E07 (V4-E08 continuous) |
| SPECIALIST REVIEW → VERIFICATION | V5-E02, V5-E03, V5-E08, V5-E07 | V5-E04, V5-E05, V5-E06 |
| VERIFICATION → PLATFORM | V6-E07; then V7-E02/E07 (memory+authority), V7-E01/E03 (identity consumers), **V8-E07 (events precede workers)**; storage ADR increments | V6-E01..E06, V7-E04/E05, V8-E01..E06 |
| PLATFORM → ORGANIZATION | V9-E06, V9-E03, V9-E01, V9-E07 | V9-E02, V9-E04, V9-E05, V10-E03 (optional) |

Notes on the two debatable stretches:
- **V7/V8 sit on the VERIFICATION → PLATFORM edge** as accumulated project/pipeline
  intelligence: they are prerequisites of the platform (events, memory, policy
  consumers) but do not block V6 work in parallel. V8-E07 → V9-E04 ordering is
  the "event platform before queue separation" rule (`V4_V10_ROADMAP.md` §0 #4);
  queues are never built ahead of a measured bottleneck.
- **Parallelism available:** after V4 exits, V6-E01/E06 (index consumers) can
  proceed alongside V5 on a second track; V7-E01 (pure local git) is the safest
  early parallel track. Merging tracks requires V5 contracts (V6 AI scopes) and
  storage ADR (V7 tables).

---

## 4. Do not build yet (roadmap out-of-scope pointer)

Normative refusal list: **`DO_NOT_BUILD_YET.md`** (companion document in
`docs/planning/`). References to "`MASTER_ROADMAP.md` §Out of scope" in other
planning docs resolve here; the normative *product* boundaries (WILL/WILL NOT)
live in `MASTER_VISION.md` §6. Top items that most often tempt premature work:

| # | Do not build | Why premature | Revisit |
|---|---|---|---|
| 1 | **Microservices / service split** (`DO_NOT_BUILD_YET.md` A1) | single-process + Action model is a stable assumption (`CURRENT_ARCHITECTURE.md` §13.1); split without measured load = reliability tax | V9 only with V9-E07 evidence; default: never |
| 2 | **Graph database** (ADR-002; refusal rationale in `ADR_INDEX.md`) | index is deterministic relational data; ADR-002 forbids early graph infra; impact analysis is bounded BFS over SQLite tables | never by default; ADR + proven V4 query limits |
| 3 | **Autonomous commits / merge / code modification** (B1/B2) | permanent product boundary (`MASTER_VISION.md` §6) — platform reviews, never writes | never |
| 4 | **Full multi-tenancy / hosted SaaS** (C1) | org model (V9) ≠ tenant isolation product; billing/SSO/per-tenant keys are a different system | V10-E03, ADR-gated, optional |
| 5 | **IDE plugins** (D1) | contracts (V9-E06 `/api/v1`) not frozen; three-surface parity drift risk before shared core proven | V10-E04 |
| 6 | **Plugin marketplace** (D2) | sandbox must prove itself first (V10-E01 escape suite); distribution/signing/review is a second system | after V10-E01 exit criteria |
| 7 | **Incident intelligence automation** (B4) | V8-E06 is read-only retrospective by rule; any trigger/remediation path violates "no autonomous actions" | never as automation; ADR if read-scope ever expands |
| 8 | **Org analytics before repository boundaries stable** (C2) | V7 analytics must first prove the no-individual-dimensions invariant at repo scope; org scoping ships in V9-E01 | V10-E05 after V9-E01/E07 exit |

Also deferred per stage: queue infrastructure ahead of measured bottlenecks
(`DO_NOT_BUILD_YET.md` A3; V9-E04 rule), vector/graph stores (V4 must-not),
cross-process coordination for V5 fan-out (in-process only), CI control of any
kind (V8 must-not), webhook endpoints before V9 authz matrix, hosted SaaS
control plane (V10-E03 optional), event-driven everything (A3).

---

## 5. Stage exit-criteria rollup (gates)

Full criteria: `V4_V10_ROADMAP.md` §Exit criteria per stage. Rollup — a stage
exits only when **all** gates are green:

| Stage | Gate 1 (correctness) | Gate 2 (quality/cost) | Gate 3 (security) | Gate 4 (compat/process) |
|---|---|---|---|---|
| **Phase 0** | D1–D7 each have passing regression tests; exit-1 on bad `INPUT_*`; double-mute idempotent | harness runs in CI, reproducible score; telemetry fields populated in report | D1 base-revision invariant restored; redaction on telemetry | suite + docker green; lint gate active; docs match behavior |
| **V4** | index hash-sealed from `base_sha`; fp v2 100% state continuity on fixture PR series | relevance@k ≥ 0.8 (proposed baseline); harness ≥ Phase 0; prompt tokens −15% median (proposed baseline) | poisoning corpus neutralized; budget caps bound API calls; provenance unforgeable | report/storage additive only; zero-key path full-fidelity |
| **V5** | concurrency stress green; registry fake-provider wiring test; merger goldens | V5-E08 delta report in CI: quality ≥ baseline, cost ≤ cap (proposed baseline ≤ 1.2× median) | cross-agent output re-validated; per-prompt fencing; budget pre-flight | default path equivalent-or-better; static fallback still honestly labelled |
| **V6** | corpus floors precision ≥ 0.7 / recall ≥ 0.6 (proposed baseline); policy truth table; tier honesty | every security finding carries ≥ 1 resolvable evidence record; harness no regression | advisory fetch pinned/offline-in-CI; exclusion baseline non-overridable at evaluator; AI-corpus green | new YAML keys optional; severity behavior unchanged by default |
| **V7** | history fixtures deterministic + shallow-degrade; authority matrix; relations fixtures | harness with history ≥ baseline | poisoning corpus cannot reach approved memory; no author-dimension query path exists | `repo_memory` backfill idempotent; history absence labelled not fatal |
| **V8** | ingestion + correlation fixtures green; replay-equality; malformed → labelled | cost within proposed caps (measured via telemetry) | secret-leak corpus zero-persist; workflow YAML parse-never-execute; **no queue/worker symbols** | features graceful-absence; event log internal |
| **V9** | scope matrix CI invariant green; policy precedence deterministic; worker kill-drill | API contract snapshots + breaking-change detector; worker/queue parity tests | cross-org deny; human approval on org memory; audit hash-chain | Action contract byte-unchanged; legacy token/routes compatible |
| **V10** | sandbox escape suite 100% denied; CLI/Action/sandbox parity; capability manifests fail closed | command center from precomputed rollups only | plugin output model-untrusted treatment; no-token-by-default; (E03) tenant matrix if ADR approved | plugins default-off; contract snapshot vs Phase 0 byte-compatible |

Rollup rule: **no stage exits on partial credit** — an unmet security or compat
gate blocks the next stage's hard prerequisites regardless of feature completion.

---

## 6. Cross-references

| Document | Answers |
|---|---|
| `CURRENT_ARCHITECTURE.md` | What is true today (D1–D7, C1–C14, verified at commit `2841b23`) — wins on any disagreement |
| `MASTER_VISION.md` | What/why: 12 planes, capability areas A–AK, product boundaries |
| `V4_V10_ROADMAP.md` | Stage-by-stage plan: 13 subsections per stage incl. full exit criteria + generation-boundary rationale (§0) |
| `EPIC_BACKLOG.md` | Epic → ticket breakdown and counts (authoritative for ticket counts cited here) |
| `DEPENDENCY_GRAPH.md` | Detailed epic-level dependency edges beyond §3 critical path |
| `MIGRATION_PLAN.md` | V3 compatibility: Action inputs, config, storage, findings, comments per stage |
| `SECURITY_ROADMAP.md` | Threat model and per-stage security work behind §1 "Security work" |
| `TESTING_EVALUATION_PLAN.md` | Test pyramid + eval harness design behind §1 "Testing work" |
| `COST_TOKEN_ARCHITECTURE.md` | Telemetry schema, budget/arbitration design behind §1 token/cost gates |
| `ADR_INDEX.md` | Decisions referenced here: ADR-002 (no graph DB), ADR-003 (memory authority/inheritance), storage-consolidation ADR (V7 hard gate) |
| `DO_NOT_BUILD_YET.md` | Normative refusal list — §4 above is the summary, that file is the authority |
