# Final Planning Consistency Audit

> **Audit date:** 2026-10-03
> **Repository state:** commit `2841b23` (working tree)
> **Scope:** All documents under `docs/planning/` cross-checked against each other and against the actual V3 source code.
> **Method:** Read-only. No planning document was modified. No source code was modified. This file is the only artifact created by the audit.

---

## 1. Planning Inventory

### 1.1 Documents present (12 of 16 expected)

| # | Document | Status | Lines |
|---|---|---|---|
| 1 | `MASTER_VISION.md` | ✅ present | 165 |
| 2 | `CURRENT_ARCHITECTURE.md` | ✅ present | 311 |
| 3 | `TARGET_ARCHITECTURE.md` | ✅ present | 393 |
| 4 | `ARCHITECTURE_EVOLUTION.md` | ✅ present | 175 |
| 5 | `V4_V10_ROADMAP.md` | ✅ present | 1,364 |
| 6 | `MASTER_ROADMAP.md` | ✅ present | 153 |
| 7 | `EPIC_BACKLOG.md` | ✅ present | 1,554 |
| 8 | `DEPENDENCY_GRAPH.md` | ❌ **MISSING** | — |
| 9 | `DATA_MODEL.md` | ✅ present | 235 |
| 10 | `AI_AGENT_ARCHITECTURE.md` | ❌ **MISSING** | — |
| 11 | `SECURITY_ROADMAP.md` | ❌ **MISSING** | — |
| 12 | `TESTING_EVALUATION_PLAN.md` | ✅ present | 444 |
| 13 | `COST_TOKEN_ARCHITECTURE.md` | ✅ present | 269 |
| 14 | `MIGRATION_PLAN.md` | ❌ **MISSING** | — |
| 15 | `ADR_INDEX.md` | ✅ present | 729 |
| 16 | `DO_NOT_BUILD_YET.md` | ✅ present | 361 |

### 1.2 Documents missing (4)

- `DEPENDENCY_GRAPH.md`
- `AI_AGENT_ARCHITECTURE.md`
- `SECURITY_ROADMAP.md`
- `MIGRATION_PLAN.md`

All four were assigned to background drafting agents that failed with provider rate-limit errors. The 12 existing documents contain **41 dangling cross-references** to these four missing files.

---

## 2. Overall Consistency Result

| Dimension | Result |
|---|---|
| V4–V10 stage structure | ✅ Consistent (minor naming drift on V8) |
| Epic ID integrity (57-epic scheme) | ✅ Clean — no non-canonical IDs, no duplicates, all 57 referenced |
| Dependency integrity (hard/soft graph) | ✅ No cycles, no impossible orderings; ⚠ systematic soft→hard elevation tension |
| Current architecture accuracy | ⚠ 3 factual errors, 4 imprecisions in `CURRENT_ARCHITECTURE.md` |
| D1–D7 defect consistency | ✅ Consistently represented; no doc claims they are fixed |
| Data model consistency | ⚠ 1 HIGH contradiction (identity v2 mechanism), 3 terminology issues |
| AI architecture consistency | ✅ Coherent across existing docs (AI_AGENT_ARCHITECTURE.md missing) |
| Security consistency | ✅ Coherent across existing docs (SECURITY_ROADMAP.md missing) |
| Testing/evaluation coverage | ⚠ 5 capabilities lack assigned testing strategy |
| Cost/token consistency | ✅ Grounded in current budgets and constraints |
| ADR coverage | ⚠ 3 significant decisions lack ADRs |
| Do-Not-Build boundary | ✅ Respected — no violations |
| Git/repository safety | ✅ Clean — no production/test/CI changes |

**Verdict:** The plan set is **incomplete** (4 of 16 documents missing) and contains **1 HIGH-severity contradiction** (identity v2 mechanism). The architecture is **not ready to freeze** until the missing documents are written and the HIGH contradiction is resolved.

---

## 3. V4–V10 Consistency

### 3.1 Stage naming

| Stage | `EPIC_BACKLOG.md` | `V4_V10_ROADMAP.md` | `MASTER_ROADMAP.md` | Consistent? |
|---|---|---|---|---|
| Phase 0 | "V3.x" | "V3.x" | "Foundation (Phase 0)" | ✅ |
| V4 | Deep repository intelligence | Deep repository intelligence | Core intelligence | ✅ |
| V5 | Multi-agent engineering review | Multi-agent engineering review | Specialist review | ✅ |
| V6 | Security + testing + architecture intelligence | Security + testing + architecture intelligence | Verification intelligence | ✅ |
| V7 | Historical / project / team intelligence | Historical / project / team intelligence | Historical intelligence | ✅ |
| V8 | **CI / release / incident intelligence** | **CI/CD + release / incident intelligence** | Pipeline intelligence | ⚠ naming drift |
| V9 | Organization platform | Organization platform | Organization platform | ✅ |
| V10 | Ecosystem / platform | Ecosystem / platform | Ecosystem | ✅ |

**Finding STAGE-01 (LOW):** V8 stage name differs — "CI / release" vs "CI/CD + release". The canonical structure uses "CI/CD + release + incident intelligence". `EPIC_BACKLOG.md` drops the "CD".

### 3.2 Capability placement

All major capabilities from `MASTER_VISION.md` §5 (A–AK) are assigned to stages consistently across `V4_V10_ROADMAP.md`, `MASTER_ROADMAP.md`, and `EPIC_BACKLOG.md`. No capability appears in conflicting stages. The `V4_V10_ROADMAP.md` §0 "generation boundary rationale" documents 8 deliberate deviations from the naive V4–V10 hypothesis; all 8 are consistently reflected in the other two documents.

---

## 4. Epic ID Integrity

### 4.1 Canonical scheme verification

- **57 epics** in canonical scheme: V3 (6) + V4 (8) + V5 (8) + V6 (8) + V7 (7) + V8 (7) + V9 (7) + V10 (6).
- **Non-canonical IDs found:** 0
- **Canonical IDs never referenced:** 0
- **Duplicate epic headings in `EPIC_BACKLOG.md`:** 0 (71 headings = 57 epic entries in §2 + 14 "— tickets" breakdown headings in §3 — intentional structure, not duplication)
- **Epics with conflicting names:** 0
- **Epics assigned to conflicting stages:** 0

### 4.2 Epic ID references per document

All 12 existing documents reference epic IDs from the canonical set. `EPIC_BACKLOG.md` and `V4_V10_ROADMAP.md` are the most complete (all 57 referenced). `MASTER_VISION.md` references 9. `COST_TOKEN_ARCHITECTURE.md` references 5. No document invents an ID outside the scheme.

**Verdict:** Epic ID integrity is **clean**.

---

## 5. Dependency Integrity

### 5.1 Hard-dependency graph analysis

Extracted all 57 epic dependency declarations from `EPIC_BACKLOG.md` and cross-checked against `V4_V10_ROADMAP.md` "Prerequisites & dependencies" and `MASTER_ROADMAP.md` "Key dependencies" columns.

- **Circular dependencies:** 0
- **Impossible orderings** (earlier-stage epic hard-depends on later-stage epic): 0
- **Missing stage placements:** 0 (all 57 epics have a stage)

### 5.2 Findings

**Finding DEP-01 (MEDIUM):** Systematic soft→hard elevation tension. `V4_V10_ROADMAP.md` and `MASTER_ROADMAP.md` consistently elevate `EPIC_BACKLOG.md` *soft* dependencies to stage-level *hard* dependencies:

| Epic | EPIC_BACKLOG says | Roadmaps say | Tension |
|---|---|---|---|
| V4 stage | V3-E02 soft, V3-E03 soft | V3-E02 hard, V3-E03 hard | Roadmap stricter |
| V5 stage | V3-E03 not listed on V5-E01 | V3-E03 hard | Roadmap stricter |
| V6 stage | V4-E01 soft (V6-E01), V5-E02 soft | V4-E01 hard, V5-E02 hard | Roadmap stricter |
| V8 stage | V6-E03 soft, V6-E07 soft | V6-E03 hard, V6-E07 hard | Roadmap stricter |

This is not a logical contradiction (hard is stronger than soft), but it means `EPIC_BACKLOG.md` understates prerequisites. An implementer working only from the backlog would not know these are gating.

**Finding DEP-02 (MEDIUM):** `V5-E01` (fan-out orchestration) does not list `V3-E03` (evaluation harness) as a dependency — neither hard nor soft. But `V4_V10_ROADMAP.md` V5 prerequisites say "Hard: V3-E02 telemetry + V3-E03 harness" and `V5-E08` hard-depends on `V3-E03`. The harness is a prerequisite for the *stage* but not for the *epic* that creates the multi-agent output the harness must measure.

**Finding DEP-03 (MEDIUM):** `V7-E02` (memory hierarchy) does not list `V4-E05` (finding identity v2) as a dependency. Memory entries reference findings by fingerprint; identity v2 changes the fingerprint model. Soft dependency on `V4-E04` (provenance) is listed but not `V4-E05`.

**Finding DEP-04 (LOW):** `V6-E03` (test intelligence) lists `V8-E02` as a soft dependency, but `V8-E02` is in a later stage. This is acceptable for a soft dependency but should be noted as a forward reference.

### 5.3 Cross-document dependency consistency

`V4_V10_ROADMAP.md` and `MASTER_ROADMAP.md` are fully consistent with each other on dependencies. The only tension is with `EPIC_BACKLOG.md` (see DEP-01). `MIGRATION_PLAN.md` (missing) would normally be the fifth dependency cross-check source.

---

## 6. Current Architecture Accuracy

`CURRENT_ARCHITECTURE.md` was verified against the actual V3 source code. The following claims are **not accurate** or are **imprecise**:

### 6.1 Factual errors

**Finding ARCH-01 (MEDIUM):** Claims "14 redaction patterns" in `redact_secrets()`.
- **Claim:** `CURRENT_ARCHITECTURE.md` §6 and §11: "redact_secrets: 14 patterns"
- **Reality:** `ai_pr_reviewer/security.py:88-107` — `_REDACT_PATTERNS` contains exactly **12** tuples.
- **Recommended correction:** Change "14 patterns" to "12 patterns".

**Finding ARCH-02 (LOW):** Claims "22 test files".
- **Claim:** `CURRENT_ARCHITECTURE.md` header: "464 passed, 1 warning" and "22 test files"
- **Reality:** `tests/` contains **21** `test_*.py` files + 1 `conftest.py` = 22 total `.py` files, but only 21 are test files.
- **Recommended correction:** State "21 test files (+ conftest)".

**Finding ARCH-03 (MEDIUM):** D6 presented as fully unfixed.
- **Claim:** `CURRENT_ARCHITECTURE.md` §11: "D6 | Numeric INPUT_* parsing (pr_number, max_comments, batch_chars) raises raw ValueError"
- **Reality:** `config.py:140-142` — `repo_context_chars` now uses `_int_field()` (safe). Only `pr_number` (line 113), `max_comments` (line 119), and `batch_chars` (line 129) still use raw `int()`. The defect is **partially fixed** — 1 of 4 fields hardened.
- **Recommended correction:** Update D6 to note `repo_context_chars` is now safe; only 3 fields remain raw.

### 6.2 Imprecisions

**Finding ARCH-04 (LOW):** Claims "~24 routes" in dashboard.
- **Reality:** `dashboard/app.py` contains exactly **23** route decorators.

**Finding ARCH-05 (LOW):** Lists "8 markdown findings" as a hard-coded cap.
- **Reality:** `reporter.py:267` — `build_summary_markdown(result, top_n: int = 8)` — the 8 is a function default parameter, not a named constant.

**Finding ARCH-06 (INFO):** "dismissed is declared but never produced by engine code — vestigial" — **verified accurate**. `FindingState.DISMISSED` exists but no engine code sets it; `mark_dismissed()` sets `"muted"`.

**Finding ARCH-07 (INFO):** "body/finding caps (2 MB / 500)" — the 2 MB body check is **writes-only** (`dashboard/app.py:336-339`: `if not is_read`). Reads are not body-capped.

### 6.3 Verified accurate

The following major claims in `CURRENT_ARCHITECTURE.md` were verified as accurate against source: pipeline order (orchestrator.py steps a–i), models.py fields/enums/health-score deductions, findings.py fingerprint/dedup/lifecycle/mutes, verification.py 3-state + `_unverify`, model_router.py routing/breaker/retry/token tiers, config.py layering/defaults, repo_context.py budgets/base_sha fallback, storage.py schema/connection handling, dashboard/app.py auth/rate-limits/caps, dashboard/storage.py mute idempotency bug, github_client.py base_sha gap/file caps, security.py nonce/injection patterns, action.yml inputs/outputs, example-workflow.yml permissions, D1–D7 defects, C1–C14 constraints.

---

## 7. D1–D7 Defect Consistency

### 7.1 Representation across documents

| Defect | Docs mentioning it | Consistent? |
|---|---|---|
| D1 (base_sha) | CURRENT_ARCHITECTURE, EPIC_BACKLOG, MASTER_ROADMAP, V4_V10_ROADMAP, ADR_INDEX, ARCHITECTURE_EVOLUTION, DO_NOT_BUILD_YET, TESTING_EVALUATION_PLAN, TARGET_ARCHITECTURE, DATA_MODEL | ✅ |
| D2 (capped verification) | CURRENT_ARCHITECTURE, EPIC_BACKLOG, MASTER_ROADMAP, V4_V10_ROADMAP, ADR_INDEX, ARCHITECTURE_EVOLUTION, DO_NOT_BUILD_YET, TESTING_EVALUATION_PLAN | ✅ |
| D3 (below-threshold dropped) | CURRENT_ARCHITECTURE, EPIC_BACKLOG, MASTER_ROADMAP, V4_V10_ROADMAP, ADR_INDEX, ARCHITECTURE_EVOLUTION, TESTING_EVALUATION_PLAN | ✅ |
| D4 (max_comments caps report) | CURRENT_ARCHITECTURE, EPIC_BACKLOG, MASTER_ROADMAP, V4_V10_ROADMAP, ADR_INDEX, ARCHITECTURE_EVOLUTION, TESTING_EVALUATION_PLAN | ✅ |
| D5 (no severity sort) | CURRENT_ARCHITECTURE, EPIC_BACKLOG, MASTER_ROADMAP, V4_V10_ROADMAP, ARCHITECTURE_EVOLUTION, TESTING_EVALUATION_PLAN | ✅ |
| D6 (config crash) | CURRENT_ARCHITECTURE, EPIC_BACKLOG, MASTER_ROADMAP, V4_V10_ROADMAP, ADR_INDEX, ARCHITECTURE_EVOLUTION, TESTING_EVALUATION_PLAN | ⚠ see ARCH-03 |
| D7 (mute not idempotent) | CURRENT_ARCHITECTURE, EPIC_BACKLOG, MASTER_ROADMAP, V4_V10_ROADMAP, ADR_INDEX, ARCHITECTURE_EVOLUTION, TESTING_EVALUATION_PLAN | ✅ |

### 7.2 No false "fixed" claims

No planning document claims any of D1–D7 has been fixed. All documents correctly treat them as **open defects** to be resolved in Phase 0 (V3-E01). ✅

### 7.3 Prerequisite treatment

All seven defects are correctly treated as prerequisites for future work:
- D1 is a hard prerequisite for V4-E01 (index must be built at base revision).
- D2/D3/D4/D5 are hard prerequisites for V3-E03 (evaluation harness must measure trustworthy behavior).
- D6 is a hard prerequisite for V3-E05 (config contract hardening).
- D7 is a soft prerequisite for V3-E04 (storage debt — same code area).

**Verdict:** D1–D7 consistency is **verified** (with the ARCH-03 caveat on D6's partial fix).

---

## 8. Data Model Consistency

### 8.1 HIGH-severity contradiction

**Finding DM-01 (HIGH):** V4-E05 identity v2 mechanism contradicts ADR-005.

| Source | Mechanism |
|---|---|
| `EPIC_BACKLOG.md` V4-E05 | "dual-computation: every run computes v1 and v2, an alias table maps v1↔v2, lookups accept either; cutover only after the alias table covers live history" |
| `MASTER_ROADMAP.md` V4 row | "fingerprint v2 (dual-compute)" |
| `ADR_INDEX.md` ADR-005 | "layer identity instead of widening it: 1. add provenance fields … 2. keep fingerprint as primary key; add an occurrence key for cross-engine matching … 3. relations attach to (fingerprint, provenance) pairs" |
| `DATA_MODEL.md` §5.1 | Follows ADR-005's layered model (occurrence key, no alias table, no cutover) |

This is a **three-way inconsistency**: `EPIC_BACKLOG.md` + `MASTER_ROADMAP.md` describe a dual-computation + alias-table + cutover model; `ADR-005` + `DATA_MODEL.md` describe a layered model with no cutover. An implementer would not know which to build.

**Recommended correction:** Reconcile V4-E05 and MASTER_ROADMAP with ADR-005 (or update ADR-005 to match the dual-computation model). The layered model (ADR-005) is simpler and already has two documents behind it; the dual-computation model adds an alias-table migration burden.

### 8.2 Terminology issues

**Finding DM-02 (MEDIUM):** `DATA_MODEL.md` contains a stale caveat: "EPIC_BACKLOG.md was not yet in the tree when this document was written; verify the IDs against it when it lands." `EPIC_BACKLOG.md` **is** now in the tree. All epic IDs cited in `DATA_MODEL.md` are present in `EPIC_BACKLOG.md`.

**Finding DM-03 (MEDIUM):** "SecurityFinding" and "ArchitectureFinding" are entity names invented in `DATA_MODEL.md`. They appear nowhere else in the plan set or codebase. The codebase uses `Finding` with `category='security'` (`models.py:44-47`, `VALID_CATEGORIES`). While `DATA_MODEL.md` correctly states these live "inside the Finding table", the names don't match current terminology.

**Finding DM-04 (LOW):** "ReviewRun" entity home is listed as "relational (SQLite now)" but no `review_runs` table exists today. The data lives inside `ReportRow.payload` JSON. Should be "payload JSON inside ReportRow (today) → own table at V5".

**Finding DM-05 (LOW):** "Verification" entity is classed as "event record" but its current state is payload fields on Finding. The doc correctly notes this is aspirational.

**Finding DM-06 (LOW):** "MemoryEntry" entity name doesn't match current table/column names (`repo_memory` / `RepoMemoryRow`).

### 8.3 Verified consistent

- v1 fingerprint description (`sha256(category|file|normalized_title)[:16]`, line excluded) — accurate.
- Review identity formats (`review_id = owner/repo#pr@sha12`, report id format) — accurate.
- Retention section correctly labeled "proposed baseline (NOT current behavior)" — accurate.
- Storage-homes decision record consistent with ADR-011.
- FindingEvidence record shape matches ADR-004.
- Event envelope schema matches `TARGET_ARCHITECTURE.md`.
- "One writer per datum" principle consistent across `DATA_MODEL.md` and `TARGET_ARCHITECTURE.md`.
- "Derived beats stored" principle consistent with `MASTER_VISION.md`.
- "No individual performance data" principle consistent with `MASTER_VISION.md` WILL NOT list.

---

## 9. AI Architecture Consistency

`AI_AGENT_ARCHITECTURE.md` is **missing** (see §1.2). The following checks were performed on the documents that do exist:

### 9.1 Agent responsibilities and orchestration

- `MASTER_VISION.md` §5 E/F: "V5, gated on provenance" — consistent with `V4_V10_ROADMAP.md` V5 hard deps (V4-E04 + V4-E05).
- `ADR-006` (bounded fan-out under one orchestrator): consistent with `V4_V10_ROADMAP.md` V5-E01 (fan-out orchestration) and the C5 in-process carve-out.
- `TARGET_ARCHITECTURE.md` Phase A package boundaries: `orchestration/` (planner/executor/merger/synthesizer) — consistent with `MASTER_ROADMAP.md` V5 architecture changes.

### 9.2 Routing and provider abstraction

- `ADR-007` (structural protocol as the seam): consistent with `CURRENT_ARCHITECTURE.md` §8 and `TARGET_ARCHITECTURE.md` §7.2.
- `MASTER_ROADMAP.md` V5: "model_router.py → capability registry" — consistent with `EPIC_BACKLOG.md` V5-E05.

### 9.3 Context retrieval and token budgets

- `COST_TOKEN_ARCHITECTURE.md` references current char budgets (80k/12k) and C7 — consistent with `CURRENT_ARCHITECTURE.md`.
- `V4_V10_ROADMAP.md` V4-E02: "token-aware retrieval" — consistent with `COST_TOKEN_ARCHITECTURE.md` telemetry spine.

### 9.4 Verification and evidence

- `ADR-012` (deterministic evidence only): consistent with `CURRENT_ARCHITECTURE.md` §5 (verification lifecycle) and `MASTER_ROADMAP.md` V6 ("T1 coverage floor; T3 observed-test-evidence only").
- `ADR-004` (evidence as first-class records): consistent with `DATA_MODEL.md` FindingEvidence shape and `EPIC_BACKLOG.md` V4-E04.

### 9.5 Failure handling

- `MASTER_ROADMAP.md` V5: "agents never post directly (merged+validated only)" — consistent with `DO_NOT_BUILD_YET.md` B5 (no auto-mute without human) and `CURRENT_ARCHITECTURE.md` (model output untrusted).
- `V4_V10_ROADMAP.md` V5: "cross-agent output re-validated as untrusted; per-prompt fencing" — consistent with `CURRENT_ARCHITECTURE.md` §6 (security boundary).

### 9.6 Anti-patterns

- `DO_NOT_BUILD_YET.md` E1–E4 (giant prompt, AI-authored memory, self-modifying prompts, multi-agent loops without budgets) — all consistent with `MASTER_VISION.md` principles and `EPIC_BACKLOG.md` epic designs (V5-E01 has budgets, V5-E07 arbitrates).

**Verdict:** AI architecture is **coherent** across existing documents. The missing `AI_AGENT_ARCHITECTURE.md` is the primary gap.

---

## 10. Security Consistency

`SECURITY_ROADMAP.md` is **missing** (see §1.2). The following checks were performed on the documents that do exist:

### 10.1 Trust boundaries

- `CURRENT_ARCHITECTURE.md` §6 (security boundary diagram): untrusted = PR diff, repo files, issue/comment text, model output, memory notes, repo context. Trusted = `.ai-pr-reviewer.yml` (base revision), dashboard settings, CLI/env config, focus areas. Consistent with `MASTER_VISION.md` principles.
- `TARGET_ARCHITECTURE.md` Phase A boundaries: security column consistent with `CURRENT_ARCHITECTURE.md`.

### 10.2 Prompt injection defenses

- `CURRENT_ARCHITECTURE.md` §6: nonce fencing + 8-pattern injection screening + redaction. Consistent with `MASTER_VISION.md` and `EPIC_BACKLOG.md` V4-E08 (intelligence security & budgets).
- `V4_V10_ROADMAP.md` V4-E08: "retrieval fencing + injection exclusion, path allowlist, budget caps as DoS control" — consistent.

### 10.3 Secret handling

- `CURRENT_ARCHITECTURE.md` §6: `redact_secrets()` on everything stored/posted. Consistent with `COST_TOKEN_ARCHITECTURE.md` ("telemetry must pass `redact_secrets()` before storage/posting").
- `MASTER_ROADMAP.md` V7: "secrets redacted from digests" — consistent.

### 10.4 Authorization and tenant isolation

- `MASTER_ROADMAP.md` V9: "scope matrix as CI invariant (cross-org deny)" — consistent with `DO_NOT_BUILD_YET.md` C1 (full multi-tenancy refused until V10-E03, ADR-gated).
- `TARGET_ARCHITECTURE.md` Phase D: "row-level scope in data layer" — consistent.

### 10.5 Memory poisoning

- `MASTER_ROADMAP.md` V7: "authority model blocks memory poisoning" — consistent with `ADR-003` (memory authority model) and `DO_NOT_BUILD_YET.md` E2 (AI-authored permanent memory refused).
- `EPIC_BACKLOG.md` V7-E07 (memory security): consistent.

### 10.6 Plugin security

- `MASTER_ROADMAP.md` V10: "plugin code is hostile: sandbox escape suite, output treated as model-untrusted, no tokens by default, manifest signing" — consistent with `DO_NOT_BUILD_YET.md` D2 (plugin marketplace refused until V10-E01 proves itself).

### 10.7 GitHub permissions

- `CURRENT_ARCHITECTURE.md` §6: "no `checks: write`" — consistent with `MASTER_VISION.md` and `example-workflow.yml`.
- `MASTER_ROADMAP.md` V8: "token perms unchanged" — consistent.

### 10.8 Auditability

- `CURRENT_ARCHITECTURE.md` §7: `audit.jsonl` append-only. Consistent with `DATA_MODEL.md` AuditRecord entity and `MASTER_ROADMAP.md` V9 (metrics/audit platform).

**Verdict:** Security is **coherent** across existing documents. The missing `SECURITY_ROADMAP.md` is the primary gap — it is the document that would contain the full threat model and per-subsystem trust-boundary table.

---

## 11. Testing & Evaluation Coverage

### 11.1 Coverage by capability

| Capability | Testing strategy assigned? | Where |
|---|---|---|
| Repository index (V4-E01) | ✅ | `TESTING_EVALUATION_PLAN.md` L7/L8 + `V4_V10_ROADMAP.md` V4 |
| Context engine v2 (V4-E02) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 + `V4_V10_ROADMAP.md` V4 |
| Change impact analysis (V4-E03) | ❌ **No** | — |
| Evidence engine (V4-E04) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Finding identity v2 (V4-E05) | ✅ | `TESTING_EVALUATION_PLAN.md` L16 (migration) |
| Digital twin seed (V4-E06) | ✅ | `V4_V10_ROADMAP.md` V4 |
| Intelligence read contracts (V4-E07) | ✅ | `TESTING_EVALUATION_PLAN.md` L3 |
| Intelligence security (V4-E08) | ✅ | `TESTING_EVALUATION_PLAN.md` L5/L6 |
| Fan-out orchestration (V5-E01) | ✅ | `TESTING_EVALUATION_PLAN.md` L14 (load) |
| Specialist contracts (V5-E02) | ✅ | `TESTING_EVALUATION_PLAN.md` L4 |
| Finding merger (V5-E03) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Risk engine (V5-E04) | ✅ | `TESTING_EVALUATION_PLAN.md` L12 |
| Provider registry (V5-E05) | ⚠ partial | `TESTING_EVALUATION_PLAN.md` L4 (provider contract) but no registry-specific test |
| Council synthesis (V5-E06) | ✅ | `TESTING_EVALUATION_PLAN.md` L12 |
| Cost arbitration (V5-E07) | ✅ | `TESTING_EVALUATION_PLAN.md` L13 (performance) |
| Multi-agent evaluation (V5-E08) | ✅ | `TESTING_EVALUATION_PLAN.md` L11/L12 |
| Security engine (V6-E01) | ✅ | `TESTING_EVALUATION_PLAN.md` L5 |
| AI security v2 (V6-E02) | ✅ | `TESTING_EVALUATION_PLAN.md` L6 |
| Test intelligence (V6-E03) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Architecture intelligence (V6-E04) | ✅ | `V4_V10_ROADMAP.md` V6 |
| Advanced verification (V6-E05) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Dependency intelligence (V6-E06) | ✅ | `V4_V10_ROADMAP.md` V6 |
| Policy engine (V6-E07) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Security eval corpus (V6-E08) | ✅ | `TESTING_EVALUATION_PLAN.md` L9/L10 |
| Git history (V7-E01) | ✅ | `V4_V10_ROADMAP.md` V7 |
| Memory hierarchy (V7-E02) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Finding relations (V7-E03) | ❌ **No** | — |
| Issue/requirement linkage (V7-E04) | ✅ | `V4_V10_ROADMAP.md` V7 |
| Team analytics (V7-E05) | ❌ **No** | — |
| Historical evidence (V7-E06) | ✅ | `V4_V10_ROADMAP.md` V7 |
| Memory security (V7-E07) | ❌ **No** | — |
| CI ingestion (V8-E01) | ✅ | `TESTING_EVALUATION_PLAN.md` L3 |
| Test-failure correlation (V8-E02) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Release intelligence (V8-E03) | ✅ | `V4_V10_ROADMAP.md` V8 |
| Docs intelligence (V8-E04) | ✅ | `V4_V10_ROADMAP.md` V8 |
| Infrastructure intelligence (V8-E05) | ✅ | `V4_V10_ROADMAP.md` V8 |
| Incident intelligence (V8-E06) | ✅ | `V4_V10_ROADMAP.md` V8 |
| Event platform (V8-E07) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Org model (V9-E01) | ✅ | `TESTING_EVALUATION_PLAN.md` L3 |
| Org policy (V9-E02) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Versioned API (V9-E03) | ✅ | `TESTING_EVALUATION_PLAN.md` L3 |
| Workers (V9-E04) | ✅ | `TESTING_EVALUATION_PLAN.md` L14/L15 |
| Org memory (V9-E05) | ✅ | `TESTING_EVALUATION_PLAN.md` L7 |
| Extensibility contract (V9-E06) | ✅ | `TESTING_EVALUATION_PLAN.md` L4 |
| Observability (V9-E07) | ✅ | `TESTING_EVALUATION_PLAN.md` L13 |
| Plugin system (V10-E01) | ✅ | `TESTING_EVALUATION_PLAN.md` L5 |
| Provider ecosystem (V10-E02) | ✅ | `TESTING_EVALUATION_PLAN.md` L4 |
| Multi-tenancy (V10-E03) | ⚠ optional | `DO_NOT_BUILD_YET.md` — ADR-gated, no test strategy needed until approved |
| IDE/CLI (V10-E04) | ✅ | `TESTING_EVALUATION_PLAN.md` L3 |
| Org analytics (V10-E05) | ✅ | `TESTING_EVALUATION_PLAN.md` L12 |
| Command center (V10-E06) | ✅ | `TESTING_EVALUATION_PLAN.md` L3 |

### 11.2 Findings

**Finding TEST-01 (MEDIUM):** `TESTING_EVALUATION_PLAN.md` has no testing strategy for **memory poisoning / memory security** (V7-E07). The word "poison" appears 0 times. `V4_V10_ROADMAP.md` V7 mentions "poisoning corpus" and "authority matrix" but `TESTING_EVALUATION_PLAN.md` does not assign a testing layer or method for this.

**Finding TEST-02 (MEDIUM):** No testing strategy for **change impact analysis** (V4-E03). The word "impact" appears 0 times in `TESTING_EVALUATION_PLAN.md`. Impact analysis is a core V4 capability with no assigned evaluation method.

**Finding TEST-03 (MEDIUM):** No testing strategy for **finding relations** (V7-E03). The word "relations" appears 0 times. Relations (duplicate/caused_by/fixed_by/regression_of) are a significant identity feature with no assigned test layer.

**Finding TEST-04 (MEDIUM):** No testing strategy for **team/repository analytics** (V7-E05). The word "analytics" appears 0 times. Analytics has no assigned evaluation method (particularly the "no individual rankings" invariant).

**Finding TEST-05 (LOW):** No explicit **provider failover** testing strategy for the capability registry (V5-E05). The word "failover" appears 4 times but in the context of the existing static fallback, not the V5-E05 registry-driven routing. The current suite has `test_provider_failover.py` but the plan does not assign a testing layer for registry-driven failover.

---

## 12. Cost & Token Consistency

### 12.1 Grounding in current budgets

`COST_TOKEN_ARCHITECTURE.md` correctly references:
- `batch_chars` / `DEFAULT_TOKEN_BUDGET` = 80,000 chars (`config.py:78`, `context.py:33`)
- `repo_context_chars` = 12,000 chars (`config.py:99`)
- C7 constraint (character budgets, not token budgets)
- V3-E02 telemetry foundation
- V5-E07 cost arbitration

### 12.2 Token budget model

The proposed token budget model (all marked "proposed baseline"):
- PR diff: 80,000 chars ≈ 20,000 tokens
- Repo context: 12,000 chars ≈ 3,000 tokens
- V5 multi-agent: 300,000 tokens/run hard cap; per-agent 60,000; V5-E07 arbitrates
- V9 org: 5,000,000 tokens/month/org

These are internally consistent (60k × 5 agents = 300k cap) and grounded in the current character budgets.

### 12.3 Cost mentions per stage in V4_V10_ROADMAP

| Stage | token mentions | cost mentions | Assessment |
|---|---|---|---|
| Phase 0 | 10 | 11 | Appropriate (telemetry foundation) |
| V4 | 8 | 4 | Appropriate (budgets) |
| V5 | 6 | 14 | Appropriate (multi-agent arbitration) |
| V6 | 3 | 5 | Appropriate |
| V7 | 2 | 1 | Appropriate |
| V8 | 5 | 3 | Appropriate |
| V9 | 11 | 5 | Appropriate (org envelope) |
| V10 | 7 | 10 | Appropriate (plugins, multi-tenancy) |

### 12.4 Findings

**Finding COST-01 (LOW):** `COST_TOKEN_ARCHITECTURE.md` does not explicitly reconcile the V5 multi-agent token cap (300,000 tokens/run) with the V4 context budget (20,000 tokens for diff + 3,000 for repo context). The 300k cap is for the *entire* run (all agents, all batches), while the 20k/3k are *per-batch* context budgets. The relationship between per-batch context and per-run total is not explicitly stated.

**Finding COST-02 (INFO):** All numeric targets in `COST_TOKEN_ARCHITECTURE.md` are correctly marked "proposed baseline". No unsupported certainty.

---

## 13. ADR Coverage

### 13.1 ADRs present (16)

ADR-001 through ADR-016 are documented in `ADR_INDEX.md`. Statuses:
- **Accepted (de facto):** ADR-001, ADR-005 (v1), ADR-007, ADR-008 (in-process), ADR-010 (single-tenant), ADR-011 (seam), ADR-012, ADR-015 (engine placement)
- **Proposed — requires human approval:** ADR-002, ADR-003, ADR-004, ADR-005 (v2), ADR-006, ADR-008 (queue boundary), ADR-009, ADR-010 (multi-tenant boundary), ADR-011 (evolution steps), ADR-013, ADR-014, ADR-016

### 13.2 Coverage gaps

**Finding ADR-01 (MEDIUM):** **Context retrieval/ranking strategy** has no ADR. This is a major architectural decision (how the context engine v2 retrieves, ranks, and budgets repository content) that will be implemented in V4-E02. It is distinct from ADR-002 (repository graph representation) and ADR-011 (storage evolution).

**Finding ADR-02 (MEDIUM):** **Adaptive review depth** has no ADR. V5-E04 introduces depth levels (lightweight/normal/context-aware/multi-specialist/deep) with quality/latency/cost trade-offs. This is a significant decision that interacts with ADR-006 (agent architecture) and ADR-014 (cost accounting) but is not covered by either.

**Finding ADR-03 (LOW):** **Finding relations model** has no ADR. V7-E03 introduces relations (duplicate/caused_by/fixed_by/regression_of) that attach to identity. This is related to ADR-005 (finding identity) but relations are a distinct modeling decision.

**Finding ADR-04 (LOW):** **CI correlation methodology** has no ADR. V8-E02 introduces test-failure correlation with PR changes. The methodology (what constitutes correlation vs causation) is a significant decision.

**Finding ADR-05 (LOW):** **API versioning strategy** has no ADR. V9-E03 introduces `/api/v1`. The versioning policy (how versions are introduced, deprecated, and retired) is a significant decision for a public API.

### 13.3 Verified coverage

The following major decisions **are** covered by ADRs: modular monolith (001), repository graph (002), memory authority (003), evidence model (004), finding identity (005), agent architecture (006), provider abstraction (007), queue/event (008), plugin contract (009), multi-tenant boundary (010), storage evolution (011), verification trust (012), webhook security (013), telemetry/cost (014), policy placement (015), testing gate (016).

---

## 14. Do-Not-Build Boundary Check

### 14.1 Boundary items in DO_NOT_BUILD_YET.md

21 items in 5 themes:
- **A (distribution theater):** microservices, Kubernetes, queues, distributed tracing, GraphQL, real-time collaborative dashboard
- **B (autonomous write actions):** auto-commits, auto-merge, auto-deploy, incident automation, auto-mute
- **C (platform scope creep):** full multi-tenancy, org analytics/individual rankings, unbounded ingestion, data warehouse
- **D (extensibility ahead of contracts):** IDE plugins, plugin marketplace
- **E (AI scope creep):** giant prompt, AI-authored memory, self-modifying prompts, multi-agent loops without budgets

### 14.2 Roadmap compliance check

| Refused item | Scheduled in Phase 0/V4/V5? | Consistent? |
|---|---|---|
| Microservices | No — Phase A is modular monolith | ✅ |
| Kubernetes | No | ✅ |
| Queues | No — V8-E07 is "append-only log — no queues"; V9-E04 is "only where measured" | ✅ |
| Distributed tracing | No | ✅ |
| GraphQL | No | ✅ |
| Real-time collaborative dashboard | No | ✅ |
| Auto-commits | No — `MASTER_VISION.md` WILL NOT list | ✅ |
| Auto-merge | No | ✅ |
| Auto-deploy | No | ✅ |
| Incident automation | No — V8-E06 is "read-only retrospective" | ✅ |
| Auto-mute | No — `DO_NOT_BUILD_YET.md` B5; `MASTER_ROADMAP.md` V9 says "human approval for org memory" | ✅ |
| Full multi-tenancy | No — V10-E03 is "strictly optional, ADR-gated" | ✅ |
| Org analytics / individual rankings | No — V7-E05 is "no individual rankings"; V10-E05 is after V9-E01/E07 | ✅ |
| Unbounded ingestion | No — V4-E08 is "budget caps as DoS control" | ✅ |
| Data warehouse | No | ✅ |
| IDE plugins | No — V10-E04, after V9-E03/V9-E06 contracts | ✅ |
| Plugin marketplace | No — after V10-E01 exit criteria | ✅ |
| Giant prompt | No — V5-E02 extracts shared prompt-builder | ✅ |
| AI-authored memory | No — ADR-003 authority model; `MASTER_VISION.md` WILL NOT | ✅ |
| Self-modifying prompts | No | ✅ |
| Multi-agent loops without budgets | No — V5-E01 has budgets, V5-E07 arbitrates | ✅ |

### 14.3 Finding

**Finding DNB-01 (INFO):** No boundary violations. All 21 refused items are either explicitly negated in the roadmap or deferred to the correct stage with appropriate gating. The V8-E07 "append-only log — no queues" carve-out and V9-E04 "only where measured" are consistent with the queue refusal.

---

## 15. Git/Repository Safety

### 15.1 Worktree state

```
 D .github/dependabot.yml          (pre-existing — was deleted before audit began)
?? AGENTS.md                       (pre-existing — untracked before audit began)
?? docs/                           (12 new planning documents under docs/planning/)
```

### 15.2 Tracked-file changes

```
.github/dependabot.yml | 12 ------------
1 file changed, 12 deletions(-)
```

This deletion was **pre-existing** — it was present in the very first `git status` before any planning work began. No new tracked-file changes were introduced during planning or this audit.

### 15.3 Untracked files

Only `AGENTS.md` (pre-existing) and `docs/planning/*.md` (12 new planning documents). No production code, no tests, no CI files, no `.github/dependabot.yml` changes.

### 15.4 Commits and pushes

- **HEAD:** `2841b23` (unchanged — no commits made)
- **No pushes performed**

### 15.5 Safety verdict

✅ **Clean.** No production files modified. No tests modified. No CI files modified. No `.github/dependabot.yml` changes introduced. `AGENTS.md` not modified. No commits. No pushes.

---

## 16. Blocking Issues

| ID | Severity | Description |
|---|---|---|
| **BLOCK-01** | **BLOCKING** | **4 of 16 planning documents are missing:** `DEPENDENCY_GRAPH.md`, `AI_AGENT_ARCHITECTURE.md`, `SECURITY_ROADMAP.md`, `MIGRATION_PLAN.md`. The plan set is incomplete. 41 dangling cross-references point to these files. The architecture cannot be frozen without them. |

---

## 17. Non-Blocking Issues

### HIGH

| ID | Description |
|---|---|
| DM-01 | V4-E05 identity v2 mechanism contradiction: `EPIC_BACKLOG.md` + `MASTER_ROADMAP.md` say "dual-computation + alias table + cutover"; `ADR-005` + `DATA_MODEL.md` say "layered, occurrence key, no cutover". |

### MEDIUM

| ID | Description |
|---|---|
| ARCH-01 | `CURRENT_ARCHITECTURE.md` says "14 redaction patterns" — actually 12. |
| ARCH-03 | D6 presented as fully unfixed; `repo_context_chars` is now safe (partially fixed). |
| DEP-01 | Systematic soft→hard elevation tension between `EPIC_BACKLOG.md` and the two roadmap docs. |
| DEP-02 | `V5-E01` missing `V3-E03` as a dependency. |
| DEP-03 | `V7-E02` missing `V4-E05` as a dependency. |
| DM-02 | `DATA_MODEL.md` stale caveat about `EPIC_BACKLOG.md` not being in the tree. |
| DM-03 | "SecurityFinding"/"ArchitectureFinding" are invented terms, used nowhere else. |
| TEST-01 | No testing strategy for memory poisoning / memory security (V7-E07). |
| TEST-02 | No testing strategy for change impact analysis (V4-E03). |
| TEST-03 | No testing strategy for finding relations (V7-E03). |
| TEST-04 | No testing strategy for team/repository analytics (V7-E05). |
| ADR-01 | Context retrieval/ranking strategy has no ADR. |
| ADR-02 | Adaptive review depth has no ADR. |

### LOW

| ID | Description |
|---|---|
| ARCH-02 | "22 test files" — actually 21 test files + conftest. |
| ARCH-04 | "~24 routes" — actually 23. |
| ARCH-05 | "8 markdown findings" is a function default, not a named constant. |
| DEP-04 | `V6-E03` soft-depends on `V8-E02` (forward reference to later stage). |
| DM-04 | "ReviewRun" home says "relational (SQLite now)" but no such table exists. |
| DM-05 | "Verification" classed as "event record" but is payload fields today. |
| DM-06 | "MemoryEntry" name doesn't match current `repo_memory`/`RepoMemoryRow`. |
| STAGE-01 | V8 stage name drift: "CI / release" vs "CI/CD + release". |
| TEST-05 | No explicit provider failover testing for V5-E05 registry. |
| COST-01 | V5 multi-agent token cap not explicitly reconciled with V4 per-batch context budgets. |
| ADR-03 | Finding relations model has no ADR. |
| ADR-04 | CI correlation methodology has no ADR. |
| ADR-05 | API versioning strategy has no ADR. |

### INFO

| ID | Description |
|---|---|
| ARCH-06 | "dismissed vestigial" — verified accurate. |
| ARCH-07 | 2MB body check is writes-only. |
| DM-07–DM-15 | Data model claims verified accurate. |
| DNB-01 | No DO_NOT_BUILD_YET boundary violations. |
| COST-02 | All numeric targets correctly marked "proposed baseline". |

---

## 18. Required Corrections Before V4 Implementation

The following must be resolved before V4 implementation begins:

1. **Write the 4 missing documents** (BLOCK-01): `DEPENDENCY_GRAPH.md`, `AI_AGENT_ARCHITECTURE.md`, `SECURITY_ROADMAP.md`, `MIGRATION_PLAN.md`. These are not optional — they are part of the plan set and are referenced 41 times by existing documents.

2. **Resolve the identity v2 contradiction** (DM-01): Reconcile `EPIC_BACKLOG.md` V4-E05 and `MASTER_ROADMAP.md` with `ADR-005` / `DATA_MODEL.md`. Recommendation: adopt the layered model (ADR-005) — it is simpler, already has two documents behind it, and avoids the alias-table migration burden.

3. **Fix the factual errors in `CURRENT_ARCHITECTURE.md`** (ARCH-01, ARCH-03): This is the "ground truth" document — its errors propagate. Change "14 patterns" to "12"; update D6 to note the partial fix.

4. **Reconcile the dependency tension** (DEP-01, DEP-02, DEP-03): Either update `EPIC_BACKLOG.md` to promote the soft deps to hard (matching the roadmaps) or update the roadmaps to demote them to soft. The backlog should not understate prerequisites.

5. **Add testing strategies for the 5 uncovered capabilities** (TEST-01 through TEST-05): memory poisoning, impact analysis, finding relations, analytics, provider failover.

6. **Add ADRs for the 5 uncovered decisions** (ADR-01 through ADR-05): context retrieval, adaptive depth, finding relations, CI correlation, API versioning.

---

## 19. Architecture Freeze Recommendation

### 19.1 Current readiness

| Criterion | Ready? |
|---|---|
| All 16 planning documents written | ❌ No — 4 missing |
| No HIGH-severity contradictions | ❌ No — DM-01 |
| No factual errors in ground-truth document | ❌ No — ARCH-01, ARCH-03 |
| Dependencies fully consistent | ⚠ Partial — systematic tension |
| Testing coverage complete | ⚠ Partial — 5 gaps |
| ADR coverage complete | ⚠ Partial — 5 gaps |
| Do-Not-Build boundary respected | ✅ Yes |
| Git/repository safety | ✅ Yes |
| Epic ID integrity | ✅ Yes |
| V4–V10 structure consistency | ✅ Yes |

### 19.2 Recommendation

**DO NOT FREEZE.** The architecture is **not ready to freeze** because:

1. The plan set is **incomplete** (4 of 16 documents missing).
2. There is **1 HIGH-severity contradiction** (identity v2 mechanism) that would cause implementation confusion.
3. The ground-truth document (`CURRENT_ARCHITECTURE.md`) contains **factual errors** that propagate to all other documents.

### 19.3 Path to freeze

1. Write the 4 missing documents.
2. Resolve DM-01 (identity v2 contradiction).
3. Fix ARCH-01 and ARCH-03 in `CURRENT_ARCHITECTURE.md`.
4. Reconcile DEP-01/02/03 (dependency tension).
5. Add testing strategies for TEST-01 through TEST-05.
6. Add ADRs for ADR-01 through ADR-05.
7. Re-run this audit.

**Estimated effort:** The 4 missing documents are the bulk of the work. The corrections are small and surgical. Once the missing documents exist and the HIGH contradiction is resolved, the architecture is otherwise coherent and ready to freeze.

---

## Summary of All Findings

| Severity | Count | IDs |
|---|---|---|
| BLOCKING | 1 | BLOCK-01 |
| HIGH | 1 | DM-01 |
| MEDIUM | 12 | ARCH-01, ARCH-03, DEP-01, DEP-02, DEP-03, DM-02, DM-03, TEST-01, TEST-02, TEST-03, TEST-04, ADR-01, ADR-02 |
| LOW | 13 | ARCH-02, ARCH-04, ARCH-05, DEP-04, DM-04, DM-05, DM-06, STAGE-01, TEST-05, COST-01, ADR-03, ADR-04, ADR-05 |
| INFO | 5 | ARCH-06, ARCH-07, DNB-01, COST-02, DM-07–DM-15 |

**Total: 32 findings** (1 BLOCKING, 1 HIGH, 12 MEDIUM, 13 LOW, 5 INFO)
