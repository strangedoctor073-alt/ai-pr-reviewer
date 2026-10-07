# Migration Plan — V3 → V10 Compatibility Strategy

> Status: planning document (v1) — created during remediation to resolve BLOCK-01.
> Repository state: commit `2841b23`.
> Canonical stage structure: Phase 0/"V3.x", V4, V5, V6, V7, V8, V9, V10.
> Guiding rule: **No big-bang rewrite.** V3 must keep working at every stage. The Action contract is additive-only. Storage schema is additive-first. Rollback is always possible by pinning the previous tag.

---

## 1. Compatibility contract (what never breaks without a major version)

| Surface | Guarantee |
|---|---|
| GitHub Action inputs | Additive-only; no input removed or renamed without a major version |
| GitHub Action outputs | `findings_count`, `critical_count`, `report_path`, `health_score`, `health_grade` — preserved |
| Exit codes | 0 (clean), 1 (config error), 2 (fail_on threshold) — preserved |
| Report JSON top-level fields | Additive-only; no field removed or retyped |
| `ReviewStorage` protocol methods | Additive-only; existing method signatures preserved |
| `AIProvider` protocol | Additive-only; `analyze(context) → AnalysisOutcome` preserved |
| `.ai-pr-reviewer.yml` schema | Additive-only; new keys are optional with defaults |
| Finding fingerprint v1 | Preserved as primary key through V10 (layered model, ADR-005) |
| GitHub comment behavior | Inline comments + summary review; state markers; duplicate prevention |
| Static fallback | Always available; always honestly labelled "not AI" |
| Zero-API-key path | `--mock` / `--static` fully functional at every stage |

**Machine-checkable half.** `tests/test_action_contract.py`
(`V3-E05-T03`) and `tests/test_report_schema.py` (`V3-E05-T04`) turn the
Action-input, Action-output, exit-code and report-JSON rows above into
blocking CI tests: the snapshots freeze names/defaults and the report guard
is additive-only (additions pass, removals/renames fail). Breaking any of
these surfaces fails the suite before it can ship — update the snapshot in
the same reviewed change only when the change is genuinely additive.

---

## 2. Per-stage migration table

### 2.1 Phase 0 (V3-E01..E06)

| Dimension | Impact |
|---|---|
| Backward compatibility | D1–D5 change behavior (fixes); D6 changes error handling; D7 changes storage. All are bug fixes, not breaking changes. |
| Configuration migration | None. |
| Database migration | None (D7 mute idempotency is a code fix, not schema). |
| API versioning | None. |
| GitHub Action compatibility | No input/output changes. |
| Existing user configuration | No changes. |
| Existing findings | No migration (fingerprints unchanged). |
| Existing memory | No migration. |
| Rollback | Revert to pre-Phase-0 tag; behavior returns to V3. |
| Deprecation notes | D3/D4 change report counts (below-threshold findings now appear; comment cap decoupled from report cap) — CHANGELOG note required. |

### 2.2 V4 (V4-E01..E08)

| Dimension | Impact |
|---|---|
| Backward compatibility | New `index/` and `evidence.py` subsystems are additive. `context.py` gains token-aware retrieval but char-budget fallback remains. `Finding` gains provenance fields (additive). |
| Configuration migration | New optional keys in `.ai-pr-reviewer.yml` (e.g. `review.context_budget`) default to current behavior. |
| Database migration | New tables: `repo_index`, `finding_evidence`, `context_artifacts`. Additive only. Existing tables unchanged. |
| API versioning | None (internal read contracts only; public API is V9). |
| GitHub Action compatibility | No input/output changes. New optional inputs (e.g. `index_enabled`) default to off. |
| Existing user configuration | No changes. |
| Existing findings | v1 fingerprints unchanged; provenance backfilled where determinable. |
| Existing memory | No migration. |
| Rollback | Revert to Phase 0 tag; index/evidence tables unused. |
| Deprecation notes | None. |

### 2.3 V5 (V5-E01..E08)

| Dimension | Impact |
|---|---|
| Backward compatibility | `orchestrator.py` → `orchestration/` is an internal restructure; the CLI contract is unchanged. Council is opt-in; default path is equivalent-or-better single-provider. |
| Configuration migration | New optional inputs (e.g. `council_enabled`, `max_specialists`) default to off/current. |
| Database migration | New table: `review_runs` (telemetry). Additive. |
| API versioning | None. |
| GitHub Action compatibility | No input/output changes. |
| Existing user configuration | No changes. |
| Existing findings | No migration. |
| Existing memory | No migration. |
| Rollback | Revert to V4 tag; council disabled; single-provider path restored. |
| Deprecation notes | None. |

### 2.4 V6 (V6-E01..E08)

| Dimension | Impact |
|---|---|
| Backward compatibility | New `security_eng/`, `test_intel/`, `arch_rules/`, `deps/`, `policy/` subsystems are additive. `verification.py` gains tiers but T1 (coverage) remains the floor. |
| Configuration migration | New optional YAML keys (e.g. `security.enabled`, `policy.levels`) default to current behavior. |
| Database migration | New tables: `test_evidence`, `ci_results`, `dependencies`, `policy_evaluations`. Additive. |
| API versioning | None. |
| GitHub Action compatibility | No input/output changes. |
| Existing user configuration | No changes. |
| Existing findings | No migration; verification tiers are additive metadata. |
| Existing memory | No migration. |
| Rollback | Revert to V5 tag; new subsystems unused. |
| Deprecation notes | None. |

### 2.5 V7 (V7-E01..E07)

| Dimension | Impact |
|---|---|
| Backward compatibility | `memory.py` gains hierarchy + authority model; existing `repo_memory` rows backfilled with `level=repo, authority=human`. New `history/` and `linkage.py` are additive. |
| Configuration migration | New optional YAML keys (e.g. `memory.levels`) default to current behavior. |
| Database migration | New tables: `finding_relations`, `memory_hierarchy`. `repo_memory` gains `level` and `authority` columns (additive, backfilled). |
| API versioning | None. |
| GitHub Action compatibility | No input/output changes. |
| Existing user configuration | No changes. |
| Existing findings | No migration; relations are additive. |
| Existing memory | Backfilled with `level=repo, authority=human` (idempotent). |
| Rollback | Revert to V6 tag; hierarchy columns unused. |
| Deprecation notes | None. |

### 2.6 V8 (V8-E01..E07)

| Dimension | Impact |
|---|---|
| Backward compatibility | New `events/`, `ci_correlation/`, `release_intel/`, `docs_intel/`, `infra_intel/`, `incident_intel/` are additive. Event platform v1 is an append-only log — no queues. |
| Configuration migration | New optional inputs (e.g. `ci_ingestion_enabled`) default to off. |
| Database migration | New table: `events` (append-only log). Additive. |
| API versioning | None (event log is internal). |
| GitHub Action compatibility | No input/output changes. |
| Existing user configuration | No changes. |
| Existing findings | No migration. |
| Existing memory | No migration. |
| Rollback | Revert to V7 tag; event log unused. |
| Deprecation notes | None. |

### 2.7 V9 (V9-E01..E07)

| Dimension | Impact |
|---|---|
| Backward compatibility | `dashboard/app.py` → versioned `api/v1/` with scope authz. Legacy routes deprecated with headers. Org model is additive. Workers are optional deployment. |
| Configuration migration | New optional inputs (e.g. `org_id`) default to empty (single-org). |
| Database migration | New tables: `organizations`, `teams`, `org_policies`. Additive. |
| API versioning | `/api/v1/` is the first versioned API. Legacy routes deprecated with `Deprecation` header. |
| GitHub Action compatibility | **Byte-unchanged.** Action contract is identical. |
| Existing user configuration | No changes. |
| Existing findings | No migration. |
| Existing memory | No migration. |
| Rollback | Revert to V8 tag; versioned API unused; legacy routes restored. |
| Deprecation notes | Legacy dashboard routes deprecated with headers; sunset date documented. |

### 2.8 V10 (V10-E01..E06)

| Dimension | Impact |
|---|---|
| Backward compatibility | `plugins/` is opt-in (default off). Provider ecosystem is additive. Multi-tenancy is strictly optional (ADR-gated). IDE/CLI share the local-review core. |
| Configuration migration | New optional inputs (e.g. `plugins_enabled`) default to off. |
| Database migration | New tables: `plugins`, `tenants` (only if V10-E03 approved). Additive. |
| API versioning | `/api/v1/` preserved; new endpoints additive. |
| GitHub Action compatibility | No input/output changes. |
| Existing user configuration | No changes. |
| Existing findings | No migration. |
| Existing memory | No migration. |
| Rollback | Revert to V9 tag; plugins disabled. |
| Deprecation notes | None. |

---

## 3. Database migration strategy

### 3.1 Principles

1. **Additive-first:** new tables and columns are added; existing tables and columns are never removed or retyped.
2. **Payload-then-normalize:** new entities start as JSON payloads inside existing rows (following the current `finding_history.payload` pattern); normalize into own tables only when query evidence justifies it.
3. **Hand-rolled `ALTER TABLE` for now:** the current approach (best-effort `ALTER TABLE ... ADD COLUMN`) is acceptable at current schema size. Adopt a real migration tool (e.g. Alembic) when schema churn accelerates in V4+ — the decision record, full inventory, tool criteria and measurable trigger live in `ADR-022` (written by V3-E04-T06; mandatory trigger: first non-additive change, scheduled review: first V4 storage addition).
4. **Idempotent:** every migration can be re-run safely.
5. **Backfill before cutover:** new columns are backfilled before any code depends on them.

### 3.2 Schema evolution by stage

| Stage | New tables | New columns | Migration tool |
|---|---|---|---|
| Phase 0 | — | — | — |
| V4 | `repo_index`, `finding_evidence`, `context_artifacts` | — | Hand-rolled |
| V5 | `review_runs` | — | Hand-rolled |
| V6 | `test_evidence`, `ci_results`, `dependencies`, `policy_evaluations` | — | Hand-rolled |
| V7 | `finding_relations`, `memory_hierarchy` | `repo_memory.level`, `repo_memory.authority` | Hand-rolled |
| V8 | `events` | — | Hand-rolled |
| V9 | `organizations`, `teams`, `org_policies` | — | Alembic (proposed) |
| V10 | `plugins`, `tenants` (optional) | — | Alembic (proposed) |

### 3.3 Rollback strategy

- Every migration is backward-compatible: old code ignores new tables/columns.
- Rollback = revert to previous tag; new tables/columns become unused (no data loss).
- Exception: V9 legacy route deprecation — rollback restores legacy routes.

---

## 4. Configuration migration

### 4.1 `.ai-pr-reviewer.yml` schema evolution

| Stage | New keys | Default | Breaking? |
|---|---|---|---|
| Phase 0 | — | — | No |
| V4 | `review.context_budget` | current char budget | No |
| V5 | `review.council_enabled`, `review.max_specialists` | off / 5 | No |
| V6 | `security.enabled`, `policy.levels` | on / repo | No |
| V7 | `memory.levels` | repo | No |
| V8 | `ci_ingestion.enabled` | off | No |
| V9 | `org.id` | (empty) | No |
| V10 | `plugins.enabled` | off | No |

### 4.2 Action inputs evolution

All new inputs are optional with defaults that preserve current behavior. No input is removed or renamed without a major version.

---

## 5. Finding identity migration (ADR-005)

### 5.1 Layered model (canonical)

- v1 fingerprint (`sha256(category|file|normalized_title)[:16]`) remains the primary key.
- Provenance fields (`engine`, `model`, `agent`, `origin`) are added to `Finding` (pipeline-owned, like `LIFECYCLE_FIELDS`).
- Occurrence key is added for cross-engine matching (additive; does not change v1 identity).
- No cutover; no alias table; no dual-computation.

### 5.2 Migration steps

1. Add provenance columns to `finding_history` (additive, nullable).
2. Backfill provenance where determinable (from `payload` JSON).
3. Add occurrence key computation to `findings.py`.
4. Update dedup to use occurrence key for cross-engine matching (v1 still primary).
5. Update dashboard feedback/mute routes to work on v1 (unchanged).

### 5.3 Continuity guarantees

- Existing comments keyed by v1 fingerprints keep working.
- Existing mute rows keyed by v1 fingerprints keep working.
- Existing lifecycle (first_seen_sha, last_seen_sha, resolved_at) unchanged.
- 100% state continuity on fixture PR series (test).

---

## 6. GitHub Action compatibility

### 6.1 Contract preservation

The Action contract is **byte-unchanged** across all stages:

- Inputs: additive-only.
- Outputs: `findings_count`, `critical_count`, `report_path`, `health_score`, `health_grade` — preserved.
- Exit codes: 0/1/2 — preserved.
- Permissions: `contents: read`, `pull-requests: write` — preserved.
- Trigger: `pull_request` — preserved.
- Checkout: base revision — preserved.

### 6.2 Versioning

- Users pin `@v2` (current). New stages ship as `@v3`, `@v4`, etc.
- Major versions are reserved for breaking changes (none planned).
- Deprecation: old major versions receive security fixes for 12 months after a new major ships.

---

## 7. Deprecation policy

| Item | Deprecation window | Sunset |
|---|---|---|
| Legacy dashboard routes (V9) | 12 months | Documented in CHANGELOG |
| Char-based budgets (V4) | 6 months | Token-aware becomes default; char fallback removed |
| v1-only fingerprint (never) | — | v1 remains primary through V10 (layered model) |
| `analyzer.py` / `heuristics.py` facades | 6 months | Removed after deprecation notice |

---

## 8. Cross-references

- Ground truth: `CURRENT_ARCHITECTURE.md`
- Vision and planes: `MASTER_VISION.md`
- Target design: `TARGET_ARCHITECTURE.md`
- Dependencies: `DEPENDENCY_GRAPH.md`
- Data model: `DATA_MODEL.md`
- AI architecture: `AI_AGENT_ARCHITECTURE.md`
- Security: `SECURITY_ROADMAP.md`
- Testing: `TESTING_EVALUATION_PLAN.md`
- Cost: `COST_TOKEN_ARCHITECTURE.md`
- Decisions: `ADR_INDEX.md` (ADR-005 finding identity, ADR-011 storage evolution, ADR-022 migration-tool trigger)
- Refusal list: `DO_NOT_BUILD_YET.md`
- Audit: `FINAL_CONSISTENCY_AUDIT.md`
