# Dependency Graph — Capability & Epic Dependencies

> Status: planning document (v1) — created during remediation to resolve BLOCK-01.
> Repository state: commit `2841b23`.
> Canonical stage structure: Phase 0/"V3.x", V4, V5, V6, V7, V8, V9, V10.
> Canonical epic IDs: V3-E01..E06, V4-E01..E08, V5-E01..E08, V6-E01..E08, V7-E01..E07, V8-E01..E07, V9-E01..E07, V10-E01..E06 (57 total).

---

## 1. How to read this document

- **HARD** dependency: the dependent epic cannot be implemented correctly without the prerequisite. Gating.
- **SOFT** dependency: the dependent epic benefits from or is informed by the prerequisite, but can degrade gracefully without it. Advisory.
- **FUTURE** dependency: the prerequisite is in a later stage; the dependency is a forward reference that must be respected when the later stage lands.
- **OPTIONAL** dependency: the dependent epic may consume the prerequisite if available, but does not require it.

---

## 2. Capability dependency graph

### 2.1 Foundation → Core Intelligence

```
C3 Repository Context (current: repo_context.py, bounded 8-file fetch)
    ↓ HARD
V4-E01 Repository Index (deterministic repo map at base_sha)
    ↓ HARD
V4-E02 Context Engine v2 (retrieval/ranking/token budgets/provenance)
    ↓ HARD
V4-E03 Change Impact Analysis (references/imports/dependents)
    ↓ HARD
V4-E04 Evidence Engine (FindingEvidence with provenance)
    ↓ HARD
V4-E05 Finding Identity v2 (layered: v1 primary + provenance + occurrence key)
    ↓ HARD
V4-E06 Digital Twin Seed (layered projection over index)
    ↓ HARD
V4-E07 Intelligence Read Contracts (internal read APIs)
    ↓ HARD
V4-E08 Intelligence Security & Budgets (continuous from V4-E01)
```

### 2.2 Core Intelligence → Specialist Review

```
V4-E04 Evidence Engine
    ↓ HARD
V5-E01 Fan-out Orchestration (bounded, per-agent breakers/budgets)
    ↓ HARD
V5-E02 Specialist Reviewer Contracts (prompt/task registry, capability declaration)
    ↓ HARD
V5-E03 Finding Merger (provenance-aware dedup via occurrence key)
    ↓ HARD
V5-E06 Council Synthesis
V5-E04 Risk Engine v1 + Adaptive Depth
    ↓ SOFT (V4-E03 impact features feed risk)
V5-E05 Provider Capability Registry + Task Routing
    ↓ HARD (V3-E02 telemetry feeds capability/cost data)
V5-E07 Cost/Token Arbitration
V5-E08 Multi-Agent Evaluation Harness
    ↓ HARD (V3-E03 harness + V5-E01)
```

### 2.3 Specialist Review → Verification Intelligence

```
V4-E01 Repository Index
    ↓ HARD
V6-E01 Security Engine (pattern+AST+dependency checks)
    ↓ HARD
V6-E02 AI Security v2 (context provenance tagging, poison defenses)
V4-E01 + V4-E06
    ↓ HARD
V6-E04 Architecture Intelligence (layering/coupling/ADRs)
V4-E04 + V6-E03
    ↓ HARD
V6-E05 Advanced Verification Tiers (T1 coverage floor; T3 observed-test-evidence)
V4-E01
    ↓ HARD
V6-E06 Dependency Intelligence (advisories, license)
V4-E04
    ↓ HARD
V6-E07 Policy Engine v1 (org/team/repo scope evaluation)
V6-E01 + V3-E03
    ↓ HARD
V6-E08 Security Evaluation Corpus
```

### 2.4 Verification Intelligence → Platform

```
V4-E05 Finding Identity v2
    ↓ HARD
V7-E03 Finding Relations (duplicate/caused_by/fixed_by/regression_of)
V4-E04
    ↓ HARD
V7-E04 Issue/Requirement Linkage
V4-E01
    ↓ HARD
V7-E01 Git History Intelligence (blame, hotspots, reverts)
V3-E04
    ↓ HARD
V7-E02 Memory Hierarchy + Authority Model
    ↓ HARD
V7-E07 Memory Security
V7-E01
    ↓ HARD
V7-E06 Historical Evidence in Review
V3-E04 + V7-E01
    ↓ HARD
V7-E05 Team/Repository Analytics (no individual rankings)
V4-E01 + V4-E04
    ↓ HARD
V8-E01 CI Ingestion & Correlation
    ↓ HARD
V8-E02 Test-Failure Correlation
V7-E01
    ↓ HARD
V8-E03 Release Intelligence
V4-E01
    ↓ HARD
V8-E04 Documentation Intelligence
V4-E01
    ↓ HARD
V8-E05 Infrastructure Intelligence
V8-E01
    ↓ HARD
V8-E06 Incident Intelligence (read-only)
V3-E02 + V3-E04
    ↓ HARD
V8-E07 Internal Event Platform v1 (append-only log — no queues)
```

### 2.5 Platform → Organization

```
V8-E07 Event Platform
    ↓ HARD
V9-E04 Event-Driven Workers (only where measured)
V6-E07 Policy Engine v1
    ↓ HARD
V9-E02 Org Policy Engine (inheritance, evaluation caching)
V7-E02 + V7-E07
    ↓ HARD
V9-E05 Org Memory
V4-E07 + V9-E01
    ↓ HARD
V9-E03 Versioned API Platform (/api/v1)
V9-E01 + V9-E03
    ↓ HARD
V9-E01 Multi-Repository/Org Model
    ↓ HARD
V9-E06 Extensibility Contract v1
V3-E02 + V8-E07
    ↓ HARD
V9-E07 Observability Platform
```

### 2.6 Organization → Ecosystem

```
V9-E06 Extensibility Contract
    ↓ HARD
V10-E01 Plugin System (sandboxed, capability manifests)
V9-E03 Versioned API
    ↓ HARD
V10-E04 IDE/CLI Ecosystem
V9-E01 + V9-E02
    ↓ HARD
V10-E05 Org-Scale Analytics
V9-E03 + V9-E07
    ↓ HARD
V10-E06 Engineering Command Center
V5-E05 + V9-E06
    ↓ HARD
V10-E02 Provider Capability Ecosystem
V9-E01 + V9-E03 + V9-E04
    ↓ HARD (V10-E03 strictly optional, ADR-gated)
V10-E03 Hosted Multi-Tenant Foundation
```

---

## 3. Epic-level dependency edges

### 3.1 Phase 0 (V3-E01..E06)

| Epic | Depends on | Type |
|---|---|---|
| V3-E01 | — | — |
| V3-E02 | V3-E03, V3-E04 | soft |
| V3-E03 | V3-E01, V3-E02 | soft |
| V3-E04 | V3-E01 | soft |
| V3-E05 | V3-E01 (hard), V3-E06, V3-E04 | hard + soft |
| V3-E06 | V3-E01..V3-E05 | soft |

### 3.2 V4 (V4-E01..E08)

| Epic | Depends on | Type |
|---|---|---|
| V4-E01 | V3-E01 (hard), V3-E04 (hard), V3-E02 (hard), V3-E03 (hard) | hard |
| V4-E02 | V4-E01 (hard), V3-E02 (soft), V4-E03 (soft) | hard + soft |
| V4-E03 | V4-E01 (hard), V4-E02 (soft) | hard + soft |
| V4-E04 | V4-E01 (soft) | soft |
| V4-E05 | V4-E04 (hard), V3-E03 (soft) | hard + soft |
| V4-E06 | V4-E01 (hard), V4-E02 (hard), V4-E03 (soft) | hard + soft |
| V4-E07 | V4-E01 (hard), V4-E04 (hard), V4-E02 (soft), V4-E06 (soft) | hard + soft |
| V4-E08 | V4-E01 (hard), V4-E02 (hard), V4-E04 (soft) | hard + soft |

### 3.3 V5 (V5-E01..E08)

| Epic | Depends on | Type |
|---|---|---|
| V5-E01 | V4-E04 (hard), V4-E05 (hard), V4-E07 (hard), V3-E02 (hard), V3-E03 (soft), V3-E04 (soft) | hard + soft |
| V5-E02 | V4-E04 (hard), V5-E01 (hard), V4-E02 (soft) | hard + soft |
| V5-E03 | V4-E04 (hard), V4-E05 (hard), V5-E02 (hard), V3-E03 (soft) | hard + soft |
| V5-E04 | V3-E02 (soft), V4-E03 (soft), V5-E07 (soft) | soft |
| V5-E05 | V3-E02 (hard), V5-E01 (soft), V5-E02 (soft) | hard + soft |
| V5-E06 | V5-E03 (hard), V5-E04 (soft), V3-E03 (soft) | hard + soft |
| V5-E07 | V3-E02 (hard), V5-E05 (hard), V5-E01 (soft), V5-E04 (soft) | hard + soft |
| V5-E08 | V3-E03 (hard), V5-E01 (hard) | hard |

### 3.4 V6 (V6-E01..E08)

| Epic | Depends on | Type |
|---|---|---|
| V6-E01 | V4-E04 (hard), V4-E01 (hard), V5-E02 (soft) | hard + soft |
| V6-E02 | V6-E01 (hard), V4-E08 (soft), V5-E01 (soft) | hard + soft |
| V6-E03 | V4-E01 (hard), V6-E05 (soft), V8-E02 (future-soft) | hard + soft + future |
| V6-E04 | V4-E01 (hard), V4-E06 (hard), V4-E03 (soft) | hard + soft |
| V6-E05 | V4-E04 (hard), V6-E03 (hard), V8-E02 (future-soft) | hard + future |
| V6-E06 | V4-E01 (hard), V6-E01 (soft), V8-E05 (future-soft) | hard + soft + future |
| V6-E07 | V4-E04 (hard), V3-E05 (soft), V6-E01 (soft), V6-E03 (soft) | hard + soft |
| V6-E08 | V6-E01 (hard), V3-E03 (hard), V6-E02 (soft) | hard + soft |

### 3.5 V7 (V7-E01..E07)

| Epic | Depends on | Type |
|---|---|---|
| V7-E01 | V4-E01 (hard), V4-E06 (soft) | hard + soft |
| V7-E02 | V3-E04 (hard), V4-E04 (soft), V4-E05 (soft), V7-E01 (soft) | hard + soft |
| V7-E03 | V4-E05 (hard), V7-E01 (soft) | hard + soft |
| V7-E04 | V4-E04 (hard), V7-E01 (soft), V8-E01 (future-soft) | hard + soft + future |
| V7-E05 | V3-E04 (hard), V7-E01 (soft), V3-E02 (soft) | hard + soft |
| V7-E06 | V7-E01 (hard), V7-E02 (hard), V4-E04 (hard), V7-E03 (soft), V5-E06 (soft) | hard + soft |
| V7-E07 | V7-E02 (hard), V6-E02 (soft), V4-E08 (soft) | hard + soft |

### 3.6 V8 (V8-E01..E07)

| Epic | Depends on | Type |
|---|---|---|
| V8-E01 | V3-E02 (hard), V8-E07 (soft), V4-E04 (soft) | hard + soft |
| V8-E02 | V8-E01 (hard), V6-E03 (hard), V6-E05 (soft) | hard + soft |
| V8-E03 | V7-E01 (hard), V8-E01 (soft), V4-E06 (soft) | hard + soft |
| V8-E04 | V4-E01 (hard), V6-E04 (soft), V7-E01 (soft) | hard + soft |
| V8-E05 | V4-E01 (hard), V6-E07 (hard), V6-E01 (soft), V8-E01 (soft) | hard + soft |
| V8-E06 | V8-E01 (hard), V7-E01 (soft), V8-E03 (soft) | hard + soft |
| V8-E07 | V3-E02 (hard), V3-E04 (hard), V8-E01 (soft) | hard + soft |

### 3.7 V9 (V9-E01..E07)

| Epic | Depends on | Type |
|---|---|---|
| V9-E01 | V3-E04 (hard), V8-E07 (hard), V7-E05 (soft) | hard + soft |
| V9-E02 | V6-E07 (hard), V9-E01 (hard), V4-E04 (soft) | hard + soft |
| V9-E03 | V9-E01 (hard), V3-E05 (soft), V9-E07 (soft) | hard + soft |
| V9-E04 | V8-E07 (hard), V9-E01 (soft), V3-E04 (soft) | hard + soft |
| V9-E05 | V7-E02 (hard), V9-E01 (hard), V7-E07 (soft), V9-E02 (soft) | hard + soft |
| V9-E06 | V4-E07 (hard), V5-E05 (hard), V9-E03 (soft), V8-E07 (soft) | hard + soft |
| V9-E07 | V3-E02 (hard), V8-E07 (hard), V9-E03 (soft), V9-E04 (soft) | hard + soft |

### 3.8 V10 (V10-E01..E06)

| Epic | Depends on | Type |
|---|---|---|
| V10-E01 | V9-E06 (hard), V9-E03 (soft), V4-E07 (soft) | hard + soft |
| V10-E02 | V5-E05 (hard), V9-E06 (hard), V5-E02 (soft), V10-E01 (soft) | hard + soft |
| V10-E03 | V9-E01 (hard), V9-E03 (hard), V9-E04 (hard), V9-E07 (soft) | hard + soft |
| V10-E04 | V9-E03 (hard), V4-E07 (hard), V10-E01 (soft) | hard + soft |
| V10-E05 | V7-E05 (hard), V9-E01 (hard), V9-E07 (hard), V8-E03 (soft), V7-E01 (soft) | hard + soft |
| V10-E06 | V9-E03 (hard), V9-E07 (hard), V7-E05 (soft), V8-* (soft), V9-E02 (soft), V10-E05 (soft) | hard + soft |

---

## 4. Critical path

The minimum architecture that unlocks the maximum future scope:

```
FOUNDATION (Phase 0)
  V3-E01 (defect triage) → V3-E02 (telemetry) → V3-E03 (harness) → V3-E04 (storage)
    ↓
CORE INTELLIGENCE (V4)
  V4-E01 (index) → V4-E02 (context v2) → V4-E04 (evidence) → V4-E05 (identity v2)
    ↓
SPECIALIST REVIEW (V5)
  V5-E01 (fan-out) → V5-E02 (contracts) → V5-E03 (merger) → V5-E07 (arbitration)
    ↓
VERIFICATION (V6)
  V6-E01 (security engine) → V6-E05 (verification tiers) → V6-E07 (policy v1)
    ↓
PLATFORM (V7-V9)
  V7-E02 (memory hierarchy) → V8-E07 (events) → V9-E01 (org) → V9-E03 (API) → V9-E07 (observability)
    ↓
ORGANIZATION (V10)
  V10-E01 (plugins) → V10-E06 (command center)
```

### 4.1 Reusable foundations (built once, consumed everywhere)

| Foundation | Stage landed | Consumed by |
|---|---|---|
| Telemetry spine (V3-E02) | Phase 0 | V4-E02 (budgets), V5-E04 (risk), V5-E05 (routing), V5-E07 (arbitration), V8-E07 (events), V9-E07 (observability) |
| Evaluation harness (V3-E03) | Phase 0 | V4-E02 (retrieval quality), V4-E05 (dedup quality), V5-E08 (multi-agent eval), V6-E08 (security corpus) |
| Storage framework (V3-E04) | Phase 0 | V4-E01 (index storage), V7-E02 (memory hierarchy), V8-E07 (event log), V9-E01 (org model) |
| Repository index (V4-E01) | V4 | V4-E02, V4-E03, V4-E06, V4-E07, V6-E01, V6-E03, V6-E04, V6-E06, V7-E01, V8-E04, V8-E05 |
| Context engine v2 (V4-E02) | V4 | V4-E03 (ranking), V5-E01 (planner context), V6-E01 (security context) |
| Evidence engine (V4-E04) | V4 | V4-E05, V5-E01, V5-E03, V6-E01, V6-E05, V6-E07, V7-E04, V8-E01 |
| Finding identity v2 (V4-E05) | V4 | V5-E03 (merger), V7-E03 (relations), all fingerprint consumers |
| Event schema (V8-E07) | V8 | V9-E04 (workers), V9-E07 (observability), V10-E06 (command center) |
| Provider registry (V5-E05) | V5 | V9-E06 (extensibility contract), V10-E02 (provider ecosystem) |
| Policy evaluator (V6-E07) | V6 | V9-E02 (org policy), V8-E03 (release rules), V8-E05 (infra policy) |

---

## 5. Anti-patterns (dependency violations to avoid)

1. **Dashboards before data contracts** — building V10-E06 (command center) before V9-E03 (versioned API) freezes nothing and rework is guaranteed.
2. **Plugins before stable contracts** — V10-E01 before V9-E06 means plugins target moving interfaces.
3. **Microservices before workload boundaries** — V9-E04 (workers) before V9-E07 (observability) evidence is premature; workers without measured bottlenecks are a reliability tax.
4. **Org features before repository boundaries** — V9-E01 (org model) before V4-E01 (index) and V3-E04 (storage) means org scoping has no substrate.
5. **Complex graphs before repository relationships proven useful** — a graph database before V4-E01 (deterministic index) proves the relational model insufficient is premature; ADR-002.
6. **Multi-agent before provenance** — V5-E01 before V4-E04/V4-E05 produces findings that cannot later be attributed; attribution is lost data, not backfillable.
7. **Queues before events** — V9-E04 (workers) before V8-E07 (event platform) means workers have no event log to consume; ADR-008.
8. **Memory writes before authority model** — V7-E02 before V7-E07 (memory security) means mass memory writes without poisoning defenses.

---

## 6. Cross-references

- Ground truth: `CURRENT_ARCHITECTURE.md`
- Vision and planes: `MASTER_VISION.md`
- Target design: `TARGET_ARCHITECTURE.md`
- Stage-by-stage plan: `V4_V10_ROADMAP.md`
- Executive roadmap: `MASTER_ROADMAP.md`
- Epic definitions: `EPIC_BACKLOG.md`
- Data model: `DATA_MODEL.md`
- AI architecture: `AI_AGENT_ARCHITECTURE.md`
- Security: `SECURITY_ROADMAP.md`
- Testing: `TESTING_EVALUATION_PLAN.md`
- Cost: `COST_TOKEN_ARCHITECTURE.md`
- Migration: `MIGRATION_PLAN.md`
- Decisions: `ADR_INDEX.md`
- Refusal list: `DO_NOT_BUILD_YET.md`
- Audit: `FINAL_CONSISTENCY_AUDIT.md`
