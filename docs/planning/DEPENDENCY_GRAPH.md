# Dependency Graph — Capability & Epic Dependencies

> Status: planning document (v1) — created during remediation to resolve BLOCK-01.
> Repository state: commit `2841b23`.
> Canonical stage structure: Phase 0/"V3.x", V4, V4.0, V4.2, V4.4, V4.6, V4.8, V4.10.
> Canonical epic IDs: V3-E01..E06, V4-E01..E08, V4.0-E01..E08, V4.2-E01..E08, V4.4-E01..E07, V4.6-E01..E07, V4.8-E01..E07, V4.10-E01..E06 (57 total).

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
V4.0-E01 Fan-out Orchestration (bounded, per-agent breakers/budgets)
    ↓ HARD
V4.0-E02 Specialist Reviewer Contracts (prompt/task registry, capability declaration)
    ↓ HARD
V4.0-E03 Finding Merger (provenance-aware dedup via occurrence key)
    ↓ HARD
V4.0-E06 Council Synthesis
V4.0-E04 Risk Engine v1 + Adaptive Depth
    ↓ SOFT (V4-E03 impact features feed risk)
V4.0-E05 Provider Capability Registry + Task Routing
    ↓ HARD (V3-E02 telemetry feeds capability/cost data)
V4.0-E07 Cost/Token Arbitration
V4.0-E08 Multi-Agent Evaluation Harness
    ↓ HARD (V3-E03 harness + V4.0-E01)
```

### 2.3 Specialist Review → Verification Intelligence

```
V4-E01 Repository Index
    ↓ HARD
V4.2-E01 Security Engine (pattern+AST+dependency checks)
    ↓ HARD
V4.2-E02 AI Security v2 (context provenance tagging, poison defenses)
V4-E01 + V4-E06
    ↓ HARD
V4.2-E04 Architecture Intelligence (layering/coupling/ADRs)
V4-E04 + V4.2-E03
    ↓ HARD
V4.2-E05 Advanced Verification Tiers (T1 coverage floor; T3 observed-test-evidence)
V4-E01
    ↓ HARD
V4.2-E06 Dependency Intelligence (advisories, license)
V4-E04
    ↓ HARD
V4.2-E07 Policy Engine v1 (org/team/repo scope evaluation)
V4.2-E01 + V3-E03
    ↓ HARD
V4.2-E08 Security Evaluation Corpus
```

### 2.4 Verification Intelligence → Platform

```
V4-E05 Finding Identity v2
    ↓ HARD
V4.4-E03 Finding Relations (duplicate/caused_by/fixed_by/regression_of)
V4-E04
    ↓ HARD
V4.4-E04 Issue/Requirement Linkage
V4-E01
    ↓ HARD
V4.4-E01 Git History Intelligence (blame, hotspots, reverts)
V3-E04
    ↓ HARD
V4.4-E02 Memory Hierarchy + Authority Model
    ↓ HARD
V4.4-E07 Memory Security
V4.4-E01
    ↓ HARD
V4.4-E06 Historical Evidence in Review
V3-E04 + V4.4-E01
    ↓ HARD
V4.4-E05 Team/Repository Analytics (no individual rankings)
V4-E01 + V4-E04
    ↓ HARD
V4.6-E01 CI Ingestion & Correlation
    ↓ HARD
V4.6-E02 Test-Failure Correlation
V4.4-E01
    ↓ HARD
V4.6-E03 Release Intelligence
V4-E01
    ↓ HARD
V4.6-E04 Documentation Intelligence
V4-E01
    ↓ HARD
V4.6-E05 Infrastructure Intelligence
V4.6-E01
    ↓ HARD
V4.6-E06 Incident Intelligence (read-only)
V3-E02 + V3-E04
    ↓ HARD
V4.6-E07 Internal Event Platform v1 (append-only log — no queues)
```

### 2.5 Platform → Organization

```
V4.6-E07 Event Platform
    ↓ HARD
V4.8-E04 Event-Driven Workers (only where measured)
V4.2-E07 Policy Engine v1
    ↓ HARD
V4.8-E02 Org Policy Engine (inheritance, evaluation caching)
V4.4-E02 + V4.4-E07
    ↓ HARD
V4.8-E05 Org Memory
V4-E07 + V4.8-E01
    ↓ HARD
V4.8-E03 Versioned API Platform (/api/v1)
V4.8-E01 + V4.8-E03
    ↓ HARD
V4.8-E01 Multi-Repository/Org Model
    ↓ HARD
V4.8-E06 Extensibility Contract v1
V3-E02 + V4.6-E07
    ↓ HARD
V4.8-E07 Observability Platform
```

### 2.6 Organization → Ecosystem

```
V4.8-E06 Extensibility Contract
    ↓ HARD
V4.10-E01 Plugin System (sandboxed, capability manifests)
V4.8-E03 Versioned API
    ↓ HARD
V4.10-E04 IDE/CLI Ecosystem
V4.8-E01 + V4.8-E02
    ↓ HARD
V4.10-E05 Org-Scale Analytics
V4.8-E03 + V4.8-E07
    ↓ HARD
V4.10-E06 Engineering Command Center
V4.0-E05 + V4.8-E06
    ↓ HARD
V4.10-E02 Provider Capability Ecosystem
V4.8-E01 + V4.8-E03 + V4.8-E04
    ↓ HARD (V4.10-E03 strictly optional, ADR-gated)
V4.10-E03 Hosted Multi-Tenant Foundation
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

### 3.3 V4.0 (V4.0-E01..E08)

| Epic | Depends on | Type |
|---|---|---|
| V4.0-E01 | V4-E04 (hard), V4-E05 (hard), V4-E07 (hard), V3-E02 (hard), V3-E03 (soft), V3-E04 (soft) | hard + soft |
| V4.0-E02 | V4-E04 (hard), V4.0-E01 (hard), V4-E02 (soft) | hard + soft |
| V4.0-E03 | V4-E04 (hard), V4-E05 (hard), V4.0-E02 (hard), V3-E03 (soft) | hard + soft |
| V4.0-E04 | V3-E02 (soft), V4-E03 (soft), V4.0-E07 (soft) | soft |
| V4.0-E05 | V3-E02 (hard), V4.0-E01 (soft), V4.0-E02 (soft) | hard + soft |
| V4.0-E06 | V4.0-E03 (hard), V4.0-E04 (soft), V3-E03 (soft) | hard + soft |
| V4.0-E07 | V3-E02 (hard), V4.0-E05 (hard), V4.0-E01 (soft), V4.0-E04 (soft) | hard + soft |
| V4.0-E08 | V3-E03 (hard), V4.0-E01 (hard) | hard |

### 3.4 V4.2 (V4.2-E01..E08)

| Epic | Depends on | Type |
|---|---|---|
| V4.2-E01 | V4-E04 (hard), V4-E01 (hard), V4.0-E02 (soft) | hard + soft |
| V4.2-E02 | V4.2-E01 (hard), V4-E08 (soft), V4.0-E01 (soft) | hard + soft |
| V4.2-E03 | V4-E01 (hard), V4.2-E05 (soft), V4.6-E02 (future-soft) | hard + soft + future |
| V4.2-E04 | V4-E01 (hard), V4-E06 (hard), V4-E03 (soft) | hard + soft |
| V4.2-E05 | V4-E04 (hard), V4.2-E03 (hard), V4.6-E02 (future-soft) | hard + future |
| V4.2-E06 | V4-E01 (hard), V4.2-E01 (soft), V4.6-E05 (future-soft) | hard + soft + future |
| V4.2-E07 | V4-E04 (hard), V3-E05 (soft), V4.2-E01 (soft), V4.2-E03 (soft) | hard + soft |
| V4.2-E08 | V4.2-E01 (hard), V3-E03 (hard), V4.2-E02 (soft) | hard + soft |

### 3.5 V4.4 (V4.4-E01..E07)

| Epic | Depends on | Type |
|---|---|---|
| V4.4-E01 | V4-E01 (hard), V4-E06 (soft) | hard + soft |
| V4.4-E02 | V3-E04 (hard), V4-E04 (soft), V4-E05 (soft), V4.4-E01 (soft) | hard + soft |
| V4.4-E03 | V4-E05 (hard), V4.4-E01 (soft) | hard + soft |
| V4.4-E04 | V4-E04 (hard), V4.4-E01 (soft), V4.6-E01 (future-soft) | hard + soft + future |
| V4.4-E05 | V3-E04 (hard), V4.4-E01 (soft), V3-E02 (soft) | hard + soft |
| V4.4-E06 | V4.4-E01 (hard), V4.4-E02 (hard), V4-E04 (hard), V4.4-E03 (soft), V4.0-E06 (soft) | hard + soft |
| V4.4-E07 | V4.4-E02 (hard), V4.2-E02 (soft), V4-E08 (soft) | hard + soft |

### 3.6 V4.6 (V4.6-E01..E07)

| Epic | Depends on | Type |
|---|---|---|
| V4.6-E01 | V3-E02 (hard), V4.6-E07 (soft), V4-E04 (soft) | hard + soft |
| V4.6-E02 | V4.6-E01 (hard), V4.2-E03 (hard), V4.2-E05 (soft) | hard + soft |
| V4.6-E03 | V4.4-E01 (hard), V4.6-E01 (soft), V4-E06 (soft) | hard + soft |
| V4.6-E04 | V4-E01 (hard), V4.2-E04 (soft), V4.4-E01 (soft) | hard + soft |
| V4.6-E05 | V4-E01 (hard), V4.2-E07 (hard), V4.2-E01 (soft), V4.6-E01 (soft) | hard + soft |
| V4.6-E06 | V4.6-E01 (hard), V4.4-E01 (soft), V4.6-E03 (soft) | hard + soft |
| V4.6-E07 | V3-E02 (hard), V3-E04 (hard), V4.6-E01 (soft) | hard + soft |

### 3.7 V4.8 (V4.8-E01..E07)

| Epic | Depends on | Type |
|---|---|---|
| V4.8-E01 | V3-E04 (hard), V4.6-E07 (hard), V4.4-E05 (soft) | hard + soft |
| V4.8-E02 | V4.2-E07 (hard), V4.8-E01 (hard), V4-E04 (soft) | hard + soft |
| V4.8-E03 | V4.8-E01 (hard), V3-E05 (soft), V4.8-E07 (soft) | hard + soft |
| V4.8-E04 | V4.6-E07 (hard), V4.8-E01 (soft), V3-E04 (soft) | hard + soft |
| V4.8-E05 | V4.4-E02 (hard), V4.8-E01 (hard), V4.4-E07 (soft), V4.8-E02 (soft) | hard + soft |
| V4.8-E06 | V4-E07 (hard), V4.0-E05 (hard), V4.8-E03 (soft), V4.6-E07 (soft) | hard + soft |
| V4.8-E07 | V3-E02 (hard), V4.6-E07 (hard), V4.8-E03 (soft), V4.8-E04 (soft) | hard + soft |

### 3.8 V4.10 (V4.10-E01..E06)

| Epic | Depends on | Type |
|---|---|---|
| V4.10-E01 | V4.8-E06 (hard), V4.8-E03 (soft), V4-E07 (soft) | hard + soft |
| V4.10-E02 | V4.0-E05 (hard), V4.8-E06 (hard), V4.0-E02 (soft), V4.10-E01 (soft) | hard + soft |
| V4.10-E03 | V4.8-E01 (hard), V4.8-E03 (hard), V4.8-E04 (hard), V4.8-E07 (soft) | hard + soft |
| V4.10-E04 | V4.8-E03 (hard), V4-E07 (hard), V4.10-E01 (soft) | hard + soft |
| V4.10-E05 | V4.4-E05 (hard), V4.8-E01 (hard), V4.8-E07 (hard), V4.6-E03 (soft), V4.4-E01 (soft) | hard + soft |
| V4.10-E06 | V4.8-E03 (hard), V4.8-E07 (hard), V4.4-E05 (soft), V4.6-* (soft), V4.8-E02 (soft), V4.10-E05 (soft) | hard + soft |

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
SPECIALIST REVIEW (V4.0)
  V4.0-E01 (fan-out) → V4.0-E02 (contracts) → V4.0-E03 (merger) → V4.0-E07 (arbitration)
    ↓
VERIFICATION (V4.2)
  V4.2-E01 (security engine) → V4.2-E05 (verification tiers) → V4.2-E07 (policy v1)
    ↓
PLATFORM (V4.4-V4.8)
  V4.4-E02 (memory hierarchy) → V4.6-E07 (events) → V4.8-E01 (org) → V4.8-E03 (API) → V4.8-E07 (observability)
    ↓
ORGANIZATION (V4.10)
  V4.10-E01 (plugins) → V4.10-E06 (command center)
```

### 4.1 Reusable foundations (built once, consumed everywhere)

| Foundation | Stage landed | Consumed by |
|---|---|---|
| Telemetry spine (V3-E02) | Phase 0 | V4-E02 (budgets), V4.0-E04 (risk), V4.0-E05 (routing), V4.0-E07 (arbitration), V4.6-E07 (events), V4.8-E07 (observability) |
| Evaluation harness (V3-E03) | Phase 0 | V4-E02 (retrieval quality), V4-E05 (dedup quality), V4.0-E08 (multi-agent eval), V4.2-E08 (security corpus) |
| Storage framework (V3-E04) | Phase 0 | V4-E01 (index storage), V4.4-E02 (memory hierarchy), V4.6-E07 (event log), V4.8-E01 (org model) |
| Repository index (V4-E01) | V4 | V4-E02, V4-E03, V4-E06, V4-E07, V4.2-E01, V4.2-E03, V4.2-E04, V4.2-E06, V4.4-E01, V4.6-E04, V4.6-E05 |
| Context engine v2 (V4-E02) | V4 | V4-E03 (ranking), V4.0-E01 (planner context), V4.2-E01 (security context) |
| Evidence engine (V4-E04) | V4 | V4-E05, V4.0-E01, V4.0-E03, V4.2-E01, V4.2-E05, V4.2-E07, V4.4-E04, V4.6-E01 |
| Finding identity v2 (V4-E05) | V4 | V4.0-E03 (merger), V4.4-E03 (relations), all fingerprint consumers |
| Event schema (V4.6-E07) | V4.6 | V4.8-E04 (workers), V4.8-E07 (observability), V4.10-E06 (command center) |
| Provider registry (V4.0-E05) | V4.0 | V4.8-E06 (extensibility contract), V4.10-E02 (provider ecosystem) |
| Policy evaluator (V4.2-E07) | V4.2 | V4.8-E02 (org policy), V4.6-E03 (release rules), V4.6-E05 (infra policy) |

---

## 5. Anti-patterns (dependency violations to avoid)

1. **Dashboards before data contracts** — building V4.10-E06 (command center) before V4.8-E03 (versioned API) freezes nothing and rework is guaranteed.
2. **Plugins before stable contracts** — V4.10-E01 before V4.8-E06 means plugins target moving interfaces.
3. **Microservices before workload boundaries** — V4.8-E04 (workers) before V4.8-E07 (observability) evidence is premature; workers without measured bottlenecks are a reliability tax.
4. **Org features before repository boundaries** — V4.8-E01 (org model) before V4-E01 (index) and V3-E04 (storage) means org scoping has no substrate.
5. **Complex graphs before repository relationships proven useful** — a graph database before V4-E01 (deterministic index) proves the relational model insufficient is premature; ADR-002.
6. **Multi-agent before provenance** — V4.0-E01 before V4-E04/V4-E05 produces findings that cannot later be attributed; attribution is lost data, not backfillable.
7. **Queues before events** — V4.8-E04 (workers) before V4.6-E07 (event platform) means workers have no event log to consume; ADR-008.
8. **Memory writes before authority model** — V4.4-E02 before V4.4-E07 (memory security) means mass memory writes without poisoning defenses.

---

## 6. Cross-references

- Ground truth: `CURRENT_ARCHITECTURE.md`
- Vision and planes: `MASTER_VISION.md`
- Target design: `TARGET_ARCHITECTURE.md`
- Stage-by-stage plan: `V4_STAGES_ROADMAP.md`
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
