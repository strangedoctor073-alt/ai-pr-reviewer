# DATA MODEL — Future conceptual model (V3 → V10)

> Status: planning document (v1) — describes repo state at commit `2841b23`
> (`CURRENT_ARCHITECTURE.md`, verified 2026-10-03). Entities marked with stages
> V4+ do not exist yet; future storage homes are **proposals**, not code.
> Companions: `TARGET_ARCHITECTURE.md` (where each contract lives),
> `ARCHITECTURE_EVOLUTION.md` (when each subsystem lands).

---

## 1. Scope and modeling rules

1. **JSON payload inside an existing row is the default home for every new
   entity.** This repo already has a proven pattern: `finding_history.payload`
   is a free TEXT column of `Finding.to_dict()` keyed by
   `(repo, pr_number, fingerprint)` (`ai_pr_reviewer/storage.py`), mirrored as
   `FindingHistoryRow.payload: JSON` and `ReportRow.payload: JSON`
   (`dashboard/models_db.py`). A new entity starts the same way — inside the row
   of its parent — and is promoted to its own table only on **query evidence**.
2. **Normalization triggers (evidence, not aspiration).** Promote a payload to a
   real table only when at least one holds: (a) a shipped query must
   filter/aggregate across parents and today's implementation loads all rows
   into Python (the pattern of `list_findings`/`stats`/`metrics` in
   `dashboard/storage.py` — constraint C9); (b) referential integrity or a
   join is load-bearing for correctness (e.g. relations between findings);
   (c) payload size starts dominating row scans. Everything else stays JSON.
3. **One writer per datum** in every phase (`TARGET_ARCHITECTURE.md` §7.3).
4. **Derived beats stored.** Anything recomputable from repository/Git/GitHub
   state is a projection, stored only as a cache with an explicit refresh path.
5. **Identity is deterministic** — never AI-produced (`MASTER_VISION.md` §3.2).
6. **No individual performance data.** Team analytics aggregate or anonymize;
   individual rankings are not modeled at all (vision §6).

### Home vocabulary

| Home | Meaning |
|---|---|
| **relational (SQLite now)** | lives in engine SQLite (`LocalReviewStorage`) and/or dashboard SQLAlchemy (`DbStorage`); SQLite WAL today |
| **relational (Postgres-later)** | same logical schema promoted via `DATABASE_URL` when scale/Phase B needs it (ADR-011) |
| **object/artifact storage** | content-addressed file/blob (report artifacts, context artifacts, raw CI logs); metadata row in relational |
| **search index** | full-text/faceted index — built only when a shipped query needs it (query evidence, rule 2) |
| **future graph storage — revisit (ADR-002)** | candidate *long-term* home for heavily-interlinked data; relational/JSON now, revisit only when a real traversal query cannot be served |

## 2. Entity catalog

Class key: **real** = independent existence tracked over time · **projection** =
derived cache of an external/source-of-truth fact · **event record** =
append-only fact about something that happened.

| Entity | Class | Home | Arrives | Seed today / notes |
|---|---|---|---|---|
| Organization | real (V9) | relational (SQLite now, Postgres-later) | V9 | today only implied by the `owner/` prefix of `repo` strings (`review_state` PK); becomes a real row when org policy/memory arrive; optional multi-tenant scoping per ADR-010 |
| Team | real (V7) | relational (Postgres-later) | V7 | no team concept exists; seed = grouping of GitHub logins/repos; **no individual rankings** may be derived from it |
| User | real (V7, minimal) | relational (Postgres-later) | V7 | today just `ReportRow.author` (string) and PR author in `PRContext`; store login only where audit/analytics need it; analytics path should prefer hashed/stable pseudonyms |
| Repository | real | relational (SQLite now) | exists (implicit) | today a TEXT column repeated on every table (`repo`); V4 turns it into an indexed row with index metadata; org = prefix until V9 |
| RepositoryComponent | projection | relational + payload JSON; **future graph storage — revisit (ADR-002)** | V4 | units of the deterministic index (packages/dirs/symbols) feeding change-impact; JSON rows under the repository index; never a graph DB on aspiration |
| PullRequest | real | relational (SQLite now) | exists (implicit) | keyed `repo#pr_number` (PK of `review_state` in `ai_pr_reviewer/storage.py`, `ReviewStateRow` in `dashboard/models_db.py`); V4 adds index metadata (intent, scope) as payload |
| Commit | projection | relational + payload JSON | V4 (V7 deepens) | today only `last_reviewed_sha`/`base_sha` strings; index stores a bounded set of relevant commits; full history intelligence is V7, still bounded |
| Review | real | relational (SQLite now) | exists | the *report*: `dashboard/models_db.py: ReportRow` (PK = `{slug}-pr{n}-{yyyymmdd}-{uuid6}` from `reporter.py: new_report_id`), engine-side `review-report.json` |
| ReviewRun | real | relational (SQLite now) + telemetry records | Phase 0 (seed) / V5 | the *execution*: provider, model, duration, usage, fallback, queue/inline mode. Today scattered (`duration_ms`, `engine`, `fallback_used` in report JSON; provider counters unreported — C6). Split from Review because N runs can precede one posted review |
| Finding | real | relational, **payload JSON inside row** (exists) | exists | PK `(repo, pr_number, fingerprint)`; payload = full `Finding.to_dict()`. Stays one table for ALL intelligence types (security/test/architecture are categories, not tables — rule 2) |
| FindingEvidence | real (V4-E04) | payload JSON first → own table when cross-finding evidence queries ship (V5/V6) | V4 | array of content-addressed records inside the finding payload — `{id, kind, locator, retrieved_at, content_hash, summary}` per ADR-004; promotion justified when merge/tier queries filter by evidence type across findings |
| FindingRelation | real (V7-E03) | relational from day one (join-shaped; integrity matters) + **graph revisit (ADR-002)** | V7 | typed edges between finding identities (`caused_by`, `regression_of`, `duplicates`, …); requires identity v2 (V4-E05); small volume, but rule 2(b) applies |
| Verification | event record | payload fields now → append rows when V6 tiers ship history queries | exists (fields) / V6 tiers | today: `verification_status`/`verification_reason`/`verified_at` on the Finding payload (`ai_pr_reviewer/models.py`); deterministic coverage check only (`verification.py`). Tiers (V6) keep the deterministic result as floor; history becomes rows when a query needs "verification over time" |
| MemoryEntry | real | relational (exists) | exists | `repo_memory` (engine, read-only for engine) + `RepoMemoryRow` (dashboard CRUD); V7 (V7-E02) adds `scope` (org▸team▸repo▸component▸PR), `authority` class, `origin` columns — additive, per ADR-003; mute rows (`fingerprint:<fp>` path_pattern) are *decisions*, a subtype, not notes |
| Policy | real (document-authoritative) | file in repo (`.ai-pr-reviewer.yml` @ base revision) + cached row; org copy relational (V9) | exists (repo) / V6 engine / V9 org | the document is the source of truth; rows are projections; privacy baseline in `rules.py` is non-removable in *code*, not data |
| PolicyEvaluation | event record | payload JSON in review payload → relational when V6+ queries ship | V6 | `{policy_ref, subject, decision, reasons, evaluated_at}` per review; explainability record; promotion when dashboards filter decisions across reviews |
| Provider | real (config-declared) | config now → registry row (V5) | exists / V5 registry | today hardcoded wiring sites (`AI_BACKENDS`, `select_backend`); capability registry (V5) makes it queryable data |
| Model | real (V5) | registry row (relational) | V5 | model id, provider, capability/cost/context-window metadata; **no retired model IDs stored as defaults** (release-test invariant) |
| ContextArtifact | real (V4) | object/artifact storage + metadata row | V4 | bounded context pieces with provenance (what text, from which revision, budget cost); replaces bare character budgets (C7); large blobs never ride relational rows |
| TestEvidence | event record | payload JSON → object storage for raw output (V6) | V6 | test names/status/durations/coverage pointers tied to findings; raw logs in artifact storage, summary in payload |
| CIResult | event record (V8-E01) | payload JSON first; relational when correlation queries ship (V8+) | V8 | run id, workflow, status, conclusion, timing, commit; correlation to PRs/findings via keys; raw logs to artifact storage |
| Dependency | projection | relational + payload JSON (snapshot per index refresh) | V6 | derived from manifests/lockfiles; version, ecosystem, advisories; a cache of source-of-truth files, refreshable |
| SecurityFinding | projection (Finding specialization) | **inside the Finding table** (category + provenance) | V6 | never a parallel store: `category='security'` (+ engine/rule provenance) keeps identity, lifecycle, dedup and comment sync working unchanged |
| ArchitectureFinding | projection (Finding specialization) | inside the Finding table | V6 | same rule as SecurityFinding; architecture intelligence emits normal findings with a distinct category/provenance |
| Event | event record | append-only file/outbox (relational) now-formalized → event store (V8) | V8 platform (schema earlier) | envelope `{schema_version, event_id, type, occurred_at, source, repo, subject, payload}` (`TARGET_ARCHITECTURE.md` §7.4); retention-bounded; immutable |
| AuditRecord | event record | append-only file now → relational (Postgres-later) | exists | `dashboard/data/audit.jsonl` (append-only, token-auth actions); grows to memory/policy/org actions (V7 memory security, V9 org audit); never contains secrets/diff content |
| Plugin | real (V9 contract, V10 runtime) | registry row (relational) | V9/V10 | declared capabilities + version + trust class; plugin *output* enters as FindingEvidence-like records — plugins own no core tables |

## 3. What deliberately does NOT become a table (yet)

- **Any V6+ intelligence output as its own store.** Security, architecture,
  test, dependency intelligence all emit `Finding` rows with categories and
  provenance. Separate stores would fork identity/lifecycle/dedup (C4) and
  create storage implementation #4 — the exact disease of `CURRENT_ARCHITECTURE`
  §7 (three duplicated schemas today).
- **Repository index internals.** The V4 index is a rebuildable projection;
  stored where rebuild cost justifies it (relational + payload), not treated as
  authoritative data.
- **Graph storage.** `RepositoryComponent` and `FindingRelation` are *marked*
  for graph revisit (ADR-002) but live relationally until a real traversal
  query proves relational insufficient.
- **Search index.** Built only when shipped queries need full-text/faceted
  retrieval (dashboard finding browser is the first candidate, V9-era); until
  then SQL + payload JSON is the index.
- **Telemetry as core rows.** Usage/latency records stay append-only and
  disposable — they feed aggregation, not entity state (`ARCHITECTURE_EVOLUTION`
  §3 telemetry spine).

## 4. Entity–relationship sketch

Minimal stable core (bold) plus how later entities attach. `(P)` = payload JSON
inside another row; `[n]` = stage of arrival.

```
 Organization [V9] ──────────────┐  (derived from repo "owner/" prefix until V9)
                                 ▼
                       ┌──────────────────────┐
                       │ **Repository**       │ key: owner/name (string today)
                       │  index meta [V4]     │
                       └──────────┬───────────┘
          ┌───────────────────────┼─────────────────────────┐
          ▼                       ▼                         ▼
 ┌─────────────────┐   ┌──────────────────────┐   ┌──────────────────────┐
 │ **PullRequest** │   │ RepositoryComponent  │   │ Dependency [V6] (P)  │
 │ key: repo#pr    │   │ [V4] (P) ──┐         │   │ Commit [V4/V7] (P)   │
 └────────┬────────┘   └────────────┼─────────┘   └──────────────────────┘
          │                         │  both: projection; graph storage
          │                         └── revisit (ADR-002) ──┘
          ▼
 ┌────────────────────────────────────────────┐
 │ **Review / ReviewRun**                     │
 │  report id  slug-prN-YYYYMMDD-uuid6        │
 │  review_id  owner/repo#pr@sha12            │
 │  run: provider, model [V5], usage [Ph0]    │
 └───────┬───────────────────────┬────────────┘
         │                       │
         ▼                       ▼
 ┌──────────────────┐   ┌────────────────────┐    ┌──────────────────────┐
 │ **Finding**      │   │ ContextArtifact    │    │ CIResult [V8] (P)    │
 │ key: repo#pr#fp  │   │ [V4] (artifact +   │    │ TestEvidence [V6] (P)│
 │ payload JSON     │   │  metadata row)     │    │ PolicyEvaluation[V6] │
 └───┬──────┬───────┘   └────────────────────┘    └──────────────────────┘
     │      │
     │      ├─ FindingEvidence [V4] (P → table on query evidence)
     │      ├─ Verification (fields → tiers rows [V6])
     │      ├─ FindingRelation [V7]  ← anchors on identity v2 (V4-E05)
     │      └─ SecurityFinding / ArchitectureFinding [V6]  (same table,
     │           category + provenance — not separate stores)
     │
     ├──────────────► **MemoryEntry** (repo scope today → hierarchy [V7],
     │                authority per ADR-003; mute = decision subtype)
     ▼
 **Policy** (file @ base revision; engine [V6]; org scope [V9])
     └─ PolicyEvaluation [V6]

 Cross-cutting (no FK to core; attach by keys):
   Provider/Model [V5] · Event [V8] · AuditRecord (now) · Plugin [V9/V10]
   Team/User [V7] (group Repository/author — no individual rankings)
```

## 5. Identity and keys

### 5.1 Finding identity — v1 today, v2 with provenance (constraint C4)

- **v1 (today):** `sha256(category|file|normalized_title)[:16]`, line number
  deliberately excluded so churn keeps identity
  (`ai_pr_reviewer/findings.py: fingerprint_finding`). Documented gap: two
  engines wording the same issue differently get different fingerprints —
  cross-engine dedup does not work (C4), and no field says *who* produced a
  finding (C3).
- **v2 (V4-E05, with provenance from V4-E04)** — per `ADR_INDEX.md` **ADR-005**
  (v1 accepted de facto, v2 proposed): identity is *layered, not widened*:
  - the v1 `fingerprint` stays the **primary storage/lifecycle/mute/comment
    key** — its hash inputs are frozen (comment ids, mute rows and lifecycle
    history all reference it; changing inputs is an auto re-decision);
  - an **occurrence key** (fingerprint + normalized anchor context) is added for
    cross-engine dedup/merge decisions *only* — never a storage key;
  - a **provenance block** on every finding: `engine`, `model`/`agent`,
    `origin` (which specialist/rule pack), `first_run`, `evidence_refs`
    (closes C3);
  - relations attach to **(fingerprint, provenance) pairs**, so two engines'
    renderings of one issue link explicitly instead of colliding.
- Migration mechanics: dual-write the new fields from the first v2-capable
  release; merge matches on the occurrence key where both sides carry
  provenance, falls back to v1; no mass rewrite of `finding_history`
  (additive payload fields only). Formula ownership: **ADR-005** (v2 is
  *Proposed — requires human approval*).

### 5.2 Review identity formats (unchanged across all phases)

| Id | Format | Source | Rule |
|---|---|---|---|
| `review_id` | `owner/repo#pr@sha12` | `ReviewKey.as_id()` (`ai_pr_reviewer/models.py`) | stable forever; `sha12` is a *display* truncation — full `head_sha` stays in payload/state rows; parse-safe (`#`/`@` splitting in `storage.py`) |
| report id | `{repo-slug}-pr{n}-{YYYYMMDD}-{uuid6}` | `reporter.py: new_report_id` | append-only artifact key (String(140) PK) |
| review state key | `owner/repo#pr` | PK of `review_state` / `ReviewStateRow` | one row per PR; `base_sha` + `last_reviewed_sha` (defect D1: populate `base_sha`) |
| local runs | `pr_number == 0` → `is_persistable()` guard (`review_state.py`) | | local runs never collide with PR state |
| org scope (V9) | derived `owner/` prefix → real Organization key | | additive migration; existing keys stay valid |

### 5.3 Key strategy

Natural composite keys rule the core (`repo, pr_number[, fingerprint]`) — they
are readable, debuggable in SQLite, and stable across storage engines. Surrogate
ids (uuid) appear only where the natural key is unknowable (report id, event
id). Fingerprints are 16-hex by design (friendliness in GitHub comments/URLs,
negligible collision risk at repo scale — see `findings.py` docstring); v2 may
widen *stored* identity but must keep the 16-hex display form.

## 6. Retention — proposed baseline (NOT current behavior)

**Current state: no retention whatsoever.** `finding_history` grows forever,
dashboard reads load all rows (C9), `audit.jsonl` is append-only forever, no
pruning exists anywhere. The following is a **proposal (marked: proposed
baseline)** — it requires sign-off and, critically, must be validated against
lifecycle behavior before enabling (see hazard below).

| Data | Proposed retention | Rationale |
|---|---|---|
| `finding_history` for PRs closed/merged > 180 days | archive payload to compressed artifact, keep identity row (fingerprint, first/last seen, final state) 400 days, then drop | keeps cross-run identity for a year; bounds row growth |
| `finding_history` for open PRs | never pruned | lifecycle correctness |
| Review reports / `reports` rows | 400 days full payload; aggregates (severity counts, health) retained longer | dashboard/metrics windows ~13 months |
| `review_state` | retained while PR is open + 90 days after close | incremental-diff anchor |
| Repo memory (human-authored) | retained indefinitely (subject to user deletion) | it is the project's knowledge; engine never auto-writes |
| Audit records | 400 days minimum (compliance-shaped), append-only | accountability for token/policy/memory actions |
| Event records (V8+) | 90 days hot (relational), then aggregate or drop | events are facts, not state |
| Context artifacts / raw CI logs / test evidence blobs | 30–90 days (proposed baseline) | large, re-derivable; provenance pointers keep the *record* even after blob expiry |
| Telemetry records (Phase 0) | 90 days raw, aggregates longer | measurement, disposable |

**Hazard (must be resolved before any pruning ships):** `apply_lifecycle()`
(`ai_pr_reviewer/findings.py`) compares against *previous findings*; a pruned
finding that reappears reads as `new` (not `active`) and may re-post a GitHub
comment. Therefore: retention windows must exceed any plausible open-PR
lifetime, pruning must run only on closed-PR data, and a dry-run metric
("findings affected by pruning") must be observed first. Deletion is idempotent
and never cascades into `github_comment_id` history needed by open PRs.

## 7. Storage-homes decision record (summary)

| Decision | Home | Trigger to revisit |
|---|---|---|
| payload-in-row for Finding/evidence/CI/test/policy-eval | relational (SQLite now / Postgres-later) | shipped query needs cross-row filter/aggregate (rule 2a) — first candidates: dashboard finding browser, V5 merge analytics |
| artifacts (reports, context, logs) | object/artifact storage + metadata row | blob count/size exceeds single-node comfort (Phase C) |
| `FindingRelation`, `RepositoryComponent` | relational; **graph revisit (ADR-002)** | a real traversal query (depth/impact walk) cannot be served relationally within latency budget |
| full-text/faceted search | none until built | shipped search UX needs it (V9-era dashboard/API) |
| event store | outbox/append-only → event store (V8, ADR-008) | consumer count/volume makes polling outbox insufficient |
| Postgres promotion | SQLite now; `DATABASE_URL` already supported by `DbStorage` (ADR-011) | triggers B1/B2 in `TARGET_ARCHITECTURE.md` §6 |
| telemetry/aggregates | append-only + aggregation tables | analytics queries load operational rows in Python (C9 pattern) |

---

### Cross-references

Contracts and homes: `TARGET_ARCHITECTURE.md` §7 (data/provider/storage/event
contracts, additive-first JSON, `schema_version`) and §2 (one writer per
datum). Arrival order and foundations: `ARCHITECTURE_EVOLUTION.md` §2–§3.
Ground truth for the existing rows/payloads: `CURRENT_ARCHITECTURE.md` §7
(storage model), §11 (C3/C4/C9 defects constraining identity and retention).

Epics (`EPIC_BACKLOG.md`): **V4-E04** evidence → FindingEvidence; **V4-E05**
identity → §5.1; **V7-E02** memory hierarchy → MemoryEntry; **V7-E03**
relations → FindingRelation; **V8-E01** CI results → CIResult; **V9-E03**
public API → Organization/API scoping. Defect epics V3-E01..E06 gate Phase 0.

Decisions (`ADR_INDEX.md`): **ADR-002** (repository graph as derived
deterministic index — no graph DB, revisit conditions in that ADR) governs
§2/§7 graph flags; **ADR-003** (memory authority model) governs MemoryEntry's
`authority` field and Policy scoping; **ADR-004** (evidence as first-class
records with provenance) governs the FindingEvidence record shape (§2, §5.1);
**ADR-005** (finding identity: v1 accepted, v2 layered) governs §5.1 — identity
v2 remains *Proposed, requires human approval*; **ADR-011** (storage evolution
behind `ReviewStorage`, retention before new entities) governs every promotion
in §3/§7 and the retention proposal in §6; **ADR-014** (local-first telemetry)
shapes telemetry records; **ADR-015** (policy evaluation at engine, base
revision) shapes the Policy/PolicyEvaluation homes.

Retention §6 is a **proposed baseline**, not implemented behavior. Epic IDs
(V4-E04, V4-E05, V7-E02, V7-E03, V8-E01, V9-E03, V3-E01..E06) are taken from
the engagement brief — `EPIC_BACKLOG.md` was not yet in the tree when this
document was written; verify the IDs against it when it lands.
