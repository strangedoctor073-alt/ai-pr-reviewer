# AI & Agent Architecture — Responsible AI Design

> Status: planning document (v1) — created during remediation to resolve BLOCK-01.
> Repository state: commit `2841b23`.
> Canonical stage structure: Phase 0/"V3.x", V4, V5, V6, V7, V8, V9, V10.

---

## 1. Design stance

AI is used for **judgment, summarization, and synthesis** — never for identity, state, or truth-by-authority. Deterministic systems own everything that must be reproducible and auditable. This is the core principle from `MASTER_VISION.md` §3 and it governs every decision below.

---

## 2. Deterministic vs AI classification

### 2.1 Deterministic systems (never AI)

| System | Current location | Why deterministic |
|---|---|---|
| Diff parsing | `diff_parser.py` | Byte-exact, reproducible |
| Fingerprinting / identity | `findings.py` | Identity must be stable across runs |
| Lifecycle transitions | `findings.py` | State machine, not judgment |
| Verification arithmetic | `verification.py` | Coverage math, not judgment |
| Redaction / fencing | `security.py` | Security-critical, must be total |
| Policy evaluation | `rules.py` (today) → `policy/` (V6) | Rules are rules |
| Static rules | `static/` | Regex/AST, not judgment |
| Budget enforcement | `context.py` → `context/` (V4) | Hard caps, not judgment |
| Anchoring | `orchestrator.py` | Line math, not judgment |
| Dedup | `findings.py` | Fingerprint equality, not judgment |

### 2.2 AI-assisted (AI proposes, deterministic disposes)

| System | Stage | AI role | Deterministic role |
|---|---|---|---|
| Finding generation | current | Propose findings from diff | Validate, anchor, threshold, cap |
| Summary generation | current | Write review summary | Truncate, redact, label engine |
| Fix suggestions | current | Suggest fixes | Never apply; verify deterministically |
| Context ranking | V4 | Rank retrieved context | Enforce budgets, redact, fence |
| Impact analysis | V4 | (deterministic graph traversal) | — |
| Risk scoring | V5 | (deterministic feature scoring) | — |
| Test intelligence | V6 | (deterministic mapping) | — |
| Architecture intelligence | V6 | (deterministic rule checks) | — |

### 2.3 AI-generated (AI creates content, human/disposition owns persistence)

| System | Stage | Output | Persistence rule |
|---|---|---|---|
| Review summary | current | Markdown text | Posted as review comment (ephemeral) |
| Finding explanations | current | Text per finding | Stored with finding (pipeline-owned) |
| Council synthesis | V5 | Merged summary | Posted as review comment (ephemeral) |
| Fix plans | V6 | Suggested approach text | Stored with finding (pipeline-owned) |

### 2.4 AI-verified (AI output checked by deterministic evidence)

| System | Stage | Verification |
|---|---|---|
| Fix verification | current (C4) | Deterministic coverage check — AI cannot claim "resolved" |
| Suggestion verification | V6 | Test evidence tiers — AI cannot claim "verified" without deterministic backing |

### 2.5 Human-approved (only humans create persistent truth)

| System | Stage | Rule |
|---|---|---|
| Project memory | current (C7) | Engine has no `add_repo_memory` path; dashboard/CLI only |
| Memory hierarchy | V7 | Authority model: human > curated > evidence > observed > inferred |
| Org memory | V9 | Human approval required |
| Policy | current → V6/V9 | Human-authored YAML; engine evaluates, never writes |
| Mute/dismissal | current | Dashboard feedback (human action) |

---

## 3. Model router evolution

### 3.1 Current architecture (V3)

- `AIProvider` protocol: `analyze(context) → AnalysisOutcome` (structural, `ai/provider.py`).
- Three AI implementations: `ClaudeProvider`, `OpenAIProvider`, `GeminiProvider` — feature-identical by construction (shared `SYSTEM_PROMPT`, batching, fencing, per-batch static fallback).
- `StaticProvider`: deterministic rules engine adapter.
- Routing: `select_backend` heuristic → `provider_order` failover → static last resort.
- Circuit breakers: per-backend, process-global, threshold 2, recovery 60s.
- Retry: `RetryPolicy` (3 attempts, 1s base, 30s cap, 25% jitter).

### 3.2 V5 evolution: capability registry + task routing

```
model_router.py
  ↓
Provider Capability Registry (V5-E05)
  ├── provider metadata: name, models, capabilities, cost tier, latency class
  ├── task types: review, security-review, test-review, arch-review, synthesis
  └── routing: task type + PR risk + cost budget → provider selection
```

**Capability declaration** (new): each provider declares `supports(task_type, context_shape) → bool`. This replaces the current assumption that all providers are feature-identical.

**Task-aware routing** (new): the router selects a provider based on the task (security review → provider with security capability + cost tier), not just failover order.

**Per-task breakers** (new): circuit breakers become per-(provider, task) instead of per-provider, so a security-review failure does not block a general review.

### 3.3 V10 evolution: provider ecosystem

- Local providers (Ollama, vLLM) via the same `AIProvider` protocol.
- Provider plugins via the extensibility contract (V9-E06).
- Capability negotiation: provider advertises capabilities; router matches tasks to capabilities.

---

## 4. Specialist agents (V5)

### 4.1 Architecture

```
Review Orchestrator (V5-E01)
  ├── Planner: selects specialists based on risk + context
  ├── Executor: bounded fan-out (max N specialists, per-agent budget)
  ├── Merger: provenance-aware dedup via occurrence key (V5-E03)
  └── Synthesizer: council summary (V5-E06)
```

### 4.2 Specialist contracts (V5-E02)

Each specialist is a prompt template + task type + capability requirement:

| Specialist | Task type | Trigger | Budget |
|---|---|---|---|
| Correctness reviewer | review | always | base |
| Security reviewer | security-review | risk ≥ medium OR security files changed | base |
| Test reviewer | test-review | test files changed OR missing tests | base |
| Performance reviewer | perf-review | perf-sensitive files changed | base |
| Architecture reviewer | arch-review | arch-sensitive files changed | base |

**Activation rule**: specialists activate only when risk features (V5-E04) or file-type triggers justify them. The planner must degrade gracefully if the index (V4-E01) is absent.

### 4.3 Bounded fan-out

- **Max specialists per run**: 5 (proposed baseline).
- **Per-agent token budget**: 60,000 tokens (proposed baseline).
- **Per-run token cap**: 300,000 tokens (proposed baseline); V5-E07 arbitrates.
- **Concurrency**: in-process, bounded (C5 fix: per-call breaker state or lock).
- **No queues**: fan-out is in-process; queues remain V9-E04.

### 4.4 Finding merger (V5-E03)

- Provenance-aware: each finding carries (fingerprint, provenance) where provenance = (engine, model, agent).
- Dedup: occurrence key (from V4-E05) enables cross-engine matching without changing v1 identity.
- Attribution preserved: merged findings retain per-agent provenance; the report shows which agent found what.

### 4.5 Council synthesis (V5-E06)

- Merged findings → single summary.
- Per-task usage reported (tokens, latency, agent count).
- Degradation: if agents fail, fall back to single-provider review with honest attribution.

---

## 5. Context engine (V4-E02)

### 5.1 Current architecture (V3)

- `context.py`: `build_context` assembles `ReviewContext` with diff, project rules, previous findings, memory notes, repo context, focus areas.
- `repo_context.py`: bounded fetch (8 files, 12k chars, 16 probes) at base revision.
- Budget: `batch_chars` = 80,000 chars (greedy end-trim).
- Fencing: nonce-fenced `<untrusted_diff>`, injection screening, redaction.

### 5.2 V4 evolution: retrieval/ranking/provenance

```
context.py
  ↓
Context Engine v2 (V4-E02)
  ├── Retrieval: index-based (V4-E01) instead of import-heuristic
  ├── Ranking: relevance scoring (impact analysis from V4-E03 feeds ranking)
  ├── Budgets: token-aware (not char-aware); per-source budget table
  └── Provenance: every context artifact carries source + retrieved_at + content_hash
```

**Retrieval strategy** (proposed ADR-017): hybrid — deterministic index lookup for changed files + referenced files + config; ranked retrieval for supplementary context. No vector database at this stage; the index (V4-E01) is a deterministic symbol/file index.

**Budget table** (proposed baseline):

| Source | Budget | Priority |
|---|---|---|
| PR diff (trimmed) | 20,000 tokens | core |
| Repo context (8 files) | 3,000 tokens | supportive |
| Memory notes | 2,000 tokens | supportive |
| Project rules | 1,000 tokens | core |
| Previous findings | 2,000 tokens | supportive |
| Evidence (V4-E04) | 4,000 tokens | supportive |

**Provenance**: every context artifact is a `ContextArtifact` record (see `DATA_MODEL.md`) with `{source, locator, retrieved_at, content_hash}`. Provenance is pipeline-owned; model output cannot set it.

---

## 6. Evidence engine (V4-E04)

### 6.1 Evidence model

Every important finding carries evidence:

```json
{
  "finding_id": "<fingerprint>",
  "evidence": [
    {
      "id": "<evidence_id>",
      "kind": "changed_code|referenced_code|rule|test_output|history|tool_output",
      "locator": "<file:line or URL>",
      "retrieved_at": "<ISO8601>",
      "content_hash": "<sha256>",
      "summary": "<human-readable description>"
    }
  ]
}
```

### 6.2 Evidence levels (V6-E05)

| Tier | Name | What it proves | Who verifies |
|---|---|---|---|
| T0 | No verification | Nothing | — |
| T1 | Diff coverage | Finding is still present in the diff | deterministic (current) |
| T2 | Context verification | Finding is present in referenced code | deterministic |
| T3 | Test evidence | A test covers the behavior | deterministic (test runner output) |
| T4 | Multi-reviewer | Multiple agents agree | deterministic (occurrence key match) |

**Rule**: AI output can never claim T2+ without deterministic evidence. The `_unverify()` revert (current `verification.py`) remains the floor.

---

## 7. Verification trust model (ADR-012)

- **Deterministic evidence only**: verification states (`resolved`, `still_present`, `unable_to_verify`) are computed from diff coverage, never from model output.
- **No false "resolved"**: `_unverify()` reverts premature `resolved → active` when coverage is partial/none.
- **AI cannot claim verification**: model output is parsed via `Finding.from_untrusted_dict` which strips `LIFECYCLE_FIELDS` including `verification_status`.
- **Test evidence (T3)**: requires actual test runner output, not model assertion.

---

## 8. Failure handling

### 8.1 Provider failure

- Retry (3 attempts) → circuit breaker (threshold 2, recovery 60s) → failover to next provider → static fallback.
- Static fallback is honestly labelled "not AI" (`engine="static"`, `fallback_used=True`).
- Degraded runs store findings but withhold `last_reviewed_sha` advance (current behavior, preserved).

### 8.2 Agent failure (V5)

- Per-agent breaker: if a specialist fails, it is skipped; the merger proceeds with remaining agents.
- If all agents fail: fall back to single-provider review with honest attribution.
- No partial posting: agents never post directly; only the merged+validated result is posted.

### 8.3 Context failure

- Repo context fetch failure → warning + continue without repo context (current behavior, preserved).
- Index failure (V4) → degrade to import-heuristic retrieval (current `repo_context.py` behavior).
- Memory failure → warning + continue without memory (current behavior, preserved).

### 8.4 Storage failure

- All storage operations degrade to warnings; the review result is never lost to I/O failure (current behavior, preserved).

---

## 9. Anti-patterns (explicitly refused)

| Anti-pattern | Why harmful | Control |
|---|---|---|
| Giant unified prompt | Context window overflow; quality degradation | Per-specialist prompts; budget enforcement |
| Unnecessary multi-agent calls | Cost multiplication without quality gain | Risk-gated activation; per-run token cap |
| Uncontrolled autonomous actions | Security risk; no human oversight | Agents never post directly; merged+validated only |
| AI-written persistent memory | Poisoning; untrusted truth | Human-approved only (ADR-003) |
| Unsupported certainty | False confidence; bad decisions | Confidence + evidence required; "we don't know" is valid |
| Unbounded repository ingestion | DoS; cost explosion | Budget caps everywhere; V4-E08 |
| Multi-agent loops without budgets | Cost explosion; infinite loops | Bounded fan-out; per-agent budget; per-run cap |
| Self-modifying prompts | Unpredictable behavior; security risk | Prompts are code, not data; versioned with the engine |

---

## 10. Evaluation

### 10.1 Model evaluation (TESTING_EVALUATION_PLAN.md L11)

- Golden corpus (V3-E03) scored against expected findings.
- Precision, recall, false-positive rate measured per provider.
- Run periodically (not on every PR) to control cost.

### 10.2 Multi-agent evaluation (V5-E08)

- A/B comparison: single-provider vs council on the same corpus.
- Quality: precision/recall delta (must be ≥ baseline).
- Cost: token usage delta (must be ≤ 1.2× median, proposed baseline).
- Report in CI; never block individual PRs on AI-quality metrics.

### 10.3 Routing evaluation

- Route → precision/recall correlation (V5-E05 registry data).
- Fail-closed: if routing cannot select a provider, fall back to static.

---

## 11. Cross-references

- Ground truth: `CURRENT_ARCHITECTURE.md`
- Vision and planes: `MASTER_VISION.md`
- Target design: `TARGET_ARCHITECTURE.md`
- Dependencies: `DEPENDENCY_GRAPH.md`
- Data model: `DATA_MODEL.md`
- Security: `SECURITY_ROADMAP.md`
- Testing: `TESTING_EVALUATION_PLAN.md`
- Cost: `COST_TOKEN_ARCHITECTURE.md`
- Migration: `MIGRATION_PLAN.md`
- Decisions: `ADR_INDEX.md` (ADR-006 agent architecture, ADR-007 provider abstraction, ADR-012 verification trust, ADR-014 telemetry)
- Refusal list: `DO_NOT_BUILD_YET.md`
- Audit: `FINAL_CONSISTENCY_AUDIT.md`
