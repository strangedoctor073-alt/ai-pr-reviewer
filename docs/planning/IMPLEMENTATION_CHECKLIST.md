# Implementation Checklist

> Status: living execution checklist — created 2026-10-04 during the V4 campaign
> repository audit. Ground truth: commit `2841b23` + uncommitted working tree
> (V4-E04 provenance work from the previous run). Planning documents in
> `docs/planning/` remain the source of truth for intended architecture; actual
> source code is the source of truth for what is implemented.

## Current Position

- **Current version:** V3 shipped (Action at `2841b23`); Phase 0 ("V3.x"
  validation & hardening) **6/6 epics done** — V3-E01 complete (D1–D7 fixed and
  pinned by `tests/test_defect_regressions.py`); V3-E02 complete 6/6;
  V3-E03 complete 5/5; V3-E04 complete 7/7; V3-E05 complete 5/5;
  **V3-E06 complete 6/6 (this run)**.
- **Last completed epic:** **V3-E06 · documentation & release hygiene** ✅
  (all 6 tickets in one run; everything uncommitted). Before that: V3-E05 ✅
  5/5; V3-E04 ✅ 7/7; V3-E03 ✅ 5/5; V3-E02 ✅ 6/6; V3-E01 ✅ 8/8; V4-E04
  remains 🟡 partial from a prior run (T01 done; T02/T05's hard blocker
  V3-E04-T02 now cleared; T03/T04 partial).
- **Current epic:** none — V3-E06 finished this run; **Phase 0 is
  complete**, STOPPED awaiting authorization for the next phase (the V4
  entry condition "Phase 0 complete" is now satisfied; V4-E01 is the next
  critical-path epic and is not started).
- **Next dependency-ready epic:** **V4-E01** (Phase 0 order finished
  V3-E01 ✅ → V3-E02 ✅ → V3-E03 ✅ → V3-E04 ✅ → V3-E05 ✅ → V3-E06 ✅; see
  `DEPENDENCY_GRAPH.md`; V4-E01's hard deps and the phase gate are all
  satisfied). Not started — V4 work was out of scope for this run.
- **Overall status:** 🟡 **Phase 0 6/6 complete**; V4 still
  out-of-order-partial (V4-E04 🟡 without V4-E01..E03 prerequisites); suite
  **886 passed, 2 skipped** (was 757 at the V3-E04 baseline; +117 V3-E05,
  +12 V3-E06). Offline CI gate: `python -m eval.harness --gate` → OK (8
  cases, precision/recall/guard all 1.000, fp_rate 0.000, labels 12/12);
  `python -m ruff check .` → green (new `lint` gate, V3-E06-T02).

### Epic/ticket selection rationale (runs 1–5)

1. Audit result: V3-E01 ✅ 8/8 (prior run); every other Phase 0 epic and
   V4-E01/E02/E03 untouched; V4-E04 🟡 partial; V4-E05..E08 untouched.
2. `DEPENDENCY_GRAPH.md:291` Phase 0 order: V3-E01 ✅ → **V3-E02** (zero hard
   deps; soft deps V3-E03/V3-E04 incomplete but soft = allowed). Earliest
   incomplete dependency-ready epic = **V3-E02**. ✅
3. Run 1 (5-ticket limit): dependency-valid backlog prefix
   **T01 → T02 → T03 → T04 → T05** (T03/T04 hard-dep T02; T05 hard-dep T04 —
   satisfied in-batch). **T06 left** (hard deps T01+T02).
4. ADR gate check: **ADR-014 (local-first telemetry & cost accounting) exists
   but is "Proposed — requires human approval before implementation"**. No
   planning doc gates V3-E02 on ADR-014 acceptance (unlike V4-E02→ADR-017 etc.),
   and the mission's stop condition is a *missing* ADR — this one is written in
   full. Decision: implement V3-E02 **strictly inside ADR-014's written
   decision** (local-first, content-free records, price table NOT hardcoded,
   no egress) and **flag ADR-014 ratification as a required human decision**
   (see Technical Debt 8). All work is additive + uncommitted → a veto is cheap.
5. V4-E04 stays 🟡 (T02/T05 hard-blocked on unimplemented `V3-E04-T02`) —
   substituting it would skip a hard dependency; not attempted.
6. Run 2 (one-ticket limit): only **V3-E02-T06** was authorized and eligible
   (hard deps T01+T02 ✅; it is the epic's last ticket). Implemented the
   adversarial/no-content invariant with minimal production hardening at the
   storage and report boundaries — V3-E03 explicitly NOT started.
7. Run 3 (one-complete-epic limit): earliest dependency-ready epic =
   **V3-E03** (no hard deps; soft deps E01/E02 ✅; Phase 0 order). ADR gate
   check: ADR-016 (evaluation gate strategy) exists but is **"Proposed —
   requires human approval"** and is NOT a hard gate for this epic (epic hard
   deps: —). Decision: implement strictly inside ADR-016's written decision
   (Tier A deterministic corpus gate blocks CI; AI/trend layers never block)
   and **flag ADR-016 ratification as a required human decision** (Technical
   Debt 12) — same pattern as ADR-014/debt 8. All work additive + uncommitted
   → a veto stays cheap.
8. Run 4 (one-complete-epic limit): earliest dependency-ready epic =
   **V3-E04** (hard deps: —; soft dep E01 ✅; Phase 0 order). ADR gate
   check: **ADR-014 and ADR-016 are now human-approved (2026-10-06)** —
   debts 8/12 closed, `ADR_INDEX.md` statuses updated; T06 wrote **ADR-022**
   (migration-tool trigger) strictly as a *proposal* (adoption deferred, no
   code). Two parity gaps surfaced by T07's suite were real bugs and were
   fixed inline with the epic (local caller-dict mutation; json
   fingerprint-less save) — reported as bugs, not silent scope.
9. Run 5 (one-complete-epic limit): earliest dependency-ready epic =
   **V3-E05** (hard dep V3-E01 ✅; soft dep V3-E04 ✅; Phase 0 order). No ADR
   gates this epic. Planning-vs-code reconciliation done BEFORE writing
   tests: the D13 "8 hard-coded sites" inventory was stale — 6 of the
   documented caps were already named constants; the genuinely literal ones
   (step-summary `top_n=8`, dashboard analyze/settings/note bounds) were
   named this run with quality-ceiling comments, and a grep guard
   (`tests/test_cap_constants.py`) makes the defect unable to creep back.
   D12's duplicate baseline became an identity-enforced single source.
   D10 (risk/verification in report JSON) is named "contract snapshot
   territory" but is NOT in this epic's purpose (D6 follow-through, D12,
   D13 only) and no ticket required it — it stays open; the additive-only
   report guard will accept it whenever a future ticket ships it.
10. Run 6 (one-complete-epic limit): earliest dependency-ready epic =
    **V3-E06** (hard deps: —; soft deps E01–E05 ✅; Phase 0 order closes
    here). Premise reconciliation again, before writing anything: D11's
    "no production caller" holds only for `get_analyzer` /
    `ClaudeAnalyzer` / `MockAnalyzer` — `StaticAnalyzer`,
    `AnalysisOutcome` and `heuristics.analyze_with_rules` ARE production
    (model_router, all three providers, dashboard analyze endpoint), so
    the deprecation warns at the module boundary and on the dead entry
    points without touching live paths (Python's default filters keep
    normal runs quiet). D14: the ruff baseline had exactly one
    pre-existing F821 (annotation-only `RetryPolicy`) — fixed with a
    `TYPE_CHECKING` import (zero runtime change) — then the gate was
    mutation-verified (injected undefined name → red → restored → green).
    The fixture "regeneration gotcha" was settled empirically, not from
    the stale claim: the suite rewrites nothing (`conftest.py` builds
    into a pytest temp dir), while `python demo/make_fixtures.py`
    rewrites all three samples with CRLF on Windows — observed, restored
    to a clean tree, and documented in CONTRIBUTING. AGENTS.md (protected
    by mission rule — must not be modified) still states the OLD gotcha
    and an imprecise CI-version line: flagged for a human, not edited.

## Epic Status

Statuses: ⬜ Not started · 🟡 Partially implemented · 🔴 Blocked (hard
dependency incomplete) · 🔵 In progress · ✅ Complete.

### Phase 0 — "V3.x" (tracked here because V4 hard-gates on it)

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V3-E01 | correctness defect triage | ✅ Complete | 8/8 tickets | — | D1–D7 fixed + pinned in `test_defect_regressions.py` (suite 506 at completion) |
| V3-E02 | telemetry foundation | ✅ Complete | **6/6 tickets** | — (soft: E03, E04) | Batch 1 (T01–T05) + this run (T06 adversarial/no-content invariant; boundaries hardened in `telemetry.py`, 2 storage save paths, `ReviewResult.to_dict`). ADR-014 ratification pending (debt 8); cost series deferred (debt 9); provider warning echo (debt 11). Suite 557 |
| V3-E03 | evaluation harness foundation | ✅ Complete | **5/5 tickets** | — (soft: E01 ✅, E02 ✅) | `eval/` harness (loader→runner→match→score→gate/report), 8-case corpus (GOLDEN/FPCLEAN/INJ + D2–D6), `eval/baseline.json`, additive CI job `evaluation` (`python -m eval.harness --gate`), `--json` report, CONTRIBUTING guide. ADR-016 ratification pending (debt 12); thresholds proposed/uncalibrated (debt 14). Suite 661 |
| V3-E04 | storage & dashboard debt remediation | ✅ Complete | **7/7 tickets** | — (soft: E01 ✅) | T01 connection lifecycle (closes debt 13) · T03 shared `storage_schema.py` · T04 capability flags (no getattr probes) · T02 retention policy + `retention_days` config (**closes debt 10**; unblocks V4-E04-T02) · T05 SQL aggregation/perf/index/backfill · T06 ADR-022 (proposal) · T07 parity suite incl. HTTP path. ADR-014/016 ratified (closes debts 8/12). Suite 757 |
| V3-E05 | config & contract hardening | ✅ Complete | **5/5 tickets** | V3-E01 (✅) | T01 single-sourced sensitive baseline (closes D12, identity-enforced) · T02 named cap constants + value freeze + grep guard (closes D13) · T03 Action contract snapshot (inputs/outputs, example-workflow invariants, exit codes 0/1/2; mutation-checked) · T04 additive-only report JSON guard + machine-checkable half documented in `MIGRATION_PLAN.md` §1 (mutation-checked) · T05 89-row layering precedence matrix + dashboard/policy merge pins + forward-compat warnings (mutation-checked ×2). Suite 874 |
| V3-E06 | documentation & release hygiene | ✅ Complete | **6/6 tickets** | — (soft: E01–E05 ✅) | T01 facade deprecation warnings + docstring truth (closes D11) · T02 pinned ruff `lint` CI job, mutation-verified (closes D14 first half) · T03 Python support policy stated once — README §5 / ci.yml / CONTRIBUTING (closes D14 second half) · T04 README contract pass + `tests/test_readme_contract.py` (6) · T05 fixture hygiene audit, results recorded, regeneration gotcha → CONTRIBUTING · T06 CHANGELOG `Unreleased` + pinning guidance + release checklist gating on E05-T03/T04. Suite 886 |

### V4 — Deep repository intelligence

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V4-E01 | repository index | ⬜ Not started | 0/6 tickets | V3-E01 (✅), V3-E02 (✅), V3-E03 (✅), V3-E04 (✅), V3-E05 (✅), V3-E06 (✅) | Critical-path start of V4; Phase 0 hard prereqs: **6 of 6 done** — Phase 0 complete, so the V4 entry condition is satisfied and V4-E01 is dependency-ready. NOT started (V4 out of scope for this run) |
| V4-E02 | context engine v2 | 🔴 Blocked | 0/5 tickets | V4-E01 | Needs ADR-017 before implementation |
| V4-E03 | change impact analysis | 🔴 Blocked | 0/4 tickets | V4-E01 | |
| V4-E04 | evidence engine & provenance | 🟡 Partially implemented | 1/5 tickets complete | — (T02 blocker cleared — V3-E04-T02 shipped) | See Ticket Checklist below |
| V4-E05 | finding identity v2 | 🔴 Blocked | 0/6 tickets | V4-E04 | Ticket list conflicts with ADR-005 — see Technical Debt |
| V4-E06 | digital twin seed | 🔴 Blocked | 0/4 tickets | V4-E01, V4-E02 | |
| V4-E07 | intelligence read contracts | 🔴 Blocked | 0/4 tickets | V4-E01, V4-E04 | |
| V4-E08 | intelligence security & budgets | 🔴 Blocked | 0/5 tickets | V4-E01, V4-E02 | Continuous from V4-E01 per roadmap |

### V5 — Multi-agent engineering review

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V5-E01 | fan-out orchestration | 🔴 Blocked | 0 | V4-E04, V4-E05, V4-E07, V3-E02 | |
| V5-E02 | specialist reviewer contracts | 🔴 Blocked | 0 | V4-E04, V5-E01 | |
| V5-E03 | finding merger | 🔴 Blocked | 0 | V4-E04, V4-E05, V5-E02 | |
| V5-E04 | risk engine v1 + adaptive depth | 🔴 Blocked | 0 | — (all soft) | Stage order still requires V4 first; needs ADR-018 |
| V5-E05 | provider capability registry + routing | 🔴 Blocked | 0 | V3-E02 | |
| V5-E06 | council synthesis | 🔴 Blocked | 0 | V5-E03 | |
| V5-E07 | cost/token arbitration | 🔴 Blocked | 0 | V3-E02, V5-E05 | |
| V5-E08 | multi-agent evaluation harness | 🔴 Blocked | 0 | V3-E03, V5-E01 | |

### V6 — Security, testing & architecture intelligence

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V6-E01 | security engine | 🔴 Blocked | 0 | V4-E04, V4-E01 | |
| V6-E02 | AI security v2 | 🔴 Blocked | 0 | V6-E01 | |
| V6-E03 | dependency graph analysis | 🔴 Blocked | 0 | V4-E01 | |
| V6-E04 | architecture intelligence | 🔴 Blocked | 0 | V4-E01, V4-E06 | |
| V6-E05 | advanced verification tiers | 🔴 Blocked | 0 | V4-E04, V6-E03 | |
| V6-E06 | dependency intelligence | 🔴 Blocked | 0 | V4-E01 | |
| V6-E07 | policy engine v1 | 🔴 Blocked | 0 | V4-E04 | |
| V6-E08 | security evaluation corpus | 🔴 Blocked | 0 | V6-E01, V3-E03 | |

### V7 — Historical / project / team intelligence

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V7-E01 | git history intelligence | 🔴 Blocked | 0 | V4-E01 | |
| V7-E02 | memory hierarchy + authority model | 🔴 Blocked | 0 | V3-E04 (✅) | Hard dep done; stage order still requires V4–V6 first |
| V7-E03 | finding relations | 🔴 Blocked | 0 | V4-E05 | Needs ADR-019 |
| V7-E04 | issue/requirement linkage | 🔴 Blocked | 0 | V4-E04 | |
| V7-E05 | team/repository analytics | 🔴 Blocked | 0 | V3-E04 (✅) | Hard dep done; stage order still requires V4–V6 first |
| V7-E06 | historical evidence in review | 🔴 Blocked | 0 | V7-E01, V7-E02, V4-E04 | |
| V7-E07 | memory security | 🔴 Blocked | 0 | V7-E02 | |

### V8 — CI / release / incident intelligence

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V8-E01 | CI ingestion & correlation | 🔴 Blocked | 0 | V3-E02 | |
| V8-E02 | test-failure correlation | 🔴 Blocked | 0 | V8-E01, V6-E03 | Needs ADR-020 |
| V8-E03 | release intelligence | 🔴 Blocked | 0 | V7-E01 | |
| V8-E04 | documentation intelligence | 🔴 Blocked | 0 | V4-E01 | |
| V8-E05 | infrastructure intelligence | 🔴 Blocked | 0 | V4-E01, V6-E07 | |
| V8-E06 | incident intelligence | 🔴 Blocked | 0 | V8-E01 | |
| V8-E07 | internal event platform v1 | 🔴 Blocked | 0 | V3-E02 (✅), V3-E04 (✅) | Hard deps done; stage order still requires V4–V7 first |

### V9 — Organization platform

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V9-E01 | multi-repository/org model | 🔴 Blocked | 0 | V3-E04 (✅), V8-E07 | |
| V9-E02 | org policy engine | 🔴 Blocked | 0 | V6-E07, V9-E01 | |
| V9-E03 | versioned API platform (/api/v1) | 🔴 Blocked | 0 | V9-E01 | Needs ADR-021 |
| V9-E04 | event-driven workers | 🔴 Blocked | 0 | V8-E07 | |
| V9-E05 | org memory | 🔴 Blocked | 0 | V7-E02, V9-E01 | |
| V9-E06 | extensibility contract v1 | 🔴 Blocked | 0 | V4-E07, V5-E05 | |
| V9-E07 | observability platform | 🔴 Blocked | 0 | V3-E02, V8-E07 | |

### V10 — Ecosystem / platform

| Epic | Name | Status | Completion | Dependencies (hard) | Notes |
|------|------|--------|------------|---------------------|-------|
| V10-E01 | plugin system (sandboxed) | 🔴 Blocked | 0 | V9-E06 | |
| V10-E02 | provider capability ecosystem | 🔴 Blocked | 0 | V5-E05, V9-E06 | |
| V10-E03 | hosted multi-tenant foundation | 🔴 Blocked | 0 | V9-E01, V9-E03, V9-E04 | Optional, ADR-gated |
| V10-E04 | IDE/CLI ecosystem | 🔴 Blocked | 0 | V9-E03, V4-E07 | |
| V10-E05 | org-scale analytics | 🔴 Blocked | 0 | V7-E05, V9-E01, V9-E07 | |
| V10-E06 | engineering command center | 🔴 Blocked | 0 | V9-E03, V9-E07 | |

## Ticket Checklist

### V3-E01 · correctness defect triage — ✅ COMPLETE (8/8 tickets, this run)

Ticket order executed: T05 → T01 → T06 → T07 → T04 → T02 → T03 → T08
(T05 first — the sort underpins T04/T02; T08 pins all).

- [x] **V3-E01-T05** · Severity-sort findings before any cap applies (D5) — ✅
  - Files: `ai_pr_reviewer/orchestrator.py` (`severity_sort_key`, `validate_findings` sorts `valid` + `below` before cap; `run()` sorts `lifecycle_findings` after dismissals)
  - Tests: `test_pipeline.py::test_inline_cap_follows_severity_not_provider_order` (adversarial order → critical/high in cap; reversed input → identical output); static tests unchanged
  - Notes: key `(-sev_rank, file or "", line or 0)`; consumers: report JSON, summary top-N, `cli._post_and_sync` cap slice

- [x] **V3-E01-T01** · Populate `base_sha` in `GitHubClient` (D1) — ✅
  - Files: `ai_pr_reviewer/github_client.py` (`get_pr` from `pr["base"]["sha"]`, `get_event_context` from event `base.sha`)
  - Tests: `test_github_incremental.py` — 3 new tests incl. end-to-end "context built through real `get_pr` fetches at `BASE_SHA`, never head"
  - Notes: base-revision trust invariant untouched; local-mode fallback in `repo_context.py` kept

- [x] **V3-E01-T06** · Safe numeric config parsing with exit 1 (D6) — ✅
  - Files: `ai_pr_reviewer/config.py` — `_strict_int` (raises `ConfigError(SystemExit)` → exit 1, message names field + bad value, no secret echo) wired at the 3 bare `int()` sites (`pr_number`, `max_comments`, `batch_chars`)
  - Tests: `test_config.py` — 3 parametrized field tests + subprocess end-to-end (exit 1, `max_comments`/`abc` in stderr, no `Traceback`) + valid-parse parity
  - Notes: `_int_field` silent-fallback for `repo_context_chars` preserved (pre-existing non-defect — see Technical Debt 7)

- [x] **V3-E01-T07** · Dashboard mute idempotency (D7) — ✅
  - Files: `dashboard/storage.py` — `DbStorage.record_feedback` looks up `repo + path_pattern="fingerprint:<fp>"` (old: never-matching `session.get(RepoMemoryRow, repo)` PK) and upserts; `JsonStorage.record_feedback` inline upsert (old: append via `add_repo_memory`)
  - Tests: `test_dashboard_storage.py` — 5 mutes → exactly 1 row (both backends), note updates, mute not a path note, distinct fingerprint → own row
  - Notes: `add_repo_memory` stays append-only for human notes; write-protection routes (`app.py:_is_mute_memory_row`) unchanged; no schema change

- [x] **V3-E01-T04** · Separate report cap from inline-comment cap (D4) — ✅
  - Files: `ai_pr_reviewer/orchestrator.py` (pipeline uses uncapped `reported` for report/health/lifecycle), `ai_pr_reviewer/cli.py` (`to_post[:cfg.max_comments]` — cap lives where comments are posted)
  - Tests: `test_orchestrator.py` — `test_report_and_health_ignore_the_inline_comment_cap` (30 findings/cap 5 → 30 reported, suppressed 25, health == cap-30 run) and end-to-end `cli.run` test (5 inline comments, report + `findings_count=10` carry all 10)
  - Notes: `action.yml` documented behavior ("extra findings go in the summary") now true

- [x] **V3-E01-T02** · Verification must receive the uncapped finding list (D2) — ✅
  - Files: `ai_pr_reviewer/orchestrator.py` (both `_apply_lifecycle` and `verify_findings` get `reported`)
  - Tests: `test_orchestrator.py::test_verification_receives_the_uncapped_finding_list` — spy on `verify_findings` proves uncapped `current`; still-present finding at rank 21 stays `active` + `VERIFICATION_PRESENT`
  - Notes: `_unverify()` / `verification.py` untouched

- [x] **V3-E01-T03** · Record below-threshold findings instead of dropping them (D3) — ✅
  - Files: `ai_pr_reviewer/orchestrator.py` (5th return category `below_threshold`, sorted), `ai_pr_reviewer/models.py` (`ReviewResult.below_threshold` field + `to_dict` key), `ai_pr_reviewer/reporter.py` (`below_threshold_count` in `finalize_report`; summary notes split: cap-overflow vs below-threshold)
  - Tests: `test_orchestrator.py::test_below_threshold_findings_stay_visible_in_the_report` — report JSON carries `below_threshold` + count; `open_findings`/`findings_count` still threshold-based; summary says "below the severity threshold"
  - Notes: additive field only; `findings_count` semantics (≥ threshold) unchanged per acceptance

- [x] **V3-E01-T08** · Defect regression matrix for D1–D7 — ✅
  - Files: new `tests/test_defect_regressions.py` — 7 tests, `D#` in every docstring, fully offline (MockTransport / Wired fakes / tmp_path SQLite+JSON)
  - Tests: all 7 pass under `PYTHONUTF8=1 python -m pytest tests/ -q` → **506 passed, 1 warning** (pre-existing Starlette deprecation)
  - Notes: D1/D6 self-contained; D2–D4 reuse `test_orchestrator.Wired` harness; D7 covers both storage backends in one test

### V3-E02 · telemetry foundation — ✅ COMPLETE (6/6 tickets)

Batch 1 (5-ticket limit): **T01 → T02 → T03 → T04 → T05** (dependency-valid
backlog prefix). Run 2 (one-ticket limit): **T06** — epic finished. ADR-014
implementation guardrails applied throughout: content-free records,
`to_telemetry_row` chokepoint, no hardcoded prices, no telemetry egress;
T06 extended the same sanitizer to every storage/report boundary without
touching `security.py`.

- [x] **V3-E02-T01** · Token/usage capture on provider calls — ✅
  - Files: new `ai_pr_reviewer/telemetry.py` (`UsageRecord` with typed
    `ok`/`unavailable`/`n/a` states, `for_call`, `summarize_calls`);
    `ai/claude.py`, `ai/openai.py`, `ai/gemini.py` (per-call `usage_records`
    + `duration_ms` timing + `usage_summary()`; **Gemini `usageMetadata`
    parsing added** — replaced the dead TODO, legacy totals now populate);
    `model_router.StaticProvider.usage_summary()` → `n/a`
  - Tests: `tests/test_telemetry.py` (6 T01 tests) — all three providers
    populated from mocked responses; missing usage → `unavailable` with
    `None` fields (**never fake 0**); static/mock → `n/a`; record dict is a
    fixed content-free allowlist
  - Notes: legacy `total_input_tokens` ints kept as-is for back-compat; typed
    record is the source of truth

- [x] **V3-E02-T02** · Telemetry record on `AnalysisOutcome` and report JSON — ✅
  - Files: `telemetry.py` (`RunTelemetry`, **`to_telemetry_row` chokepoint**:
    allowlist `_RUN_FIELDS/_CALL_FIELDS/_EVENT_FIELDS` + recursive
    `redact_secrets`, bounded calls/events); `models.py`
    (`AnalysisOutcome.telemetry` + `ReviewResult.telemetry` fields — both
    append-only, `to_dict` key added); providers/`StaticAnalyzer` set
    `outcome.telemetry`; `orchestrator.run()` serializes once via the
    chokepoint (None → report `null`, never invented numbers)
  - Tests: `test_telemetry.py` (7 T02 tests) — mock/static report carries
    typed block with `usage.state="n/a"`; live provider row carries tokens +
    per-batch `duration_ms`; planted keys (`prompt`/`file`/`secret`) dropped
    structurally; secret-shaped strings (`sk-proj-…`, `ghp_…`) redacted;
    positional `AnalysisOutcome` compat preserved
  - Notes: `test_review_state.py::test_analysis_outcome_defaults_and_field_order`
    extended with `telemetry` as the newest append (contract guard intact)

- [x] **V3-E02-T03** · Retry/failover/circuit events as telemetry — ✅
  - Files: `retry.py` (`events` field + `_record_event` — attempt, delay_ms,
    status, exception **type name only**, `ts`); providers `telemetry_events`
    property (harvest source); `model_router.run_analysis` accumulates
    `provider_error` / `failover` / `circuit` (state transition detection) /
    `static_fallback` events + `_attach_events` merges them ahead of the
    winning provider's own events (no duplicates)
  - Tests: `test_telemetry.py` (6 T03 tests) — structured retry events;
    exhausted retries carry type name not message (secret-echo guard);
    forced-failover produces exact `[provider_error, failover]` sequence;
    second failing run yields `circuit closed→open`; provider retry events
    reach the outcome; events pass the redaction chokepoint; clean run
    leaves outcomes untouched (logging/warnings unchanged)
  - Notes: `RetryPolicy.events` is in-memory only — no behavior/logging change

- [x] **V3-E02-T04** · Persist telemetry (additive storage) — ✅
  - Files: `ai_pr_reviewer/storage.py` (`telemetry` table via `CREATE TABLE
    IF NOT EXISTS` + `save_telemetry`/`get_telemetry` upsert-by-review-id);
    `dashboard/models_db.py` (`TelemetryRow`, scalar columns for aggregation
    + `payload` JSON); `dashboard/storage.py` (`DbStorage`/`JsonStorage`
    save/get — JsonStorage uses `telemetry.json`); `orchestrator._persist`
    **getattr-guarded, drop-safe** call (failure → warning only)
  - Tests: `test_storage_client.py` (4) — round-trip/upsert, missing→None,
    **old-DB migration leaves finding_history/review_state rows intact**,
    **unavailable tokens store SQL NULL not 0**; `test_dashboard_storage.py`
    (2 round-trip/None) and `test_orchestrator.py` (4: result copy through
    chokepoint, save called with `acme/api#7@new222`, storage without the
    capability skipped silently, failing save warns but findings+SHA proceed)
  - Notes: `DashboardStorageClient` has no `save_telemetry` → skipped by the
    guard (dashboard still receives telemetry inside report JSON payload) —
    acceptable, recorded (now explicit: capability absent, new debt 15);
    retention shipped in V3-E04-T02 (this run — debt 10 closed)

- [x] **V3-E02-T05** · Surface telemetry in dashboard metrics — ✅
  - Files: `dashboard/storage.py` (module-level `_telemetry_summary` —
    shared aggregation: runs/tokens/usage_states/avg_call_ms/by_repo;
    `DbStorage.metrics` reads scalar columns only, `JsonStorage.metrics`
    reads `telemetry.json`); `dashboard/static/app.js` (`renderMetrics`
    gains a guarded "Token usage & provider latency" block + per-repo bars,
    renders zero-series for pre-telemetry data)
  - Tests: `test_dashboard_storage.py` (4) — seeded series exact sums on
    both backends with `set(metrics) == legacy keys | {telemetry}`
    (**additive contract**), no-telemetry → zero series with every old field
    intact, `/api/metrics` endpoint serves the series under existing auth
  - Notes: **cost series deliberately deferred** — ADR-014 wants a price
    table *in config* (not hardcoded); see Technical Debt 9. Rate limits and
    route auth untouched (endpoint code unchanged)

- [x] **V3-E02-T06** · Telemetry redaction + no-content invariant — ✅ complete
  (this run, single-ticket batch; hard deps T01+T02 ✅)
  - Files: `ai_pr_reviewer/telemetry.py` (shared sanitizer: `_EVENT_TYPES` /
    `_INT_EVENT_FIELDS` value+int allowlists, `_bounded_str`, `_redact` now
    also neutralizes fences via `security.OPEN_TAG_RE`, `_sanitize_usage` /
    `_sanitize_event` / `_sanitize_row`, new public `sanitize_telemetry`),
    `ai_pr_reviewer/storage.py` (Local `save_telemetry` sanitizes at the
    boundary; non-dict → not persisted), `dashboard/storage.py` (DbStorage +
    JsonStorage same — JsonStorage metadata keys no longer overwritable),
    `ai_pr_reviewer/models.py` (`ReviewResult.to_dict` re-applies the
    sanitizer; `None` stays `None`); **`security.py` untouched** (reused, no
    second redaction implementation)
  - Tests: new `tests/test_telemetry_nocontent.py` (16) — enumerated-field
    contract, planted keys/fences/secrets (sk-, ghp_, AKIA, Bearer) never
    survive chokepoint/storage/report, invalid usage state can't claim
    tokens, unknown event type dropped whole, non-dict rejected, idempotent,
    exception messages type-name-only across claude + router failover, all
    3 provider response/prompt paths clean, SQLite/DB/JSON round-trips +
    raw payload/file-text scans, report block sanitized, end-to-end chain
  - Notes: provider per-batch warnings still echo `{exc}` (pre-existing,
    not telemetry) → Technical Debt 11. **V3-E02 now 6/6 ✅**

### V3-E03 · evaluation harness foundation — ✅ COMPLETE (5/5 tickets)

Run 3 (one-complete-epic limit; soft deps E01/E02 ✅, no hard deps;
ADR-016 followed as written — see rationale item 7). Everything
test-side/harness-side: **no production code was modified for this
epic** (the pipeline is exercised through the real local-file path,
not a re-implementation).

- [x] **V3-E03-T01** · Harness skeleton + golden corpus loader — ✅
  complete
  - Files: new `eval/` package — `eval/__init__.py`,
    `eval/harness/{__init__,loader,runner,__main__}.py`; corpus:
    `eval/corpus/{regression/GOLDEN-SEC-001, false-positive/FPCLEAN-001,
    injection/INJ-001}/` (`case.yaml` + `pr.diff`)
  - Verified: `python -m eval.harness` runs all cases offline
    (`engine=static`, zero API keys, `Config` built field-by-field so
    host `INPUT_*`/key env cannot flip the engine); strict schema fails
    loudly (20 malformed-manifest cases, traversal/absolute paths,
    unknown layer dirs, duplicate ids, empty corpus → `CorpusError`,
    CLI exit 2); labels probe-verified against real engine output
    (exact lines 7/9, categories, titles)
  - Tests: `tests/test_evaluation_harness.py` — loader schema/ordering,
    runner offline/isolation/redaction, CLI per-case output (42)
- [x] **V3-E03-T02** · Scoring metrics — ✅ complete
  - Files: new `eval/harness/match.py` (one-to-one greedy match: file +
    line±tolerance + category + severity floor + title regex; trap
    predicate reused for violations), `eval/harness/score.py`
    (precision / recall / false-positive-rate / recall_critical_high,
    micro-averaged, null-on-zero-denominator, xfail/errored/skipped
    excluded from ratios), doc entry `TESTING_EVALUATION_PLAN.md` §5.5
    ("as implemented" — normative metric definitions)
  - Verified: two consecutive runs → byte-identical scorecard
    (`dumps_scorecard` + full CLI stdout); deliberately broken golden
    fixture → recall & guard drop proven by test; exact-math unit tests
    (tolerance, one-to-one, bucket semantics, micro vs mean)
  - Tests: +23 (matching, metric math, determinism, broken fixture,
    doc-presence)
- [x] **V3-E03-T03** · Baseline capture + regression gate — ✅ complete
  - Files: new `eval/harness/gate.py` (`corpus_hash` sha256 over
    path+bytes, slash-normalized; `build_baseline`; `check_gate` on
    schema version, corpus drift, per-metric allowed-drop, violations/
    errors/failed), new `eval/baseline.json` (measured, versioned,
    no timestamps — regeneration byte-identical), CLI `--gate` /
    `--update-baseline` (refuses broken states), `.github/workflows/
    ci.yml` **additive** `evaluation` job (existing `test` /
    `action-image` jobs byte-untouched — asserted by test)
  - Verified: gate passes against committed baseline; baseline
    regenerates byte-identically; **lowering expected-label coverage
    fails the gate even when every metric is identical** (corpus-hash
    drift test); thresholds documented in-file (proposed, strict 0.0
    allowed drop; fp_rate inverted — a rise fails)
  - Tests: +19 (gate logic, baseline currency, CLI plumbing,
    coverage-gaming, CI wiring)
- [x] **V3-E03-T04** · Defect corpus D1–D7 — ✅ complete
  - Files: new corpus cases
    `eval/corpus/regression/DEFECT-D2-01..D6-01` (D2 seeded previous
    via `LocalReviewStorage` + beyond-cap `state: active`; D3
    below-threshold bucket label; D4 4 findings under `max_comments: 2`;
    D5 severity-vs-file `report_order`; D6 `config_error: true`)
  - Verified: all pass against fixed production code; **re-introduction
    spot-checks** monkeypatch each defect back into production
    (`_apply_lifecycle`+`verify_findings` capped, `validate_findings`
    dropping below / capping report, `severity_sort_key` without
    severity, raw `ValueError` config) and assert the matching case
    fails with the precise diagnostic; runtime < 60s budget test
  - D1/D7 excluded with rationale: transport/storage defects that never
    change what a review finds on a diff — cross-referenced by test to
    their unit pins in `tests/test_defect_regressions.py`
  - Incidental fix (harness-only): runner now calls `gc.collect()` after
    runs — discovered sqlite connection cycle keeps `state.db` locked on
    Windows, breaking temp-dir cleanup (production untouched → debt 13)
  - Tests: +12
- [x] **V3-E03-T05** · Harness JSON report + contributor docs — ✅
  complete
  - Files: new `eval/harness/report.py` (byte-stable JSON: scorecard +
    `run.{git_commit,git_dirty,corpus_hash,case_count}`; honest `null`s
    without git; no timestamps/durations), CLI `--json PATH` (written
    even when the gate fails — CI artifact), `CONTRIBUTING.md`
    "Evaluation harness" section (run/gate/add-case/baseline/report +
    fixture rules), `TESTING_EVALUATION_PLAN.md` §5.5 updated
  - Verified: report contains score, case count, git identity;
    two reports byte-identical on same commit; corpus secret-scan (9
    token patterns) clean; provenance all hand-authored/synthetic
  - Tests: +8 (report shape/stability/gate-failure artifact, docs
    presence, corpus safety). **V3-E03 now 5/5 ✅**

**V3-E03 exit criteria:** ✅ one command prints a score · ✅ byte-stable
across runs (in-process + CLI) · ✅ broken fixture lowers the score
(proven) · ✅ CI runs it offline without network/API keys (additive job,
no secrets/env) · ✅ runtime < 60s (measured ~5s) · ✅ no production-code
changes · ✅ full suite **661 passed** · ✅ `git diff --check` clean ·
✅ baseline current, `--gate` OK · ✅ no ADR hard gate skipped (ADR-016
followed as written; ratification → debt 12) · ✅ no commit.

### V3-E04 · storage & dashboard debt remediation — ✅ COMPLETE (7/7 tickets, this run)

- [x] **V3-E04-T01** · Storage connection lifecycle — ✅ complete
  - Files: `ai_pr_reviewer/storage.py` (`_connection()` contextmanager; 9 call
    sites converted), `tests/test_storage_client.py` (+4)
  - Verified: every SQLite connection closes deterministically on context
    exit — **closes Technical Debt 13** (GC-only close)

- [x] **V3-E04-T02** · Retention policy — ✅ complete
  - Files: `ai_pr_reviewer/storage_schema.py` (`retention_cutoff`,
    `is_stale` — one policy definition for every backend),
    `ai_pr_reviewer/storage.py` (`LocalReviewStorage.prune` + best-effort
    hook in `resolve_storage`), `ai_pr_reviewer/config.py` (`retention_days`,
    strict layering, negative → ConfigError), `dashboard/storage.py`
    (`DbStorage.prune`, `JsonStorage.prune` + slug),
    `dashboard/app.py` (lifespan `_retention_days`/`_retention_prune`;
    `DASHBOARD_RETENTION_DAYS` overrides `RETENTION_DAYS`)
  - Policy per `DATA_MODEL.md` §6: default 0 = keep everything; history
    pruned only when the row **and** its `review_state` are stale (blocks
    lifecycle resurrection); NULL/`''` timestamps never pruned; repo memory,
    review states, reports and the audit trail never pruned; idempotent;
    `dry_run` reports the same counts; the engine prunes **Local only**
    (`CAP_PRUNE` — never deletes remote dashboard data)
  - Tests: 5 engine (`test_t02_*`) + 4 config + 5 dashboard — **closes
    Technical Debt 10**

- [x] **V3-E04-T03** · Shared storage schema module — ✅ complete
  - Files: new `ai_pr_reviewer/storage_schema.py` (review-id format/parse,
    key builders, `fingerprint:` mute prefix, `CAP_*`/`CORE_CAPABILITIES`,
    retention helpers) — stdlib-only leaf; engine + dashboard consume it
    instead of re-deriving formats (dashboard via lazy `_schema()`)
  - Tests: new `tests/test_storage_schema.py` (16) — mute helpers, parse
    matrix, key builders, **ownership scan** (only the owner module defines
    each literal) with a vacuity guard

- [x] **V3-E04-T04** · Capability flags — ✅ complete
  - Files: `ai_pr_reviewer/storage.py` (`has_capability()` single
    chokepoint, `ReviewStorage.capabilities: frozenset[str]`, no
    `getattr(storage, ...)` probes anywhere — pinned), branching in
    context/orchestrator; `dashboard/storage.py` (Db/Json declare
    capabilities + `get_dismissed_fingerprints`)
  - Sets: core-5 everywhere · `LIST`+`DISMISSED` everywhere · `TELEMETRY` +
    `PRUNE` on Local/Db/Json; the HTTP client declares neither (engine never
    writes telemetry to, or deletes data from, the dashboard) and degrades
    with a logged warning
  - Tests: 7 engine + 3 dashboard

- [x] **V3-E04-T05** · Dashboard aggregation pushdown — ✅ complete
  - Files: `dashboard/models_db.py` (additive `engine`/`fallback_used`/
    `health_score` columns + `ix_finding_histories_repo_pr`),
    `dashboard/storage.py` (stats/metrics as SQL `GROUP BY` with one-scan
    global expansions, payload-derived backfill in the same transaction as
    the ALTER, `list_findings` repo pushdown + `yield_per` streaming + early
    stop, sparse `severity_counts`, shared `_telemetry_assemble`,
    deterministic `_top_counter` tie-break, `_json_sum_sql` fallback),
    `dashboard/app.py` (`/api/findings` offset clamp)
  - Tests: 8 (`test_t05_*`) — golden cross-backend snapshot, paging windows,
    **zero-ORM-load row counts** on the aggregate paths, 50k-row perf
    baseline, legacy-DB backfill, index (fresh + legacy), JSON-sum fallback
  - Perf @50k rows: paged reads 26–70 ms (ticket's proposed baseline
    < 500 ms); aggregates gated on `loads == 0` + a 3000 ms gross-regression
    ceiling (min-of-N to suppress scheduler noise)

- [x] **V3-E04-T06** · Migration strategy decision — ✅ complete (docs only)
  - Files: `docs/planning/ADR_INDEX.md` (**new ADR-022** + index row),
    `docs/planning/MIGRATION_PLAN.md` (§3.1 principle 3 + cross-reference)
  - ADR-022 inventories the hand-rolled additive-`ALTER` paths (2 sites,
    7 columns, 1 index, 0 down-migrations), states the failure modes, fixes
    tool criteria (must support SQLite WAL **and** PostgreSQL, pip-only, not
    in the Action image) and the trigger: **mandatory at the first
    non-additive change; scheduled review at the first V4 storage
    addition**. Status *Proposed — adoption deferred*; **no code changed by
    this ticket**

- [x] **V3-E04-T07** · Backend parity test suite — ✅ complete
  - Files: new `tests/test_storage_parity.py` — 46 cases (44 pass + 2
    capability-aware skips) parametrized over Local/Db/Json **and the real
    HTTP path** (engine `DashboardStorageClient` → FastAPI app over ASGI,
    offline)
  - Covers: capability declarations vs methods, empty reads, state
    lifecycle, findings round-trip/upsert/isolation, fingerprint-less save,
    caller-data immutability, memory-note globbing, verbatim list contract,
    dismissed lifecycles, telemetry + prune gated round trips, one
    literal cross-backend comparison, HTTP fail-closed auth edge
  - Self-test: intentionally broken Json dismissed-reader → suite red
    (2 failures) → reverted → green
  - **Parity-revealed bugs fixed inline** (reported as bugs): local
    `save_findings` mutated the caller's dict (now copies, like every other
    backend); json stored fingerprint-less findings without computing one
    (now computes exactly like the DB backend)
  - Documented accepted deviations: Finding-vs-dict return types, no
    row-order contract, dashboard-only `id`, Json telemetry metadata keys,
    HTTP = no telemetry/prune + token auth

**V3-E04 exit criteria:** ✅ all 7 tickets · ✅ full suite **757 passed,
2 skipped** · ✅ `git diff --check` clean · ✅ `python -m eval.harness
--gate` OK (8 cases, labels 12/12) · ✅ no demo/sample churn · ✅ ADR-022
written and referenced from `MIGRATION_PLAN.md` · ✅ ADR-014/ADR-016
human approval recorded in `ADR_INDEX.md` (debts 8/12 closed) · ✅ no
commit.

### V3-E05 · config & contract hardening — ✅ COMPLETE (5/5 tickets, this run)

- [x] **V3-E05-T01** · Single-source the sensitive-path baseline (D12) — ✅ complete
  - `dashboard/app.py` now imports `SENSITIVE_EXCLUDE_GLOBS` from
    `ai_pr_reviewer.rules`; the byte-identical duplicate list is gone
  - Deliberately a module-level (eager) import, not dashboard's usual lazy
    pattern: `dashboard.app` only imports with the repo root on `sys.path`,
    i.e. exactly when the engine is importable — fail-closed on a privacy
    control, no new dependency edge
  - Tests: identity check (`dashboard_app.SENSITIVE_EXCLUDE_GLOBS is` the
    engine's object — re-hardcoding a copy fails); dashboard merge of junk
    payloads can never shrink the baseline union (fail closed)
- [x] **V3-E05-T02** · Centralize hard-coded caps as named constants (D13) — ✅ complete
  - Planning-vs-code reconciliation first: 6 of the documented "8 sites"
    were already named constants (`MAX_CONTEXT_FILES`, `MAX_CONFIG_CANDIDATES`,
    `MAX_MEMORY_ENTRIES`, …); genuinely literal caps named this run with
    quality-ceiling comments — `reporter.MAX_MARKDOWN_FINDINGS` (8),
    `dashboard.app.MAX_ANALYZE_DIFF_CHARS` (50 000) / `MAX_ANALYZE_FINDINGS`
    (50) / `MAX_SETTINGS_*` (200/100/50), `config.DEFAULT_MAX_COMMENTS` (20,
    shared with the dashboard), memory-note bound single-sourced to the
    engine's `MAX_NOTE_CHARS` (dashboard `_max_note_chars()` fallback derives
    from it)
  - `tests/test_cap_constants.py`: value freeze + grep guard pinning the
    documented cap values at the documented sites; out-of-scope bounds
    documented in the test docstring (DB column widths, id/slug/hash
    truncation, error-echo bounds, validation ranges)
  - All values unchanged → golden outputs unchanged (suite green)
- [x] **V3-E05-T03** · Action contract snapshot — ✅ complete (mutation-checked)
  - New `tests/test_action_contract.py` (8 tests): inputs/outputs snapshot
    (names + required + defaults frozen; descriptions presence-frozen only,
    wording stays cosmetic), `INPUT_*` plumbing both directions (declared ↔
    `cli`/`config` readers), outputs written by `cli._set_github_output`
    == declared outputs, example-workflow invariants (pull_request trigger
    only, **base** revision checkout, `persist-credentials: false`,
    workflow-level permissions, exact major-version pin), repo-wide
    structural `pull_request_target` scan (YAML-parsed triggers — warning
    prose mentioning it doesn't trip), exit codes 0/1/2 enumerated
    in-process
  - Mutations: output rename → red; input default `20→10` → red; restored →
    8 pass, `action.yml` byte-clean
- [x] **V3-E05-T04** · Report JSON schema guard — ✅ complete (mutation-checked)
  - New `tests/test_report_schema.py` (4 tests): 23 required top-level keys
    of `ReviewResult.to_dict()` and 23 required finding keys frozen;
    additive fields allowed at both levels (guard is deliberately
    additive-only); JSON round-trip pinned; built against the real
    models/reporter, not a mock
  - Documented as the machine-checkable half of the report contract in
    `MIGRATION_PLAN.md` §1 (human half = the doc itself)
  - Mutation: dropping `health_score` from `ReviewResult.to_dict()` → red;
    restored → green
  - D10 (risk/verification keys) deliberately NOT added — outside this
    epic's purpose; the additive-only guard accepts it whenever a future
    ticket ships it
- [x] **V3-E05-T05** · Config layering precedence test matrix — ✅ complete (mutation-checked ×2)
  - `tests/test_config.py`: **89-row** parametrized matrix (default, each
    single layer, every precedence pair) over 19 fields pinning
    CLI > `INPUT_*` > plain env > default; list-field layering
    (exclude/focus); dashboard-rules merge semantics (fills gaps, never
    overrides an explicit value, invalid severity ignored, unreachable
    dashboard = no-crash, no credentials = no HTTP call — with credentials
    actually set in the merge tests so no assertion is vacuous);
    `_effective_severity_threshold` override semantics pinned
  - Forward-compat: unknown `INPUT_*` env var warns **without echoing its
    value** (secret-safe); unknown `.ai-pr-reviewer.yml` top-level keys
    warn and don't break; `KNOWN_INPUT_ENV_VARS` cross-checked against
    action.yml plumbing AND against the names actually read in config
    source
  - Mutations: `_str_field` env-over-CLI flip → 4 matrix rows red;
    `github_token` CLI side dropped → 3 rows red; both restored → green
  - Debt-7 question answered by pinning test
    (`test_repo_context_chars_garbage_falls_back_to_default`): the budget
    keeps `_int_field`'s silent fallback — a typo'd budget must not kill a
    review, unlike the strict `ConfigError` numeric fields

**V3-E05 exit criteria:** ✅ all 5 tickets · ✅ full suite **874 passed,
2 skipped** (1 pre-existing StarletteDeprecationWarning) · ✅
`git diff --check` clean · ✅ `python -m eval.harness --gate` OK (8 cases,
labels 12/12, precision/recall 1.000) · ✅ security invariants untouched
(`test_security`, `test_release_hardening` green) · ✅ no demo/sample
churn · ✅ mutation checks recorded for T03 (×2), T04 (×1), T05 (×2) ·
✅ no commit.

### V3-E06 · documentation & release hygiene — ✅ COMPLETE (6/6 tickets, this run)

- [x] **V3-E06-T01** · Deprecate legacy facades (D11) — ✅ complete
  - Premise reconciled first: only `get_analyzer` / `ClaudeAnalyzer` /
    `MockAnalyzer` are dead; `StaticAnalyzer`, `AnalysisOutcome` and
    `heuristics.analyze_with_rules` are production (model_router, three
    providers, dashboard endpoint) and stay warning-clean apart from the
    one-per-process module notice Python hides outside `__main__`
  - `analyzer.py` + `heuristics.py` emit `DeprecationWarning` at import;
    `get_analyzer()` warns on call; every stale docstring claim ("used
    today by cli.py", "orchestrator hasn't landed", "currently just
    cli.py", "cli.py calls analyze_with_rules") corrected to reality
  - Removal version stated everywhere: **v4.0.0, no earlier than
    2027-04-07** (6-month window, MIGRATION_PLAN §7)
  - `tests/test_deprecation.py` (5): subprocess import-warnings for both
    modules (clean interpreter, can't be masked by `sys.modules`),
    call-site warning with behavior unchanged, stale-claim grep, and a
    production-package scan proving the dead symbols have no callers
  - README Layout comments mark both files deprecated; CHANGELOG entry
    under `Unreleased → Deprecated`
- [x] **V3-E06-T02** · Lint gate in CI (ruff baseline) — ✅ complete (mutation-checked)
  - Baseline had exactly **one** pre-existing finding (F821
    `RetryPolicy` — annotation-only, never evaluated under `from
    __future__ import annotations`) → fixed with a `TYPE_CHECKING`
    import (runtime lazy import untouched); zero other findings
  - Additive `lint` CI job: checkout → setup-python 3.12 → pinned
    `ruff==0.16.10` → `python -m ruff check .`; existing jobs byte-unchanged
    (only the matrix comment was reworded to state the T03 policy)
  - Mutation check: injected undefined name → ruff red → restored →
    "All checks passed!" (exit 0)
  - `pyproject.toml` comment updated (was "not part of CI"); new
    `test_lint_job_is_additive_offline_and_pinned` structural guard
  - Note: the E03 job-set snapshot (`test_existing_jobs_are_untouched`)
    gained `lint` in its expected set — a deliberate contract evolution
    authorized by this ticket; every other assertion in it stays as-is
- [x] **V3-E06-T03** · Python support matrix unification (D14 second half) — ✅ complete
  - Policy decided and stated once: **supported range 3.11–3.13; Action
    runtime pinned 3.12 (`action.yml` + `python:3.12-slim`); CI test
    matrix = the whole range (unchanged); lint/evaluation jobs on 3.12;
    local best-effort through 3.14; `PYTHONUTF8=1` Windows gotcha**
  - Documented in README §5 "Supported Python versions" (authoritative),
    the ci.yml matrix comment, and CONTRIBUTING — matrix itself NOT
    changed (stated explicitly in the comment)
  - AGENTS.md restates versions imprecisely ("CI … target 3.12") —
    protected by mission rule, flagged for a human instead of edited
- [x] **V3-E06-T04** · Public contract documentation pass — ✅ complete
  - README gained the two missing contract sections: **Report JSON**
    (all 23 top-level + 23 finding fields, cross-linked to the E05-T04
    guard) and **Configuration layering** (CLI > `INPUT_*` > plain env >
    default, plus both merges: dashboard fills-gaps-only, policy
    unions/exact-input-wins)
  - `tests/test_readme_contract.py` (6): inputs table ↔ `action.yml`
    (names + non-empty defaults, all 21), outputs (5), exit-code line
    with meanings, report fields listed = fields the real pipeline
    emits (built from `models`+`reporter`, not a mock), layering order
    + both merges documented, `.ai-pr-reviewer.yml.example` parses under
    `load_project_rules` with zero unknown/invalid warnings
  - Example workflow invariants deliberately not duplicated — enforced
    by E05-T03's `test_action_contract.py` (cross-referenced in the new
    test's docstring); `action.yml`/`example-workflow.yml` untouched
- [x] **V3-E06-T05** · Fixture & demo hygiene audit — ✅ complete (results recorded)
  - Empirical, not assumed: secret-pattern scan over `demo/`+`eval/`+
    `tests/` (15 hits, **all** synthetic redaction fixtures —
    `ghp_AbCdEf…`, `AIzaSyD-FAKEFAKE…`, `AKIAIOSFODNN7EXAMPLE`); sample
    diffs reference synthetic repos only; **zero** tracked
    `.db`/`.jsonl`/settings files (`dashboard/data` = `.gitkeep` only)
  - Regeneration gotcha settled by observation: the suite rewrites
    nothing (conftest builds into a pytest temp dir — README's claim is
    true); `python demo/make_fixtures.py` rewrites all three samples
    with CRLF → `git` modified + `.gitattributes` LF warnings →
    **restored to a clean tree immediately**
  - Documented where contributors see it: CONTRIBUTING "Demo fixtures &
    the regeneration gotcha" (churn warning + audit result + keep-new-
    fixtures-obviously-fake rule)
- [x] **V3-E06-T06** · Release hygiene: tagging, CHANGELOG, version story — ✅ complete
  - `CHANGELOG.md` gained an **`Unreleased`** section with the Phase 0
    contract-relevant entries (Added / Deprecated / Changed / Fixed /
    Security) — including the E06-T01 deprecation notice
  - README §7 rewritten as "Versioning, releases & license": major-tag
    pinning guidance (`@v2` moving major vs `v2.0.0` immutable — both
    verified against the actual tags), stage majors `@v3`/`@v4`,
    12-month security-fix window (MIGRATION_PLAN §6.2), current
    deprecation windows (§7), and a 4-step **release checklist** whose
    step 2 names `tests/test_action_contract.py` (V3-E05-T03) and
    `tests/test_report_schema.py` (V3-E05-T04) as contract gates (+ the
    new readme-contract test)
  - CONTRIBUTING: contract-affecting changes now also require a
    CHANGELOG entry

**V3-E06 exit criteria:** ✅ all 6 tickets · ✅ full suite **886 passed,
2 skipped** (3 warnings: 1 pre-existing Starlette + the 2 new facade
notices) · ✅ `python -m ruff check .` green · ✅ `python -m eval.harness
--gate` OK (8 cases, labels 12/12) · ✅ `git diff --check` clean · ✅
tree audit: 52 entries all accounted for; `AGENTS.md`, `action.yml`,
`demo/` untouched; `D .github/dependabot.yml` preserved · ✅ mutation
check recorded for T02 (lint red→green) · ✅ no commit.

### V4-E04 · evidence engine & provenance — audit of previous run's work (5 tickets)

- [x] **V4-E04-T01** · Provenance field design on `Finding` (additive) — ✅ complete
  - Files: `ai_pr_reviewer/models.py` (4 fields, `LIFECYCLE_FIELDS`, `to_dict`/`from_dict`), `tests/test_evidence.py` (19 tests)
  - Verified: model output cannot forge provenance (`from_untrusted_dict` strips); old findings round-trip with `None`
  - Note: fields are engine/model/agent/origin (per C3) rather than the ticket's evidence-record tuple (source kind/locator/hash/captured-at) — that tuple belongs to T02's evidence record

- [ ] **V4-E04-T02** · Evidence record schema + storage — ❌ not started (blocker CLEARED)
  - Missing: `evidence` entity behind `ReviewStorage` seam, content-hash integrity, redacted-at-write
  - Blocker status: hard dep `V3-E04-T02` **shipped this run** (retention: `retention_days` config + `prune()` on every backend, policy per `DATA_MODEL.md` §6) — T02 is now dependency-ready and remains unstarted
  - Unresolved issues: implementing it expands into V4 scope (correct — it is a V4 ticket)

- [~] **V4-E04-T03** · Provenance attachment through the pipeline — 🟡 partial
  - Done: orchestrator populates engine/model/origin after dedup (`orchestrator.py:175-184`)
  - Missing: "attribution survives dedup" (dedup does NOT merge provenance lists — `findings.py:deduplicate` unaware of provenance); static findings do not cite rule IDs at provenance level; no "no finding lacks provenance" invariant test

- [~] **V4-E04-T04** · Provenance in report + dashboard rendering — 🟡 partial
  - Done: report JSON passthrough (`reporter.py:_FINDING_PASSTHROUGH`)
  - Missing: dashboard rendering (`dashboard/` has zero provenance references — verified); null-provenance "unavailable (reason)" label

- [ ] **V4-E04-T05** · Evidence redaction + untrusted-content conformance — ❌ not started (BLOCKED by T02)

**V4-E04 exit-criteria status:** 1 of 4 met (stripping test ✅); "evidence persists byte-identically" ❌; "dashboard shows provenance" ❌; "every finding carries provenance or null-with-reason" 🟡.

## Version Gates

Actual completion gate per `V4_V10_ROADMAP.md` exit criteria (a version is
complete only when **all** its stage epics are ✅ **and** all exit items pass):

- **V4 gate** (7 items): (1) index built from `base_sha`, hash-sealed, PR-modified file cannot alter its own review's index; (2) context provenance `{source ref, reason, tokens}` + harness relevance ≥ 0.8@10, no regression vs Phase 0; (3) bounded, truncation-flagged impact closures, degrade to "impact unknown"; (4) every AI finding carries provenance, none settable via `from_untrusted_dict`; (5) fingerprint v2 dual-compute with 100% state continuity migration; (6) injection/poisoning corpus 100% neutralized + budget-cap tests; (7) harness score ≥ Phase 0 score, full suite green, zero-key path exercises index end-to-end. **Entry gate: Phase 0 complete.**
- **V5 gate** (5 groups): planner→executor→merger→synthesizer green under concurrency stress with no global breaker state; registry adding-fake-provider wiring test; merger golden suite with per-agent provenance + single merged comments; V5-E08 council-vs-single deltas in CI (quality ≥ baseline, cost ≤ cap); budget/failure drills correctly labelled.
- **V6 gate** (5): security engine at corpus precision/recall floor with evidence-backed findings (locator or dropped); arch/test-intel fixtures + partial-analysis labelling; verification tiers incl. "model cannot claim test evidence" negative test; policy truth-table suite with non-overridable exclusion baseline; secret-leak corpus clean.
- **V7 gate** (5): deterministic history on fixtures with labelled shallow-clone degradation; memory authority/poisoning corpus cannot reach approved level, backfill idempotent; relations from deterministic rules with caps; linkage with fenced issue bodies; analytics aggregate-only invariant (no author dimensions).
- **V8 gate** (5): CI ingestion with rate-limit/missing-data drills never fatal; correlation with causation-vs-correlation honesty tests; evidence-backed release/docs/infra findings; append-only event log with replay-equality + **zero queue/worker symbols** (negative architecture test); secret-leak corpus clean in events/correlations/report.
- **V9 gate** (5): scope-matrix CI invariant with cross-org denial; policy inheritance fixtures + effective-policy audit; `/api/v1` snapshot + breaking-change detector + SPA on v1 with deprecation headers; org-scoping migration idempotency + JsonStorage fate decided; workers only where V9-E07 shows bottleneck with parity + kill drills.
- **V10 gate** (5): sandbox escape suite 100% denied + crash isolation + malicious-plugin corpus neutralized + plugin-disabled degradation; manifest/API-range parity for first-party rule packs; capability registry with ≥ 1 offline local adapter + retired-model deny-list; CLI == Action == sandbox parity; command center from precomputed rollups with no-individual-dimensions invariant on v1 only.

## Known Technical Debt

Kept separate from epic completion (per mission: never silently convert
pre-existing defects into epic credit):

1. **D1–D7** — ✅ **fixed this run** (V3-E01) and pinned 1:1 in
   `tests/test_defect_regressions.py`. Original defect sites for the record: D1
   (`get_pr`/`get_event_context` built `PRContext` without `base_sha`), D2
   (verification got the capped `inline` list), D3 (below-threshold `continue`
   dropped findings), D4 (`inline = valid[:cfg.max_comments]` fed report/health),
   D5 (no sort — "Already sorted by analyzers" comment), D6 (3 of 4 numeric
   fields raw `int()`), D7 (mute lookup by non-PK minted duplicate rows).
2. **D10–D14 final status (Phase 0 closed):** D10 undeclared
   `ReviewResult` runtime attributes (risk/verification missing from
   report JSON) — **remains open**; it sat in "V3-E05 contract snapshot
   territory" but was outside that epic's purpose and no ticket required
   it, so no ticket claimed it; the additive-only report guard accepts it
   whenever a future ticket ships the keys → still unmapped, candidate
   for a V4 ticket. D11 legacy facades — ✅ **closed by V3-E06-T01**
   (DeprecationWarnings with removal version, corrected docstrings,
   README/CHANGELOG statements, `tests/test_deprecation.py`). D12
   duplicate sensitive baselines — ✅ **closed by V3-E05-T01** (one
   owner, identity-enforced). D13 hard-coded caps — ✅ **closed by
   V3-E05-T02** (named constants + value freeze + grep guard). D14 no
   lint/type gate + Python matrix split — ✅ **closed by V3-E06-T02/T03**
   (pinned ruff `lint` CI job, mutation-verified; support policy stated
   once in README §5 with the matrix unchanged).
3. **V4-E05 ticket-list conflict (planning discrepancy — reported, NOT fixed):** `EPIC_BACKLOG.md` V4-E05-T02..T06 still describe dual-computation → alias table → cutover, while the V4-E05 epic entry, ADR-005 and DM-01 resolution mandate the **layered identity model** (v1 primary, additive provenance + occurrence key, **no alias table, no cutover**). The epic entry was reconciled during remediation; the ticket breakdown was missed. Needs a planning-doc fix decision before V4-E05 starts.
4. **12 remaining LOW/MEDIUM audit findings** — documented in `PLANNING_REMEDIATION_REPORT.md` §9 (cosmetic/out-of-scope; untouched).
5. **Pre-existing worktree items (do not touch):** `D .github/dependabot.yml`, `?? AGENTS.md` — predate this work; leave as-is unless an epic explicitly requires otherwise.
6. **V4-E04 out-of-order start** — previous run implemented V4-E04 before V4-E01/E02/E03 and Phase 0, contrary to roadmap internal order. Work is additive and safe (models-layer only), but the epic remains incomplete and must not be cited as satisfying V4 stage gates.
7. **D6 scope decision (reconciliation note):** `_strict_int` was wired at the 3
   bare `int()` sites (`pr_number`, `max_comments`, `batch_chars`). The 4th
   field `repo_context_chars` keeps its pre-existing `_int_field()` silent-fallback
   to the default — deliberately out of V3-E01 scope (it was never a raw
   `int()` and changing its behavior is a policy question for V3-E05 config
   hardening, not a defect fix). **Answered by V3-E05-T05 (this run):** keep
   the silent fallback — a typo'd *budget* must never kill a review (strict
   `ConfigError` stays reserved for fields where a wrong value silently
   corrupts review structure). Pinned by
   `test_repo_context_chars_garbage_falls_back_to_default` so a future "make
   it strict" change is a reviewed decision, not an accident.
8. **ADR-014 ratification — ✅ RESOLVED (human-approved 2026-10-06):**
   ADR-014 "Local-first telemetry & cost accounting" was implemented in
   V3-E02 strictly inside its written decision (content-free records, single
   serialization chokepoint, **no hardcoded price table**, no telemetry
   egress) while flagged as pending; the human **approved** it on
   2026-10-06 and `ADR_INDEX.md` now reads "Approved — human ratification
   2026-10-06". The price-table config question remains open as debt 9.
9. **Cost series deferred from V3-E02-T05:** the dashboard shows tokens +
   latency but no `cost_estimate_usd` — ADR-014 requires the price table to
   live in *config* (never hardcoded per provider), and no ticket in T01–T05
   defines that config surface (epic exit criteria mention only tokens/usage
   markers, report telemetry, storage round-trip, redaction). Follow-up:
   decide the price-table config shape during ADR-014 ratification (or
   V5-E07 cost arbitration). The `usage.duration_ms` → `call_ms` column and
   `_telemetry_summary` leave a clean seam for it.
10. **Telemetry/finding retention — ✅ RESOLVED (V3-E04-T02, this run):**
    time-based pruning shipped on every backend: `retention_days` config
    (default 0 = keep everything; `INPUT_RETENTION_DAYS`/`RETENTION_DAYS`;
    negative → config error), `prune()` on Local/Db/Json behind
    `CAP_PRUNE`, dashboard lifespan hook (`DASHBOARD_RETENTION_DAYS`
    overrides `RETENTION_DAYS`), policy per `DATA_MODEL.md` §6 — active PRs
    and unknown ages never pruned, repo memory/review states/reports/audit
    never touched, idempotent, `dry_run` observable. The V4-E04-T02
    dependency is cleared.
11. **Provider per-batch fallback warnings echo full exception messages
    (discovered during T06, deliberately NOT fixed):** `claude.py:245`,
    `openai.py:78`, `gemini.py:85` all use
    `f"... failed after retries ({exc}) — ..."`, so an exception message
    carrying request bodies/secrets lands in report `warnings` (router
    warnings are type-name-only per C5; this predates V3-E02 and is not
    telemetry). T06 pinned only the *already-required* type-name-only
    contracts (events + router warnings). Follow-up: align the three
    provider warnings to `type(exc).__name__` + a redaction pass — needs its
    own ticket to avoid silent scope creep. Notably,
    `test_telemetry_nocontent.py::test_t06_claude_exception_message_never_reaches_telemetry`
    documents the boundary (asserts telemetry clean only).
12. **ADR-016 ratification — ✅ RESOLVED (human-approved 2026-10-06):**
    ADR-016 (evaluation gate strategy: Tier A deterministic blocks / Tier B
    AI trends never block) was human-approved on 2026-10-06;
    `ADR_INDEX.md` now reads "Approved — human ratification 2026-10-06".
    The Tier A deterministic corpus gate keeps blocking CI exactly as
    written; the uncalibrated thresholds remain open as debt 14.
13. **`LocalReviewStorage` connections closed only on GC — ✅ RESOLVED
    (V3-E04-T01, this run):** `_connection()` is now a contextmanager that
    closes the connection on context exit (all 9 call sites converted),
    pinned by tests in `tests/test_storage_client.py`; the Windows file-lock
    symptom debt 13 described can no longer outlive a store operation. The
    harness's `gc.collect()` workaround remains (harmless belt-and-braces).
14. **Gate thresholds are proposed and uncalibrated:** `eval/baseline.json`
    allows 0.0 drop on precision/recall/recall_critical_high (and 0.0
    rise on false_positive_rate) — correct for a fully synthetic corpus
    where any movement is self-inflicted, but asserted as *proposed
    baseline* per V3-E03 acceptance. Recalibrate (if ever) when the corpus
    grows real-world diversity or ADR-016 Tier B AI trends come online;
    thresholds live in the baseline file itself, so a change is a
    reviewed diff.
15. **No engine→dashboard telemetry route over HTTP (pre-existing V3-E02
    seam, made explicit by V3-E04-T04 — new this run):**
    `DashboardStorageClient` declares no `save_telemetry` capability, and
    the dashboard has no `/api/reviews/.../telemetry` endpoint — so an
    engine configured with `dashboard_url` drops its telemetry row with a
    logged warning (drop-safe per ADR-014) while still carrying telemetry
    inside the report JSON payload. Closing it needs an endpoint + client
    method + auth story for a dashboard write surface. Until then,
    `test_t07_telemetry_round_trip_when_capability_declared` skips the HTTP
    param with an explicit reason, and orchestrator telemetry persistence
    branches on the capability.

## Execution History

| Date | Epic | Files changed | Tests | Commit | Decisions / next |
|------|------|---------------|-------|--------|------------------|
| 2026-10-04 | (planning) audit + remediation of 16-doc planning set | `docs/planning/*` (18 docs) | n/a (planning only) | none (untracked) | `FINAL_CONSISTENCY_AUDIT.md` preserved; DM-01 → layered identity (ADR-005) |
| 2026-10-04 | V4-E04 (previous run, partial) | `ai_pr_reviewer/models.py`, `orchestrator.py`, `reporter.py`, `tests/test_review_state.py`, new `tests/test_evidence.py` | 483 passed | none | T01 complete; T03/T04 partial; T02/T05 blocked on V3-E04-T02. Reported "complete" — audit disagrees (🟡) |
| 2026-10-04 | V3-E01 (this run) | `ai_pr_reviewer/`: `orchestrator.py` (sort + 5-way split + uncapped wiring), `cli.py` (posting cap), `models.py` (`below_threshold`), `reporter.py` (counts/wording), `github_client.py` (`base_sha`), `config.py` (`_strict_int`); `dashboard/storage.py` (mute upsert); tests: new `test_defect_regressions.py` (7), + `test_config.py`, `test_dashboard_storage.py`, `test_github_incremental.py`, `test_orchestrator.py`, `test_pipeline.py` | 506 passed, 1 warning (pre-existing) | none (no commit unless requested) | ✅ 8/8 tickets. Decisions: `_strict_int`→exit 1 for 3 bare-int sites, `_int_field` fallback kept (debt 7); D7 fixed on both backends, `add_repo_memory` still append-only; cap moved to `cli._post_and_sync`. Next dependency-ready: V3-E02 |
| 2026-10-04 | V3-E02 batch 1 (this run, 5-ticket limit) | new `ai_pr_reviewer/telemetry.py`; `ai_pr_reviewer/`: `ai/claude.py`, `ai/openai.py`, `ai/gemini.py` (usage capture + `usageMetadata` + outcome telemetry), `analyzer.py` (static `n/a`), `model_router.py` (events + `StaticProvider.usage_summary`), `retry.py` (`events`), `models.py` (2 append-only fields + `to_dict`), `orchestrator.py` (chokepoint copy + drop-safe persist), `storage.py` (telemetry table); `dashboard/`: `models_db.py` (`TelemetryRow`), `storage.py` (save/get + metrics + `_telemetry_summary`), `static/app.js` (metrics block); tests: new `test_telemetry.py` (19) + `test_storage_client.py` (+4), `test_dashboard_storage.py` (+7), `test_orchestrator.py` (+5), `test_review_state.py` (contract list extended) | **541 passed, 1 warning** (pre-existing), `git diff --check` clean, no sample churn | none (no commit unless requested) | T01–T05 ✅; **T06 remains → next batch**. ADR-014 ratification flagged (debt 8); cost series deferred (debt 9); retention waits for V3-E04 (debt 10). Next: V3-E02-T06, then V3-E02 completes → V3-E03 |
| 2026-10-04 | V3-E02-T06 (run 2, one-ticket limit) | `ai_pr_reviewer/telemetry.py` (shared `_sanitize_row` + value/int allowlists + fence-aware `_redact` + public `sanitize_telemetry`), `ai_pr_reviewer/storage.py`, `dashboard/storage.py` (DbStorage + JsonStorage boundary sanitizing), `ai_pr_reviewer/models.py` (`ReviewResult.to_dict` report-boundary sanitize); new `tests/test_telemetry_nocontent.py` (16); **`security.py` reused, not modified** | **557 passed, 1 warning** (pre-existing), `git diff --check` clean, no sample churn | none (no commit unless requested) | T06 ✅ → **V3-E02 complete 6/6**. Adversarial/no-content invariant enforced structurally at chokepoint + all 3 storage backends + report boundary (non-dict rejected, unknown event types dropped, invalid usage state coerced to `unavailable` w/ tokens dropped, fences neutralized via existing `OPEN_TAG_RE`). Provider warning `{exc}` echo → debt 11. **V3-E03 NOT started.** Next: V3-E03 |
| 2026-10-05 | V3-E03 (run 3, one-complete-epic limit) | new `eval/` package: `eval/__init__.py`, `eval/harness/{__init__,loader,runner,match,score,gate,report,__main__}.py`, `eval/baseline.json`, `eval/corpus/` (8 cases: GOLDEN-SEC-001, FPCLEAN-001, INJ-001, DEFECT-D2-01..D6-01); `.github/workflows/ci.yml` (additive `evaluation` job only), `CONTRIBUTING.md` (harness guide), `docs/planning/TESTING_EVALUATION_PLAN.md` (§5.5 as-implemented), new `tests/test_evaluation_harness.py` (104); **zero production-code changes** (`ai_pr_reviewer/` untouched for this epic) | **661 passed, 1 warning** (pre-existing), `git diff --check` clean, no sample churn, `python -m eval.harness --gate` OK | none (no commit unless requested) | **V3-E03 complete 5/5**. Offline deterministic harness (loader→runner→match→score→gate/report), corpus-hash baseline gate, re-introduction spot-checks prove each D-case sensitivity; D1/D7 excluded with cross-ref test (transport/storage defects unobservable via diff); discovered sqlite GC-lock quirk → debt 13 (harness-side `gc.collect()`, pinned); ADR-016 followed as written, ratification → debt 12; thresholds uncalibrated → debt 14. **STOPPED.** Next dependency-ready: V3-E04 |
| 2026-10-06 | V3-E04 (run 4, one-complete-epic limit) | `ai_pr_reviewer/storage.py` (`_connection()` lifecycle + 9 call sites, `has_capability` + Protocol `capabilities`, Local `prune`, `resolve_storage` retention hook, caller-copy fix in `save_findings`); new `ai_pr_reviewer/storage_schema.py` (review-id/keys/mute prefix/capabilities/retention helpers, shared by engine + dashboard); `ai_pr_reviewer/config.py` (`retention_days` strict load + negative guard); `dashboard/storage.py` (Db/Json capabilities + `get_dismissed_fingerprints`, Db/Json `prune`, T05 SQL aggregation + `yield_per` + payload backfill + sparse severity_counts + deterministic `_top_counter` + `_telemetry_assemble`, Json fingerprint-injection fix), `dashboard/models_db.py` (3 additive metric columns + `ix_finding_histories_repo_pr`), `dashboard/app.py` (lifespan retention hook, `/api/findings` offset clamp); docs: `ADR_INDEX.md` (new **ADR-022** + index row; ADR-014/016 statuses → human-approved 2026-10-06), `MIGRATION_PLAN.md` (ADR-022 refs), this checklist; tests: new `tests/test_storage_schema.py` (16) + new `tests/test_storage_parity.py` (46 cases), `test_storage_client.py` (+16), `test_config.py` (+4), `test_dashboard_storage.py` (+16) | **757 passed, 2 skipped, 1 warning** (pre-existing), `git diff --check` clean, no sample churn, `python -m eval.harness --gate` OK (8 cases, labels 12/12) | none (no commit unless requested) | **V3-E04 complete 7/7** (T01→T03→T04→T02→T05→T06→T07). Closes debts 8 (ADR-014 ratified), 10 (retention), 12 (ADR-016 ratified), 13 (deterministic conn close); new debt 15 (no HTTP telemetry route). ADR-022 proposal-only (trigger: first non-additive change / first V4 storage addition). T07 self-test: broken backend → red → reverted. Parity bugs fixed inline: local caller-dict mutation, json fingerprint-less save. **V3-E05 NOT started. STOPPED.** Next dependency-ready: V3-E05 |
| 2026-10-07 | V3-E05 (run 5, one-complete-epic limit) | `ai_pr_reviewer/config.py` (`DEFAULT_MAX_COMMENTS`, `KNOWN_INPUT_ENV_VARS` + `_warn_unknown_inputs` hook at `load_config` entry); `ai_pr_reviewer/rules.py` (`KNOWN_TOP_LEVEL_KEYS` + unknown-key warning in `_normalize`); `ai_pr_reviewer/reporter.py` (`MAX_MARKDOWN_FINDINGS`); `dashboard/app.py` (engine `SENSITIVE_EXCLUDE_GLOBS` import replacing the duplicate list, `MAX_ANALYZE_*`/`MAX_SETTINGS_*` constants, shared `DEFAULT_MAX_COMMENTS`/`MAX_NOTE_CHARS` use); `dashboard/storage.py` (`_max_note_chars()` single-sourcing the note bound to the engine); `docs/planning/MIGRATION_PLAN.md` (§1 machine-checkable-half paragraph), this checklist; new tests: `tests/test_action_contract.py` (8) + `tests/test_report_schema.py` (4) + `tests/test_cap_constants.py` (3), `tests/test_config.py` (+98: 89-row layering matrix, list layering, 5 dashboard-merge, `_effective_severity_threshold`, 2 forward-compat, D6-scope pin), `tests/test_rules.py` (+4: unknown-key warning, baseline identity, merge-never-drops, dashboard-union) | **874 passed, 2 skipped, 1 warning** (pre-existing), `git diff --check` clean, no sample churn, `python -m eval.harness --gate` OK (8 cases, labels 12/12) | none (no commit unless requested) | **V3-E05 complete 5/5** (T01→T02→T03→T04→T05). Closes D12 (identity-enforced single source) and D13 (value freeze + grep guard); answers debt-7 policy question (budget keeps silent fallback, pinned); **D10 stays open** (outside epic purpose; additive-only report guard accepts it later); D11/D14 → V3-E06. Mutation checks: T03 ×2, T04 ×1, T05 ×2 (all restored → green). Dashboard-merge tests initially vacuous (no credentials → merge no-op) — fixed by configuring url/token before asserting. **V3-E06 NOT started. STOPPED.** Next dependency-ready: V3-E06 |
| 2026-10-07 | V3-E06 (run 6, one-complete-epic limit) | `ai_pr_reviewer/analyzer.py` (truthful docstring rewrite, module-level DeprecationWarning, `get_analyzer` call warning, corrected `StaticAnalyzer`/`ClaudeAnalyzer`/`MockAnalyzer` docs), `ai_pr_reviewer/heuristics.py` (deprecation notice + module warning + stale cli.py claim removed), `ai_pr_reviewer/github_client.py` (`TYPE_CHECKING` import fixing the pre-existing F821 — zero runtime change); `.github/workflows/ci.yml` (additive pinned `lint` job; matrix comment reworded to state the T03 policy — matrix itself unchanged); `pyproject.toml` (ruff comment: now enforced in CI); `README.md` (Report JSON section 23+23 fields, Configuration layering section, §5 Supported Python versions + PYTHONUTF8 gotcha, §7 Versioning/pinning/release checklist, Layout deprecation notes); `CHANGELOG.md` (new `Unreleased` section: Added/Deprecated/Changed/Fixed/Security), `CONTRIBUTING.md` (Python matrix + lint gate, Demo fixtures & regeneration gotcha incl. audit result, CHANGELOG-entry requirement); new tests: `tests/test_deprecation.py` (5) + `tests/test_readme_contract.py` (6), `tests/test_evaluation_harness.py` (+1 lint-job structural guard; job-set snapshot += `lint`, a deliberate ticket-authorized evolution) | **886 passed, 2 skipped, 3 warnings** (1 pre-existing + 2 new facade notices), `python -m ruff check .` green, `git diff --check` clean, no sample churn (regen gotcha observed then restored to clean), `python -m eval.harness --gate` OK (8 cases, labels 12/12) | none (no commit unless requested) | **V3-E06 complete 6/6** (T01→T02→T03→T04→T05→T06). Closes D11 (facade deprecation, removal v4.0.0 no earlier than 2027-04-07) and D14 (ruff `lint` job mutation-verified + Python policy stated once, matrix unchanged). Premise reconciliations: D11 "no production caller" true only for the dead entry points (StaticAnalyzer/AnalysisOutcome/heuristics are production — warned at module boundary only); fixture "samples rewritten by build_all()" stale for the suite (conftest → temp dir), true only for direct `python demo/make_fixtures.py` (CRLF churn observed + restored). AGENTS.md (protected) has stale gotchas → flagged, not edited. **Phase 0 6/6 COMPLETE. STOPPED.** Next dependency-ready: V4-E01 (not started, out of scope) |
