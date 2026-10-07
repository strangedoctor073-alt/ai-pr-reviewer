# EPIC BACKLOG — V3 → V10 (AI GitHub PR Reviewer, V3)

> Status: planning document (v1) — epic hierarchy, canonical 57-epic list, and
> proposed tickets, grounded in `CURRENT_ARCHITECTURE.md` (verified current
> state: diagrams, defects D1-D7, constraints C1-C14, stable assumptions,
> keep/evolve/replace, storage model, Action contract) and `MASTER_VISION.md`
> (vision, 12 planes, product boundaries, OSS strategy) at commit 2841b23.
> No source code, tests, CI, or non-`docs/planning/` files were modified.

---

## 1. Hierarchy rules, ID scheme, and what a ticket is

**Hierarchy:** Stage → Epic → Ticket. Nothing else is planned at this level.

- **Stage** = generation of capability. Canonical order, fixed:
  `Phase 0 / "V3.x"` (V3 validation & hardening) → `V4` (deep repository
  intelligence) → `V5` (multi-agent engineering review) → `V6`
  (security+testing+architecture intelligence) → `V7`
  (historical/project/team intelligence) → `V8`
  (CI/release/incident intelligence) → `V9` (organization platform) → `V10`
  (ecosystem/platform).
- **Epic** = a coherent capability slice that delivers user-visible value and
  can ship independently. An epic has an exit criteria list; when all exit
  criteria verifiably pass, the epic is done. Epics are never split across
  stages.
- **Ticket** = the smallest reviewable unit of implementation work: one PR-sized
  change (or a tightly coupled pair) with its own acceptance criteria and
  rollback story. A ticket must be implementable without needing to know the
  rest of the plan beyond its stated dependencies.

**ID scheme:**

| Level | Pattern | Example |
|---|---|---|
| Epic | `Vn-Enn` | `V4-E05` |
| Ticket | `Vn-Enn-Tnn` | `V4-E05-T03` |

IDs are **permanent**. A ticket that is descoped is `CANCELLED`, never renumbered.
A split produces `T03a`/`T03b`. Stage prefix encodes the stage the epic was
planned in, not the calendar date it ships.

**Ticket vs epic test:** if the work cannot be described with 1-3 acceptance
criteria and a single rollback strategy, it is an epic (or an epic that needs
decomposition), not a ticket.

**Dependency verbs used below:** `hard` = cannot start or cannot land before the
provider; `soft` = strongly improves odds / avoids rework, but work can proceed.

---

## 2. Epic entries (57)

### Phase 0 — "V3.x" (V3 validation & hardening)

#### V3-E01 · correctness defect triage
- **Purpose**: Fix the seven verified correctness/security defects D1-D7 before any new capability is built on top of them.
- **User value**: Reviews cite the right code (base revision, not head), no finding is ever falsely closed or silently dropped, comment caps behave as documented, config typos fail cleanly.
- **Current state**: D1 `base_sha` never set — `github_client.py:80-89,111-120`, fallback `repo_context.py:238`; D2 verification receives capped list — `orchestrator.py:183-189` vs `verification.py:85-136`; D3 below-threshold findings dropped — `orchestrator.py:79-84`, `reporter.py:316-318`; D4 `max_comments` caps whole report — `orchestrator.py:174-176` vs `action.yml:44`; D5 no severity sort before caps — `orchestrator.py:82` (only `static/engine.py:72` sorts); D6 raw `ValueError` on numeric `INPUT_*` — `config.py:113,119,129`; D7 mute not idempotent — `dashboard/storage.py:337`.
- **Target state**: All seven fixed with regression tests; triage ledger closed; no behavior change outside the defect semantics.
- **Dependencies**: hard: —; soft: `V3-E03` (regression coverage), `V3-E05` (config validation hardening).
- **Architecture impact**: Small, surgical: `github_client` populates `PRContext.base_sha`; orchestrator splits *reported* vs *verified* vs *posted* finding lists; `validate_findings` gains a sort + threshold-recording step.
- **Security impact**: High — D1 is a base-revision invariant violation (context fetched at untrusted PR head). Fix must not weaken `.ai-pr-reviewer.yml` base-revision trust model.
- **Testing impact**: New regression tests per defect (D1 needs a `get_pr`/`get_event_context` fixture, not a hand-built `PRContext`); suite must stay green at 464+.
- **Migration impact**: Report JSON gains fields (suppressed-below-threshold list) — additive only. Comment volume on large PRs may rise (previously silent findings now appear in summary) — deprecation note in CHANGELOG.
- **Cost impact**: Neutral to slightly positive token use (uncapped verification list is internal, not prompt content).
- **Complexity**: M — seven small fixes, but D2/D3/D4 reshape the findings pipeline and interact; Risk: M — changing `base_sha` alters which repo files are fetched and could regress incremental mode if tested only by hand.
- **Exit criteria**: `get_pr()`/`get_event_context()` set `base_sha` and a test fails if they don't; verification receives the uncapped list (test: top-20-capped still-present finding stays `active`); below-threshold findings appear in report with a `suppressed` marker; comment cap and report cap are independent config; `INPUT_PR_NUMBER=abc` exits `1` with a clear message; repeat mute on same fingerprint creates exactly one row.

#### V3-E02 · telemetry foundation
- **Purpose**: Make cost/token/latency measurable end-to-end — nothing can be managed that isn't measured (prerequisite for every later cost/budget epic).
- **User value**: Users see what a review costs in tokens/ms, per provider and per batch; maintainers can prove budget changes didn't regress cost.
- **Current state**: Token usage counted on Claude/OpenAI provider instances but **never surfaced** (absent from `AnalysisOutcome`, report, storage, dashboard); Gemini usage parsing is a TODO in code; no cost model, no per-batch latency — constraint C6.
- **Target state**: Telemetry record produced by every run (tokens in/out, per-batch latency, provider, model, fallback events), carried through `AnalysisOutcome` → report JSON → storage → dashboard `/api/metrics`.
- **Dependencies**: hard: —; soft: `V3-E03` (baseline the numbers), `V3-E04` (storage seam for persisting telemetry).
- **Architecture impact**: `AnalysisOutcome` and report JSON gain additive fields; a small telemetry collector (likely module under `ai_pr_reviewer/`) replaces ad-hoc per-provider counters; `model_router` becomes the aggregation point.
- **Security impact**: Medium — telemetry must pass `redact_secrets()` before storage/posting; never include prompt bodies or file content in telemetry.
- **Testing impact**: Unit tests for counter aggregation and redaction; a golden-report test asserting telemetry fields exist and are numeric.
- **Migration impact**: Additive JSON fields only; dashboard schema gains nullable columns (hand-rolled `ALTER TABLE` is acceptable at this size — see `V3-E04`).
- **Cost impact**: This *is* the cost epic's foundation; the collector itself costs ~nothing (in-process counters).
- **Complexity**: M — plumbing across provider/router/report/storage/dashboard with a hard no-secret-leak constraint; Risk: L — additive, well-isolated.
- **Exit criteria**: Every provider (incl. Gemini) reports token usage or an explicit "usage unavailable" marker; report JSON contains tokens/latency for mock and live runs; telemetry survives storage round-trip; a redaction test proves no key material can appear in stored telemetry.

#### V3-E03 · evaluation harness foundation
- **Purpose**: Build the offline, deterministic harness that measures review *quality* (not just behavior) so every later intelligence epic has a regression gate.
- **User value**: Prevents silent quality regressions; lets maintainers compare engines/configs on the same corpus; gives contributors a fast local quality check.
- **Current state**: Absent — the 464-test suite is behavior/contract oriented (`tests/`), `demo/` provides sample diffs and fixtures but no scoring; there is no corpus, no metric definition, no baseline file.
- **Target state**: A harness (likely module + `tests/` integration) that runs the engine over a golden corpus (`demo/samples/*.diff` extended), scores findings against expected labels, and emits a comparable report; wired into CI as a non-flaky check.
- **Dependencies**: hard: —; soft: `V3-E01`, `V3-E02` (harness reports defects fixed + cost per run).
- **Architecture impact**: None on production code — harness is test-side only; must reuse `--mock`/`--static` deterministic path so it needs no API keys (AGENTS.md: suite is fully offline).
- **Security impact**: Fixtures must contain no secrets, real PR diffs, or dashboard data (`CONTRIBUTING.md` constraint).
- **Testing impact**: The epic *is* testing infrastructure; adds corpus files + a scoring module + a CI step that must not break the `python -m pytest tests/ -q` contract.
- **Migration impact**: None for users; the corpus is internal. Note `tests/test_pipeline.py` / `test_static_engine.py` rewrite `demo/samples/*.diff` (line endings) — harness must tolerate or isolate that.
- **Cost impact**: Free (offline, mock engine); later doubles as multi-agent cost/quality benchmark (`V5-E08`).
- **Complexity**: L — metric definition is the hard part (what counts as a true positive in review?) and must stay deterministic; Risk: M — a badly designed metric becomes a False gate that blocks good changes.
- **Exit criteria**: One command runs the corpus and prints a score; score is byte-stable across runs on the same commit; a deliberately broken fixture lowers the score (proven by test); CI runs it without network or API keys.

#### V3-E04 · storage & dashboard debt remediation
- **Purpose**: Pay down constraint C9 (unbounded growth, unclosed connections, three duplicated schema implementations, O(all) queries) before any stage adds new entities to storage.
- **User value**: Dashboard stays fast as history grows; no fd leaks in long-lived dashboard processes; adding entities later has one place to change, not three.
- **Current state**: `LocalReviewStorage` opens a connection per call and never closes it, no retention/pruning; `DbStorage` (SQLAlchemy) and `JsonStorage` duplicate the same logical schema plus the HTTP contract; `review_id` parsing and `"fingerprint:"` literals duplicated across modules; dashboard `list_findings`/`stats`/`metrics` load all rows into Python; hand-rolled `ALTER TABLE` migrations; `dashboard/data/.gitkeep` missing on clean checkout (known failing test).
- **Target state**: Connections context-managed and closed; retention/pruning policy (config-driven, off by default); shared schema/constants module consumed by all three backends; dashboard queries paginated/indexed; `.gitkeep` restored; a written decision recorded on when to adopt a real migration tool.
- **Dependencies**: hard: —; soft: `V3-E01` (D7 mute idempotency lands in the same storage code).
- **Architecture impact**: Strengthens the `ReviewStorage` Protocol seam (`storage.py`) — the seam every future epic (memory, evidence, telemetry, org) extends; may promote the two `getattr`-guarded optional capabilities into declared, capability-flagged methods.
- **Security impact**: Low — retention must not prune audit/privacy-relevant rows silently (document what is kept); token file perms unchanged.
- **Testing impact**: Parity suite asserting all three backends behave identically (including `getattr`-guarded paths); connection-leak test; pagination tests with synthetic large datasets.
- **Migration impact**: Additive columns/tables only; existing `review_state`, `finding_history`, `repo_memory`, `reports` rows preserved; hand-rolled `ALTER TABLE` kept for now, migration-tool adoption marked **proposal** pending `V4` schema growth.
- **Cost impact**: Neutral; prevents future cost of O(all) scans on large dashboards.
- **Complexity**: L — touches three storage implementations + HTTP contract with zero tolerance for data loss; Risk: M — storage bugs are silent until users lose history.
- **Exit criteria**: No unclosed SQLite connections (test asserts cleanup); a 50k-row fixture paginates dashboard findings/stats in bounded time; shared constants module exists and all three backends import it; retention job is idempotent and off by default; clean checkout passes `test_gitkeep_placeholder_exists`.

#### V3-E05 · config & contract hardening
- **Purpose**: Freeze the public contract (Action inputs/outputs, exit codes, report JSON, config layering) with tests, and close the duplicate-baseline and silent-cap defects (D6 follow-through, D12, D13).
- **User value**: Upgrades can't silently break workflows; config errors are actionable; security baselines can't diverge between engine and dashboard.
- **Current state**: Defaults duplicated across `action.yml`, `config.py`, CLI args; D12 sensitive-path baselines duplicated between `rules.py` and `dashboard/app.py`, synced only by convention; D13 caps hard-coded at 8 sites (8 context files, 4 config probes, 50 memory entries, 20 comments, 500 dashboard findings, 8 markdown findings); no snapshot test freezes inputs/outputs/exit codes; numeric parsing crash covered by `V3-E01-T06`.
- **Target state**: Single source of defaults; a contract snapshot test covering `action.yml` inputs/outputs + exit codes 0/1/2 + report JSON top-level fields; shared sensitive-baseline module; caps centralized as named constants with documented rationale.
- **Dependencies**: hard: `V3-E01` (D6 numeric parsing must land first); soft: `V3-E06` (docs reflect the frozen contract), `V3-E04` (storage contract included in the snapshot).
- **Architecture impact**: Consolidates config layering (CLI > `INPUT_*` > env > defaults) into validated parsing; establishes the compatibility contract later codified in `MIGRATION_PLAN.md`.
- **Security impact**: High-value — single non-removable privacy baseline implementation (currently `rules.py` vs `dashboard/app.py` divergence is a silent-failure risk); config validation must not echo secrets in error text.
- **Testing impact**: Snapshot/contract tests for inputs, outputs, exit codes, report schema; a test that fails if a cap constant is re-hardcoded outside the shared module.
- **Migration impact**: Additive-only rule becomes mechanically enforced; unknown future inputs warned (not fatal) to preserve forward compatibility.
- **Cost impact**: None.
- **Complexity**: M — mostly mechanical, but the snapshot test must be stable across cosmetic `action.yml` edits; Risk: L — additive hardening.
- **Exit criteria**: Renaming an `action.yml` output fails CI via snapshot test; duplicating a sensitive glob outside the shared module fails CI; `fail_on`/`max_comments`/`batch_chars` garbage values exit `1` with a config message (no traceback); contract test enumerates exit codes 0/1/2.

#### V3-E06 · documentation & release hygiene
- **Purpose**: Remove doc/code drift and land the missing engineering gates (D11, D14) so the codebase can grow without accumulating contradictions.
- **User value**: Contributors trust the docs; users know exactly which Python/model/Action versions are supported; releases are pinned and auditable.
- **Current state**: D11 legacy facades `analyzer.py`/`heuristics.py`/`get_analyzer` have stale docstrings and no production caller; D14 no lint/type gate in CI (ruff configured, not installed), Python support story split (Action 3.12, CI 3.11-3.13, local 3.14); `README.md` is primary doc; `example-workflow.yml` must stay on `pull_request` + base checkout; planning doc set (`TARGET_ARCHITECTURE.md`, `MASTER_ROADMAP.md`, `ADR_INDEX.md`, …) referenced but not all present yet.
- **Target state**: Facades retired behind deprecation notices; ruff (and optionally mypy, non-strict) enforced in CI; Python support matrix stated once and consistent across README/AGENTS/CI/action; planning docs cross-linked and complete; CHANGELOG discipline for every contract change.
- **Dependencies**: hard: —; soft: `V3-E01`..`V3-E05` (docs describe post-fix behavior).
- **Architecture impact**: None functionally; deletes two dead import paths (`analyzer`, `heuristics`) that currently mislead contributors about the composition root.
- **Security impact**: Positive — CI lint catches security-adjacent mistakes early; doc pass re-verifies the invariants (no `pull_request_target`, no `checks: write`, base checkout).
- **Testing impact**: Adds a lint step that must pass on the current tree first (baseline before enforce); tests for the deprecation warning path.
- **Migration impact**: Removing facades is technically a breaking change for any external importer — deprecation window + CHANGELOG entry + grep for external references before removal.
- **Cost impact**: CI minutes increase slightly (lint job is seconds).
- **Complexity**: S — well-understood mechanical work with one care point (facade removal must not break the dashboard's runtime `sys.path` import of engine code); Risk: L.
- **Exit criteria**: `analyzer`/`heuristics` emit `DeprecationWarning` and README states removal release; `ruff` runs green in CI; Python version statement is identical in README, `action.yml`/CI, and AGENTS.md; `python -m pytest tests/ -q` still fully offline and green.

---

### V4 — Deep repository intelligence

> **V4 scope record — approved 2026-10-07 (C0-T01).** The V4 execution plan
> (charter: 14 hard rules; evaluation-first; additive-only; no V3 breaking
> changes) supersedes the *ticket outlines* in this file where they conflict;
> epic IDs are unchanged and are never renumbered. Active epics:
> **P0 — E01, E02, E04, E05, E08 · P1 — E03, E09, E10, E11**.
> **Deferred: E06 (digital twin seed), E07 (read contracts)** — IDs reserved,
> outlines below are dormant; do not work them. Rejected for V4: autonomous
> fixes, multi-agent/critic loops, embeddings/RAG, cost-based routing,
> provider specialization, local models, Checks API, enterprise SSO/RBAC,
> microservices, auto-reseverity, auto-mute, votes-in-prompt, dashboard
> config editing. Compatibility: report schema, Action inputs/outputs, config,
> and storage are **additive-only**; `@v3.0.0` remains valid forever; V4 ships
> as a new immutable tag.
>
> **Supersession — material deltas from the outlines below:**
> 1. **The index is ephemeral** (per-run, budgeted, optional gitignored
>    cache): old `V4-E01-T01` (persistent storage schema) and `V4-E01-T03`
>    (incremental refresh) are **out of V4 scope**; no `repo_index` table
>    (ADR-022 trigger review recorded 2026-10-07).
> 2. **Evidence ships embedded on findings** (additive `evidence[]` +
>    pipeline-owned provenance already at `models.py:142-147`): old
>    `V4-E04-T02`'s separate persistent evidence store is deferred with the
>    content-addressed part of ADR-004 (V4 staging note, 2026-10-07).
> 3. **Identity is layered with no cutover** (ADR-005 approved 2026-10-07):
>    old `V4-E05-T03` (alias table), `V4-E05-T04` (backfill) and
>    `V4-E05-T06` (cutover to v2 authority) are **rejected** — v1 stays the
>    storage key; the occurrence key is computed, never authoritative.
> 4. **E06/E07 are deferred**: their outlines below are dormant; minimal
>    read needs fold into E01/E02.
>
> **Approved V4 ticket manifest** — this table is the ID/title authority;
> per-ticket detail is issued batch-by-batch:
>
> | Epic | Tickets |
> |---|---|
> | C0 | T01 adoption checkpoint (ADR-022 review) · T02 ADR-005 reconciliation · T03 context contract (ADR-017) · T04 evaluation metrics · T05 ADR-004 approval |
> | V4-E01 | T01 file inventory · T02 symbol-lite extraction · T03 import graph · T04 context budgets · T05 pipeline wiring (no prompt change) · T06 index tests |
> | V4-E02 | T01 selection result model · T02 selection algorithm · T03 provider prompt wiring · T04 relevance@10 · T05 context documentation |
> | V4-E03 | T01 impact specification · T02 bounded traversal · T03 impact prompt section · T04 evaluation case |
> | V4-E04 | T01 provenance design (DONE in code) · T02 finding evidence · T03 multi-source provenance extension (additive) · T04 D10 report surfacing · T05 static evidence normalization |
> | V4-E05 | T01 identity specification · T02 occurrence-key implementation · T03 cross-engine dedup · T04 continuity tests · T05 static floor (P2, optional) |
> | V4-E08 | T01 threat model · T02 untrusted repo-context fencing · T03 index security limits · T04 provider warning sanitization (debt 11) · T05 output redaction chokepoint · T06 feedback poisoning protection · T07 security regression suite |
> | V4-E09 | T01 feedback schema · T02 persist votes · T03 suppression rules · T04 staging application · T05 disable+expiry · T06 isolation/security · T07 effectiveness evaluation |
> | V4-E10 | T01 comment fingerprints · T02 sticky summary · T03 lifecycle sync · T04 lifecycle safety tests · T05 additive outputs |
> | V4-E11 | T01 corpus expansion · T02 precision/recall gate · T03 relevance gate · T04 severity/finding/fix metrics · T05 verification metric · T06 latency (+ telemetry ingestion route, debt 15) · T07 cost table (debt 9) · T08 Tier-B providers · T09 CI quality gates |
>
> Threats: `V4_THREAT_MODEL.md` (E08-T01) · Metrics: `TESTING_EVALUATION_PLAN.md`
> §8 · Contracts: `ADR_INDEX.md` (ADR-004/005/017/022, ratified 2026-10-07).

#### V4-E01 · repository index
- **Purpose**: Build the deterministic repository index (files, symbols, imports, structure) that every later intelligence capability reads instead of the current 8-file bounded fetch.
- **User value**: Reviews understand cross-file references, real import chains, and project layout rather than guessing from the diff alone.
- **Current state**: Absent — `repo_context.py` does a bounded best-effort fetch (≤16 probes, 12k chars, capped at 8 context files / 4 config probes per D13), documented as a *seed*; `diff_parser.py` parses only the diff; no symbol/import table anywhere (explicitly "must be built" in `CURRENT_ARCHITECTURE.md` §14).
- **Target state**: A new subsystem: index built from the checked-out base revision, stored in a new store (SQLite/file — no graph DB per ADR-002), queried by the context engine; built incrementally per review, bounded by size/time budgets.
- **Dependencies**: hard: `V3-E01` (must index the *base* revision — D1 fix is the precondition), `V3-E04` (storage seam), `V3-E02` (telemetry drives budgets), `V3-E03` (quality gate); soft: —.
- **Architecture impact**: New likely module (index builder) + new storage entity; `repo_context.py` becomes a consumer, not the retrieval mechanism; `context.py` gains an index-backed retrieval path behind a capability check.
- **Security impact**: Index content is **untrusted repository data** — must pass `_safe_repo_path`, fencing, and injection screening before reaching prompts; index must never include secret-bearing files (privacy baseline applies to the index too).
- **Testing impact**: Determinism tests (same tree → same index), budget-bound tests, injection tests on adversarial file contents; corpus reuse from `V3-E03`.
- **Migration impact**: Absent-index behavior must equal today's behavior (graceful degradation); index is a new store with its own retention, no migration of existing data.
- **Cost impact**: Index build is CPU/disk, not tokens; index-backed retrieval should *reduce* tokens by fetching precisely instead of broadly.
- **Complexity**: XL — language-aware symbol/import extraction plus budget/safety bounds is the largest single new subsystem of V4; Risk: H — quality of extraction determines whether V4 intelligence is real or decorative.
- **Exit criteria**: Index builds offline on this repo in bounded time/size (proposed baseline: ≤10 s, ≤50 MB — to be re-measured); a symbol lookup returns definition + importers for a known function; with the index absent, review output is byte-identical to pre-V4; a malicious symlink/`../` path cannot enter the index (test).

#### V4-E02 · context engine v2
- **Purpose**: Replace static character budgets (C7) with token-aware, relevance-ranked retrieval over the repository index, while keeping the bounded-everything principle.
- **User value**: The prompt gets the *right* context (relevant symbols, called functions, config) within a real token budget → fewer hallucinated findings, fewer missed cross-file bugs.
- **Current state**: `context.py` assembles context with independent character caps (`batch_chars` 80k, `repo_context_chars` 12k) that are never summed and misnamed `token_budget` (C7); single shared `SYSTEM_PROMPT` copy-pasted across 3 providers (C2); `_apply_context_budget` truncates, does not rank.
- **Target state**: Retrieval API over the index with relevance scoring (deterministic-first), a unified token-aware budget manager (chars→token estimate with headroom), and prompt assembly extracted into one shared layer (also unblocks `V5-E02`).
- **Dependencies**: hard: `V4-E01`; soft: `V3-E02` (measure token deltas), `V4-E03` (impact analysis feeds relevance ranking).
- **Architecture impact**: `context.py` becomes an orchestrator over retrieval + budget modules; shared prompt-builder is the single wiring point for all providers (removes C2 triplication); budget becomes a first-class object, not scattered constants.
- **Security impact**: Retrieved content is untrusted → reuses fencing/redaction on *every* retrieval path; budget exhaustion must degrade loudly (never silently drop security context — product boundary).
- **Testing impact**: Retrieval relevance tests against the golden corpus; budget-sum tests proving no path exceeds the token ceiling; prompt-assembly snapshot tests shared across providers.
- **Migration impact**: Existing `INPUT_*` budget fields keep working (mapped to token-equivalents with a deprecation note); `.ai-pr-reviewer.yml` schema unchanged.
- **Cost impact**: Directly reduces tokens per review (proposed baseline: ≥20% median reduction on the golden corpus — mark as proposed baseline); must be proven by `V3-E03` harness.
- **Complexity**: L — retrieval + budget + prompt extraction, all testable offline; Risk: M — bad relevance silently worsens reviews, which only the harness can catch.
- **Exit criteria**: One budget object governs all context (test sums all contributors); no provider duplicates prompt assembly (grep-level test); token estimate vs actual stays within a stated tolerance; below-threshold/security-relevant context is never the thing truncated (test).

#### V4-E03 · change impact analysis
- **Purpose**: Given a diff, determine what else it affects — callers, dependents, tests, config — and feed that into review focus and risk.
- **User value**: Reviewers get "this change touches the refund path used by 3 modules and 2 tests" instead of a flat file list; missed blast radius becomes a first-class signal.
- **Current state**: Absent — only diff-scoped data exists (`diff_parser.py`, `filter_files`); `repo_context.py` fetches a handful of related files heuristically; no import/call graph exists anywhere.
- **Target state**: Bounded impact propagation over the index graph: direct dependents → N-hop (small N) → impact set with confidence labels; consumed by context assembly, risk (`V5-E04`), and report rendering.
- **Dependencies**: hard: `V4-E01` (graph comes from the index); soft: `V4-E02` (impact results feed retrieval ranking).
- **Architecture impact**: New likely module (analysis over index data); no new store; must expose results through the read contract (`V4-E07`) rather than reaching into the index directly.
- **Security impact**: Impact output is derived from untrusted source — treat like index content (fenced, redacted, no absolute paths); never lets an untrusted path name drive file reads.
- **Testing impact**: Determinism + bounded-complexity tests (huge fan-out must cap, not explode); golden cases for known call chains in fixtures.
- **Migration impact**: Purely additive signal — absent graph ⇒ empty impact set ⇒ behavior unchanged.
- **Cost impact**: CPU-bound; if impact enters prompts it adds tokens — must go through the `V4-E02` budget with an explicit cap.
- **Complexity**: L — propagation is simple, honest confidence labeling and bounding are the real work; Risk: M — wrong impact claims erode trust more than no claims.
- **Exit criteria**: Known call chain yields the full dependent set with confidence; a pathological fan-out fixture terminates under a documented cap; impact absent ⇒ zero behavioral diff; every impact claim carries provenance (which index entry, which hop).

#### V4-E04 · evidence engine & provenance
- **Purpose**: Give every finding an evidence record with provenance — the enforcement of vision principle #1 ("evidence-driven, never assertion-driven") and the hard prerequisite for multi-agent merge (C3).
- **User value**: "Why was I told this?" becomes answerable: the exact lines read, the model, the rule, the tool output, with a visible confidence and an explicit "we don't know" state.
- **Current state**: Absent — `Finding` has no provenance fields (C3: no engine/model/agent/origin); report shows `engine`/`model` at run level only; cross-engine dedup destroys attribution; council merge is impossible; evidence store listed as "must be built".
- **Target state**: Evidence record type (source kind, locator, content hash, captured-at, confidence) + provenance fields on `Finding`; persisted in a new store; rendered in report JSON and dashboard; feeding verification tiers later.
- **Dependencies**: hard: — (models-layer change can start immediately); soft: `V4-E01` (index entries become evidence sources).
- **Architecture impact**: `models.Finding` gains additive optional fields (must not break `from_untrusted_dict` lifecycle-stripping invariant — provenance is pipeline-owned like lifecycle fields); new evidence store behind the storage seam; reporter/dashboard render new fields.
- **Security impact**: Evidence content may quote code/secrets → `redact_secrets()` on everything persisted or displayed; evidence must be treated as untrusted-derived in prompts; privacy baseline applies to what evidence may capture.
- **Testing impact**: Provenance round-trip tests; test that model output cannot forge provenance (via `from_untrusted_dict` stripping); redaction test on evidence payloads.
- **Migration impact**: Old findings without provenance must render as "provenance unavailable", never crash; report JSON additive fields only.
- **Cost impact**: Hashing/storage is cheap; storing evidence increases DB size — pair with `V3-E04` retention policy.
- **Complexity**: L — schema + pipeline plumbing + rendering, with the invariant that model output stays untrusted; Risk: H — everything downstream (V5 merge, V6 verification, V7 relations, V8 correlation) inherits its shape, so a weak schema is expensive to fix later.
- **Exit criteria**: Every finding in a report carries provenance (or an explicit null with reason); model-supplied provenance in output JSON is stripped by `from_untrusted_dict` (test); evidence persists and reloads byte-identically; dashboard shows provenance without leaking redacted content.

#### V4-E05 · finding identity v2
- **Purpose**: Fix the title-based fingerprint's documented cross-engine dedup gap (C4) with a v2 identity that survives engine/wording changes — without orphaning a single existing fingerprint.
- **User value**: The same real issue is one finding, not three (one per engine/rewrite); lifecycle history stays intact across the migration; no duplicate comments.
- **Current state**: `findings.py:fingerprint_finding` = `sha256(category|file|normalized_title)[:16]`, line deliberately excluded (churn keeps identity) — but wording changes across engines break identity (documented dedup gap); relations have no stable identity to attach to; migrations must not orphan existing rows (`finding_history` keyed by `repo#pr#fp`).
- **Target state**: v2 identity (proposed basis: category + file + anchored location range + normalized semantic anchor — final spec in ADR) with **layered identity**: v1 fingerprint remains the primary key; provenance fields (engine, model, agent, origin) are added; an occurrence key enables cross-engine matching; no cutover — v1 stays authoritative. See ADR-005.
- **Dependencies**: hard: `V4-E04` (provenance/origin participates in identity decisions); soft: `V3-E03` (measures dedup quality before/after).
- **Architecture impact**: `findings.py` fingerprint function gains provenance fields and an occurrence key; v1 fingerprint remains primary; all fingerprint consumers (`findings`, `verification`, dashboard feedback/mute routes, `github_sync` comment-id harvesting) continue to work on v1; the occurrence key is additive for cross-engine dedup.
- **Security impact**: Identity inputs must come from pipeline-owned data, never model output; provenance fields are pipeline-owned (like `LIFECYCLE_FIELDS`) — model output cannot set them.
- **Testing impact**: Property tests (v1 stable across runs), alias-resolution tests, duplicate-comment regression tests across two engines; migration test on a seeded pre-v2 database.
- **Migration impact**: **MUST NOT orphan existing fingerprints** — layered model specified in `MIGRATION_PLAN.md`; v1 fingerprints remain primary with zero migration; provenance and occurrence key are additive; dashboard mute rows keyed by v1 fingerprints keep working unchanged.
- **Cost impact**: Negligible compute; avoids duplicate-comment token cost later.
- **Complexity**: XL — touches every fingerprint consumer plus a live data migration with zero-loss requirement; Risk: H — identity bugs silently split or merge findings and corrupt lifecycle history.
- **Exit criteria**: A finding re-reported by a different engine dedups to one identity via the occurrence key (harness case); existing v1 fingerprints resolve unchanged (test); provenance fields are populated on all new findings (test); muting a pre-v2 fingerprint still mutes it (test).

#### V4-E06 · digital twin seed
- **Purpose**: Create the *seed projection* of the digital twin — the layered index snapshot of repo structure/ownership/dependency state — without building a separate CQRS/GRAPH system (vision §5-D).
- **User value**: Later stages get one coherent, versioned "what this repository is" snapshot to reason over, instead of re-deriving structure per review.
- **Current state**: Absent — `repo_context.py` + `diff_parser.py` are the only seed; no snapshot, no layering, no versioning of structural state.
- **Target state**: A projection built from the V4 index: layers (files → symbols → modules → dependency edges), versioned by commit SHA, stored alongside the index, readable through the intelligence contract; updated incrementally as reviews run.
- **Dependencies**: hard: `V4-E01`, `V4-E02`; soft: `V4-E03` (impact results enrich the projection).
- **Architecture impact**: Explicitly a *projection* (read model), not an event-sourced store — it derives from index + git state and can always be rebuilt; no new write-path subsystem.
- **Security impact**: Inherits index trust rules; twin content used in prompts must be fenced/redacted; twin must not become a covert channel for untrusted repo content into trusted config.
- **Testing impact**: Rebuild-equivalence test (projecting twice = identical); incremental update equals full rebuild on the corpus.
- **Migration impact**: None — new derived data, fully rebuildable, disposable on rollback.
- **Cost impact**: Storage only; rebuild is CPU — bounded by index budgets.
- **Complexity**: M — mostly disciplined projection code if V4-E01 is solid; Risk: M — scope creep toward the "separate twin system" anti-pattern must be actively refused.
- **Exit criteria**: Twin snapshot exists per commit and is rebuildable from scratch; incremental update is proven equal to full rebuild (test); no event-sourcing/graph-DB dependency introduced; consumers read it only via the `V4-E07` contract.

#### V4-E07 · intelligence read contracts
- **Purpose**: Publish the read-only interface through which all intelligence artifacts (index, impact, evidence, twin) are consumed — so downstream epics depend on a contract, not on internal module shapes.
- **User value**: Indirect but foundational: stable contracts mean later features (reviewers, dashboard, plugins) don't churn when index internals change; graceful "intelligence unavailable" behavior for users.
- **Current state**: Absent — `repo_context` and `context` are consumed directly by the orchestrator; the two `getattr`-guarded optional `ReviewStorage` capabilities show the current pattern (undeclared, silently varying by backend).
- **Target state**: A declared read protocol (likely module, mirroring the `ReviewStorage`/`AIProvider` seam pattern) with explicit capability flags, availability states (`available|building|degraded|absent`), and a contract test kit every backend/implementer must pass.
- **Dependencies**: hard: `V4-E01`, `V4-E04`; soft: `V4-E02`, `V4-E06`.
- **Architecture impact**: Extends the repo's proven "protocol seam" pattern (§13.10) to intelligence; establishes the shape later versioned by `V9-E03` (API platform) and implemented by `V10-E01` (plugins).
- **Security impact**: Contract forbids untrusted-content escapes: no method may return content that hasn't passed fencing; the contract is the enforcement point for that rule.
- **Testing impact**: A reusable conformance suite (like protocol tests for `ReviewStorage` but explicit); absent/degraded-state tests.
- **Migration impact**: None — new contract over new capabilities; existing paths untouched.
- **Cost impact**: None directly.
- **Complexity**: M — interface design is cheap, getting the availability/degradation semantics right is the work; Risk: L if kept read-only and small.
- **Exit criteria**: Two independent implementations pass the same conformance suite; orchestrator consumes intelligence only through the protocol (import-lint test); `absent` state is handled by a tested code path, not an exception.

#### V4-E08 · intelligence security & budgets
- **Purpose**: Harden every *new* untrusted-input surface V4 introduces (indexed repo content, retrieved snippets, impact/twin data) and bound its compute/token cost (vision §5-T: security upgraded at each stage).
- **User value**: The new intelligence cannot be prompt-injected via a crafted repository, and won't blow the token/time budget on a huge repo.
- **Current state**: Partial — `security.py` provides fencing, 8-pattern injection screening (warnings only), 14-pattern redaction, `_safe_repo_path`; but none of it is wired against index/retrieval paths (they don't exist yet), and there is no budget object for index builds.
- **Target state**: Screening/fencing/redaction applied on every intelligence read path by construction (via the `V4-E07` contract); explicit budgets for index build time/size, retrieval hops, and prompt-attached intelligence tokens; adversarial corpus covering repo-content injection.
- **Dependencies**: hard: `V4-E01`, `V4-E02` (there must be surfaces to secure); soft: `V4-E04` (evidence records capture security events).
- **Architecture impact**: Security becomes a property of the retrieval contract, not per-caller discipline; budgets join the `V4-E02` budget object.
- **Security impact**: This epic *is* security — highest-priority gate for V4; must preserve non-removable privacy baseline and base-revision trust model for anything index-derived.
- **Testing impact**: Adversarial fixtures (symlinks, `../` paths, fence-spoofing file contents, injection patterns in symbols/comments); budget-exhaustion tests must show loud degradation, not silent truncation of security context.
- **Migration impact**: None for existing users; screening additions may raise new warnings on previously-accepted content (documented).
- **Cost impact**: Bounds *other* epics' cost — this is the guardrail V5 fan-out later reuses.
- **Complexity**: L — broad surface audit + adversarial tests; Risk: H — an unsecured intelligence path is a prompt-injection vector into every future review.
- **Exit criteria**: Every intelligence read path passes through fencing/redaction (enforced by contract conformance test); adversarial corpus returns zero injected instructions into the prompt (test); index build and retrieval abort with a warning when budgets are exceeded; no privacy-baseline file can enter the index (test).

---

### V5 — Multi-agent engineering review

#### V5-E01 · fan-out orchestration
- **Purpose**: Add a bounded fan-out layer that runs multiple specialist analyses concurrently — the structural answer to C1 (one provider per run, first-success failover).
- **User value**: A single review gets multiple independent expert angles instead of one generalist pass, within a hard concurrency/cost bound.
- **Current state**: Absent — `model_router.run_analysis` is sequential primary→secondary→static; circuit breakers are process-global with one half-open trial and assume sequential use (C5); no merge primitive.
- **Target state**: New orchestration layer above `model_router`: spawns N specialist tasks with bounded concurrency, per-task isolation (breaker/circuit scope), partial-failure tolerance (some specialists failing ⇒ degraded but valid review), feeding `V5-E03` merger.
- **Dependencies**: hard: `V4-E04` (provenance), `V4-E05` (identity for merge), `V4-E07` (contracts), `V3-E02` (cost telemetry); soft: `V3-E03` (harness measures multi-agent quality), `V3-E04` (concurrency-safe storage).
- **Architecture impact**: The largest architectural addition since V3: `orchestrator.py` splits into review orchestrator + fan-out layer; C5 breakers must be re-scoped per task (process-global state becomes a liability); determinism of the overall pipeline must survive concurrency.
- **Security impact**: Each task is a new untrusted-input boundary; specialist prompts inherit fencing from `V4-E08`; concurrency must not weaken rate-limit or redaction discipline; no specialist may post to GitHub (only the merger output does).
- **Testing impact**: Determinism under concurrency (same inputs ⇒ same merged output regardless of task completion order); partial-failure tests; harness extension later via `V5-E08`.
- **Migration impact**: Single-agent path stays the default until fan-out proves out (config flag, default off); Action contract unchanged.
- **Cost impact**: Up to N× tokens — gated by `V5-E07` arbitration and budgets from `V3-E02`; must never fan out without a budget.
- **Complexity**: XL — concurrency, failure semantics, determinism, and cost control at once; Risk: H — cost blowups, nondeterministic merges, and breaker races are all live failure modes.
- **Exit criteria**: Fan-out with 1 specialist produces byte-identical output to single-agent (test); one specialist hard-failing still yields a valid, honestly-attributed review; concurrency cap and token ceiling are enforced, not advisory (test); no specialist performs GitHub I/O (test).

#### V5-E02 · specialist reviewer contracts
- **Purpose**: Define what a specialist reviewer *is* — inputs, outputs, scope, and non-goals — and extract the shared prompt-builder that C2 currently blocks.
- **User value**: Reviews come from named, understandable roles (security, tests, API-shape, performance…) with predictable focus, instead of one generic prompt.
- **Current state**: Absent — single shared `SYSTEM_PROMPT` copy-pasted across `ai/claude.py`, `ai/openai.py`, `ai/gemini.py` (C2), `_extract_json` triplicated; no role concept anywhere; static rule packs are the only "specialists" and are deterministic.
- **Target state**: A declared specialist contract (name, focus, inputs, output schema, tool/deterministic-check slots) + one shared prompt/parse layer consumed by all providers; deterministic tooling (regex/AST/API-shape) wired as first-class specialist steps where it beats AI.
- **Dependencies**: hard: `V4-E04`, `V5-E01`; soft: `V4-E02` (shared prompt extraction lands there first).
- **Architecture impact**: Removes the C2 triplication permanently; specialists declare capabilities consumed by `V5-E05` routing; contract output = `AnalysisOutcome`-shaped with provenance.
- **Security impact**: Each specialist prompt is an injection surface → fencing enforced by the shared builder; specialist output is untrusted and flows through existing validation (`from_untrusted_dict` unchanged).
- **Testing impact**: Contract conformance per specialist; prompt snapshot tests; deterministic-tool specialists get exact-match tests.
- **Migration impact**: Single "generalist" specialist is the v1 default — behavior-compatible; `.ai-pr-reviewer.yml` may later select specialists (additive schema, staged).
- **Cost impact**: Specialists can *reduce* tokens by narrowing scope; net effect measured by `V5-E08`.
- **Complexity**: L — contract design + refactor, well-guarded by the shared builder; Risk: M — over-broad specialists degenerate into N copies of the same review.
- **Exit criteria**: No provider module contains prompt text (grep test); every specialist passes a conformance suite; a deterministic specialist and an AI specialist both satisfy the same output contract; the generalist default reproduces pre-V5 output on the corpus.

#### V5-E03 · finding merger
- **Purpose**: Merge findings from multiple specialists into one deduplicated, provenance-preserving, consistently-ranked finding set (the missing half of C3/C4).
- **User value**: Users see one coherent review — one finding per real issue, with all supporting specialist opinions attached — not N conflicting lists.
- **Current state**: Absent — `findings.deduplicate` is title-based, first-wins, single-stream; documented that cross-engine wording differences don't dedup; no ranking beyond static's own sort (D5 fixed in `V3-E01`).
- **Target state**: Merger operating on identity-v2 + provenance: cross-specialist dedup, agreement/conflict recording, severity reconciliation with deterministic rules, stable global ordering before any cap.
- **Dependencies**: hard: `V4-E04`, `V4-E05`, `V5-E02`; soft: `V3-E03` (dedup-quality metrics).
- **Architecture impact**: New deterministic merge module between fan-out and the existing lifecycle/verification pipeline; ranking becomes a single owned step (closing the D5 class of bug structurally).
- **Security impact**: Merge output must not let a lower-trust specialist upgrade a finding's severity beyond rules; redaction applied post-merge on the unified payload.
- **Testing impact**: Golden merge cases (agreeing, conflicting, reworded, cross-engine duplicate); determinism test (task order irrelevant); harness scoring of merged output.
- **Migration impact**: Single-stream path bypasses the merger by default ⇒ byte-compatible until fan-out enabled.
- **Cost impact**: Merge itself is deterministic/cheap; saves tokens by preventing re-review of duplicates.
- **Complexity**: L — deterministic rules, but severity reconciliation policy is a real design decision; Risk: M — a bad merge silently hides findings (worst-case failure for a reviewer).
- **Exit criteria**: Same issue from 2 specialists = 1 finding with 2 provenance records (test); conflicts produce an explicit conflict record, never a silent winner (test); merged output passes pre-existing lifecycle/verification unchanged; harness shows dedup precision ≥ single-stream baseline (proposed baseline).

#### V5-E04 · risk engine & adaptive depth
- **Purpose**: Compute an explainable risk score for the change and route review depth accordingly (vision §5-G/H: informational until proven, cheap and explainable).
- **User value**: Trivial docs PRs get fast shallow reviews; auth/payment changes get deeper multi-angle review — better quality per token.
- **Current state**: Minimal — `classify_risk` exists at run level (large-PR threshold 30 files raises a label); `review.mode` is a static config; no feature-based risk, no depth routing; health score is output, not input.
- **Target state**: Risk features derived from deterministic signals (size, surface sensitivity from policy/focus, impact set from `V4-E03`, history from later stages), each shown with its contribution; depth policy maps risk → specialist set/budget within `V5-E01` fan-out bounds.
- **Dependencies**: hard: —; soft: `V3-E02` (cost data), `V4-E03` (impact features), `V5-E07` (budget coupling).
- **Architecture impact**: New likely module producing an explainable score; feeds fan-out sizing — must stay a *deterministic* function (vision principle #2: no AI for state/authority).
- **Security impact**: Risk must never *reduce* below the security baseline depth (no "low risk ⇒ skip security checks" escape); focus/exclude policy can add risk signals but not remove security coverage.
- **Testing impact**: Explainability assertions (score = sum of shown contributions); monotonicity tests; A/B via `V3-E03` harness that adaptive depth doesn't lose findings on high-risk fixtures.
- **Migration impact**: Default stays current fixed depth until the engine proves out (flag, default off); existing `review.mode` continues to work.
- **Cost impact**: This is a cost-*shaping* epic: proposed baseline ≥15% token reduction on low-risk fixtures at equal harness score (mark as proposed baseline).
- **Complexity**: M — the engine is simple; proving "informational until proven" without a good metric is the real risk; Risk: M — premature depth reduction loses findings and destroys trust.
- **Exit criteria**: Every score ships its feature contributions in the report; no config path can disable security-specialist depth below baseline (test); adaptive mode matches fixed-mode harness score on high-risk fixtures; default configuration produces pre-V5 behavior.

#### V5-E05 · provider capability registry & task routing
- **Purpose**: Replace the 7 hard-coded provider wiring sites with a capability registry that routes each task to a provider/model able to run it (vision §5-U).
- **User value**: Adding or switching providers stops being a 7-site edit; users get honest errors when a model can't do a task, instead of silent degradation.
- **Current state**: Adding a backend touches `AI_BACKENDS`, `select_backend`, `build_provider`, `Config`/`load_config`, CLI args, `action.yml`, reporter labels (§10.1); no capability declaration, no per-backend retry config, no discovery; only Claude has a default model (retired-ID guard is test-enforced).
- **Target state**: Registry entry per backend (capabilities, context window, cost class, tool support, default-model policy), consumed by routing for both single-agent and fan-out tasks; config validation consults the registry for actionable errors.
- **Dependencies**: hard: `V3-E02` (telemetry feeds capability/cost data); soft: `V5-E01` (tasks to route), `V5-E02` (task types from specialist contracts).
- **Architecture impact**: `model_router` becomes registry-driven; the 7-site wiring collapses to registry + CLI; OpenAI-compatible `base_url` endpoints register as configurable-capability providers.
- **Security impact**: Registry must keep the no-retired-model-IDs invariant (registry data validated by the existing release scan); capability claims are untrusted config-adjacent data → validated, not assumed.
- **Testing impact**: Registry conformance per backend; routing tests (task requiring capability X never routed to provider lacking it); the existing retired-model scan extended to registry files.
- **Migration impact**: Existing `provider_order`/`model`/`base_url` inputs keep exact semantics (registry maps them, doesn't replace them); Action contract unchanged.
- **Cost impact**: Enables cost-aware routing (a cheap model for cheap tasks) — quantified only after `V5-E07`.
- **Complexity**: M — mostly restructuring existing knowledge into data; Risk: L — additive behind unchanged inputs.
- **Exit criteria**: Adding a mock backend requires touching exactly one registry file (test demonstrates it); routing rejects impossible task/provider pairs with a config error (exit 1); all current inputs behave identically (contract snapshot from `V3-E05` passes); retired-ID scan covers registry.

#### V5-E06 · council synthesis
- **Purpose**: Synthesize merged specialist findings into a single coherent review narrative with explicit disagreement handling (vision §5-F).
- **User value**: The review reads as one expert opinion that acknowledges "the security specialist flagged X, the test specialist disagreed, evidence says…", rather than a pile of disconnected notes.
- **Current state**: Absent — one `summary` string from one provider; no cross-finding narrative, no disagreement concept.
- **Target state**: A synthesis step (AI for summarization/judgment — permitted by principle #2) over the deterministic merger output: narrative summary, disagreement/confidence section, per-finding pointers back to evidence; budgeted as one bounded call.
- **Dependencies**: hard: `V5-E03` (needs merged findings); soft: `V5-E04` (risk shapes emphasis), `V3-E03` (quality gate).
- **Architecture impact**: One new step after merge, before reporter; output schema fixed so reporter/dashboard stay provider-agnostic.
- **Security impact**: Synthesis is a second untrusted-model-output surface → same validation + fencing + redaction discipline; it may *summarize* evidence but never *create* findings or alter lifecycle fields (pipeline-owned invariant).
- **Testing impact**: Tests that synthesis cannot add/modify findings (only annotate); disagreement-section presence tests; golden summaries on the corpus.
- **Migration impact**: Off until fan-out on; single-agent path keeps its existing summary (compatibility).
- **Cost impact**: One bounded call per review — must be covered by the arbitration budget (`V5-E07`).
- **Complexity**: L — bounded step with a strict output contract; Risk: M — a hallucinating synthesis can misrepresent findings even if findings themselves are correct.
- **Exit criteria**: Synthesis output cannot change the finding set (test: injected "add a finding" instruction in specialist output is ignored); every narrative claim links to an evidence ID (test); disabled flag reproduces pre-V5 summary exactly.

#### V5-E07 · cost/token arbitration
- **Purpose**: Turn measured telemetry (`V3-E02`) into an enforceable per-review budget that arbitrates how many specialists/models/synthesis a run may buy.
- **User value**: Predictable cost per review with a hard ceiling; users choose economy/balanced/maximum and actually get the cost profile they chose.
- **Current state**: No cost data surfaced anywhere (C6); `response_budget` input exists (economy/balanced/maximum/automatic, `action.yml`) but is not backed by token accounting; budgets are characters and never summed (C7).
- **Target state**: Budget ledger per run: reserve → allocate across specialist tasks/synthesis → enforce hard stop with honest degradation ("specialist 4 skipped: budget exhausted" in warnings); per-model cost table; dashboard cost views.
- **Dependencies**: hard: `V3-E02`, `V5-E05` (cost per routed model); soft: `V5-E01`, `V5-E04` (spend shaped by depth).
- **Architecture impact**: Budget object from `V4-E02` gains a ledger; fan-out consults it before spawning; enforcement is deterministic (no mid-response truncation of a model call — reserve up front).
- **Security impact**: Budget warnings must be redacted like all output; budget exhaustion must never silently drop security-critical context (product boundary) — it degrades *depth*, loudly.
- **Testing impact**: Ledger arithmetic tests; exhaustion tests proving warnings + attribution; no-double-spend under concurrency.
- **Migration impact**: Existing `response_budget` input now actually means something — same keyword set, documented mapping (additive semantics, no input change).
- **Cost impact**: This *is* the cost-control epic; target: hard ceiling never exceeded (proposed baseline: 0 overruns across harness runs — mark as proposed baseline).
- **Complexity**: M — accounting + concurrency, given telemetry already exists; Risk: M — off-by-one reservations either waste budget or overrun.
- **Exit criteria**: A run provably never exceeds its configured ceiling (test with expensive fake provider); every skipped task appears in warnings with reason; `response_budget` maps to documented ceilings; dashboard shows spend per run.

#### V5-E08 · multi-agent evaluation harness
- **Purpose**: Extend the `V3-E03` harness to score multi-agent output — merge quality, disagreement handling, cost/quality curves — so fan-out is held to evidence, not enthusiasm.
- **User value**: Users can trust that multi-agent mode is measurably better (or be shown it isn't); maintainers can tune depth/council without blind changes.
- **Current state**: Absent — `V3-E03` harness (once built) covers single-stream only; no multi-agent corpus, no cost-per-quality metric.
- **Target state**: Harness gains specialist-scenario cases, merge-precision/recall scoring, cost-per-true-positive curves, and an A/B mode (single vs multi on same corpus) as a CI gate.
- **Dependencies**: hard: `V3-E03`, `V5-E01`; soft: all other V5 epics (each adds measurable behavior).
- **Architecture impact**: Test-side only; must keep the offline/no-API-key property for CI, with an optional credentialed nightly lane for live models.
- **Security impact**: Corpus still must contain no secrets/real diffs (`CONTRIBUTING.md`); adversarial cases reused from `V4-E08`/`V6-E08`.
- **Testing impact**: The epic is the testing asset for all of V5; adds flakiness control (multi-agent nondeterminism must be pinned or sampled with stable aggregates).
- **Migration impact**: None for users.
- **Cost impact**: Free offline; live lane cost bounded by budget (proposed baseline: ≤$X/night — TBD, mark as proposed baseline).
- **Complexity**: L — scoring multi-agent output honestly is genuinely hard; Risk: M — a weak metric green-lights expensive regressions.
- **Exit criteria**: A/B report (single vs multi, score + cost) generated by one command; CI gate blocks merge-precision regressions; flakiness below a stated threshold over N repeat runs (proposed baseline); offline mode requires no keys.

---

### V6 — Security + testing + architecture intelligence

#### V6-E01 · security engine
- **Purpose**: Promote security from static rule pack + prompt guidance to a dedicated deterministic security analysis engine with its own severity model.
- **User value**: Security issues get specialized, explainable, deterministic detection with consistent severity — independent of whichever LLM ran.
- **Current state**: Partial — `security.py` (fence/screen/redact) protects *the system*; `static/` SEC001-008 rules flag security smells in diffs; `.ai-pr-reviewer.yml` carries security focus rules as free-text prompt guidance (no rule toggles); no dedicated security engine or dataflow analysis.
- **Target state**: New likely module: security analyzers (pattern + dataflow-lite over the diff and index), normalized security findings with CWE-style classification and severity, consumable both as static findings and as evidence for specialists.
- **Dependencies**: hard: `V4-E04` (evidence/provenance), `V4-E01` (index for cross-file analysis); soft: `V5-E02` (feeds the security specialist).
- **Architecture impact**: Extends `static/` registry pattern into a named sub-engine; deterministic-first (principle #2), so results are testable without keys.
- **Security impact**: This is the security-content epic; false-negative cost is high, false-positive cost is trust — both need the evaluation corpus (`V6-E08`).
- **Testing impact**: Rule-by-rule unit tests + corpus scoring; severity calibration tests.
- **Migration impact**: New findings appear in existing report shape (new categories) — additive; users' `severity_threshold` semantics unchanged.
- **Cost impact**: Deterministic — zero tokens for the core; AI augmentation (if any) is budgeted.
- **Complexity**: L — many rules, but each is small and testable; Risk: M — noisy security findings drive users to mute the whole category.
- **Exit criteria**: Each analyzer rule has a positive and negative fixture; security findings carry evidence + CWE reference; corpus false-positive rate under a stated threshold (proposed baseline: <10% — mark as proposed baseline); works with `--mock` (no keys).

#### V6-E02 · AI security v2
- **Purpose**: Upgrade the *system-vs-model* security layer: adversarial prompting, model-output attacks, and the new V4-V5 untrusted surfaces beyond today's 8 static patterns.
- **User value**: Reviews stay trustworthy under adversarial PRs designed to manipulate the reviewer (e.g. "ignore previous instructions" embedded in code/comments).
- **Current state**: `security.py` scans 8 injection patterns → warnings only (forensic, not blocking); fences/spoof-neutralization for diff content; model output filtered for lifecycle fields; no attacks modeled against retrieved index content, specialist prompts, or synthesis.
- **Target state**: Layered AI-security: injection detection upgraded for retrieved/context content, model-output attack patterns (exfiltration instructions, tool-abuse attempts), prompt-perimeter tests, and per-stage surface checklist (V4 index, V5 agents, V7 memory, V8 CI content, V9 webhooks, V10 plugins — vision §5-T).
- **Dependencies**: hard: `V6-E01` (engine to attach findings to); soft: `V4-E08`, `V5-E01` (surfaces already secured, this hardens them).
- **Architecture impact**: Screening becomes a staged pipeline (ingress → retrieval → prompt → model-output → egress) with one config point instead of scattered calls.
- **Security impact**: Highest — but scoped to *adversarial* ML-abuse, distinct from `SECURITY_ROADMAP.md`'s baseline; must preserve "warnings, not censorship" posture unless a pattern is proven exploitable.
- **Testing impact**: Adversarial suite (each pattern has an exploit-shaped fixture + a benign false-positive guard); regression runs in `V6-E08`.
- **Migration impact**: New warnings may appear on previously-accepted content — documented, and warning-not-fatal by default (forensic posture preserved).
- **Cost impact**: Detection is cheap; extra prompt-hardening tokens are budgeted.
- **Complexity**: L — pattern/detector work with hard false-positive constraints; Risk: M — over-blocking destroys review usefulness.
- **Exit criteria**: Every V4/V5 untrusted surface has a screening test; adversarial fixtures are detected and benign twins are not; no pattern can leak secrets in its own warning text; staged-perimeter checklist documented and enforced by tests.

#### V6-E03 · test intelligence
- **Purpose**: Understand a repository's tests — what exists, what the change touches, what's missing — and turn that into evidence for review and verification.
- **User value**: "This changes auth and adds no auth test" becomes a finding backed by actual test-coverage evidence, not a generic prompt suggestion.
- **Current state**: Absent — tests are only file paths in the diff (`diff_parser`), excluded like any other file if configured; no test inventory, no coverage linkage, no test-health signal (only later `V8-E02` failure data).
- **Target state**: Test index from `V4-E01` (test files, frameworks, test→module mapping where derivable), change-to-test coverage gap analysis, test evidence records feeding verification tiers (`V6-E05`).
- **Dependencies**: hard: `V4-E01` (index); soft: `V6-E05` (consumes as evidence), `V8-E02` (later failure/health data).
- **Architecture impact**: Extends index schema with test taxonomy; produces evidence records via `V4-E04`; no new store.
- **Security impact**: Test code is untrusted repo content too (fencing applies); coverage-gap findings must never recommend disabling/weakening tests (echoes `.ai-pr-reviewer.yml` rule intent).
- **Testing impact**: Fixture repos with known test layouts; determinism of mapping; false-positive control via `V6-E08`.
- **Migration impact**: Additive findings category; excluded paths (privacy baseline) remain excluded — test intelligence must not read excluded files.
- **Cost impact**: Deterministic core; zero added tokens unless surfaced into prompts (budgeted).
- **Complexity**: L — deriving test→module mapping without running the suite is heuristic; Risk: M — wrong "missing test" claims are annoying and erode trust.
- **Exit criteria**: Known fixture maps changed module → existing tests (or explicit none); excluded/secret paths never indexed as tests; gap findings cite the changed symbols as evidence; absent index ⇒ no test-intelligence findings (no crash).

#### V6-E04 · architecture intelligence
- **Purpose**: Detect and evidence architectural properties of the change: layering violations, dependency-direction breaches, boundary drift against an explicit architecture model.
- **User value**: Reviews catch "controller now imports repository internals" and "this layering rule broke" — the class of PR humans argue about in hindsight.
- **Current state**: Absent — no architecture model, no layering rules, `.ai-pr-reviewer.yml` `rules:` are free-text prompt guidance only; `repo_context` sees at most 8 files.
- **Target state**: Declarative architecture description (modules/layers/allowed-dependency-directions, stored as trusted repo config), checked deterministically against the index graph, plus drift reporting vs prior state (twin from `V4-E06`).
- **Dependencies**: hard: `V4-E01`, `V4-E06`; soft: `V4-E03` (impact analysis shares the graph).
- **Architecture impact**: New likely module (architecture rules over index); the architecture description itself is a new trusted-config section (additive `.ai-pr-reviewer.yml` schema, later org-wide in `V9-E02`).
- **Security impact**: Architecture config is read from the trusted base revision like all policy; violations are findings, never auto-fixes (no code modification, ever).
- **Testing impact**: Fixtures with deliberate violations; absence-of-model ⇒ silent no-op test; calibration via `V6-E08`.
- **Migration impact**: Fully opt-in (no architecture model ⇒ zero new findings); existing configs unaffected.
- **Cost impact**: Deterministic — zero tokens.
- **Complexity**: L — rule engine over an existing graph, if V4 holds; Risk: L (opt-in) but adoption risk if config burden is high.
- **Exit criteria**: A fixture with an explicit architecture model reports its violations with the offending edge as evidence; no model ⇒ byte-identical output (test); violations never trigger remediation code paths (test).

#### V6-E05 · advanced verification tiers
- **Purpose**: Extend the deterministic 3-state verification model with evidence tiers (static analysis, test execution evidence) while keeping the current coverage check as the floor.
- **User value**: "Resolved" becomes meaningfully stronger: a fix can be confirmed by running the relevant test or static analysis, not only by diff-coverage heuristics.
- **Current state**: `verification.py` — deterministic, no-I/O coverage check over the flagged line range (`all|partial|none|file-missing`) + `_unverify()`; 3 states; no test execution, no static re-check; D2 (capped-list input) fixed in `V3-E01`.
- **Target state**: Tiered verification: T0 diff coverage (existing floor) → T1 static analysis confirms pattern gone → T2 test evidence (from CI/test intel) confirms behavior; each finding records which tier verified it; escalation is opt-in and budgeted.
- **Dependencies**: hard: `V4-E04` (evidence), `V6-E03` (test evidence source); soft: `V8-E02` (CI failure data strengthens T2).
- **Architecture impact**: `verification.py` stays the deterministic core but gains tier handlers; **no verification step performs arbitrary I/O by default** — T2 consumes *recorded* evidence (from CI ingest) rather than executing tests inside the review (execution belongs to the user's CI, not our Action).
- **Security impact**: Verification evidence is untrusted-derived (CI logs, test output) → redaction mandatory; verification must never be markable-by-model (pipeline-owned state invariant preserved).
- **Testing impact**: Per-tier state-machine tests; evidence-forgery tests (model-supplied "tests pass" evidence ignored); existing 464-test invariants must hold unchanged.
- **Migration impact**: Existing 3-state outputs remain valid (tier is an additive field); dashboard/report consumers unaffected until they opt in.
- **Cost impact**: T0/T1 deterministic (free); consuming CI evidence costs nothing extra; never runs tests in the Action (bounded).
- **Complexity**: L — state machine extension with a strict "evidence, not execution" boundary; Risk: M — a wrong "resolved" is the most costly error class in this domain.
- **Exit criteria**: A finding can carry tier+evidence and still round-trip through old consumers (additive test); model-provided evidence is rejected (test); T0 behavior is bit-identical to today's when no higher evidence exists; no new network I/O added to verification (test/lint).

#### V6-E06 · dependency intelligence
- **Purpose**: Analyze the repository's dependency posture: what's declared, what the change adds/updates, known-risk signals (license, staleness, advisories where locally available).
- **User value**: "This PR adds an unmaintained transitive dep with a copyleft license" becomes an evidence-backed finding at review time.
- **Current state**: Absent — dependency manifests are ordinary files, usually excluded by default patterns (e.g. `**/*.lock` in this repo's own config); no manifest parsing, no advisory source.
- **Target state**: Manifest parsers (pip/npm/etc. — deterministic), diff-aware change detection (added/updated/removed deps), advisory lookup **only from locally-configured/offline sources by default** (no implicit external calls), evidence records per signal.
- **Dependencies**: hard: `V4-E01`; soft: `V6-E01` (security severity model), `V8-E05` (infra overlap).
- **Architecture impact**: New likely module (manifest readers) over the index; advisory source is a pluggable read-only interface (later fed by `V8-E07` events) — no new write paths.
- **Security impact**: Advisory data is external/untrusted → validated, fenced, redacted; **no network calls by default** preserves the offline/hermetic property; excluded paths stay excluded (privacy baseline wins over dependency visibility — documented).
- **Testing impact**: Manifest fixtures per ecosystem; offline-default test (no HTTP); exclusion-respected test.
- **Migration impact**: Additive findings; default-off for ecosystems with no parser config; lockfile exclusions mean partial visibility until users opt in (documented).
- **Cost impact**: Deterministic — free; optional advisory refresh is a scheduled, budgeted fetch (opt-in).
- **Complexity**: M — parsers are mechanical, advisory sourcing policy is the careful part; Risk: L.
- **Exit criteria**: Added dependency in a fixture produces a finding with manifest+line evidence; no-network default asserted by a test; privacy-excluded manifests are not read (test); ecosystem coverage stated explicitly (start: pip + npm — proposed).

#### V6-E07 · policy engine v1
- **Purpose**: Turn policy from "free-text prompt rules + one threshold" into an evaluated, explainable policy engine (repo/team scopes), the deterministic enforcement arm of governance (vision §5-R).
- **User value**: Teams express enforceable rules ("auth changes require tests", "no new deps in this path") that produce consistent findings with cited clauses — instead of hoping the LLM reads the YAML.
- **Current state**: `rules.py` parses `.ai-pr-reviewer.yml` (`review.mode`, `review.severity_threshold`, `rules`, `exclude`, `focus`) with a non-removable exclusion baseline; `rules:` is prompt guidance only — nothing evaluates it; dashboard has its own rules editing surface.
- **Target state**: A policy schema v2 (additive) with structured, machine-checkable clauses; a deterministic evaluator producing policy findings with clause provenance; evaluation interface designed for org-level reuse in `V9-E02`; still no auto-remediation.
- **Dependencies**: hard: `V4-E04` (clause provenance); soft: `V3-E05` (config contract hardening), `V6-E01`/`V6-E03` (clauses over security/test intel).
- **Architecture impact**: New likely module (policy evaluator) behind a stable interface; `rules.py` keeps loading v1 schema and forwards (layering preserved: CLI > `INPUT_*` > env > defaults, project policy merged as today).
- **Security impact**: Policy is trusted config read from base revision; the non-removable privacy baseline is **never** expressible as removable policy (invariant preserved and test-enforced); evaluator must not become a code-modification trigger.
- **Testing impact**: Clause evaluation fixtures (pass/fail/unknown); v1-schema compatibility tests; baseline-removal-must-fail test.
- **Migration impact**: v1 configs keep working untouched (structured clauses are additive keys); unknown clause types degrade to guidance-with-warning, not fatal (forward compat).
- **Cost impact**: Deterministic — free.
- **Complexity**: L — schema + evaluator + strict backward compat; Risk: M — policy engines invite scope creep into full OPA-land, which is out of scope for v1.
- **Exit criteria**: A structured clause in a fixture config yields a finding citing its clause ID; v1-only config produces byte-identical behavior (test); privacy baseline cannot be weakened by any config (test); evaluator interface is documented for `V9-E02` reuse.

#### V6-E08 · security evaluation corpus
- **Purpose**: Give security work a measurable gate: a corpus of vulnerable and secure code patterns with expected detections, wired into the harness.
- **User value**: Security improvements are provable and regressions are caught before release; users can see detection/false-positive rates instead of taking them on faith.
- **Current state**: Absent — `demo/samples/*.diff` are demo fixtures, not labeled security cases; no labeled corpus, no detection metrics.
- **Target state**: Labeled corpus (vulnerable variants + benign twins + false-positive guards) covering `V6-E01`/`V6-E02` rules, scored by the `V3-E03` harness, gated in CI.
- **Dependencies**: hard: `V6-E01`, `V3-E03`; soft: `V6-E02` (adversarial cases).
- **Architecture impact**: Test-side only; corpus stored as fixtures (no secrets/real diffs — `CONTRIBUTING.md`).
- **Security impact**: Corpus is security-sensitive material — must be synthetic, license-clean, and contain no working exploit payloads beyond minimal detection triggers (documented handling).
- **Testing impact**: The epic *is* the gate: detection-rate and false-positive-rate thresholds become CI assertions.
- **Migration impact**: None.
- **Cost impact**: Free offline.
- **Complexity**: M — corpus curation is labor, engineering is light; Risk: L — main risk is a corpus that only tests the rules as written (tautology), mitigated by benign twins.
- **Exit criteria**: Every `V6-E01` rule has ≥1 vulnerable + ≥1 benign fixture; detection/false-positive rates are CI-enforced numbers; corpus runs fully offline; coverage gaps are listed explicitly.

---

### V7 — Historical / project / team intelligence

#### V7-E01 · git history intelligence
- **Purpose**: Index git history (commits, authors-as-roles, churn, co-change, prior decisions) as a first-class intelligence source.
- **User value**: Reviews know "this function changed 6 times this quarter, twice fixing bugs" and surface regression-prone context the diff alone can't show.
- **Current state**: Absent — only `compare_commits` for incremental diffs and the `last_reviewed_sha` pointer; no history indexing, no churn/blame intelligence (`P` capability area: V7).
- **Target state**: History index (bounded depth/time), churn & co-change signals, changelog/decision retrieval; served through the `V4-E07` read contract; consumed by `V7-E06` and analytics.
- **Dependencies**: hard: `V4-E01`; soft: `V4-E06` (twin gains history layer).
- **Architecture impact**: Extends the index with a history layer (git is the source of truth — no parallel event store); all reads budgeted.
- **Security impact**: Commit messages/author metadata are untrusted (and often contain secrets/PII) → fencing + redaction mandatory; authorship is used as *role signal*, never for individual ranking (vision §6 boundary).
- **Testing impact**: Fixture repos with crafted history; bounded-depth tests; redaction tests on commit-message content.
- **Migration impact**: New store/layer only — nothing existing changes.
- **Cost impact**: CPU/disk; retrieval tokens bounded via `V4-E02` budget.
- **Complexity**: L — git plumbing + bounded queries; Risk: M — history data is noisy; over-trusting it produces confident wrong context.
- **Exit criteria**: Churn/co-change queries return correct results on a crafted fixture repo; untrusted commit-message content cannot reach a prompt un-fenced (test); depth/time budgets enforced (test); no individual-ranking fields produced (test).

#### V7-E02 · memory hierarchy & authority model
- **Purpose**: Evolve flat human-authored repo memory into a hierarchy (org→team→repo→component→PR→finding) with a strict authority model (ADR-003): AI observations never become permanent truth automatically.
- **User value**: Institutional knowledge accumulates in the right scope and stays trustworthy — reviewed facts at repo level, decisions at team level — without the engine writing its own canon.
- **Current state**: `memory.py` + `repo_memory` table: human-authored notes only, engine read-only, fenced when embedded; mutes are `fingerprint:<fp>` rows; no levels, no promotion workflow, no authority rules.
- **Target state**: Scoped memory levels with precedence resolution, explicit provenance class (`human-authored` vs `observed` vs `inferred`), a promotion workflow requiring human approval, and a read API that labels authority on every item.
- **Dependencies**: hard: `V3-E04` (storage must handle new entity safely); soft: `V4-E04` (provenance classes), `V4-E05` (memory entries reference findings by fingerprint), `V7-E01` (history informs observation).
- **Architecture impact**: `memory.py` becomes a hierarchy-aware layer over an extended storage schema; the engine keeps read-only authority — writes only via human/CI-approved paths (stable assumption §13.4).
- **Security impact**: Memory poisoning is the threat: observed/inferred items must be visibly labeled and structurally unable to override human-authored policy or the privacy baseline; promotion is an audited, human-gated operation.
- **Testing impact**: Authority precedence tests; "AI observation cannot satisfy a policy clause" test; poisoning fixtures (untrusted PR content attempting memory writes).
- **Migration impact**: Existing `repo_memory` rows import as `human-authored` at repo scope (highest authority) — zero semantic change for current data.
- **Cost impact**: Negligible; memory retrieval is token-bounded (existing 50-entry cap centralizes into budget).
- **Complexity**: L — schema + precedence + promotion workflow; Risk: H — authority bugs silently convert guesses into organizational truth, violating a hard product boundary.
- **Exit criteria**: No code path lets engine output write `human-authored` memory without human action (test); precedence is total and tested across all level pairs; migrated rows retain authority class; every memory read carries its authority label in output.

#### V7-E03 · finding relations
- **Purpose**: Model relationships between findings (duplicate-of, causes, supersedes, regression-of) on top of identity v2 — turning isolated findings into a graph.
- **User value**: Duplicates collapse visibly, a root cause is linked to its symptoms, and a reopened finding shows what previously fixed it.
- **Current state**: Absent — dedup is first-occurrence-wins with a documented cross-engine gap (C4); no relation concept; `finding_history` tracks state only; identity too weak to attach relations to (fixed by `V4-E05`).
- **Target state**: Relation records (typed, provenance-bearing, confidence-labeled) computed deterministically where possible, AI-proposed-but-human/lifecycle-confirmed where not; surfaced in report + dashboard; storage additive.
- **Dependencies**: hard: `V4-E05` (stable identity is the anchor); soft: `V7-E01` (history distinguishes regression-of).
- **Architecture impact**: New entity behind the storage seam; merge (`V5-E03`) and lifecycle consume relations; rendering in reporter/dashboard additive.
- **Security impact**: Relations must not let untrusted model output forge links that suppress findings (a "duplicate-of" claim is never a drop — merged findings keep provenance); redaction on relation notes.
- **Testing impact**: Relation round-trip + lifecycle interaction tests (a relation can't falsely resolve); adversarial "mark everything duplicate" fixture.
- **Migration impact**: Additive — existing findings simply have no relations until computed; identity-v2 aliasing (from `V4-E05`) keeps relations from orphaning.
- **Cost impact**: Near-zero storage/compute; token cost only if relations enter prompts (budgeted).
- **Complexity**: M — schema + deterministic computation + conservative AI proposals; Risk: M — wrong relations mislead (e.g. false duplicate-of hiding a real issue).
- **Exit criteria**: A duplicate pair across two engines links as one relation with both provenances retained (test); relations never remove a finding from the report (test); relation graph survives identity migration (seeded-DB test); every relation carries source + confidence.

#### V7-E04 · issue/requirement linkage
- **Purpose**: Link reviews to issues/requirements (read-only GitHub issue/PR data) so findings can be tied to intent — and gaps reported as evidence-backed signals, never asserted compliance (vision §5-Z).
- **User value**: A reviewer can say "this PR references #123 but the linked requirement's acceptance criteria aren't addressed" — with the criteria quoted as evidence.
- **Current state**: Absent — `github_client` reads PR metadata/diff/comments only; no issue fetching, no requirement model, no linkage concept.
- **Target state**: Read-only ingestion of linked issues/requirements (PR body refs, issue text), retrieval of their content as context/evidence, and gap *signals* labeled as signals — explicitly no compliance claims.
- **Dependencies**: hard: `V4-E04` (evidence); soft: `V7-E01` (history cross-links), `V8-E01` (CI linkage later).
- **Architecture impact**: `github_client` gains read endpoints (respecting C8 rate-limit awareness work); requirement extraction is a likely module producing evidence, not state.
- **Security impact**: Issue/comment text is untrusted (injection surface already noted in security diagram) → fenced/redacted like diffs; no new write permissions (permissions stay `pull-requests: write` + `contents: read`; reading issues uses the same token — verify scope, document it).
- **Testing impact**: Linkage fixtures with crafted (injecting) issue text; "signal not compliance" wording assertion test; rate-limit handling tests.
- **Migration impact**: Additive — no issue data ⇒ behavior unchanged; new API calls are best-effort with degrade-and-warn (stable assumption §13.6).
- **Cost impact**: Additional GitHub API calls (C8 aware — must add rate-limit handling here or earlier); token cost of issue context bounded by `V4-E02` budget.
- **Complexity**: M — mostly retrieval + conservative claims; Risk: M — over-claiming requirement coverage violates a hard product boundary.
- **Exit criteria**: Linked issue text reaches the prompt only fenced+redacted (test); output never contains a compliance/coverage *claim* — only cited signals (assertion test); absent issues ⇒ zero behavior change; API usage stays within documented rate-limit budget.

#### V7-E05 · team/repository analytics
- **Purpose**: Produce repository/team trend analytics (review volume, finding categories over time, hotspots) from platform data — trends and hotspots only, explicitly no individual performance rankings (vision §5-AD, §6).
- **User value**: Maintainers see where review attention and defect categories are trending, and which modules keep generating findings.
- **Current state**: Minimal — dashboard `/api/stats` and `/api/metrics` compute from stored reports (all rows into Python, C9); report JSON has counts; no time-series model, no hotspot concept, no analytics store.
- **Target state**: Analytics as derived read-models over reports/findings/history (aggregated at ingest, not O(all) scans), surfaced in the dashboard; every metric documented with its derivation.
- **Dependencies**: hard: `V3-E04` (storage performance + retention); soft: `V7-E01` (churn hotspots), `V3-E02` (cost/telemetry series).
- **Architecture impact**: Aggregation-at-write replaces O(all) reads; analytics is a projection, rebuildable from source data (no event-sourcing requirement).
- **Security impact**: **Hard boundary**: no individual identifiers in metrics (no author scores, no rankings); repo/org scope only; aggregates must be non-invertible for small cohorts (k-threshold for small-N groups — proposed baseline k=5, mark as proposed baseline).
- **Testing impact**: Aggregation correctness tests; a "no individual dimension" schema test; rebuild-equivalence (projection == recompute).
- **Migration impact**: Existing reports are backfillable into aggregates (additive); old rows without new fields aggregate into "unknown" buckets, never dropped.
- **Cost impact**: Write-time aggregation costs a little per review; saves the O(all) read cost permanently.
- **Complexity**: M — classic aggregate/projection work with a hard privacy constraint; Risk: M — privacy boundary is a product-boundary violation if crossed accidentally.
- **Exit criteria**: Metric definitions documented and reproducible from raw data (test); no metric schema contains an individual-identifying dimension (schema test); small-cohort suppression enforced; dashboard queries run bounded on a large fixture.

#### V7-E06 · historical evidence in review
- **Purpose**: Feed history/memory/relations into live reviews as bounded, provenance-tagged evidence — the payoff loop where past reviews make future reviews better (vision §2 loop).
- **User value**: The reviewer remembers: "this exact finding was dismissed last month with reason X", "this area regressed twice before" — and says so, with provenance.
- **Current state**: Partial/minimal — `storage.get_previous_findings` supplies lifecycle state and `memory.py` supplies human notes (both already context-budgeted); no history, relations, or cross-PR memory reach the prompt beyond those two narrow feeds.
- **Target state**: A retrieval step that composes prior findings, relation context, history signals, and scoped memory into the context budget with explicit provenance and authority labels (from `V7-E02`), used by both single-agent and council paths.
- **Dependencies**: hard: `V7-E01`, `V7-E02`, `V4-E04`; soft: `V7-E03`, `V5-E06`.
- **Architecture impact**: Extends `context.py` composition (post-`V4-E02` budget object); one retrieval entry point, not scattered history fetches.
- **Security impact**: All historical content is untrusted-derived → fencing/redaction; memory authority labels must survive into the prompt; untrusted PR content can never masquerade as historical memory.
- **Testing impact**: Prompt-content tests proving provenance labels present; injection-via-history fixtures; budget-sum tests including new feeds.
- **Migration impact**: Existing previous-findings/memory feeds keep identical semantics; new feeds are budget-capped additions (token deltas measured by `V3-E03`).
- **Cost impact**: Adds tokens per review — must fit budget with an explicit default (proposed baseline: ≤10% of context budget — mark as proposed baseline).
- **Complexity**: M — composition discipline; Risk: M — stale/wrong historical context can cause confidently wrong reviews.
- **Exit criteria**: Every historical item in the prompt carries a provenance tag (test); budget includes history feeds in its sum (test); disabled feeds ⇒ byte-identical pre-V7 output (test); authority labels from `V7-E02` are visible in the prompt.

#### V7-E07 · memory security
- **Purpose**: Secure the memory subsystem end-to-end: poisoning resistance, authority enforcement, retention/PII hygiene (memory becomes a durable attack surface once hierarchy lands).
- **User value**: Stored knowledge can't be quietly weaponized — a malicious PR can't plant "guidance" that later distorts every review.
- **Current state**: Partial — memory is human-authored only, engine read-only, notes fenced when embedded, dashboard mute rows write-protected; but there's no poisoning model (because there's nothing to poison yet beyond human input), no retention, no audit trail for memory mutations.
- **Target state**: Memory threat model with enforced controls: input screening on every write path, authority enforcement as code (`V7-E02`), append-only audit of changes, retention/PII policy, and an adversarial corpus (poisoning attempts) gated in CI.
- **Dependencies**: hard: `V7-E02` (there must be an authority model to enforce); soft: `V6-E02` (adversarial detection patterns), `V4-E08`.
- **Architecture impact**: Cross-cutting controls on `memory.py` + dashboard memory routes + storage; no new subsystem — hardening of one.
- **Security impact**: This epic *is* the memory security boundary; must extend the documented invariants (engine-never-writes, human-approved promotion, fencing) with tests that fail if any is relaxed.
- **Testing impact**: Poisoning corpus (untrusted content attempting memory write via diff/comments/API), authority-bypass attempts, audit-trail completeness, retention job correctness.
- **Migration impact**: Existing rows unaffected; new screening may flag previously-stored notes for human review (warn, don't delete).
- **Cost impact**: Negligible.
- **Complexity**: M — controls are straightforward once `V7-E02` exists; Risk: H — memory poisoning silently corrupts all downstream intelligence, and is hard to notice after the fact.
- **Exit criteria**: Every memory write path passes screening + authority checks (route-enumeration test); mutations produce audit entries; poisoning corpus yields zero successful unauthorized writes; retention never deletes `human-authored` rows without explicit policy (test).

---

### V8 — CI / release / incident intelligence

#### V8-E01 · CI ingestion & correlation
- **Purpose**: Ingest CI/workflow results (read-only) and correlate them with PRs/reviews so the platform knows what actually happened after a change.
- **User value**: Reviews can reference "CI was red on this branch 3 times this week" and post-run context becomes available to verification.
- **Current state**: Absent — `github_client` reads PRs/diffs/comments only; `action.yml` runs *as* a CI step but consumes nothing from other workflows; no CI event model (capability `O` is V8).
- **Target state**: Read-only CI run/workflow-run ingestion (via GitHub API), normalized run records correlated to commits/PRs, exposed through the read contract; feeds `V8-E02` and verification tier T2.
- **Dependencies**: hard: `V3-E02` (telemetry spine + budget discipline); soft: `V8-E07` (event platform carries records), `V4-E04` (correlation evidence).
- **Architecture impact**: Extends `github_client` with rate-limit-aware read endpoints (C8 must be addressed here at latest); run records are a new additive store entity.
- **Security impact**: CI logs/output are untrusted (and secret-bearing) → redaction mandatory; read-only is enforced (no re-run/cancel/write API calls — permission set unchanged); logs never reach prompts un-fenced.
- **Testing impact**: Fixture CI payloads (incl. log lines containing fake secrets → redacted); rate-limit backoff tests; read-only guard tests (no write endpoints called).
- **Migration impact**: Additive store; no CI data ⇒ behavior unchanged; degrade-and-warn on API limits (stable assumption §13.6).
- **Cost impact**: Additional GitHub API consumption — rate-limit handling (C8) is a prerequisite cost control.
- **Complexity**: L — API ingestion + normalization + correlation; Risk: M — rate limits and log-volume growth are the practical failure modes.
- **Exit criteria**: A fixture workflow-run record lands correlated to the right PR/commit; log payloads are redacted before storage (test); only read endpoints invoked (test); missing CI data ⇒ zero behavior change.

#### V8-E02 · test-failure correlation
- **Purpose**: Correlate test failures with the changes that plausibly caused them, giving verification (T2) and reviewers failure context with evidence.
- **User value**: "The failing test is in the module this PR touched, and it passed before this change" becomes a first-class signal instead of a wall of red.
- **Current state**: Absent — no CI data (built by `V8-E01`), no failure model, verification has no test evidence.
- **Target state**: Failure records normalized (test ID, suite, error signature), pre/post comparison across the change window, correlation as *evidence* (confidence-labeled), consumed by verification tier T2 and review context.
- **Dependencies**: hard: `V8-E01`, `V6-E03` (test inventory); soft: `V6-E05` (verification consumer).
- **Architecture impact**: New likely module (correlation over run records + index); produces evidence records via `V4-E04` — no new store.
- **Security impact**: Error signatures may embed secrets/PII → redaction on ingest; correlation output is evidence, never an automated verdict (no auto-fix/auto-merge).
- **Testing impact**: Fixtures with known causality; confidence calibration tests; redaction tests on failure text.
- **Migration impact**: Additive; no CI data ⇒ no signals.
- **Cost impact**: CPU only beyond ingest; bounded storage with retention (`V3-E04`).
- **Complexity**: M — normalization + probabilistic correlation with honest confidence; Risk: M — wrong causal claims ("this PR broke it") are costly to trust.
- **Exit criteria**: Known-causality fixture correlates correctly with confidence shown; unrelated failure yields no claim (test); redaction applied before storage (test); signals are advisory only — no verdict/action paths (test).

#### V8-E03 · release intelligence
- **Purpose**: Understand releases: what shipped, what changed since the last tag, risk concentration, and release-note context — read-only.
- **User value**: Reviewers and maintainers see release-scoped context (breaking-change candidates, accumulated risk) at PR and dashboard level.
- **Current state**: Absent — `CHANGELOG.md` is manually maintained; no tag/release ingestion, no "since last release" analysis (capability `AB`: V8).
- **Target state**: Release/tag ingestion (read-only), diff-since-last-release summaries, risk aggregation over shipped changes, release-context views; release notes are *drafted* for humans, never published by the platform (MAY boundary in vision §6).
- **Dependencies**: hard: `V7-E01` (history layer); soft: `V8-E01` (post-release CI health), `V4-E06` (twin drift across releases).
- **Architecture impact**: Reads git tags + GitHub release objects; aggregation reuses analytics projections (`V7-E05`); no new write capability.
- **Security impact**: Release/notes content is untrusted-derived → fencing/redaction; **no publishing** — drafts only (autonomous-write boundary).
- **Testing impact**: Fixture repos with tags; draft-only assertion (no POST to releases — read-only guard test); aggregation correctness.
- **Migration impact**: Additive; no tags/releases ⇒ silent no-op.
- **Cost impact**: API reads bounded; summaries are budgeted token calls (opt-in).
- **Complexity**: M — mostly aggregation + conservative wording; Risk: L.
- **Exit criteria**: Diff-since-last-release computed correctly on a tagged fixture; no release-publishing API path exists (test); drafts are clearly labeled and human-triggered only; absent tags ⇒ zero behavior change.

#### V8-E04 · documentation intelligence
- **Purpose**: Assess documentation coverage and drift: does the repo's docs match its code, and did this change invalidate docs?
- **User value**: "This PR changes the public API and the README still shows the old signature" becomes a finding with cited evidence.
- **Current state**: Absent — docs are ordinary files (often excluded); no doc inventory, no code↔doc mapping (capability `Y`: V8).
- **Target state**: Doc inventory + structure from the index, code↔doc linkage where deterministically derivable, staleness/drift signals as evidence-backed findings; explicit "we don't know" when linkage is unclear.
- **Dependencies**: hard: `V4-E01`; soft: `V6-E04` (architecture descriptions count as docs), `V7-E01` (docs' own change history).
- **Architecture impact**: Index extensions + a drift-analysis likely module; findings flow through existing pipeline (additive category).
- **Security impact**: Doc content is untrusted repo content (fencing applies); drift findings must not quote excluded/secret paths (privacy baseline).
- **Testing impact**: Fixtures with deliberate doc drift + benign twins; linkage-confidence tests; exclusion-respected test.
- **Migration impact**: Additive findings; no docs ⇒ no findings (not an error).
- **Cost impact**: Deterministic core — free; optional LLM summarization of drift is budgeted.
- **Complexity**: M — deterministic linkage is heuristic and honest-confidence is essential; Risk: L (annoying-but-cheap false positives) — mitigated by confidence labeling.
- **Exit criteria**: Changed-API fixture with stale README yields a finding citing both sides as evidence; ambiguous linkage yields "uncertain", not a claim (test); excluded paths never appear in doc findings (test).

#### V8-E05 · infrastructure intelligence
- **Purpose**: Analyze infrastructure-as-code and deployment configuration changes (workflows, Dockerfile, IaC) with deterministic checks and risk context.
- **User value**: "This workflow change grants write permissions to a fork-triggered job" is caught at review time with the exact rule cited.
- **Current state**: Absent — `.github/workflows/*.yml`, `Dockerfile`, and IaC files are reviewed as ordinary text; some security baseline coverage exists via static rules; no infra-specific model or misconfig rules (capability `X`: V8).
- **Target state**: Infra file inventory + schema-aware parsing (workflow YAML, Dockerfile, common IaC), deterministic misconfiguration rules (permission scope, pinning, secrets handling), and change-risk context (deploy-path changes flagged).
- **Dependencies**: hard: `V4-E01`, `V6-E07` (policy clauses over infra); soft: `V6-E01` (shared severity), `V8-E01` (CI context).
- **Architecture impact**: Schema-aware parsers as a likely module over the index; rules join the `static/` registry pattern (single wiring point preserved).
- **Security impact**: High-value detection surface (workflow perms are how Actions get compromised) — but rules are read-only analysis; must itself avoid executing/parsing untrusted IaC (parse, never interpret).
- **Testing impact**: Fixture workflows/Dockerfiles per rule with benign twins; parse-safety tests (malformed/hostile files don't hang or execute anything).
- **Migration impact**: Additive findings; existing excluded paths still excluded.
- **Cost impact**: Deterministic — free.
- **Complexity**: L — several schema parsers + rule sets; Risk: M — workflow false positives annoy the exact users who care most.
- **Exit criteria**: Over-permissioned fixture workflow yields a finding citing the offending key (path evidence); malformed/hostile file is handled safely without exception leak (test); all rules have benign twins; no interpretation/execution of parsed content (design + test).

#### V8-E06 · incident intelligence (read-only)
- **Purpose**: Learn from incidents retroactively: ingest incident records (from configured sources), link them to changes, and inform future reviews — strictly read-only.
- **User value**: After an incident, reviews of similar changes gain context ("a change like this caused INC-42 last quarter") as evidence, not prophecy.
- **Current state**: Absent — no incident model, no integration; explicitly scoped as *retrospective and read-only* (vision §5-AC; no autonomous production integration).
- **Target state**: Configured-source incident ingestion (manual export/API, opt-in), normalization, change-linkage as confidence-labeled evidence, surfaced in review context and analytics.
- **Dependencies**: hard: `V8-E01` (correlation machinery); soft: `V7-E01` (history linkage), `V8-E03` (release correlation).
- **Architecture impact**: New additive store entity + ingest adapter behind a read-only interface; no run-time Actions integration, no write-back to incident tools.
- **Security impact**: Incident records are highly sensitive (PII/secrets/outage details) → redaction on ingest, strict source allow-listing, retention policy, and no prompt use without fencing; the read-only boundary is test-enforced.
- **Testing impact**: Sensitive-fixture redaction tests; read-only guard (no outbound write calls); linkage-confidence tests; retention tests.
- **Migration impact**: Additive + fully opt-in (no sources configured ⇒ feature absent).
- **Cost impact**: Ingest is bounded; linked context tokens go through the budget.
- **Complexity**: M — adapters + sensitive-data discipline; Risk: M — sensitive-data handling mistakes are the main hazard.
- **Exit criteria**: Configured fixture incident lands redacted and linked with confidence; no outbound write path exists (test); absent configuration ⇒ zero surface (test); retention prunes per policy (test).

#### V8-E07 · internal event platform v1
- **Purpose**: Establish the internal event schema and bus (in-process/queue-light) that telemetry, CI records, memory changes, and analytics already want — the AG→AH foundation.
- **User value**: Users don't see this directly; they see faster, consistent, non-lossy propagation (e.g. review completed ⇒ dashboard metrics updated without polling).
- **Current state**: Absent — components couple directly (dashboard POST /api/reports is the de-facto event; no event schema, no bus; `CURRENT_ARCHITECTURE.md` §14: event platform "must be built").
- **Target state**: Versioned internal event schema, an in-process dispatcher with bounded queues and backpressure, per-event redaction, and subscriber contracts (telemetry, analytics, dashboard sync); **no distributed broker** (anti-pattern guard).
- **Dependencies**: hard: `V3-E02` (telemetry spine defines first events), `V3-E04` (storage integrity under async writes); soft: `V8-E01` (first real producer).
- **Architecture impact**: A seam, not a rewrite: producers emit events alongside existing synchronous paths (which keep working); consumers subscribe; ordering/at-least-once semantics documented per event type.
- **Security impact**: Events carry untrusted-derived payloads → schema-level redaction + fencing before any consumer sees them; event names/versions are trusted, payloads are not; no event may trigger a write action outside the platform's existing boundaries (autonomous-write prohibition).
- **Testing impact**: Schema validation per event; backpressure/loss tests (bounded queue behavior defined, not accidental); redaction-on-emit tests; ordering guarantees where claimed.
- **Migration impact**: Existing direct paths keep working — events are additive notifications, so rollback = unsubscribe, not downgrade.
- **Cost impact**: Memory/CPU only; prevents future polling costs.
- **Complexity**: M — schema + dispatcher done small; Risk: H if scope creeps toward a distributed system (explicitly refused), L if kept in-process.
- **Exit criteria**: ≥3 real producers/emitters and consumers wired with schema-validated payloads; queue bounds + overflow behavior tested and documented; redaction-on-emit tested; no external broker dependency introduced; synchronous fallback path still works with bus disabled (test).

---

### V9 — Organization platform

#### V9-E01 · multi-repository/org model
- **Purpose**: Introduce the org/repo hierarchy as data — repositories belong to orgs, findings/policies/memory/analytics are scoped accordingly (capability `AJ`).
- **User value**: Organizations get one place where all their repos' reviews, policies, and memory live, with correct scoping — without changing how a single repo works.
- **Current state**: Absent — everything is keyed by `repo` string (`review_state`, `finding_history`, `repo_memory`, dashboard routes `/api/repos/{owner}/{name}/...`); no org entity, no cross-repo queries.
- **Target state**: Org entity + membership scoping added additively; existing `owner/name` keys remain valid (org derived from owner, explicit org model optional); cross-repo queries behind the versioned API (`V9-E03`).
- **Dependencies**: hard: `V3-E04` (storage framework), `V8-E07` (events for org-level propagation); soft: `V7-E05` (analytics roll up to org).
- **Architecture impact**: The foundational V9 boundary decision: scoping is a *data* concern first (org_id columns/derived), not a deployment rewrite; single-repo users see no change.
- **Security impact**: Scoping is an authorization boundary — org isolation enforced at the storage/API seam (cross-org reads must be structurally impossible, not filtered by convention); token/auth model evolves in `V9-E03`.
- **Testing impact**: Isolation tests (org A can never read org B — adversarial query fixtures); single-repo backcompat tests; migration-equivalence tests.
- **Migration impact**: Existing rows adopt derived org scope (owner-derived) with zero data rewrite required; explicit org membership is opt-in.
- **Cost impact**: None material for single-repo users.
- **Complexity**: L — schema + isolation discipline across three storage backends; Risk: H — isolation bugs are security bugs, discovered late.
- **Exit criteria**: Cross-org read attempt fails at the storage seam (test); single-repo config behaves byte-identically (test); existing rows resolve to an org without manual migration (test); org-scoped queries are index-backed, not O(all).

#### V9-E02 · org policy engine
- **Purpose**: Extend `V6-E07` policy from repo/team to org scope with inheritance and override rules (vision §5-R, ADR-003).
- **User value**: Org sets baseline rules once ("no unpinned Actions", "auth changes require tests"); teams override downward where allowed, with every evaluation citing which scope decided.
- **Current state**: Repo-level only (`rules.py` / `.ai-pr-reviewer.yml`, free-text `rules:` + thresholds); no org scope, no inheritance, no evaluation.
- **Target state**: Org policy documents (versioned, trusted), inheritance chain org→team→repo with explicit override semantics, evaluated by the `V6-E07` evaluator unchanged; every policy finding cites scope + clause + precedence decision.
- **Dependencies**: hard: `V6-E07` (evaluator interface), `V9-E01` (org scoping); soft: `V4-E04` (clause provenance).
- **Architecture impact**: Reuses the evaluator — this epic is about *sources and precedence*, not a second engine; policy documents are trusted config served to runs (base-revision trust model extends to org-level config).
- **Security impact**: Org policy is trusted input but must still respect the non-removable privacy baseline (org config can only *add* exclusions — same invariant as repo config); precedence resolution is security-relevant (a repo must not silently defeat an org security clause — override rules must be explicit, not permissive).
- **Testing impact**: Precedence matrix tests (every scope×override combination); baseline-integrity tests under org config; provenance-of-decision tests.
- **Migration impact**: Existing `.ai-pr-reviewer.yml` = org-absent ⇒ behaves exactly as today; org policy is opt-in.
- **Cost impact**: Deterministic — free; policy docs add negligible context tokens (fetched via read contract, budgeted).
- **Complexity**: L — inheritance semantics are the classic source of subtle bugs; Risk: M — precedence surprises silently disable rules.
- **Exit criteria**: Precedence matrix fully tested (org>team>repo with explicit override flags); a repo config cannot weaken the privacy baseline even under org policy (test); every evaluation output cites deciding scope+clause; org-absent ⇒ byte-identical behavior (test).

#### V9-E03 · versioned API platform
- **Purpose**: Turn the dashboard's internal ~24-route HTTP API into a versioned, documented, stable public platform API (capability `AF`).
- **User value**: External tooling (IDE plugins, CI dashboards, org dashboards, third-party integrations) can depend on the platform without breakage risk.
- **Current state**: Dashboard HTTP API is internal: unversioned routes (`/api/reports`, `/api/stats`, `/api/metrics`, `/api/reviews/...`, `/api/repos/.../memory`, `/api/findings/.../feedback`, `/api/badge/...`, `/api/sandbox/simulate`), single shared token auth, OpenAPI UI disabled, engine↔dashboard calls swallow errors (stateless degrade).
- **Target state**: Versioned surface (`/v1/...`) with published schema, scoped auth beyond a single shared token, deprecation headers/policy, and contract tests; existing unversioned routes kept as the internal/compat path for a full deprecation window.
- **Dependencies**: hard: `V9-E01` (org scoping is the authz model); soft: `V3-E05` (contract snapshot methodology), `V9-E07` (observability over the API).
- **Architecture impact**: First *public* contract — the point where internal routes freeze; `DashboardStorageClient` keeps using the internal path (engine↔dashboard is not a public API).
- **Security impact**: Biggest auth change in the platform's life: token scoping (read vs write vs org), constant-time compare + weak-token refusal preserved, rate limits per scope; sandbox route stays unauthenticated-by-design only if unchanged and documented; API surface must not expand the Action's permission set.
- **Testing impact**: Contract/schema tests for `/v1`; authz matrix tests (scoped token can/cannot); deprecation-header tests; **no breaking-change gate**: additive-only enforced by schema diff (like `V3-E05` does for `action.yml`).
- **Migration impact**: Unversioned routes = current consumers' compat path; versioned path is additive; dashboard SPA migrates internally when ready; no removal before the deprecation window (see `MIGRATION_PLAN.md`).
- **Cost impact**: None material.
- **Complexity**: L — design + authz + docs; Risk: H — a public API is expensive to change later; getting v1 wrong is a long-lived liability.
- **Exit criteria**: `/v1` schema published and contract-tested; scoped tokens enforce an authz matrix (tests); unversioned routes still serve existing consumers (compat test); deprecation policy implemented with headers, not just docs.

#### V9-E04 · event-driven workers
- **Purpose**: Where (and only where) workload boundaries justify it, move event consumers to worker execution with bounded queues (capability `AH`) — the queue half of `V8-E07`.
- **User value**: Heavy jobs (index rebuilds, analytics backfills, large-org processing) stop blocking reviews; users get backpressure instead of timeouts.
- **Current state**: Single-process, sequential review; dashboard single-worker (rate limiter + audit file are per-process); no queue, no workers; C5 breakers assume sequential use.
- **Target state**: Work-item abstraction with bounded queue + worker execution *for identified heavy tasks only*, reusing the same engine entry points (no forked logic), with explicit at-least-once semantics, idempotent handlers, and per-worker telemetry.
- **Dependencies**: hard: `V8-E07` (event schema/dispatch); soft: `V9-E01` (org-scale workloads justify it), `V3-E04` (concurrent-safe storage).
- **Architecture impact**: The queue is introduced *after* workload boundaries are proven (anti-pattern guard: microservices/queues before boundaries = refused); in-process execution remains the default and fallback.
- **Security impact**: Workers must inherit identical trust boundaries (fencing/redaction per task), never widen permissions; work items are untrusted-derived payloads → schema-validated + redacted at emit (from `V8-E07` rules); crash-safety must not skip security steps.
- **Testing impact**: Idempotency tests (duplicate delivery ⇒ same result), crash-recovery tests, "queue disabled ⇒ identical behavior" tests, per-worker budget/telemetry tests.
- **Migration impact**: Opt-in deployment shape; single-process default unchanged (rollback = disable queue, same binaries).
- **Cost impact**: Operational cost (more moving parts) — only justified where measured load exists (gate on `V9-E07` metrics).
- **Complexity**: M (in-process queue) to L (separate worker process); Risk: M — distributed execution multiplies failure modes while staying single-tenant.
- **Exit criteria**: Every queued handler is idempotent (test); duplicate/failed delivery behaves per documented semantics (test); in-process default produces identical results (test); a measured workload justifies each worker (documented).

#### V9-E05 · org memory
- **Purpose**: Add org-scoped memory to the `V7-E02` hierarchy (org→team→repo→…), with promotion workflows and authority rules intact.
- **User value**: Decisions made once at the org level inform every repo's reviews (with authority labels), instead of being copy-pasted per repo.
- **Current state**: Memory = `repo_memory` (repo-scope, human-authored, engine read-only) + mutes; no higher scopes, no promotion, no cross-repo retrieval (hierarchy landed as `V7-E02` design for org level — this epic ships the org level).
- **Target state**: Org-level memory store + authority precedence across org/team/repo + promotion workflow (repo-observed → org-approved, human-gated) + cross-repo retrieval scoped by authorization, all through the `V7-E02` read API.
- **Dependencies**: hard: `V7-E02`, `V9-E01`; soft: `V7-E07` (memory security controls), `V9-E02` (org policy is the sibling trusted-config surface).
- **Architecture impact**: Extends the existing hierarchy — no new memory subsystem; the org level is a scope, not a rewrite.
- **Security impact**: Org memory is the highest-blast-radius memory: poisoning at org level contaminates every repo → `V7-E07` controls must be proven at org scope before promotion features ship; promotion is human-gated and audited (no autonomous truth-writing — hard boundary).
- **Testing impact**: Precedence tests extended to org level; cross-org isolation (adversarial fixtures); promotion-gate tests; poisoning corpus rerun at org scope.
- **Migration impact**: Existing repo rows unaffected (org level absent ⇒ identical precedence as `V7-E02` v1); promotion is opt-in.
- **Cost impact**: Retrieval tokens grow with hierarchy depth — bounded by budget with explicit caps (proposed baseline: org-level entries ≤20% of memory budget — mark as proposed baseline).
- **Complexity**: M — reuses hierarchy, but org-scale blast radius raises the security bar; Risk: H — a poisoned org memory is a platform-wide trust failure.
- **Exit criteria**: Org memory cannot be written by the engine on any path (test); precedence org>team>repo fully tested; cross-org isolation adversarially tested; migration of existing rows shows zero precedence change (test).

#### V9-E06 · extensibility contract v1
- **Purpose**: Write down and stabilize the extension surface (providers, rule packs, storage, reporting) as a versioned contract with conformance tests — the precondition for plugins (capability `AI` contract half).
- **User value**: Third parties can build against documented, stable interfaces with a compatibility promise, instead of copying internals.
- **Current state**: Informal seams only: `AIProvider` protocol (7 hard-coded wiring sites — addressed in `V5-E05`), `static/engine.build_default_registry()` tuple (single wiring point), `ReviewStorage` protocol with two undeclared `getattr`-guarded capabilities; **no plugin system, no event bus, no versioned API, no public extension contract** (§10.5).
- **Target state**: Declared extension points with stability levels (`experimental|stable|frozen`), semantic versioning promise, capability declarations, and a conformance kit per point; the `getattr` gaps in `ReviewStorage` become declared capabilities.
- **Dependencies**: hard: `V4-E07` (read contract design precedent), `V5-E05` (registry-driven providers); soft: `V9-E03` (versioning machinery), `V8-E07` (event consumer extension point).
- **Architecture impact**: Crystallizes the repo's proven protocol-seam pattern into a *published* contract; deliberately excludes core lifecycle/security code from the extension surface (OSS contribution boundary, vision §7).
- **Security impact**: Contract states trust rules for extensions (untrusted input handling, no autonomous writes, redaction obligations) — enforceable via conformance tests; storage extension = data access, so capability flags gate sensitive operations.
- **Testing impact**: Conformance kit is the deliverable: every current backend/provider/rule-pack passes it; contract-frozen schema tests (breaking change fails CI).
- **Migration impact**: Existing informal seams remain valid (contract formalizes them); the two `ReviewStorage` optional capabilities become declared with default-implemented fallbacks — no backend breaks.
- **Cost impact**: None.
- **Complexity**: M — mostly design + documentation + conformance tests; Risk: M — freezing too early fossilizes a bad interface (mitigated by `experimental` level).
- **Exit criteria**: Each extension point has a stability level and conformance suite; current implementations pass; a documented breaking-change rule (what may change per stability level); `ReviewStorage` capabilities all declared (no `getattr` guards remain — grep test).

#### V9-E07 · observability platform
- **Purpose**: Unify telemetry (`V3-E02`), events (`V8-E07`), and analytics (`V7-E05`) into one observability surface: metrics, traces of a review's stages, and health signals (plane 10).
- **User value**: Operators can answer "why is this review slow/expensive/failing?" from one place instead of correlating report JSON, audit log, and CI by hand.
- **Current state**: Fragmented: report JSON (run-level), `/api/metrics` (dashboard), `audit.jsonl` (append-only), telemetry not yet surfaced (fixed by `V3-E02`); no stage-level traces, no alerting, no unified schema.
- **Target state**: Unified metrics/trace schema over the event spine, per-stage review traces (context build → each specialist → merge → verify → post), health/SLO dashboards, and export hooks (OTLP-compatible — proposal) without adding heavy deps to the Action image.
- **Dependencies**: hard: `V3-E02`, `V8-E07`; soft: `V9-E03` (API exposure), `V9-E04` (worker metrics).
- **Architecture impact**: Consumes, doesn't create: schema consolidation over existing telemetry/events; must respect the `requirements-action.txt` leanness invariant (heavy deps stay dashboard-side).
- **Security impact**: Traces carry untrusted-derived content → redaction at emit (from `V3-E02` discipline); trace export is opt-in with explicit endpoint config (no implicit exfiltration of repo-derived data).
- **Testing impact**: Schema-unification tests; redaction-on-export tests; "no Action image weight change" test (dependency set unchanged).
- **Migration impact**: Existing `/api/metrics` and report fields kept (additive superset); exporters opt-in.
- **Cost impact**: Storage for traces (retention via `V3-E04`); export egress opt-in.
- **Complexity**: M — consolidation more than invention; Risk: L.
- **Exit criteria**: One schema covers telemetry+events+analytics (documented, tested); a single review's stages are traceable end-to-end in the dashboard; export disabled ⇒ no network egress (test); `requirements-action.txt` unchanged (test).

---

### V10 — Ecosystem / platform

#### V10-E01 · plugin system
- **Purpose**: Ship the plugin system the contract (`V9-E06`) promises: third-party analyzers/reporters/consumers loadable without forking core (capability `AI` shipping half).
- **User value**: Communities extend the platform (custom analyzers, org-specific checks, reporters) while core stays reviewed-in-house.
- **Current state**: Absent — extension today means editing tuples (`build_default_registry()`) or forking; no loader, no isolation, no contract (§10.5).
- **Target state**: Plugin discovery/loading against the `V9-E06` contract, explicit capability grants, trust labeling for plugin-derived content (never trusted as input), and lifecycle (enable/disable/version-check) — delivered as OSS community surface per vision §7.
- **Dependencies**: hard: `V9-E06` (contract must exist first — anti-pattern guard: plugins before stable contracts = refused); soft: `V9-E03` (distribution/registry surface), `V4-E07` (read contract is what plugins consume).
- **Architecture impact**: The first true third-party code boundary: plugin API deliberately narrow (analyze/report, never lifecycle/verification/storage-write); conformance kit from `V9-E06` becomes the load gate.
- **Security impact**: **Plugin output is untrusted** (vision §6 last bullet): fenced/redacted like model output; plugins declare permissions and get only granted capabilities; a plugin can never write memory as `human-authored`, post to GitHub, or modify code (autonomous-write boundary); plugin-supplied *code* execution is scoped to analysis of already-fetched data — no implicit network/filesystem grants (design constraint, threat model in `SECURITY_ROADMAP.md`).
- **Testing impact**: Malicious-plugin fixtures (attempting lifecycle forgery, ungranted capability use, unredacted exfiltration) all blocked by tests; conformance gate before load.
- **Migration impact**: Core users unaffected (no plugins ⇒ no behavior change); plugin authors target the documented contract from day one.
- **Cost impact**: None for core; plugin review/triage is a maintainer-cost commitment (OSS governance).
- **Complexity**: XL — plugin security + API stability + lifecycle in one; Risk: H — a weak plugin boundary is a remote-code/trust hole, and a unstable contract creates ecosystem lock-in.
- **Exit criteria**: A sample third-party plugin passes conformance and runs without core changes; malicious-plugin fixtures all blocked (tests); no plugin can reach lifecycle/storage-write/GitHub-write APIs (structural test); contract stability levels honored (breaking-change gate).

#### V10-E02 · provider capability ecosystem
- **Purpose**: Open the provider layer to community adapters (local models, region-specific hosts, niche providers) via the registry + conformance path (capability `U` ecosystem half).
- **User value**: Users plug in any provider (incl. fully local, keyless) with one adapter instead of a PR into core; capability data routes tasks honestly.
- **Current state**: Three providers (`ai/claude.py`, `ai/openai.py`, `ai/gemini.py`) + static, each added through 7 hard-coded sites (collapsed by `V5-E05` registry); OpenAI-compatible `base_url` already supports some endpoints ad hoc; no community adapter path, no conformance.
- **Target state**: Documented adapter SDK against the provider contract + registry, conformance suite (including honest fallback attribution, retired-ID guard, usage reporting), and a curated community registry listing (no auto-install).
- **Dependencies**: hard: `V5-E05` (registry), `V9-E06` (stable provider contract); soft: `V5-E02` (specialist task capabilities), `V10-E01` (loading/packaging machinery).
- **Architecture impact**: Core stops being the bottleneck for provider support — the OSS contribution surface vision §7 names (rule packs + provider adapters + plugins) becomes real.
- **Security impact**: Adapter code is third-party code (same trust posture as plugins: capability-scoped, output untrusted, secrets never logged); BYO-key model preserved; retired-model-ID invariant enforced by the extended release scan on adapters.
- **Testing impact**: Conformance suite is the gate (failover, circuit, retry, usage reporting, static-fallback labelling must behave per contract); no-network test for local adapters.
- **Migration impact**: In-tree providers migrate onto the adapter path with byte-identical behavior (contract snapshot from `V3-E05` extended to providers); existing inputs unchanged.
- **Cost impact**: Zero for core; adapters run under the same budget/arbitration (`V5-E07`) — no un-budgeted providers.
- **Complexity**: M — contract + conformance + docs, most knowledge already exists in-tree; Risk: L — gated behind a stable contract.
- **Exit criteria**: An out-of-tree mock adapter passes conformance and runs a real review (offline test); in-tree provider behavior is byte-identical post-migration (snapshot test); retired-ID scan covers adapter sources; registry-only wiring proven (one-file add).

#### V10-E03 · hosted multi-tenant foundation (optional)
- **Purpose**: If (and only if) hosting is pursued, lay the tenancy foundations: tenant isolation, quota/metering, and a deployment model — labelled a **future option**, not a commitment (vision §7, §5-AK).
- **User value**: Operators can run a shared instance for multiple teams with isolation guarantees and per-tenant cost visibility.
- **Current state**: Absent — single-process, single-tenant; SQLite WAL / optional Postgres dashboard DB; one shared dashboard token; no tenant concept anywhere.
- **Target state**: Tenant model layered on org scoping (`V9-E01`), per-tenant storage/auth/quota enforcement, metering fed by the telemetry spine; explicit go/no-go decision gate before this epic starts.
- **Dependencies**: hard: `V9-E01`, `V9-E03`, `V9-E04`; soft: `V9-E07` (metering/observability).
- **Architecture impact**: Validates whether single-process assumptions (C5 global breakers, per-process rate limiter/audit file) survive shared hosting — the point where those become mandatory fixes, not earlier.
- **Security impact**: Tenant isolation is the hardest security boundary in the plan: cross-tenant reads/writes must be structurally impossible; secrets per-tenant, never process-global; threat model required before code (gate).
- **Testing impact**: Cross-tenant adversarial isolation suite; quota-enforcement tests; load tests on rate limiter/audit paths (per-process state).
- **Migration impact**: Irrelevant to self-hosted/OSS users (opt-in deployment shape); Action contract untouched.
- **Cost impact**: Highest operational cost of any epic (infrastructure, compliance burden) — which is why it is optional.
- **Complexity**: XL — tenancy + isolation + metering + ops; Risk: H — but explicitly de-risked by being optional and gated.
- **Exit criteria**: Go/no-go decision record precedes implementation; cross-tenant isolation suite passes adversarially; per-tenant metering reconciles with `V3-E02` telemetry; OSS single-tenant path ships unchanged alongside.

#### V10-E04 · IDE/CLI ecosystem
- **Purpose**: Bring the platform to developers where they work: richer CLI (local review, explain, query) and IDE-facing integration, without forking the engine (capability `A`).
- **User value**: Developers run reviews locally with full intelligence (no GitHub round-trip), inspect why a finding was made, and get findings in-editor.
- **Current state**: Minimal — `python -m ai_pr_reviewer --diff-file … --mock` local mode with deterministic static engine (fully offline, honestly labelled), `--output` report JSON; no explain/query subcommands, no IDE surface, no structured query API for tooling.
- **Target state**: CLI subcommand surface (review / explain finding / query index / eval) over the existing engine + read contract; IDE integration consumes the versioned API or CLI JSON output (no new protocol invented); offline parity with GitHub mode wherever data allows.
- **Dependencies**: hard: `V9-E03` (versioned API for tooling), `V4-E07` (read contract for query/explain); soft: `V10-E01` (plugin packaging for editor extensions).
- **Architecture impact**: Presentation-layer only — reuses engine + contracts; explicitly does not fork review logic into a second implementation (one engine everywhere).
- **Security impact**: Local mode touches local files → same privacy exclusions and redaction; IDE integration must not exfiltrate code (local-first, opt-in network); no new autonomous write paths (IDE never applies fixes).
- **Testing impact**: CLI contract tests (exit codes, JSON shape) extending `V3-E05` snapshot discipline; offline-parity tests (local vs GitHub mode on same fixture).
- **Migration impact**: Existing `python -m ai_pr_reviewer` invocation and flags remain valid (subcommands are additive); Action contract untouched.
- **Cost impact**: None for platform; local mode is free (static/mock path) or BYO-key.
- **Complexity**: M — CLI/UX work over stable internals; Risk: L — but scope creep toward "rewrite as IDE plugin" must be refused (anti-pattern).
- **Exit criteria**: `explain` returns provenance for any finding ID via the read contract; local mode reproduces GitHub-mode output on the same fixture (test); all existing CLI flags behave identically (snapshot test); no new network calls in offline mode (test).

#### V10-E05 · org-scale analytics
- **Purpose**: Scale the analytics plane to organization level: multi-repo trends, cross-repo hotspots, portfolio views — trends and hotspots only, never individual rankings (vision §5-AD).
- **User value**: Engineering leaders see where risk concentrates across the portfolio (which repos, which change types, which categories trend up) with evidence behind every number.
- **Current state**: Absent at org scope — `V7-E05` analytics are per-repo; dashboard `/api/stats`/`/api/metrics` are single-repo; no cross-repo rollup, no time-series warehouse.
- **Target state**: Org-scoped aggregation over the analytics projections (rebuildable, no event-sourcing requirement), portfolio dashboards behind the versioned API, with the `V7-E05` small-cohort suppression and no-individual-dimension invariants carried up a level.
- **Dependencies**: hard: `V7-E05`, `V9-E01`, `V9-E07`; soft: `V8-E03` (release dimension), `V7-E01` (churn dimension).
- **Architecture impact**: Consumes projections; aggregation-at-write continues — no O(all) scans even at org scale; may add rollup tables (additive, rebuildable).
- **Security impact**: Privacy boundary scales with blast radius: no individual dimensions (schema test carried forward), small-N suppression at every rollup level, org isolation on every query (`V9-E01` seam).
- **Testing impact**: Aggregation correctness across repos; suppression at org level; rebuild-equivalence at scale; isolation tests per query.
- **Migration impact**: Additive — existing per-repo metrics unchanged; org rollups are new derived data (rebuildable from source).
- **Cost impact**: Write-time aggregation grows with volume but stays bounded; retention via `V3-E04`.
- **Complexity**: M — proven projection pattern at larger scale; Risk: M — privacy suppression bugs at org scale are high-consequence.
- **Exit criteria**: Cross-repo rollup equals sum of per-repo projections (test); no individual dimension at any rollup level (schema test); small-N suppression enforced org-wide; queries bounded on a multi-repo fixture.

#### V10-E06 · engineering command center
- **Purpose**: Evolve the dashboard from a reports viewer into the unified engineering command center (capability `AE`): one surface over reviews, verification, policy, incidents, analytics, and cost.
- **User value**: Teams operate the whole loop from one place — triage findings, track verification, see policy posture and cost, and act (within the no-autonomous-write boundary).
- **Current state**: Dashboard is a dependency-free hash-router SPA (`dashboard/static/`) with reviews, report detail, findings, metrics, sandbox, rules/memory views; single shared token, ~24 routes, OpenAPI UI disabled; no unified workflow, no cross-plane views, no triage queue.
- **Target state**: Command-center UI over the versioned API (`V9-E03`) aggregating all planes' read models, plus human-triggered actions (mute, approve memory promotion, re-run, export) that stay inside the existing permission boundary; role-aware views for org deployment.
- **Dependencies**: hard: `V9-E03`, `V9-E07`; soft: all read models it displays (`V7-E05`, `V8-*`, `V9-E02`, `V10-E05`).
- **Architecture impact**: Presentation layer over existing read contracts — deliberately *last*, after data contracts exist (anti-pattern guard: dashboards before data contracts = refused); SPA stays dependency-free unless a measured need changes that (proposal).
- **Security impact**: Every action button maps to an already-authorized API operation (no new write paths invented in UI); authz matrix from `V9-E03` enforced per view; CSP/rate-limit posture preserved.
- **Testing impact**: UI contract tests against the versioned API schema; authz tests per view/action; action-boundary tests (no command-center action exceeds existing API permissions).
- **Migration impact**: Existing SPA routes/APIs keep working; command center is an additive view set; existing single-token users see the same data.
- **Cost impact**: None material (client-side only).
- **Complexity**: L — broad but shallow (aggregation of stable contracts); Risk: L if contracts hold, M if UI pressures contracts to break (refused by additive-only gate).
- **Exit criteria**: Every command-center view reads only versioned-API fields (schema test); every action maps to an existing authorized endpoint (test); legacy SPA routes still function (compat test); no unversioned internal route is reachable from the new UI (test).

---

## 3. Proposed implementation tickets

### 3.1 Ticket strategy

A **ticket** is the unit that gets implemented, reviewed, and merged. Every ticket
below (and every ticket later cut for `V5`–`V10`) is written against the same
16-field template. The template exists so that a ticket can be picked up by a
different engineer (or session) with **zero additional context**: the *why*
lives in the ticket, the *what exactly* lives in the acceptance criteria, and
the *how not to break users* lives in the rollback strategy.

The 16 fields:

| # | Field | What it answers |
|---|---|---|
| 1 | **Ticket ID** | `Vn-Enn-Tnn` — permanent, never reused. |
| 2 | **Title** | Verb-first, one line, names the affected behavior. |
| 3 | **Goal** | The single outcome; if you can't state it in one sentence, split the ticket. |
| 4 | **Why it exists** | The defect/constraint/vision item that caused it (D#, C#, epic exit criterion). |
| 5 | **Prerequisites** | Hard blockers *outside* this epic (deps within the epic are implicit). |
| 6 | **Files/modules likely affected** | Real current paths for V3 work; "likely module"/"new subsystem" for future work — never invented precise paths. |
| 7 | **API/data contracts** | Exact inputs/outputs/schemas touched, and whether each change is additive. |
| 8 | **Implementation requirements** | Ordered, testable steps — the how, without pseudocode. |
| 9 | **Security requirements** | Invariants that must hold (fencing, redaction, base-revision trust, permissions), or "none beyond suite invariants". |
| 10 | **Tests required** | Named test files/modules (existing `tests/*.py` for V3; "new test module in `tests/`" for later stages). |
| 11 | **Acceptance criteria** | 1–3 verifiable bullets; the reviewer's checklist. |
| 12 | **Definition of done** | Suite green (`PYTHONUTF8=1 python -m pytest tests/ -q`), docs updated if public contract changed, no line-ending churn committed. |
| 13 | **Dependencies** | Related ticket IDs (hard/soft). |
| 14 | **Risk** | H/M/L + the one way this ticket can go wrong. |
| 15 | **Rollback strategy** | How to undo: config flag, revert commit, or data migration reversal. |
| 16 | **Estimate** | S/M/L relative size — planning hint only, not a commitment. |

**Cutting rules:** one behavior change per ticket; a ticket that needs both a
schema change *and* a behavior change across two subsystems is usually two
tickets; defects (D#) map 1:1 to a ticket unless fixing them inseparably
reduces risk (then one ticket, multiple criteria). Tickets under `V3` must each
leave the suite green and the Action contract untouched — no ticket may bundle
an unrelated contract change.

### 3.2 Phase 0 — V3 epic ticket breakdowns

#### V3-E01 · correctness defect triage — tickets

- **V3-E01-T01** · Populate `base_sha` in `GitHubClient`
  - *Goal*: `get_pr()` and `get_event_context()` set `PRContext.base_sha` so repository context is fetched at the base revision, not the head (D1).
  - *Likely files*: `ai_pr_reviewer/github_client.py`, `ai_pr_reviewer/models.py`, `ai_pr_reviewer/repo_context.py`, `tests/test_repo_context.py`, `tests/test_github_incremental.py`.
  - *Key requirements*: read `pull_request.base.sha` from both the API and `GITHUB_EVENT_PATH` payload; keep `repo_context.py:238` fallback for absent `base_sha` (local mode has no base); tests must construct context the way production does (via `get_pr`/`get_event_context`), not by hand-setting `base_sha`.
  - *Acceptance*: a test asserting `get_pr()` returns non-empty `base_sha`; a test asserting repo-context ref equals base, not head; existing incremental/fallback tests unchanged and green.
  - *Dependencies*: — (first ticket of Phase 0).

- **V3-E01-T02** · Verification must receive the uncapped finding list
  - *Goal*: `verify_findings()` compares previous findings against the full deduped set, not the `max_comments`-capped inline list, so cap overflow can never synthesize a false `resolved` (D2).
  - *Likely files*: `ai_pr_reviewer/orchestrator.py`, `ai_pr_reviewer/verification.py`, `tests/test_verification.py`, `tests/test_orchestrator.py`.
  - *Key requirements*: split `validate_findings()` results into *reported/all-anchored* vs *inline-posted* lists; pass the uncapped anchored list as `current` to `verify_findings()`; `_unverify()` semantics unchanged.
  - *Acceptance*: regression test where a still-present finding falls outside the top-20 cap and stays `active`; report still shows capped inline comments; health score computed from uncapped set.
  - *Dependencies*: hard `V3-E01-T05` (sort must exist before "top-N" is meaningful).

- **V3-E01-T03** · Record below-threshold findings instead of dropping them
  - *Goal*: findings under `severity_threshold` are retained in the report (counted, listed as suppressed-below-threshold) instead of vanishing (D3).
  - *Likely files*: `ai_pr_reviewer/orchestrator.py`, `ai_pr_reviewer/reporter.py`, `ai_pr_reviewer/models.py`, `tests/test_review_experience.py`.
  - *Key requirements*: `validate_findings()` returns below-threshold findings as a fourth category; `ReviewResult` gains an additive field (e.g. `below_threshold: list` / counts); `reporter.py` summary `suppressed` wording becomes truthful (below-threshold vs cap-overflow distinguished); `action.yml` output `findings_count` semantics unchanged (still ≥ threshold).
  - *Acceptance*: below-threshold findings appear in `review-report.json` with a distinguishing marker; `findings_count` output unchanged for existing configs; summary no longer claims suppression it didn't perform.
  - *Dependencies*: hard `V3-E01-T04` (cap semantics must be split first).

- **V3-E01-T04** · Separate report cap from inline-comment cap
  - *Goal*: `max_comments` limits only inline GitHub comments; the report/health score reflect all anchored findings, matching `action.yml:44` ("Extra findings go in the summary") (D4).
  - *Likely files*: `ai_pr_reviewer/orchestrator.py`, `ai_pr_reviewer/reporter.py`, `ai_pr_reviewer/config.py`, `tests/test_pipeline.py`.
  - *Key requirements*: introduce a separate internal limit for report listing if a bound is still needed (named constant, documented — addresses D13-adjacent hard-coded caps); health score input = uncapped anchored set; step summary may remain bounded (`top_n`) but must show total counts.
  - *Acceptance*: a 30-finding run with `max_comments=5` posts 5 inline comments but reports 30 findings; health score identical to a run with `max_comments=30`; `action.yml` documented behavior now true (test asserts it).
  - *Dependencies*: hard `V3-E01-T05`.

- **V3-E01-T05** · Severity-sort findings before any cap applies
  - *Goal*: sort all findings critical→info deterministically before inline/report/summary truncation, so caps never prefer mild over critical (D5).
  - *Likely files*: `ai_pr_reviewer/orchestrator.py`, `ai_pr_reviewer/static/engine.py`, `ai_pr_reviewer/reporter.py`, `tests/test_findings.py`.
  - *Key requirements*: single sort at pipeline level (keep static's own sort harmless); stable secondary key (file, line) for determinism; AI-provider output must not be trusted to arrive sorted (comment at `orchestrator.py:82` corrected).
  - *Acceptance*: fixture with mixed severities in adversarial input order yields critical findings inside the cap and info outside; two runs produce identical ordering; static-engine behavior unchanged (its own tests stay green).
  - *Dependencies*: — (sort lands first, then T02/T04 consume it).

- **V3-E01-T06** · Safe numeric config parsing with exit 1
  - *Goal*: garbage numeric `INPUT_*` values (`pr_number`, `max_comments`, `batch_chars`, …) produce a clear config error and exit code `1` instead of an unhandled `ValueError` traceback (D6).
  - *Likely files*: `ai_pr_reviewer/config.py`, `tests/test_config.py`.
  - *Key requirements*: wrap every `int()`/numeric parse in config loading with a validation helper raising the existing config-error type; message names the input and shows the bad value; exit code is `1` (config error, distinct from `2` fail-on-threshold); no secret values echoed.
  - *Acceptance*: `INPUT_MAX_COMMENTS=abc` exits 1 with message containing `max_comments`; valid values parse exactly as today (contract snapshot from `V3-E05` protects this); traceback-free output asserted.
  - *Dependencies*: — (can land immediately).

- **V3-E01-T07** · Dashboard mute idempotency
  - *Goal*: muting the same fingerprint repeatedly updates/reuses the single mute row instead of minting a duplicate per click (D7).
  - *Likely files*: `dashboard/storage.py`, `dashboard/app.py`, `tests/test_dashboard_storage.py`.
  - *Key requirements*: fix `record_feedback` lookup to target the mute row by its actual identity (`path_pattern` = `fingerprint:<fp>` + repo, not `session.get(RepoMemoryRow, repo)`); upsert semantics; existing mute-write-protection (mute rows write-protected) preserved.
  - *Acceptance*: N mute requests for one fingerprint produce exactly 1 row (test loops N=5); mute still applies to engine runs via `get_dismissed_fingerprints`; no schema change required (if one is needed it must be additive `ALTER TABLE`).
  - *Dependencies*: soft `V3-E04-T03` (shared `fingerprint:` literal prevents a re-drift).

- **V3-E01-T08** · Defect regression matrix for D1–D7
  - *Goal*: one test module that pins all seven defects as permanent regressions, so Phase 0 fixes can't silently revert.
  - *Likely files*: new `tests/test_defect_regressions.py` (name adjustable), touching fixtures from `tests/conftest.py`.
  - *Key requirements*: each D# gets at least one failing-before/passing-after test referencing the D# in its docstring; suite stays fully offline; no fixture secrets/real diffs (`CONTRIBUTING.md`).
  - *Acceptance*: all 7 defects covered; test names map 1:1 to D1–D7; suite green under `PYTHONUTF8=1 python -m pytest tests/ -q`.
  - *Dependencies*: hard `V3-E01-T01`..`T07` (it pins them).

#### V3-E02 · telemetry foundation — tickets

- **V3-E02-T01** · Token/usage capture on provider calls
  - *Goal*: every provider run records input/output tokens (Gemini usage parsing included) or an explicit "unavailable" marker.
  - *Likely files*: `ai_pr_reviewer/ai/claude.py`, `ai_pr_reviewer/ai/openai.py`, `ai_pr_reviewer/ai/gemini.py`, `ai_pr_reviewer/model_router.py`.
  - *Key requirements*: usage parsed from provider responses into one shared record type; absence is a typed state, not a zero (never fake `0` tokens); no prompt content stored.
  - *Acceptance*: mocked responses from all three providers populate the record; a provider without usage reports `unavailable`; static/mock runs mark `n/a`.
  - *Dependencies*: —

- **V3-E02-T02** · Telemetry record on `AnalysisOutcome` and report JSON
  - *Goal*: carry per-run telemetry (tokens, batch count, per-batch latency, model, fallback events) through `AnalysisOutcome` → `finalize_report` as additive JSON fields.
  - *Likely files*: `ai_pr_reviewer/models.py`, `ai_pr_reviewer/reporter.py`, `tests/test_review_experience.py`.
  - *Key requirements*: additive-only fields (contract snapshot from `V3-E05-T03` must pass); redaction applied before inclusion; field naming follows existing report conventions.
  - *Acceptance*: mock run report contains telemetry fields with correct types; snapshot test updated deliberately (reviewed), not accidentally; no keys/paths from local dev leaked (redaction test).
  - *Dependencies*: hard `V3-E02-T01`.

- **V3-E02-T03** · Retry/failover/circuit events as telemetry
  - *Goal*: record retry attempts, failover transitions, and breaker open/close as first-class telemetry events with timestamps.
  - *Likely files*: `ai_pr_reviewer/retry.py`, `ai_pr_reviewer/circuit.py`, `ai_pr_reviewer/model_router.py`.
  - *Key requirements*: events are structured (type, backend, attempt, delay, outcome), not log strings; process-global breaker state remains unchanged (C5 not fixed here — out of scope); no secrets in event payloads.
  - *Acceptance*: a forced-failover test produces the expected event sequence; events pass redaction; logging behavior unchanged for existing tests.
  - *Dependencies*: hard `V3-E02-T02`.

- **V3-E02-T04** · Persist telemetry (additive storage)
  - *Goal*: store run telemetry alongside reports so cost/latency can be queried later; hand-rolled additive column/table only.
  - *Likely files*: `ai_pr_reviewer/storage.py`, `dashboard/storage.py`, `dashboard/models_db.py`, `tests/test_storage_client.py`, `tests/test_dashboard_storage.py`.
  - *Key requirements*: additive schema (no destructive `ALTER`); both engine SQLite and dashboard `DbStorage` keep parity; `JsonStorage` stores the blob without schema pain; telemetry rows follow retention policy from `V3-E04`.
  - *Acceptance*: telemetry round-trips through all three backends; migration on an existing DB leaves old rows intact; missing-telemetry rows don't break reads (backcompat).
  - *Dependencies*: hard `V3-E02-T02`; soft `V3-E04-T01`.

- **V3-E02-T05** · Surface telemetry in dashboard metrics
  - *Goal*: `/api/metrics` (and the metrics SPA view) expose tokens/cost/latency series per repo.
  - *Likely files*: `dashboard/app.py`, `dashboard/storage.py`, `dashboard/static/app.js`.
  - *Key requirements*: read-only aggregation (respect C9: use indexed/limited queries, not O(all) where avoidable); additive response fields only; auth posture unchanged (reads optionally unauthenticated per existing config).
  - *Acceptance*: metrics endpoint returns telemetry series from seeded data; existing consumers of `/api/metrics` see unchanged old fields (additive test); rate limits unchanged.
  - *Dependencies*: hard `V3-E02-T04`.

- **V3-E02-T06** · Telemetry redaction + no-content invariant
  - *Goal*: enforce that telemetry can never contain prompt bodies, file contents, secrets, or raw model output (structural, not by convention).
  - *Likely files*: `ai_pr_reviewer/security.py` (reuse `redact_secrets`), new telemetry collector module or `ai_pr_reviewer/reporter.py`.
  - *Key requirements*: allowlist schema for telemetry fields (anything not on the list is dropped); test asserts a payload containing a planted key/fence never survives; warning-path messages type-name-only where already required.
  - *Acceptance*: adversarial test plants a fake secret in every provider path and asserts absence in stored/reported telemetry; allowlist is the enforced contract (test enumerates fields).
  - *Dependencies*: hard `V3-E02-T01`, `V3-E02-T02`.

#### V3-E03 · evaluation harness foundation — tickets

- **V3-E03-T01** · Harness skeleton + golden corpus loader
  - *Goal*: an offline runner that loads labeled fixture diffs and executes the deterministic review path over them.
  - *Likely files*: new harness module (likely under `tests/` or a `benchmarks/`-style directory — final location TBD at implementation), fixtures under `demo/samples/` or a new fixtures dir; `tests/conftest.py`.
  - *Key requirements*: zero network/API keys (reuse `--mock`/`--static` path); corpus files carry no secrets/real diffs; loader validates label schema.
  - *Acceptance*: one command runs the corpus and prints per-case results; runs offline in CI; malformed label file fails loudly.
  - *Dependencies*: —

- **V3-E03-T02** · Scoring metrics definition + implementation
  - *Goal*: deterministic metrics (finding precision/recall proxies vs expected labels, stability across runs) implemented and documented.
  - *Likely files*: same harness module as T01; docs entry in `docs/planning/TESTING_EVALUATION_PLAN.md` if/when that doc exists (else README testing section).
  - *Key requirements*: every metric has a written definition; scoring must be reproducible (same commit ⇒ same score, asserted); no AI in the scoring path.
  - *Acceptance*: two consecutive runs produce identical scores (test); metric definitions documented alongside code; deliberately broken fixture scores lower (test).
  - *Dependencies*: hard `V3-E03-T01`.

- **V3-E03-T03** · Baseline capture + regression gate
  - *Goal*: record current scores as a checked-in baseline; CI compares against it and fails on regression beyond a threshold.
  - *Likely files*: harness module, baseline file, `.github/workflows/ci.yml` (CI change — must be minimal and additive).
  - *Key requirements*: threshold documented (proposed baseline: fail on any critical/high recall drop — mark as proposed baseline); baseline updates are deliberate, reviewed diffs; gate stays offline.
  - *Acceptance*: lowering expected-label coverage in a temp fixture fails the gate (test); baseline file format versioned; CI job addition does not alter existing jobs.
  - *Dependencies*: hard `V3-E03-T02`.

- **V3-E03-T04** · Defect corpus (D1–D7 as harness cases)
  - *Goal*: encode each Phase 0 defect as a harness scenario so future refactors are measured against them too, not only unit tests.
  - *Likely files*: harness fixtures; cross-references `tests/test_defect_regressions.py`.
  - *Key requirements*: cases chosen where the defect changes an *observable review outcome* (e.g. cap-induced false resolved); unit tests remain the primary guard (harness adds end-to-end coverage).
  - *Acceptance*: each harness case fails when its defect is re-introduced (spot-checked during implementation); suite runtime stays bounded (proposed baseline: harness < 60 s offline — mark as proposed baseline).
  - *Dependencies*: hard `V3-E01-T08`, `V3-E03-T01`.

- **V3-E03-T05** · Harness report output + contributor docs
  - *Goal*: machine-readable score output (JSON) + a short contributor guide for adding cases.
  - *Likely files*: harness module, `CONTRIBUTING.md` (docs-only addition allowed? — CONTRIBUTING is outside `docs/planning/`; **ticket proposes it for implementers**, this planning session does not modify it).
  - *Key requirements*: output schema stable enough to diff; guide explains label schema, secret/PII prohibition, and how to update baselines.
  - *Acceptance*: JSON output parses and contains score, case count, and git-identifiable run metadata; docs instructions verified by following them verbatim on a clean checkout.
  - *Dependencies*: hard `V3-E03-T02`.

#### V3-E04 · storage & dashboard debt remediation — tickets

- **V3-E04-T01** · Close SQLite connections (connection lifecycle)
  - *Goal*: `LocalReviewStorage` opens connections per call and never closes them — make every call close its connection (context managers) without changing semantics.
  - *Likely files*: `ai_pr_reviewer/storage.py`, `tests/test_storage_client.py`.
  - *Key requirements*: `with conn` → commit **and** close; per-call open/close behavior otherwise unchanged (no connection pool yet — smallest safe fix); no behavior change for concurrent readers beyond today's guarantees.
  - *Acceptance*: test asserts connections are closed (e.g. file-handle count or `__exit__` instrumentation); full suite green; WAL/locking behavior unchanged.
  - *Dependencies*: —

- **V3-E04-T02** · Retention/pruning policy for `finding_history`
  - *Goal*: configurable, default-off retention that bounds unbounded growth (C9) without losing current lifecycle correctness.
  - *Likely files*: `ai_pr_reviewer/storage.py`, `ai_pr_reviewer/config.py`, `dashboard/storage.py`, `tests/test_storage_client.py`.
  - *Key requirements*: additive config (`retention_days`, default 0=keep-all ⇒ zero behavior change); pruning never removes rows referenced by active `review_state`; same policy honored by engine and dashboard backends; audit rows excluded.
  - *Acceptance*: seeded old rows pruned only when enabled (test); disabled by default asserted (test); pruning is idempotent and resumable.
  - *Dependencies*: hard `V3-E04-T01`.

- **V3-E04-T03** · Shared schema constants module
  - *Goal*: one module owns `fingerprint:` prefix, `review_id` parsing, and cross-store key formats; all three storage implementations import it.
  - *Likely files*: `ai_pr_reviewer/storage.py` (or new shared module in engine), `dashboard/storage.py`, `ai_pr_reviewer/findings.py`, `ai_pr_reviewer/memory.py`.
  - *Key requirements*: behavior-identical refactor first (no logic changes); import-direction respected (dashboard may import engine lazily as it already does for sandbox); grep for duplicated literals must come up empty after.
  - *Acceptance*: literal-duplication test (or grep-based CI check) passes; all three backends pass parity suite; no behavior diffs (suite green with zero fixture changes).
  - *Dependencies*: —

- **V3-E04-T04** · Declare optional `ReviewStorage` capabilities
  - *Goal*: replace the two undeclared `getattr`-guarded capabilities (`get_dismissed_fingerprints`, `list_repo_memory`) with declared protocol members + capability flags, eliminating silently-varying behavior.
  - *Likely files*: `ai_pr_reviewer/storage.py`, `ai_pr_reviewer/context.py` / `orchestrator.py` (call sites), `dashboard/storage.py`, `tests/test_storage_client.py`.
  - *Key requirements*: additive protocol extension (existing implementations keep working); callers branch on capability flag, not `getattr`; documented fallback behavior when a backend lacks a capability.
  - *Acceptance*: no `getattr` guards remain at call sites (grep test); a backend without the capability degrades with a warning (test); both real backends declare full capability set.
  - *Dependencies*: hard `V3-E04-T03`.

- **V3-E04-T05** · Bound dashboard read queries (pagination + indexes)
  - *Goal*: `list_findings`, `stats`, `metrics` stop loading all rows into Python; add pagination/limits and DB-side aggregation.
  - *Likely files*: `dashboard/app.py`, `dashboard/storage.py`, `dashboard/models_db.py`, `dashboard/static/app.js` (if paging UI needed), `tests/test_dashboard_storage.py`.
  - *Key requirements*: additive API params (`limit`/`offset` or cursor) with defaults preserving current page shapes; aggregation moves into the DB; row-count tests on a large synthetic dataset.
  - *Acceptance*: 50k-row fixture serves paged queries in bounded time (proposed baseline: < 500 ms — mark as proposed baseline); default responses remain backward compatible (snapshot test); indexes added additively.
  - *Dependencies*: hard `V3-E04-T03`.

- **V3-E04-T06** · Migration strategy decision (hand-rolled → real tool)
  - *Goal*: write the decision record for *when* to adopt a real migration tool, and inventory current hand-rolled `ALTER TABLE` paths — **proposal only**, adoption deferred until V4 schema growth.
  - *Likely files*: docs (new ADR in `docs/planning/` ADR set — the ADR file itself is written by the planning/implementation effort that owns `ADR_INDEX.md`); `dashboard/storage.py` (inventory, no code change in this ticket).
  - *Key requirements*: document current additive-`ALTER` inventory and failure modes; specify adoption trigger (e.g. first non-additive schema change or Nth additive change — proposed baseline: trigger review at first V4 storage addition); tool evaluation criteria (must support SQLite WAL + Postgres).
  - *Acceptance*: decision record exists and is referenced from `MIGRATION_PLAN.md`; no code changed by this ticket; trigger condition stated.
  - *Dependencies*: —

- **V3-E04-T07** · Backend parity test suite
  - *Goal*: one parametrized suite asserting identical behavior across `LocalReviewStorage`, `DbStorage`, `JsonStorage` (including HTTP client path).
  - *Likely files*: new `tests/test_storage_parity.py`, existing `tests/test_storage_client.py`, `tests/test_dashboard_storage.py`.
  - *Key requirements*: covers lifecycle of every protocol method + both formerly-undeclared capabilities; JsonStorage single-worker limitation documented as an accepted deviation; suite stays offline.
  - *Acceptance*: parametrized run passes for all three backends; an intentionally broken backend fails the parity suite (self-test during implementation); no production code changed except where parity reveals real bugs (file those separately).
  - *Dependencies*: hard `V3-E04-T04`.

#### V3-E05 · config & contract hardening — tickets

- **V3-E05-T01** · Single-source the sensitive-path baseline (D12)
  - *Goal*: one module owns the non-removable privacy exclusion baseline consumed by both `rules.py` and `dashboard/app.py`.
  - *Likely files*: `ai_pr_reviewer/rules.py`, `dashboard/app.py`, possibly `ai_pr_reviewer/security.py`, `tests/test_security.py`, `tests/test_rules.py`.
  - *Key requirements*: baseline remains non-removable (repo config can only *add* exclusions — invariant preserved); dashboard imports engine constant (existing lazy-import pattern); no glob removed from either side (union must not shrink — test asserts).
  - *Acceptance*: a test enumerates both sides and fails on divergence; removal attempt via config still fails (existing invariant tests stay green); dashboard sensitive-glob behavior byte-identical.
  - *Dependencies*: —

- **V3-E05-T02** · Centralize hard-coded caps as named constants (D13 inventory)
  - *Goal*: move the 8 documented hard-coded caps (8 context files, 4 config probes, 50 memory entries, 20 comments, 500 dashboard findings, 8 markdown findings, …) into a named, documented constants surface — values unchanged in this ticket.
  - *Likely files*: `ai_pr_reviewer/context.py`, `ai_pr_reviewer/reporter.py`, `ai_pr_reviewer/orchestrator.py`, `ai_pr_reviewer/memory.py`, `dashboard/app.py`, `dashboard/storage.py`.
  - *Key requirements*: pure refactor (no value changes); each constant gets a comment naming its quality-ceiling consequence; future configurability is out of scope (a later epic decides which become inputs).
  - *Acceptance*: no magic numbers remain at the documented sites (grep test); suite green with zero golden-output changes.
  - *Dependencies*: —

- **V3-E05-T03** · Action contract snapshot test
  - *Goal*: freeze `action.yml` inputs/outputs (names, defaults, descriptions-as-contract) so any breaking change fails CI.
  - *Likely files*: new `tests/test_action_contract.py`, `action.yml`.
  - *Key requirements*: snapshot covers input names/defaults and output names; additive changes allowed via deliberate snapshot update; also asserts example workflow stays on `pull_request` (never `pull_request_target`) and checks out base revision.
  - *Acceptance*: renaming/removing an output fails the test (verified by temporary mutation); adding one passes only with reviewed snapshot diff; invariants (permissions, no `checks: write`) asserted.
  - *Dependencies*: —

- **V3-E05-T04** · Report JSON top-level schema guard
  - *Goal*: freeze `review-report.json` top-level fields and `Finding.to_dict()` keys as additive-only.
  - *Likely files*: new `tests/test_report_schema.py`, `ai_pr_reviewer/reporter.py`, `ai_pr_reviewer/models.py`.
  - *Key requirements*: schema = required top-level fields + required finding keys; unknown/additive fields allowed (dashboard and future consumers rely on that); removals/renames fail.
  - *Acceptance*: removing `health_score` from the report fails CI (verified by mutation); `V3-E01`/`V3-E02` additive fields pass without touching this guard's required list; guard documented as the machine-checkable half of the compatibility contract in `MIGRATION_PLAN.md`.
  - *Dependencies*: —

- **V3-E05-T05** · Config layering precedence test matrix
  - *Goal*: pin CLI > `INPUT_*` > env > defaults precedence, plus the two orthogonal merges (dashboard rules, `.ai-pr-reviewer.yml`), as a full matrix test.
  - *Likely files*: `ai_pr_reviewer/config.py`, `ai_pr_reviewer/rules.py`, `tests/test_config.py`.
  - *Key requirements*: every precedence pair covered; `severity_threshold` explicit-vs-policy override semantics (`_effective_severity_threshold`) pinned; unknown/future keys warn, don't crash (forward compat).
  - *Acceptance*: matrix test enumerates all pairs; existing config tests unchanged; a deliberate precedence flip fails the matrix (mutation-checked).
  - *Dependencies*: hard `V3-E01-T06`.

#### V3-E06 · documentation & release hygiene — tickets

- **V3-E06-T01** · Deprecate legacy facades (`analyzer.py`, `heuristics.py`)
  - *Goal*: emit `DeprecationWarning` from `analyzer`/`heuristics`/`get_analyzer`, correct their stale docstrings, and state the removal release (D11).
  - *Likely files*: `ai_pr_reviewer/analyzer.py`, `ai_pr_reviewer/heuristics.py`, `README.md` (note), `CHANGELOG.md`.
  - *Key requirements*: no production caller exists (verified) — behavior unchanged; warning fires on import/use, not in tests that import them intentionally (filter or update tests); removal happens only in a later major/minor per deprecation policy.
  - *Acceptance*: importing the facade warns with removal version; suite green; grep for docstring claims contradicted by reality returns nothing.
  - *Dependencies*: —

- **V3-E06-T02** · Lint gate in CI (ruff) baseline
  - *Goal*: install and run `ruff` (already configured) as a CI step, with a green baseline (D14 first half).
  - *Likely files*: `.github/workflows/ci.yml`, `pyproject.toml` (config already present), source files **only if** baseline requires trivial fixes (mechanical, separately reviewed).
  - *Key requirements*: gate is additive (new step, existing steps untouched); start with a scope that is green today or fix trivially-safe findings in the same PR; never couple lint changes with behavior changes.
  - *Acceptance*: CI runs ruff and passes; introducing a lint error fails CI (verified locally); lint step runtime negligible.
  - *Dependencies*: —

- **V3-E06-T03** · Python support matrix unification (D14 second half)
  - *Goal*: one authoritative statement of supported Python versions across Action (3.12), CI (3.11–3.13), local (3.14), README, and AGENTS-facing docs.
  - *Likely files*: `README.md`, `.github/workflows/ci.yml`, `action.yml` (comment only if needed), `AGENTS.md` if it restates versions.
  - *Key requirements*: decide + document policy (e.g. Action pins 3.12, CI tests floor→ceiling of supported range, local best-effort — final wording is an implementation decision recorded in the ticket); no silent CI matrix change without stating it.
  - *Acceptance*: all docs state the same matrix; CI matrix matches the documented range; Windows gotchas (`PYTHONUTF8=1`) documented alongside.
  - *Dependencies*: —

- **V3-E06-T04** · Public contract documentation pass
  - *Goal*: README (inputs table, outputs, exit codes 0/1/2, report JSON fields, config layering) matches code exactly, checked against the `V3-E05` snapshots.
  - *Likely files*: `README.md`, `.ai-pr-reviewer.yml.example`, `example-workflow.yml`.
  - *Key requirements*: documentation claims verified against `action.yml`/`config.py`/`reporter.py`; example workflow stays `pull_request` + base checkout; example config stays schema-valid.
  - *Acceptance*: a doc-vs-contract test (or documented checklist run) finds zero mismatches; every exit code documented with its meaning; example config parses under `load_project_rules`.
  - *Dependencies*: hard `V3-E05-T03`, `V3-E05-T04`.

- **V3-E06-T05** · Fixture & demo hygiene audit
  - *Goal`: verify `demo/`, `tests/`, and sample diffs contain no secrets/real PRs/dashboard data, and document the regeneration gotcha (samples rewritten by `build_all()`).
  - *Likely files*: `demo/`, `tests/`, `CONTRIBUTING.md` (proposed edit), `demo/make_fixtures.py`.
  - *Key requirements*: audit is documented (checklist + result), not assumed; line-ending churn warning documented so contributors don't commit CRLF churn; regeneration path stays reproducible.
  - *Acceptance*: audit performed with results recorded; gotcha documented where contributors see it; no files modified in the audit itself beyond docs.
  - *Dependencies*: —

- **V3-E06-T06** · Release hygiene: tagging, CHANGELOG, version story
  - *Goal*: define how releases/tags map to Action major versions (`@v2`/`@v3` pinning guidance) and require CHANGELOG entries for every contract-affecting change.
  - *Likely files*: `CHANGELOG.md`, `README.md` (pinning section), `AGENTS.md`-adjacent contributor docs (proposed).
  - *Key requirements*: states the deprecation windows formalized in `MIGRATION_PLAN.md`; pinning guidance explicit (users advised to pin major tag); release checklist includes contract-snapshot review.
  - *Acceptance*: CHANGELOG has an "Unreleased" section with the Phase 0 contract-relevant entries; pinning guidance documented; checklist exists and references `V3-E05-T03`/`T04` as release gates.
  - *Dependencies*: hard `V3-E05-T03`.

### 3.3 V4 epic ticket breakdowns

#### V4-E01 · repository index — tickets

- **V4-E01-T01** · Index data model + storage schema
  - *Goal*: define entities (files, directories, symbols, import edges) and their additive storage schema (new tables/namespace — no graph DB, ADR-002).
  - *Likely files/new subsystem*: index data model (new module), storage additions in `ai_pr_reviewer/storage.py` / `dashboard/models_db.py`.
  - *Key requirements*: schema versioned from day one; keyed by commit SHA for rebuildability; size budgets declared in schema constraints; privacy-baseline exclusions are structurally un-indexable.
  - *Acceptance*: schema documented + versioned; excluded paths rejected at write (test); rebuild-from-scratch equals incremental (test).
  - *Dependencies*: hard `V3-E04-T03`, `V3-E04-T06` (migration strategy in place first).

- **V4-E01-T02** · Base-revision traversal & extraction
  - *Goal*: walk the tree at `PRContext.base_sha` (per D1 fix) extracting file inventory, language, symbols, and imports deterministically.
  - *Likely files/new subsystem*: traversal/extraction module (new), `ai_pr_reviewer/github_client.py` (read helpers, rate-limit aware per C8), `ai_pr_reviewer/repo_context.py`.
  - *Key requirements*: reads base revision only (invariant); `_safe_repo_path` for every path; bounded (file count, size, time); local mode uses working tree with identical extraction code.
  - *Acceptance*: extraction identical for base-sha and local-tree on the same content (test); oversized/hostile repo aborts with warning, never hangs; no excluded path read (test).
  - *Dependencies*: hard `V4-E01-T01`, `V3-E01-T01`.

- **V4-E01-T03** · Incremental index refresh
  - *Goal*: refresh only what the diff touched instead of full rebuilds per review.
  - *Likely files/new subsystem*: index refresh module (new), reuses `compare_commits` from `ai_pr_reviewer/github_client.py`.
  - *Key requirements*: incremental result proven equal to full rebuild (property test); force-push/fallback reuses existing incremental-diff fallback semantics; index keyed by SHA makes staleness detectable, not dangerous.
  - *Acceptance*: incremental == full on fixtures (test); stale index never serves silently (test: wrong-SHA read fails closed to full path); refresh within time budget (proposed baseline: <2 s for fixture repo — mark as proposed baseline).
  - *Dependencies*: hard `V4-E01-T02`.

- **V4-E01-T04** · Index budgets & failure degradation
  - *Goal*: hard bounds (bytes, entries, build time) with loud, honest degradation when exceeded — review proceeds without index.
  - *Likely files/new subsystem*: budget guards in index module; warning surfacing via existing `context_warnings` mechanism in `ai_pr_reviewer/context.py`.
  - *Key requirements*: budgets are named constants (per `V3-E05-T02` discipline) or config (additive); exceed ⇒ warning + degraded mode, never partial-lying index; telemetry records index status (`V3-E02`).
  - *Acceptance*: budget-exceeded test produces warning + no index reads; run completes normally otherwise (existing tests green); index status visible in report (additive field).
  - *Dependencies*: hard `V4-E01-T02`.

- **V4-E01-T05** · Index security screening
  - *Goal*: every index-derived value passes fencing/redaction before prompt use; index cannot become an injection channel.
  - *Likely files/new subsystem*: screening at the read boundary of the index module; `ai_pr_reviewer/security.py` reuse.
  - *Key requirements*: screening is on the *read* path (defense at consumption, not trust at build); adversarial fixture files (fence spoofing, injection patterns in symbol names) neutralized; secrets-bearing content excluded by baseline before indexing.
  - *Acceptance*: adversarial corpus test: injected instruction strings never appear verbatim in prompt-bound output; planted secret in an indexed file never surfaces (test); zero screening bypass via index path (conformance with `V4-E08`).
  - *Dependencies*: hard `V4-E01-T02`.

- **V4-E01-T06** · Index CLI + observability
  - *Goal*: build/inspect the index from the CLI for debugging (`build`, `stats` subcommands — additive to existing invocation).
  - *Likely files*: `ai_pr_reviewer/cli.py`, index module(s), `README.md` (docs).
  - *Key requirements*: existing invocation unchanged (`python -m ai_pr_reviewer --diff-file … --mock` snapshot-tested); stats output shows size/entries/build time; no network in local mode.
  - *Acceptance*: old CLI flags behave identically (snapshot); `stats` reports real numbers; offline operation asserted (test).
  - *Dependencies*: hard `V4-E01-T03`, `V4-E01-T04`.

#### V4-E02 · context engine v2 — tickets

- **V4-E02-T01** · Shared prompt assembly layer (C2 extraction)
  - *Goal*: one prompt-builder consumed by all three providers; delete the triplicated `SYSTEM_PROMPT`/`_extract_json`.
  - *Likely files*: `ai_pr_reviewer/ai/claude.py`, `ai_pr_reviewer/ai/openai.py`, `ai_pr_reviewer/ai/gemini.py`, new shared prompt module, `tests/test_ai_provider.py`.
  - *Key requirements*: byte-identical prompt output vs today for the same context (golden snapshot); `_extract_json` consolidation with identical tolerance behavior; no provider-specific logic in the shared layer except declared capabilities.
  - *Acceptance*: golden prompt snapshots identical pre/post refactor (test built from current behavior); triplication gone (grep); all provider tests green.
  - *Dependencies*: —

- **V4-E02-T02** · Unified budget object (fixes C7)
  - *Goal*: single token-aware budget object summing all context contributors (diff, repo context, memory, previous findings, later feeds) with one ceiling.
  - *Likely files*: `ai_pr_reviewer/context.py`, `ai_pr_reviewer/config.py`, new budget module (likely), `tests/test_context.py`.
  - *Key requirements*: `token_budget` misnomer resolved (chars→estimated tokens with documented conversion factor — proposed baseline: chars/4 estimate, validate against real usage telemetry from `V3-E02` — mark as proposed baseline); all current inputs keep working (`batch_chars`, `repo_context_chars` map into the budget with deprecation notes); security context never the truncation victim (explicit priority ordering, test).
  - *Acceptance*: sum-of-contributors ≤ ceiling in every test path; existing inputs produce equivalent effective limits (compat test); conversion accuracy reported from telemetry (not asserted as exact).
  - *Dependencies*: hard `V3-E02-T02` (needs usage data), `V4-E01-T04`.

- **V4-E02-T03** · Retrieval API over the index
  - *Goal*: replace the static 8-file/16-probe fetch with query-based retrieval (symbols referenced by the diff, their importers, config files, docs) under the budget.
  - *Likely files/new subsystem*: retrieval module (new), `ai_pr_reviewer/repo_context.py` (demoted to fallback), `ai_pr_reviewer/context.py`.
  - *Key requirements*: `repo_context.py` remains the absent-index fallback with byte-equivalent behavior; retrieval results carry provenance (`V4-E04`); every result screened (`V4-E01-T05` path); D13 caps centralized not removed silently.
  - *Acceptance*: with index absent, output byte-identical to pre-V4 (test); with index, retrieved set includes known cross-file reference missed by 16-probe fetch (fixture test); budget ceiling never exceeded (test).
  - *Dependencies*: hard `V4-E01-T03`, `V4-E02-T02`.

- **V4-E02-T04** · Deterministic relevance ranking
  - *Goal*: rank retrieval candidates deterministically (diff-touched > direct importers > N-hop > peripheral) so context selection is explainable.
  - *Likely files/new subsystem*: ranking module (new), `tests/test_context.py`.
  - *Key requirements*: fully deterministic (no AI for ordering — principle #2); ranking factors logged as provenance so users see *why* context was chosen; ties broken stably.
  - *Acceptance*: same inputs ⇒ same ranking (test); ranking factors present in provenance output; golden ranking fixture committed.
  - *Dependencies*: hard `V4-E02-T03`.

- **V4-E02-T05** · Context-budget telemetry + token savings report
  - *Goal*: measure and report context-engine savings (tokens used vs ceiling, sources by category) via `V3-E02` telemetry.
  - *Likely files*: `ai_pr_reviewer/context.py`, `ai_pr_reviewer/reporter.py`, `dashboard/app.py` (metrics read-only).
  - *Key requirements*: additive report fields; savings claims computed, not asserted (feeds `V3-E03` harness); redaction applies.
  - *Acceptance*: report shows budget usage by source category; harness measures median token delta vs baseline (proposed baseline: ≥20% reduction — mark as proposed baseline); no content in telemetry (test).
  - *Dependencies*: hard `V4-E02-T03`.

#### V4-E03 · change impact analysis — tickets

- **V4-E03-T01** · Direct-dependency extraction (callers/importers)
  - *Goal*: for each symbol/file touched by the diff, resolve its direct dependents from the index graph.
  - *Likely files/new subsystem*: impact module (new), reads index data only.
  - *Key requirements*: resolution is index-only (no runtime code execution, no network); unresolved references reported as unknown, never guessed (confidence field mandatory).
  - *Acceptance*: known call-chain fixture returns correct direct dependents; unknown references produce `unknown` confidence (test); deterministic across runs.
  - *Dependencies*: hard `V4-E01-T01`.

- **V4-E03-T02** · Bounded N-hop propagation
  - *Goal*: propagate to dependents with a hard hop/size cap and honest truncation signaling.
  - *Likely files/new subsystem*: impact module, budget integration from `V4-E02-T02`.
  - *Key requirements*: caps as named constants; truncation reported ("impact truncated at hop 2"), never silent; pathological fan-out fixture terminates within time budget.
  - *Acceptance*: pathological fixture completes under cap (test: bounded runtime + truncation signal); depth/size limits documented; zero unbounded recursion possible (structural test).
  - *Dependencies*: hard `V4-E03-T01`.

- **V4-E03-T03** · Impact set → review focus signals
  - *Goal*: feed the impact set into context retrieval (what to read) and risk/depth inputs (how hard to look) — outputs, not decisions.
  - *Likely files*: `ai_pr_reviewer/context.py`, impact module, `ai_pr_reviewer/orchestrator.py` (signal wiring only).
  - *Key requirements*: signals are additive inputs; absence of impact ⇒ unchanged behavior; no finding is generated from impact alone (impact is context, evidence is per-finding).
  - *Acceptance*: context includes impact-derived retrieval when present (test); absent impact ⇒ byte-identical behavior (test); no new finding types introduced by this ticket.
  - *Dependencies*: hard `V4-E02-T03`, `V4-E03-T02`.

- **V4-E03-T04** · Impact evidence rendering (report/dashboard)
  - *Goal*: surface "this change affects …" with per-edge provenance in report JSON and dashboard, additive fields only.
  - *Likely files*: `ai_pr_reviewer/reporter.py`, `dashboard/static/app.js`, `dashboard/app.py` (read-only).
  - *Key requirements*: additive schema (passes `V3-E05-T04` guard unchanged); every listed impact cites an index entry + hop; redaction on file/symbol names per existing rules.
  - *Acceptance*: report contains impact section with provenance when computed, absent otherwise (test); schema guard passes; dashboard renders without breaking old reports (backcompat test).
  - *Dependencies*: hard `V4-E03-T02`.

#### V4-E04 · evidence engine & provenance — tickets

- **V4-E04-T01** · Provenance field design on `Finding` (additive)
  - *Goal*: add optional provenance fields (source kind, locator, hash, captured-at, confidence) to `Finding` without touching lifecycle stripping.
  - *Likely files*: `ai_pr_reviewer/models.py`, `tests/test_findings.py`.
  - *Key requirements*: provenance is pipeline-owned → added to `LIFECYCLE_FIELDS`-equivalent stripping set so `from_untrusted_dict` drops model-supplied provenance; additive `to_dict()` output; absent provenance renders as explicit null-with-reason, never crashes.
  - *Acceptance*: model output carrying forged provenance is stripped (test); old serialized findings round-trip (test); report schema guard passes (additive).
  - *Dependencies*: —

- **V4-E04-T02** · Evidence record schema + storage
  - *Goal*: persistent evidence records (source, locator, content hash, captured-at, redacted snapshot-or-reference) with additive storage.
  - *Likely files/new subsystem*: evidence store (new entity via `ReviewStorage` seam), `ai_pr_reviewer/storage.py`, `dashboard/storage.py`.
  - *Key requirements*: content-hash integrity (tamper-evident); snapshots redacted before write; retention policy from `V3-E04-T02` applies; never stores unredacted secrets (test).
  - *Acceptance*: evidence round-trips byte-identically post-redaction; planted secret absent from stored evidence (test); retention prunes evidence with findings (test).
  - *Dependencies*: hard `V4-E04-T01`, `V3-E04-T02`.

- **V4-E04-T03** · Provenance attachment through the pipeline
  - *Goal*: every pipeline stage that produces or transforms a finding records where it came from (engine/model/static rule ID/human).
  - *Likely files*: `ai_pr_reviewer/orchestrator.py`, `ai_pr_reviewer/static/engine.py`, `ai_pr_reviewer/ai/*.py`, `ai_pr_reviewer/findings.py`.
  - *Key requirements*: attribution survives dedup (dedup keeps first occurrence *and* merges provenance list — fixes C3's "dedup destroys attribution"); deterministic engines carry rule IDs; AI findings carry model + prompt-version identifier.
  - *Acceptance*: a deduped finding from two engines retains both provenance records (test); static findings cite rule IDs (test); no finding in any report lacks provenance (invariant test).
  - *Dependencies*: hard `V4-E04-T01`.

- **V4-E04-T04** · Provenance in report + dashboard rendering
  - *Goal*: "why was I told this" is answerable in both the artifact and the UI.
  - *Likely files*: `ai_pr_reviewer/reporter.py`, `dashboard/app.py`, `dashboard/static/app.js`.
  - *Key requirements*: additive JSON (schema guard passes); UI shows provenance without exposing redacted content; null-provenance renders as "unavailable (reason)".
  - *Acceptance*: report finding carries provenance; dashboard detail view renders it; backcompat with old reports (no provenance) tested.
  - *Dependencies*: hard `V4-E04-T03`.

- **V4-E04-T05** · Evidence redaction + untrusted-content conformance
  - *Goal*: structural guarantee that evidence ingestion passes `redact_secrets()` + fencing (the security half of the epic).
  - *Likely files*: `ai_pr_reviewer/security.py`, evidence store module, `tests/test_security.py`.
  - *Key requirements*: redaction is *inside* the evidence write path, not at callers; adversarial evidence payloads (fence spoofing, planted keys) neutralized; conformance reusable by `V4-E08`.
  - *Acceptance*: adversarial suite passes (planted secrets/never-verbatim instructions); redaction-at-write proven (test bypasses callers, writes direct, still redacted); `V4-E08` can import the conformance checks.
  - *Dependencies*: hard `V4-E04-T02`.

#### V4-E05 · finding identity v2 — tickets

- **V4-E05-T01** · Identity v2 specification + ADR
  - *Goal*: write the v2 basis (fields, normalization, location anchoring) and record it as an ADR in the ADR set (`ADR_INDEX.md` — ADR-005 per plan references).
  - *Likely files/new subsystem*: ADR document (planning docs), spec comment in findings module at implementation time.
  - *Key requirements*: must preserve the deliberate line-exclusion property where still desired (churn tolerance) while fixing cross-engine wording sensitivity; must define stability guarantees and failure modes; explicitly out of scope: model-influenced identity.
  - *Acceptance*: spec exists with worked examples (same issue, different engines/wordings ⇒ same identity; different issues ⇒ different); stability properties stated; rollback to v1 specified.
  - *Dependencies*: hard `V4-E04-T03` (provenance participates), `V3-E03-T02` (metrics to prove it).

- **V4-E05-T02** · Dual-computation (v1 + v2) implementation
  - *Goal*: add provenance fields and occurrence key to every finding; v1 remains authoritative.
  - *Likely files*: `ai_pr_reviewer/findings.py`, `ai_pr_reviewer/models.py`, `tests/test_findings.py`.
  - *Key requirements*: v1 output byte-identical (regression: existing fingerprint tests unchanged); v2 computed alongside; disagreement rate surfaced as telemetry (`V3-E02`).
  - *Acceptance*: both fingerprints present on every new finding (test); v1 unchanged for all existing fixtures (test); disagreement rate visible in report (additive field).
  - *Dependencies*: hard `V4-E05-T01`.

- **V4-E05-T03** · Alias table + identity resolver
  - *Goal*: storage of v1↔v2 aliases and a single resolver used by every fingerprint consumer.
  - *Likely files/new subsystem*: alias storage (additive table via `ReviewStorage` seam), resolver module, call sites in `ai_pr_reviewer/findings.py`, `ai_pr_reviewer/verification.py`, `ai_pr_reviewer/memory.py` (mute rows), `dashboard/app.py` (feedback/mute routes).
  - *Key requirements*: resolver accepts either version, returns canonical; every consumer migrated (grep for raw fingerprint use must go through resolver); alias rows are trusted pipeline state (never writable from untrusted input — test).
  - *Acceptance*: lookup by v1 resolves to v2-canonical and vice versa (test); all call sites use resolver (grep test); untrusted input cannot insert aliases (test).
  - *Dependencies*: hard `V4-E05-T02`.

- **V4-E05-T04** · Backfill existing fingerprints (zero-orphan)
  - *Goal*: backfill provenance fields on existing `finding_history` rows where determinable.
  - *Likely files/new subsystem*: backfill routine (CLI-invoked, idempotent), `ai_pr_reviewer/storage.py`, `dashboard/storage.py`.
  - *Key requirements*: idempotent + resumable; **no row deleted** — aliases added, payloads untouched; run on all three backends; engine SQLite and dashboard stores both covered.
  - *Acceptance*: backfilled DB: 100% of stored fingerprints resolve with provenance (test); re-running backfill changes nothing (idempotency test); rollback (drop provenance columns) restores v1-only behavior exactly.
  - *Dependencies*: hard `V4-E05-T03`.

- **V4-E05-T05** · Dual-computation soak + disagreement review
  - *Goal*: measure v1↔v2 disagreement in real runs before switching authority; review every disagreement class.
  - *Likely files*: telemetry (`V3-E02` fields), harness comparisons (`V3-E03`), report additive field.
  - *Key requirements*: occurrence key enables cross-engine dedup without changing v1 identity; disagreement report (v1 vs occurrence-key match rate) is a deliverable.
  - *Acceptance*: soak report exists with class breakdown; gate decision recorded (proceed/fix); no unexplained disagreement classes.
  - *Dependencies*: hard `V4-E05-T02`, `V3-E03-T02`.

- **V4-E05-T06** · Cutover to v2 authority (flagged, reversible)
  - *Goal*: switch consumers to v2-canonical identity behind a config flag (default on after soak), v1 retained read-only.
  - *Likely files*: resolver module, `ai_pr_reviewer/config.py` (additive flag), consumers migrated in T03.
  - *Key requirements*: one-flag revert to v1-only (ignore occurrence key); dedup/cross-engine quality measured before/after via harness (`V5-E08`-style A/B via `V3-E03`).
  - *Acceptance*: harness shows cross-engine duplicate reduction (measurable improvement, test asserts direction); flag-off reproduces v1 behavior byte-identically (test); mute-by-old-fingerprint still works (test).
  - *Dependencies*: hard `V4-E05-T04`, `V4-E05-T05`.

#### V4-E06 · digital twin seed — tickets

- **V4-E06-T01` · Layered projection schema
  - *Goal*: define the projection layers (files → symbols → modules → dependency edges) as a versioned, rebuildable read model keyed by commit.
  - *Likely files/new subsystem*: twin projection module (new), consumes index schema (`V4-E01-T01`).
  - *Key requirements*: strictly a *projection* — no write-ahead/event-sourcing, no graph DB (ADR-002); rebuildable from index + git state alone; schema versioned.
  - *Acceptance*: projection builds from index data only (test: no other inputs); version field enforced; rebuild-from-zero documented and tested.
  - *Dependencies*: hard `V4-E01-T01`, `V4-E02-T03`.

- **V4-E06-T02` · Snapshot builder (full + incremental)
  - *Goal*: build twin snapshots per commit, incrementally refreshed during reviews.
  - *Likely files/new subsystem*: twin builder (new), wired into orchestrator context phase (non-blocking, degrade-and-warn).
  - *Key requirements*: review must not fail or block on twin build (stable assumption §13.6); incremental update proven equal to full rebuild (property test); build time budgeted (proposed baseline: ≤ index build time — mark as proposed baseline).
  - *Acceptance*: incremental == full (test); twin build failure ⇒ warning only, review proceeds (test); budgets enforced.
  - *Dependencies*: hard `V4-E06-T01`, `V4-E01-T03`.

- **V4-E06-T03` · Twin read API via intelligence contract
  - *Goal*: expose the twin through the `V4-E07` read protocol (availability states, capability flags), never by direct module import.
  - *Likely files/new subsystem*: read-contract implementation for twin; orchestrator/context consume via contract.
  - *Key requirements*: contract conformance suite (from `V4-E07-T02`) must cover twin; absent-twin path = current behavior.
  - *Acceptance*: twin read only through protocol (import-lint test); conformance suite green; absent ⇒ byte-identical behavior (test).
  - *Dependencies*: hard `V4-E06-T01`, `V4-E07-T02`.

- **V4-E06-T04` · Drift & retention controls
  - *Goal*: bound twin storage (retention per `V3-E04-T02`) and compute structural drift between snapshots (what changed structurally since last review).
  - *Likely files/new subsystem*: drift computation (new), retention wiring.
  - *Key requirements*: drift output is additive context (feeds `V6-E04` later); retention never breaks rebuildability (dropped snapshots rebuildable from source); no autonomous write actions ever derived from drift.
  - *Acceptance*: drift between two crafted snapshots correct (test); retention prunes snapshots but rebuild still works (test); drift never triggers remediation (structural test).
  - *Dependencies*: hard `V4-E06-T02`.

#### V4-E07 · intelligence read contracts — tickets

- **V4-E07-T01` · Read protocol definition + availability semantics
  - *Goal*: declare the intelligence read protocol (methods, return shapes, `available|building|degraded|absent` states, capability flags) modeled on `ReviewStorage`.
  - *Likely files/new subsystem*: protocol module (new); `ai_pr_reviewer/storage.py` as pattern reference.
  - *Key requirements*: read-only by construction (no method may mutate); every returned value already-screened (contract-level security rule); states are explicit, exceptions are contract violations.
  - *Acceptance*: protocol documented with state machine; misuse (write attempt) unrepresentable (type-level test or conformance failure); state transitions defined for absent→available.
  - *Dependencies*: hard `V4-E01-T01`, `V4-E04-T01`.

- **V4-E07-T02` · Conformance test kit
  - *Goal*: reusable suite every intelligence implementation must pass (like the `ReviewStorage` parity idea, but declared).
  - *Likely files/new subsystem*: conformance module under `tests/`.
  - *Key requirements*: covers security invariants (screened content only), state handling, absence behavior, budget compliance; designed so `V5`+ contributors reuse it (documented).
  - *Acceptance*: index, impact, evidence, twin implementations all pass (parametrized test); a deliberately broken implementation fails (self-test); kit documented for external implementers.
  - *Dependencies*: hard `V4-E07-T01`.

- **V4-E07-T03` · Orchestrator migration to contract reads
  - *Goal*: orchestrator/context consume intelligence only through the protocol; direct imports of index/twin modules become import errors.
  - *Likely files*: `ai_pr_reviewer/orchestrator.py`, `ai_pr_reviewer/context.py`, import-lint test.
  - *Key requirements*: behavior-preserving migration (byte-identical outputs on corpus pre/post); degraded/absent states wired to warnings via existing `context_warnings`.
  - *Acceptance*: import-lint test enforces protocol-only consumption; corpus output byte-identical (harness); degraded state produces honest warning (test).
  - *Dependencies*: hard `V4-E07-T02`.

- **V4-E07-T04` · "Intelligence used" reporting
  - *Goal*: every report states which intelligence sources were available/used/refused (honest-engine-labelling extended to intelligence).
  - *Likely files*: `ai_pr_reviewer/reporter.py`, dashboard report view, `tests/test_review_experience.py`.
  - *Key requirements*: additive report fields; absent intelligence reported as absent (never implied present); fields pass schema guard.
  - *Acceptance*: report enumerates source states accurately in present/absent/degraded runs (three tests); UI renders it; guard passes.
  - *Dependencies*: hard `V4-E07-T01`.

#### V4-E08 · intelligence security & budgets — tickets

- **V4-E08-T01` · Threat model for intelligence surfaces
  - *Goal*: document attack surfaces (index build, retrieval, impact, twin, evidence) with concrete abuse cases and required controls, feeding `SECURITY_ROADMAP.md`.
  - *Likely files/new subsystem*: threat-model document (planning docs), referenced by `V4` tickets' security requirements.
  - *Key requirements*: covers poisoning (malicious repo content), path/symlink escapes, fence spoofing, budget-exhaustion DoS; maps each abuse case to a control + test ticket; inherits base-revision trust model.
  - *Acceptance*: each listed abuse case has an owning control and test; doc reviewed against actual `V4` implementation surfaces; no surface documented-but-uncontrolled (gap list explicit).
  - *Dependencies*: hard `V4-E01-T01`, `V4-E02-T03` (surfaces exist).

- **V4-E08-T02` · Screened-by-default read boundary
  - *Goal*: make screening structural at the contract level — no intelligence value reaches a prompt without passing fence+redact (conformance-enforced, not caller-disciplined).
  - *Likely files/new subsystem*: security wrapper at protocol boundary; `ai_pr_reviewer/security.py`; conformance suite (`V4-E07-T02`).
  - *Key requirements*: wrapper applies `wrap_untrusted_diff`-style fencing + `redact_secrets` to all returned content; direct-bypass attempts fail conformance; performance overhead measured and bounded.
  - *Acceptance*: conformance test fails for an unscreened implementation (self-test); adversarial corpus returns zero verbatim injected instructions (test); overhead within budget (proposed baseline: <10% of context build time — mark as proposed baseline).
  - *Dependencies*: hard `V4-E07-T01`.

- **V4-E08-T03` · Resource budgets (build/retrieval/prompt-attach)
  - *Goal*: named, enforced budgets for index build time/size, retrieval hops/results, and intelligence tokens in prompt — each exceeding ⇒ warning + degrade, never hang or silent truncation.
  - *Likely files/new subsystem*: budget enforcement in index/retrieval modules; telemetry fields (`V3-E02`).
  - *Key requirements*: budgets wired to the `V4-E02-T02` unified budget where prompt-attached; per-stage budgets declared in one place (per `V3-E05-T02`); degrade is loud and honest.
  - *Acceptance*: each budget has an exhaustion test producing warning + continued review; ceilings visible in telemetry; no path blocks indefinitely (time-bound test).
  - *Dependencies*: hard `V4-E02-T02`, `V4-E01-T04`.

- **V4-E08-T04` · Adversarial intelligence corpus
  - *Goal*: permanent adversarial fixture set (hostile file names, fence-spoofing contents, injection in symbol names, symlink/`../` paths, oversized trees) gated in the harness.
  - *Likely files/new subsystem*: adversarial fixtures + harness integration (`V3-E03`).
  - *Key requirements*: fixtures synthetic and secret-free (`CONTRIBUTING.md`); every threat-model abuse case from T01 has ≥1 fixture; benign twins prevent over-blocking.
  - *Acceptance*: corpus green on current code; reintroducing a removed control fails a fixture (mutation-checked); CI runs offline.
  - *Dependencies*: hard `V4-E08-T01`.

- **V4-E08-T05` · Intelligence security regression gate
  - *Goal*: wire T01–T04 outcomes into CI as a blocking gate so V4 security can't regress silently.
  - *Likely files*: `.github/workflows/ci.yml` (additive step), harness (`V3-E03`), conformance suite.
  - *Key requirements*: gate is offline + deterministic; failures name the broken control; gate additions don't alter existing jobs.
  - *Acceptance*: gate blocks on a planted violation (verified locally); runtime bounded (proposed baseline: <2 min — mark as proposed baseline); existing CI untouched.
  - *Dependencies*: hard `V4-E08-T02`, `V4-E08-T04`.

### 3.4 V5–V10 epic ticket outlines (IDs + titles only)

Tickets for later stages are intentionally cut at title level only — details
would be fiction until their prerequisite epics are verified complete. Each
line is one proposed ticket; counts are exact and feed §4.

**V5 — Multi-agent engineering review**

- V5-E01-T01 · Fan-out scheduler with bounded concurrency and per-task isolation
- V5-E01-T02 · Re-scope circuit breakers per task (retire process-global assumption, C5)
- V5-E01-T03 · Partial-failure semantics: degraded-but-honest multi-agent run
- V5-E01-T04 · Determinism guarantee: task completion order must not affect output
- V5-E01-T05 · Fan-out feature flag + single-agent equivalence gate
- V5-E02-T01 · Shared prompt-builder + `_extract_json` consolidation (if not done in V4-E02-T01)
- V5-E02-T02 · Specialist contract schema (inputs/outputs/scope/non-goals)
- V5-E02-T03 · Deterministic specialist slots (regex/AST/API-shape checks)
- V5-E02-T04 · Specialist conformance suite + generalist default equivalence
- V5-E03-T01 · Provenance-aware cross-specialist dedup on identity v2
- V5-E03-T02 · Severity reconciliation rules (deterministic, explainable)
- V5-E03-T03 · Conflict records instead of silent winners
- V5-E03-T04 · Golden merge corpus + determinism-under-ordering tests
- V5-E04-T01 · Risk feature set v1 (size, sensitivity, impact, history signals)
- V5-E04-T02 · Explainable score output (contributions in report)
- V5-E04-T03 · Depth routing policy mapping risk → specialist set + budget
- V5-E04-T04 · Security-depth floor: config can never reduce below baseline (test-enforced)
- V5-E05-T01 · Provider capability registry schema + in-tree provider entries
- V5-E05-T02 · Registry-driven routing replacing 7 hard-coded wiring sites
- V5-E05-T03 · Config validation via registry (actionable exit-1 errors)
- V5-E05-T04 · Retired-model-ID scan extended to registry data
- V5-E06-T01 · Synthesis stage contract (annotate-only, findings immutable)
- V5-E06-T02 · Disagreement/confidence section rendering
- V5-E06-T03 · Evidence-linked narrative (every claim cites an evidence ID)
- V5-E06-T04 · Synthesis injection resistance tests
- V5-E07-T01 · Per-run budget ledger (reserve → allocate → settle)
- V5-E07-T02 · Hard ceiling enforcement with honest skip warnings
- V5-E07-T03 · `response_budget` → documented token ceilings mapping
- V5-E07-T04 · Cost reporting in dashboard (spend per run, per backend)
- V5-E08-T01 · Multi-agent corpus scenarios (merge/disagreement/depth cases)
- V5-E08-T02 · Merge precision/recall scoring in harness
- V5-E08-T03 · Cost-per-true-positive curves + single-vs-multi A/B report
- V5-E08-T04 · Concurrency flakiness control (repeat-run stability gate)

**V6 — Security + testing + architecture intelligence**

- V6-E01-T01 · Security analyzers module + rule registry extension
- V6-E01-T02 · Security finding severity model + CWE-style classification
- V6-E01-T03 · Dataflow-lite checks over diff + index (deterministic)
- V6-E01-T04 · Cross-file security signals via retrieval (budgeted)
- V6-E01-T05 · Security findings rendering + false-positive controls
- V6-E02-T01 · Injection detection for retrieved/context content (beyond 8 patterns)
- V6-E02-T02 · Model-output attack patterns (exfiltration/tool-abuse attempts)
- V6-E02-T03 · Prompt-perimeter hardening applied at shared prompt-builder
- V6-E02-T04 · Per-stage untrusted-surface checklist enforced by tests
- V6-E03-T01 · Test taxonomy in index (files, frameworks, test→module mapping)
- V6-E03-T02 · Changed-code → existing-test mapping
- V6-E03-T03 · Coverage-gap findings with symbol-level evidence
- V6-E03-T04 · Test evidence records for verification tier T2
- V6-E04-T01 · Architecture description schema (trusted config, additive YAML)
- V6-E04-T02 · Layer/dependency-direction checker over index graph
- V6-E04-T03 · Architecture drift vs twin snapshot
- V6-E04-T04 · Violation findings with offending-edge evidence
- V6-E05-T01 · Verification tier model (T0 coverage → T1 static → T2 test evidence)
- V6-E05-T02 · Static re-check tier (pattern gone after fix)
- V6-E05-T03 · Consumed test-evidence adapter (read-only, no in-review execution)
- V6-E05-T04 · Tier attribution field + evidence-forgery rejection tests
- V6-E06-T01 · Manifest parsers (pip, npm; ecosystem list explicit)
- V6-E06-T02 · Diff-aware dependency change detection
- V6-E06-T03 · Offline advisory source interface (no network by default)
- V6-E06-T04 · License/staleness signals + exclusion-respected reads
- V6-E07-T01 · Policy schema v2 (structured clauses, additive to `.ai-pr-reviewer.yml`)
- V6-E07-T02 · Deterministic policy evaluator + clause provenance
- V6-E07-T03 · Policy findings pipeline integration (never auto-remediation)
- V6-E07-T04 · v1-config compatibility + non-removable-baseline tests
- V6-E08-T01 · Labeled vulnerable + benign-twin corpus per V6-E01 rule
- V6-E08-T02 · Detection/false-positive rate metrics in harness
- V6-E08-T03 · CI thresholds + baseline file for security detection
- V6-E08-T04 · Adversarial AI-security cases shared with V4-E08 corpus

**V7 — Historical / project / team intelligence**

- V7-E01-T01 · Bounded git history index (commits, churn, co-change)
- V7-E01-T02 · Churn/co-change queries via read contract
- V7-E01-T03 · Commit-message fencing + redaction on retrieval
- V7-E01-T04 · Depth/time budgets + role-only (never ranking) authorship handling
- V7-E02-T01 · Memory schema v2 (scopes, provenance classes) — additive tables
- V7-E02-T02 · Authority precedence resolution across all scope pairs
- V7-E02-T03 · Human-gated promotion workflow with audit trail
- V7-E02-T04 · Legacy `repo_memory` import as `human-authored` (zero semantic change)
- V7-E02-T05 · Read API returns authority labels on every item
- V7-E03-T01 · Relation model (types, confidence, provenance) + storage
- V7-E03-T02 · Deterministic relation computation (duplicate-of, supersedes)
- V7-E03-T03 · Conservative AI-proposed relations (confirm-before-merge)
- V7-E03-T04 · Relation rendering + "relations never drop findings" tests
- V7-E04-T01 · Read-only issue/requirement ingestion (rate-limit aware, C8)
- V7-E04-T02 · Linkage scoring with evidence + explicit confidence
- V7-E04-T03 · Gap signals wording + "never asserted compliance" tests
- V7-E04-T04 · Issue-text fencing/redaction + privacy-baseline respect
- V7-E05-T01 · Aggregation-at-write analytics projections (replace O(all) reads)
- V7-E05-T02 · Metric definitions + reproducibility tests
- V7-E05-T03 · No-individual-dimension schema guard + small-cohort suppression
- V7-E05-T04 · Dashboard trend/hotspot views over projections
- V7-E06-T01 · Unified historical retrieval step under the budget object
- V7-E06-T02 · Provenance tags on every historical prompt item (test-enforced)
- V7-E06-T03 · Authority-label survival into prompts
- V7-E06-T04 · Historical-feed token ceiling + disabled-equals-baseline test
- V7-E07-T01 · Memory threat model + write-path screening/authority enforcement
- V7-E07-T02 · Append-only memory audit trail
- V7-E07-T03 · Retention/PII hygiene (never prune `human-authored` silently)
- V7-E07-T04 · Memory poisoning corpus gated in CI

**V8 — CI / release / incident intelligence**

- V8-E01-T01 · GitHub API rate-limit handling (X-RateLimit awareness, C8) — prerequisite
- V8-E01-T02 · CI run/workflow-run read-only ingestion adapters
- V8-E01-T03 · Normalized run records + additive storage schema
- V8-E01-T04 · Run↔commit/PR correlation + log redaction on ingest
- V8-E01-T05 · Read-only guard tests (no write endpoints invoked)
- V8-E02-T01 · Failure signature normalization (test ID, suite, error class)
- V8-E02-T02 · Pre/post change-window failure comparison
- V8-E02-T03 · Correlation confidence model + "no unrelated claims" tests
- V8-E02-T04 · Failure evidence rendering for review + verification T2 input
- V8-E03-T01 · Tag/release ingestion (read-only) + fixture repos
- V8-E03-T02 · Diff-since-last-release computation (bounded)
- V8-E03-T03 · Release risk aggregation over shipped changes
- V8-E03-T04 · Draft release-note generation (human-triggered only, no publishing)
- V8-E04-T01 · Doc inventory + structure from index
- V8-E04-T02 · Code↔doc linkage with explicit confidence
- V8-E04-T03 · Staleness/drift findings citing both sides as evidence
- V8-E04-T04 · Excluded-path + no-compliance-claim tests
- V8-E05-T01 · Infra file parsers (workflow YAML, Dockerfile; parse-never-execute)
- V8-E05-T02 · Misconfiguration rules (permissions, pinning, secrets handling)
- V8-E05-T03 · Deploy-path change risk context
- V8-E05-T04 · Rule fixtures with benign twins + malformed-file safety tests
- V8-E06-T01 · Configured-source incident ingestion (allow-listed, opt-in)
- V8-E06-T02 · Incident redaction + retention on ingest
- V8-E06-T03 · Change-linkage as confidence-labeled evidence
- V8-E06-T04 · Read-only boundary + absent-config no-surface tests
- V8-E07-T01 · Versioned internal event schema (payload = untrusted-derived)
- V8-E07-T02 · In-process dispatcher with bounded queues + backpressure
- V8-E07-T03 · Redaction-on-emit + schema validation
- V8-E07-T04 · Subscriber contracts (telemetry, analytics, dashboard sync)
- V8-E07-T05 · Synchronous fallback + bus-disabled equivalence tests

**V9 — Organization platform**

- V9-E01-T01 · Org entity + owner-derived scope columns (additive)
- V9-E01-T02 · Storage-seam org isolation (structurally impossible cross-org reads)
- V9-E01-T03 · Legacy row adoption (zero-rewrite org derivation)
- V9-E01-T04 · Cross-repo query layer (index-backed, bounded)
- V9-E01-T05 · Adversarial cross-tenant/cross-org isolation suite
- V9-E02-T01 · Org policy documents (versioned, trusted, base-revision read)
- V9-E02-T02 · Inheritance precedence resolver (org>team>repo, explicit overrides)
- V9-E02-T03 · Clause provenance: every evaluation cites deciding scope
- V9-E02-T04 · Baseline-integrity tests (org config can only add exclusions)
- V9-E03-T01 · Versioned `/v1` API surface + published schema
- V9-E03-T02 · Scoped tokens + authz matrix (read/write/org) with existing crypto discipline
- V9-E03-T03 · Additive-only schema-diff gate for public API
- V9-E03-T04 · Deprecation headers + unversioned-route compat window
- V9-E03-T05 · OpenAPI publication + contract test kit
- V9-E04-T01 · Workload boundary analysis (measure before queue — anti-pattern gate)
- V9-E04-T02 · Bounded queue + worker execution for identified heavy tasks
- V9-E04-T03 · Idempotent handlers + at-least-once delivery semantics
- V9-E04-T04 · In-process default + queue-disabled equivalence tests
- V9-E05-T01 · Org-scope memory store + precedence extension
- V9-E05-T02 · Human-gated org promotion with audit (no engine writes)
- V9-E05-T03 · Cross-repo memory retrieval authorization
- V9-E05-T04 · Org-scope poisoning corpus + isolation tests
- V9-E06-T01 · Extension point inventory + stability levels (`experimental|stable|frozen`)
- V9-E06-T02 · `ReviewStorage` capabilities fully declared (no `getattr` — grep test)
- V9-E06-T03 · Conformance kit per extension point + current implementations pass
- V9-E06-T04 · Breaking-change rule documentation + frozen-surface CI gate
- V9-E07-T01 · Unified metrics/trace schema over telemetry + events
- V9-E07-T02 · Per-stage review traces (context → specialists → merge → verify → post)
- V9-E07-T03 · Redaction-at-emit + opt-in export endpoints (no implicit egress)
- V9-E07-T04 · Health/SLO dashboards (proposed baselines TBD) + Action-image leanness test

**V10 — Ecosystem / platform**

- V10-E01-T01 · Plugin manifest + discovery/loading against V9-E06 contract
- V10-E01-T02 · Capability grants + narrow plugin API (analyze/report only)
- V10-E01-T03 · Plugin output trust handling (fence/redact like model output)
- V10-E01-T04 · Malicious-plugin fixtures (lifecycle forgery, ungranted capability, exfiltration)
- V10-E01-T05 · Sample third-party plugin + contributor docs (OSS surface)
- V10-E02-T01 · Provider adapter SDK + documented adapter contract
- V10-E02-T02 · Adapter conformance suite (failover, breaker, retry, usage, labelling)
- V10-E02-T03 · In-tree providers migrated to adapter path (byte-identical snapshot)
- V10-E02-T04 · Curated community registry listing (no auto-install)
- V10-E03-T01 · Tenancy model design + threat model (go/no-go gate precedes code)
- V10-E03-T02 · Per-tenant storage/auth/quota enforcement
- V10-E03-T03 · Cross-tenant adversarial isolation suite
- V10-E03-T04 · Tenant metering reconciled with telemetry spine
- V10-E04-T01 · CLI subcommands (review / explain / query / eval) additive surface
- V10-E04-T02 · Explain-provenance over read contract (any finding ID)
- V10-E04-T03 · Offline parity: local mode reproduces GitHub-mode on fixture
- V10-E04-T04 · IDE integration via versioned API/CLI JSON (no forked logic)
- V10-E05-T01 · Org rollup tables (additive, rebuildable) over analytics projections
- V10-E05-T02 · Portfolio dashboards over versioned API
- V10-E05-T03 · Suppression + no-individual invariants at org rollup level
- V10-E05-T04 · Rollup-equals-projection reconciliation tests
- V10-E06-T01 · Command-center view layer over versioned API only (schema test)
- V10-E06-T02 · Human action buttons mapped to existing authorized endpoints
- V10-E06-T03 · Role-aware views for org deployment (authz matrix enforcement)
- V10-E06-T04 · Legacy SPA route preservation + unversioned-route isolation tests

---

## 4. Count summary

### 4.1 Epics and proposed tickets per stage

| Stage | Epics | Proposed tickets | Ticketed in this document |
|---|---:|---:|---|
| Phase 0 / V3.x (validation & hardening) | 6 | 37 | Full breakdown (§3.2) |
| V4 (deep repository intelligence) | 8 | 38 | Full breakdown (§3.3) |
| V5 (multi-agent engineering review) | 8 | 34 | Titles only (§3.4) |
| V6 (security+testing+architecture intelligence) | 8 | 34 | Titles only (§3.4) |
| V7 (historical/project/team intelligence) | 7 | 32 | Titles only (§3.4) |
| V8 (CI/release/incident intelligence) | 7 | 34 | Titles only (§3.4) |
| V9 (organization platform) | 7 | 34 | Titles only (§3.4) |
| V10 (ecosystem/platform) | 6 | 28 | Titles only (§3.4) |
| **Total** | **57** | **271** | — |

### 4.2 Per-epic ticket counts

| Epic | Tickets | Epic | Tickets |
|---|---:|---|---:|
| V3-E01 | 8 | V6-E01 | 5 |
| V3-E02 | 6 | V6-E02 | 4 |
| V3-E03 | 5 | V6-E03 | 4 |
| V3-E04 | 7 | V6-E04 | 4 |
| V3-E05 | 5 | V6-E05 | 4 |
| V3-E06 | 6 | V6-E06 | 4 |
| V4-E01 | 6 | V6-E07 | 4 |
| V4-E02 | 5 | V6-E08 | 4 |
| V4-E03 | 4 | V7-E01 | 4 |
| V4-E04 | 5 | V7-E02 | 5 |
| V4-E05 | 6 | V7-E03 | 4 |
| V4-E06 | 4 | V7-E04 | 4 |
| V4-E07 | 4 | V7-E05 | 4 |
| V4-E08 | 5 | V7-E06 | 4 |
| V5-E01 | 5 | V7-E07 | 4 |
| V5-E02 | 4 | V8-E01 | 5 |
| V5-E03 | 4 | V8-E02 | 4 |
| V5-E04 | 4 | V8-E03 | 4 |
| V5-E05 | 4 | V8-E04 | 4 |
| V5-E06 | 4 | V8-E05 | 4 |
| V5-E07 | 4 | V8-E06 | 4 |
| V5-E08 | 4 | V8-E07 | 5 |
| | | V9-E01 | 5 |
| | | V9-E02 | 4 |
| | | V9-E03 | 5 |
| | | V9-E04 | 4 |
| | | V9-E05 | 4 |
| | | V9-E06 | 4 |
| | | V9-E07 | 4 |
| | | V10-E01 | 5 |
| | | V10-E02 | 4 |
| | | V10-E03 | 4 |
| | | V10-E04 | 4 |
| | | V10-E05 | 4 |
| | | V10-E06 | 4 |

**Grand totals: 57 epics · 271 proposed tickets** (75 fully specified for
Phase 0 + V4; 196 titled outlines for V5–V10).

---

### Cross-references
Ground truth: `CURRENT_ARCHITECTURE.md` · Vision & planes: `MASTER_VISION.md`
· Dependencies: `DEPENDENCY_GRAPH.md` · Compatibility & rollback:
`MIGRATION_PLAN.md` · Decisions: `ADR_INDEX.md` (ADR-005 finding identity,
ADR-011 storage evolution) · Target design: `TARGET_ARCHITECTURE.md` ·
Ordering: `MASTER_ROADMAP.md`, `V4_V10_ROADMAP.md` · Do-not-build list:
`DO_NOT_BUILD_YET.md`
