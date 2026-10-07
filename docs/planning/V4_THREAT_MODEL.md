# V4 THREAT MODEL — Intelligence, Feedback & Lifecycle Surfaces

> Status: V4-C0 deliverable (`V4-E08-T01`), recorded 2026-10-07.
> Scope: every V4 capability (P0/P1) with its abuse cases, controls, owning
> tickets, and the regression test that pins the control. Inherits the V3
> trust model (`security.py`; base-revision policy read; non-removable privacy
> exclusion baseline; `pull_request` — never `pull_request_target`).
> Related: `SECURITY_ROADMAP.md` · `ADR_INDEX.md` (ADR-004/005/017/022) ·
> `EPIC_BACKLOG.md` (V4 scope record) · `TESTING_EVALUATION_PLAN.md` §8.

## 0. Trust model recap (unchanged from V3)

Untrusted: PR diff, PR body, branch names, repository file content, model
output, provider warnings/responses, feedback free-text, foreign GitHub
comment bodies.

Trusted: `.ai-pr-reviewer.yml` from the **base revision**, pipeline-owned
fields (lifecycle + provenance — stripped by `from_untrusted_dict`), and
fingerprints computed by the engine.

Invariants carried into V4: **nothing executes repository code** (hard rule
2); everything posted or stored passes `redact_secrets()` — V4 closes the
finding→comment/report chokepoint gap at `V4-E08-T05`; privacy exclusions can
only grow (non-removable).

## 1. Repository index (V4-E01) — P0

| Abuse case | Control | Owner | Test |
|---|---|---|---|
| Huge/pathological tree → unbounded reads, runner DoS | `max_files` / `max_bytes` / per-file size cap, traversal depth cap; exhaustion = loud warning + partial index, never a crash | `E01-T04`, `E08-T03` | oversized-tree fixture exhausts budget, run completes |
| Symlink or `../` path escapes the worktree | path containment on every indexed path (`_safe_repo_path` pattern); symlinks never followed outside the checkout | `E08-T03` | symlink-escape fixture → path rejected |
| Planted prompt-injection in file content later retrieved | index stores **data only, never instructions**; every prompt-bound chunk wrapped in `<untrusted_repo_file>` fences + injection screening | `E08-T02`, `E02-T03` | injection corpus → zero verbatim instructions in prompt |
| Privacy-baseline file indexed and quoted | non-removable exclusion baseline filters index reads (`rules.py`) | `E01-T04` | excluded path never appears in the index |
| Vendor/minified bombs | vendor/minified skip rules + size caps | `E01-T04` | fixture skips |

## 2. Context selection & impact (V4-E02, E03) — P0/P1

| Abuse case | Control | Owner | Test |
|---|---|---|---|
| Selected repo file carries instructions ("ignore previous…") | all selected content fenced as untrusted; diff section unchanged; closed reason set keeps instruction/data separation explicit | `E08-T02`, `E02-T03` | prompt snapshot asserts fences; injection corpus |
| Budget exhaustion silently drops security-relevant context | `budget_state` is explicit (`ok`/`truncated`/`exhausted`) and warned — never silent | `E01-T04` | exhaustion produces warning + continued run |
| Impact traversal explosion (fan-out DoS) | depth/node/byte limits with explicit truncation flag | `E03-T02` | pathological fan-out fixture terminates under cap |
| Untrusted path name drives a file read outside checkout | paths from the index are validated before any read | `E08-T03` | traversal test |

## 3. Evidence & provenance (V4-E04) — P0

| Abuse case | Control | Owner | Test |
|---|---|---|---|
| Secret quoted into evidence → leaks via report/comment/dashboard | `redact_secrets()` on write **and** at the single output chokepoint | `E04-T02`, `E08-T05` | planted secret absent from report and comment |
| Model forges `provenance`/`evidence` in output JSON | provenance pipeline-owned; `from_untrusted_dict` strips it (existing invariant) | `E04-T02` | forged-provenance strip test |
| Fence-spoofing text inside evidence re-injected in prompts | evidence rendered as data; fenced when prompt-bound | `E04-T05`, `E08-T02` | adversarial evidence fixture |

## 4. Feedback & suppression (V4-E09) — P1

| Abuse case | Control | Owner | Test |
|---|---|---|---|
| PR author creates/modifies suppression rules (silences reviews) | rules originate **only** from authenticated dashboard/CLI actions — structurally no ingest path from diff, model output, or PR content | `E09-T06`, `E08-T06` | rule-injection attempt via PR content has no path |
| Rule flooding / unbounded growth | caps: rules per repo, creation rate, event rate, stored rule size; default expiry | `E08-T06` | flood test hits caps; expiry test |
| Cross-repository leakage (repo A rules suppress repo B) | repository-scoped rows; isolation enforced at query level | `E09-T06` | isolation test |
| Feedback text carries secrets/PII into storage | redaction at event persistence | `E08-T05`, `E09-T02` | planted secret redacted at rest |
| Silent behavior change (black-box "learning") | `feedback.enabled` default **false**; suppressed findings counted (`suppressed_count`), never erased; disable-all restores exact V3 behavior | `E09-T05` | behavior-equivalence test |

## 5. GitHub lifecycle (V4-E10) — P1

| Abuse case | Control | Owner | Test |
|---|---|---|---|
| Marker forged in a foreign comment hijacks ownership | markers are server-generated from engine-side identity only; pre-existing foreign comments are never adopted | `E10-T01`, `E10-T04` | foreign-marker fixture rejected |
| Reviewer edits/deletes another actor's comment | only comment IDs recorded by this engine are PATCHed/deleted; ownership checks retained | `E10-T04` | lifecycle safety suite |
| Sticky summary becomes an injection sink | summary is engine-rendered from redacted report data; any PR/foreign text is fenced, never trusted | `E10-T02`, `E08-T05` | summary-render redaction test |
| Comment/review spam (GitHub platform dialog limit ≈ 250) | ≤ 1 sticky summary, existing caps unchanged, additive outputs are counts/ids only (no free text) | `E10-T02`, `E10-T04` | duplicate-comment regression; platform cap respected |

## 6. Telemetry & dashboard (V4-E11, E08) — P1

| Abuse case | Control | Owner | Test |
|---|---|---|---|
| Spoofed/unauthenticated telemetry ingestion | existing `X-Dashboard-Token` auth; payload structured + redacted; LAN-documented scope (network auth explicitly V5, never claimed) | `E11-T06` | auth + redaction tests on the route |
| Provider warning echoes untrusted content into logs/output (debt 11) | truncation + `redact_secrets()` + safe formatting of warning text | `E08-T04` | warning-injection fixture |
| Cost/latency data silently triggers routing (behavior change) | display-only guarantee: no cost- or latency-based routing in V4 | `E11-T07` | review gate — no routing code path |

## 7. Acceptance (E08-T01 done when…)

- Every P0/P1 capability above has ≥ 1 abuse case, control, owner, and test.
- Every control maps to a ticket in the approved V4 manifest
  (`EPIC_BACKLOG.md`, V4 scope record).
- `V4-E08-T07` turns these rows into permanent regression tests: prompt
  injection, symlink escape, oversized files, secret leakage, warning echo,
  feedback poisoning, cross-repository isolation, marker forgery.
- Known gaps stated explicitly (not silent): network-grade dashboard auth
  (V5 decision; documented LAN scope until then); Checks API (rejected — no
  permission expansion in V4).
