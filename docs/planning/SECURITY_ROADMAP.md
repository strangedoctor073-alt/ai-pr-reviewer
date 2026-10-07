# Security Roadmap — Threat Model & Security Evolution

> Status: planning document (v1) — created during remediation to resolve BLOCK-01.
> Repository state: commit `2841b23`.
> Canonical stage structure: Phase 0/"V3.x", V4, V5, V6, V7, V8, V9, V10.

---

## 1. Security design stance

Security is **continuous**, not stage-gated. Every stage that adds a new untrusted input surface must upgrade injection screening, redaction, and authorization **in that stage**. V6 (security engine) does not absorb later stages' security work. This is the principle from `MASTER_VISION.md` §5 capability T and `V4_V10_ROADMAP.md` §0 deviation #8.

---

## 2. Current security controls (V3 — verified)

| Control | Location | Threat addressed |
|---|---|---|
| Nonce fencing | `security.py:wrap_untrusted_diff` | Fence spoofing / data-vs-instruction confusion |
| Injection screening | `security.py:scan_prompt_injection` (8 patterns) | Instruction impersonation in untrusted text |
| Secret redaction | `security.py:redact_secrets` (12 patterns) | Secret leakage through comments/reports/dashboard |
| Untrusted model output | `models.py:Finding.from_untrusted_dict` | Model setting lifecycle fields |
| Path traversal protection | `github_client.py:_safe_repo_path` | Path traversal into token-bearing URLs |
| Base-revision checkout | `example-workflow.yml` | PR rewriting its own policy |
| No `pull_request_target` | `example-workflow.yml` | PR executing with elevated permissions |
| Minimal permissions | `example-workflow.yml` (`contents: read`, `pull-requests: write`) | Token abuse |
| Constant-time token compare | `dashboard/app.py` (`hmac.compare_digest`) | Timing attacks on dashboard token |
| Weak-token refusal | `dashboard/app.py` (`WEAK_TOKENS`) | Guessable dashboard token |
| Rate limiting | `dashboard/app.py` (sliding window, 240/30 per 60s) | Brute force / DoS |
| Body/finding caps | `dashboard/app.py` (2 MB / 500) | Memory exhaustion |
| CSP / nosniff / no-referrer | `dashboard/app.py` middleware | XSS / clickjacking |
| XSS escaping | `dashboard/static/app.js` (`esc()`, `mdLite()`) | Stored XSS via findings/memory |
| Non-removable privacy baseline | `rules.py:SENSITIVE_EXCLUDE_GLOBS` | Repo config removing privacy exclusions |
| Audit logging | `dashboard/app.py` (`audit.jsonl`) | Forensic trail |
| Honest static labelling | `reporter.py` (`_ENGINE_FOOTER`) | Static output misrepresented as AI |
| No retired model IDs | `tests/test_release_hardening.py` | Silent provider failures |
| Warning sanitization | `orchestrator.py:_scrub` | Secrets in warnings |

### 2.1 Known gaps (V3 — documented, not yet fixed)

| Gap | Severity | Stage to fix |
|---|---|---|
| `base_sha` never populated → repo context at PR head | HIGH (D1) | Phase 0 (V3-E01) |
| Injection screening is signature-based; novel phrasings pass | MEDIUM | Continuous |
| `redact_secrets` false positives on 40-char SHAs | LOW | Phase 0 (document) |
| Badge/sandbox unauthenticated | MEDIUM | V9 (badge), V10 (sandbox) |
| Content-Length-only body cap (chunked requests bypass) | MEDIUM | V9 |
| No webhook auth (no webhooks yet) | N/A | V9 (when webhooks land) |
| Dashboard rate limiter is per-process (single-worker) | MEDIUM | V9 (when multi-worker) |
| Policy trust depends on consumer checkout behavior | MEDIUM | V9 (enforce in Action) |

---

## 3. Threat model

### 3.1 Malicious PR

| Threat | Current control | Required evolution |
|---|---|---|
| PR diff contains prompt injection | Nonce fencing + injection screening | V4: index content is also fenced; V5: agent prompts fenced per-agent |
| PR modifies `.ai-pr-reviewer.yml` | Warning on policy file change | V9: enforce base-revision policy in Action |
| PR contains secrets | `redact_secrets` on everything stored/posted | Continuous: extend patterns as needed |
| PR is huge (DoS) | `batch_chars` 80k, `max_comments` 20, 1000-file cap | V4: budget caps as DoS control (V4-E08) |
| PR contains path traversal in file paths | `_safe_repo_path` | Continuous |

### 3.2 Malicious repository content

| Threat | Current control | Required evolution |
|---|---|---|
| Repo files contain injection | Repo context fenced + screened | V4: index content fenced; retrieval provenance tracked |
| Repo files contain secrets | `redact_secrets` on repo context | Continuous |
| Repo is huge (unbounded ingestion) | 8-file / 12k char budget | V4: hard budget caps (V4-E08) |
| Repo contains symlinks/submodules | `get_file` rejects non-file types | Continuous |

### 3.3 Malicious issue/comment

| Threat | Current control | Required evolution |
|---|---|---|
| Issue body contains injection | Not applicable (no issue ingestion yet) | V7: fence issue bodies as untrusted |
| Comment contains injection | Not applicable (no comment ingestion yet) | V7: fence comment bodies as untrusted |

### 3.4 Malicious memory

| Threat | Current control | Required evolution |
|---|---|---|
| Memory note contains injection | Memory fenced + screened | V7: authority model (ADR-003); AI cannot write memory |
| Memory note contains secrets | `redact_secrets` on memory | Continuous |
| Memory poisoning (AI tries to write) | Engine has no `add_repo_memory` path | V7: authority model enforces human-only writes |
| Memory row is a mute (dismissal) | `fingerprint:` prefix; write-protected in dashboard | V7: mute rows are human-authored only |

### 3.5 Malicious model output

| Threat | Current control | Required evolution |
|---|---|---|
| Model sets lifecycle fields | `from_untrusted_dict` strips `LIFECYCLE_FIELDS` | Continuous: provenance fields also pipeline-owned |
| Model claims "resolved" | Deterministic verification; `_unverify` revert | V6: verification tiers; AI cannot claim T2+ |
| Model output contains secrets | `redact_secrets` on everything posted/stored | Continuous |
| Model output is huge | `MAX_FINDINGS_PER_BATCH` 200; `max_tokens` tiers | V5: per-agent budget caps |

### 3.6 Malicious plugin (V10)

| Threat | Current control | Required evolution |
|---|---|---|
| Plugin escapes sandbox | N/A (no plugins yet) | V10: out-of-process sandbox; capability IPC; no tokens by default |
| Plugin exfiltrates data | N/A | V10: network egress control; manifest signing |
| Plugin is supply-chain attack | N/A | V10: plugin signing + API-range; curated registry |

### 3.7 Compromised provider

| Threat | Current control | Required evolution |
|---|---|---|
| Provider returns malicious content | Model output is untrusted; validated | Continuous: per-agent fencing (V5) |
| Provider is down | Circuit breaker + failover + static fallback | V5: per-task breakers |
| Provider leaks secrets | Secrets never in URLs; warnings sanitized | Continuous |

### 3.8 Secret leakage

| Threat | Current control | Required evolution |
|---|---|---|
| Secret in diff | `redact_secrets` | Continuous |
| Secret in repo context | `redact_secrets` | Continuous |
| Secret in memory | `redact_secrets` | Continuous |
| Secret in model output | `redact_secrets` on posted/stored | Continuous |
| Secret in telemetry | N/A (no telemetry yet) | V3-E02: telemetry passes `redact_secrets` |
| Secret in warnings | `_scrub` (patterns + configured credentials) | Continuous |
| Secret in error messages | Type name only (never message) | Continuous |

### 3.9 GitHub token abuse

| Threat | Current control | Required evolution |
|---|---|---|
| Token in URL | `_safe_repo_path`; secrets never in URLs | Continuous |
| Token scope escalation | Minimal permissions; no `checks: write` | Continuous |
| Token in logs | `_scrub` on warnings | Continuous |

### 3.10 Path traversal

| Threat | Current control | Required evolution |
|---|---|---|
| `../` in file paths | `_safe_repo_path` rejects `..` segments | Continuous |
| Absolute paths | `_safe_repo_path` rejects absolute paths | Continuous |
| Backslash normalization | `_safe_repo_path` normalizes `\` → `/` | Continuous |

### 3.11 Prompt injection

| Threat | Current control | Required evolution |
|---|---|---|
| "Ignore previous instructions" | Injection screening (8 patterns) | Continuous: extend patterns |
| Role override | Injection screening | Continuous |
| System prompt fishing | Injection screening | Continuous |
| Suppress findings | Injection screening | Continuous |
| Fake authority | Injection screening | Continuous |
| Fence spoofing | Nonce fencing; spoofed tags neutralized | Continuous |
| Fake chat turn | Injection screening | Continuous |
| Novel phrasings | **Gap**: signature-based screening misses novel phrasings | V6: defense-in-depth (nonce fence is primary; screening is forensic) |

### 3.12 Context poisoning

| Threat | Current control | Required evolution |
|---|---|---|
| Repo content poisons context | Fenced + screened | V4: index content fenced; provenance tracked |
| Memory poisons context | Fenced + screened; human-authored only | V7: authority model |
| Model output poisons next prompt | Model output is untrusted; never fed back as instructions | V5: per-agent fencing |

### 3.13 Tenant isolation failure (V10)

| Threat | Current control | Required evolution |
|---|---|---|
| Cross-tenant data leak | N/A (single-tenant) | V10: row-level scope; scope matrix as CI invariant |
| Cross-tenant policy leak | N/A | V10: org policy scoping |

### 3.14 Webhook spoofing (V9)

| Threat | Current control | Required evolution |
|---|---|---|
| Forged webhook | N/A (no webhooks yet) | V9: HMAC signature validation; timestamp/replay window |
| Replay attack | N/A | V9: nonce/timestamp store |

### 3.15 Supply-chain attack

| Threat | Current control | Required evolution |
|---|---|---|
| Malicious dependency | `requirements.txt` pinned minimums; Dependabot | Continuous: audit deps; V6-E06 dependency intelligence |
| Malicious GitHub Action | Pinned actions (`@v7`) | Continuous |
| Malicious plugin | N/A | V10: signing + curated registry |

---

## 4. Per-subsystem trust boundaries

### 4.1 Repository index (V4-E01)

| Attribute | Value |
|---|---|
| Trust boundary | Index content is derived from untrusted repo files |
| Untrusted input | Repo file contents at base revision |
| Required sanitization | Fence as untrusted; redact secrets; injection screen |
| Required authorization | None (read-only index) |
| Audit requirements | Index build logged; hash-sealed |
| Failure mode | Index build fails → degrade to import-heuristic (current behavior) |

### 4.2 Evidence engine (V4-E04)

| Attribute | Value |
|---|---|
| Trust boundary | Evidence content is derived from untrusted repo files |
| Untrusted input | Repo file contents, tool output |
| Required sanitization | Redact secrets; content-hash for integrity |
| Required authorization | None (read-only) |
| Audit requirements | Evidence provenance recorded |
| Failure mode | Evidence fetch fails → finding posted without evidence (degraded) |

### 4.3 Specialist agents (V5)

| Attribute | Value |
|---|---|
| Trust boundary | Agent output is untrusted model output |
| Untrusted input | Agent model output |
| Required sanitization | Re-validate as untrusted; per-prompt fencing; lifecycle fields stripped |
| Required authorization | Agents never post directly; merged+validated only |
| Audit requirements | Per-agent provenance recorded |
| Failure mode | Agent fails → skipped; merger proceeds with remaining agents |

### 4.4 Security engine (V6-E01)

| Attribute | Value |
|---|---|
| Trust boundary | Security findings are deterministic verdicts over untrusted code |
| Untrusted input | Repo file contents, dependency manifests |
| Required sanitization | Strict manifest/lockfile parsing (no exec); pinned-host advisory fetch |
| Required authorization | None (read-only) |
| Audit requirements | Security findings carry evidence |
| Failure mode | Advisory fetch fails → skip advisory checks; pattern checks still run |

### 4.5 Test/CI ingestion (V6-E03, V8-E01)

| Attribute | Value |
|---|---|
| Trust boundary | CI logs and test output are untrusted content |
| Untrusted input | CI logs, workflow YAML, test output |
| Required sanitization | Redact at ingest; parse-never-execute; no CI control |
| Required authorization | Read-only CI API; token perms unchanged |
| Audit requirements | Ingestion logged; correlation evidence recorded |
| Failure mode | Ingestion fails → skip correlation; review proceeds without CI context |

### 4.6 Memory hierarchy (V7-E02)

| Attribute | Value |
|---|---|
| Trust boundary | Memory is human-authored; AI cannot write |
| Untrusted input | Human-authored notes (still fenced + screened) |
| Required sanitization | Fence + screen; authority model (ADR-003) |
| Required authorization | Human approval for writes; mute rows write-protected |
| Audit requirements | Authority + provenance on every memory entry |
| Failure mode | Memory load fails → continue without memory (current behavior) |

### 4.7 Event platform (V8-E07)

| Attribute | Value |
|---|---|
| Trust boundary | Events are internal; event content is untrusted-derived |
| Untrusted input | CI logs, diffs, incident text |
| Required sanitization | Redact at ingest; fence in event payloads |
| Required authorization | Internal only; not public API |
| Audit requirements | Event log is append-only |
| Failure mode | Event write fails → warning; review proceeds |

### 4.8 Webhooks (V9)

| Attribute | Value |
|---|---|
| Trust boundary | Webhook payloads are untrusted until verified |
| Untrusted input | Webhook HTTP payload |
| Required sanitization | HMAC signature validation; timestamp/replay window; re-sanitize at consume |
| Required authorization | Signature verification |
| Audit requirements | Rejected webhooks logged |
| Failure mode | Invalid signature → reject + log |

### 4.9 Versioned API (V9-E03)

| Attribute | Value |
|---|---|
| Trust boundary | API consumers are authenticated users |
| Untrusted input | API request bodies |
| Required sanitization | Input validation; body caps; rate limiting |
| Required authorization | Scoped tokens; route×role matrix |
| Audit requirements | Audit log for all writes |
| Failure mode | Auth failure → 401; rate limit → 429 |

### 4.10 Plugins (V10-E01)

| Attribute | Value |
|---|---|
| Trust boundary | Plugin code is hostile |
| Untrusted input | Plugin output |
| Required sanitization | Output treated as model-untrusted; re-validate |
| Required authorization | Capability manifest; no tokens by default; sandbox |
| Audit requirements | Plugin id+version in provenance |
| Failure mode | Plugin crash → isolated; sandbox escape → denied + logged |

### 4.11 Hosted multi-tenancy (V10-E03)

| Attribute | Value |
|---|---|
| Trust boundary | Tenants are isolated; tenant data is untrusted to other tenants |
| Untrusted input | Tenant-provided config, repos, plugins |
| Required sanitization | Row-level scope; tenant isolation tests |
| Required authorization | RBAC; SSO; per-tenant tokens |
| Audit requirements | Cross-tenant access attempts logged |
| Failure mode | Isolation failure → deny + alert |

---

## 5. Security evolution roadmap

### 5.1 Phase 0 (V3-E01..E06)

| Work item | Epic | Threat addressed |
|---|---|---|
| Fix D1 (base_sha) | V3-E01 | Repo context at untrusted PR head |
| Fix D6 (config crash) | V3-E01 | Clean failure on malformed input |
| Fix D7 (mute idempotency) | V3-E01 | Duplicate mute rows |
| Telemetry redaction | V3-E02 | Secret leakage in telemetry |
| Document redaction false positives | V3-E06 | SHA redaction false positives |

### 5.2 V4 (V4-E01..E08)

| Work item | Epic | Threat addressed |
|---|---|---|
| Index content fencing | V4-E08 | Context poisoning via index |
| Budget caps as DoS control | V4-E08 | Unbounded ingestion |
| Provenance unforgeable | V4-E04 | Evidence spoofing |
| Identity inputs pipeline-owned | V4-E05 | Model setting identity |

### 5.3 V5 (V5-E01..E08)

| Work item | Epic | Threat addressed |
|---|---|---|
| Per-agent fencing | V5-E01 | Agent prompt injection |
| Cross-agent output re-validation | V5-E01 | Malicious agent output |
| Agents never post directly | V5-E01 | Uncontrolled autonomous actions |
| Budget pre-flight | V5-E07 | Cost explosion |

### 5.4 V6 (V6-E01..E08)

| Work item | Epic | Threat addressed |
|---|---|---|
| Security engine | V6-E01 | Security findings with evidence |
| AI security v2 | V6-E02 | Context provenance tagging; poison defenses |
| Strict manifest parsing | V6-E06 | Dependency risk |
| Policy evaluator re-enforces baseline | V6-E07 | Policy removing privacy baseline |

### 5.5 V7 (V7-E01..E07)

| Work item | Epic | Threat addressed |
|---|---|---|
| Memory authority model | V7-E02 | Memory poisoning |
| Memory security | V7-E07 | Authority enforcement |
| Git read-only execution | V7-E01 | Command injection via git |
| No author-dimension queries | V7-E05 | Individual rankings |

### 5.6 V8 (V8-E01..E07)

| Work item | Epic | Threat addressed |
|---|---|---|
| CI log redaction at ingest | V8-E01 | Secret leakage via CI logs |
| Parse-never-execute | V8-E01 | CI log injection |
| Event log append-only | V8-E07 | Event tampering |

### 5.7 V9 (V9-E01..E07)

| Work item | Epic | Threat addressed |
|---|---|---|
| Webhook HMAC + replay window | V9-E04 | Webhook spoofing; replay |
| Scope matrix as CI invariant | V9-E03 | Cross-tenant/policy leak |
| Scoped tokens | V9-E03 | Token abuse |
| API contract snapshots | V9-E03 | Breaking changes |
| Badge/sandbox auth | V9-E03 | Unauthenticated info leak |

### 5.8 V10 (V10-E01..E06)

| Work item | Epic | Threat addressed |
|---|---|---|
| Plugin sandbox + escape suite | V10-E01 | Plugin escape |
| Plugin signing + API-range | V10-E01 | Supply-chain attack |
| Tenant isolation | V10-E03 | Cross-tenant data leak |
| RBAC + SSO | V10-E03 | Unauthorized access |

---

## 6. Security invariants (test-enforced — do not relax)

The following invariants are enforced by the current test suite and must remain enforced in every future stage:

1. Static output must never read as AI (`reporter.py` `_ENGINE_FOOTER`).
2. Primary config error is fatal; secondary is a warning (`model_router.py`).
3. No hardcoded retired model IDs (`tests/test_release_hardening.py`).
4. Untrusted-diff nonce fencing + injection screening + `redact_secrets` on everything posted/stored.
5. Memory and repo-context fenced identically to diff.
6. `LIFECYCLE_FIELDS` stripped from model output (`models.py:from_untrusted_dict`).
7. Failure warnings must not echo exception messages — type name only (`model_router.py`).
8. Privacy baseline exclusions non-removable (`rules.py`).
9. No `pull_request_target`; base-revision checkout; minimal permissions.
10. Constant-time token compare; weak-token refusal; rate limiting; body/finding caps.
11. No automatic code modification; no autonomous write actions.

---

## 7. Cross-references

- Ground truth: `CURRENT_ARCHITECTURE.md`
- Vision and planes: `MASTER_VISION.md`
- Target design: `TARGET_ARCHITECTURE.md`
- Dependencies: `DEPENDENCY_GRAPH.md`
- Data model: `DATA_MODEL.md`
- AI architecture: `AI_AGENT_ARCHITECTURE.md`
- Testing: `TESTING_EVALUATION_PLAN.md`
- Cost: `COST_TOKEN_ARCHITECTURE.md`
- Migration: `MIGRATION_PLAN.md`
- Decisions: `ADR_INDEX.md` (ADR-003 memory authority, ADR-012 verification trust, ADR-013 webhook security)
- Refusal list: `DO_NOT_BUILD_YET.md`
- Audit: `FINAL_CONSISTENCY_AUDIT.md`
