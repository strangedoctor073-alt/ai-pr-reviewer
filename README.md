# 🤖 AI PR Reviewer

[![Validate](https://github.com/strangedoctor073-alt/ai-pr-reviewer/actions/workflows/ci.yml/badge.svg)](https://github.com/strangedoctor073-alt/ai-pr-reviewer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**An AI-powered pull-request reviewer with a deterministic static-analysis
fallback.** The GitHub Action sends every PR diff to Claude, posts real findings
as inline review comments, and pushes a structured report to a small web
dashboard.

> **How intelligent is the review, honestly?**
> The review intelligence is **Claude** — prompted as a strict senior engineer,
> producing validated, line-anchored findings. There is **no AI in the
> fallback**: when no API key is configured, a ~25-rule regex engine
> (`static-rules-v1`) runs instead so you can demo and test the *plumbing*
> for free. It is deterministic static analysis, not a lightweight AI — the
> labels in the UI, the CLI output and the reports all say so explicitly
> (`mode: "static"`, `model: "static-rules-v1"`, chip: *"static rules — not AI"*).

```
┌────────────┐   PR opened/updated   ┌─────────────────────────────────────┐
│  GitHub PR │ ────────────────────► │  AI PR Reviewer (GitHub Action)     │
└────────────┘                       │                                     │
                                     │  1. fetch PR diff  (REST v3.diff)   │
                                     │  2. parse → files/hunks/line map    │
                                     │  3. injection screen + nonce-fence  │
                                     │  4. review with Claude (strict JSON)│
                                     │  5. validate, anchor, redact        │
                                     │  6. post inline review + summary    │
                                     │  7. push report ──► Dashboard       │
                                     └───────────────┬─────────────────────┘
                                                     ▼
                                     ┌─────────────────────────────────────┐
                                     │  Dashboard (FastAPI + vanilla JS)   │
                                     │  SQLite / PostgreSQL storage        │
                                     │  token auth · rate limits · audit   │
                                     └─────────────────────────────────────┘
```

## ✨ Highlights

| Capability | What It Does | Why It Matters |
|---|---|---|
| 🧠 **Multi-Provider AI** | Claude, OpenAI, and Google Gemini in one action — pass one provider's API key (and, for OpenAI/Gemini, a `model`) | Use whichever provider your team already pays for |
| 🤖 **Custom LLM Endpoints** | Pass `openai_base_url` (+ `model`) to use Ollama, Groq, DeepSeek or any OpenAI-compatible server; the key is optional for local endpoints | Local/private reviews or low-latency inference via drop-in replacement |
| 💯 **PR Health Score** | 0–100 score + letter grade (A+/A/B/C/D) computed from open findings | At-a-glance PR risk gauge in every comment, dashboard tile, and badge |
| 🔎 **Repository-aware Review** | Reads a bounded, deterministic set of related files (imports the change depends on, project configuration) from the PR **base** revision | The reviewer sees the code the change points at, not just the hunks — for a fixed character budget |
| 🛡️ **Defensive Prompt Architecture** | Nonce-fenced diff boundaries with local instruction-injection screening | Mitigates (does not eliminate) attempts to steer the review model from PR contents |
| 🔒 **Secret Redaction & Privacy Baseline** | Pattern-based scrubbing of tokens, credentials and PEM keys, plus exact removal of the credentials the run was configured with; secret-bearing paths never reach a provider | Best-effort defence against credential leaks into comments and the dashboard |
| ⚡ **Deterministic Static Fallback** | ~25 regex/AST rules that run when no API key is set or a provider call fails | Full pipeline testing and CI dry-runs with zero API cost |
| ✅ **Fix Verification** | Earlier findings are re-checked as `resolved` / `still_present` / `unable_to_verify` — pure line arithmetic, never executing code or applying patches | "Fixed" means the flagged code was actually reviewed and the issue is gone |
| 🔄 **Stable PR Comments** | Findings reuse their GitHub comment across pushes, state changes edit that same comment, and an unchanged review posts no duplicate | The PR thread stays readable instead of accumulating noise |
| 🔁 **Provider Failover** | `provider_order` lists backends to try in order, with bounded retries and an in-process circuit breaker | A provider outage degrades to the next provider (then to static, clearly labelled) instead of failing the review |
| 🎯 **Safe Line Anchoring** | Unanchored findings stay in summary; never misattributed to unrelated code | Developers only get inline comments on code they actually changed |
| 📊 **Live Dashboard + ⚡ Sandbox** | Self-hosted web UI with live findings/metrics, real feedback API, and a one-click diff sandbox for instant demos | Full visibility, feedback loop, and a shareable demo with no setup |
| 🏷️ **Dynamic SVG Badge** | `GET /api/badge/{owner}/{repo}` — embed a live health score badge in any README (public, unauthenticated endpoint) | Every repository can show its review health at a glance |

---

### Embed a health badge in your README

```markdown
![AI Review Health](https://your-dashboard.example.com/api/badge/your-org/your-repo)
```

Displays: **AI PR Reviewer** | **98% health (A+)** — colour shifts green → amber → red as the score drops.

---

## What's in the box

- **Claude-backed review** with a machine-checkable contract: `file`, `line`
  (in the *new* file), `severity`, `category`, `explanation`, optional
  `suggestion` snippet, `confidence`.
- **Safe inline anchoring** — a unified-diff parser maps findings strictly to lines
  changed in the PR; findings that reference lines outside the diff stay in the
  summary with their original file and line, never snapped to innocent code.
- **Prompt-injection defenses** — diffs are fenced between nonce-tagged
  `<untrusted_diff>` markers (spoofed markers neutralized), screened locally
  for instruction-impersonation phrases, and the system prompt tells the model
  to treat fenced content as data and report manipulation attempts in
  `warnings`.
- **Secret redaction** — findings/summaries are scrubbed (AWS/GitHub/Slack/
  OpenAI-style tokens, `Bearer` headers, `password=…`, private-key blocks,
  high-entropy hex) before anything is posted to GitHub or stored.
- **Resilient posting** — if GitHub rejects a grouped inline review, the
  summary still lands and each inline finding is retried independently; only
  GitHub-rejected findings are omitted. If that recovery fails entirely, the
  review lands as a regular PR comment.
- **Deterministic static-analysis fallback** (`--mock`/`--static`) — same
  output contract, zero API cost, for CI plumbing tests and demos.
- **Repository context** — a bounded, deterministically chosen set of other
  repository files (imports the change depends on, project configuration) read
  from the PR base revision, redacted, screened and fenced as untrusted data.
- **Fix verification** — `resolved` / `still_present` / `unable_to_verify` for
  earlier findings, computed from the diff this run already has: no code is
  executed and no fix is applied automatically.
- **Comment synchronization** — a finding keeps the id of its GitHub comment
  across pushes; state changes edit that comment and a run with nothing new
  posts no duplicate review.
- **Project memory** — human-authored, path-scoped notes managed from the
  dashboard (categories, enable/disable, mute rows kept separate); the engine
  itself never writes memory.
- **Dashboard** — browse reviews, filter by severity/repo, inspect findings
  with GitHub deep links, and edit shared review rules the Action pulls before
  each review.

---

## 1 · Use as a GitHub Action

### Quick start

1. **Add your Anthropic API key** to the repository you want reviewed, as an
   Actions secret named `ANTHROPIC_API_KEY` (*Settings → Secrets and variables →
   Actions*). Claude usage is billed to that key.
2. **Add the workflow.** Copy [`example-workflow.yml`](example-workflow.yml) into
   that repository as `.github/workflows/ai-pr-review.yml`.
3. **Open a pull request.** The Action posts one review — inline comments plus a
   summary — and uploads `review-report.json` as an artifact.

No API key? Leave the secret unset (or set `mock: true`) and the Action runs
the free deterministic static rules instead: regex plus a few AST checks, **not
AI**. It is useful for trying the plumbing, not a substitute for the Claude
review.

The example workflow uses `strangedoctor073-alt/ai-pr-reviewer@v2`. If you fork
this repository, point `uses:` at your fork and tag a release.

The workflow checks out the PR's **base revision** before running the Action,
so `.ai-pr-reviewer.yml` is repository-owner configuration rather than
untrusted PR content. Fork PRs use the static engine and produce only an
artifact; they receive no repository secrets and make no GitHub or dashboard
writes. Do not replace `pull_request` with `pull_request_target`.

Setting `mock: true` forces the deterministic static rules (not AI) even when
an API key is present.

**Other providers.** For OpenAI, Gemini or a custom OpenAI-compatible endpoint,
set the matching key input **and** `model`. There is deliberately no built-in
default model for them: providers retire model IDs regularly, and a stale
default would fail every review. Without `model` the run exits with code `1`
and a clear message. Claude defaults to `claude-sonnet-4-6`.

### Inputs (abridged)

| Input | Default | Description |
|---|---|---|
| `github_token` | — (required) | Token with `pull-requests:write` |
| `pr_number` | Event PR | Required for manual workflow runs; otherwise taken from the event |
| `anthropic_api_key` | — | Without it (or with `mock: true`) the static fallback runs |
| `model` | Claude: `claude-sonnet-4-6` | Model id. **Required** for OpenAI, Gemini and custom endpoints |
| `openai_api_key` / `gemini_api_key` | — | Use OpenAI / Gemini instead of Claude (needs `model`) |
| `openai_base_url` | — | OpenAI-compatible endpoint (Ollama, Groq, …); needs `model`, key optional |
| `severity_threshold` | `medium` | Min severity for inline comments; an explicit input overrides repository policy |
| `max_comments` | `20` | Inline-comment cap; rest go to the summary |
| `batch_chars` | `80000` | Maximum diff characters per Claude request batch |
| `review_mode` | `automatic` | Output budget: `economy`, `balanced`, `maximum`, or project policy |
| `exclude` | — | Newline-separated globs (`**/*.lock`, `**/dist/**`…) |
| `focus` | — | Newline-separated prompt hints (`SQL injection`, …) |
| `fail_on` | `never` | Fail the check at/above: `info…critical` |
| `mock` | `false` | Force the static fallback (NOT AI) |
| `no_comment` | `false` | Write the report without creating GitHub comments |
| `dashboard_url` / `dashboard_token` | — | Push reports + pull shared rules |
| `output` | `review-report.json` | Workspace-relative report path |
| `provider_order` | — | Comma-separated AI failover order (`claude,openai`); the static engine stays the last fallback |
| `repo_context_chars` | `12000` | Character budget for the extra repository context described below; `0` disables it |

**Outputs:** `findings_count`, `critical_count`, `report_path`, `health_score`,
`health_grade`. A markdown digest is also written to the job's **Step Summary**;
the example workflow uploads `review-report.json` as an artifact.

### Provider failover

`provider_order` names the AI backends to try in order (`claude,openai`).
Without it the usual provider selection applies, and in `mock` mode no backend
is listed at all.

- **What counts as a failure** — the backend raised, or every batch of its run
  fell back to the static rules. Either way the next backend in the order is
  tried, still bounded by the retries each provider already performs
  internally (exponential backoff + jitter); failover adds no new retry loop.
- **Configuration** — only the *first* backend is validated strictly, because
  that one has to be usable: a bad `model` there exits with code `1` and a
  clear message. A backend further down the order with a bad configuration is
  skipped with a warning instead of failing the run.
- **Circuit breaker** — a backend that keeps failing is skipped for a short
  cool-down rather than paying for another timeout; once the cool-down elapses
  exactly one recovery attempt is allowed (success closes it, failure re-opens
  it with a fresh cool-down). State is per-backend and in-process — no new
  database and no external service — so one backend being down never blocks
  another.
- **Deterministic static fallback** — when no AI backend completes the review,
  the rule engine covers it. The report, the Step Summary and the console all
  say so explicitly, the run is recorded as `engine: static` with a
  *"— not an AI review"* label, and **a static result is never presented as an
  AI review**. When this happened because every configured AI backend failed
  (rather than a deliberate `--mock` / `--static` run), `last_reviewed_sha` is
  also **not** advanced — the analysis that should have covered those commits
  did not happen, so the next run re-reviews them and gives the providers
  another try.

### Repository context

Beyond the diff, the reviewer reads a small, **deterministically chosen** set
of *other* repository files, in this order:

1. imports/references the change depends on, discovered from the changed
   files' own diff lines;
2. project configuration (`pyproject.toml`, `package.json`, …);
3. the changed files themselves, as budget filler (code beyond the hunks).

Selection is pure string parsing of content we already have: there is no
repository listing, no code search and no recursive walk, so the number of API
calls is bounded (at most **16** content fetches, misses included) before the
budget even applies. Files are read from the PR **base** revision, so a PR
cannot choose what is fed back to the reviewer.

**Size controls** — at most **8** files, at most **4 000** characters per file
(truncated with a marker), and at most `repo_context_chars` characters in
total (default `12000`; `0` disables repository context). Reaching the budget
skips the remaining candidates and adds a warning — nothing else changes.

**Security boundaries** — candidate paths are validated (`..`, absolute and
drive-letter paths are rejected) before they are spliced into a URL; content is
**secret-redacted** when collected, then **screened for prompt injection and
nonce-fenced as untrusted data** exactly like the diff, in its own block whose
surrounding prose tells the model it is reference material, never instructions.
A missing file, a rate limit or an unreachable GitHub API means "no repository
context, plus a warning" — never a failed review.

### Fix verification

When review state is available, each earlier finding is compared with this run
and records exactly one of three outcomes:

| Status | Meaning |
|---|---|
| `resolved` | The flagged code was part of this review and the issue was not reported again (or the file left the change entirely). |
| `still_present` | The reviewer reports it again. |
| `unable_to_verify` | No evidence either way: only part of the range was examined, the file was not part of this review, or the finding was never re-examined. |

Verification is **deterministic** — line arithmetic over the diff this run
already has. It never downloads or executes code, never applies a patch, never
asks a model, and never lets a finding close itself: anything that cannot be
confirmed is reverted to `active`, so an unverified finding keeps counting
against the health score. The outcome is stored with the finding
(`verification_status`, `verification_reason`, `verified_at`) and reported in
the summary.

### GitHub finding synchronization

Review state and GitHub stay in step through a stable finding ↔ comment
mapping:

- **Stable mapping** — a finding records the id of the comment posted for it
  (from the posting response, or matched against the comments this run just
  created on path + line + commit + our exact first line of text) and keeps it
  across reviews. A human's comment, an older review's comment or a comment on
  another commit is never claimed as ours.
- **No duplicates** — a finding that already carries a comment id is *updated*,
  never posted a second time, and a run with nothing new to say posts no second
  summary at all (see *GitHub developer experience* below).
- **Lifecycle synchronization** — when a finding becomes `resolved`, `muted`,
  `dismissed` or `reopened`, its existing comment is edited to start with a
  short marker, so a reader of the PR sees the current state without another
  comment being opened.
- **Graceful GitHub failures** — a deleted comment (404), a rate limit or a
  missing permission degrades to a warning on the report; the internal result,
  the findings and the Step Summary are unaffected. No new GitHub permission is
  involved: only the existing `pull-requests: write`.

### Project memory

The dashboard can store short, **human-authored** notes per repository:

- **Scoped or global** — each row carries a path pattern (`src/**`, `*.py`, or
  `*` for global) and applies only when it matches a file this review touched.
- **Categories** — `project-rule`, `preferred-pattern`, `known-exception`,
  `review-preference` (anything else reads as the default `project-rule`).
- **Enable/disable** — a note can be switched off without deleting it, so it
  stays on the dashboard but stops feeding the reviewer.
- **CRUD** — `POST`, `GET`, `PUT` and `DELETE
  /api/repos/{owner}/{repo}/memory` (edits and deletes select the row with
  `?id=`); all writes require the dashboard token.
- **Mute rows stay separate** — `fingerprint:<fp>` rows written by the feedback
  buttons are dismissal decisions, not advice: they are filtered out of every
  prompt, read back only as dismissals, and the memory API refuses to edit or
  delete them (403).
- **Bounded and untrusted** — at most 50 rows, 1 000 characters per note,
  secret-redacted and fenced like any other non-diff text before it can reach
  a prompt. **The reviewer never writes memory**: the engine has no
  memory-write path at all, so neither a model response, a PR nor a diff can
  create or change permanent memory — only the authenticated dashboard API can.

### GitHub developer experience

- **A summary that says what actually ran** — the comment and Step Summary
  include a `Review Engine` row (`engine · title`), a **risk** row when the
  orchestrator computed one, and a **verification** row such as
  `2 ✅ fixed & verified · 1 🔍 re-reported · 3 ❓ unable to verify`. Static
  output always carries *"— not an AI review"*.
- **Resolved findings are listed apart** — in their own collapsible block,
  without a severity label and with their verification mark, so a closed issue
  is never counted among the issues still to act on.
- **Duplicate reviews are suppressed** — a run with no new inline content and
  no lifecycle transition posts no second, identical review comment (the
  report and Step Summary are still written). The first review of a PR, any
  new finding, and any state change (opened, resolved, muted, dismissed,
  reopened) are always worth posting.
- **Inline comment content is stable** — the same renderer produces the
  comment when it is first posted and every time it is later updated, so a
  state marker never replaces the finding's text.

### Repository policy

Copy [`.ai-pr-reviewer.yml.example`](.ai-pr-reviewer.yml.example) to the
reviewed repository's base branch. Its `exclude`, `focus`, and non-default
`severity_threshold` are applied to every review. Its free-form `rules` are
sent only to Claude in a separate trusted prompt section; the static fallback
cannot enforce arbitrary natural-language conventions. `review.mode` changes
Claude's response budget when the Action input remains `automatic`.

A built-in privacy baseline (`.env*`, `*.pem`/`*.key`/`*.p12`/`*.pfx`,
`*.tfstate`, `.ssh/**`, `.aws/**`, `secrets/**`, `credentials/**`,
`service-account*.json`, …) is always excluded from the diff sent to any
analyzer, on top of whatever `exclude` your policy adds — a repository's
`.ai-pr-reviewer.yml` can only add exclusions, never remove this baseline.

### How a review is produced

1. `GET /repos/{owner}/{repo}/pulls/{n}` (+ `Accept: application/vnd.github.v3.diff`).
2. The diff is parsed into files → hunks → **new-file line numbers** (renames,
   `/dev/null` new files, binary entries handled).
3. Excluded globs are dropped; the rest is packed into batches (80k chars).
4. **Repository context** (when `repo_context_chars > 0`) — the bounded set of
   related files is read from the PR **base** revision, secret-redacted,
   screened and fenced as its own untrusted block.
5. Each batch is **screened for prompt injection**, **fenced with a fresh
   nonce**, and sent to the configured provider (or the next one, on failover)
   with a system prompt that (a) pins the output schema, (b) declares the
   fenced blocks untrusted data, (c) forbids quoting secrets. Model output is
   JSON-validated, findings are snapped to real diff lines, and every string is
   **secret-redacted**.
6. Findings are fingerprinted and deduplicated, earlier findings are carried
   through the lifecycle (**new / active / reopened / resolved**) and then
   **verified** (`resolved` / `still_present` / `unable_to_verify`), and
   dashboard dismissals are applied last.
7. One `COMMENT` review is posted: inline comments + markdown summary, with a
   regular-comment fallback. Comment ids are recorded and, on later runs,
   state changes edit the existing comment instead of opening a new one.

### Known limitations

- **Repeat pushes can repeat comments.** Review state is only kept when a
  dashboard (or `--storage-file` when running locally) is configured. Without
  one, every run is a fresh, full review, so a new push can post findings that
  an earlier push already raised. With state configured, a finding reuses its
  existing comment and an unchanged review posts nothing.
- **Repository policy is only trusted if you check out the PR base.** The Action reads
  `.ai-pr-reviewer.yml` from the workspace. With a default `actions/checkout` on
  `pull_request` that is the merge commit, so a PR could rewrite its own exclusions.
  Use the base-checkout step from the example workflow. The Action also warns when a PR
  modifies the policy file.
- **Static fallback is regex-level.** It will miss most real bugs and produces false
  positives; it is a plumbing test and safety net, not a code reviewer.
- **Large PRs are batched** (`batch_chars`); the model never sees the whole repository,
  only the diff plus a few related files.
- **Fork and Dependabot PRs get a read-only token**, so the Action cannot
  comment on them. The review is still produced, and a failed post is reported
  as a warning in the step summary instead of failing the run. The example
  workflow already sends fork PRs through the static engine with `no_comment`.

---

## 2 · The dashboard

The dashboard is **optional** — the Action works without it.

```bash
pip install -r requirements.txt
uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
```

On first start the dashboard **generates an API token and prints it in the
server log** (it's persisted in `dashboard/data/settings.json` — treat it as a
secret; rotate by deleting the file and restarting). Reads require this token
by default — the browser prompts for it and keeps it in `sessionStorage` for
the active tab only. `DASHBOARD_REQUIRE_TOKEN_FOR_READS=0` disables that
prompt and is for a local, disposable demo only; don't set it on anything
reachable outside your machine. Use the token wherever `X-Dashboard-Token` is
required:

```bash
export DASHBOARD_TOKEN=...   # from the server log
python demo/seed_demo.py     # seed three demo reviews
```

**Storage:** SQLite by default (`dashboard/data/reviews.db`, WAL mode).
Point `DATABASE_URL` at PostgreSQL for anything multi-user, e.g.
`DATABASE_URL=postgresql+psycopg://user:pass@host/apr`. Legacy JSON-file
reports are migrated into the DB once on first start. The pure-JSON backend
survives only as a zero-dependency fallback if SQLAlchemy is missing — it is
not recommended.

**Features:** severity stat cards, search + severity/repo filters, report
detail with suggested fixes and GitHub deep links, warnings panel (including
prompt-injection screens), and a **Rules & Settings** page (threshold, comment
cap, exclude globs, focus areas) served to the Action via `GET /api/config`.
A **Project memory** panel lists a repository's notes with category,
path pattern and an enable/disable switch, and lets you add, edit and delete
them (dismissal rows are shown read-only).

The **Findings** and **Metrics** tabs, the feedback buttons, the diff **Sandbox**
and the settings form are all backed by the API below (`/api/findings`,
`/api/metrics`, `/api/findings/{fp}/feedback`, `/api/sandbox/simulate`,
`/api/settings`). On a fresh install with zero reviews they are simply empty.

To connect the Action, deploy the dashboard somewhere GitHub-hosted runners can
reach over HTTPS (`localhost` will not work) and set the `PR_DASHBOARD_URL` and
`PR_DASHBOARD_TOKEN` secrets used by the example workflow.

### API

| Method | Path | Auth | Notes |
|---|---|---|---|
| `GET` | `/api/health` | — | Backend, limits, uptime |
| `GET` | `/api/reports?limit=&offset=` | reads* | Paginated (max 200/page) |
| `GET` | `/api/reports/{id}` | reads* | Full report |
| `POST` | `/api/reports` | token | Action pushes a report (≤2 MB, ≤500 findings) |
| `DELETE` | `/api/reports/{id}` | token | |
| `GET` | `/api/stats` | reads* | Aggregates |
| `GET`/`PUT` | `/api/settings` | reads* / token | Validated rules |
| `GET` | `/api/config` | token | Action consumes before review |
| `GET`/`POST`/`PUT`/`DELETE` | `/api/reviews/{owner}/{repo}/{pr}/state` and `/findings`; `/api/repos/{owner}/{repo}/memory` (`PUT`/`DELETE` select a row with `?id=`) | reads* / token | Review state the Action stores between pushes; project memory (mute rows refused with 403) |
| `GET` | `/api/findings`, `/api/metrics` | reads* | Findings browser and aggregate metrics |
| `POST` | `/api/findings/{fingerprint}/feedback` | token | `up` / `down` / `mute` |
| `GET` | `/api/badge/{owner}/{repo}` | **none (public)** | SVG health badge; reveals a repo's average score to anyone who knows its name |
| `POST` | `/api/sandbox/simulate` | **none (rate-limited)** | Runs the static rules on a pasted diff (≤ 50 000 chars) |

\* Reads require the token by default (`DASHBOARD_REQUIRE_TOKEN_FOR_READS=1`).
The UI prompts for it, keeps it in `sessionStorage` and sends it on every call.
Set the variable to `0` only for a throwaway local demo.

---

## 3 · Security model

This is a **hardened prototype**. The following are implemented; the "before
production" list below is what we'd still want.

**Implemented**

| Threat | Mitigation |
|---|---|
| Guessable dashboard token on an exposed host | Token auto-generated (`secrets.token_urlsafe`), weak/known defaults (`demo-token`, `changeme`, …) refused at startup unless `DASHBOARD_ALLOW_DEMO_TOKEN=1`; token compare is constant-time (`hmac.compare_digest`) |
| API abuse / brute force | Per-IP sliding-window rate limits (reads 240/min, writes 30/min; tunable via `DASHBOARD_RATE_LIMIT_*`), 429 + `Retry-After` |
| Oversized/abusive payloads | Request bodies > 2 MB → 413; reports capped at 500 stored findings (worst kept, `truncated_findings` flagged) |
| Secrets leaking out via findings or errors | `redact_secrets()` scrubs AWS/GitHub/Slack/Google-style keys, `Bearer` headers, `key=secret` pairs, private-key blocks and long hex from every posted/stored string; provider warnings are additionally scrubbed of the exact credentials the run was configured with, and API keys are never put in request URLs. This is best-effort pattern matching, not a guarantee |
| Prompt injection from PR content | Nonce-fenced `<untrusted_diff>` blocks with spoofed-tag neutralization, local injection screening (hits → report warnings), system-prompt rules to treat fenced text as data and never comply, model-reported `warnings` surfaced in the dashboard |
| Repository files feeding the prompt | Repository content is **untrusted reference material**: paths are validated (`..`, absolute, drive-letter) before they enter a URL, content is secret-redacted on collection, then screened and nonce-fenced in its own block whose prose says it is data, never instructions. No repository listing, code search or recursive walk is performed, and files are read from the PR **base** revision |
| Model output steering pipeline state | Findings produced by a model are parsed with `Finding.from_untrusted_dict`, which drops every pipeline-owned field (`state`, `fingerprint`, `github_comment_id`, `verification_*`) — a response shaped by a malicious diff cannot close, mute or re-open a finding, nor claim another comment |
| Untrusted fixes being executed | Suggestions are rendered as text only; nothing downloads, executes or auto-applies model-generated code or patches. Fix verification is line arithmetic over the diff already in memory |
| Expanding GitHub permissions | Comment synchronization reuses the existing `pull-requests: write` scope (`GET`/`PATCH` on PR review comments). V3 adds no `checks: write`, no workflow permission change, and the example workflow stays on `pull_request` |
| XSS via malicious PR titles/finding text | All model data rendered through escaping (`esc()` before markdown-lite); links restricted to `https?:` with `rel="noopener"`; CSP `default-src 'self'`, `nosniff`, `Referrer-Policy: no-referrer` |
| Secrets living in reviewed files | A non-removable privacy baseline (`.env*`, `*.pem`/`*.key`, cloud/SSH credential dirs, service-account JSON, …) excludes secret-bearing paths from the diff before it reaches any analyzer, in both `ai_pr_reviewer/rules.py` and the dashboard's saved settings |
| Over-privileged tokens | Workflow declares `contents: read` + `pull-requests: write` only; the bot cannot push code or touch Actions/secrets. Use a fine-grained PAT scoped to PR read/write if `secrets.GITHUB_TOKEN` isn't suitable |
| Posture mistakes | **Never** switch the trigger to `pull_request_target` — it runs with base-repo secrets against untrusted forks |
| No forensic trail | Every write and every rejected auth attempt appended to `dashboard/data/audit.jsonl` |
| Dashboard tampering | Settings writes validated server-side (threshold enum, caps, list limits) |
| Token at rest | `dashboard/data/settings.json` is written with mode `0600` where the OS supports it |

**Before production (known gaps, on purpose)**

- Put the dashboard behind TLS + real SSO/OIDC or an authenticating proxy
  (GitHub OAuth apps work well here); the token is a service credential, not a
  user-login system.
- Rate limits key on the socket IP: behind a reverse proxy every client shares the
  proxy's address unless you configure proxy headers correctly.
- `GET /api/badge/...` and `POST /api/sandbox/simulate` are unauthenticated by design;
  put them behind your proxy's auth or disable them if that is not acceptable.
- Serve with multiple uvicorn/gunicorn workers only against PostgreSQL
  (in-memory rate-limit buckets and the audit file are per-process).
- Add schema migrations (Alembic) once the model evolves beyond v1.
- Add `X-Frame-Options: DENY` / `frame-ancestors` when you deploy (it's
  omitted so the in-IDE preview can embed the app cross-origin).
- Consider async review queues (webhook receiver + worker) instead of running
  Claude inline in the Action if you have very large PRs.

---

## 4 · Local demo (no GitHub, no API key)

```bash
python demo/make_fixtures.py     # build realistic buggy diffs via real git repos
python -m ai_pr_reviewer \
  --diff-file demo/samples/payments_refunds.diff \
  --repo acme/payments --pr 42 --mock --no-comment --output demo/out/report.json
python demo/seed_demo.py         # push the three demo reviews to the dashboard
```

Exit codes: `0` clean, `1` config error, `2` `fail_on` threshold reached.

## 5 · Tests

```bash
python -m pytest tests/ -q
```

The suite covers diff parsing, Action input layering, provider selection and
failover (circuit breaker included), repository context and its path/budget
boundaries, fix verification, GitHub comment synchronization, project memory,
GitHub review recovery, dashboard storage/authentication, security
boundaries, and regression tests for the v2 pre-release audit
(`tests/test_release_hardening.py`). All provider and GitHub traffic is mocked;
no network or API key is needed.

The run is hermetic: pytest config lives in `pyproject.toml`, and the demo
PR-diff fixtures are generated into a pytest temp directory (the committed
`demo/samples/*.diff` files are reference data and are never rewritten), so
two consecutive runs leave `git status` clean. CI runs the suite on Python
3.11, 3.12 and 3.13.

## 6 · Layout

```
ai_pr_reviewer/          # the engine (run by the composite Action; also buildable as a Docker image)
  diff_parser.py         #   unified diff → hunks with new-file line map
  security.py            #   injection screening, diff fencing, secret redaction
  rules.py                #   .ai-pr-reviewer.yml parsing → ReviewPolicy
  context.py              #   diff + rules + previous findings + memory + repo context → ReviewContext
  repo_context.py         #   bounded set of other repo files (imports, project config) for C3
  memory.py               #   project-memory rows: categories, mute rows, path selection (C7)
  model_router.py         #   picks Claude / OpenAI / Gemini per config, provider failover + circuit breaker
  circuit.py              #   in-process circuit breaker that paces provider failover
  retry.py                #   backoff + jitter for the Anthropic call
  ai/
    provider.py           #     AIProvider protocol (shared by all backends)
    claude.py              #     ClaudeProvider — prompting, batching, fallback-on-failure
    openai.py, gemini.py   #     OpenAI / OpenAI-compatible and Gemini providers
  static/                 #   deterministic rule engine (NOT AI)
    engine.py              #     StaticEngine: runs the registry, implements AIProvider too
    registry.py             #     RuleRegistry — rule_id/language/category/severity/confidence
    python_rules.py, javascript_rules.py, shell_rules.py, security_rules.py, test_rules.py
  heuristics.py            #   back-compat facade over static/engine.py (old import path)
  analyzer.py              #   legacy ClaudeAnalyzer/StaticAnalyzer facade over ai/ + static/
  findings.py              #   fingerprinting, deduplication, lifecycle (new/active/resolved…)
  verification.py          #   resolved / still_present / unable_to_verify for earlier findings (C4)
  review_state.py          #   stable review identity (repo + PR + head SHA)
  orchestrator.py          #   ReviewOrchestrator — wires all of the above into one review
  models.py                #   shared dataclasses: PRContext, Finding, ReviewResult, ReviewKey…
  storage.py               #   ReviewStorage protocol + dashboard HTTP client + local SQLite backend
  github_client.py         #   REST: PR, diff, reviews, comments (+ comment updates)
  github_sync.py           #   keeps GitHub comments in step with finding states (C5)
  reporter.py               #   report JSON, step summary, dashboard push
  cli.py / config.py        #   orchestration & config layering (calls orchestrator.py)
dashboard/
  app.py                 #   FastAPI app: auth, rate limits, caps, audit, CSP
  storage.py             #   SQLAlchemy (SQLite/Postgres) + JSON fallback
  models_db.py           #   ORM schema
  static/                #   dependency-free SPA
demo/                    #   fixture repos, diffs, dashboard seeder
tests/                   #   pytest suite
action.yml               #   composite GitHub Action (pip install + python -m ai_pr_reviewer)
Dockerfile               #   optional container build of the same engine (built in CI)
```

## 7 · Changelog & license

See [CHANGELOG.md](CHANGELOG.md).

[MIT](LICENSE).
