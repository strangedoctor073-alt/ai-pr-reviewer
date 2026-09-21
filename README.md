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

## What's in the box

- **Claude-backed review** with a machine-checkable contract: `file`, `line`
  (in the *new* file), `severity`, `category`, `explanation`, optional
  `suggestion` snippet, `confidence`.
- **Correct inline anchoring** — a unified-diff parser maps findings to lines
  GitHub allows comments on; out-of-range lines snap to the nearest changed
  line; unanchorable findings stay in the summary.
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

The example workflow uses `strangedoctor073-alt/ai-pr-reviewer@v1`. If you fork
this repository, point `uses:` at your fork and tag a release.

The workflow checks out the PR's **base revision** before running the Action,
so `.ai-pr-reviewer.yml` is repository-owner configuration rather than
untrusted PR content. Fork PRs use the static engine and produce only an
artifact; they receive no repository secrets and make no GitHub or dashboard
writes. Do not replace `pull_request` with `pull_request_target`.

For an on-demand run, choose **Run workflow** and supply the pull-request
number. The same Action configuration can be used without an API key by
setting `mock: true`; that runs deterministic static rules, not AI.

### Inputs (abridged)

| Input | Default | Description |
|---|---|---|
| `github_token` | — (required) | Token with `pull-requests:write` |
| `pr_number` | Event PR | Required for manual workflow runs; otherwise taken from the event |
| `anthropic_api_key` | — | Without it (or with `mock: true`) the static fallback runs |
| `model` | `claude-sonnet-4-6` | Any Claude model id (`claude-haiku-4-5` for cheap/high-volume) |
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

**Outputs:** `findings_count`, `critical_count`, `report_path`. A markdown
digest is also written to the job's **Step Summary**, and `review-report.json`
is available as an artifact.

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
4. Each batch is **screened for prompt injection**, **fenced with a fresh
   nonce**, and sent to Claude with a system prompt that (a) pins the output
   schema, (b) declares the fenced block untrusted data, (c) forbids quoting
   secrets. Model output is JSON-validated, findings are snapped to real diff
   lines, and every string is **secret-redacted**.
5. One `COMMENT` review is posted: inline comments + markdown summary, with a
   regular-comment fallback.

### Known limitations

- **Repeat pushes can repeat comments.** Review state is only kept when a
  dashboard (or `--storage-file` when running locally) is configured. Without
  one, every run is a fresh, full review, so a new push can post findings that
  an earlier push already raised.
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

The **Findings** and **Metrics** tabs, the per-review timeline, and the
project-rules and feedback panels on the Settings page are previews that show
sample data. That data — repos like `acme/payments-service`, `acme/infra`,
`webshop/frontend` — is hardcoded in `dashboard/static/app.js` (the `MOCK`
object) and is not fetched from the API, so it appears on a completely fresh
install with zero real reviews, before you've run anything. Each of those
sections carries a visible **PREVIEW** badge for that reason. The **Reviews**
list, review detail page, and the settings form are the only parts wired to
real stored data (`GET/PUT /api/...`) — if a review doesn't show up there, it
isn't actually stored.

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
| `GET`/`PUT`/`POST` | `/api/reviews/{owner}/{repo}/{pr}/state` and `/findings`; `/api/repos/{owner}/{repo}/memory` | reads* / token | Review state the Action stores between pushes |

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
| Secrets leaking out via findings | `redact_secrets()` scrubs AWS/GitHub/Slack/Google-style keys, `Bearer` headers, `key=secret` pairs, private-key blocks and long hex from every posted/stored string |
| Prompt injection from PR content | Nonce-fenced `<untrusted_diff>` blocks with spoofed-tag neutralization, local injection screening (hits → report warnings), system-prompt rules to treat fenced text as data and never comply, model-reported `warnings` surfaced in the dashboard |
| XSS via malicious PR titles/finding text | All model data rendered through escaping (`esc()` before markdown-lite); links restricted to `https?:` with `rel="noopener"`; CSP `default-src 'self'`, `nosniff`, `Referrer-Policy: no-referrer` |
| Secrets living in reviewed files | A non-removable privacy baseline (`.env*`, `*.pem`/`*.key`, cloud/SSH credential dirs, service-account JSON, …) excludes secret-bearing paths from the diff before it reaches any analyzer, in both `ai_pr_reviewer/rules.py` and the dashboard's saved settings |
| Over-privileged tokens | Workflow declares `contents: read` + `pull-requests: write` only; the bot cannot push code or touch Actions/secrets. Use a fine-grained PAT scoped to PR read/write if `secrets.GITHUB_TOKEN` isn't suitable |
| Posture mistakes | **Never** switch the trigger to `pull_request_target` — it runs with base-repo secrets against untrusted forks |
| No forensic trail | Every write and every rejected auth attempt appended to `dashboard/data/audit.jsonl` |
| Dashboard tampering | Settings writes validated server-side (threshold enum, caps, list limits) |

**Before production (known gaps, on purpose)**

- Put the dashboard behind TLS + real SSO/OIDC or an authenticating proxy
  (GitHub OAuth apps work well here); the token is a service credential, not a
  user-login system.
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

The suite covers diff parsing, Action input layering, provider fallback,
GitHub review recovery, dashboard storage/authentication, and security
boundaries.

## 6 · Layout

```
ai_pr_reviewer/          # the engine (shipped in the Action's Docker image)
  diff_parser.py         #   unified diff → hunks with new-file line map
  security.py            #   injection screening, diff fencing, secret redaction
  rules.py                #   .ai-pr-reviewer.yml parsing → ReviewPolicy
  context.py              #   diff + related files + rules + memory → ReviewContext
  model_router.py         #   picks Claude vs. the static engine per PR/policy
  retry.py                #   backoff + jitter for the Anthropic call
  ai/
    provider.py           #     AIProvider protocol (shared by both backends)
    claude.py              #     ClaudeProvider — prompting, batching, fallback-on-failure
  static/                 #   deterministic rule engine (NOT AI)
    engine.py              #     StaticEngine: runs the registry, implements AIProvider too
    registry.py             #     RuleRegistry — rule_id/language/category/severity/confidence
    python_rules.py, javascript_rules.py, shell_rules.py, security_rules.py, test_rules.py
  heuristics.py            #   back-compat facade over static/engine.py (old import path)
  analyzer.py              #   legacy ClaudeAnalyzer/StaticAnalyzer facade over ai/ + static/
  findings.py              #   fingerprinting, deduplication, lifecycle (new/active/resolved…)
  review_state.py          #   stable review identity (repo + PR + head SHA)
  orchestrator.py          #   ReviewOrchestrator — wires all of the above into one review
  models.py                #   shared dataclasses: PRContext, Finding, ReviewResult, ReviewKey…
  storage.py               #   ReviewStorage protocol + dashboard HTTP client + local SQLite backend
  github_client.py         #   REST: PR, diff, reviews, comments
  reporter.py               #   report JSON, step summary, dashboard push
  cli.py / config.py        #   orchestration & config layering (calls orchestrator.py)
dashboard/
  app.py                 #   FastAPI app: auth, rate limits, caps, audit, CSP
  storage.py             #   SQLAlchemy (SQLite/Postgres) + JSON fallback
  models_db.py           #   ORM schema
  static/                #   dependency-free SPA
demo/                    #   fixture repos, diffs, dashboard seeder
tests/                   #   pytest suite
action.yml + Dockerfile  #   GitHub Action wrapper
```

## 7 · License

[MIT](LICENSE).
