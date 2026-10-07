# AGENTS.md

AI PR Reviewer: a composite GitHub Action (`action.yml`) that runs the Python
engine in `ai_pr_reviewer/`, plus an optional FastAPI dashboard in `dashboard/`.
No build step; pip only. The Action image targets Python 3.12; CI tests
3.11–3.13 (the local 3.14 interpreter runs the suite fine).

## Current release state (V3.0.0)

- `v3.0.0` → commit `1afc351` — immutable: never move the tag, never amend
  the release commit. The GitHub Release "AI PR Reviewer v3.0.0" is marked
  Latest; docs/examples pin the Action at `@v3.0.0` (no moving `v3` tag).
- `main` may advance past the tag with docs/fix commits; that is expected.
- Public contract: 21 Action inputs, 5 outputs, report JSON is
  **additive-only** (`tests/test_report_schema.py` guards it).
- Protected pre-existing worktree state: `.github/dependabot.yml` shows as
  deleted (` D`) — intentional. Never restore it, never stage it.
- `AGENTS.md` (this file) is updated only on explicit user instruction.

## V4 status — planning complete, execution not started

- The V4 master plan is approved: epics `V4-E01`…`V4-E11`
  (`V4-E06` digital-twin seed and `V4-E07` read-contract kit are DEFERRED;
  their IDs stay reserved — never renumber epics, planning docs cross-ref them).
- V3.0.0 is the stable baseline. V4 rules: additive-only schema, report
  schema additive, privacy baseline non-removable, no rewrites of stable
  components for style, evaluation before implementation, no destructive
  migrations.
- Batch 1 (C0-T01…T05 + E08-T01) complete; next: Batch 2 (E08-T02/T03 + E01).

## Commands

- All tests: `python -m pytest tests/ -q` — exactly what CI runs
  (`.github/workflows/ci.yml`). Fully offline: providers and GitHub are mocked,
  no API keys needed.
- Single test: `python -m pytest tests/test_orchestrator.py::test_name -q`.
- **Always use `python -m pytest`, never bare `pytest`** (no `pytest` script on
  PATH here, and `-m` puts the repo root on `sys.path`).
  `tests/test_config.py`, `tests/test_multi_provider.py` and
  `tests/test_release_hardening.py` have no `sys.path.insert` of their own and
  fail to import `ai_pr_reviewer` otherwise.
- Lint: `python -m ruff check .` — CI pins `ruff==0.16.10` (baseline
  E9/F63/F7/F82). No formatter/typechecker is configured.
- Eval gate: `python -m eval.harness --gate` (offline 8-case corpus,
  non-zero exit on any regression). Full release gate = pytest + eval +
  ruff + `git diff --check`. CI runs 4 jobs: `test`, `action-image`,
  `evaluation`, `lint`.
- Local review with no GitHub and no API cost:
  `python -m ai_pr_reviewer --diff-file demo/samples/payments_refunds.diff --repo acme/payments --pr 42 --mock --no-comment --output demo/out/report.json`
  (`--mock` / `--static` = deterministic regex engine, **not AI**).
  Exit codes: `0` clean, `1` config error, `2` `fail_on` threshold reached.
- Dashboard: `pip install -r requirements.txt`, then
  `uvicorn dashboard.app:app --host 127.0.0.1 --port 8000`. The API token is
  printed on first start (stored in `dashboard/data/settings.json`); seed with
  `python demo/seed_demo.py` while it runs.

## Windows checkout gotchas (verified here)

- `tests/test_release_hardening.py::test_no_retired_model_ids_are_hardcoded_in_the_engine`
  reads engine sources with `Path.read_text()` using the locale encoding, so it
  blows up under cp1252. Run with `PYTHONUTF8=1` (886 passed, 2 skipped;
  without it, 2 source-scanning tests fail under cp1252).
- `tests/test_pipeline.py` and `tests/test_static_engine.py` call
  `demo.make_fixtures.build_all()`, which shells out to `git` in temp dirs and
  **rewrites `demo/samples/*.diff`**. Expect those three files to show as
  modified after a test run (CRLF vs `.gitattributes` `eol=lf`) — don't commit
  line-ending-only churn.

## Structure

- `ai_pr_reviewer/` — engine. `python -m ai_pr_reviewer` → `cli.py` →
  `orchestrator.py`; `model_router.py` selects Claude / OpenAI / Gemini /
  static. `static/` is a deterministic rule engine — never describe it as AI.
  `rules.py` parses `.ai-pr-reviewer.yml` into `ReviewPolicy`.
- `dashboard/` — FastAPI app (`dashboard.app:app`), SQLAlchemy storage
  (SQLite default, `DATABASE_URL` for Postgres), dependency-free SPA in
  `dashboard/static/`.
- Config layering (`config.py`): CLI args > `INPUT_*` env (what `action.yml`
  sets) > plain env vars.
- `requirements.txt` = engine + dashboard + pytest. `requirements-action.txt` =
  lean deps for the Action image; keep fastapi/uvicorn/sqlalchemy out of it.
- `.ai-pr-reviewer.yml` is *this* repo's review policy (read only from the
  trusted base revision); `.ai-pr-reviewer.yml.example` is the user template.
- `README.md` is the primary doc (inputs, API table, security model, layout).

## Security invariants — tests enforce these; don't relax them

- PR diffs are untrusted input: nonce-fenced `<untrusted_diff>` blocks and
  injection screening (`security.py`), plus `redact_secrets()` on warnings,
  telemetry, memory and repository context. Invariant to uphold: everything
  posted or stored must be redacted as well — V4 ticket `V4-E08-T06` pins
  the finding→comment/report chokepoint, which today is not yet
  test-enforced. Don't widen that gap.
- The privacy baseline exclusion list in `ai_pr_reviewer/rules.py` is
  non-removable — repository config can only add exclusions.
- Keep the example workflow on `pull_request` (never `pull_request_target`) and
  checking out the PR **base** revision, so a PR can't rewrite its own policy.
- No retired model ids may be hardcoded anywhere under `ai_pr_reviewer/`.
  Only Claude has a default model (`claude-sonnet-4-6`); OpenAI/Gemini/custom
  endpoints require an explicit `model` (config error `1` otherwise).
- Fixtures must contain no secrets, real PR diffs, or dashboard data
  (`CONTRIBUTING.md`); update README / `example-workflow.yml` when the public
  Action contract (inputs, outputs) changes.
