# Changelog

## Unreleased

Phase 0 ("V3.x" validation & hardening). Nothing here renames or removes
an input, an output or a required report field — additions only, plus the
deprecation notice below. Contract-relevant entries only.

### Added
- Evaluation gate: blocking `evaluation` CI job running the offline,
  deterministic corpus (`python -m eval.harness --gate`, ADR-016 Tier A).
- Lint gate: blocking `lint` CI job running the pinned ruff
  critical-defect ruleset (`E9`, `F63`, `F7`, `F82`).
- Report JSON (additive): `below_threshold` findings, the `telemetry`
  block, and per-finding provenance fields (`provenance_engine`,
  `provenance_model`, `provenance_agent`, `provenance_origin`). The
  required-field contract is frozen by `tests/test_report_schema.py`.
- Config: `retention_days` review-retention setting (environment/CLI;
  every storage backend prunes older reviews per the documented policy).
- Python support policy stated once (README §5): supported range
  3.11–3.13, Action runtime pinned to 3.12, local best-effort through
  3.14, `PYTHONUTF8=1` Windows guidance documented.

### Deprecated
- The `ai_pr_reviewer.analyzer` and `ai_pr_reviewer.heuristics` import
  facades now emit `DeprecationWarning`. Their dead entry points —
  `get_analyzer()`, `ClaudeAnalyzer`, `MockAnalyzer` — have no production
  callers and will be removed in **v4.0.0, no earlier than 2027-04-07**
  (6-month window, `docs/planning/MIGRATION_PLAN.md` §7). The production
  imports that live in the same files (`StaticAnalyzer`,
  `AnalysisOutcome`, `analyze_with_rules`) keep working until then.

### Changed
- Unknown `INPUT_*` environment variables and unknown top-level keys in
  `.ai-pr-reviewer.yml` now log a warning (names only, never values)
  instead of being silently ignored — forward compatibility for future
  inputs without breaking today's runs.

### Fixed
- The v2 pre-release audit defects D1–D7: inline findings not sorted
  before the comment cap, verification seeing only the capped comment
  list, below-threshold findings dropped from the report, report/health
  consuming the uncapped inline list, raw `int()` crashes on three
  numeric inputs (now a clean exit 1 naming the field), and duplicate
  minted mute rows on both storage backends.
- Stale compatibility-facade docstrings that claimed `cli.py` still used
  `get_analyzer` (it runs through `orchestrator` + `model_router`) and
  that the orchestrator "hasn't landed yet".

### Security
- The sensitive-path privacy baseline and the documented caps are pinned
  by tests: the dashboard reuses the engine's baseline object
  (identity-checked) and `tests/test_cap_constants.py` freezes every
  documented cap value, so neither can drift without a reviewed diff.

## 2.0.0

### Added
- Multi-provider reviews: Claude, OpenAI and Google Gemini, plus any
  OpenAI-compatible endpoint (`openai_base_url`, e.g. Ollama / Groq / DeepSeek).
- PR Health Score and grade (`health_score`, `health_grade` Action outputs, report field, dashboard badge).
- Incremental reviews, finding lifecycle (new / active / resolved) and review state.
- Dashboard: findings browser, metrics, feedback, public SVG health badge, diff sandbox.
- Static-rules fallback reorganised into a rule registry (~25 rules).
- Warning when a PR modifies `.ai-pr-reviewer.yml` (policy must come from the trusted base revision).

### Security
- Provider API keys are never placed in URLs (Gemini key moved from `?key=` to the
  `x-goog-api-key` header) and provider/HTTP error text is scrubbed of the
  configured credentials before it reaches reports, step summaries or comments.
- Dashboard token file is written with mode 0600 where the OS supports it.

### Changed (breaking)
- `model` has no built-in default for OpenAI, Gemini or custom endpoints: it must be
  set explicitly (exit code 1 with a clear message otherwise). Claude still defaults
  to `claude-sonnet-4-6`. Provider model IDs are retired regularly; a hard-coded
  default would silently fail.
- The example workflow checks out the PR **base** revision and uses `@v2`.

### Fixed
- OpenAI/Gemini-only setups no longer send the Claude model name to the vendor.
- `health_score` / `health_grade` outputs declared in `action.yml` are now actually written.
- OpenAI-compatible endpoints that need no API key (local models) now work.
- Missing `--diff-file` gives a clean error instead of a traceback.
- Removed `cache:` from the composite action's `setup-python` step (its
  `cache-dependency-path` pointed outside the workspace).

## 1.0.0
- Initial release.
