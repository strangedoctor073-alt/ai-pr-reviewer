# Changelog

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
