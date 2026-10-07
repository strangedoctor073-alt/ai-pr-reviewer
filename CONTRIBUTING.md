# Contributing

Thanks for improving AI PR Reviewer.

## Before opening a pull request

- Keep each pull request focused on one behavior change.
- Add or update tests for behavior changes.
- Run `python -m pytest tests/ -q` locally — on a Windows cp1252 checkout
  run it as `PYTHONUTF8=1 python -m pytest tests/ -q`. The supported Python
  range (**3.11–3.13**, Action runtime pinned to 3.12) is stated in
  README §5 "Supported Python versions"; CI's `lint` job also requires
  `python -m ruff check .` to stay green.
- Do not include secrets, real pull-request diffs, or dashboard data in fixtures.
- Update the README or example workflow when the public Action contract changes,
  and add a CHANGELOG entry for every contract-affecting change (the release
  checklist in README §7 names the contract gates).

## Demo fixtures & the regeneration gotcha

- `demo/samples/*.diff` is committed reference data. The **test suite
  never rewrites it**: `tests/conftest.py` builds the fixtures into a
  pytest temp directory once per session, so two consecutive suite runs
  leave `git status` clean.
- To regenerate the samples deliberately, run `python demo/make_fixtures.py`
  (it shells out to `git` in temp repos). **On Windows this rewrites all
  three files with CRLF while `.gitattributes` (`* text=auto eol=lf`)
  forces LF**, so git reports them as modified with line-ending-only
  churn. Review `git diff` before committing and never commit pure
  line-ending churn.
- Fixture hygiene (audited 2026-10-07 during V3-E06-T05): `demo/`,
  `eval/` and `tests/` contain no secrets, no real pull-request diffs and
  no dashboard data; no `.db`/`.jsonl`/settings files are tracked. The
  secret-shaped strings that appear in tests are deliberately synthetic
  redaction fixtures (e.g. `AKIAIOSFODNN7EXAMPLE`, `ghp_AbCdEf…`) — keep
  any new ones obviously fake.

## Pull requests

Explain the problem, the chosen approach, and validation performed. Preserve the
security boundaries: PR diffs are untrusted input, repository policy must come
from a trusted base revision, and fork-triggered workflows must not receive
repository secrets.

## Evaluation harness (offline quality gate)

`eval/` holds the deterministic evaluation corpus and its runner — fully
offline: no network, no API keys. Metric definitions live in
`docs/planning/TESTING_EVALUATION_PLAN.md` §4/§5 and are executable in
`eval/harness/score.py`.

- **Run it:** `python -m eval.harness` prints per-case verdicts and the
  score (precision / recall / false-positive-rate / recall-critical-high;
  a ratio with no data prints `null`, never a fabricated number).
- **CI gate:** `python -m eval.harness --gate` compares this run against
  `eval/baseline.json` and fails (exit 1) on any drop beyond the
  documented strict thresholds, on corpus/baseline drift, or on any
  case failure — this is the blocking `evaluation` job in CI.
- **Add a case:** create `eval/corpus/<layer>/<case-id>/` containing a
  `case.yaml` and a `pr.diff` (real `diff --git` headers, correct hunk
  line counts). Layers: `regression`, `known-bug`, `false-positive`,
  `false-negative`, `injection`, `quality`. Provenance must be
  `hand-authored` or `synthetic` — never real PR diffs. Labels state what
  the engine must report (file, line hint, severity floor, title regex,
  optional `bucket`/`state`), plus traps (`must_not_report`,
  `no_findings`) for what it must never report; see existing cases and
  the strict schema in `eval/harness/loader.py`.
- **Move the baseline deliberately:** after any corpus change or an
  intended score change, run `python -m eval.harness --update-baseline`
  and commit the reviewed diff — the baseline embeds the corpus hash, so
  it can only move together with the corpus it describes. Failing or
  errored states are refused.
- **Machine-readable results:** `--json PATH` writes a byte-stable
  report (score, case count, corpus hash, git commit/dirty flag) for CI
  artifacts.
- Fixture rules apply here too: **no secrets, real pull-request diffs,
  or dashboard data anywhere under `eval/`.**

## Reporting vulnerabilities

Do not use a public issue for suspected vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.
