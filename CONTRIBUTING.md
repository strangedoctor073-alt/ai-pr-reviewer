# Contributing

Thanks for improving AI PR Reviewer.

## Before opening a pull request

- Keep each pull request focused on one behavior change.
- Add or update tests for behavior changes.
- Run `python -m pytest tests/ -q` locally.
- Do not include secrets, real pull-request diffs, or dashboard data in fixtures.
- Update the README or example workflow when the public Action contract changes.

## Pull requests

Explain the problem, the chosen approach, and validation performed. Preserve the
security boundaries: PR diffs are untrusted input, repository policy must come
from a trusted base revision, and fork-triggered workflows must not receive
repository secrets.

## Reporting vulnerabilities

Do not use a public issue for suspected vulnerabilities. Follow
[SECURITY.md](SECURITY.md) instead.
