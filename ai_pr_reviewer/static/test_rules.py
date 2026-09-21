"""Test-gap heuristic.

For each changed non-test source file, check whether *some* changed file in
the same diff looks like its test, using a simple naming-convention match
(tests/test_foo.py, foo_test.py, foo.test.js, foo.spec.ts, ...) — nothing
fancier: no import-graph analysis, no coverage data. If nothing matches,
emit ONE low-confidence, low-severity, file-level (line=None) finding.

This is deliberately a `diff_rule` (works over the whole `list[FileDiff]`),
not a `file_rule` — a single file's own diff never contains enough
information to say whether *some other file* in the PR is its test.

Explicitly out of scope: files that are themselves tests,
config files, or docs never get flagged (a docs-only or config-only PR
doesn't need a test file).
"""
from __future__ import annotations

import re

from ..diff_parser import FileDiff
from ..models import Finding
from .registry import RuleRegistry, lang_of

_TEST_PATH_PATTERNS = [
    re.compile(r"(^|/)tests?/"),
    re.compile(r"(^|/)__tests__/"),
    re.compile(r"(^|/)test_[^/]+\.py$"),
    re.compile(r"(^|/)[^/]+_test\.py$"),
    re.compile(r"(^|/)[^/]+\.(test|spec)\.[jt]sx?$"),
]

# Extensions/basenames that are config or docs, not "source" — never flagged
# for a missing test, and never treated as a candidate test file either.
_NON_SOURCE_EXTENSIONS = {
    "md", "rst", "txt", "yml", "yaml", "json", "toml", "ini", "cfg", "conf",
    "lock", "gitignore", "dockerignore", "env", "cfg", "csv", "svg", "png",
    "jpg", "jpeg", "gif", "ico", "html", "css",
}
_NON_SOURCE_BASENAMES = {
    "dockerfile", "makefile", "license", "changelog", "readme", "notice",
}

# "Source" languages this heuristic knows how to pair with a test file.
# Anything else (shell scripts, config, etc.) is skipped — the naming
# convention below is really a Python/JS/TS convention.
_SOURCE_LANGS = {"py", "js", "jsx", "ts", "tsx"}


def _is_test_path(path: str) -> bool:
    return any(p.search(path) for p in _TEST_PATH_PATTERNS)


def _is_non_source(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    base = name.rsplit(".", 1)[0].lower()
    ext = lang_of(path)
    return ext in _NON_SOURCE_EXTENSIONS or base in _NON_SOURCE_BASENAMES


def _stem(path: str) -> str:
    """Normalized basename for a loose match: strip extension and common
    test prefixes/suffixes so `payments.py` and `test_payments.py` (or
    `payments_test.py`, `payments.test.js`, `payments.spec.ts`) compare
    equal."""
    name = path.rsplit("/", 1)[-1]
    name = re.sub(r"\.(py|jsx?|tsx?)$", "", name)
    name = re.sub(r"\.(test|spec)$", "", name)
    name = re.sub(r"^test_", "", name)
    name = re.sub(r"_test$", "", name)
    return name.lower()


def test_gap_findings(files: list[FileDiff]) -> list[Finding]:
    test_stems = {_stem(fd.path) for fd in files
                  if not fd.is_binary and _is_test_path(fd.path)}

    out: list[Finding] = []
    for fd in files:
        if fd.is_binary or fd.is_deleted:
            continue
        if _is_test_path(fd.path) or _is_non_source(fd.path):
            continue
        if lang_of(fd.path) not in _SOURCE_LANGS:
            continue
        if fd.additions == 0:
            continue
        if _stem(fd.path) in test_stems:
            continue
        out.append(Finding(
            file=fd.path, line=None, severity="low", category="testing",
            title="possible missing test coverage",
            explanation=(
                f"This diff changes {fd.path} but no changed file in the same "
                "PR looks like its test (checked simple naming conventions: "
                "tests/test_<name>, <name>_test, <name>.test/.spec). This is a "
                "low-confidence heuristic, not proof there's no test — the "
                "test file may simply not need changes, or may live under a "
                "different name."),
            confidence="low", rule_id="TEST001"))
    return out


def register(registry: RuleRegistry) -> None:
    registry.add_diff_rule(test_gap_findings)
