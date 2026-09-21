"""Rule shape + registry for the static-analysis engine.

`Rule` is the same frozen dataclass that used to live in heuristics.py —
moved here unchanged so every rule module can share one
definition. `RuleRegistry` is intentionally a simple list-append registry,
not a plugin system: rule modules call `register(registry)` at import time
and append into one of three buckets depending on how much context the
check needs:

  * ``line_rules``  — a regex `Rule` tested against every ADDED line in a
    file, independently, via `Rule.pattern`. This is the original
    heuristics.py model and covers the vast majority of checks.
  * ``file_rules``  — a callable ``(FileDiff) -> list[Finding]`` for checks
    that need more than one line of context (e.g. the AST-based Python
    checks, which need to see a whole statement/block).
  * ``diff_rules``  — a callable ``(list[FileDiff]) -> list[Finding]`` for
    checks that need to see the *whole changed file set* at once (e.g. the
    test-gap heuristic, which looks for a sibling test file elsewhere in
    the same diff).
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from ..diff_parser import FileDiff
from ..models import Finding

FileRule = Callable[[FileDiff], list[Finding]]
DiffRule = Callable[[list[FileDiff]], list[Finding]]


def lang_of(path: str) -> str:
    """File-extension language tag, e.g. 'py', 'js'. Shared by every rule
    module and by engine.py's line-rule runner (same logic that used to be
    a private helper inside heuristics.py)."""
    name = path.rsplit("/", 1)[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: re.Pattern
    languages: tuple[str, ...]          # file extensions; empty tuple = all
    severity: str
    category: str
    title: str
    explanation: str
    suggestion: str | None = None
    confidence: str = "medium"


class RuleRegistry:
    """Collects rules/analyzers contributed by every static-rules module.

    Deliberately dumb: three flat lists, appended to by each module's
    `register()` function. No discovery, no priorities, no plugin loading —
    a fancier registry isn't warranted yet.
    """

    def __init__(self) -> None:
        self.line_rules: list[Rule] = []
        self.file_rules: list[FileRule] = []
        self.diff_rules: list[DiffRule] = []

    def add_line_rules(self, rules: list[Rule]) -> None:
        self.line_rules.extend(rules)

    def add_file_rule(self, fn: FileRule) -> None:
        self.file_rules.append(fn)

    def add_diff_rule(self, fn: DiffRule) -> None:
        self.diff_rules.append(fn)

    def rule_ids(self) -> set[str]:
        """All rule_ids contributed by line_rules — useful for tests that
        assert an id was migrated without duplication."""
        return {r.rule_id for r in self.line_rules}
