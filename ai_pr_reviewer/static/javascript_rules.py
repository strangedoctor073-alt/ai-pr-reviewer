"""JavaScript/TypeScript static line-rules.

Relocated (unchanged): ERR004 (`var`), ERR005 (loose equality), HYG002
(console.log). SEC005 (innerHTML/XSS) and SEC006 (localStorage token) are
also JS-relevant but live in security_rules.py — the single source of
truth for every SEC* rule_id (see that module's docstring) — so they are
not redefined here.

Additional rules: a couple of deterministic regex checks beyond the migrated
ones. This intentionally stays regex-based for now — a real JS/TS parser
is future work.
"""
from __future__ import annotations

import re

from .registry import Rule, RuleRegistry

JAVASCRIPT_RULES: list[Rule] = [
    Rule("ERR004", re.compile(r"\bvar\s+\w+\s*="),
         ("js", "ts"), "low", "bug",
         "`var` is function-scoped and hoisted",
         "`var` can leak out of blocks and cause closure bugs. Use let/const."),
    Rule("ERR005", re.compile(r"[^=!<>]==[^=]"),
         ("js", "ts"), "medium", "bug",
         "Loose equality (==) performs type coercion",
         "`==` coerces types ('' == 0 is true). Use === / !== to avoid subtle bugs."),
    Rule("HYG002", re.compile(r"console\.log\("),
         ("js", "ts"), "low", "style",
         "console.log left in code",
         "Debug logging should use a leveled logger or be removed before merge."),

    # --- additional JS rules ---
    Rule("JS001",
         re.compile(r"`[^`]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^`]*\$\{", re.I),
         ("js", "ts", "jsx", "tsx"), "critical", "security",
         "Possible SQL injection via template-literal query",
         "A SQL keyword and a `${...}` interpolation appear in the same template "
         "literal, so a value is likely being concatenated straight into a query. "
         "Use a parameterized query / query builder instead.",
         "db.query('SELECT * FROM orders WHERE id = ?', [orderId])"),
    Rule("JS002", re.compile(r"\bdocument\.write(ln)?\s*\("),
         ("js", "ts", "jsx", "tsx"), "medium", "security",
         "document.write() can introduce XSS and blocks parsing",
         "document.write() executes synchronously during parsing and, if fed "
         "user-controlled content, can inject markup/scripts. Use DOM APIs "
         "(createElement/textContent) or a templating/render layer instead."),
]


def register(registry: RuleRegistry) -> None:
    registry.add_line_rules(JAVASCRIPT_RULES)
