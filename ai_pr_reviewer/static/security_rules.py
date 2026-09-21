"""Security line-rules SEC001-SEC008.

Relocated from the old flat heuristics.py RULES list — pattern, rule_id,
severity, title and explanation text are all unchanged from the original,
this is a move, not a rewrite. No new rules are added here: the "strong
static fallback" security upgrades are the AST-based
Python checks (see python_rules.py) and the expanded secret-redaction
patterns in security.py, which is a distinct concern (detection here vs.
redaction there — see security.py's module docstring).

SEC005 (innerHTML/XSS) and SEC006 (localStorage token) are JS-language
checks and SEC008 (chmod 777) is also relevant to shell scripts, but all
eight SEC* rules are kept here as the single source of truth so a rule_id
is only ever registered once. javascript_rules.py and shell_rules.py
cross-reference them in their own docstrings rather than redefining them.
"""
from __future__ import annotations

import re

from .registry import Rule, RuleRegistry

SEC_RULES: list[Rule] = [
    Rule("SEC001",
         re.compile(
             r"f[\"'][^\"']*\b(SELECT|INSERT|UPDATE|DELETE)\b"
             r"|(execute|executemany|raw|query|text)\s*\(\s*f[\"']"
             r"|(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*[\"']\s*(%|%\s*\(|\+\s*\w)",
             re.I),
         ("py",), "critical", "security",
         "Possible SQL injection via string-formatted query",
         "This query is built with an f-string/formatting, so any user-controlled "
         "value is interpolated directly into SQL. Use parameterized queries instead.",
         'cursor.execute("SELECT * FROM orders WHERE id = %s", (order_id,))'),
    Rule("SEC002",
         re.compile(
             r"(password|passwd|secret|api_key|apikey|token|access_key)\s*[:=]\s*"
             r"([\"'][^\"']{6,}[\"']|[A-Za-z0-9_\-]{8,})", re.I),
         (), "critical", "security",
         "Hardcoded credential in source code",
         "A secret appears to be hardcoded. Move it to an environment variable or a "
         "secrets manager — anything committed to git is considered compromised.",
         'API_KEY = os.environ["API_KEY"]'),
    Rule("SEC003", re.compile(r"\beval\s*\("),
         ("py", "js", "ts"), "critical", "security",
         "Use of eval() executes arbitrary code",
         "eval() on untrusted input allows remote code execution. Parse data with a "
         "safe parser (ast.literal_eval / JSON) instead."),
    Rule("SEC004", re.compile(r"\bos\.system\s*\(|subprocess\.\w+\([^)]*shell\s*=\s*True"),
         ("py",), "high", "security",
         "Shell command built from code without escaping",
         "Passing user data through a shell enables command injection. Prefer "
         "subprocess.run([...]) with a list of args and shell=False."),
    Rule("SEC005", re.compile(r"\.innerHTML\s*="),
         ("js", "ts", "jsx", "tsx"), "high", "security",
         "Assignment to innerHTML can introduce XSS",
         "If any part of this string is user-controlled, attackers can inject scripts. "
         "Use textContent or a sanitizing renderer."),
    Rule("SEC006", re.compile(r"localStorage\.setItem\([\"'](.*token|.*secret|.*password)", re.I),
         ("js", "ts"), "high", "security",
         "Auth token stored in localStorage",
         "localStorage is readable by any JavaScript on the page (including injected "
         "XSS payloads). Prefer httpOnly, secure cookies for session tokens."),
    Rule("SEC007", re.compile(r"verify\s*=\s*False"),
         ("py",), "critical", "security",
         "TLS certificate verification disabled",
         "verify=False disables HTTPS certificate checks, enabling man-in-the-middle "
         "attacks. Remove it or pin a CA bundle."),
    Rule("SEC008", re.compile(r"chmod[^\n]*777|0o777"),
         ("py", "sh", "bash"), "medium", "security",
         "World-writable permission granted (777)",
         "777 lets any user/process modify this file. Grant only the permissions "
         "actually needed (e.g. 0o755)."),
]


def register(registry: RuleRegistry) -> None:
    registry.add_line_rules(SEC_RULES)
