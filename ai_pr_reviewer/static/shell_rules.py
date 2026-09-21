"""Shell/bash static rules.

Relocated (unchanged): ERR007 (`rm -rf` with an unquoted variable). SEC008
(chmod 777) is also shell-relevant but lives in security_rules.py, the
single source of truth for SEC* rule_ids — see that module's docstring.

Additional rules:

* SH001 — a bare `$VAR` / `${VAR}` outside any quotes. This can't be a
  plain regex `Rule` the way the others are: `"$VAR"` and `$VAR` differ
  only in characters that may be arbitrarily far to the left on the line,
  so telling them apart needs a tiny linear quote-parity scan, not a
  single pattern match. It's registered as a `file_rule` instead of a
  line `Rule` for that reason. It's a heuristic, not a shell parser — it
  tracks single/double-quote state char-by-char and nothing fancier
  (no here-docs, no backslash-escape handling), so treat it as
  low-confidence.
* SH002 — `curl ... | sh` / `| bash` install pipelines.
* SH003 — a chmod numeric mode whose world-permission digit is 7, for
  modes other than exactly 777/0777 (SEC008 already owns that exact case;
  this catches siblings like 707 or 757 that are still world-writable).
"""
from __future__ import annotations

import re

from ..diff_parser import FileDiff
from ..models import Finding
from .registry import Rule, RuleRegistry, lang_of

SHELL_RULES: list[Rule] = [
    Rule("ERR007", re.compile(r"\brm\s+-rf\s+\$?\{?\w"),
         ("sh", "bash"), "high", "bug",
         "Unquoted variable with rm -rf",
         "If the variable is empty or contains spaces this deletes unintended paths. "
         "Quote it and guard against emptiness.",
         'rm -rf "${BUILD_DIR:?}"'),

    # --- additional shell rules ---
    Rule("SH002",
         re.compile(r"curl\b[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"),
         ("sh", "bash"), "high", "security",
         "Piping curl output straight into a shell",
         "`curl ... | sh` runs whatever the remote server returns, with no "
         "integrity check — a compromised or MITM'd endpoint means arbitrary "
         "code execution. Download, checksum/verify, then execute.",
         "curl -sSL -o install.sh https://example.com/install.sh && "
         "sha256sum -c install.sh.sha256 && sh install.sh"),
    Rule("SH003",
         re.compile(r"\bchmod\s+(?:-{1,2}\S+\s+)*[+-]?(?!0?777\b|0o777\b)(?:0o)?0?[0-7]{2}7\b"),
         ("sh", "bash"), "medium", "security",
         "World-writable/executable permission granted",
         "The last (world) permission digit is 7 — any user/process can modify or "
         "execute this. Grant only the permissions actually needed.",
         "chmod 750 script.sh"),
]


def _find_unquoted_vars(text: str) -> list[str]:
    """Names of `$VAR`/`${VAR}` occurrences outside single- or
    double-quoted spans on this line (see module docstring for caveats)."""
    var_re = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
    hits: list[str] = []
    in_single = in_double = False
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue
        if ch == "$" and not in_single and not in_double:
            m = var_re.match(text, i)
            if m:
                hits.append(m.group(1))
                i = m.end()
                continue
        i += 1
    return hits


def unquoted_var_findings(fd: FileDiff) -> list[Finding]:
    if fd.is_binary or lang_of(fd.path) not in ("sh", "bash"):
        return []
    out: list[Finding] = []
    for line_no, text in fd.added_lines():
        if re.match(r"^\s*#", text):
            continue
        names = _find_unquoted_vars(text)
        if not names:
            continue
        detail = f"`${names[0]}`" if len(names) == 1 else f"{len(names)} variables"
        out.append(Finding(
            file=fd.path, line=line_no, severity="low", category="bug",
            title="Unquoted shell variable",
            explanation=(
                f"{detail} appears outside quotes. If it's empty or contains "
                "whitespace/globs, word-splitting can change this command's "
                "behavior. Quote it: \"$VAR\"."),
            confidence="low", rule_id="SH001"))
    return out


def register(registry: RuleRegistry) -> None:
    registry.add_line_rules(SHELL_RULES)
    registry.add_file_rule(unquoted_var_findings)
