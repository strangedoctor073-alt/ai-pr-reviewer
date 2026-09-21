"""Python-specific static rules.

Two layers:

1. Relocated regex line-rules (ERR001-003, ERR006, RES001-002, HYG001,
   HYG003-004) — pattern, rule_id, severity and message text are unchanged
   from the original heuristics.py, this is a move, not a rewrite.

2. AST-based checks (rule_ids AST001-AST006) — the real
   quality upgrade. These parse actual Python syntax instead of matching
   text, so they don't get fooled by e.g. a mutable default spanning a
   line break, and they catch `except Exception: pass` regardless of
   whether `pass` sits on the same source line as `except` (ERR001/ERR002
   only match same-line text).

KNOWN LIMITATION (by design, not a bug): we only have the
diff text, not the full new file, so a hunk's added lines are not
necessarily valid Python on their own (e.g. a change that touches only the
*body* of a function, not its `def` line, or one half of a bracket pair
that spans unchanged context lines). We AST-parse each contiguous run of
added ('+') lines within a hunk as a best-effort standalone module
(dedented first, so an indented method body has a chance to parse), and
silently skip any run that raises SyntaxError. This means the AST checks
are best-effort and will miss some real issues that the equivalent regex
rules above may still catch on their own — that's an acceptable trade-off
for a deterministic *fallback*, not a replacement for the Claude reviewer.
"""
from __future__ import annotations

import ast
import re
import textwrap

from ..diff_parser import FileDiff
from ..models import Finding
from .registry import Rule, RuleRegistry, lang_of

# --------------------------------------------------------------------------
# 1 · Relocated regex rules (unchanged behavior)
# --------------------------------------------------------------------------

PYTHON_RULES: list[Rule] = [
    Rule("ERR001", re.compile(r"except\s*:\s*(pass|#|$)"),
         ("py",), "high", "error-handling",
         "Bare `except:` swallows every exception",
         "A bare except catches SystemExit/KeyboardInterrupt and hides real failures. "
         "Catch the specific exception and log or handle it.",
         "except RefundError:\n    logger.exception(\"refund failed\")"),
    Rule("ERR002", re.compile(r"except\s+Exception\s*:\s*pass"),
         ("py",), "medium", "error-handling",
         "Silent `except Exception: pass` hides failures",
         "Swallowing all exceptions makes bugs invisible. At minimum, log the error."),
    Rule("ERR003", re.compile(r"==\s*None\b|!=\s*None\b"),
         ("py",), "low", "style",
         "Compare to None with `is`",
         "PEP 8: comparisons to None should use `is` / `is not` — `==` can be "
         "overloaded and behave unexpectedly.",
         "if result is not None:"),
    Rule("ERR006", re.compile(r"def\s+\w+\([^)]*=\s*(\[\]|\{\})"),
         ("py",), "high", "bug",
         "Mutable default argument shared across calls",
         "Default list/dict arguments are created once and mutated across calls, "
         "a classic source of state-leak bugs.",
         "def add_item(item, items=None):\n    items = items if items is not None else []"),
    Rule("RES001", re.compile(r"=\s*open\("),
         ("py",), "medium", "resource-leak",
         "File opened without a context manager",
         "File handles opened with open() are only closed when GC runs. Use "
         "`with open(...) as f:` to close deterministically."),
    Rule("RES002", re.compile(r"\basync\s+def\b|\bawait\s"), (), "low", "race-condition",
         "Async code — check for shared mutable state",
         "Concurrent tasks can interleave between awaits. Verify shared state is "
         "protected or confined to one task."),
    Rule("HYG001", re.compile(r"^\s*print\("),
         ("py",), "low", "style",
         "Debug print() left in code",
         "Use the project logger so output is leveled, formatted and routable.",
         'logger.debug("...")'),
    Rule("HYG003", re.compile(r"(TODO|FIXME|HACK|XXX)\b"),
         (), "info", "maintainability",
         "TODO/FIXME comment introduced",
         "Track this work in an issue rather than a comment so it doesn't rot."),
    Rule("HYG004", re.compile(r"\btime\.sleep\("),
         ("py",), "low", "performance",
         "time.sleep() in request path",
         "Blocking sleeps stall the whole event loop/worker. Use async sleep or a "
         "retry/backoff library with jitter."),
]

# --------------------------------------------------------------------------
# 2 · AST-based checks (new)
# --------------------------------------------------------------------------

_SUBPROCESS_SHELL_FUNCS = {"run", "call", "Popen", "check_call", "check_output"}
_UNSAFE_YAML_LOADERS = {"Loader"}  # presence checked, not the value — see note below


def _added_blocks(fd: FileDiff) -> list[tuple[int, str]]:
    """Group each hunk's contiguous runs of added ('+') lines into
    (new_file_start_line, dedented_source) blocks, so ast.parse() gets a
    chance at something structurally coherent instead of one line at a
    time. Context/removed lines break a run, since the AST needs to see
    added code exactly as it will appear (nothing from the removed side)."""
    blocks: list[tuple[int, str]] = []
    for hunk in fd.hunks:
        run: list[str] = []
        run_start: int | None = None
        for hl in hunk.lines:
            if hl.tag == "+":
                if run_start is None:
                    run_start = hl.new_no
                run.append(hl.text)
            else:
                if run:
                    blocks.append((run_start, "\n".join(run)))
                run, run_start = [], None
        if run:
            blocks.append((run_start, "\n".join(run)))
    return blocks


def _mutable_default_findings(fd: FileDiff, start: int, tree: ast.AST) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        defaults = list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]
        if any(isinstance(d, (ast.List, ast.Dict, ast.Set)) for d in defaults):
            out.append(Finding(
                file=fd.path, line=start + node.lineno - 1,
                severity="high", category="bug",
                title="Mutable default argument shared across calls (AST-detected)",
                explanation=(
                    f"`{node.name}` has a list/dict/set default. Defaults are "
                    "evaluated once at def-time and shared across every call, a "
                    "classic source of state-leak bugs."),
                suggestion=(
                    f"def {node.name}(..., items=None):\n"
                    "    items = items if items is not None else []"),
                confidence="high", rule_id="AST001"))
    return out


def _eval_exec_findings(fd: FileDiff, start: int, tree: ast.AST) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ("eval", "exec"):
            out.append(Finding(
                file=fd.path, line=start + node.lineno - 1,
                severity="critical", category="security",
                title=f"Use of {node.func.id}() executes arbitrary code (AST-detected)",
                explanation=(
                    f"{node.func.id}() on untrusted input allows remote code "
                    "execution. Parse data with a safe parser (ast.literal_eval / "
                    "JSON) instead."),
                confidence="high", rule_id="AST002"))
    return out


def _subprocess_shell_findings(fd: FileDiff, start: int, tree: ast.AST) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        if node.func.attr not in _SUBPROCESS_SHELL_FUNCS:
            continue
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                out.append(Finding(
                    file=fd.path, line=start + node.lineno - 1,
                    severity="high", category="security",
                    title="subprocess call with shell=True (AST-detected)",
                    explanation=(
                        "Passing user data through a shell enables command "
                        "injection. Prefer a list of args with shell=False."),
                    suggestion="subprocess.run([...], shell=False)",
                    confidence="high", rule_id="AST003"))
    return out


def _bare_except_findings(fd: FileDiff, start: int, tree: ast.AST) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        line = start + node.lineno - 1
        if node.type is None:
            out.append(Finding(
                file=fd.path, line=line, severity="high", category="error-handling",
                title="Bare `except:` clause (AST-detected)",
                explanation=(
                    "A bare except catches SystemExit/KeyboardInterrupt too and "
                    "hides real failures. Catch the specific exception."),
                confidence="high", rule_id="AST004"))
        elif (isinstance(node.type, ast.Name) and node.type.id == "Exception"
              and len(node.body) == 1 and isinstance(node.body[0], ast.Pass)):
            out.append(Finding(
                file=fd.path, line=line, severity="medium", category="error-handling",
                title="Silent `except Exception: pass` (AST-detected)",
                explanation="Swallowing all exceptions makes bugs invisible. At "
                            "minimum, log the error.",
                confidence="high", rule_id="AST004"))
    return out


def _unsafe_deserialization_findings(fd: FileDiff, start: int, tree: ast.AST) -> list[Finding]:
    out: list[Finding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        base = node.func.value
        base_name = base.id if isinstance(base, ast.Name) else None
        line = start + node.lineno - 1
        if base_name == "pickle" and node.func.attr in ("load", "loads"):
            out.append(Finding(
                file=fd.path, line=line, severity="high", category="security",
                title="Unsafe pickle deserialization (AST-detected)",
                explanation=(
                    "pickle.load/loads can execute arbitrary code when fed "
                    "untrusted data. Use a safe serialization format (JSON) for "
                    "anything that isn't fully trusted."),
                confidence="medium", rule_id="AST005"))
        elif base_name == "yaml" and node.func.attr == "load":
            # We only check whether a Loader= kwarg was supplied at all, not
            # whether it's actually SafeLoader — a full type check would need
            # to resolve the import alias, which is out of scope for a
            # best-effort AST pass on a diff fragment. Document as best-effort.
            if not any(kw.arg in _UNSAFE_YAML_LOADERS for kw in node.keywords):
                out.append(Finding(
                    file=fd.path, line=line, severity="high", category="security",
                    title="yaml.load() without an explicit Loader (AST-detected)",
                    explanation=(
                        "yaml.load() without Loader=yaml.SafeLoader can "
                        "instantiate arbitrary Python objects from the input. "
                        "Use yaml.safe_load() or pass Loader=yaml.SafeLoader."),
                    suggestion="yaml.safe_load(stream)",
                    confidence="medium", rule_id="AST006"))
    return out


_AST_CHECKS = (
    _mutable_default_findings,
    _eval_exec_findings,
    _subprocess_shell_findings,
    _bare_except_findings,
    _unsafe_deserialization_findings,
)


def ast_checks(fd: FileDiff) -> list[Finding]:
    """Entry point registered as a `file_rule`. Only runs on .py files."""
    if fd.is_binary or lang_of(fd.path) != "py":
        return []
    findings: list[Finding] = []
    for start, block_src in _added_blocks(fd):
        try:
            tree = ast.parse(textwrap.dedent(block_src))
        except SyntaxError:
            # Expected and common: a diff hunk's added lines alone often
            # aren't valid Python on their own (see module docstring).
            continue
        for check in _AST_CHECKS:
            findings.extend(check(fd, start, tree))
    return findings


def register(registry: RuleRegistry) -> None:
    registry.add_line_rules(PYTHON_RULES)
    registry.add_file_rule(ast_checks)
