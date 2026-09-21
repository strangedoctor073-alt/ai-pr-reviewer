"""Backward-compatible facade.

The heuristic rule engine described in this module's old docstring now
lives in :mod:`ai_pr_reviewer.static` (registry + per-language rule
modules + AST-based Python checks). This file is kept as a thin
compatibility shim so existing imports keep working unchanged:

    from ai_pr_reviewer.heuristics import analyze_with_rules, Rule

See ai_pr_reviewer/static/engine.py for the real implementation.
"""
from __future__ import annotations

from .diff_parser import FileDiff
from .models import Finding
from .static.engine import StaticEngine as _Engine
from .static.registry import Rule  # noqa: F401 -- re-exported for compatibility

_default_engine = _Engine()


def analyze_with_rules(files: list[FileDiff]) -> list[Finding]:
    """Run every static rule over every ADDED line (and, for Python files,
    the new AST-based checks) of the diff. Backward-compatible wrapper --
    behavior/output shape unchanged, implementation moved to
    ai_pr_reviewer.static.engine.StaticEngine."""
    return _default_engine.run(files)


# `RULES` used to be a flat list of ~21 regex Rule objects; those now live
# split by category across ai_pr_reviewer/static/{security,python,
# javascript,shell}_rules.py (see StaticEngine's registry for the live
# set). Nothing in this codebase imports RULES directly -- cli.py and
# analyzer.py only ever call analyze_with_rules() -- so it's kept as an
# empty list here rather than re-exported, to avoid implying this is the
# full/live rule set.
RULES: list[Rule] = []
