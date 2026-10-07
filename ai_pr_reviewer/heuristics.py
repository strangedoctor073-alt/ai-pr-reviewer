"""Backward-compatible facade — deprecated (removal in v4.0.0).

The heuristic rule engine described in this module's old docstring now
lives in :mod:`ai_pr_reviewer.static` (registry + per-language rule
modules + AST-based Python checks). This file is kept as a thin shim so
existing imports keep working unchanged:

    from ai_pr_reviewer.heuristics import analyze_with_rules, Rule

See ai_pr_reviewer/static/engine.py for the real implementation. New code
should import :mod:`ai_pr_reviewer.static` directly. The shim's removal
is scheduled for ``v4.0.0`` — no earlier than 2027-04-07 (6-month
window, ``MIGRATION_PLAN.md`` section 7). Importing this module emits a
``DeprecationWarning``; its one production caller is
``analyzer.StaticAnalyzer`` (lazy import inside ``analyze()``).
"""
from __future__ import annotations

import warnings

from .diff_parser import FileDiff
from .models import Finding
from .static.engine import StaticEngine as _Engine
from .static.registry import Rule  # noqa: F401 -- re-exported for compatibility

_default_engine = _Engine()

# V3-E06-T01 (debt D11): fires once per process at first import; hidden by
# Python's default warning filters outside __main__, surfaced once by pytest.
warnings.warn(
    "ai_pr_reviewer.heuristics is a deprecated compatibility shim over "
    "ai_pr_reviewer.static (removal in v4.0.0 - no earlier than "
    "2027-04-07, MIGRATION_PLAN.md section 7); import "
    "ai_pr_reviewer.static for new code.",
    DeprecationWarning,
    stacklevel=2,
)


def analyze_with_rules(files: list[FileDiff]) -> list[Finding]:
    """Run every static rule over every ADDED line (and, for Python files,
    the new AST-based checks) of the diff. Backward-compatible wrapper --
    behavior/output shape unchanged, implementation moved to
    ai_pr_reviewer.static.engine.StaticEngine."""
    return _default_engine.run(files)


# `RULES` used to be a flat list of ~21 regex Rule objects; those now live
# split by category across ai_pr_reviewer/static/{security,python,
# javascript,shell}_rules.py (see StaticEngine's registry for the live
# set). Nothing in this codebase imports RULES directly -- analyzer.py's
# StaticAnalyzer is the only production caller of analyze_with_rules()
# (tests import it directly too) -- so it's kept as an empty list here
# rather than re-exported, to avoid implying this is the full/live rule
# set.
RULES: list[Rule] = []
