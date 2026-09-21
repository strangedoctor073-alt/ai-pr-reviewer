"""Deterministic static-analysis engine — the rule engine used
as a fallback when no Anthropic API key is configured. It is plain rule
matching (regex + best-effort AST checks), NOT an AI reviewer.

Entry point: :class:`ai_pr_reviewer.static.engine.StaticEngine`.
``ai_pr_reviewer.heuristics.analyze_with_rules`` is kept as a
backward-compatible wrapper around it.
"""
