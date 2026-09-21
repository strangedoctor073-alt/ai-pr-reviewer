"""StaticEngine — orchestrates every static-rules module.

Wires security_rules + python_rules + javascript_rules + shell_rules +
test_rules into one RuleRegistry and runs it over a diff. Two entry points:

* ``run(files)`` — the actual engine: takes ``list[FileDiff]``, returns
  ``list[Finding]``, sorted by severity exactly like the original
  ``analyze_with_rules()``. Fully self-contained and independently
  testable.

* ``analyze(context)`` — implements the ``AIProvider`` protocol
  (``ai_pr_reviewer/ai/provider.py``) so the model router can swap
  between Claude and this engine interchangeably. Thin wrapper around
  ``run()`` that packages the result as an ``AnalysisOutcome``
  (``ai_pr_reviewer/models.py``, with ``engine``/``fallback_used``/
  ``batch_count``). Only ``context.files`` is read, so anything with a
  ``.files`` attribute satisfies this method at runtime — the real
  ``ReviewContext`` (``ai_pr_reviewer/context.py``) isn't a hard
  import-time dependency of this module. ``AnalysisOutcome`` is imported
  lazily inside the method for the same reason.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Any

from ..diff_parser import FileDiff
from ..models import SEVERITY_ORDER, Finding
from ..security import scan_prompt_injection
from . import javascript_rules, python_rules, security_rules, shell_rules, test_rules
from .registry import RuleRegistry, lang_of

if TYPE_CHECKING:  # pragma: no cover — type-checking only, not a runtime import
    from ..context import ReviewContext  # provided by context.py
    from ..models import AnalysisOutcome  # provided by models.py

_COMMENT_LINE_RE = re.compile(r"^\s*(#|//|\*|\")")  # skip obvious comment lines


def build_default_registry() -> RuleRegistry:
    """Wire every static-rules module into one registry. A plain function
    rather than a module-level singleton, so tests (or a future caller
    that wants a subset of rules) can build their own registry cheaply."""
    registry = RuleRegistry()
    for module in (security_rules, python_rules, javascript_rules, shell_rules, test_rules):
        module.register(registry)
    return registry


class StaticEngine:
    """Deterministic rule-based analysis — NOT an AI reviewer (see
    analyzer.py's StaticAnalyzer docstring for the same framing; this
    class is the V2 home for that logic — heuristics.py is now a thin
    compatibility shim around it)."""

    def __init__(self, registry: RuleRegistry | None = None) -> None:
        self.registry = registry or build_default_registry()

    def run(self, files: list[FileDiff]) -> list[Finding]:
        """Run every registered line-rule, file-rule and diff-rule over
        the diff and return the combined findings, sorted by severity
        (critical first) — the same sort ``analyze_with_rules()`` did."""
        findings: list[Finding] = []
        for fd in files:
            if fd.is_binary:
                continue
            findings.extend(self._run_line_rules(fd))
            for file_rule in self.registry.file_rules:
                findings.extend(file_rule(fd))
        for diff_rule in self.registry.diff_rules:
            findings.extend(diff_rule(files))
        findings.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
        return findings

    def _run_line_rules(self, fd: FileDiff) -> list[Finding]:
        lang = lang_of(fd.path)
        out: list[Finding] = []
        for line_no, text in fd.added_lines():
            if _COMMENT_LINE_RE.match(text):
                continue
            for rule in self.registry.line_rules:
                if rule.languages and lang not in rule.languages:
                    continue
                if rule.pattern.search(text):
                    out.append(Finding(
                        file=fd.path, line=line_no, severity=rule.severity,
                        category=rule.category, title=rule.title,
                        explanation=rule.explanation, suggestion=rule.suggestion,
                        confidence=rule.confidence, rule_id=rule.rule_id,
                    ))
        return out

    def analyze(self, context: "ReviewContext | Any") -> "AnalysisOutcome":
        """AIProvider.analyze(context) -> AnalysisOutcome. See module
        docstring — ``context`` only needs a ``.files: list[FileDiff]``
        attribute; the real ``ReviewContext``/``AnalysisOutcome`` classes
        are imported lazily, not at module load time.
        """
        from ..models import AnalysisOutcome  # provided by models.py

        files = context.files
        findings = self.run(files)

        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        pretty = ", ".join(f"{v} {k}" for k, v in sorted(
            counts.items(), key=lambda kv: -kv[1])) or "no issues"

        warnings: list[str] = []
        diff_text = "\n\n".join(fd.to_diff_text() for fd in files)
        for hit in scan_prompt_injection(diff_text):
            warnings.append(f"prompt-injection screen: {hit}")

        summary = (
            f"Deterministic static-analysis fallback (rule engine — not AI) "
            f"scanned {len(files)} changed file(s) and matched {len(findings)} "
            f"rule(s): {pretty}. Configure an Anthropic API key for a real "
            f"Claude review."
        )
        return AnalysisOutcome(
            findings=findings, summary=summary, mode="static",
            model="static-rules-v1", warnings=warnings,
            engine="static", fallback_used=False, batch_count=1,
        )
