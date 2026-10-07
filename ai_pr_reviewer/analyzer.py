"""Analysis backends — legacy compatibility facade (deprecated).

The composition root is :func:`ai_pr_reviewer.model_router.get_provider`,
which builds ``ReviewContext``-based providers from
:mod:`ai_pr_reviewer.ai`; the CLI pipeline runs through
:mod:`ai_pr_reviewer.orchestrator`. This module is *not* the entry point
its older docstring claimed.

What still lives here (supported until the facade is removed):

* ``StaticAnalyzer`` — the deterministic rule-backed fallback (NOT AI).
  Still production: ``model_router.StaticProvider`` adapts it, each
  ``ai/`` provider falls back to it per batch when the vendor call
  fails, and ``dashboard/app.py``'s analyze endpoint uses it. The rules
  themselves live in :mod:`ai_pr_reviewer.static`; this class is the
  adapter over them.
* ``AnalysisOutcome`` — re-exported from :mod:`ai_pr_reviewer.models`
  (the planned move landed) so ``from ..analyzer import AnalysisOutcome``
  in ``ai/`` and ``model_router`` keeps working.

Deprecated — no production callers, removal in ``v4.0.0`` (no earlier
than 2027-04-07; 6-month window per ``MIGRATION_PLAN.md`` section 7):

* ``get_analyzer(...)`` — superseded by ``model_router.get_provider``;
  ``cli.py`` never calls it.
* ``ClaudeAnalyzer`` — adapter over ``ai.claude.ClaudeProvider``; only
  tests still construct it.
* ``MockAnalyzer`` — alias of ``StaticAnalyzer``; test-only name.

Importing this module emits a ``DeprecationWarning``; so does calling
``get_analyzer``. :mod:`ai_pr_reviewer.heuristics` (the rule shim) is
deprecated the same way.
"""
from __future__ import annotations

import warnings
from dataclasses import dataclass, field

from .diff_parser import FileDiff
from .models import AnalysisOutcome, Finding
from .security import scan_prompt_injection
from .telemetry import RunTelemetry, UsageRecord

# AnalysisOutcome lives in models.py (findings/summary/mode/model/warnings plus
# engine/fallback_used/batch_count). Re-exported here so the existing
# `from ..analyzer import AnalysisOutcome` in `ai/claude.py` and
# `model_router.py` keeps working.

# V3-E06-T01 (debt D11): one DeprecationWarning per process, at first import.
# Python's default filters hide DeprecationWarning raised outside __main__, so
# CLI/dashboard runs stay quiet while pytest surfaces it once.
warnings.warn(
    "ai_pr_reviewer.analyzer is a legacy facade: get_analyzer(), "
    "ClaudeAnalyzer and MockAnalyzer are deprecated (no production callers) "
    "and the facade will be removed in v4.0.0 - no earlier than "
    "2027-04-07 (6-month window, MIGRATION_PLAN.md section 7). "
    "StaticAnalyzer and AnalysisOutcome remain usable from here until "
    "that removal.",
    DeprecationWarning,
    stacklevel=2,
)


class StaticAnalyzer:
    """Deterministic rule-backed fallback — static analysis, NOT an AI reviewer.

    Still production (unlike the deprecated entry points below): the
    ``model_router.StaticProvider`` adapter, the per-batch fallback inside
    every ``ai/`` provider, and the dashboard's analyze endpoint all run
    this. Also used when no API key is configured or ``--static`` is
    passed. Produces the same Finding contract so the posting/reporting
    pipeline can be exercised end-to-end without network access or cost.
    """

    def analyze(self, files: list[FileDiff]) -> AnalysisOutcome:
        from .heuristics import analyze_with_rules

        findings = analyze_with_rules(files)
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        pretty = ", ".join(f"{v} {k}" for k, v in sorted(
            counts.items(), key=lambda kv: -kv[1])) or "no issues"

        warnings: list[str] = []
        diff_text = "\n\n".join(f.to_diff_text() for f in files)
        for hit in scan_prompt_injection(diff_text):
            warnings.append(f"prompt-injection screen: {hit}")

        summary = (
            f"Deterministic static-analysis fallback (rule engine — not AI) "
            f"scanned {len(files)} changed file(s) and matched {len(findings)} "
            f"rule(s): {pretty}. Configure an Anthropic API key for a real "
            f"Claude review."
        )
        outcome = AnalysisOutcome(findings, summary, mode="static",
                                  model="static-rules-v1", warnings=warnings,
                                  engine="static")
        # V3-E02-T02: the rule engine spends no tokens — usage is the
        # typed "n/a" state (reporting 0 would claim a measured zero),
        # and there are no provider calls to time.
        outcome.telemetry = RunTelemetry(
            provider="static", model="static-rules-v1",
            usage=UsageRecord.na("static", "static-rules-v1"))
        return outcome


# Backward-compatible alias for existing callers/tests. Deprecated along with
# this module (test-only name — production uses StaticAnalyzer directly).
MockAnalyzer = StaticAnalyzer


@dataclass
class _LegacyFileListContext:
    """Minimal duck-typed stand-in for ``context.py``'s ``ReviewContext`` — carries
    only the two attributes ``ClaudeProvider.analyze`` reads
    (``files``, ``focus_areas``), so ``ClaudeAnalyzer`` below can keep
    accepting a raw file list for its existing callers. Not a general
    ``ReviewContext`` replacement — once every caller builds a real one via
    ``context.build_context()``, this (and ``ClaudeAnalyzer``) can go away.
    """

    files: list[FileDiff]
    focus_areas: list[str] = field(default_factory=list)


class ClaudeAnalyzer:
    """Backward-compatible adapter over
    :class:`ai_pr_reviewer.ai.claude.ClaudeProvider`.

    Deprecated: no production caller remains (the CLI pipeline goes through
    ``orchestrator`` + ``model_router.get_provider``); only
    ``tests/test_ai_provider.py`` still constructs it. It accepts a raw
    ``list[FileDiff]``, predating the ``ReviewContext`` contract, and wraps a
    minimal stand-in context so the old and new call shapes share one
    implementation of ClaudeProvider's retry/backoff and per-batch static
    fallback. Removal: ``v4.0.0`` (no earlier than 2027-04-07).
    """

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6",
                max_tokens: int = 4096, batch_chars: int = 80_000,
                focus_areas: list[str] | None = None, timeout: float = 240.0):
        from .ai.claude import ClaudeProvider

        self._provider = ClaudeProvider(
            api_key=api_key, model=model, max_tokens=max_tokens,
            batch_chars=batch_chars, focus_areas=focus_areas, timeout=timeout,
        )
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.batch_chars = batch_chars
        self.focus_areas = focus_areas or []

    def analyze(self, files: list[FileDiff]) -> AnalysisOutcome:
        context = _LegacyFileListContext(files=files, focus_areas=self.focus_areas)
        return self._provider.analyze(context)

    @property
    def total_input_tokens(self) -> int:
        return self._provider.total_input_tokens

    @property
    def total_output_tokens(self) -> int:
        return self._provider.total_output_tokens


def get_analyzer(api_key: str | None, model: str, mock: bool,
                 focus_areas: list[str] | None = None,
                 batch_chars: int = 80_000):
    """Deprecated: pick a backend (Claude when a key is available, else static).

    No production caller remains — ``cli.py`` goes through
    ``orchestrator`` and ``model_router.get_provider(cfg, context)``, which
    speaks the ``ReviewContext``-based ``AIProvider`` contract directly.
    Removal: ``v4.0.0`` (no earlier than 2027-04-07).
    """
    warnings.warn(
        "get_analyzer() is deprecated (no production callers) and will be "
        "removed in v4.0.0 - no earlier than 2027-04-07; use "
        "model_router.get_provider(cfg, context) instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    if mock or not api_key:
        return StaticAnalyzer()
    return ClaudeAnalyzer(api_key=api_key, model=model, focus_areas=focus_areas,
                          batch_chars=batch_chars)
