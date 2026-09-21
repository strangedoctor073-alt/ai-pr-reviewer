"""Analysis backends — compatibility layer (V2).

The real implementations now live elsewhere:

* Claude-backed review    -> :mod:`ai_pr_reviewer.ai.claude` (``ClaudeProvider``),
  which implements the new :class:`ai_pr_reviewer.ai.provider.AIProvider`
  contract: ``analyze(context: ReviewContext) -> AnalysisOutcome``.
* Provider selection      -> :mod:`ai_pr_reviewer.model_router` (``get_provider``).

This module now exists to keep the OLD, still-in-use entry points working
completely unchanged:

* ``get_analyzer(api_key, model, mock, ...)`` — used today by ``cli.py``,
  which still calls ``analyzer.analyze(files)`` with a raw ``list[FileDiff]``
  (the orchestrator that will call the new context-based providers directly
  hasn't landed yet). ``ClaudeAnalyzer`` below is now a thin adapter around
  ``ClaudeProvider`` so the retry/per-batch-fallback behavior added there
  applies here too, without duplicating any logic.
* ``StaticAnalyzer`` / ``MockAnalyzer`` — unchanged; still the deterministic
  rule-based fallback (NOT AI). Used directly by ``tests/test_pipeline.py``
  and by ``get_analyzer`` when no API key is configured. Its rules now
  live in the registry under ``ai_pr_reviewer/static/``; this file is a
  compatibility facade over it.
* ``AnalysisOutcome`` — the shared contract has this moving into
  ``models.py``, gaining ``engine`` / ``fallback_used`` /
  ``batch_count``. It stays defined here, with those three fields already
  added, until that move lands — so nothing importing it from either
  location breaks during the transition.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .diff_parser import FileDiff
from .models import AnalysisOutcome, Finding
from .security import scan_prompt_injection

# AnalysisOutcome lives in models.py (findings/summary/mode/model/warnings plus
# engine/fallback_used/batch_count). Re-exported here so the existing
# `from ..analyzer import AnalysisOutcome` in `ai/claude.py` and
# `model_router.py` keeps working.


class StaticAnalyzer:
    """Deterministic rule-based fallback — static analysis, NOT an AI reviewer.

    Used when no API key is configured or ``--static`` is passed. Produces the
    same Finding contract so the posting/reporting pipeline can be exercised
    end-to-end without network access or cost.
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
        return AnalysisOutcome(findings, summary, mode="static",
                               model="static-rules-v1", warnings=warnings,
                               engine="static")


# Backward-compatible alias for existing callers/tests.
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

    Existing callers (currently just ``cli.py``) call ``.analyze(files)``
    with a raw ``list[FileDiff]``, predating the ``ReviewContext`` contract.
    Rather than duplicate ``ClaudeProvider``'s retry/fallback logic here,
    this wraps a minimal stand-in context so old and new call sites share
    one implementation — meaning the CLI now gets retry/backoff and
    per-batch static fallback for free, with no change to how it calls this
    class.
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
    """Pick the analyzer backend: Claude when a key is available, otherwise
    the deterministic static-analysis fallback.

    Kept exactly as before for ``cli.py``. New code (the V2 orchestrator)
    should use ``model_router.get_provider(cfg, context)`` instead, which
    speaks the ``ReviewContext``-based ``AIProvider`` contract directly.
    """
    if mock or not api_key:
        return StaticAnalyzer()
    return ClaudeAnalyzer(api_key=api_key, model=model, focus_areas=focus_areas,
                          batch_chars=batch_chars)
