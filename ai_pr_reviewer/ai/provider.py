"""AIProvider protocol.

This is the seam that lets the review engine and the orchestrator vary
independently: the orchestrator (``ai_pr_reviewer/orchestrator.py``)
only ever calls ``provider.analyze(context)``, and doesn't care
whether it got Claude, the deterministic static fallback, or — later — some
other model. Two implementations exist today:

* :class:`ai_pr_reviewer.ai.claude.ClaudeProvider` — the real AI reviewer.
* ``ai_pr_reviewer.model_router.StaticProvider`` — adapts the existing
  ``StaticAnalyzer`` to this same contract.

``model_router.get_provider(cfg, context)`` picks between them.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    # provided by context.py and models.py respectively.
    # Only needed for static type-checking — importing under TYPE_CHECKING
    # means this module never actually requires either file to exist yet.
    from ..context import ReviewContext
    from ..models import AnalysisOutcome


@runtime_checkable
class AIProvider(Protocol):
    """Anything that can turn a ``ReviewContext`` into an ``AnalysisOutcome``."""

    def analyze(self, context: ReviewContext) -> AnalysisOutcome: ...
