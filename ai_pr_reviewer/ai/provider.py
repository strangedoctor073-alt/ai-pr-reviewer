"""AIProvider protocol.

This is the seam that lets the review engine and the orchestrator vary
independently: the orchestrator (``ai_pr_reviewer/orchestrator.py``)
only ever calls ``provider.analyze(context)``, and doesn't care
whether it got Claude, the deterministic static fallback, or — later — some
other model. Two implementations exist today:

* :class:`ai_pr_reviewer.ai.claude.ClaudeProvider` — the real AI reviewer.
* ``ai_pr_reviewer.model_router.StaticProvider`` — adapts the existing
  ``StaticAnalyzer`` to this same contract.

``model_router.get_provider(cfg, context)`` picks between them. Which backends
exist, what each can be asked to do and how each is built is declared in
``ai_pr_reviewer.provider_registry`` (ADR-007); a backend's capabilities are
registry data, not methods on the provider.

V4.0-E02 adds the *optional* instance-side declaration ADR-007 allows: a
provider may expose ``capabilities() -> frozenset[str]`` and
:func:`capabilities_of` will read it. It is deliberately not a member of the
``AIProvider`` Protocol — ``runtime_checkable`` ``isinstance`` checks would
turn an optional declaration into a required method and break every existing
implementation (notably ``StaticProvider``). Routing keeps consulting the
registry; a declared ``capabilities()`` must agree with it (conformance test).
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


def capabilities_of(provider: object) -> frozenset[str] | None:
    """Task types ``provider`` declares, or ``None`` when it declares none.

    The optional ``capabilities()`` seam (V4.0-E02-T02, ADR-007): a
    provider — in-tree or a test fake — may declare the registry task types
    it can run without registering, and callers can tell "declared nothing"
    (``None``) apart from "declares no tasks" (empty set). The registry
    (``provider_registry.ProviderSpec.tasks``) remains the single source
    routing consults; this helper only reads a provider's own declaration.

    A non-iterable return is a programming error in the provider and raises
    rather than silently degrading to "undeclared".
    """
    declare = getattr(provider, "capabilities", None)
    if not callable(declare):
        return None
    declared = declare()
    if declared is None:
        return None
    if isinstance(declared, (str, bytes)) or not hasattr(declared, "__iter__"):
        raise TypeError(
            f"capabilities() must return an iterable of task type strings, "
            f"got {type(declared).__name__}")
    return frozenset(str(task) for task in declared)
