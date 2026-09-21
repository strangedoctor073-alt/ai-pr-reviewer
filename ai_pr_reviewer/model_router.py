"""Provider routing.

``get_provider(cfg, context)`` is the single place that decides which
:class:`~ai_pr_reviewer.ai.provider.AIProvider` actually reviews a PR:
Claude when an API key is configured, the deterministic static analyzer
otherwise. Both satisfy the same ``analyze(context) -> AnalysisOutcome``
contract, so ``ai_pr_reviewer/orchestrator.py`` can call whichever
it gets without a branch of its own.

Model *selection* beyond that — e.g. routing a high-risk PR to a stronger
model, smaller batches, or more retries — is planned for a future version.
``classify_risk`` below only computes and surfaces a risk label today; it
does not change what gets built. Don't overbuild this.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from .ai.claude import ClaudeProvider
from .ai.provider import AIProvider
from .analyzer import AnalysisOutcome, StaticAnalyzer
from .retry import RetryPolicy

if TYPE_CHECKING:
    from .config import Config          # provided by config.py
    from .context import ReviewContext  # provided by context.py

# Simple substring hints for "this PR touches something sensitive" — kept
# intentionally crude (no repo-aware config lookup) on purpose.
_SENSITIVE_PATH_HINTS = (
    "auth", "login", "session", "password", "payment", "billing", "invoice",
    "checkout", "stripe", "db", "database", "migrat", "sql", "secret",
    "credential", "token",
)
_LARGE_PR_FILE_THRESHOLD = 30
_REVIEW_MODE_MAX_TOKENS = {
    "economy": 2_048,
    "balanced": 4_096,
    "maximum": 8_192,
    "automatic": 4_096,
}


@dataclass
class ReviewRisk:
    """A coarse risk label for the PR being reviewed. Informational only for
    now — see module docstring."""

    level: str          # "low" | "high"
    reasons: list[str]


def classify_risk(context: ReviewContext) -> ReviewRisk:
    """PR touches auth/payment/db-looking paths, or is large -> "high"."""
    files = getattr(context, "files", None) or []
    reasons: list[str] = []

    touched = sorted({
        f.path for f in files
        if any(hint in f.path.lower() for hint in _SENSITIVE_PATH_HINTS)
    })
    if touched:
        preview = ", ".join(touched[:5])
        if len(touched) > 5:
            preview += f", +{len(touched) - 5} more"
        reasons.append(f"touches auth/payment/db-looking path(s): {preview}")
    if len(files) > _LARGE_PR_FILE_THRESHOLD:
        reasons.append(f"large PR ({len(files)} files changed)")

    return ReviewRisk(level="high" if reasons else "low", reasons=reasons)


class StaticProvider:
    """Adapts the existing :class:`StaticAnalyzer` (``analyze(files)``) to
    the ``AIProvider`` contract (``analyze(context)``), so the orchestrator
    can treat it exactly like :class:`ClaudeProvider`."""

    def __init__(self, analyzer: StaticAnalyzer | None = None):
        self._analyzer = analyzer or StaticAnalyzer()
        # Same purpose as ClaudeProvider.startup_warnings — see there.
        self.startup_warnings: list[str] = []

    def analyze(self, context: ReviewContext) -> AnalysisOutcome:
        outcome = self._analyzer.analyze(context.files)
        if self.startup_warnings:
            outcome.warnings = [*self.startup_warnings, *outcome.warnings]
        return outcome


def _review_mode(cfg: Config, context: ReviewContext) -> str:
    mode = getattr(cfg, "review_mode", "automatic")
    policy = getattr(context, "project_rules", None)
    policy_mode = getattr(policy, "mode", "automatic")
    if mode == "automatic" and policy_mode in _REVIEW_MODE_MAX_TOKENS:
        mode = policy_mode
    return mode if mode in _REVIEW_MODE_MAX_TOKENS else "automatic"


def get_provider(cfg: Config, context: ReviewContext) -> AIProvider:
    """Pick the provider for this review.

    No API key configured, or ``cfg.mock`` forces it -> the deterministic
    static-analysis fallback. Otherwise -> Claude, wrapped with retry.
    """
    if getattr(cfg, "mock", False) or not getattr(cfg, "anthropic_api_key", ""):
        return StaticProvider()

    risk = classify_risk(context)
    review_mode = _review_mode(cfg, context)
    provider = ClaudeProvider(
        api_key=cfg.anthropic_api_key,
        model=cfg.model,
        max_tokens=_REVIEW_MODE_MAX_TOKENS[review_mode],
        batch_chars=getattr(cfg, "batch_chars", 80_000),
        focus_areas=getattr(cfg, "focus_areas", None),
        retry=RetryPolicy(),
    )
    if risk.level == "high":
        # Informational only: surface why the PR was flagged. The risk level
        # does not change which model or batching is used.
        provider.startup_warnings.append(f"high-risk PR ({'; '.join(risk.reasons)})")
    return provider
