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


def select_backend(cfg: Config) -> str:
    """Return "static" | "openai" | "gemini" | "claude" for this config."""
    if getattr(cfg, "mock", False):
        return "static"

    model = getattr(cfg, "model", "") or ""
    anthropic_key = getattr(cfg, "anthropic_api_key", "")
    openai_key = getattr(cfg, "openai_api_key", "")
    gemini_key = getattr(cfg, "gemini_api_key", "")
    openai_base_url = getattr(cfg, "openai_base_url", "")

    use_openai = (model.startswith(("gpt-", "o1", "o3", "o4")) or
                  bool(openai_base_url) or
                  (openai_key and not anthropic_key and not gemini_key))
    use_gemini = (model.startswith("gemini-") or
                  (gemini_key and not anthropic_key and not openai_key and not use_openai))
    use_claude = (model.startswith("claude-") or
                  (anthropic_key and not use_openai and not use_gemini))

    # A custom OpenAI-compatible endpoint (Ollama, vLLM, …) may need no key.
    if use_openai and (openai_key or openai_base_url):
        return "openai"
    if use_gemini and gemini_key:
        return "gemini"
    if use_claude and anthropic_key:
        return "claude"
    return "static"


def provider_config_error(cfg: Config) -> str | None:
    """Return a human-readable config error, or None if the config is usable.

    Model IDs for OpenAI/Gemini turn over quickly and old ones get shut down,
    so there is deliberately no built-in default for them: a stale default
    would silently fail every review.
    """
    backend = select_backend(cfg)
    if backend in ("openai", "gemini") and not (getattr(cfg, "model", "") or "").strip():
        return (f"the {backend} provider needs an explicit model id — set the "
                f"`model` input (or --model) to a model your account can call.")
    return None


def get_provider(cfg: Config, context: ReviewContext) -> AIProvider:
    backend = select_backend(cfg)
    if backend == "static":
        return StaticProvider()

    model = getattr(cfg, "model", "") or ""
    config_error = provider_config_error(cfg)
    if config_error:
        raise ValueError(config_error)
    review_mode = _review_mode(cfg, context)
    max_tokens = _REVIEW_MODE_MAX_TOKENS[review_mode]
    batch_chars = getattr(cfg, "batch_chars", 80_000)
    focus_areas = getattr(cfg, "focus_areas", None)
    risk = classify_risk(context)

    if backend == "openai":
        from .ai.openai import OpenAIProvider
        provider = OpenAIProvider(
            api_key=getattr(cfg, "openai_api_key", "") or "unused",
            model=model,
            max_tokens=max_tokens,
            batch_chars=batch_chars,
            focus_areas=focus_areas,
            base_url=getattr(cfg, "openai_base_url", ""),
            retry=RetryPolicy(),
        )
    elif backend == "gemini":
        from .ai.gemini import GeminiProvider
        provider = GeminiProvider(
            api_key=cfg.gemini_api_key,
            model=model,
            max_tokens=max_tokens,
            batch_chars=batch_chars,
            focus_areas=focus_areas,
            retry=RetryPolicy(),
        )
    else:
        provider = ClaudeProvider(
            api_key=cfg.anthropic_api_key,
            model=model or "claude-sonnet-4-6",
            max_tokens=max_tokens,
            batch_chars=batch_chars,
            focus_areas=focus_areas,
            retry=RetryPolicy(),
        )
    if risk.level == "high":
        provider.startup_warnings.append(f"high-risk PR ({'; '.join(risk.reasons)})")
    return provider
