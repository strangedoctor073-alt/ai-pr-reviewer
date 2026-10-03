"""Provider routing: which AI reviews a PR, and what happens when it fails.

Two layers live here:

* ``get_provider(cfg, context)`` picks the provider for this run — the
  configured backend with an API key, the deterministic static analyzer
  when there isn't one. It honours the circuit breaker, so a provider that
  has been failing is not picked again while its breaker is open.
* ``run_analysis(cfg, context, primary)`` runs the review with
  **failover**: bounded retries already happen inside each provider
  (``RetryPolicy`` around the HTTP call), and anything that survives that
  as "no AI actually reviewed" is handed to the next backend in
  ``provider_order``. If every AI backend fails, the static rule engine
  runs — and the outcome says so honestly (``engine="static"``,
  ``fallback_used=True`` plus a warning), never claiming an AI review.

Provider order is configurable (``provider_order``: comma-separated
backend names). It is only honoured for backends that are actually
configured; unusable ones are skipped with a warning instead of failing
the review. ``static`` is never listed — it is the implicit final fallback.

Model *selection* beyond that — routing a high-risk PR to a stronger
model, smaller batches, or more retries — is not implemented.
``classify_risk`` only computes and surfaces a risk label; it does not
change what gets built. Don't overbuild this.
"""
from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from .ai.claude import ClaudeProvider
from .ai.provider import AIProvider
from .analyzer import AnalysisOutcome, StaticAnalyzer
from .circuit import (CLOSED, HALF_OPEN, OPEN, CircuitBreaker,
                      DEFAULT_FAILURE_THRESHOLD, DEFAULT_RECOVERY_TIMEOUT)
from .retry import RetryPolicy

if TYPE_CHECKING:
    from .config import Config          # provided by config.py
    from .context import ReviewContext  # provided by context.py

log = logging.getLogger(__name__)

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

# AI backends a provider_order may name. "static" is deliberately absent:
# it is the deterministic final fallback, not something you opt into by
# listing it (use --mock / no API key for a static-only run).
AI_BACKENDS = ("claude", "openai", "gemini")


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

    backend = "static"

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


# ------------------------------------------------------------------ failover (C6)

_ORDER_SPLIT_RE = re.compile(r"[,\s]+")


def parse_provider_order(raw: str) -> list[str]:
    """``"claude, openai"`` -> ``["claude", "openai"]``.

    Unknown names are dropped (logged, not raised: a typo in an optional
    failover list must not kill a review) and duplicates keep their first
    position, so the configured order is preserved exactly.
    """
    out: list[str] = []
    for part in _ORDER_SPLIT_RE.split(raw or ""):
        name = part.strip().lower()
        if not name or name == "static":
            continue
        if name not in AI_BACKENDS:
            log.warning("provider_order: ignoring unknown backend %r", part)
            continue
        if name not in out:
            out.append(name)
    return out


def provider_order(cfg: Config) -> list[str]:
    """AI backends to try, in order. Empty means "static only" (mock mode or
    no AI credentials at all)."""
    if getattr(cfg, "mock", False):
        return []
    explicit = parse_provider_order(getattr(cfg, "provider_order", "") or "")
    if explicit:
        return explicit
    primary = select_backend(cfg)
    return [primary] if primary in AI_BACKENDS else []


def _backend_config_error(cfg: Config, backend: str) -> str | None:
    """Why ``backend`` cannot run with this config, or None.

    Model IDs for OpenAI/Gemini turn over quickly and old ones get shut
    down, so there is deliberately no built-in default for them: a stale
    default would silently fail every review.
    """
    if backend in ("openai", "gemini") and not (getattr(cfg, "model", "") or "").strip():
        return (f"the {backend} provider needs an explicit model id — set the "
                f"`model` input (or --model) to a model your account can call.")
    return None


def provider_config_error(cfg: Config) -> str | None:
    """Human-readable config error for the *first* configured backend, or None.

    The primary backend has to be usable or the run cannot start — later
    backends in a failover chain are optional, so an unusable one degrades
    to a runtime warning instead (see ``run_analysis``).
    """
    order = provider_order(cfg)
    if not order:
        return None
    return _backend_config_error(cfg, order[0])


# --- circuit breakers (one per backend, in-memory, process-local) ----------
_BREAKERS: dict[str, CircuitBreaker] = {}
_BREAKER_CLOCK: Callable[[], float] = time.monotonic


def breaker_for(backend: str, *,
                failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
                recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT) -> CircuitBreaker:
    """The (lazily created) breaker guarding ``backend``."""
    breaker = _BREAKERS.get(backend)
    if breaker is None:
        breaker = CircuitBreaker(failure_threshold=failure_threshold,
                                 recovery_timeout=recovery_timeout,
                                 clock=_BREAKER_CLOCK)
        _BREAKERS[backend] = breaker
    return breaker


def reset_circuits(*, clock: Callable[[], float] = time.monotonic) -> None:
    """Drop all breaker state (and adopt ``clock`` for new breakers).

    Tests use this to start from a closed circuit and to drive recovery
    with a fake clock instead of waiting out ``recovery_timeout``.
    """
    _BREAKERS.clear()
    global _BREAKER_CLOCK
    _BREAKER_CLOCK = clock


def build_provider(cfg: Config, context: ReviewContext, backend: str) -> AIProvider:
    """Construct the provider for one backend (may raise ``ValueError`` for
    a bad configuration — callers decide whether that is fatal)."""
    if backend == "static":
        return StaticProvider()

    config_error = _backend_config_error(cfg, backend)
    if config_error:
        raise ValueError(config_error)

    model = getattr(cfg, "model", "") or ""
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


def get_provider(cfg: Config, context: ReviewContext) -> AIProvider:
    """The provider this run starts with: first configured backend whose
    circuit allows an attempt, else the deterministic static analyzer."""
    order = provider_order(cfg)
    if not order:
        return StaticProvider()

    # The primary must be usable — a broken configuration is an error, not
    # something to silently fall back from.
    config_error = provider_config_error(cfg)
    if config_error:
        raise ValueError(config_error)

    for backend in order:
        if _backend_config_error(cfg, backend) and backend != order[0]:
            continue                                  # optional: skipped at runtime
        if not breaker_for(backend).can_attempt():
            continue
        return build_provider(cfg, context, backend)
    return StaticProvider()       # every AI backend is circuit-open right now


def _ai_completed(outcome: AnalysisOutcome) -> bool:
    """Did an AI backend actually contribute, or was it pure static fallback?

    Providers report ``engine="static"`` when every batch fell back to the
    rule engine — that is a provider failure for failover purposes, not a
    review. (``StaticProvider`` is handled by the caller before this.)
    """
    return str(getattr(outcome, "engine", "") or "") != "static"


def run_analysis(cfg: Config, context: ReviewContext,
                 primary: AIProvider | None = None) -> AnalysisOutcome:
    """Analyze with failover, circuit breakers and an honest outcome.

    ``primary`` is whatever ``get_provider`` already chose (the orchestrator
    passes it in so it stays the first attempt, and test doubles keep
    working). Order of operations:

    1. skip backends whose breaker is open (warned once, up front);
    2. run ``primary`` — its provider already retries transient HTTP
       failures internally with bounded exponential backoff;
    3. on a *permanent* failure or an all-static outcome, record the
       failure and try the next configured backend;
    4. if nothing completed, run the deterministic static engine and say so
       in the outcome. A static result is never labelled an AI review.
    """
    if primary is None:
        primary = get_provider(cfg, context)

    order = provider_order(cfg)
    primary_backend = str(getattr(primary, "backend", "") or "")
    warnings: list[str] = []

    for backend in order:
        if not breaker_for(backend).can_attempt():
            warnings.append(f"{backend}: circuit open after repeated failures — "
                            f"skipped for this review.")

    rest: list[str] = []
    if primary_backend and primary_backend != "static":
        rest = [b for b in order
                if b != primary_backend and breaker_for(b).can_attempt()]

    def candidates():
        yield primary_backend, primary
        for backend in rest:
            try:
                yield backend, build_provider(cfg, context, backend)
            except ValueError as exc:
                # A *secondary* backend with a bad config is skipped, not fatal.
                warnings.append(f"{backend}: unavailable ({exc}) — "
                                f"skipped for this review.")

    last_static: AnalysisOutcome | None = None
    for backend, provider in candidates():
        is_static = isinstance(provider, StaticProvider)
        if not is_static and backend:
            if not breaker_for(backend).allow():
                continue                       # trial already claimed elsewhere
        try:
            outcome = provider.analyze(context)
        except Exception as exc:               # noqa: BLE001 — one provider's bug
            if not is_static and backend:
                breaker_for(backend).record_failure()
            # Type name only: an exception message may echo a request body.
            warnings.append(f"{backend or 'provider'} review failed "
                            f"({type(exc).__name__}) — trying the next provider.")
            continue

        if is_static or _ai_completed(outcome):
            if not is_static and backend:
                breaker_for(backend).record_success()
            if warnings:
                outcome.warnings = [*warnings, *outcome.warnings]
            return outcome

        # AI provider, but every batch fell back to the rule engine.
        if backend:
            breaker_for(backend).record_failure()
        warnings.append(f"{backend or 'provider'} could not complete an AI review "
                        f"(every batch fell back to static analysis) — trying the "
                        f"next provider.")
        last_static = outcome

    if last_static is None:
        last_static = StaticProvider().analyze(context)
    warnings.append("No AI provider completed this review — findings come from the "
                    "deterministic static rule engine, not from an AI review.")
    last_static.warnings = [*warnings, *last_static.warnings]
    last_static.engine = "static"
    last_static.fallback_used = True
    return last_static


__all__ = [
    "AI_BACKENDS", "CircuitBreaker", "ReviewRisk", "StaticProvider",
    "build_provider", "breaker_for", "classify_risk", "get_provider",
    "parse_provider_order", "provider_config_error", "provider_order",
    "reset_circuits", "run_analysis", "select_backend",
    "CLOSED", "OPEN", "HALF_OPEN",
]
