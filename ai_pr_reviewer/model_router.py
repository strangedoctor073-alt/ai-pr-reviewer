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
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable

from .ai.claude import ClaudeProvider  # noqa: F401  (stable import path; providers are built via the registry)
from .ai.provider import AIProvider
from .analyzer import AnalysisOutcome, StaticAnalyzer
from .circuit import (CLOSED, HALF_OPEN, OPEN, CircuitBreaker,
                      DEFAULT_FAILURE_THRESHOLD, DEFAULT_RECOVERY_TIMEOUT,
                      active_registry)  # V4.0-E01-T02
from .provider_registry import (MODEL_POLICY_EXPLICIT, STATIC_BACKEND, TASK_REVIEW,
                                TASK_TYPES, ProviderRoutingError, ai_backend_names,
                                get_spec, parse_order, resolve_factory,
                                select_backend_name)
from .retry import RetryPolicy
from .telemetry import RunTelemetry, UsageRecord, event_ts

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

# The backends a provider_order may name come from the provider registry
# (``provider_registry``): ``AI_BACKENDS`` is resolved on access so it always
# reflects the registered set. "static" is deliberately absent: it is the
# deterministic final fallback, not something you opt into by listing it (use
# --mock / no API key for a static-only run).


def __getattr__(name: str):
    if name == "AI_BACKENDS":
        return ai_backend_names()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


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

    def usage_summary(self) -> UsageRecord:
        """The rule engine spends no tokens: usage is ``n/a``, not ``0``
        (V3-E02-T01 — there is nothing to count)."""
        return UsageRecord.na(self.backend, "static-rules-v1")


def _review_mode(cfg: Config, context: ReviewContext) -> str:
    mode = getattr(cfg, "review_mode", "automatic")
    policy = getattr(context, "project_rules", None)
    policy_mode = getattr(policy, "mode", "automatic")
    if mode == "automatic" and policy_mode in _REVIEW_MODE_MAX_TOKENS:
        mode = policy_mode
    return mode if mode in _REVIEW_MODE_MAX_TOKENS else "automatic"


def select_backend(cfg: Config) -> str:
    """Return the backend name this config selects, or "static".

    The selection rule (model prefix, custom endpoint, which credentials are
    present) is registry data — see ``provider_registry.select_backend_name``.
    """
    if getattr(cfg, "mock", False):
        return STATIC_BACKEND
    return select_backend_name(cfg)


# ------------------------------------------------------------------ failover (C6)

def parse_provider_order(raw: str) -> list[str]:
    """``"claude, openai"`` -> ``["claude", "openai"]``.

    Unknown names are dropped (logged, not raised: a typo in an optional
    failover list must not kill a review) and duplicates keep their first
    position, so the configured order is preserved exactly.
    """
    names, unknown = parse_order(raw)
    for part in unknown:
        log.warning("provider_order: ignoring unknown backend %r", part)
    return names


def provider_order(cfg: Config) -> list[str]:
    """AI backends to try, in order. Empty means "static only" (mock mode or
    no AI credentials at all)."""
    if getattr(cfg, "mock", False):
        return []
    explicit = parse_provider_order(getattr(cfg, "provider_order", "") or "")
    if explicit:
        return explicit
    primary = select_backend(cfg)
    return [primary] if primary in ai_backend_names() else []


def _backend_config_error(cfg: Config, backend: str,
                          task: str = TASK_REVIEW) -> str | None:
    """Why ``backend`` cannot run ``task`` with this config, or None.

    Two things are checked, both from the provider registry: the backend must
    declare the task (a capability it does not claim is never assumed), and its
    model policy must be satisfiable. Model IDs for OpenAI/Gemini turn over
    quickly and old ones get shut down, so their registry entries carry no
    default model: a stale default would silently fail every review.
    """
    spec = get_spec(backend)
    if spec is None:
        return f"unknown provider backend {backend!r}."
    if task not in spec.tasks:
        return (f"the {backend} provider cannot run the {task!r} task (it supports: "
                f"{', '.join(sorted(spec.tasks))}) \u2014 list a backend that supports "
                f"it in `provider_order`, or drop {backend!r} from it.")
    if spec.model_policy == MODEL_POLICY_EXPLICIT \
            and not (getattr(cfg, "model", "") or "").strip():
        return (f"the {backend} provider needs an explicit model id \u2014 set the "
                f"`model` input (or --model) to a model your account can call.")
    return None


def provider_config_error(cfg: Config, task: str = TASK_REVIEW) -> str | None:
    """Human-readable config error for the *first* configured backend, or None.

    The primary backend has to be able to run ``task`` or the run cannot start
    — later backends in a failover chain are optional, so an unusable one
    degrades to a runtime warning instead (see ``run_analysis``).
    """
    order = provider_order(cfg)
    if not order:
        return _static_task_error(task)
    return _backend_config_error(cfg, order[0], task)


def _static_task_error(task: str) -> str | None:
    """The static engine is the implicit backend when nothing else is
    configured; it must be able to run the task too."""
    if task not in TASK_TYPES:
        return f"unknown task {task!r}; known tasks: {', '.join(TASK_TYPES)}."
    spec = get_spec(STATIC_BACKEND)
    if spec is not None and task in spec.tasks:
        return None
    return (f"no AI backend is configured and the static rule engine cannot run the "
            f"{task!r} task \u2014 configure an AI backend (and drop --mock).")


def route_task(cfg: Config, task: str = TASK_REVIEW) -> str:
    """Backend name that should run ``task``: the first backend in
    ``provider_order`` that declares the task and is usable with this config.

    Pure routing — circuit-breaker state is the caller's concern (see
    ``get_provider``). With no AI backend configured the static engine runs the
    task if it declares it. Raises :class:`ProviderRoutingError` (a config
    error, exit 1) when nothing can: an impossible task/provider pair is never
    downgraded silently.
    """
    if task not in TASK_TYPES:
        raise ProviderRoutingError(f"unknown task {task!r}; known tasks: "
                                   f"{', '.join(TASK_TYPES)}.")
    order = provider_order(cfg)
    if not order:
        error = _static_task_error(task)
        if error:
            raise ProviderRoutingError(error)
        return STATIC_BACKEND
    problems: list[str] = []
    for backend in order:
        error = _backend_config_error(cfg, backend, task)
        if error is None:
            return backend
        problems.append(error)
    raise ProviderRoutingError(f"no configured backend can run the {task!r} task: "
                               + " ".join(problems))


# --- circuit breakers (one per backend, in-memory, process-local) ----------
_BREAKERS: dict[str, CircuitBreaker] = {}
_BREAKER_CLOCK: Callable[[], float] = time.monotonic


def breaker_for(backend: str, *,
                failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
                recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT) -> CircuitBreaker:
    """The (lazily created) breaker guarding ``backend``."""
    # V4.0-E01-T02 (C5): inside a fan-out task the breaker comes from that
    # task's private registry, never from the process-global one below.
    scoped = active_registry()
    if scoped is not None:
        return scoped.breaker_for(backend, failure_threshold=failure_threshold,
                                  recovery_timeout=recovery_timeout)
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
    spec = get_spec(backend)
    if spec is None:
        raise ValueError(f"unknown provider backend {backend!r}.")
    if not spec.ai:
        return StaticProvider()

    config_error = _backend_config_error(cfg, backend)
    if config_error:
        raise ValueError(config_error)

    model = getattr(cfg, "model", "") or ""
    review_mode = _review_mode(cfg, context)
    kwargs = {
        "api_key": (getattr(cfg, spec.credential_field, "") if spec.credential_field
                    else "") or spec.placeholder_key,
        "model": model or spec.default_model or "",
        "max_tokens": _REVIEW_MODE_MAX_TOKENS[review_mode],
        "batch_chars": getattr(cfg, "batch_chars", 80_000),
        "focus_areas": getattr(cfg, "focus_areas", None),
        "retry": RetryPolicy(),
    }
    if spec.endpoint_field:
        kwargs["base_url"] = getattr(cfg, spec.endpoint_field, "")
    provider = resolve_factory(spec)(**kwargs)

    risk = classify_risk(context)
    notes = getattr(provider, "startup_warnings", None)
    if risk.level == "high" and isinstance(notes, list):
        notes.append(f"high-risk PR ({'; '.join(risk.reasons)})")
    return provider


def get_provider(cfg: Config, context: ReviewContext, *,
                 task: str = TASK_REVIEW) -> AIProvider:
    """The provider this run starts with: first configured backend that can run
    ``task`` and whose circuit allows an attempt, else the deterministic static
    analyzer (when it can run the task too)."""
    order = provider_order(cfg)
    if not order:
        error = _static_task_error(task)
        if error:
            raise ProviderRoutingError(error)
        return StaticProvider()

    # The primary must be usable — a broken configuration is an error, not
    # something to silently fall back from.
    config_error = provider_config_error(cfg, task)
    if config_error:
        raise ProviderRoutingError(config_error)

    for backend in order:
        if _backend_config_error(cfg, backend, task) and backend != order[0]:
            continue                                  # optional: skipped at runtime
        if not breaker_for(backend).can_attempt():
            continue
        return build_provider(cfg, context, backend)
    error = _static_task_error(task)
    if error:
        raise ProviderRoutingError(f"every backend for the {task!r} task is "
                                   f"circuit-open and the fallback cannot help: {error}")
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
    # V3-E02-T03: structured telemetry events for this run — counts,
    # backend names, status classes and exception *type names* only
    # (never an exception message: it could echo a request body or a
    # key), and never a change to existing logging behavior.
    run_events: list[dict] = []
    failed_backend: str | None = None
    failure_reason = ""

    def _note_failure(backend: str, reason: str) -> None:
        nonlocal failed_backend, failure_reason
        failed_backend = backend or "provider"
        failure_reason = reason

    def _circuit_event(backend: str, before: str | None) -> None:
        """Record a breaker state transition, if one happened."""
        if not backend or before is None:
            return
        after = breaker_for(backend).state()
        if after != before:
            run_events.append({"type": "circuit", "backend": backend,
                               "from": before, "to": after, "ts": event_ts()})

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
                run_events.append({"type": "provider_error", "backend": backend,
                                   "error": type(exc).__name__,
                                   "reason": "unusable_config", "ts": event_ts()})

    last_static: AnalysisOutcome | None = None
    for backend, provider in candidates():
        # A previous attempt failed and this is a real next backend: the
        # handover itself is a first-class telemetry event.
        if failed_backend and backend:
            run_events.append({"type": "failover", "from": failed_backend,
                               "to": backend, "reason": failure_reason,
                               "ts": event_ts()})
            failed_backend = None
        is_static = isinstance(provider, StaticProvider)
        state_before = breaker_for(backend).state() \
            if (not is_static and backend) else None
        if not is_static and backend:
            if not breaker_for(backend).allow():
                continue                       # trial already claimed elsewhere
        try:
            outcome = provider.analyze(context)
        except Exception as exc:               # noqa: BLE001 — one provider's bug
            # Harvest the failed provider's own events first — its outcome
            # never materialized to carry them.
            run_events.extend(getattr(provider, "telemetry_events", None) or [])
            reason = type(exc).__name__
            run_events.append({"type": "provider_error",
                               "backend": backend or "provider",
                               "error": reason, "ts": event_ts()})
            if not is_static and backend:
                breaker_for(backend).record_failure()
                _circuit_event(backend, state_before)
            # Type name only: an exception message may echo a request body.
            warnings.append(f"{backend or 'provider'} review failed "
                            f"({reason}) — trying the next provider.")
            _note_failure(backend, reason)
            continue

        if is_static or _ai_completed(outcome):
            if not is_static and backend:
                breaker_for(backend).record_success()
                _circuit_event(backend, state_before)
            if warnings:
                outcome.warnings = [*warnings, *outcome.warnings]
            _attach_events(outcome, run_events)
            return outcome

        # AI provider, but every batch fell back to the rule engine.
        run_events.append({"type": "provider_error",
                           "backend": backend or "provider",
                           "error": "StaticFallback", "ts": event_ts()})
        if backend:
            breaker_for(backend).record_failure()
            _circuit_event(backend, state_before)
        warnings.append(f"{backend or 'provider'} could not complete an AI review "
                        f"(every batch fell back to static analysis) — trying the "
                        f"next provider.")
        _note_failure(backend, "StaticFallback")
        last_static = outcome

    if last_static is None:
        last_static = StaticProvider().analyze(context)
    if failed_backend:
        # No further backend ran — the rule engine stood in.
        run_events.append({"type": "static_fallback", "from": failed_backend,
                           "reason": failure_reason, "ts": event_ts()})
    warnings.append("No AI provider completed this review — findings come from the "
                    "deterministic static rule engine, not from an AI review.")
    last_static.warnings = [*warnings, *last_static.warnings]
    last_static.engine = "static"
    last_static.fallback_used = True
    _attach_events(last_static, run_events)
    return last_static


def _attach_events(outcome: AnalysisOutcome, events: list[dict]) -> None:
    """V3-E02-T03 — merge router-level events into the outcome's telemetry.

    Router events (failed backends' harvested retries, ``provider_error``,
    ``failover``, ``circuit`` transitions) all happened *before* the
    successful provider's own events, so they lead the list. Outcomes
    without a telemetry block (pre-V3 test doubles) gain a minimal one.
    """
    if not events:
        return
    tel = getattr(outcome, "telemetry", None)
    if tel is None:
        tel = RunTelemetry(provider=str(getattr(outcome, "mode", "") or ""),
                           model=str(getattr(outcome, "model", "") or ""))
        outcome.telemetry = tel
    tel.events = [*events, *tel.events]


# AI_BACKENDS is resolved by the module-level __getattr__ above (registry-backed),
# which static analysis cannot see.
__all__ = [  # noqa: F822
    "AI_BACKENDS", "CircuitBreaker", "ReviewRisk", "StaticProvider",
    "build_provider", "breaker_for", "classify_risk", "get_provider",
    "parse_provider_order", "provider_config_error", "provider_order",
    "reset_circuits", "route_task", "run_analysis", "select_backend",
    "CLOSED", "OPEN", "HALF_OPEN",
]
