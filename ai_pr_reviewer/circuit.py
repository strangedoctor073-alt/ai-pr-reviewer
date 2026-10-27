"""Circuit breaker for provider failover (V3 C6).

A provider that is down should not be re-tried on every batch (or every
review of the same process): each attempt costs a timeout and a warning.
The breaker turns "keep trying" into three explicit states:

``closed``
    normal — attempts go through.
``open``
    failing past the threshold — skip this provider for ``recovery_timeout``
    seconds instead of paying for another timeout.
``half-open``
    the cool-down elapsed — allow exactly one controlled recovery attempt;
    success closes the breaker, failure re-opens it with a fresh cool-down.

In-memory and process-local on purpose: no new database, no external
service. State is per-provider, so one provider being down never blocks
another. All timing goes through an injectable clock, which is what makes
the transitions deterministic (and instant) to test.
"""
from __future__ import annotations

import contextlib
import contextvars
import threading
import time
from typing import Callable, Iterator

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half-open"

DEFAULT_FAILURE_THRESHOLD = 2
DEFAULT_RECOVERY_TIMEOUT = 60.0


class CircuitBreaker:
    """Bounded, deterministic, in-process provider health tracking."""

    def __init__(self, failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
                 recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT,
                 clock: Callable[[], float] = time.monotonic):
        self.failure_threshold = max(1, int(failure_threshold))
        self.recovery_timeout = max(0.0, float(recovery_timeout))
        self._clock = clock
        self._state = CLOSED
        self._failures = 0
        self._opened_at = 0.0
        self._trial_used = False
        # V4.0-E01-T02: transitions are check-then-act (``allow`` reads the
        # state, then claims the half-open trial); re-entrant because
        # ``record_failure`` consults ``state``. Single-threaded behavior is
        # unchanged - the lock only matters once a breaker is shared.
        self._lock = threading.RLock()

    # ------------------------------------------------------------- inspection
    def state(self) -> str:
        """Current state. ``OPEN`` flips to ``HALF_OPEN`` once the cool-down
        has elapsed — a read never mutates the breaker."""
        if self._state == CLOSED:
            return CLOSED
        if self._clock() - self._opened_at >= self.recovery_timeout:
            return HALF_OPEN
        return OPEN

    @property
    def failures(self) -> int:
        return self._failures

    def allow(self) -> bool:
        """May an attempt run right now?

        Half-open admits one attempt per cool-down window; the caller
        reports the outcome with :meth:`record_success` /
        :meth:`record_failure`.
        """
        with self._lock:
            state = self.state()
            if state == OPEN:
                return False
            if state == HALF_OPEN:
                if self._trial_used:
                    return False
                self._trial_used = True
                return True
            return True

    def can_attempt(self) -> bool:
        """:meth:`allow` without claiming the half-open trial.

        For callers that only *select* a provider (``get_provider``); the
        code that actually runs the attempt uses ``allow()`` so exactly one
        recovery attempt happens per cool-down window.
        """
        with self._lock:
            state = self.state()
            if state == OPEN:
                return False
            if state == HALF_OPEN:
                return not self._trial_used
            return True

    # ------------------------------------------------------------- reporting
    def record_success(self) -> None:
        with self._lock:
            self._state = CLOSED
            self._failures = 0
            self._trial_used = False

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._trial_used = False
            # A failure while half-open (or once the threshold is reached)
            # opens the breaker with a fresh cool-down window.
            if self.state() == HALF_OPEN or self._failures >= self.failure_threshold:
                self._state = OPEN
                self._opened_at = self._clock()

    def reset(self) -> None:
        with self._lock:
            self._state = CLOSED
            self._failures = 0
            self._trial_used = False


# ======================================================== V4.0-E01-T02 (C5)
# Per-task breaker scope. The process-global registry in ``model_router``
# assumed one sequential caller; under fan-out two tasks would share one
# half-open trial and one failure count, so one task's outage would silently
# starve (or falsely heal) another. A task now owns a private registry, made
# visible to ``model_router.breaker_for`` through a context variable - the
# scope travels with the task's own context copy and cannot leak to siblings
# or to the submitting thread.

class BreakerRegistry:
    """Breakers keyed by backend for ONE scope (one fan-out task).

    Lock-guarded so a scope may still be touched from more than one thread
    (a provider that retries on a helper thread, say). Lookup creates
    lazily, exactly like the process-global registry it mirrors.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._breakers: dict[str, CircuitBreaker] = {}

    def breaker_for(self, backend: str, *,
                    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD,
                    recovery_timeout: float = DEFAULT_RECOVERY_TIMEOUT
                    ) -> CircuitBreaker:
        with self._lock:
            breaker = self._breakers.get(backend)
            if breaker is None:
                breaker = CircuitBreaker(failure_threshold=failure_threshold,
                                         recovery_timeout=recovery_timeout,
                                         clock=self._clock)
                self._breakers[backend] = breaker
            return breaker

    def states(self) -> dict[str, str]:
        """``{backend: state}`` sorted by backend - deterministic, for tests
        and diagnostics."""
        with self._lock:
            items = sorted(self._breakers.items())
        return {name: b.state() for name, b in items}

    def reset(self) -> None:
        with self._lock:
            self._breakers.clear()


_ACTIVE: contextvars.ContextVar[BreakerRegistry | None] = contextvars.ContextVar(
    "ai_pr_reviewer_active_breakers", default=None)


def active_registry() -> BreakerRegistry | None:
    """The registry scoped to the current task, or ``None`` outside any task
    (the process-global behavior, unchanged)."""
    return _ACTIVE.get()


@contextlib.contextmanager
def scoped_breakers(registry: BreakerRegistry) -> Iterator[BreakerRegistry]:
    """Make ``registry`` the breaker scope for the enclosed code (and only
    this context)."""
    token = _ACTIVE.set(registry)
    try:
        yield registry
    finally:
        _ACTIVE.reset(token)
