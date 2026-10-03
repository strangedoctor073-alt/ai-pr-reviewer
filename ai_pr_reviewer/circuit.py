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

import time
from typing import Callable

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
        state = self.state()
        if state == OPEN:
            return False
        if state == HALF_OPEN:
            return not self._trial_used
        return True

    # ------------------------------------------------------------- reporting
    def record_success(self) -> None:
        self._state = CLOSED
        self._failures = 0
        self._trial_used = False

    def record_failure(self) -> None:
        self._failures += 1
        self._trial_used = False
        # A failure while half-open (or once the threshold is reached)
        # opens the breaker with a fresh cool-down window.
        if self.state() == HALF_OPEN or self._failures >= self.failure_threshold:
            self._state = OPEN
            self._opened_at = self._clock()

    def reset(self) -> None:
        self._state = CLOSED
        self._failures = 0
        self._trial_used = False
