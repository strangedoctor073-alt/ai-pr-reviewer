"""Reusable retry/backoff policy.

Used today by :class:`ai_pr_reviewer.ai.claude.ClaudeProvider` around its
Anthropic API calls. The shape is deliberately generic — status code and/or
raised exception in, retry-or-not out — so the GitHub client and dashboard
client can adopt the same policy later without needing a different
type.

``call()`` handles two ways a wrapped call can fail:

1. It raises. This covers network-level problems (timeouts, connection
   errors) as well as libraries that raise on a bad status
   (``resp.raise_for_status()`` -> ``httpx.HTTPStatusError``, which carries
   the status code on ``exc.response.status_code``).
2. It returns an HTTP-response-*like* object whose ``status_code`` says the
   call failed, without raising — e.g. a raw ``httpx.Client.post(...)``
   result, which is exactly what this module's only current caller wraps.
   Not every retryable failure raises, so ``call()`` checks both.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass

# Exception class names (checked by name, not isinstance, so this module has
# no hard dependency on httpx being importable) that mean "the network/
# transport misbehaved" as opposed to "the server told us no".
_NETWORK_EXCEPTION_NAMES = (
    "ConnectError", "ConnectTimeout", "ReadTimeout", "WriteTimeout",
    "PoolTimeout", "TimeoutException", "NetworkError", "RemoteProtocolError",
)

_PERMANENT_STATUS_CODES = {400, 401, 403, 404, 422}
_RETRYABLE_STATUS_CODES = {408, 409, 425, 429, 500, 502, 503, 504}


@dataclass
class RetryPolicy:
    """Exponential backoff with jitter.

    ``is_retryable`` decides *whether* a given failure is worth retrying;
    ``call`` actually runs a function under that policy, sleeping between
    attempts and returning/re-raising the last failure once attempts are
    exhausted.
    """

    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 30.0
    jitter: float = 0.25  # fraction of the computed delay to randomize by

    def is_retryable(self, status_code: int | None, exc: Exception | None) -> bool:
        """True if this failure is worth retrying.

        - 401/403 (auth) and other 4xx client errors are permanent — the
          next attempt will fail identically, so retrying just burns time
          and, for a paid API, money.
        - 429 and 5xx are transient server/rate-limit conditions — retry.
        - Network-level exceptions (timeouts, connection errors) are
          retried even with no status code, since the request may not have
          reached the server at all.
        - Anything else (malformed-response ValueErrors, etc.) is treated
          as permanent: retrying won't change the outcome.
        """
        if status_code is not None:
            if status_code in _RETRYABLE_STATUS_CODES:
                return True
            if status_code in _PERMANENT_STATUS_CODES:
                return False
            return 500 <= status_code < 600

        if exc is not None:
            # An exception that itself carries an HTTP response (e.g.
            # httpx.HTTPStatusError from resp.raise_for_status()) — classify
            # by its status code rather than guessing from the exception type.
            code = getattr(getattr(exc, "response", None), "status_code", None)
            if code is not None:
                return self.is_retryable(code, None)

            try:
                import httpx

                if isinstance(exc, (httpx.TimeoutException, httpx.NetworkError,
                                    httpx.RemoteProtocolError)):
                    return True
            except ImportError:
                pass

            return type(exc).__name__ in _NETWORK_EXCEPTION_NAMES

        return False

    def _delay_for(self, attempt: int) -> float:
        """Delay before the *next* attempt. ``attempt`` is 1-based (the
        first retry follows attempt 1)."""
        raw = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        spread = raw * self.jitter
        return max(0.0, raw + random.uniform(-spread, spread))

    def call(self, fn, *args, **kwargs):
        """Run ``fn(*args, **kwargs)``, retrying on retryable failures.

        Returns ``fn``'s result (retrying first if it looks like a
        retryable failure — see the module docstring). If every attempt
        raises, the last exception is re-raised; if every attempt returns a
        failing response, the last response is returned as-is so the
        caller's own error handling (e.g. ``resp.raise_for_status()``)
        still fires.
        """
        last_exc: Exception | None = None
        last_result = None

        for attempt in range(1, self.max_attempts + 1):
            try:
                result = fn(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 — reclassified just below
                last_exc = exc
                status_code = getattr(getattr(exc, "response", None),
                                      "status_code", None)
                if attempt >= self.max_attempts or not self.is_retryable(status_code, exc):
                    raise
                time.sleep(self._delay_for(attempt))
                continue

            status_code = getattr(result, "status_code", None)
            if not self.is_retryable(status_code, None):
                return result
            last_result = result
            if attempt >= self.max_attempts:
                return result
            time.sleep(self._delay_for(attempt))

        if last_exc is not None:  # pragma: no cover — defensive, loop always returns/raises
            raise last_exc
        return last_result  # pragma: no cover
