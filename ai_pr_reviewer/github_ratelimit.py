"""GitHub REST rate-limit discipline (V4.6-E01-T01, the family's C8 slot).

The single implementation point for ``X-RateLimit`` awareness. Every later
feature that polls the GitHub API (V4.4-E04 issue linkage, V4.6-E03 release
reads, anything else) reuses :class:`RateLimiter` through
``GitHubClient.get_json``; none may grow a second, per-feature rate limiter.

Deliberately a **leaf**: stdlib only, no import from the rest of the engine,
so ``github_client`` can import it at module level without a cycle. It makes
*decisions* (wait, give up, count); it never performs HTTP and never raises a
``GitHubError`` — the client translates :class:`RateLimitBlocked` into
``GitHubRateLimited``.

What it does
------------
* Reads ``X-RateLimit-Limit/Remaining/Reset/Resource`` and ``Retry-After``
  from every response it is shown (:meth:`RateLimiter.observe`).
* Before the next request (:meth:`RateLimiter.before_request`) it keeps a
  **reserve** of requests in hand: the review's own calls (diff, comments)
  share the same quota, so optional polling must never spend the last of it.
* Recognizes throttling responses: HTTP 429, and HTTP 403 only when it
  carries a rate-limit signature (``Remaining: 0``, a ``Retry-After`` header,
  or GitHub's documented secondary-limit message). A bare 403 is an
  authorization failure and is **not** a throttle — callers keep seeing the
  same error they always did.
* Waits only inside hard bounds (``max_wait_seconds`` per wait,
  ``max_total_wait_seconds`` per limiter, ``max_requests`` per limiter). When
  the honest answer is "too long to wait" it raises
  :class:`RateLimitBlocked`; callers degrade with a label, they never hang a
  review.

Determinism: the clock and the sleep function are injectable and no jitter is
applied, so tests never sleep and never flake.

One limiter instance is meant to live for one review run (that is what makes
``max_requests`` a per-run budget); it is not thread-safe by design — the
engine issues GitHub reads sequentially.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from typing import Callable, Mapping

# ----------------------------------------------------------------- headers
HEADER_LIMIT = "x-ratelimit-limit"
HEADER_REMAINING = "x-ratelimit-remaining"
HEADER_RESET = "x-ratelimit-reset"
HEADER_RESOURCE = "x-ratelimit-resource"
HEADER_RETRY_AFTER = "retry-after"

#: GitHub's documented wording for secondary (abuse) limits on a 403.
_SECONDARY_MARKERS = ("secondary rate limit", "abuse detection")
#: Only this much of a 403 body is inspected for the markers above.
_BODY_SCAN_CHARS = 2_000
#: Safety margin added to a computed wait so we resume just *after* the reset.
_RESET_MARGIN_SECONDS = 1.0

# -------------------------------------------------------- block reasons
REASON_PRIMARY = "primary"          # quota (nearly) exhausted until reset
REASON_SECONDARY = "secondary"      # abuse/secondary limit, Retry-After
REASON_REQUEST_BUDGET = "request_budget"
REASON_WAIT_BUDGET = "wait_budget"


@dataclass(frozen=True)
class RateLimitPolicy:
    """Bounds for one limiter (one review run). All values are PROPOSED
    baselines — see the V4.6 plan's decision list — and every one is a named,
    importable constant so tuning is visible."""

    #: Requests kept in hand for the review's own calls.
    reserve: int = 10
    #: Longest single sleep. A longer honest wait raises RateLimitBlocked.
    max_wait_seconds: float = 60.0
    #: Cumulative sleep allowed across the limiter's lifetime.
    max_total_wait_seconds: float = 120.0
    #: Times one request may be re-sent after a throttling response.
    max_throttle_retries: int = 2
    #: Wait used for a secondary limit that sent no ``Retry-After``.
    secondary_default_wait: float = 60.0
    #: Hard per-run request budget across everything routed through here.
    max_requests: int = 200


DEFAULT_POLICY = RateLimitPolicy()


@dataclass(frozen=True)
class RateLimitSnapshot:
    """The last quota state GitHub reported. ``None`` fields = not reported."""

    limit: int | None = None
    remaining: int | None = None
    reset_at: float | None = None       # epoch seconds
    resource: str = ""


@dataclass(frozen=True)
class Throttle:
    """A response that GitHub refused because of a rate limit."""

    kind: str            # REASON_PRIMARY | REASON_SECONDARY
    wait_seconds: float  # how long GitHub (or our default) says to wait


class RateLimitBlocked(Exception):
    """Raised instead of sleeping when waiting is not acceptable.

    Not a ``GitHubError`` (this module is a leaf); ``GitHubClient`` converts
    it to ``GitHubRateLimited`` carrying the same ``reason``/``retry_after``.
    """

    def __init__(self, reason: str, retry_after: float = 0.0):
        super().__init__(f"GitHub rate limit: {reason} "
                         f"(retry after ~{int(max(0.0, retry_after))}s)")
        self.reason = reason
        self.retry_after = max(0.0, float(retry_after))


# ----------------------------------------------------------------- parsing
def _lower_headers(headers: Mapping | None) -> dict[str, str]:
    """Case-insensitive view; tolerates httpx.Headers, dicts and ``None``."""
    out: dict[str, str] = {}
    if not headers:
        return out
    try:
        items = headers.items()
    except AttributeError:
        return out
    for key, value in items:
        out[str(key).lower()] = str(value)
    return out


def _to_int(value) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def _to_epoch(value) -> float | None:
    number = _to_int(value)
    return float(number) if number is not None else None


def _retry_after_seconds(value, now: float) -> float | None:
    """``Retry-After`` as seconds: delta-seconds or an HTTP-date."""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    seconds = _to_int(text)
    if seconds is not None:
        return float(seconds)
    try:
        moment = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    return max(0.0, moment.timestamp() - now)


def _clean_resource(value) -> str:
    text = "".join(ch for ch in str(value or "") if ch.isalnum() or ch in "_-")
    return text[:32]


# ----------------------------------------------------------------- limiter
class RateLimiter:
    """Stateful, deterministic rate-limit bookkeeping for one run."""

    def __init__(self, policy: RateLimitPolicy | None = None, *,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep):
        self.policy = policy or DEFAULT_POLICY
        self._clock = clock
        self._sleep = sleep
        self._snapshot = RateLimitSnapshot()
        self._blocked_until = 0.0      # epoch; secondary-limit hold-off
        self._requests = 0
        self._throttled = 0
        self._waited = 0.0

    # ---------------------------------------------------------- accessors
    def snapshot(self) -> RateLimitSnapshot:
        return self._snapshot

    def stats(self) -> dict:
        """Counts only (ints/floats/short strings) — safe for telemetry and
        reports; never echoes a header value verbatim."""
        snap = self._snapshot
        return {
            "requests": self._requests,
            "throttled": self._throttled,
            "waited_seconds": round(self._waited, 3),
            "limit": snap.limit,
            "remaining": snap.remaining,
            "reset_at": snap.reset_at,
            "resource": snap.resource,
        }

    # -------------------------------------------------------------- waiting
    def _bounded_sleep(self, wait: float, reason: str) -> None:
        policy = self.policy
        if wait > policy.max_wait_seconds:
            raise RateLimitBlocked(reason, wait)
        if self._waited + wait > policy.max_total_wait_seconds:
            raise RateLimitBlocked(REASON_WAIT_BUDGET, wait)
        if wait > 0:
            self._sleep(wait)
            self._waited += wait

    def before_request(self) -> None:
        """Gate one outgoing request: may sleep, may raise RateLimitBlocked.

        Counts the request against ``max_requests`` only once it is allowed.
        """
        policy = self.policy
        if self._requests >= policy.max_requests:
            raise RateLimitBlocked(REASON_REQUEST_BUDGET, 0.0)

        now = self._clock()
        if self._blocked_until > now:
            self._bounded_sleep(self._blocked_until - now, REASON_SECONDARY)
            self._blocked_until = 0.0
            now = self._clock()

        snap = self._snapshot
        if (snap.remaining is not None and snap.remaining <= policy.reserve
                and snap.reset_at is not None and snap.reset_at > now):
            wait = snap.reset_at - now + _RESET_MARGIN_SECONDS
            self._bounded_sleep(wait, REASON_PRIMARY)
            # The window rolled over: the old count no longer applies.
            self._snapshot = RateLimitSnapshot(
                limit=snap.limit, remaining=None, reset_at=None,
                resource=snap.resource)

        self._requests += 1

    # ------------------------------------------------------------ observing
    def observe(self, status_code: int, headers: Mapping | None,
                body: str = "") -> Throttle | None:
        """Record a response's quota headers; return a Throttle if refused.

        ``body`` is consulted only for a 403 (to spot GitHub's secondary-limit
        message) and only its first ``_BODY_SCAN_CHARS`` characters.
        """
        h = _lower_headers(headers)
        now = self._clock()

        limit = _to_int(h.get(HEADER_LIMIT))
        remaining = _to_int(h.get(HEADER_REMAINING))
        reset_at = _to_epoch(h.get(HEADER_RESET))
        if remaining is not None or limit is not None or reset_at is not None:
            self._snapshot = RateLimitSnapshot(
                limit=limit if limit is not None else self._snapshot.limit,
                remaining=remaining,
                reset_at=reset_at,
                resource=_clean_resource(h.get(HEADER_RESOURCE))
                or self._snapshot.resource,
            )

        retry_after = _retry_after_seconds(h.get(HEADER_RETRY_AFTER), now)
        exhausted = remaining == 0

        if status_code == 429:
            throttled = True
        elif status_code == 403:
            text = str(body or "")[:_BODY_SCAN_CHARS].lower()
            throttled = (exhausted or retry_after is not None
                         or any(m in text for m in _SECONDARY_MARKERS))
        else:
            throttled = False
        if not throttled:
            return None

        self._throttled += 1
        if retry_after is not None:
            wait, kind = retry_after, (REASON_PRIMARY if exhausted
                                       else REASON_SECONDARY)
        elif exhausted and reset_at is not None:
            wait = max(0.0, reset_at - now) + _RESET_MARGIN_SECONDS
            kind = REASON_PRIMARY
        else:
            wait, kind = self.policy.secondary_default_wait, REASON_SECONDARY
        if kind == REASON_SECONDARY:
            self._blocked_until = max(self._blocked_until, now + wait)
        return Throttle(kind=kind, wait_seconds=wait)

    def backoff(self, throttle: Throttle) -> None:
        """Sleep out a Throttle inside the policy bounds, else raise."""
        self._bounded_sleep(throttle.wait_seconds, throttle.kind)
        if throttle.kind == REASON_SECONDARY:
            self._blocked_until = 0.0
        else:
            snap = self._snapshot
            self._snapshot = RateLimitSnapshot(
                limit=snap.limit, remaining=None, reset_at=None,
                resource=snap.resource)
