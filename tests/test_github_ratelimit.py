"""V4.6-E01-T01 — GitHub API rate-limit handling (the family's C8 slot).

Two layers:

* ``RateLimiter`` is pure decision logic with an injectable clock and sleep:
  every test below runs with a fake clock, never sleeps, and is deterministic
  (no jitter anywhere).
* ``GitHubClient.get_json`` is the one quota-aware read path; it is exercised
  through an in-memory ``httpx.MockTransport`` exactly like the other GitHub
  client tests, so the real constructor, headers and base URL run.

No network, no API keys, no real tokens.
"""
from __future__ import annotations

import functools
import inspect
import re
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.github_client import (GitHubClient, GitHubError,
                                          GitHubRateLimited)
from ai_pr_reviewer.github_ratelimit import (REASON_PRIMARY,
                                             REASON_REQUEST_BUDGET,
                                             REASON_SECONDARY,
                                             REASON_WAIT_BUDGET,
                                             RateLimitBlocked,
                                             RateLimitPolicy, RateLimiter,
                                             Throttle)

NOW = 1_800_000_000.0


class FakeTime:
    """Fake clock + sleep: sleeping advances the clock, nothing really waits."""

    def __init__(self, now: float = NOW):
        self.now = now
        self.slept: list[float] = []

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def make_limiter(policy: RateLimitPolicy | None = None):
    ft = FakeTime()
    return RateLimiter(policy, clock=ft.clock, sleep=ft.sleep), ft


def quota(remaining: int, reset_in: float = 30, limit: int = 5000,
          now: float = NOW) -> dict:
    return {"X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(int(now + reset_in)),
            "X-RateLimit-Resource": "core"}


# ------------------------------------------------------------ limiter: reading
def test_observe_reads_quota_headers_case_insensitively():
    lim, _ = make_limiter()
    assert lim.observe(200, {"x-ratelimit-remaining": "4999",
                             "X-RATELIMIT-LIMIT": "5000",
                             "x-ratelimit-reset": str(int(NOW + 60)),
                             "x-ratelimit-resource": "core"}) is None
    snap = lim.snapshot()
    assert (snap.limit, snap.remaining, snap.reset_at, snap.resource) == (
        5000, 4999, NOW + 60, "core")


def test_observe_tolerates_missing_and_garbage_headers():
    lim, _ = make_limiter()
    assert lim.observe(200, None) is None
    assert lim.observe(200, {}) is None
    assert lim.observe(200, {"X-RateLimit-Remaining": "lots",
                             "X-RateLimit-Reset": "-5",
                             "Retry-After": "soon"}) is None
    snap = lim.snapshot()
    assert snap.remaining is None and snap.reset_at is None


def test_stats_are_counts_only():
    lim, _ = make_limiter()
    lim.before_request()
    lim.observe(200, quota(4000))
    stats = lim.stats()
    assert stats["requests"] == 1 and stats["remaining"] == 4000
    for value in stats.values():
        assert value is None or isinstance(value, (int, float, str))


def test_resource_header_is_cleaned():
    lim, _ = make_limiter()
    lim.observe(200, {**quota(10), "X-RateLimit-Resource": "co re<script>" * 9})
    resource = lim.snapshot().resource
    assert len(resource) <= 32 and re.fullmatch(r"[A-Za-z0-9_-]*", resource)


# --------------------------------------------------- limiter: proactive waiting
def test_no_wait_while_quota_is_above_the_reserve():
    lim, ft = make_limiter(RateLimitPolicy(reserve=10))
    lim.observe(200, quota(11, reset_in=30))
    lim.before_request()
    assert ft.slept == []


def test_waits_for_reset_when_at_or_below_the_reserve():
    lim, ft = make_limiter(RateLimitPolicy(reserve=10, max_wait_seconds=60))
    lim.observe(200, quota(10, reset_in=30))
    lim.before_request()
    assert ft.slept == [31.0]            # reset + 1s margin
    # The window rolled over: the next request does not wait again.
    lim.before_request()
    assert ft.slept == [31.0]


def test_refuses_instead_of_sleeping_past_the_wait_cap():
    lim, ft = make_limiter(RateLimitPolicy(reserve=10, max_wait_seconds=60))
    lim.observe(200, quota(0, reset_in=3000))
    with pytest.raises(RateLimitBlocked) as err:
        lim.before_request()
    assert err.value.reason == REASON_PRIMARY
    assert err.value.retry_after == pytest.approx(3001.0)
    assert ft.slept == []


def test_cumulative_wait_budget_is_enforced():
    lim, ft = make_limiter(RateLimitPolicy(
        reserve=10, max_wait_seconds=60, max_total_wait_seconds=70))
    lim.observe(200, quota(5, reset_in=39, now=ft.now))
    lim.before_request()                         # waits 40
    lim.observe(200, quota(5, reset_in=39, now=ft.now))
    with pytest.raises(RateLimitBlocked) as err:  # 40 + 40 > 70
        lim.before_request()
    assert err.value.reason == REASON_WAIT_BUDGET
    assert ft.slept == [40.0]


def test_request_budget_is_enforced_per_limiter():
    lim, _ = make_limiter(RateLimitPolicy(max_requests=3))
    for _ in range(3):
        lim.before_request()
    with pytest.raises(RateLimitBlocked) as err:
        lim.before_request()
    assert err.value.reason == REASON_REQUEST_BUDGET
    assert lim.stats()["requests"] == 3


def test_a_blocked_request_is_not_counted():
    lim, _ = make_limiter(RateLimitPolicy(reserve=10, max_wait_seconds=5))
    lim.observe(200, quota(0, reset_in=500))
    with pytest.raises(RateLimitBlocked):
        lim.before_request()
    assert lim.stats()["requests"] == 0


# ---------------------------------------------------- limiter: throttle detection
def test_429_with_retry_after_is_a_secondary_throttle():
    lim, _ = make_limiter()
    throttle = lim.observe(429, {"Retry-After": "7"})
    assert throttle == Throttle(kind=REASON_SECONDARY, wait_seconds=7.0)
    assert lim.stats()["throttled"] == 1


def test_403_with_exhausted_quota_is_a_primary_throttle():
    lim, _ = make_limiter()
    throttle = lim.observe(403, quota(0, reset_in=20))
    assert throttle == Throttle(kind=REASON_PRIMARY, wait_seconds=21.0)


def test_403_with_retry_after_is_a_throttle():
    lim, _ = make_limiter()
    throttle = lim.observe(403, {"Retry-After": "12"}, "Forbidden")
    assert throttle is not None and throttle.wait_seconds == 12.0


def test_403_with_secondary_limit_message_uses_the_default_wait():
    lim, _ = make_limiter(RateLimitPolicy(secondary_default_wait=45))
    throttle = lim.observe(
        403, {}, '{"message":"You have exceeded a secondary rate limit."}')
    assert throttle == Throttle(kind=REASON_SECONDARY, wait_seconds=45.0)


def test_bare_403_is_an_auth_failure_not_a_throttle():
    lim, _ = make_limiter()
    assert lim.observe(403, {"X-RateLimit-Remaining": "4000"},
                       "Resource not accessible by integration") is None
    assert lim.observe(403, {}, "rate limited") is None  # words alone are not a signature
    assert lim.stats()["throttled"] == 0


@pytest.mark.parametrize("status", [200, 201, 304, 404, 422, 500, 502])
def test_other_statuses_are_never_throttles(status):
    lim, _ = make_limiter()
    assert lim.observe(status, quota(0, reset_in=5)) is None


def test_retry_after_http_date_is_parsed():
    lim, _ = make_limiter()
    # 1_800_000_030 = Fri, 15 Jan 2027 08:00:30 GMT
    throttle = lim.observe(429, {"Retry-After": "Fri, 15 Jan 2027 08:00:30 GMT"})
    assert throttle is not None
    assert throttle.wait_seconds == pytest.approx(30.0)


def test_secondary_throttle_holds_off_the_next_request():
    lim, ft = make_limiter(RateLimitPolicy(max_wait_seconds=60))
    lim.observe(429, {"Retry-After": "20"})
    lim.before_request()
    assert ft.slept == [20.0]
    lim.before_request()
    assert ft.slept == [20.0]            # hold-off cleared once served


def test_backoff_sleeps_within_bounds_and_refuses_beyond():
    lim, ft = make_limiter(RateLimitPolicy(max_wait_seconds=30))
    lim.backoff(Throttle(REASON_SECONDARY, 10))
    assert ft.slept == [10]
    with pytest.raises(RateLimitBlocked) as err:
        lim.backoff(Throttle(REASON_PRIMARY, 31))
    assert err.value.reason == REASON_PRIMARY


def test_limiter_is_deterministic():
    runs = []
    for _ in range(2):
        lim, ft = make_limiter()
        lim.observe(200, quota(3, reset_in=17))
        lim.before_request()
        lim.observe(429, {"Retry-After": "4"})
        lim.before_request()
        runs.append(ft.slept)
    assert runs[0] == runs[1]


# ------------------------------------------------- client: GitHubClient.get_json
def make_client(monkeypatch, handler, limiter=None):
    """A real GitHubClient whose HTTP layer is an in-memory transport."""
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client",
        functools.partial(real_client, transport=httpx.MockTransport(recording)))
    return GitHubClient(token="t0ken", repo="acme/payments",
                        rate_limiter=limiter), seen


def test_get_json_returns_parsed_json_with_a_get(monkeypatch):
    gh, seen = make_client(
        monkeypatch, lambda r: httpx.Response(200, json={"ok": True},
                                              headers=quota(4000)))
    assert gh.get_json("/repos/acme/payments/actions/runs",
                       {"per_page": 100}) == {"ok": True}
    assert [r.method for r in seen] == ["GET"]
    assert seen[0].url.path == "/repos/acme/payments/actions/runs"
    assert gh.rate_limit_stats()["remaining"] == 4000


@pytest.mark.parametrize("path", [
    "/repos/other/repo/actions/runs",                     # another repository
    "/repos/acme/payments/../other/x",                    # climb out
    "/repos/acme/payments/",                              # nothing after prefix
    "/repos/acme/payments//runs",                         # empty segment
    "/repos/acme/payments/actions/runs?per_page=1",       # query smuggled in path
    "/repos/acme/payments/a b",                           # whitespace
    "/repos/acme/payments/actions/ｒuns",                  # non-ASCII lookalike
    "https://evil.example/repos/acme/payments/actions/runs",
    "repos/acme/payments/actions/runs",
    "",
    None,
])
def test_get_json_refuses_paths_outside_the_repository(monkeypatch, path):
    gh, seen = make_client(monkeypatch, lambda r: httpx.Response(200, json={}))
    with pytest.raises(GitHubError, match="unsafe read path"):
        gh.get_json(path)
    assert seen == []                    # nothing was sent


def test_throttled_read_waits_then_succeeds(monkeypatch):
    ft = FakeTime()
    limiter = RateLimiter(clock=ft.clock, sleep=ft.sleep)
    replies = iter([httpx.Response(429, headers={"Retry-After": "5"}, text=""),
                    httpx.Response(200, json={"n": 1})])
    gh, seen = make_client(monkeypatch, lambda r: next(replies), limiter)
    assert gh.get_json("/repos/acme/payments/actions/runs") == {"n": 1}
    assert len(seen) == 2 and ft.slept == [5.0]


def test_throttle_retries_are_bounded_then_raise_rate_limited(monkeypatch):
    ft = FakeTime()
    policy = RateLimitPolicy(max_throttle_retries=2)
    limiter = RateLimiter(policy, clock=ft.clock, sleep=ft.sleep)
    gh, seen = make_client(
        monkeypatch,
        lambda r: httpx.Response(429, headers={"Retry-After": "3"}, text=""),
        limiter)
    with pytest.raises(GitHubRateLimited) as err:
        gh.get_json("/repos/acme/payments/actions/runs")
    assert len(seen) == 3                       # first send + 2 re-sends
    assert err.value.reason == REASON_SECONDARY
    assert err.value.retry_after == 3.0
    assert err.value.status_code == 429
    assert isinstance(err.value, GitHubError)   # callers' generic handlers still work


def test_exhausted_quota_far_from_reset_degrades_without_hanging(monkeypatch):
    ft = FakeTime()
    limiter = RateLimiter(clock=ft.clock, sleep=ft.sleep)
    gh, seen = make_client(
        monkeypatch,
        lambda r: httpx.Response(200, json={}, headers=quota(0, reset_in=3000)),
        limiter)
    gh.get_json("/repos/acme/payments/actions/runs")        # sees remaining=0
    with pytest.raises(GitHubRateLimited) as err:
        gh.get_json("/repos/acme/payments/actions/runs")
    assert err.value.reason == REASON_PRIMARY
    assert len(seen) == 1 and ft.slept == []    # second request never sent


def test_reserve_protects_the_review_s_own_quota(monkeypatch):
    ft = FakeTime()
    limiter = RateLimiter(RateLimitPolicy(reserve=10), clock=ft.clock,
                          sleep=ft.sleep)
    gh, seen = make_client(
        monkeypatch,
        lambda r: httpx.Response(200, json={}, headers=quota(9, reset_in=3000)),
        limiter)
    gh.get_json("/repos/acme/payments/actions/runs")
    with pytest.raises(GitHubRateLimited):
        gh.get_json("/repos/acme/payments/actions/runs")
    assert len(seen) == 1


def test_bare_403_stays_a_plain_github_error(monkeypatch):
    gh, seen = make_client(
        monkeypatch, lambda r: httpx.Response(403, text="Resource not accessible"))
    with pytest.raises(GitHubError) as err:
        gh.get_json("/repos/acme/payments/actions/runs")
    assert not isinstance(err.value, GitHubRateLimited)
    assert err.value.status_code == 403
    assert len(seen) == 1                       # a 403 is never re-sent


def test_secondary_limit_message_on_a_403_is_recognized_by_the_client(monkeypatch):
    ft = FakeTime()
    limiter = RateLimiter(RateLimitPolicy(secondary_default_wait=7,
                                          max_throttle_retries=1),
                          clock=ft.clock, sleep=ft.sleep)
    gh, seen = make_client(
        monkeypatch,
        lambda r: httpx.Response(
            403, text='{"message": "You have exceeded a secondary rate limit."}'),
        limiter)
    with pytest.raises(GitHubRateLimited) as err:
        gh.get_json("/repos/acme/payments/actions/runs")
    assert err.value.reason == REASON_SECONDARY
    assert len(seen) == 2 and ft.slept == [7.0]


def test_404_and_5xx_are_plain_errors_with_status(monkeypatch):
    for status in (404, 500):
        gh, seen = make_client(monkeypatch,
                               lambda r, s=status: httpx.Response(s, text="x"))
        with pytest.raises(GitHubError) as err:
            gh.get_json("/repos/acme/payments/actions/runs")
        assert err.value.status_code == status and len(seen) == 1


def test_non_json_success_is_a_clean_error(monkeypatch):
    gh, _ = make_client(monkeypatch,
                        lambda r: httpx.Response(200, text="<html>nope</html>"))
    with pytest.raises(GitHubError, match="non-JSON"):
        gh.get_json("/repos/acme/payments/actions/runs")


def test_request_budget_applies_across_calls(monkeypatch):
    limiter = RateLimiter(RateLimitPolicy(max_requests=2))
    gh, seen = make_client(monkeypatch, lambda r: httpx.Response(200, json=[]),
                           limiter)
    gh.get_json("/repos/acme/payments/actions/runs")
    gh.get_json("/repos/acme/payments/actions/runs")
    with pytest.raises(GitHubRateLimited) as err:
        gh.get_json("/repos/acme/payments/actions/runs")
    assert err.value.reason == REASON_REQUEST_BUDGET and len(seen) == 2


# -------------------------------------------------- contract / anti-fork guards
def test_existing_constructor_contract_is_additive_only():
    params = list(inspect.signature(GitHubClient.__init__).parameters)
    assert params[:5] == ["self", "token", "repo", "api_url", "retry"]
    assert params[5:] == ["rate_limiter"]
    assert inspect.signature(GitHubClient.__init__).parameters[
        "rate_limiter"].default is None


def test_existing_read_paths_keep_their_behavior(monkeypatch):
    """The pre-existing methods are untouched: a 403 from get_pr_files is the
    same plain error it always was (no new retry, sleep or label)."""
    gh, seen = make_client(monkeypatch,
                           lambda r: httpx.Response(403, text="rate limited"))
    with pytest.raises(GitHubError) as err:
        gh.get_pr_files(7)
    assert err.value.status_code == 403 and len(seen) == 1


def test_there_is_exactly_one_rate_limit_implementation():
    """§D.3 bottleneck #2 / §H.2: no per-feature rate limiting. Only
    ``github_ratelimit`` may read X-RateLimit headers inside the engine."""
    offenders = []
    for path in (ROOT / "ai_pr_reviewer").rglob("*.py"):
        if path.name == "github_ratelimit.py":
            continue
        text = path.read_text(encoding="utf-8").lower()
        if re.search(r"""["']x-ratelimit""", text):
            offenders.append(path.name)
    assert offenders == []
