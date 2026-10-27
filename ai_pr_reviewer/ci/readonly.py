"""Structural read-only guard for CI ingestion (V4.6-E01-T05).

CI data is observed, never controlled: nothing in this epic may re-run,
cancel, approve, dispatch or otherwise write to GitHub Actions. The guarantee
is *structural*, three independent layers deep:

1. **Capability.** Ingestion code receives a :class:`ReadOnlyGitHub`, whose
   only public method is ``get_json``. It holds no reference the caller can
   reach and exposes no ``post``/``patch``/``put``/``delete`` (nor
   ``post_review``/``create_comment``/...). ``GitHubClient.get_json`` itself
   is GET-only.
2. **Allowlist.** ``get_json`` refuses any path that is not one of
   ``READ_ENDPOINTS`` — an explicit list of read-only Actions/PR-commit
   endpoints — and any path containing a control verb
   (``FORBIDDEN_SEGMENTS``: ``rerun``, ``cancel``, ``approve``, ...).
   A refusal raises :class:`ReadOnlyViolation`, which is a programming error
   and is deliberately *not* swallowed by the degrade-with-label handlers.
3. **Tests.** ``tests/test_ci_readonly_guard.py`` checks the source of every
   module in this package with ``ast`` (no write-capable attribute calls, no
   HTTP-library imports, no write-method names) and drives a full ingestion
   against a transport that fails the test on any non-GET request.

Required token permission: reading workflow runs needs ``actions: read``.
Without it GitHub answers 403/404 and ingestion degrades with a label; this
package never asks for, and its guard never permits, a write scope.
"""
from __future__ import annotations

import re

#: The only endpoints CI ingestion may read (all GET).
READ_ENDPOINTS = (
    re.compile(r"/repos/[^/]+/[^/]+/actions/runs"),
    re.compile(r"/repos/[^/]+/[^/]+/actions/runs/[0-9]{1,20}"),
    re.compile(r"/repos/[^/]+/[^/]+/actions/runs/[0-9]{1,20}/jobs"),
    re.compile(r"/repos/[^/]+/[^/]+/actions/runs/[0-9]{1,20}"
               r"/attempts/[0-9]{1,6}/jobs"),
    re.compile(r"/repos/[^/]+/[^/]+/pulls/[0-9]{1,10}/commits"),
)

#: Path segments that name a control action. Even if a future allowlist edit
#: were careless, a path containing one is refused.
FORBIDDEN_SEGMENTS = frozenset({
    "rerun", "rerun-failed-jobs", "cancel", "force-cancel", "approve",
    "dispatches", "pending_deployments", "enable", "disable", "logs",
    "artifacts", "secrets", "variables", "caches", "permissions",
})

#: Attribute names that must never be *called* by ingestion code. Used by the
#: AST guard test; kept here so the policy has a single home.
WRITE_CALL_NAMES = frozenset({
    "post", "put", "patch", "delete", "request", "send", "stream",
    "post_review", "create_comment", "update_review_comment",
})

#: Modules ingestion code must never import (it goes through the reader).
FORBIDDEN_IMPORTS = frozenset({"httpx", "requests", "urllib", "urllib3",
                               "http", "aiohttp", "socket"})


class ReadOnlyViolation(ValueError):
    """CI ingestion tried to read a non-allowlisted path or a control verb.

    A bug in this codebase, not a runtime condition: callers must not
    degrade-and-continue past it.
    """


def check_read_path(path: str) -> str:
    """Return ``path`` if it is an allowlisted read endpoint, else raise."""
    if not isinstance(path, str):
        raise ReadOnlyViolation("read path must be a string")
    segments = {seg.lower() for seg in path.split("/") if seg}
    hit = segments & FORBIDDEN_SEGMENTS
    if hit:
        raise ReadOnlyViolation(
            f"refusing control/non-read endpoint segment(s): {sorted(hit)}")
    if not any(rx.fullmatch(path) for rx in READ_ENDPOINTS):
        raise ReadOnlyViolation(f"endpoint is not on the CI read allowlist: "
                                f"{path!r}")
    return path


class ReadOnlyGitHub:
    """The only GitHub handle CI ingestion is given: ``get_json`` and nothing
    else. Wraps any object with a compatible ``get_json`` (normally
    ``GitHubClient``)."""

    __slots__ = ("_reader",)

    def __init__(self, reader):
        if not callable(getattr(reader, "get_json", None)):
            raise TypeError("ReadOnlyGitHub needs an object with get_json()")
        object.__setattr__(self, "_reader", reader)

    def __setattr__(self, name, value):  # immutable capability
        raise AttributeError("ReadOnlyGitHub is immutable")

    def get_json(self, path: str, params: dict | None = None):
        return self._reader.get_json(check_read_path(path), params)
