"""V4-E09 — the WRITE side of feedback & suppression (dashboard / CLI only).

This module is the single place where a suppression rule or a feedback
event row is *planned*: validated, redacted, capped and given its origin.
It exists as a separate module from :mod:`ai_pr_reviewer.feedback` (the
engine's read-only half) so that the invariant from
``docs/planning/V4_THREAT_MODEL.md`` §4 is structural:

    Suppression rules originate ONLY from authenticated dashboard / CLI
    actions. There is no path from a PR diff, a PR body or model output to
    create or modify one.

How that is enforced *by construction* rather than by a check someone
must remember to call:

1. **Sealed authority.** Every rule writer here takes an
   :class:`AdminAuthority`. It can only be minted by
   :func:`mint_admin_authority`, which itself verifies a secret admin
   token (constant-time) that is *different from* the dashboard API token
   the review Action holds. The planners and the storage writers refuse
   anything else, and the row's ``origin`` is copied from the authority —
   never from request data.
2. **Closed input grammar.** :func:`parse_rule_spec` accepts a fixed key
   set and fixed field grammars; unknown keys (``origin``, ``created_by``,
   ``id`` …) are rejected, not ignored. No field can carry finding text,
   so model output has nothing to be smuggled through.
3. **Schema CHECKs.** ``storage_schema`` constrains ``origin`` to
   ``RULE_ORIGINS`` and a rule's shape to "names its target", so even a
   writer that bypassed this module could not insert a forged or
   match-everything rule.
4. **Import isolation.** Nothing the review pipeline imports reaches this
   module (``tests/test_feedback.py`` walks the import graph from the
   Action entry point and asserts it), and the engine's two storage
   classes declare no authoring capability.

All planners are pure (rows in, rows out, injectable clock) so every
backend — SQL and JSON — shares one set of rules and one set of caps.
"""
from __future__ import annotations

import hmac
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import storage_schema as S
from .security import redact_secrets

#: Raw (pre-redaction) free-text ceiling. Bounds the work the redaction
#: regexes can be asked to do on a hostile payload; the *stored* caps
#: (``MAX_REASON_CHARS`` / ``MAX_EVENT_NOTE_CHARS``) apply after redaction.
MAX_RAW_TEXT_CHARS = 2_000
#: Minimum length of the admin token. Shorter values fail closed.
MIN_ADMIN_TOKEN_CHARS = 16

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


# ------------------------------------------------------------------ errors
class FeedbackError(Exception):
    """Base for every error this module raises. ``status`` is the HTTP
    status the dashboard maps it to; ``code`` is a stable machine string.
    Messages never echo request content (nothing untrusted is reflected)."""

    status = 400
    code = "invalid"

    def __init__(self, message: str, *, code: str | None = None,
                 status: int | None = None, retry_after: int | None = None):
        super().__init__(message)
        if code is not None:
            self.code = code
        if status is not None:
            self.status = status
        self.retry_after = retry_after


class FeedbackValidationError(FeedbackError):
    status = 400
    code = "invalid"


class FeedbackCapError(FeedbackError):
    """A cap was hit (rate, active-rule count or stored-row count)."""

    status = 409
    code = "cap_reached"


class AuthorityError(FeedbackError):
    """The caller is not (or cannot be) an authenticated rule author."""

    status = 401
    code = "unauthorized"


# --------------------------------------------------------------- authority
_MINT = object()


class AdminAuthority:
    """Proof that a human action was authenticated as a rule author.

    Immutable and mint-restricted: constructing one directly raises, and
    ``copy`` / ``pickle`` cannot fabricate a new one. Every rule writer
    demands one, and the stored ``origin`` is read off it — so a rule's
    provenance is a property of *how it was authenticated*, not something
    any request field can claim.

    Python cannot make this unforgeable against code that already runs in
    the process (and the engine never executes repository code — hard rule
    2). The guarantee that matters is the call graph: nothing that handles
    PR-derived data can reach :func:`mint_admin_authority` (it needs a
    secret the pipeline does not hold), and that is tested directly.
    """

    __slots__ = ("_origin",)

    def __init__(self, origin: str, *, _mint: object = None):
        if _mint is not _MINT:
            raise TypeError("AdminAuthority can only be minted by "
                            "mint_admin_authority()")
        if origin not in S.RULE_ORIGINS:
            raise ValueError("unknown authority origin")
        object.__setattr__(self, "_origin", origin)

    @property
    def origin(self) -> str:
        return self._origin

    def __setattr__(self, name, value):
        raise AttributeError("AdminAuthority is immutable")

    def __delattr__(self, name):
        raise AttributeError("AdminAuthority is immutable")

    def __repr__(self) -> str:
        return f"AdminAuthority(origin={self._origin!r})"

    def __copy__(self):
        return self

    def __deepcopy__(self, memo):
        return self

    def __reduce__(self):
        raise TypeError("AdminAuthority cannot be pickled")


def mint_admin_authority(provided: str | None, expected: str | None, *,
                         engine_token: str = "",
                         origin: str = S.ORIGIN_DASHBOARD) -> AdminAuthority:
    """Verify an admin token and mint the authority for one action.

    Fails *closed* in every unconfigured or ambiguous state:

    * ``expected`` empty            -> 503 (rule authoring disabled);
    * ``expected`` too short        -> 503;
    * ``expected`` equals the dashboard API token (``engine_token``) -> 503:
      reusing the Action's token would defeat the point of a separate
      credential for the highest-stakes action;
    * ``provided`` missing/wrong    -> 401 (constant-time comparison).
    """
    exp = (expected or "").strip()
    if not exp:
        raise AuthorityError(
            "suppression-rule authoring is disabled: DASHBOARD_ADMIN_TOKEN "
            "is not configured", status=503, code="admin_unconfigured")
    if len(exp) < MIN_ADMIN_TOKEN_CHARS:
        raise AuthorityError(
            f"DASHBOARD_ADMIN_TOKEN must be at least "
            f"{MIN_ADMIN_TOKEN_CHARS} characters", status=503,
            code="admin_token_weak")
    if engine_token and hmac.compare_digest(exp.encode("utf-8"),
                                            engine_token.encode("utf-8")):
        raise AuthorityError(
            "DASHBOARD_ADMIN_TOKEN must differ from the dashboard API token",
            status=503, code="admin_token_reused")
    given = provided or ""
    if not given or not hmac.compare_digest(given.encode("utf-8"),
                                            exp.encode("utf-8")):
        raise AuthorityError("invalid or missing admin token")
    return AdminAuthority(origin if origin in S.RULE_ORIGINS
                          else S.ORIGIN_DASHBOARD, _mint=_MINT)


def require_authority(authority: object) -> AdminAuthority:
    """The check every writer makes *inside itself* (callers cannot skip it)."""
    if not isinstance(authority, AdminAuthority):
        raise AuthorityError("an authenticated AdminAuthority is required",
                             status=403, code="authority_required")
    return authority


# ---------------------------------------------------------------- helpers
def validate_repo(repo: object) -> str:
    """``owner/name`` in the system's grammar; anything else is rejected.

    Every row this module produces carries this value, and every query the
    stores run filters on it — repository scoping starts here.
    """
    text = repo if isinstance(repo, str) else ""
    if len(text) > 200 or not S.REPO_RE.fullmatch(text):
        raise FeedbackValidationError("invalid repository")
    if any(part in (".", "..") for part in text.split("/")):
        raise FeedbackValidationError("invalid repository")
    return text


def _clean_text(value: object, field_name: str, *, stored_max: int) -> str:
    """Redact, strip control characters, bound. Used for every free-text
    value at *persistence time* (not merely at display time)."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FeedbackValidationError(f"{field_name} must be a string")
    if len(value) > MAX_RAW_TEXT_CHARS:
        raise FeedbackValidationError(f"{field_name} is too long")
    text = _CONTROL_CHARS.sub("", redact_secrets(value)).strip()
    if len(text) > stored_max:
        raise FeedbackValidationError(
            f"{field_name} is too long (max {stored_max} characters)")
    return text


def _truncate_text(value: object, field_name: str, *, stored_max: int) -> str:
    """Like :func:`_clean_text` but truncates instead of rejecting — used
    for vote notes, where dropping the tail beats refusing a vote."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise FeedbackValidationError(f"{field_name} must be a string")
    text = _CONTROL_CHARS.sub(
        "", redact_secrets(value[:MAX_RAW_TEXT_CHARS])).strip()
    return text[:stored_max]


def row_is_active(row: dict, now: datetime) -> bool:
    """Not disabled and not yet expired. An unparseable expiry is treated
    as *expired* — a malformed row fails toward "no suppression"."""
    if row.get("disabled_at"):
        return False
    expires = S.parse_feedback_iso(row.get("expires_at"))
    return expires is not None and expires > now


def _assert_scoped(rows: list[dict], repo: str) -> None:
    """Defense in depth for isolation: a planner refuses to run over rows
    from any other repository, whatever query produced them."""
    for row in rows:
        if row.get("repo") != repo:
            raise FeedbackError(
                "cross-repository rows passed to a feedback planner",
                code="isolation_violation", status=500)


# ---------------------------------------------------------- rule creation
_RULE_KEYS = frozenset({"match_kind", "fingerprint", "rule_id", "path_glob",
                        "reason", "ttl_days"})
_EVENT_KEYS = frozenset({"fingerprint", "kind", "note"})


@dataclass(frozen=True)
class RuleSpec:
    """A validated request to create one rule — no origin, no id, no time:
    those are assigned by the writer, never supplied."""

    match_kind: str
    fingerprint: str = ""
    rule_id: str = ""
    path_glob: str = ""
    reason: str = ""
    ttl_days: int = S.DEFAULT_RULE_TTL_DAYS


def _reject_unknown(body: dict, allowed: frozenset) -> None:
    if set(body) - allowed:
        # Names are deliberately not echoed: they are untrusted input.
        raise FeedbackValidationError(
            f"unknown field(s); allowed: {', '.join(sorted(allowed))}")


def _validate_glob(glob: str) -> str:
    if not S.PATH_GLOB_RE.fullmatch(glob):
        raise FeedbackValidationError("path_glob has invalid characters")
    if glob.startswith("/") or ".." in glob.split("/"):
        raise FeedbackValidationError(
            "path_glob must be relative and may not contain '..'")
    if sum(glob.count(c) for c in "*?[") > S.MAX_PATH_GLOB_WILDCARDS:
        raise FeedbackValidationError("path_glob has too many wildcards")
    return glob


def parse_rule_spec(body: object) -> RuleSpec:
    """Strictly parse a rule-creation request body.

    Raises :class:`FeedbackValidationError` for anything outside the closed
    grammar. Unknown keys are an error (not ignored): an ``origin`` or
    ``created_by`` field in a body is a sign of something trying to choose
    its own provenance, and must fail loudly.
    """
    if not isinstance(body, dict):
        raise FeedbackValidationError("body must be a JSON object")
    _reject_unknown(body, _RULE_KEYS)

    kind = body.get("match_kind")
    if kind not in S.RULE_MATCH_KINDS:
        raise FeedbackValidationError(
            f"match_kind must be one of {list(S.RULE_MATCH_KINDS)}")

    def _opt(name: str) -> str:
        value = body.get(name, "")
        if value in (None, ""):
            return ""
        if not isinstance(value, str):
            raise FeedbackValidationError(f"{name} must be a string")
        return value

    fingerprint, rule_id, glob = _opt("fingerprint"), _opt("rule_id"), \
        _opt("path_glob")
    if kind == S.RULE_MATCH_FINGERPRINT:
        if rule_id or glob:
            raise FeedbackValidationError(
                "a fingerprint rule takes no rule_id or path_glob")
        if not S.FINGERPRINT_RE.fullmatch(fingerprint):
            raise FeedbackValidationError(
                "fingerprint must be 8-64 lowercase hex characters")
    else:
        if fingerprint:
            raise FeedbackValidationError(
                "a rule_path rule takes no fingerprint")
        if not S.RULE_ID_RE.fullmatch(rule_id):
            raise FeedbackValidationError(
                "rule_id must be one exact finding rule id")
        if not glob:
            raise FeedbackValidationError(
                "path_glob is required (use '**' to mean every path)")
        glob = _validate_glob(glob)

    ttl = body.get("ttl_days", S.DEFAULT_RULE_TTL_DAYS)
    if isinstance(ttl, bool) or not isinstance(ttl, int):
        raise FeedbackValidationError("ttl_days must be an integer")
    if not 1 <= ttl <= S.MAX_RULE_TTL_DAYS:
        raise FeedbackValidationError(
            f"ttl_days must be between 1 and {S.MAX_RULE_TTL_DAYS} "
            f"(every rule expires)")

    reason = body.get("reason", "")
    if reason is not None and not isinstance(reason, str):
        raise FeedbackValidationError("reason must be a string")
    return RuleSpec(match_kind=kind, fingerprint=fingerprint, rule_id=rule_id,
                    path_glob=glob, reason=reason or "", ttl_days=ttl)


def _same_target(row: dict, spec: RuleSpec) -> bool:
    return (row.get("match_kind") == spec.match_kind
            and row.get("fingerprint", "") == spec.fingerprint
            and row.get("rule_id", "") == spec.rule_id
            and row.get("path_glob", "") == spec.path_glob)


@dataclass
class RulePlan:
    """What a store should do to realize one create request."""

    action: str                     # "create" | "exists"
    row: dict                       # the row created, or the existing one
    purge_ids: list[str] = field(default_factory=list)


def plan_rule_creation(existing: list[dict], repo: str, spec: RuleSpec,
                       authority: object,
                       now: datetime | None = None) -> RulePlan:
    """Decide how to create one rule, applying every cap.

    ``existing`` is *every* stored rule row of ``repo`` (the store queries
    with a repository filter; this function re-asserts it). Order of
    checks is deliberate: authority, repository, idempotence (a duplicate
    of an in-force rule is returned as-is and consumes no rate budget),
    creation rate, purge of long-inactive rows, active cap, stored cap.
    """
    auth = require_authority(authority)
    repo = validate_repo(repo)
    _assert_scoped(existing, repo)
    moment = S.feedback_now(now)

    for row in existing:
        if row_is_active(row, moment) and _same_target(row, spec):
            return RulePlan("exists", dict(row))

    hour_ago = S.feedback_iso(moment - timedelta(hours=1))
    recent = sum(1 for r in existing
                 if str(r.get("created_at", "")) >= hour_ago)
    if recent >= S.MAX_RULE_CREATES_PER_HOUR:
        raise FeedbackCapError(
            f"rule creation rate limit reached "
            f"({S.MAX_RULE_CREATES_PER_HOUR} per hour per repository)",
            code="rate_limited", status=429, retry_after=3600)

    active = [r for r in existing if row_is_active(r, moment)]
    if len(active) >= S.MAX_ACTIVE_RULES_PER_REPO:
        raise FeedbackCapError(
            f"active rule cap reached ({S.MAX_ACTIVE_RULES_PER_REPO} per "
            f"repository); disable or let rules expire first",
            code="active_cap")

    # Inactive rows past their audit window make room; nothing active or
    # recently inactive is ever purged to satisfy a create.
    keep_after = S.feedback_iso(moment - timedelta(
        days=S.INACTIVE_RULE_RETENTION_DAYS))
    purge = [r["id"] for r in existing
             if not row_is_active(r, moment)
             and str(r.get("updated_at") or r.get("created_at", "")) < keep_after]
    if len(existing) - len(purge) >= S.MAX_STORED_RULES_PER_REPO:
        raise FeedbackCapError(
            f"stored rule cap reached ({S.MAX_STORED_RULES_PER_REPO} per "
            f"repository)", code="stored_cap")

    now_iso = S.feedback_iso(moment)
    row = {
        "id": S.new_suppression_rule_id(),
        "repo": repo,
        "match_kind": spec.match_kind,
        "fingerprint": spec.fingerprint,
        "rule_id": spec.rule_id,
        "path_glob": spec.path_glob,
        "reason": _clean_text(spec.reason, "reason",
                              stored_max=S.MAX_REASON_CHARS),
        "origin": auth.origin,            # from the authority, never a request
        "created_at": now_iso,
        "expires_at": S.feedback_iso(moment + timedelta(days=spec.ttl_days)),
        "disabled_at": "",
        "updated_at": now_iso,
    }
    size = sum(len(str(row[k]).encode("utf-8")) for k in
               ("fingerprint", "rule_id", "path_glob", "reason"))
    if size > S.MAX_RULE_BYTES:
        raise FeedbackValidationError(
            f"rule is too large (max {S.MAX_RULE_BYTES} bytes)")
    return RulePlan("create", row, purge)


def plan_disable(existing: list[dict], repo: str, rule_id: str,
                 authority: object, now: datetime | None = None
                 ) -> tuple[dict | None, bool]:
    """Disable one rule of ``repo``. Returns ``(row, changed)``; ``row`` is
    None when no such rule exists *in this repository* (a rule id from
    another repository is indistinguishable from a missing one)."""
    require_authority(authority)
    repo = validate_repo(repo)
    _assert_scoped(existing, repo)
    moment = S.feedback_now(now)
    for row in existing:
        if row.get("id") == rule_id:
            if row.get("disabled_at"):
                return dict(row), False
            updated = dict(row)
            updated["disabled_at"] = updated["updated_at"] = \
                S.feedback_iso(moment)
            return updated, True
    return None, False


def plan_disable_all(existing: list[dict], repo: str, authority: object,
                     now: datetime | None = None) -> list[dict]:
    """Disable every in-force rule of ``repo`` — the emergency brake."""
    require_authority(authority)
    repo = validate_repo(repo)
    _assert_scoped(existing, repo)
    moment = S.feedback_now(now)
    stamp = S.feedback_iso(moment)
    out = []
    for row in existing:
        if row_is_active(row, moment):
            updated = dict(row)
            updated["disabled_at"] = updated["updated_at"] = stamp
            out.append(updated)
    return out


# -------------------------------------------------------------- feedback events
@dataclass(frozen=True)
class EventSpec:
    fingerprint: str
    kind: str
    note: str = ""


def parse_event_spec(body: object) -> EventSpec:
    """Strictly parse a vote. The repository is never part of the body — it
    comes from the route — so a body cannot address another repository."""
    if not isinstance(body, dict):
        raise FeedbackValidationError("body must be a JSON object")
    _reject_unknown(body, _EVENT_KEYS)
    fingerprint = body.get("fingerprint")
    if not isinstance(fingerprint, str) or \
            not S.FINGERPRINT_RE.fullmatch(fingerprint):
        raise FeedbackValidationError(
            "fingerprint must be 8-64 lowercase hex characters")
    kind = body.get("kind")
    if kind not in S.FEEDBACK_KINDS:
        raise FeedbackValidationError(
            f"kind must be one of {list(S.FEEDBACK_KINDS)}")
    note = body.get("note", "")
    if note is not None and not isinstance(note, str):
        raise FeedbackValidationError("note must be a string")
    return EventSpec(fingerprint=fingerprint, kind=kind, note=note or "")


def check_event_caps(total_for_repo: int, last_hour_for_repo: int) -> int:
    """Enforce the event rate cap; return how many *oldest* rows the store
    must drop so the stored count stays within ``MAX_EVENTS_PER_REPO``."""
    if last_hour_for_repo >= S.MAX_EVENTS_PER_HOUR:
        raise FeedbackCapError(
            f"feedback rate limit reached ({S.MAX_EVENTS_PER_HOUR} per hour "
            f"per repository)", code="rate_limited", status=429,
            retry_after=3600)
    return max(0, total_for_repo + 1 - S.MAX_EVENTS_PER_REPO)


def build_event_row(repo: str, spec: EventSpec, origin: str,
                    now: datetime | None = None) -> dict:
    """The row for one vote. Free text is redacted here — at persistence
    time, inside the write path every backend shares — not at display."""
    repo = validate_repo(repo)
    if origin not in S.RULE_ORIGINS:
        raise FeedbackValidationError("unknown origin")
    return {
        "id": S.new_feedback_event_id(),
        "repo": repo,
        "fingerprint": spec.fingerprint,
        "kind": spec.kind,
        "note": _truncate_text(spec.note, "note",
                               stored_max=S.MAX_EVENT_NOTE_CHARS),
        "origin": origin,
        "created_at": S.feedback_iso(S.feedback_now(now)),
    }


def hour_cutoff(now: datetime | None = None) -> str:
    """ISO timestamp one hour before ``now`` — the rate-window boundary the
    stores use in their ``created_at >= ?`` count queries."""
    return S.feedback_iso(S.feedback_now(now) - timedelta(hours=1))
