"""Synchronize the internal finding lifecycle with GitHub review comments
(V3 C5).

The reviewer keeps its own truth — findings with fingerprints and states in
storage — and GitHub is a *view* of that truth. This module is the adapter:

* **stable mapping.** A finding records ``github_comment_id`` the first time
  a comment is posted for it (from the posting response, or by matching the
  comment we just created), and the id survives subsequent reviews, so the
  same finding always points at the same comment.
* **no duplicates.** A finding that already has a comment id is updated,
  never re-posted (``cli`` filters it out of the inline-comment set).
* **state changes are reflected.** When a finding flips to resolved, muted,
  dismissed or reopened, its existing comment is PATCHed with a short
  marker so a reader of the PR sees the current state without a second
  comment being opened.
* **failures never touch the review.** Every GitHub error here degrades to
  a warning (deleted comment, rate limit, missing permission): the internal
  result, the report and the step summary are already written and stay
  intact.

Only ``pull-requests: write`` — the permission the Action already has — is
used. No check runs (they would need ``checks: write``).

V4-E10 (GitHub lifecycle) extends this module without replacing any of the above:

* **comment fingerprints (T01).** Every inline comment the engine renders ends
  with one server-generated, hidden marker line carrying the *finding
  fingerprint* only (``<!-- ai-pr-reviewer:v1 kind=comment fp=... -->``). A
  marker is a **hint, never a credential**: it is public the moment it is
  posted and anyone can copy it. Ownership therefore never comes from reading
  markers off arbitrary comments - it comes from an :class:`OwnershipLedger`
  that only the engine's own doors can fill (see that class).
* **structural ownership.** Every PATCH/DELETE goes through exactly two
  functions, :func:`guarded_update` and :func:`guarded_delete`, which accept
  only an :class:`OwnedCommentId` - a capability object that only a ledger can
  mint, and only for ids the engine itself recorded.
* **sticky summary (T02).** At most one engine-owned summary comment per PR,
  updated in place (:func:`sync_sticky_summary`); the body is rendered by
  ``reporter.render_sticky_summary`` from already-redacted report data.
* **lifecycle sync (T03).** State sync is ownership-gated, idempotent where it
  can cheaply be, and stops writing for the rest of the run once GitHub answers
  403/429 (the shared ``RetryPolicy`` still handles transient 429/5xx).
* **additive outputs (T05).** :class:`LifecycleStats` reports counts, ids and
  closed-vocabulary words only - never free text.

The engine still never approves, merges, or does anything beyond commenting.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from .findings import fingerprint_finding
from .github_client import GitHubError
from .models import Finding

log = logging.getLogger(__name__)

#: Marker prepended to a comment body once the finding reaches that state.
#: States not listed here (new/active) keep their body exactly as posted.
STATE_MARKERS = {
    "resolved": "\u2705 **Resolved**",
    "muted": "\U0001f507 **Muted**",
    "dismissed": "\U0001f6ab **Dismissed**",
    "reopened": "\U0001f501 **Reopened**",
}

MAX_SYNC_ERRORS = 5      # one loud warning per review, not one per comment

# --------------------------------------------------------------------------
# V4-E10 constants. Nothing below is a new *cap* on existing behaviour: the
# inline-comment cap (``max_comments``) and the report caps are untouched.
# --------------------------------------------------------------------------
MARKER_TAG = "ai-pr-reviewer"
MARKER_VERSION = "v1"

#: Issue-comment pages scanned (100 each) when looking for this engine's one
#: sticky summary. Bounded on purpose: a read, never a crawl of a whole PR.
MAX_DISCOVERY_PAGES = 3
_PER_PAGE = 100

#: Platform comment-thread ceiling documented in V4_THREAT_MODEL.md section 5
#: ("GitHub platform dialog limit ~ 250"). A thread already this long with no
#: sticky summary of ours in it does not get a new engine comment: adding to
#: it is exactly the "comment spam" the threat model's control forbids.
PLATFORM_COMMENT_SOFT_CAP = 250

#: A sticky body is rendered from capped report data and is far smaller than
#: this; anything bigger is a bug upstream and is refused rather than posted.
MAX_STICKY_BODY_CHARS = 20_000

_REPO_PART = r"[A-Za-z0-9_.-]{1,100}"
_FP_PATTERN = r"[0-9a-f]{16}"
_COMMENT_MARKER_RE = re.compile(
    rf"^<!-- {MARKER_TAG}:{MARKER_VERSION} kind=comment fp=({_FP_PATTERN}) -->$")
_STICKY_MARKER_RE = re.compile(
    rf"^<!-- {MARKER_TAG}:{MARKER_VERSION} kind=sticky "
    rf"repo=({_REPO_PART}/{_REPO_PART}) pr=([0-9]{{1,9}}) -->$")
#: Anything that even *looks like the start of* one of our markers.
_MARKER_LIKE_RE = re.compile(rf"<!--\s*{MARKER_TAG}:", re.I)
_REPO_RE = re.compile(rf"^{_REPO_PART}/{_REPO_PART}$")
_FP_RE = re.compile(rf"^{_FP_PATTERN}$")


def _valid_repo(repo: object) -> bool:
    """``owner/name`` as GitHub allows it: never a dot-only (``.``/``..``) part."""
    return (isinstance(repo, str) and bool(_REPO_RE.match(repo))
            and not any(set(part) <= {"."} for part in repo.split("/")))


# ===================================================================== markers

def neutralize_untrusted_markup(text: str) -> str:
    """Make HTML-comment syntax in untrusted text inert.

    Finding titles/explanations come from model output steered by a PR; the
    sticky summary may echo PR-derived paths. If any of that text could emit
    ``<!--``, it could plant a second marker-shaped line in a body the engine
    owns. Replacing the two delimiters (they render identically as text in
    GitHub markdown) guarantees that the *only* marker in an engine body is
    the one the engine appended itself.
    """
    return str(text).replace("<!--", "&lt;!--").replace("-->", "--&gt;")


@dataclass(frozen=True)
class EngineMarker:
    """A parsed marker. ``kind`` is ``"comment"`` or ``"sticky"``."""

    kind: str
    fingerprint: str | None = None     # kind == "comment"
    repo: str | None = None            # kind == "sticky"
    pr_number: int | None = None       # kind == "sticky"


def _fingerprint_of(f: Finding) -> str:
    fp = getattr(f, "fingerprint", None)
    if isinstance(fp, str) and _FP_RE.match(fp):
        return fp
    return fingerprint_finding(f)


def render_comment_marker(fingerprint: str) -> str:
    """The hidden marker line for an inline comment (engine-side input only)."""
    if not isinstance(fingerprint, str) or not _FP_RE.match(fingerprint):
        raise ValueError("a comment marker needs a 16-hex finding fingerprint")
    return f"<!-- {MARKER_TAG}:{MARKER_VERSION} kind=comment fp={fingerprint} -->"


def render_sticky_marker(repo: str, pr_number: int) -> str:
    """The hidden marker line for the sticky summary of ``repo``#``pr_number``."""
    if (not _valid_repo(repo)
            or isinstance(pr_number, bool) or not isinstance(pr_number, int)
            or not 0 < pr_number < 10 ** 9):
        raise ValueError("a sticky marker needs a valid owner/name and PR number")
    return f"<!-- {MARKER_TAG}:{MARKER_VERSION} kind=sticky repo={repo} pr={pr_number} -->"


def parse_marker(body: object) -> EngineMarker | None:
    """Strictly parse the marker of an engine-rendered body, else ``None``.

    Strict on purpose: exactly ONE marker-shaped string may exist anywhere in
    the body, it must be the last line, and it must match the full grammar.
    Anything ambiguous (two markers, a marker mid-body, extra fields) is
    ``None``. A parsed marker proves nothing about *who wrote* the comment -
    see :class:`OwnershipLedger` for that.
    """
    if not isinstance(body, str):
        return None
    text = body.replace("\r\n", "\n").rstrip()
    if len(_MARKER_LIKE_RE.findall(text)) != 1:
        return None
    last = text.rsplit("\n", 1)[-1].strip()
    m = _COMMENT_MARKER_RE.match(last)
    if m:
        return EngineMarker(kind="comment", fingerprint=m.group(1))
    m = _STICKY_MARKER_RE.match(last)
    if m and _valid_repo(m.group(1)):
        return EngineMarker(kind="sticky", repo=m.group(1), pr_number=int(m.group(2)))
    return None


# ================================================================= ownership

class ForeignCommentError(PermissionError):
    """Raised when something tries to mutate a comment this engine does not own."""


_MINT = object()        # private: only OwnershipLedger.mint() holds it


@dataclass(frozen=True)
class OwnedCommentId:
    """Capability: "this engine recorded this comment id".

    Cannot be constructed outside this module's ledger (the private sentinel
    is checked on creation), and :func:`guarded_update` / :func:`guarded_delete`
    accept nothing else - a bare ``int`` is a ``ForeignCommentError``. That is
    what makes "only ids this engine recorded are ever PATCHed or deleted" a
    property of the types, not a convention callers have to remember.
    """

    kind: str                                   # "review" | "issue"
    comment_id: int
    _token: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _MINT:
            raise ForeignCommentError(
                "OwnedCommentId can only be minted by an OwnershipLedger")


def _as_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if number > 0 else None


@dataclass(frozen=True)
class EngineIdentity:
    """The GitHub account the engine acts as - learned ONLY from responses to
    requests the engine itself made, never from the content of any comment."""

    login: str = ""
    user_id: int | None = None

    def matches(self, user: object) -> bool:
        if not isinstance(user, dict):
            return False
        uid = user.get("id")
        if (self.user_id is not None and isinstance(uid, int)
                and not isinstance(uid, bool)):
            return uid == self.user_id          # ids beat logins (logins rename)
        login = user.get("login")
        return bool(self.login and isinstance(login, str)
                    and login.casefold() == self.login.casefold())


def identity_from_payload(payload: object) -> EngineIdentity | None:
    """Identity from the ``user`` of a GitHub object the engine just created."""
    user = payload.get("user") if isinstance(payload, dict) else None
    if not isinstance(user, dict):
        return None
    login = user.get("login") if isinstance(user.get("login"), str) else ""
    uid = user.get("id") if (isinstance(user.get("id"), int)
                             and not isinstance(user.get("id"), bool)) else None
    if not login and uid is None:
        return None
    return EngineIdentity(login=login, user_id=uid)


class OwnershipLedger:
    """The set of GitHub comment ids this engine owns, and how it learned each.

    Exactly three doors fill it:

    1. **created** - the id came back in the response to a request this
       engine just made (:meth:`record_created`). The same responses are the
       only source of the engine's :class:`EngineIdentity` (:meth:`learn_identity`).
    2. **adopted** - a *listed* comment passed *all* of: authored by the known
       engine identity, a strict marker of the right kind, and the expected
       fingerprint / repo+PR (:meth:`adopt_inline_comment`,
       :meth:`adopt_sticky_comment`). The ledger itself performs the checks, so
       a caller cannot adopt by skipping them. With no known identity nothing
       can be adopted - the answer is "no", never "probably".
    3. **persisted** - the id was recorded by the engine in its own storage
       during an earlier run (:meth:`record_persisted`); the trust model treats
       engine storage as trusted. These ids get an extra pre-write check
       (``sync_finding_states``) whenever the identity is known.

    A foreign comment that merely *contains* a marker, or an exact copy of an
    engine body, enters through none of them.
    """

    def __init__(self, identity: EngineIdentity | None = None):
        self.identity = identity
        self._origin: dict[tuple[str, int], str] = {}
        #: Set once GitHub answers 403/429 to a write: the rest of the run
        #: stops writing instead of hammering a limit it already hit.
        self.writes_blocked = False

    # -- door 1 ------------------------------------------------------------
    def learn_identity(self, created_payload: object) -> bool:
        """Record who we are from an object GitHub returned for our own POST.
        The first identity learned wins; a later payload never replaces it."""
        if self.identity is not None:
            return False
        found = identity_from_payload(created_payload)
        if found is None:
            return False
        self.identity = found
        return True

    def record_created(self, kind: str, comment_id: object) -> bool:
        cid = _as_int(comment_id)
        if cid is None or kind not in ("review", "issue"):
            return False
        self._origin[(kind, cid)] = "created"
        return True

    # -- door 3 ------------------------------------------------------------
    def record_persisted(self, kind: str, comment_id: object) -> bool:
        cid = _as_int(comment_id)
        if cid is None or kind not in ("review", "issue"):
            return False
        self._origin.setdefault((kind, cid), "persisted")
        return True

    # -- door 2 ------------------------------------------------------------
    def _authored_by_engine(self, comment: object) -> bool:
        return (self.identity is not None and isinstance(comment, dict)
                and self.identity.matches(comment.get("user")))

    def adopt_inline_comment(self, comment: object, expected_fingerprint: str) -> bool:
        """Adopt a listed inline review comment iff it is provably ours."""
        if not isinstance(comment, dict):
            return False
        cid = _as_int(comment.get("id"))
        if cid is None or not self._authored_by_engine(comment):
            return False
        marker = parse_marker(comment.get("body"))
        if (marker is None or marker.kind != "comment"
                or marker.fingerprint != expected_fingerprint):
            return False
        self._origin.setdefault(("review", cid), "adopted")
        return True

    def adopt_sticky_comment(self, comment: object, repo: str, pr_number: int) -> bool:
        """Adopt a listed issue comment iff it is this engine's sticky summary
        for exactly this repository and pull request."""
        if not isinstance(comment, dict):
            return False
        cid = _as_int(comment.get("id"))
        if cid is None or not self._authored_by_engine(comment):
            return False
        marker = parse_marker(comment.get("body"))
        if (marker is None or marker.kind != "sticky"
                or marker.repo != repo or marker.pr_number != pr_number):
            return False
        self._origin.setdefault(("issue", cid), "adopted")
        return True

    # -- queries / capability ---------------------------------------------
    def origin(self, kind: str, comment_id: object) -> str | None:
        cid = _as_int(comment_id)
        return self._origin.get((kind, cid)) if cid is not None else None

    def owns(self, kind: str, comment_id: object) -> bool:
        return self.origin(kind, comment_id) is not None

    def mint(self, kind: str, comment_id: object) -> OwnedCommentId:
        """The capability for an owned id; ``ForeignCommentError`` otherwise."""
        cid = _as_int(comment_id)
        if cid is None or (kind, cid) not in self._origin:
            raise ForeignCommentError(
                f"refusing to mint a capability for a {kind} comment this "
                f"engine did not record")
        return OwnedCommentId(kind=kind, comment_id=cid, _token=_MINT)


#: One ledger per process = per review run (the Action runs one review per
#: process). ``cli`` reaches it implicitly through ``record_comment_ids`` /
#: ``link_comment_ids`` / ``sync_finding_states``; tests pass their own.
_PROCESS_LEDGER = OwnershipLedger()


def process_ledger() -> OwnershipLedger:
    return _PROCESS_LEDGER


def reset_process_ledger() -> OwnershipLedger:
    """Start a fresh process ledger (tests / long-lived hosts)."""
    global _PROCESS_LEDGER
    _PROCESS_LEDGER = OwnershipLedger()
    return _PROCESS_LEDGER


# ================================================================ statistics

STICKY_ACTIONS = ("created", "updated", "unchanged", "skipped", "failed")
STICKY_SKIP_REASONS = (
    "not_run", "no_client", "unsupported", "invalid_scope", "invalid_body",
    "identity_unknown", "writes_blocked", "discovery_failed",
    "discovery_incomplete", "platform_cap",
)
_COUNT_CEILING = 1_000_000


def _count(value) -> int:
    n = _as_int(value)
    return 0 if n is None else min(n, _COUNT_CEILING)


@dataclass
class LifecycleStats:
    """What the lifecycle layer did this run - counts, ids and closed words.

    This is the *additive report output* (T05). By construction it cannot hold
    free text: :meth:`to_report_fields` emits only non-negative integers, one
    positive id and two words drawn from fixed vocabularies.
    """

    sticky_action: str = "skipped"
    sticky_skip_reason: str | None = "not_run"
    sticky_comment_id: int | None = None
    sticky_duplicates_seen: int = 0
    comments_linked: int = 0
    comments_updated: int = 0
    comments_unchanged: int = 0
    comments_refused_foreign: int = 0
    comments_failed: int = 0
    comments_skipped_blocked: int = 0

    def set_sticky(self, action: str, reason: str | None = None,
                   comment_id: int | None = None) -> None:
        self.sticky_action = action if action in STICKY_ACTIONS else "failed"
        self.sticky_skip_reason = reason if reason in STICKY_SKIP_REASONS else None
        self.sticky_comment_id = _as_int(comment_id)

    def to_report_fields(self) -> dict:
        """``{"github_lifecycle": {...}}`` - merge into the report with
        ``report.update(stats.to_report_fields())``."""
        action = self.sticky_action if self.sticky_action in STICKY_ACTIONS else "failed"
        reason = (self.sticky_skip_reason
                  if self.sticky_skip_reason in STICKY_SKIP_REASONS else None)
        return {"github_lifecycle": {
            "schema_version": 1,
            "sticky_action": action,
            "sticky_skip_reason": reason,
            "sticky_comment_id": _as_int(self.sticky_comment_id),
            "sticky_duplicates_seen": _count(self.sticky_duplicates_seen),
            "comments_linked": _count(self.comments_linked),
            "comments_updated": _count(self.comments_updated),
            "comments_unchanged": _count(self.comments_unchanged),
            "comments_refused_foreign": _count(self.comments_refused_foreign),
            "comments_failed": _count(self.comments_failed),
            "comments_skipped_blocked": _count(self.comments_skipped_blocked),
        }}


# ============================================================ GitHub adapter

class _Unsupported(Exception):
    """The client cannot do this (old client / test double)."""


class _CommentsAPI:
    """The few comment endpoints V4-E10 needs that ``GitHubClient`` lacks.

    Lives here (not in ``github_client.py``) because this module is this
    round's only file for the epic. It reuses the client's own ``_http`` and
    its shared ``RetryPolicy`` (``_retry``), so retries/backoff are the V3
    policy - not a second one. Errors carry status codes and no response text.
    """

    def __init__(self, gh):
        self.gh = gh

    @property
    def available(self) -> bool:
        repo = getattr(self.gh, "repo", None)
        return getattr(self.gh, "_http", None) is not None and isinstance(repo, str) and bool(repo)

    def _request(self, verb: str, path: str, what: str, **kwargs):
        if not self.available:
            raise _Unsupported(what)
        fn = getattr(self.gh._http, verb)
        url = f"/repos/{self.gh.repo}{path}"
        retry = getattr(self.gh, "_retry", None)
        r = retry.call(fn, url, **kwargs) if hasattr(retry, "call") else fn(url, **kwargs)
        status = getattr(r, "status_code", None)
        if status not in (200, 201, 204):
            raise GitHubError(f"{what} failed ({status})", status_code=status)
        return r

    def list_issue_comments(self, number: int, page: int) -> list[dict]:
        r = self._request("get", f"/issues/{int(number)}/comments", "GET issue comments",
                          params={"per_page": _PER_PAGE, "page": int(page)})
        data = r.json()
        return [c for c in data if isinstance(c, dict)] if isinstance(data, list) else []

    def create_issue_comment(self, number: int, body: str) -> dict:
        r = self._request("post", f"/issues/{int(number)}/comments",
                          "POST issue comment", json={"body": body})
        data = r.json()
        return data if isinstance(data, dict) else {}

    def get_review_comment(self, comment_id: int) -> dict:
        r = self._request("get", f"/pulls/comments/{int(comment_id)}", "GET review comment")
        data = r.json()
        return data if isinstance(data, dict) else {}

    # -- mutations: reachable ONLY through guarded_update / guarded_delete ---
    def update_issue_comment(self, comment_id: int, body: str) -> dict:
        r = self._request("patch", f"/issues/comments/{int(comment_id)}",
                          "PATCH issue comment", json={"body": body})
        data = r.json()
        return data if isinstance(data, dict) else {}

    def delete_issue_comment(self, comment_id: int) -> None:
        self._request("delete", f"/issues/comments/{int(comment_id)}",
                      "DELETE issue comment")

    def delete_review_comment(self, comment_id: int) -> None:
        self._request("delete", f"/pulls/comments/{int(comment_id)}",
                      "DELETE review comment")


# ================================================== the mutation chokepoint

def guarded_update(gh, owned: OwnedCommentId, body: str) -> dict:
    """PATCH a comment - the ONLY place in this module that edits one.

    ``owned`` must be an :class:`OwnedCommentId`; anything else (an ``int``
    read off a finding, a comment dict from a listing) is refused before any
    request is built.
    """
    if not isinstance(owned, OwnedCommentId):
        raise ForeignCommentError("refusing to edit a comment id this engine did not record")
    if owned.kind == "review":
        return gh.update_review_comment(owned.comment_id, body)
    return _CommentsAPI(gh).update_issue_comment(owned.comment_id, body)


def guarded_delete(gh, owned: OwnedCommentId) -> None:
    """DELETE a comment - the ONLY place in this module that removes one.

    Nothing in the review flow calls this: it exists so that if a deletion is
    ever added it cannot bypass the ownership check.
    """
    if not isinstance(owned, OwnedCommentId):
        raise ForeignCommentError("refusing to delete a comment id this engine did not record")
    api = _CommentsAPI(gh)
    if owned.kind == "review":
        return api.delete_review_comment(owned.comment_id)
    return api.delete_issue_comment(owned.comment_id)


def _note_blocked(ledger: OwnershipLedger, exc: Exception) -> bool:
    """403/429 from GitHub: stop writing for the rest of this run."""
    if isinstance(exc, GitHubError) and exc.status_code in (403, 429):
        ledger.writes_blocked = True
        return True
    return False


# ================================================================ rendering

def render_finding_comment(f: Finding) -> str:
    """Inline-comment body for ``f``.

    Single source of truth: the same text is used when the comment is first
    posted and when it is later updated, so a state marker can be added
    without ever losing the finding's content.

    V4-E10-T01: the body ends with the engine's hidden fingerprint marker.
    Finding text is untrusted model output, so any HTML-comment syntax in it
    is neutralised first - the engine's marker is then the only one the body
    can contain, and the first line (what V3 matched on) is unchanged for
    ordinary text.
    """
    n = neutralize_untrusted_markup
    body = (f"**\U0001f916 {f.severity.upper()}: {n(f.title)}** `{n(f.category)}`\n\n"
            f"{n(f.explanation)}")
    if f.suggestion:
        body += "\n\n```suggestion\n" + n(f.suggestion) + "\n```"
    return body + "\n\n" + render_comment_marker(_fingerprint_of(f))


def comment_key(f: Finding) -> tuple[str, int | None]:
    """(path, line) anchor a GitHub comment is keyed by."""
    return (f.file, f.line)


def _first_line(body: str) -> str:
    return body.split("\n", 1)[0]


def _strip_state_marker(body: str) -> str:
    """Drop a leading visible state marker line (and its blank line)."""
    for marker in STATE_MARKERS.values():
        if body.startswith(marker + "\n\n"):
            return body[len(marker) + 2:]
        if body == marker:
            return ""
    return body


# ================================================================ id capture

def record_comment_ids(findings: list[Finding], post_response,
                       *, ledger: OwnershipLedger | None = None) -> int:
    """Take comment ids out of a ``post_review`` response, if it has any.

    The 422-recovery path posts comments one by one and those responses
    carry an ``id``; the grouped-review response normally does not (callers
    fall back to :func:`link_comment_ids`). Returns how many findings
    gained an id.

    V4-E10: the response is the engine's own - so it is also where the
    engine learns *which GitHub account it is* (the review's ``user``), and
    every id taken from it is recorded in the ownership ledger as created.
    """
    if not isinstance(post_response, dict):
        return 0
    ledger = process_ledger() if ledger is None else ledger
    ledger.learn_identity(post_response.get("body"))
    ids = post_response.get("comment_ids")
    if not isinstance(ids, dict):
        return 0
    linked = 0
    for f in findings:
        if f.github_comment_id:
            continue
        raw = ids.get(comment_key(f))
        if raw in (None, ""):
            continue
        try:
            f.github_comment_id = int(raw)
            linked += 1
        except (TypeError, ValueError):
            continue
        ledger.record_created("review", f.github_comment_id)
    return linked


def link_comment_ids(gh, pr_number: int, findings: list[Finding],
                     head_sha: str, *, ledger: OwnershipLedger | None = None,
                     stats: LifecycleStats | None = None) -> tuple[int, list[str]]:
    """Match freshly posted findings to the comments GitHub just created.

    One bounded read of the PR's recent review comments, matched on
    (path, line) + commit + the exact first line of the body we rendered.

    V3 stopped there, which meant any comment that *looked* like ours - a
    human's paste, a bot's copy - at the same spot could be adopted and later
    edited. V4-E10-T01 closes that: a candidate is adopted only through
    :meth:`OwnershipLedger.adopt_inline_comment` - authored by the account
    this engine learned from its own POST response, carrying a strict marker
    with *this finding's* fingerprint. With no known identity nothing is
    adopted (fail closed); the cost of a miss is only that the next review
    cannot update that comment.

    Degrades to a warning: without ids the only cost is that the next
    review cannot update that comment.
    """
    warnings: list[str] = []
    pending = [f for f in findings if not f.github_comment_id]
    if not pending or gh is None:
        return 0, warnings

    lister = getattr(gh, "list_review_comments", None)
    if not callable(lister):
        return 0, warnings
    ledger = process_ledger() if ledger is None else ledger
    stats = LifecycleStats() if stats is None else stats
    if ledger.identity is None:
        warnings.append("could not tell which GitHub account this review was posted "
                        "as; findings were left without a comment mapping for this "
                        "run (the engine never adopts a comment it cannot attribute "
                        "to itself).")
        return 0, warnings
    try:
        comments = lister(pr_number)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"could not list GitHub review comments "
                        f"({type(exc).__name__}); findings were left without a "
                        f"comment mapping for this run.")
        return 0, warnings

    by_key: dict[tuple[str, int | None], list[dict]] = {}
    for c in comments:
        if not isinstance(c, dict):
            continue
        by_key.setdefault((str(c.get("path") or ""),
                           c.get("line") or c.get("original_line")), []).append(c)

    linked = 0
    for f in pending:
        candidates = by_key.get(comment_key(f)) or []
        first_line = _first_line(render_finding_comment(f))
        expected_fp = _fingerprint_of(f)
        for c in sorted(candidates, key=lambda c: str(c.get("created_at") or ""),
                        reverse=True):
            if head_sha and c.get("commit_id") and c.get("commit_id") != head_sha:
                continue
            if _first_line(str(c.get("body") or "")) != first_line:
                continue
            if not ledger.adopt_inline_comment(c, expected_fp):
                stats.comments_refused_foreign += 1     # newer look-alike: skip it,
                continue                                # keep looking for the real one
            f.github_comment_id = _as_int(c.get("id"))
            linked += 1
            stats.comments_linked += 1
            break
    return linked, warnings


# ================================================================== sync

def _preflight_persisted(api: _CommentsAPI, ledger: OwnershipLedger,
                         f: Finding, comment_id: int, state_marker: str) -> str:
    """Extra check before editing an id loaded from storage.

    Runs only when the engine's identity is known (otherwise content is the
    only thing left to look at, and content can be copied): fetch the comment
    and require it to be authored by the engine, to carry this finding's
    marker (or, for a V3-era body, our exact rendering), and to not already
    show the state we are about to write.

    Returns ``"ok"``, ``"unchanged"``, ``"foreign"`` or ``"skip"`` (could not
    check - fetch failed or the client cannot fetch, so the PATCH is not sent
    on the strength of a check that did not happen).
    """
    try:
        payload = api.get_review_comment(comment_id)
    except _Unsupported:
        return "ok"                       # client can't fetch: V3 behaviour
    except GitHubError as exc:
        if exc.status_code == 404:
            raise                         # gone: same warning path as a PATCH 404
        _note_blocked(ledger, exc)
        return "skip"
    if not payload:
        return "skip"
    if not ledger.identity.matches(payload.get("user")):
        return "foreign"
    current = str(payload.get("body") or "").replace("\r\n", "\n")
    marker = parse_marker(current)
    if marker is not None:
        if marker.kind != "comment" or marker.fingerprint != _fingerprint_of(f):
            return "foreign"
    else:
        if _MARKER_LIKE_RE.search(current):
            return "foreign"              # marker-shaped but ambiguous: never ours
        if (_first_line(_strip_state_marker(current))
                != _first_line(render_finding_comment(f))):
            return "foreign"              # V3 body we cannot recognise
    if current.startswith(state_marker + "\n") or current == state_marker:
        return "unchanged"
    return "ok"


def sync_finding_states(gh, findings: list[Finding], *,
                        ledger: OwnershipLedger | None = None,
                        stats: LifecycleStats | None = None) -> tuple[int, list[str]]:
    """Update existing GitHub comments for findings that reached a closed
    (or reopened) state.

    ``gh`` may be None (local mode) and every failure becomes a warning -
    never an exception. Returns ``(comments updated, warnings)``.

    V4-E10: every edit goes through :func:`guarded_update` with a capability
    minted from the ownership ledger; ids loaded from storage get a
    pre-write check when the engine's identity is known; a comment already
    showing the target state is not rewritten; and once GitHub answers
    403/429 the remaining edits are skipped, not retried into the limit.
    """
    if gh is None:
        return 0, []
    updater = getattr(gh, "update_review_comment", None)
    if not callable(updater):
        return 0, []          # client too old / test double: nothing to sync

    ledger = process_ledger() if ledger is None else ledger
    stats = LifecycleStats() if stats is None else stats
    api = _CommentsAPI(gh)
    warnings: list[str] = []
    updated = 0
    errors = 0

    for f in findings:
        marker = STATE_MARKERS.get(str(getattr(f, "state", "") or ""))
        comment_id = _as_int(f.github_comment_id)
        if not marker or comment_id is None:
            continue
        if ledger.writes_blocked:
            stats.comments_skipped_blocked += 1
            continue
        ledger.record_persisted("review", comment_id)   # no-op if already known
        owned = ledger.mint("review", comment_id)
        body = f"{marker}\n\n{render_finding_comment(f)}"
        try:
            if (ledger.origin("review", comment_id) == "persisted"
                    and ledger.identity is not None and api.available):
                verdict = _preflight_persisted(api, ledger, f, comment_id, marker)
                if verdict == "foreign":
                    stats.comments_refused_foreign += 1
                    errors += 1
                    if errors <= MAX_SYNC_ERRORS:
                        warnings.append(
                            f"GitHub comment {comment_id} is not recognisably this "
                            f"engine's own comment; left it untouched.")
                    continue
                if verdict == "skip":
                    stats.comments_failed += 1
                    errors += 1
                    if errors <= MAX_SYNC_ERRORS:
                        warnings.append(
                            f"could not verify GitHub comment {comment_id} before "
                            f"updating it; left it untouched.")
                    continue
                if verdict == "unchanged":
                    stats.comments_unchanged += 1
                    continue
            guarded_update(gh, owned, body)
            updated += 1
            stats.comments_updated += 1
        except GitHubError as exc:
            errors += 1
            stats.comments_failed += 1
            _note_blocked(ledger, exc)
            if errors > MAX_SYNC_ERRORS:
                continue
            if exc.status_code == 404:
                warnings.append(
                    f"GitHub comment {comment_id} for '{f.title}' no longer "
                    f"exists (deleted?); kept the internal state "
                    f"({getattr(f, 'state', '?')}) without touching GitHub."
                )
            else:
                warnings.append(
                    f"could not update GitHub comment {comment_id} "
                    f"({type(exc).__name__}"
                    f"{f', {exc.status_code}' if exc.status_code else ''}); "
                    f"the internal review result is unchanged."
                )
        except Exception as exc:  # noqa: BLE001 - one bad comment must not lose a review
            errors += 1
            stats.comments_failed += 1
            if errors <= MAX_SYNC_ERRORS:
                warnings.append(
                    f"could not update GitHub comment {comment_id} "
                    f"({type(exc).__name__}); the internal review result is unchanged."
                )
        log.debug("sync: %s -> %s", f.fingerprint, f.state)

    if errors > MAX_SYNC_ERRORS:
        warnings.append(f"... {errors - MAX_SYNC_ERRORS} more GitHub comment "
                        f"update(s) skipped this run.")
    return updated, warnings


# ============================================================ sticky summary

def _normalise_body(text: object) -> str:
    return str(text or "").replace("\r\n", "\n").strip()


def sync_sticky_summary(gh, *, repo: str, pr_number: int, body: str,
                        ledger: OwnershipLedger | None = None,
                        stats: LifecycleStats | None = None) -> tuple[str, list[str]]:
    """Create or update THE engine-owned sticky summary comment (<= 1 per PR).

    ``body`` is ``reporter.render_sticky_summary(report)``; this function adds
    the hidden marker itself (markers are only ever engine-generated). Returns
    ``(action, warnings)`` with ``action`` one of ``created`` / ``updated`` /
    ``unchanged`` / ``skipped`` / ``failed``; every GitHub problem becomes a
    warning, never an exception.

    The "<= 1" guarantee, and why it is structural:

    * an existing sticky is found only by :meth:`OwnershipLedger.adopt_sticky_comment`
      (engine identity + strict marker + this repo/PR) - a foreign comment
      carrying a perfect marker is ignored, never edited;
    * a new one is created only after discovery *completed* and found none -
      a failed, blocked or truncated discovery skips rather than guesses;
    * a thread already at the platform soft cap gets no new engine comment;
    * stray extra stickies are counted, never touched (only recorded ids are
      ever edited or deleted).
    """
    ledger = process_ledger() if ledger is None else ledger
    stats = LifecycleStats() if stats is None else stats
    warnings: list[str] = []

    def skip(reason: str, warning: str | None = None) -> tuple[str, list[str]]:
        stats.set_sticky("skipped", reason)
        if warning:
            warnings.append(warning)
        return "skipped", warnings

    if gh is None:
        return skip("no_client")
    api = _CommentsAPI(gh)
    if not api.available:
        return skip("unsupported")
    try:
        marker_line = render_sticky_marker(repo, pr_number)
    except ValueError:
        return skip("invalid_scope")
    if not isinstance(body, str) or not body.strip() or len(body) > MAX_STICKY_BODY_CHARS:
        return skip("invalid_body")
    if ledger.writes_blocked:
        return skip("writes_blocked")
    if ledger.identity is None:
        return skip("identity_unknown",
                    "could not tell which GitHub account this review was posted as; "
                    "the sticky summary was not synced this run.")

    full_body = f"{neutralize_untrusted_markup(body).rstrip()}\n\n{marker_line}"

    # ---- discovery: bounded, and it must COMPLETE before we may create ------
    candidates: list[dict] = []
    scanned = 0
    complete = False
    try:
        for page in range(1, MAX_DISCOVERY_PAGES + 1):
            batch = api.list_issue_comments(pr_number, page)
            scanned += len(batch)
            for c in batch:
                marker = parse_marker(c.get("body"))
                if marker is None or marker.kind != "sticky":
                    continue
                if ledger.adopt_sticky_comment(c, repo, pr_number):
                    candidates.append(c)
                else:
                    stats.comments_refused_foreign += 1     # marker-shaped, not ours
            if len(batch) < _PER_PAGE:
                complete = True
                break
    except Exception as exc:  # noqa: BLE001
        blocked = _note_blocked(ledger, exc)
        status = getattr(exc, "status_code", None)
        return skip("writes_blocked" if blocked else "discovery_failed",
                    f"could not read the PR conversation to find the sticky summary "
                    f"({type(exc).__name__}{f', {status}' if status else ''}); "
                    f"it was not synced this run.")

    candidates.sort(key=lambda c: _as_int(c.get("id")) or 0)
    stats.sticky_duplicates_seen = max(0, len(candidates) - 1)

    # ---- update the one we own ---------------------------------------------
    if candidates:
        existing = candidates[0]
        cid = _as_int(existing.get("id"))
        if _normalise_body(existing.get("body")) == _normalise_body(full_body):
            stats.set_sticky("unchanged", None, cid)
            return "unchanged", warnings
        try:
            guarded_update(gh, ledger.mint("issue", cid), full_body)
        except Exception as exc:  # noqa: BLE001
            _note_blocked(ledger, exc)
            status = getattr(exc, "status_code", None)
            stats.set_sticky("failed", None, cid)
            warnings.append(f"could not update the sticky summary comment "
                            f"({type(exc).__name__}{f', {status}' if status else ''}); "
                            f"the internal review result is unchanged.")
            return "failed", warnings
        stats.set_sticky("updated", None, cid)
        return "updated", warnings

    # ---- none exists: may we add one? --------------------------------------
    if not complete:
        return skip("discovery_incomplete")
    if scanned >= PLATFORM_COMMENT_SOFT_CAP:
        return skip("platform_cap")
    try:
        created = api.create_issue_comment(pr_number, full_body)
    except Exception as exc:  # noqa: BLE001
        _note_blocked(ledger, exc)
        status = getattr(exc, "status_code", None)
        stats.set_sticky("failed")
        warnings.append(f"could not post the sticky summary comment "
                        f"({type(exc).__name__}{f', {status}' if status else ''}); "
                        f"the internal review result is unchanged.")
        return "failed", warnings
    new_id = _as_int(created.get("id"))
    ledger.learn_identity(created)
    if new_id is None or not ledger.record_created("issue", new_id):
        stats.set_sticky("failed")
        warnings.append("the sticky summary comment was posted but GitHub returned no "
                        "usable id; it will be found again by marker next run.")
        return "failed", warnings
    stats.set_sticky("created", None, new_id)
    return "created", warnings


__all__ = [
    "MAX_DISCOVERY_PAGES", "MAX_STICKY_BODY_CHARS", "MAX_SYNC_ERRORS",
    "PLATFORM_COMMENT_SOFT_CAP", "STATE_MARKERS", "STICKY_ACTIONS",
    "STICKY_SKIP_REASONS", "EngineIdentity", "EngineMarker",
    "ForeignCommentError", "LifecycleStats", "OwnedCommentId",
    "OwnershipLedger", "comment_key", "guarded_delete", "guarded_update",
    "identity_from_payload", "link_comment_ids", "neutralize_untrusted_markup",
    "parse_marker", "process_ledger", "record_comment_ids",
    "render_comment_marker", "render_finding_comment", "render_sticky_marker",
    "reset_process_ledger", "sync_finding_states", "sync_sticky_summary",
]
