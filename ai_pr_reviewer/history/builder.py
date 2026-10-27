"""V4.4-E01-T01 — bounded git history index (commits, churn, co-change).

A per-run, read-only view of recent history built from local ``git log``:

* **commits** in a bounded window (count *and* age, the age measured from
  the HEAD commit's own timestamp so a build is reproducible);
* **churn** per path (commits, lines added/deleted, last change);
* **co-change** pairs (paths changed together in the same commit).

Invariants (each pinned by ``tests/test_history_index.py``):

* **Authorship is role-only.** By default ``git log`` is asked for sha,
  parents, commit time and subject only — no author/committer name or email
  enters the process. With ``HistoryLimits.include_roles`` (off by default)
  the author e-mail is read transiently to derive a coarse ``bot|human``
  role per commit and is discarded at once; no identity is stored, and no
  per-developer count, score or ranking exists anywhere (V4.4-E01-T04).
* **Ephemeral and additive.** Nothing is persisted, no storage table is
  added (so no ADR-gated schema work), no report field changes.
* **Never raises, degrades loudly.** Every degraded outcome sets
  ``state`` (``ok | shallow | truncated | unavailable``) and a content-free
  reason; a shallow clone is labelled, not hidden.
* **Privacy baseline applies.** Paths matching the non-removable
  ``SENSITIVE_EXCLUDE_GLOBS`` (plus caller exclusions and vendor/lockfile
  paths) never enter the index, exactly as for the repository index.
* **Commit subjects are untrusted.** They are control-character stripped,
  secret-redacted and length-capped at ingest. The index is NOT
  prompt-reachable in T01; fencing at retrieval is T03's contract.
* **Record framing cannot be forged.** Records are delimited by a per-run
  random marker, so a crafted commit subject cannot inject a fake commit.
"""
from __future__ import annotations

import os
import posixpath
import re
import secrets
import unicodedata
from dataclasses import dataclass, field

from ..index.limits import BuildDeadline, is_excluded, is_vendor_or_minified
from ..repo_context import _safe_repo_path
from ..rules import SENSITIVE_EXCLUDE_GLOBS
from ..security import redact_secrets
from .git_read import GitResult, run_git
from .limits import (MAX_SUBJECT_CHARS, SUBJECT_REDACTION_WINDOW,
                     HistoryLimits)

HISTORY_OK = "ok"
HISTORY_SHALLOW = "shallow"
HISTORY_TRUNCATED = "truncated"
HISTORY_UNAVAILABLE = "unavailable"
HISTORY_STATES = (HISTORY_OK, HISTORY_SHALLOW, HISTORY_TRUNCATED,
                  HISTORY_UNAVAILABLE)

ROLE_BOT = "bot"
ROLE_HUMAN = "human"
ROLE_UNKNOWN = "unknown"
ROLES = (ROLE_BOT, ROLE_HUMAN, ROLE_UNKNOWN)
_BOT_RE = re.compile(
    r"(\[bot\]|\bdependabot\b|\brenovate\b|\bgithub-actions\b|\bsnyk-bot\b)",
    re.I)

_SHA_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$")
_FS = "\x1f"
_SECONDS_PER_DAY = 86_400
_MAX_SHALLOW_BOUNDARIES = 10_000


# --------------------------------------------------------------------------- records

@dataclass(frozen=True)
class CommitRecord:
    """One commit in the window. Deliberately has no author fields."""

    sha: str
    committed_at: int
    #: Sanitized (control chars stripped, secrets redacted, capped). Still
    #: untrusted text: it must be fenced before it reaches any prompt.
    subject: str
    parent_count: int
    #: Paths changed (privacy-filtered). Empty for merge commits (git shows
    #: no diff for them), shallow-boundary commits and bulk commits.
    paths: tuple[str, ...] = ()
    #: Touched more paths than ``max_files_per_commit`` — excluded from
    #: churn and co-change.
    is_bulk: bool = False
    #: The oldest commit of a shallow clone. Git reports its whole tree as
    #: added; counting that as churn would be false signal.
    is_boundary: bool = False
    #: Coarse author ROLE only (``bot`` | ``human`` | ``unknown``), derived
    #: transiently at parse time and only when ``limits.include_roles`` is
    #: set. The identity it was derived from is discarded immediately. It is
    #: never aggregated per person and never used to rank anything.
    role: str = ROLE_UNKNOWN


@dataclass(frozen=True)
class PathChurn:
    path: str
    commits: int
    lines_added: int
    lines_deleted: int
    last_changed_at: int


@dataclass(frozen=True)
class CoChange:
    """Two paths changed in the same commit ``count`` times (``path_a`` <
    ``path_b``)."""

    path_a: str
    path_b: str
    count: int


@dataclass(frozen=True)
class HistoryStats:
    """Counts only — safe for logs and telemetry."""

    commits_seen: int = 0
    commits_in_window: int = 0
    bulk_commits_skipped: int = 0
    boundary_commits: int = 0
    malformed_records: int = 0
    paths_filtered: int = 0
    odd_paths_skipped: int = 0


@dataclass(frozen=True)
class HistoryIndex:
    state: str
    head_sha: str = ""
    shallow: bool = False
    #: Content-free human text explaining any degradation.
    reasons: tuple[str, ...] = ()
    #: Epoch seconds; commits older than this are outside the window.
    window_start: int = 0
    limits: HistoryLimits = field(default_factory=HistoryLimits)
    commits: tuple[CommitRecord, ...] = ()
    churn: tuple[PathChurn, ...] = ()
    co_change: tuple[CoChange, ...] = ()
    stats: HistoryStats = field(default_factory=HistoryStats)

    @property
    def is_available(self) -> bool:
        return self.state != HISTORY_UNAVAILABLE

    def summary(self) -> dict:
        """Counts-only view (no paths, no subjects)."""
        return {
            "state": self.state,
            "shallow": self.shallow,
            "commits": len(self.commits),
            "churn_paths": len(self.churn),
            "co_change_pairs": len(self.co_change),
            "reasons": list(self.reasons),
            **{k: getattr(self.stats, k) for k in HistoryStats.__dataclass_fields__},
        }


def _unavailable(limits: HistoryLimits, reason: str) -> HistoryIndex:
    return HistoryIndex(state=HISTORY_UNAVAILABLE, reasons=(reason,),
                        limits=limits)


# --------------------------------------------------------------------------- text hygiene

def clean_subject(raw: str) -> str:
    """Untrusted commit subject -> bounded, redacted, single-line text.

    Order matters: strip invisible/control characters first (so they cannot
    split a credential pattern), redact on a generous prefix, and only then
    apply the display cap (so a cap can never cut a secret into an
    unredacted fragment).
    """
    text = (raw or "")[:SUBJECT_REDACTION_WINDOW]
    text = "".join(
        " " if ch in "\t\r\n\x0b\x0c" else ch
        for ch in text
        if ch in "\t\r\n\x0b\x0c" or unicodedata.category(ch)[0] != "C")
    text = " ".join(text.split())
    text = redact_secrets(text)
    if len(text) > MAX_SUBJECT_CHARS:
        text = text[:MAX_SUBJECT_CHARS - 3].rstrip() + "..."
    return text


# --------------------------------------------------------------------------- git helpers

def classify_role(identity: str) -> str:
    """Map a transient author identity string to a coarse role. The caller
    must not keep ``identity``; only the returned role is stored."""
    if not identity or not identity.strip():
        return ROLE_UNKNOWN
    return ROLE_BOT if _BOT_RE.search(identity[:320]) else ROLE_HUMAN


def _text(result: GitResult) -> str:
    return result.stdout.decode("utf-8", errors="replace").strip()


def _read_boundaries(root: str, limits: HistoryLimits, runner) -> frozenset[str]:
    """SHAs listed in the checkout's ``shallow`` file (contained in root)."""
    res = runner(root, ["rev-parse", "--git-path", "shallow"],
                 max_output_bytes=4_096, timeout=limits.max_seconds)
    if not res.ok:
        return frozenset()
    rel = _text(res)
    path = rel if os.path.isabs(rel) else os.path.join(root, rel)
    try:
        real_root = os.path.normcase(os.path.realpath(root))
        real_path = os.path.normcase(os.path.realpath(path))
        if not real_path.startswith(real_root + os.sep):
            return frozenset()
        out: set[str] = set()
        with open(real_path, encoding="utf-8", errors="replace") as fh:
            for i, line in enumerate(fh):
                if i >= _MAX_SHALLOW_BOUNDARIES:
                    break
                sha = line.strip()
                if _SHA_RE.match(sha):
                    out.add(sha)
        return frozenset(out)
    except OSError:
        return frozenset()


def _accept_path(raw: str, exclusions: tuple[str, ...]) -> tuple[str | None, str]:
    """``(path, why_not)``: a normalized repo-relative path or the reason it
    was dropped (``odd`` | ``filtered``)."""
    if not raw or raw.startswith('"'):
        return None, "odd"
    safe = _safe_repo_path(raw)
    if safe is None or posixpath.normpath(raw) != safe:
        return None, "odd"
    if is_vendor_or_minified(safe) or is_excluded(safe, exclusions):
        return None, "filtered"
    return safe, ""


def _parse_log(text: str, marker: str, *, limits: HistoryLimits,
               boundaries: frozenset[str], exclusions: tuple[str, ...],
               ) -> tuple[list[CommitRecord], dict[str, int],
                          dict[str, list[tuple[int, int]]]]:
    """Parse ``git log --numstat`` output into records.

    Returns ``(commits, counters, line_counts)`` where ``line_counts`` maps
    ``sha`` -> per-path ``(added, deleted)`` kept aligned with
    ``CommitRecord.paths``.
    """
    counters = {"malformed": 0, "odd": 0, "filtered": 0}
    commits: list[CommitRecord] = []
    lines_by_sha: dict[str, list[tuple[int, int]]] = {}
    for chunk in text.split(marker)[1:]:
        header, _, body = chunk.partition("\n")
        want = 5 if limits.include_roles else 4
        parts = header.split(_FS, want - 1)
        if len(parts) != want:
            counters["malformed"] += 1
            continue
        if limits.include_roles:
            sha, parents_raw, ct_raw, identity, subject = parts
            role = classify_role(identity)
            del identity  # role only: the identity is dropped here
        else:
            sha, parents_raw, ct_raw, subject = parts
            role = ROLE_UNKNOWN
        parents = parents_raw.split()
        if (not _SHA_RE.match(sha) or not ct_raw.isdigit()
                or not all(_SHA_RE.match(p) for p in parents)):
            counters["malformed"] += 1
            continue
        paths: list[str] = []
        nums: list[tuple[int, int]] = []
        for line in body.splitlines():
            if not line.strip():
                continue
            fields = line.split("\t", 2)
            if len(fields) != 3:
                counters["malformed"] += 1
                continue
            added_raw, deleted_raw, raw_path = fields
            path, why = _accept_path(raw_path, exclusions)
            if path is None:
                counters["odd" if why == "odd" else "filtered"] += 1
                continue
            paths.append(path)
            nums.append((int(added_raw) if added_raw.isdigit() else 0,
                         int(deleted_raw) if deleted_raw.isdigit() else 0))
        boundary = sha in boundaries
        bulk = len(paths) > limits.max_files_per_commit
        keep = not boundary and not bulk
        commits.append(CommitRecord(
            sha=sha, committed_at=int(ct_raw),
            subject=clean_subject(subject), parent_count=len(parents),
            paths=tuple(paths) if keep else (),
            is_bulk=bulk and not boundary, is_boundary=boundary, role=role))
        lines_by_sha[sha] = nums if keep else []
    return commits, counters, lines_by_sha


# --------------------------------------------------------------------------- build

def build_history_index(root, *, exclusions=(), limits: HistoryLimits | None = None,
                        deadline: BuildDeadline | None = None,
                        runner=run_git) -> HistoryIndex:
    """Build the bounded history index for the checkout at ``root``.

    Never raises: any failure returns an ``unavailable`` index with a
    content-free reason. ``exclusions`` are caller globs added to the
    non-removable privacy baseline. ``runner`` is a test seam for the git
    executor.
    """
    limits = limits or HistoryLimits()
    try:
        return _build(root, tuple(exclusions or ()), limits, deadline, runner)
    except Exception as exc:  # noqa: BLE001 — history is a bonus, never fatal
        return _unavailable(
            limits, f"history: build failed unexpectedly ({type(exc).__name__})")


def _build(root, exclusions, limits, deadline, runner) -> HistoryIndex:
    root_s = os.fspath(root) if root is not None else ""
    if not root_s or not os.path.isdir(root_s):
        return _unavailable(limits, "history: no checkout directory")
    root_real = os.path.realpath(root_s)
    if not os.path.exists(os.path.join(root_real, ".git")):
        return _unavailable(
            limits, "history: no git checkout (fetch-depth: 0 on the "
                    "checkout step provides history)")
    deadline = deadline or BuildDeadline(limits.max_seconds)
    all_exclusions = (*SENSITIVE_EXCLUDE_GLOBS, *exclusions)

    head = runner(root_real, ["rev-parse", "--verify", "--quiet", "HEAD"],
                  max_output_bytes=4_096, timeout=limits.max_seconds)
    if head.unavailable:
        return _unavailable(limits, "history: git is not available")
    head_sha = _text(head)
    if not head.ok or not _SHA_RE.match(head_sha):
        return _unavailable(
            limits, "history: repository has no readable commits")

    shallow_res = runner(root_real, ["rev-parse", "--is-shallow-repository"],
                         max_output_bytes=64, timeout=limits.max_seconds)
    shallow = shallow_res.ok and _text(shallow_res) == "true"
    boundaries = (_read_boundaries(root_real, limits, runner)
                  if shallow else frozenset())

    marker = "@@HIST" + secrets.token_hex(8) + "@@"
    log_res = runner(
        root_real,
        ["log", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
         "--numstat", f"--max-count={limits.max_commits + 1}",
         f"--format={marker}%H{_FS}%P{_FS}%ct{_FS}"
         + (f"%ae{_FS}" if limits.include_roles else "") + "%s",
         "HEAD", "--"],
        max_output_bytes=limits.max_output_bytes, timeout=limits.max_seconds)
    if log_res.unavailable:
        return _unavailable(limits, "history: git is not available")
    if not log_res.ok and not (log_res.output_capped or log_res.timed_out):
        return _unavailable(limits, "history: git log failed")

    reasons: list[str] = []
    truncated = False
    raw_text = log_res.stdout.decode("utf-8", errors="replace")
    if log_res.output_capped:
        # The last record is incomplete; drop it rather than parse a stump.
        raw_text = raw_text[:raw_text.rfind(marker)] if marker in raw_text else ""
        truncated = True
        reasons.append("history: git output hit the size cap — older commits "
                       "not indexed")
    if log_res.timed_out:
        raw_text = raw_text[:raw_text.rfind(marker)] if marker in raw_text else ""
        truncated = True
        reasons.append("history: time budget exhausted reading git history — "
                       "older commits not indexed")

    commits, counters, line_nums = _parse_log(
        raw_text, marker, limits=limits, boundaries=boundaries,
        exclusions=all_exclusions)

    seen = len(commits)
    if seen > limits.max_commits:
        commits = commits[:limits.max_commits]
        truncated = True
        reasons.append(f"history: commit window capped at "
                       f"{limits.max_commits} commits — older history not "
                       "indexed")

    head_time = commits[0].committed_at if commits else 0
    window_start = max(0, head_time - limits.max_days * _SECONDS_PER_DAY)
    in_window = [c for c in commits if c.committed_at >= window_start]

    churn_acc: dict[str, list[int]] = {}
    pair_acc: dict[tuple[str, str], int] = {}
    paths_capped = pairs_capped = deadline_hit = False
    for commit in in_window:
        if deadline.expired():
            deadline_hit = True
            break
        nums = line_nums.get(commit.sha, [])
        for path, (added, deleted) in zip(commit.paths, nums):
            acc = churn_acc.get(path)
            if acc is None:
                if len(churn_acc) >= limits.max_tracked_paths:
                    paths_capped = True
                    continue
                acc = churn_acc[path] = [0, 0, 0, 0]
            acc[0] += 1
            acc[1] += added
            acc[2] += deleted
            acc[3] = max(acc[3], commit.committed_at)
        unique = sorted(set(p for p in commit.paths if p in churn_acc))
        for i, a in enumerate(unique):
            for b in unique[i + 1:]:
                key = (a, b)
                if key in pair_acc:
                    pair_acc[key] += 1
                elif len(pair_acc) >= limits.max_co_change_pairs:
                    pairs_capped = True
                else:
                    pair_acc[key] = 1
    if deadline_hit:
        truncated = True
        reasons.append(f"history: time budget ({deadline.seconds:g}s) "
                       "exhausted while aggregating — newer-first partial "
                       "result")
    if paths_capped:
        truncated = True
        reasons.append(f"history: churn tracking capped at "
                       f"{limits.max_tracked_paths} paths")
    if pairs_capped:
        truncated = True
        reasons.append(f"history: co-change capped at "
                       f"{limits.max_co_change_pairs} pairs")
    if shallow:
        reasons.insert(0, "history: shallow clone — history before the clone "
                          "boundary is unavailable (fetch-depth: 0 gives full "
                          "history)")

    bulk = sum(1 for c in in_window if c.is_bulk)
    boundary_n = sum(1 for c in in_window if c.is_boundary)
    stats = HistoryStats(
        commits_seen=seen, commits_in_window=len(in_window),
        bulk_commits_skipped=bulk, boundary_commits=boundary_n,
        malformed_records=counters["malformed"],
        paths_filtered=counters["filtered"], odd_paths_skipped=counters["odd"])

    state = (HISTORY_TRUNCATED if truncated
             else HISTORY_SHALLOW if shallow else HISTORY_OK)
    return HistoryIndex(
        state=state, head_sha=head_sha, shallow=shallow,
        reasons=tuple(reasons), window_start=window_start, limits=limits,
        commits=tuple(in_window),
        churn=tuple(
            PathChurn(p, v[0], v[1], v[2], v[3])
            for p, v in sorted(churn_acc.items())),
        co_change=tuple(
            CoChange(a, b, n) for (a, b), n in
            sorted(pair_acc.items(), key=lambda kv: (-kv[1], kv[0]))),
        stats=stats)
