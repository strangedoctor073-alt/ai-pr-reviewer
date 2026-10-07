"""V4-E01 — assembling one ephemeral index for a review run.

`build_index` is the only entry point: availability checks → inventory →
bounded reads + symbol extraction → import graph → a frozen
:class:`RepoIndex`. Design points that are ticket requirements, not
accidents:

* **ephemeral** — nothing here persists; the result lives on
  ``ReviewContext`` for the duration of one run (no ``repo_index``
  table, no cache file in V4's default path);
* **base-revision checkout** — the root is the checked-out tree (the
  Action checks out the PR base); when the checkout cannot be tied to
  the reviewed repository the build refuses with a warning instead of
  indexing an unknown tree;
* **degrade, never fail** — every unavailability path logs one warning
  and returns ``None``; every limit path returns a partial index with an
  explicit ``budget_state`` and warnings. A review never fails because
  of the index;
* **bounded warnings** — warning lists are capped so a pathological
  tree cannot flood the log (bounded expansion applies to diagnostics
  too).
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

from .graph import build_import_edges
from .inventory import walk_inventory
from .limits import IndexLimits, is_contained
from .symbols import extract_symbols

log = logging.getLogger(__name__)

#: Cap on stored/logged warnings per build (bounded expansion).
MAX_WARNINGS = 20

_GITDIR_RE = re.compile(r"^gitdir:\s*(.+)$", re.M)
_ORIGIN_URL_RE = re.compile(r'\[remote "origin"\](.*?)(?:\n\[|\Z)', re.S)


@dataclass(frozen=True)
class Symbol:
    """One extracted definition: ``kind`` is ``function``/``class``/``type``."""

    kind: str
    name: str
    line: int


@dataclass(frozen=True)
class FileEntry:
    """One inventoried file with its (bounded) extracted structure."""

    path: str
    size: int
    language: str
    changed: bool
    symbols: tuple[Symbol, ...] = ()
    imports: tuple[str, ...] = ()
    symbols_truncated: bool = False


@dataclass(frozen=True)
class RepoIndex:
    """Immutable snapshot of one run's repository index."""

    root: str
    files: tuple[FileEntry, ...]
    edges: tuple[tuple[str, str], ...]
    budget_state: str            # ok | truncated | exhausted
    warnings: tuple[str, ...]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(f.path for f in self.files)

    def file(self, path: str) -> FileEntry | None:
        for f in self.files:
            if f.path == path:
                return f
        return None

    def importers(self, path: str) -> tuple[str, ...]:
        """Files that import ``path`` (the reverse graph, sorted)."""
        return tuple(sorted(src for src, dst in self.edges if dst == path))


# ------------------------------------------------------------ availability

def _origin_url(root: str) -> str | None:
    """Read the ``origin`` remote URL from ``<root>/.git`` — by *reading*
    config files, never by running ``git`` (no process execution anywhere
    in the index build). Returns ``None`` when it cannot be determined
    (no origin remote, unreadable config, exotic layout): callers then
    treat the checkout as unverifiable rather than unusable."""
    git = os.path.join(root, ".git")
    config_path = None
    if os.path.isdir(git):
        config_path = os.path.join(git, "config")
    elif os.path.isfile(git):
        try:
            with open(git, encoding="utf-8", errors="replace") as fh:
                m = _GITDIR_RE.search(fh.read())
        except OSError:
            return None
        if m:
            gitdir = m.group(1).strip()
            if not os.path.isabs(gitdir):
                gitdir = os.path.join(root, gitdir)
            candidate = os.path.join(gitdir, "config")
            if os.path.isfile(candidate):
                config_path = candidate
    if not config_path or not os.path.isfile(config_path):
        return None
    try:
        with open(config_path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return None
    section = _ORIGIN_URL_RE.search(text)
    if not section:
        return None
    url = re.search(r"^\s*url\s*=\s*(\S+)", section.group(1), re.M)
    return url.group(1) if url else None


def _origin_slug(url: str) -> str:
    """``https://github.com/owner/repo.git`` / ``git@github.com:owner/repo``
    → ``owner/repo`` (lowercased), or ``""`` when unparseable."""
    u = url.strip().rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    if "://" in u:
        after = u.split("://", 1)[1]
        u = after.split("/", 1)[1] if "/" in after else ""
    elif "@" in u and ":" in u:
        u = u.split(":", 1)[1]
    return u.strip("/").lower()


def _availability_reason(root: str, expected_repo: str) -> str | None:
    """``None`` when the index may be built at ``root`` for ``expected_repo``.

    Requires a git checkout. When the reviewed repository is known *and*
    the checkout declares an origin remote, the two must agree — an
    index of the wrong tree must never silently feed context selection
    (trust boundary between "what we are reviewing" and "what we read").
    """
    git = os.path.join(root, ".git")
    if not os.path.exists(git):
        return f"no git checkout at {root!r}"
    origin = _origin_url(root)
    expected = (expected_repo or "").strip().lower()
    if origin and expected:
        slug = _origin_slug(origin)
        if slug and slug != expected:
            return (f"checkout origin {slug!r} does not match the reviewed "
                    f"repository {expected!r}")
    return None


# ------------------------------------------------------------------ build

def _cap_warnings(warnings: list[str]) -> tuple[str, ...]:
    if len(warnings) <= MAX_WARNINGS:
        return tuple(warnings)
    hidden = len(warnings) - MAX_WARNINGS
    return (*warnings[:MAX_WARNINGS], f"(+{hidden} more warning(s) suppressed)")


def build_index(root: str, *, expected_repo: str = "", changed_paths=(),
                exclusions=(), limits: IndexLimits | None = None) -> RepoIndex | None:
    """Build the ephemeral index for ``root`` — or return ``None``.

    ``None`` means *unavailable* (no checkout, origin mismatch, or an
    unexpected failure inside — the call never raises: an index problem
    must degrade to a log line, never break a review; declines log at
    INFO because absence is a supported state, failures at WARNING).
    ``budget_state`` on a returned index tells the partial story:
    ``truncated`` (file count or depth cap cut the inventory),
    ``exhausted`` (byte budget stopped symbol extraction), ``ok``
    (everything fit) — both non-``ok`` states warn loudly.

    ``exclusions`` must be the trusted policy's combined list
    (``ReviewPolicy.exclude`` carries the non-removable privacy
    baseline; ``context._build_repo_index`` is the seam that supplies
    it — direct callers are responsible for passing theirs).
    """
    limits = limits or IndexLimits()
    try:
        reason = _availability_reason(root, expected_repo)
        if reason is not None:
            # Declining to build is a *supported* degraded state in E01
            # (nothing consumes the index yet and review output is
            # unchanged), so it logs at INFO; limit exhaustion and
            # unexpected failures stay at WARNING below.
            log.info("repository index unavailable: %s", reason)
            return None

        walked, state, warnings = walk_inventory(root, limits, exclusions)

        changed = {p.replace("\\", "/").strip() for p in changed_paths}
        entries: list[FileEntry] = []
        bytes_read = 0
        exhausted = False
        for walk in walked:
            symbols: list[tuple[str, str, int]] = []
            imports: list[str] = []
            truncated = False
            if walk.size > limits.max_file_bytes:
                pass  # giant file: inventory entry only, no read
            elif exhausted or bytes_read + walk.size > limits.max_bytes:
                if not exhausted:
                    exhausted = True
                    state = "exhausted"
                    warnings.append(
                        f"index: byte budget ({limits.max_bytes}) exhausted — "
                        f"symbol extraction stopped after {len(entries)} file(s)")
            else:
                if not is_contained(root, walk.path):
                    warnings.append(
                        f"index: path rejected (outside checkout): {walk.path}")
                    continue
                full = os.path.join(root, walk.path)
                try:
                    with open(full, "rb") as fh:
                        data = fh.read()
                except OSError as exc:
                    warnings.append(
                        f"index: unreadable file skipped "
                        f"({type(exc).__name__}): {walk.path}")
                    continue
                bytes_read += len(data)
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    continue  # binary masquerading as a text suffix
                symbols, imports, truncated = extract_symbols(
                    walk.path, walk.language, text, limits)

            entries.append(FileEntry(
                path=walk.path,
                size=walk.size,
                language=walk.language,
                changed=walk.path in changed,
                symbols=tuple(Symbol(*s) for s in symbols),
                imports=tuple(imports),
                symbols_truncated=truncated,
            ))

        edges, edge_warnings = build_import_edges(entries, limits)
        warnings.extend(edge_warnings)

        index = RepoIndex(
            root=os.path.normpath(root),
            files=tuple(entries),
            edges=tuple(edges),
            budget_state=state,
            warnings=_cap_warnings(warnings),
        )
        if state != "ok":
            log.warning("repository index built partially (%s): %s",
                        state, "; ".join(index.warnings[:3]))
        return index
    except Exception as exc:  # noqa: BLE001 — belt-and-braces: never break a review
        log.warning("repository index build failed: %s", exc)
        return None
