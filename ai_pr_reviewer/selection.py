"""Context selection over the repository index (V4-E02, ADR-017).

Implements the approved **selection contract**: an explicit, deterministic
mapping of *which* repository files enter a review prompt and *why*. Every
selected file carries a reason from a closed set, a rank, a relationship and
its size; every excluded file carries a reason. Ordering is deterministic:
reason priority -> rank -> path.

Contract guarantees (ADR-017):
  * **Closed reason set.** ``changed | adjacent | import | importer |
    test_of | config_of | manual``. A new reason is a contract change, not
    an accident of a caller string.
  * **Explainable.** Any file in a prompt can answer "why am I here?"
    (``SelectedFile.reason`` + ``relationship``), and de-selection is
    auditable (``ExcludedFile.reason``).
  * **Deterministic.** Retrieval is lexical/symbolic over the index -- no
    embeddings, no vector DB, no ranking service, no model. Same inputs,
    same ordering, always.
  * **Budgeted, never silent.** The result carries a ``budget_state``
    (``ok | truncated | exhausted``) matching the index's own vocabulary,
    so running out of room is a controlled, reported state.
  * **Degrades honestly.** With no index there is no selection: callers
    keep today's behaviour and add a warning -- never a crash.

Selection is a *signal provider*, not a prompt itself: content is read and
fenced elsewhere (``context.py`` / the providers), and impact analysis
(``impact.py``) feeds it as an extra relationship so blast-radius files
are pulled in deliberately.
"""
from __future__ import annotations

from dataclasses import dataclass

from .index import RepoIndex
from .impact import ImpactResult

# --- closed sets (ADR-017) --------------------------------------------------
REASON_CHANGED = "changed"
REASON_IMPORT = "import"        # a file the diff's files import
REASON_IMPORTER = "importer"    # a file that imports the diff's files
REASON_TEST_OF = "test_of"      # a test file for a changed module
REASON_CONFIG_OF = "config_of"  # project configuration relevant to the change
REASON_ADJACENT = "adjacent"    # same-directory neighbour (weak signal)
REASON_MANUAL = "manual"        # explicitly requested (config), never inferred

#: The closed reason set. Order here defines reason *priority* (lower wins).
REASON_PRIORITY: dict[str, int] = {
    REASON_CHANGED: 0,
    REASON_IMPORT: 1,
    REASON_IMPORTER: 1,
    REASON_TEST_OF: 2,
    REASON_CONFIG_OF: 3,
    REASON_ADJACENT: 4,
    REASON_MANUAL: 5,
}
ALLOWED_REASONS = frozenset(REASON_PRIORITY)

#: budget_state vocabulary -- shared with RepoIndex so there is one budget
#: language across the intelligence subsystem (never two).
STATE_OK = "ok"
STATE_TRUNCATED = "truncated"
STATE_EXHAUSTED = "exhausted"
BUDGET_STATES = (STATE_OK, STATE_TRUNCATED, STATE_EXHAUSTED)

# Bounded everything. Selection can never flood the prompt: a hard file cap
# and a byte ceiling (the outer ``context-budget`` ceiling is honoured by
# the caller; these bound the *candidate* set before content is read).
DEFAULT_MAX_SELECTED = 24
HARD_MAX_SELECTED = 100

# Relationship-class -> why a file is here, rendered for humans. Kept short
# and deterministic; the *reason* is the machine contract, this is prose.
_RELATIONSHIP_NOTE = {
    REASON_CHANGED: "changed in this PR",
    REASON_IMPORT: "imported by a changed file",
    REASON_IMPORTER: "imports a changed file",
    REASON_TEST_OF: "test of a changed module",
    REASON_CONFIG_OF: "project configuration",
    REASON_ADJACENT: "same directory as a changed file",
    REASON_MANUAL: "requested by repository policy",
}

# Files the index cannot usefully read as "context" but that reviewers care
# about; matched by basename (config_of). Kept deliberately small and
# explicit -- never a glob over the whole tree.
_CONFIG_BASENAMES = (
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "package.json", "tsconfig.json", "Makefile", "Dockerfile",
    ".ai-pr-reviewer.yml", "go.mod", "Cargo.toml",
)


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(value)))


# Test-file naming conventions across the languages the index covers. A
# change to ``billing.py`` should surface ``test_billing.py`` (pytest),
# ``billing_test.go`` (Go), ``billing.test.ts`` / ``billing.spec.ts`` (JS/TS)
# and ``billing_spec.rb`` alike -- the closed ``test_of`` reason is only as
# useful as the conventions it can recognise.
_TEST_PREFIXES = ("test_", "tests_", "test.")
_TEST_SUFFIXES = ("_test", "_tests", ".test", ".spec", "_spec")
_TEST_DIRS = frozenset({"tests", "test", "__tests__"})


def _base_stem(path: str) -> str:
    """``src/auth/service.py`` -> ``service``; ``test_auth.py`` -> ``auth``;
    ``auth_test.go`` / ``auth.test.ts`` / ``auth.spec.ts`` -> ``auth``."""
    name = path.rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    for prefix in _TEST_PREFIXES:
        if stem.startswith(prefix) and len(stem) > len(prefix):
            return stem[len(prefix):]
    for suffix in _TEST_SUFFIXES:
        if stem.endswith(suffix) and len(stem) > len(suffix):
            return stem[:-len(suffix)]
    return stem


def _is_test_path(path: str) -> bool:
    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    stem = name.rsplit(".", 1)[0] if "." in name else name
    directories = lowered.split("/")[:-1]
    return (stem.startswith(_TEST_PREFIXES)
            or stem.endswith(_TEST_SUFFIXES)
            or any(d in _TEST_DIRS for d in directories))


@dataclass(frozen=True)
class SelectedFile:
    """One file chosen for the prompt, with everything needed to explain it."""

    path: str
    reason: str          # one of ALLOWED_REASONS
    rank: int            # 0 = the diff itself; higher = further from the change
    relationship: str    # human-readable link to the change
    size: int            # bytes at index time (0 when unknown)

    @property
    def priority(self) -> int:
        return REASON_PRIORITY[self.reason]

    def to_dict(self) -> dict:
        return {"path": self.path, "reason": self.reason, "rank": self.rank,
                "relationship": self.relationship, "size": self.size}


@dataclass(frozen=True)
class ExcludedFile:
    """A candidate considered but not selected, with the reason (ADR-017:
    'every exclusion carries a reason' -- de-selection must be auditable)."""

    path: str
    reason: str          # why it was dropped (budget | over_cap | not_indexed)

    def to_dict(self) -> dict:
        return {"path": self.path, "reason": self.reason}


@dataclass(frozen=True)
class ContextSelection:
    """The ADR-017 selection contract returned to ``context.py``."""

    selected_files: tuple[SelectedFile, ...]
    excluded_files: tuple[ExcludedFile, ...]
    budget_state: str          # ok | truncated | exhausted

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(f.path for f in self.selected_files)

    @property
    def is_empty(self) -> bool:
        return not self.selected_files

    def to_dict(self) -> dict:
        return {
            "selected_files": [f.to_dict() for f in self.selected_files],
            "excluded_files": [f.to_dict() for f in self.excluded_files],
            "budget_state": self.budget_state,
        }


def _sort_key(f: SelectedFile) -> tuple[int, int, str]:
    """ADR-017 ordering: reason priority -> rank -> path. Fully stable."""
    return (f.priority, f.rank, f.path)


def select_context(
    index: RepoIndex | None,
    changed_paths: list[str] | tuple[str, ...],
    *,
    impact: ImpactResult | None = None,
    max_selected: int = DEFAULT_MAX_SELECTED,
    budget_chars: int | None = None,
) -> ContextSelection | None:
    """Build the deterministic selection contract for one review.

    Returns ``None`` when there is no index -- the caller keeps today's
    behaviour and warns (ADR-017: "fall back to today's behavior with a
    warning, never a crash"). ``impact`` (V4-E03) is optional: when
    present its entries are folded in as ``importer``-class context at a
    deeper rank, so blast radius deliberately reaches the prompt.
    """
    if index is None:
        return None

    changed = sorted({p for p in (changed_paths or []) if p})
    cap = _clamp(max_selected, 1, HARD_MAX_SELECTED)
    sizes = {f.path: f.size for f in index.files}
    all_paths = index.paths

    # Forward / reverse import maps and the directory map are built ONCE.
    # The old per-changed-file edge rescans made selection O(changed * E);
    # on the largest permitted index that is the difference between meeting
    # and missing the ADR-017 overhead budget (p95 < 500 ms).
    forward: dict[str, set[str]] = {}
    reverse: dict[str, set[str]] = {}
    for src, dst in index.edges:
        forward.setdefault(src, set()).add(dst)
        reverse.setdefault(dst, set()).add(src)
    by_directory: dict[str, list[str]] = {}
    for path in all_paths:
        by_directory.setdefault(path.rsplit("/", 1)[0] if "/" in path else "",
                                []).append(path)

    # path -> best (reason, rank, relationship) seen. A file reachable by
    # several relationships keeps the strongest (lowest reason priority,
    # then lowest rank) so the explanation is the most informative one.
    best: dict[str, SelectedFile] = {}

    def offer(path: str, reason: str, rank: int, relationship: str) -> None:
        if reason not in ALLOWED_REASONS:  # defensive: closed set is law
            return
        entry = SelectedFile(path=path, reason=reason, rank=rank,
                             relationship=relationship,
                             size=sizes.get(path, 0))
        prev = best.get(path)
        if prev is None or _sort_key(entry) < _sort_key(prev):
            best[path] = entry

    # 0. the diff itself -- always the strongest signal.
    for p in changed:
        offer(p, REASON_CHANGED, 0, _RELATIONSHIP_NOTE[REASON_CHANGED])

    indexed = set(all_paths)

    # 1. structure: imports of and importers of the changed files.
    #    The index stores resolved edges (spec -> inventoried path), so
    #    the graph -- not the raw import specs -- is the source of truth.
    for p in changed:
        for dep in sorted(forward.get(p, ())):
            offer(dep, REASON_IMPORT, 1,
                  f"{_RELATIONSHIP_NOTE[REASON_IMPORT]} ({p})")
        for importer in sorted(reverse.get(p, ())):
            offer(importer, REASON_IMPORTER, 1,
                  f"{_RELATIONSHIP_NOTE[REASON_IMPORTER]} ({p})")

    # 2. impact closure (V4-E03) -- deeper dependents reach the prompt with
    #    an honest, weaker rank so they never outrank direct context.
    if impact is not None:
        for e in impact.entries:
            offer(e.path, REASON_IMPORTER, 1 + e.hop,
                  f"impact: {e.confidence} dependent (hop {e.hop}"
                  + (f" via {e.via}" if e.via else "") + ")")

    # 3. tests of changed modules + config, matched against the index.
    changed_stems = {_base_stem(p) for p in changed}
    for path in all_paths:
        if _is_test_path(path) and _base_stem(path) in changed_stems:
            offer(path, REASON_TEST_OF, 2, _RELATIONSHIP_NOTE[REASON_TEST_OF])
        base = path.rsplit("/", 1)[-1]
        if base in _CONFIG_BASENAMES:
            offer(path, REASON_CONFIG_OF, 3, _RELATIONSHIP_NOTE[REASON_CONFIG_OF])

    # 4. same-directory neighbours, last (weakest) -- only for changed
    #    files that are themselves indexed, and only within the cap.
    for p in changed:
        if p not in indexed:
            continue
        directory = p.rsplit("/", 1)[0] if "/" in p else ""
        for path in by_directory.get(directory, ()):
            if path != p:
                offer(path, REASON_ADJACENT, 4,
                      f"{_RELATIONSHIP_NOTE[REASON_ADJACENT]} ({directory or '.'})")

    # Order deterministically, then apply the file cap with an honest
    # exclusion list (nothing is dropped silently).
    ordered = sorted(best.values(), key=_sort_key)
    selected = [f for f in ordered if f.path in indexed or f.reason == REASON_CHANGED]
    unindexed = [f for f in ordered if f.path not in indexed and f.reason != REASON_CHANGED]

    truncated_files = selected[cap:]
    selected = selected[:cap]

    excluded = [ExcludedFile(path=f.path, reason="not_indexed") for f in unindexed]
    excluded += [ExcludedFile(path=f.path, reason="over_cap") for f in truncated_files]

    # Optional byte ceiling over the *selected set* (content is read by the
    # caller; this bounds what it will ask for). Changed files are never
    # budget-dropped -- the diff is not optional context.
    if budget_chars is not None and budget_chars > 0:
        spent = 0
        kept: list[SelectedFile] = []
        dropped: list[SelectedFile] = []
        for f in selected:
            if f.reason == REASON_CHANGED:
                spent += f.size
                kept.append(f)
                continue
            if spent + f.size <= budget_chars:
                spent += f.size
                kept.append(f)
            else:
                dropped.append(f)
        excluded += [ExcludedFile(path=f.path, reason="budget") for f in dropped]
        selected = kept
    else:
        dropped = []

    # budget_state mirrors the index's own state, upgraded to "truncated"
    # whenever this selection itself dropped something. "exhausted" is
    # reserved for an index that ran out of room while building.
    state = index.budget_state if index.budget_state in BUDGET_STATES else STATE_OK
    if (truncated_files or dropped or unindexed) and state == STATE_OK:
        state = STATE_TRUNCATED

    return ContextSelection(
        selected_files=tuple(f for f in sorted(selected, key=_sort_key)),
        excluded_files=tuple(sorted(excluded, key=lambda e: (e.reason, e.path))),
        budget_state=state,
    )
