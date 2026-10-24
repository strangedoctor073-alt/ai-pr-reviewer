"""Change-impact analysis over the repository index (V4-E03).

Given the files a diff touched, compute *what else it affects* -- the
importers (dependents) of those files, propagated a bounded number of hops
through the index's file-level import graph. Purely an analysis over index
data: no runtime code execution, no network, no model.

Scope and honesty constraints (V4-E03):
  * Resolution is **index-only**. We never guess a symbol we could not
    resolve; a changed file that is not in the index (a new file, a path
    the index skipped) is reported with ``unknown`` confidence rather than
    silently treated as "no dependents".
  * Traversal is **bounded** by named constants (``DEFAULT_MAX_HOPS`` /
    ``DEFAULT_MAX_NODES``); when the cap is hit the result is flagged
    ``truncated`` -- never a silent partial answer, and never an unbounded
    recursion (there is no recursion here at all: an iterative BFS).
  * Impact is a *signal*, not a finding. It feeds context selection
    (``V4-E03-T03`` / ``V4-E02``) and risk; it never mints a finding on its
    own, and with no index the impact set is empty and behaviour is
    byte-identical to pre-V4.

Prompt section (V4-E03-T03): :func:`render_impact_section` turns an
``ImpactResult`` into a short, deterministic text block for the review
prompt. Its output is treated exactly like index content -- it is derived
from untrusted repository paths, so every path is validated before it is
rendered (relative, printable, no ``..``), the whole block is secret-
redacted, and the size is bounded by an explicit character cap supplied by
the caller (the ``context.py`` budget). The text is *data*: the caller
fences it as untrusted before it reaches a provider.

This module reads index data only and imports no I/O, execution or network
module (enforced by a test in ``tests/test_impact.py``).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .index import RepoIndex
from .security import redact_secrets

# Bounded everything. These are the V4-E03 caps: small N (the epic says
# "N-hop (small N)"), and a hard node ceiling so a pathological fan-out
# (one hub file imported by thousands) terminates in bounded time.
DEFAULT_MAX_HOPS = 2
HARD_MAX_HOPS = 4
DEFAULT_MAX_NODES = 50
HARD_MAX_NODES = 200

# Confidence labels (V4-E03-T01: "confidence field mandatory"). Honest and
# monotonic with distance: a direct importer is a strong signal, an N-hop
# dependent is weaker, and an unresolvable seed is explicitly unknown.
CONFIDENCE_DIRECT = "direct"       # hop 1 -- imports a changed file
CONFIDENCE_INDIRECT = "indirect"   # hop >= 2 -- imports something that (transitively) imports a changed file
CONFIDENCE_UNKNOWN = "unknown"     # changed path not present in the index

VALID_CONFIDENCE = (CONFIDENCE_DIRECT, CONFIDENCE_INDIRECT, CONFIDENCE_UNKNOWN)

# Why a result is partial (``ImpactResult.truncation``). Empty string means
# the closure is complete within the index. Truncation is never silent --
# neither cap may stop the traversal without saying which one did.
TRUNCATION_NONE = ""
TRUNCATION_HOPS = "hops"     # dependents exist beyond the hop limit
TRUNCATION_NODES = "nodes"   # the affected-file ceiling was reached

# Default character ceiling for the rendered prompt section. The caller
# (``context.py``) may pass a smaller one derived from the shared budget;
# nothing may pass a larger one than HARD_SECTION_CHARS.
DEFAULT_SECTION_CHARS = 1_500
HARD_SECTION_CHARS = 4_000
# Names listed for changed files the index could not resolve.
_MAX_UNKNOWN_LISTED = 5

# A path may be echoed into a prompt only when it is plainly a relative,
# printable repository path. Anything else is counted, never rendered.
_SAFE_PATH_RE = re.compile(r"^[A-Za-z0-9_@+.,=~ \-]+(?:/[A-Za-z0-9_@+.,=~ \-]+)*$")


def _clamp(value: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(value)))


@dataclass(frozen=True)
class ImpactEntry:
    """One affected file with how it was reached and how sure we are.

    ``via`` is the immediate dependent it was reached through (the index
    edge), so every impact claim cites a concrete graph edge -- V4-E03
    exit criteria: "every impact claim carries provenance (which index
    entry, which hop)".
    """

    path: str
    hop: int                 # 1 = direct importer of a changed file
    confidence: str          # direct | indirect | unknown
    via: str | None = None   # the file this entry was reached through

    def to_dict(self) -> dict:
        return {"path": self.path, "hop": self.hop,
                "confidence": self.confidence, "via": self.via}


@dataclass(frozen=True)
class ImpactResult:
    """The bounded blast radius of a change."""

    seeds: tuple[str, ...]            # the changed files we traversed from
    entries: tuple[ImpactEntry, ...]  # affected files (excluding seeds), sorted
    truncated: bool                   # hit the hop or node cap
    unknown_seeds: tuple[str, ...]    # changed paths absent from the index
    # Additive (V4-E03-T02): *which* cap stopped the closure ("" | "hops" |
    # "nodes") and the hop limit used, so "impact truncated at hop 2" is a
    # stated fact rather than an inference. Defaults keep older constructors
    # (and callers that only read ``truncated``) working unchanged.
    truncation: str = TRUNCATION_NONE
    max_hops: int = DEFAULT_MAX_HOPS

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(e.path for e in self.entries)

    def to_dict(self) -> dict:
        return {
            "seeds": list(self.seeds),
            "entries": [e.to_dict() for e in self.entries],
            "truncated": self.truncated,
            "unknown_seeds": list(self.unknown_seeds),
            "truncation": self.truncation,
            "max_hops": self.max_hops,
        }


def compute_impact(
    index: RepoIndex | None,
    changed_paths: list[str] | tuple[str, ...],
    *,
    max_hops: int = DEFAULT_MAX_HOPS,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> ImpactResult:
    """Bounded, deterministic impact closure over the index import graph.

    Returns an empty (but well-formed) result when ``index`` is None or
    there are no changed paths -- the "impact absent => unchanged
    behaviour" contract. Deterministic: seeds and neighbours are processed
    in sorted order, so identical inputs always yield identical output.
    """
    seeds = sorted({p for p in (changed_paths or []) if p})
    hops = _clamp(max_hops, 1, HARD_MAX_HOPS)
    if index is None or not seeds:
        return ImpactResult(seeds=tuple(seeds), entries=(),
                            truncated=False, unknown_seeds=(), max_hops=hops)

    node_cap = _clamp(max_nodes, 1, HARD_MAX_NODES)

    indexed = set(index.paths)
    known_seeds = [s for s in seeds if s in indexed]
    unknown_seeds = tuple(s for s in seeds if s not in indexed)
    # A changed file is part of the change, never "affected by" it -- even
    # when it imports another changed file. Impact answers "what *else*".
    changed = set(known_seeds)

    # Reverse graph built ONCE (importers of a path, sorted) instead of
    # rescanning every edge per frontier node: traversal cost is O(E + N)
    # rather than O(N * E), which matters on the largest permitted index.
    reverse: dict[str, list[str]] = {}
    for src, dst in index.edges:
        if src in indexed:
            reverse.setdefault(dst, []).append(src)
    for importers in reverse.values():
        importers.sort()

    # BFS over the reverse graph. One entry per path, first (lowest hop)
    # wins -- deterministic by sorted traversal.
    entries: dict[str, ImpactEntry] = {}
    frontier = list(known_seeds)
    truncation = TRUNCATION_NONE

    for hop in range(1, hops + 1):
        next_frontier: list[str] = []
        for src in frontier:
            for dependent in reverse.get(src, ()):
                if dependent in entries or dependent in changed:
                    continue
                if len(entries) >= node_cap:
                    truncation = TRUNCATION_NODES
                    break
                entries[dependent] = ImpactEntry(
                    path=dependent, hop=hop,
                    confidence=(CONFIDENCE_DIRECT if hop == 1
                                else CONFIDENCE_INDIRECT),
                    via=src)
                next_frontier.append(dependent)
            if truncation:
                break
        frontier = next_frontier
        if truncation or not frontier:
            break

    # The hop cap is a cap like any other: if the last hop still has
    # dependents we did not visit, say so (a silent stop at the hop limit
    # would read as "nothing else is affected" -- the one wrong claim impact
    # analysis must never make).
    if not truncation and frontier:
        if any(d not in entries and d not in changed
               for node in frontier for d in reverse.get(node, ())):
            truncation = TRUNCATION_HOPS

    # Deterministic output order: by path (stable across runs).
    ordered = tuple(entries[k] for k in sorted(entries))
    return ImpactResult(seeds=tuple(known_seeds), entries=ordered,
                        truncated=bool(truncation),
                        unknown_seeds=unknown_seeds,
                        truncation=truncation, max_hops=hops)


# --------------------------------------------------------------------------- prompt section

def _printable_path(path: str) -> bool:
    """True only for a plain relative repository path safe to echo."""
    if not path or len(path) > 200 or path.startswith("/"):
        return False
    if any(seg in ("", ".", "..") for seg in path.split("/")):
        return False
    return bool(_SAFE_PATH_RE.match(path))


def render_impact_section(result: ImpactResult | None,
                          max_chars: int = DEFAULT_SECTION_CHARS
                          ) -> tuple[str, int]:
    """Render the bounded prompt section; returns ``(text, omitted)``.

    ``text`` is ``""`` when there is nothing affected to report -- absent or
    empty impact leaves the prompt byte-identical to pre-V4. ``omitted``
    counts affected files that exist in the result but are not listed in
    the text (section budget or an unprintable path name), so the caller can
    surface the loss instead of letting it pass silently.

    The text is deterministic (entries are already path-sorted), derived
    from untrusted repository paths, validated per path, secret-redacted
    and never longer than ``max_chars``. It is *data*: callers fence it as
    untrusted before a provider sees it.
    """
    if result is None or not result.entries:
        return "", 0
    limit = _clamp(max_chars, 0, HARD_SECTION_CHARS)
    if limit <= 0:
        return "", len(result.entries)

    head = ("Change impact (derived from the repository import graph; a "
            "context signal, not a finding). Files that depend on the "
            "changed files:")
    tail: list[str] = []
    if result.truncation == TRUNCATION_HOPS:
        tail.append(f"Impact is partial: traversal stopped at "
                    f"{result.max_hops} hop(s); further dependents exist.")
    elif result.truncation == TRUNCATION_NODES:
        tail.append("Impact is partial: the affected-file ceiling was "
                    "reached; further dependents exist.")
    unknown = [p for p in result.unknown_seeds if _printable_path(p)]
    if unknown:
        listed = ", ".join(unknown[:_MAX_UNKNOWN_LISTED])
        more = len(unknown) - _MAX_UNKNOWN_LISTED
        tail.append("Changed files not in the index (impact unknown): "
                    + listed + (f" (+{more} more)" if more > 0 else ""))

    reserve = sum(len(t) + 1 for t in tail) + 120   # room for the omission note
    lines: list[str] = []
    used = len(head) + reserve
    unprintable = budget_cut = 0
    for e in result.entries:
        if not _printable_path(e.path):
            unprintable += 1
            continue
        via = f", via {e.via}" if e.via and _printable_path(e.via) else ""
        line = f"- {e.path} [{e.confidence}, hop {e.hop}{via}]"
        if used + len(line) + 1 > limit:
            budget_cut += 1
            continue
        used += len(line) + 1
        lines.append(line)

    if not lines:
        return "", len(result.entries)
    notes = list(tail)
    if budget_cut:
        notes.append(f"... {budget_cut} more affected file(s) not listed "
                     "(impact section budget).")
    if unprintable:
        notes.append(f"{unprintable} affected path(s) not listed "
                     "(unprintable name).")
    text = redact_secrets("\n".join([head, *lines, *notes]))
    return text[:limit], budget_cut + unprintable
