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

This module reads index data only and imports no I/O, execution or network
module (enforced by a test in ``tests/test_impact.py``).
"""
from __future__ import annotations

from dataclasses import dataclass

from .index import RepoIndex

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

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(e.path for e in self.entries)

    def to_dict(self) -> dict:
        return {
            "seeds": list(self.seeds),
            "entries": [e.to_dict() for e in self.entries],
            "truncated": self.truncated,
            "unknown_seeds": list(self.unknown_seeds),
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
    if index is None or not seeds:
        return ImpactResult(seeds=tuple(seeds), entries=(),
                            truncated=False, unknown_seeds=())

    hops = _clamp(max_hops, 1, HARD_MAX_HOPS)
    node_cap = _clamp(max_nodes, 1, HARD_MAX_NODES)

    indexed = set(index.paths)
    known_seeds = [s for s in seeds if s in indexed]
    unknown_seeds = tuple(s for s in seeds if s not in indexed)
    # A changed file is part of the change, never "affected by" it -- even
    # when it imports another changed file. Impact answers "what *else*".
    changed = set(known_seeds)
    # A changed file is part of the change, never "affected by" it -- even
    # when it imports another changed file. Impact answers "what *else*".
    changed = set(known_seeds)

    # BFS over the reverse graph (importers of a path). One entry per
    # path, first (lowest hop) wins -- deterministic by sorted traversal.
    entries: dict[str, ImpactEntry] = {}
    frontier = list(known_seeds)
    truncated = False

    for hop in range(1, hops + 1):
        next_frontier: list[str] = []
        for src in frontier:
            for dependent in index.importers(src):
                if (dependent in indexed and dependent not in entries
                        and dependent not in changed):
                    if len(entries) >= node_cap:
                        truncated = True
                        break
                    confidence = (CONFIDENCE_DIRECT if hop == 1
                                  else CONFIDENCE_INDIRECT)
                    entries[dependent] = ImpactEntry(
                        path=dependent, hop=hop, confidence=confidence,
                        via=src)
                    next_frontier.append(dependent)
            else:
                continue
            break  # node cap reached inside the inner loop
        frontier = next_frontier
        if not frontier or truncated:
            break

    # Deterministic output order: by path (stable across runs).
    ordered = tuple(entries[k] for k in sorted(entries))
    return ImpactResult(seeds=tuple(known_seeds), entries=ordered,
                        truncated=truncated, unknown_seeds=unknown_seeds)
