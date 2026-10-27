"""V4.2-E04-T02 — layer / dependency-direction checker over the import graph.

Pure and deterministic: ``(model, edges) -> CheckResult``. No I/O, no model,
no network. Edges come from two places (see :mod:`.runner`): the base-tree
index graph and import lines the PR adds; this module only judges them.

Honesty rules (tested):

* an edge is *judged* only when **both** endpoints are assigned to a layer —
  unlayered files are counted, never guessed at;
* edges touching a privacy-baseline path are excluded and counted, so a
  finding can never cite (or even reveal the existence of an edge to) a
  secret-bearing path;
* when the cap is hit, or the underlying index was itself truncated, the
  result is labelled ``partial`` with reasons — a short list must never read
  as "nothing else is wrong".
"""
from __future__ import annotations

from dataclasses import dataclass

from ..index.limits import is_excluded
from ..rules import SENSITIVE_EXCLUDE_GLOBS
from .schema import ArchitectureModel

#: Absolute ceiling on violations one call may return (the model's own
#: ``max_findings`` is the default reporting cap).
HARD_MAX_VIOLATIONS = 1000

ORIGIN_BASE = "base"   # edge present in the base-tree index graph
ORIGIN_DIFF = "diff"   # edge introduced by an added import line in the PR


@dataclass(frozen=True)
class Edge:
    importer: str
    imported: str
    line: int | None = None     # new-file line of the import (diff origin)
    spec: str | None = None     # raw import spec as written
    origin: str = ORIGIN_BASE


@dataclass(frozen=True)
class Violation:
    importer: str
    imported: str
    importer_layer: str
    imported_layer: str
    line: int | None = None
    spec: str | None = None
    origin: str = ORIGIN_BASE


@dataclass(frozen=True)
class CheckResult:
    violations: tuple[Violation, ...] = ()
    total_violations: int = 0          # before the cap
    truncated: bool = False
    edges_considered: int = 0
    edges_unlayered: int = 0
    edges_excluded: int = 0
    partial: bool = False
    partial_reasons: tuple[str, ...] = ()


def _sort_key(e: Edge):
    # diff origin first on ties so the line-anchored variant wins the dedup
    return (e.importer, e.imported, 0 if e.origin == ORIGIN_DIFF else 1,
            e.line if e.line is not None else 0, e.spec or "")


def check_layers(model: ArchitectureModel, edges, *,
                 index_complete: bool = True,
                 max_violations: int | None = None) -> CheckResult:
    """Judge ``edges`` against ``model``. Order-independent: any permutation
    of ``edges`` yields an identical result."""
    cap = model.max_findings if max_violations is None else max(
        1, min(int(max_violations), HARD_MAX_VIOLATIONS))
    seen: set[tuple[str, str]] = set()
    considered = unlayered = excluded = 0
    found: list[Violation] = []

    for e in sorted(edges, key=_sort_key):
        key = (e.importer, e.imported)
        if key in seen:
            continue
        seen.add(key)
        if (is_excluded(e.importer, SENSITIVE_EXCLUDE_GLOBS)
                or is_excluded(e.imported, SENSITIVE_EXCLUDE_GLOBS)):
            excluded += 1
            continue
        considered += 1
        src = model.layer_of(e.importer)
        dst = model.layer_of(e.imported)
        if src is None or dst is None:
            unlayered += 1
            continue
        if model.allows(src, dst):
            continue
        found.append(Violation(
            importer=e.importer, imported=e.imported, importer_layer=src,
            imported_layer=dst, line=e.line, spec=e.spec, origin=e.origin))

    total = len(found)
    truncated = total > cap
    reasons: list[str] = []
    if truncated:
        reasons.append(f"violation cap reached: showing {cap} of {total}")
    if not index_complete:
        reasons.append("repository index was truncated: some imports are "
                       "not part of the analysed graph")
    return CheckResult(
        violations=tuple(found[:cap]), total_violations=total,
        truncated=truncated, edges_considered=considered,
        edges_unlayered=unlayered, edges_excluded=excluded,
        partial=bool(reasons), partial_reasons=tuple(reasons))


def project_layer_edges(model: ArchitectureModel, edges
                        ) -> dict[tuple[str, str], int]:
    """Count distinct file edges per ``(importer_layer, imported_layer)``
    pair, cross-layer only. Applies the same de-duplication and privacy
    exclusion as :func:`check_layers`, so a snapshot and a review run can
    never disagree about which edges exist."""
    counts: dict[tuple[str, str], int] = {}
    seen: set[tuple[str, str]] = set()
    for e in sorted(edges, key=_sort_key):
        key = (e.importer, e.imported)
        if key in seen:
            continue
        seen.add(key)
        if (is_excluded(e.importer, SENSITIVE_EXCLUDE_GLOBS)
                or is_excluded(e.imported, SENSITIVE_EXCLUDE_GLOBS)):
            continue
        s, d = model.layer_of(e.importer), model.layer_of(e.imported)
        if s is not None and d is not None and s != d:
            counts[(s, d)] = counts.get((s, d), 0) + 1
    return counts
