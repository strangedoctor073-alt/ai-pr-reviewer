"""V4-E01-T03 — bounded import graph over the index.

``file → imports`` / ``file → imported_by`` derived from the raw import
specs :mod:`ai_pr_reviewer.index.symbols` extracted. Resolution reuses
the *existing* spec→path resolvers from ``repo_context.py``
(``_module_paths`` / ``_js_paths``) — the same candidate order the V3
context fetch already trusts — and keeps an edge only when the resolved
candidate is itself an inventoried file (external packages stay out).

Bounded by construction: specs per file are already capped at
extraction, edges are capped at ``limits.max_edges`` (loud truncation,
never quadratic fan-out), and building the reverse map for
``importers()`` is a single O(edges) pass.
"""
from __future__ import annotations

from .limits import IndexLimits

# Existing resolvers — one implementation of "spec → candidate paths",
# shared with repo_context.py (extend, don't duplicate).
from ..repo_context import _CODE_EXTENSIONS, _js_paths, _module_paths


def _resolve(spec: str, importer: str, paths: set[str]) -> str | None:
    """Best-effort resolution of one import spec to an indexed path.

    Deterministic candidate order: relative specifiers first (JS ``./``
    style, then Python ``.``-dot style), then bare specifiers tried as
    Python modules, as exact paths, and with code extensions. Returns
    ``None`` for everything that is not in the inventory (external
    packages, Go/Java FQNs that don't map to files — honest absence,
    never an invented edge).
    """
    if spec.startswith("./") or spec.startswith("../"):
        candidates = _js_paths(spec, importer)
    elif spec.startswith("."):
        candidates = _module_paths(spec, relative_to_file=importer)
    else:
        candidates = [*_module_paths(spec), spec,
                      *(spec + ext for ext in _CODE_EXTENSIONS)]
    for cand in candidates:
        if cand and cand in paths:
            return cand
    return None


def build_import_edges(files, limits: IndexLimits) -> tuple[list[tuple[str, str]],
                                                            list[str]]:
    """Resolve import specs into ``(importer, imported)`` edges.

    ``files`` must be the inventory's ``FileEntry`` objects (path-sorted).
    Returns ``(edges, warnings)`` with edges sorted for determinism;
    hitting ``limits.max_edges`` stops resolution with an explicit
    truncation warning (threat model §1: bounded expansion, loud, never
    a crash).
    """
    paths = {f.path for f in files}
    edges: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    warnings: list[str] = []
    capped = False

    for entry in files:
        if capped:
            break
        for spec in entry.imports:
            target = _resolve(spec, entry.path, paths)
            if target is None or target == entry.path:
                continue
            key = (entry.path, target)
            if key in seen:
                continue
            if len(edges) >= limits.max_edges:
                warnings.append(
                    f"index: import-graph edge cap ({limits.max_edges}) reached "
                    f"— graph truncated")
                capped = True
                break
            seen.add(key)
            edges.append(key)

    return sorted(edges), warnings
