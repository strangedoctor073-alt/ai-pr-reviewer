"""Tests for V4-E03: change impact analysis over the index import graph.

Covers the epic's acceptance criteria:
  * known call-chain fixture returns correct direct dependents (T01)
  * unresolved/absent seeds produce ``unknown`` confidence, never a guess
  * deterministic across runs
  * pathological fan-out terminates under a documented cap and flags
    truncation (T02) -- bounded runtime + explicit signal
  * zero unbounded recursion (structural: BFS, no recursion)
  * absent index / no changed paths => empty result, behaviour unchanged
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.impact import (  # noqa: E402
    CONFIDENCE_DIRECT,
    CONFIDENCE_INDIRECT,
    CONFIDENCE_UNKNOWN,
    DEFAULT_MAX_HOPS,
    DEFAULT_MAX_NODES,
    HARD_MAX_NODES,
    ImpactEntry,
    ImpactResult,
    compute_impact,
)
from ai_pr_reviewer.index import FileEntry, RepoIndex  # noqa: E402


def _entry(path, imports=()):
    return FileEntry(path=path, size=10, language="py", changed=False,
                     imports=tuple(imports))


def _index(entries, edges):
    return RepoIndex(root=".", files=tuple(entries), edges=tuple(edges),
                     budget_state="ok", warnings=())


# A -> B -> C -> D  (A imports B, B imports C, C imports D)
# plus X -> A (X imports the changed file A)
def _chain_index():
    entries = [
        _entry("a.py"), _entry("b.py"), _entry("c.py"), _entry("d.py"),
        _entry("x.py"),
    ]
    edges = [("a.py", "b.py"), ("b.py", "c.py"), ("c.py", "d.py"),
             ("x.py", "a.py")]
    return _index(entries, edges)


class TestDirectDependents:
    """V4-E03-T01: direct dependents of a changed file."""

    def test_direct_importers_are_found_with_direct_confidence(self):
        result = compute_impact(_chain_index(), ["a.py"])
        assert "x.py" in result.paths
        entry = next(e for e in result.entries if e.path == "x.py")
        assert entry.hop == 1
        assert entry.confidence == CONFIDENCE_DIRECT
        assert entry.via == "a.py"          # provenance: which edge

    def test_absent_seed_yields_empty_but_well_formed(self):
        result = compute_impact(None, ["a.py"])
        assert result.entries == () and result.paths == ()
        assert result.seeds == ("a.py",)    # seeds still reported
        assert not result.truncated

    def test_no_changed_paths_yields_empty(self):
        result = compute_impact(_chain_index(), [])
        assert result.entries == () and result.seeds == ()

    def test_result_is_deterministic(self):
        idx = _chain_index()
        a = compute_impact(idx, ["a.py"]).to_dict()
        b = compute_impact(idx, ["a.py"]).to_dict()
        assert a == b


class TestNBoundedPropagation:
    """V4-E03-T02: bounded N-hop propagation with honest truncation."""

    def test_two_hops_reach_transitive_dependents(self):
        result = compute_impact(_chain_index(), ["d.py"], max_hops=2)
        # d.py <- c.py (hop1) <- b.py (hop2)
        hops = {e.path: e.hop for e in result.entries}
        assert hops["c.py"] == 1
        assert hops["b.py"] == 2
        assert next(e for e in result.entries
                    if e.path == "c.py").confidence == CONFIDENCE_DIRECT
        assert next(e for e in result.entries
                    if e.path == "b.py").confidence == CONFIDENCE_INDIRECT

    def test_one_hop_stops_at_direct(self):
        result = compute_impact(_chain_index(), ["d.py"], max_hops=1)
        assert result.paths == ("c.py",)

    def test_seeds_are_not_reported_as_their_own_dependents(self):
        result = compute_impact(_chain_index(), ["d.py"], max_hops=3)
        assert "d.py" not in result.paths

    def test_changed_file_importing_another_changed_file_is_not_impact(self):
        """x.py imports changed a.py and is itself changed: it is part of
        the change, so impact ("what *else* is affected") excludes it."""
        result = compute_impact(_chain_index(), ["a.py", "x.py"])
        assert result.seeds == ("a.py", "x.py")
        assert "x.py" not in result.paths


class TestPathologicalFanOut:
    """The fan-out cap terminates a hostile hub in bounded time."""

    def test_hub_fanout_is_capped_and_truncation_is_flagged(self):
        # One hub imported by 200 files -- far beyond the node cap.
        hub = "hub.py"
        entries = [_entry(hub)]
        edges = []
        for i in range(200):
            src = f"user{i:03d}.py"
            entries.append(_entry(src))
            edges.append((src, hub))
        idx = _index(entries, edges)

        result = compute_impact(idx, [hub], max_nodes=10)
        assert len(result.entries) <= 10
        assert result.truncated is True

    def test_node_cap_is_bounded_by_hard_max(self):
        assert DEFAULT_MAX_NODES <= HARD_MAX_NODES

    def test_traversal_terminates_quickly_on_fanout(self):
        import time
        hub = "hub.py"
        entries = [_entry(hub)]
        edges = [(f"u{i}.py", hub) for i in range(500)]
        entries += [_entry(f"u{i}.py") for i in range(500)]
        idx = _index(entries, edges)
        t0 = time.monotonic()
        result = compute_impact(idx, [hub])
        assert (time.monotonic() - t0) < 2.0
        assert result.truncated is True


class TestUnknownSeeds:
    """V4-E03-T01: unresolved references are reported, never guessed."""

    def test_seed_absent_from_index_is_unknown(self):
        result = compute_impact(_chain_index(), ["brand_new_file.py"])
        assert result.unknown_seeds == ("brand_new_file.py",)
        assert result.entries == ()

    def test_known_and_unknown_seeds_split(self):
        result = compute_impact(_chain_index(), ["a.py", "missing.py"])
        assert "missing.py" in result.unknown_seeds
        assert "a.py" in result.seeds
        assert "x.py" in result.paths


class TestNoUnboundedRecursion:
    """Structural guarantee: the module contains no recursion and imports
    no execution/network module (V4-E03 acceptance + index trust model)."""

    def test_module_has_no_recursive_calls_and_no_io_imports(self):
        import ast
        src = (ROOT / "ai_pr_reviewer" / "impact.py").read_text("utf-8")
        tree = ast.parse(src)
        fn_calls = {
            n.func.id for n in ast.walk(tree)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        assert "compute_impact" not in fn_calls, "traversal must be iterative"

        imports = {
            a.name.split(".")[0]
            for n in ast.walk(tree) if isinstance(n, ast.Import)
            for a in n.names
        } | {
            (n.module or "").split(".")[0]
            for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
        }
        for banned in ("subprocess", "socket", "http", "urllib", "requests",
                       "os", "shutil"):
            assert banned not in imports


class TestImpactSerialization:
    def test_to_dict_shape(self):
        d = compute_impact(_chain_index(), ["a.py"]).to_dict()
        assert set(d) == {"seeds", "entries", "truncated", "unknown_seeds"}
        assert d["entries"][0].keys() == {
            "path", "hop", "confidence", "via"}
