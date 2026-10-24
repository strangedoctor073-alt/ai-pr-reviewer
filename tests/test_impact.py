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
    DEFAULT_SECTION_CHARS,
    HARD_SECTION_CHARS,
    TRUNCATION_HOPS,
    TRUNCATION_NODES,
    TRUNCATION_NONE,
    render_impact_section,
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
        # Additive: ``truncation`` / ``max_hops`` joined the original four.
        assert set(d) == {"seeds", "entries", "truncated", "unknown_seeds",
                          "truncation", "max_hops"}
        assert d["entries"][0].keys() == {
            "path", "hop", "confidence", "via"}


# ---------------------------------------------------------------------------
# V4-E03-T02 · the hop cap is a cap like any other: never a silent stop
# ---------------------------------------------------------------------------

class TestHopCapReportsTruncation:
    """Regression: stopping at ``max_hops`` with dependents still unvisited
    used to leave ``truncated=False`` -- reading as "nothing else is
    affected", the one wrong claim impact analysis must never make."""

    def test_stopping_at_the_hop_limit_with_more_dependents_is_flagged(self):
        # d <- c (1) <- b (2) <- a (3): a hop limit of 2 leaves ``a`` unseen.
        result = compute_impact(_chain_index(), ["d.py"], max_hops=2)
        assert result.paths == ("b.py", "c.py")
        assert result.truncated is True
        assert result.truncation == TRUNCATION_HOPS
        assert result.max_hops == 2

    def test_a_closure_that_ends_exactly_at_the_limit_is_not_truncated(self):
        # d <- c (1) <- b (2) <- a (3) <- x (4); nothing imports ``x``, so a
        # hop limit of 4 sees the whole chain and ends exactly at the cap.
        result = compute_impact(_chain_index(), ["d.py"], max_hops=4)
        assert result.paths == ("a.py", "b.py", "c.py", "x.py")
        assert result.truncated is False
        assert result.truncation == TRUNCATION_NONE

    def test_node_cap_reports_nodes_not_hops(self):
        entries = [_entry("hub.py")] + [_entry(f"u{i}.py") for i in range(20)]
        edges = [(f"u{i}.py", "hub.py") for i in range(20)]
        result = compute_impact(_index(entries, edges), ["hub.py"],
                                max_nodes=5)
        assert len(result.entries) == 5
        assert result.truncation == TRUNCATION_NODES

    def test_cycles_do_not_loop_or_falsely_truncate(self):
        entries = [_entry("a.py"), _entry("b.py"), _entry("c.py")]
        edges = [("a.py", "b.py"), ("b.py", "c.py"), ("c.py", "a.py")]
        result = compute_impact(_index(entries, edges), ["a.py"], max_hops=4)
        assert set(result.paths) == {"b.py", "c.py"}
        assert result.truncated is False

    def test_deep_fan_out_across_hops_terminates_under_the_caps(self):
        """Multi-level pathological graph: 30 importers each imported by 30
        more (900 dependents). Must stop at the node ceiling, fast."""
        import time
        entries = [_entry("core.py")]
        edges = []
        for i in range(30):
            mid = f"mid{i:02d}.py"
            entries.append(_entry(mid))
            edges.append((mid, "core.py"))
            for j in range(30):
                leaf = f"leaf{i:02d}_{j:02d}.py"
                entries.append(_entry(leaf))
                edges.append((leaf, mid))
        t0 = time.monotonic()
        result = compute_impact(_index(entries, edges), ["core.py"],
                                max_hops=4, max_nodes=10_000)
        assert (time.monotonic() - t0) < 2.0
        assert len(result.entries) <= HARD_MAX_NODES
        assert result.truncation == TRUNCATION_NODES

    def test_identical_inputs_give_identical_results_in_any_edge_order(self):
        base = _chain_index()
        shuffled = _index(list(reversed(base.files)), list(reversed(base.edges)))
        assert (compute_impact(base, ["d.py"], max_hops=3).to_dict()
                == compute_impact(shuffled, ["d.py"], max_hops=3).to_dict())


# ---------------------------------------------------------------------------
# V4-E03-T03 · the rendered prompt section: bounded, validated, redacted
# ---------------------------------------------------------------------------

def _hub_result(n, **kw):
    entries = [_entry("hub.py")] + [_entry(f"user{i:03d}.py") for i in range(n)]
    edges = [(f"user{i:03d}.py", "hub.py") for i in range(n)]
    return compute_impact(_index(entries, edges), ["hub.py"],
                          max_nodes=max(n, 1), **kw)


class TestImpactSection:
    def test_absent_or_empty_impact_renders_nothing(self):
        assert render_impact_section(None) == ("", 0)
        empty = compute_impact(_chain_index(), ["x.py"])   # nothing imports x
        assert render_impact_section(empty) == ("", 0)

    def test_lists_dependents_with_confidence_hop_and_via(self):
        text, omitted = render_impact_section(
            compute_impact(_chain_index(), ["d.py"], max_hops=2))
        assert omitted == 0
        assert "- c.py [direct, hop 1, via d.py]" in text
        assert "- b.py [indirect, hop 2, via c.py]" in text
        assert "not a finding" in text      # impact is context, never a finding

    def test_is_deterministic(self):
        r = compute_impact(_chain_index(), ["d.py"], max_hops=3)
        assert render_impact_section(r) == render_impact_section(r)

    def test_partial_closure_says_so(self):
        text, _ = render_impact_section(
            compute_impact(_chain_index(), ["d.py"], max_hops=1))
        assert "Impact is partial" in text and "1 hop(s)" in text
        text, _ = render_impact_section(_hub_result(30, max_hops=1))
        assert "Impact is partial" not in text     # complete within hop 1

    def test_unresolved_changed_files_are_named_as_unknown_not_guessed(self):
        r = compute_impact(_chain_index(), ["d.py", "brand_new.py"])
        text, _ = render_impact_section(r)
        assert "impact unknown): brand_new.py" in text

    def test_size_is_bounded_and_the_loss_is_reported(self):
        r = _hub_result(150)
        text, omitted = render_impact_section(r, max_chars=600)
        assert len(text) <= 600
        assert omitted > 0
        assert "not listed (impact section budget)" in text
        assert text.count("\n- ") + omitted == len(r.entries)   # nothing vanished

    def test_the_ceiling_can_never_exceed_the_hard_cap(self):
        text, _ = render_impact_section(_hub_result(200),
                                        max_chars=10 * HARD_SECTION_CHARS)
        assert len(text) <= HARD_SECTION_CHARS
        assert DEFAULT_SECTION_CHARS <= HARD_SECTION_CHARS

    def test_zero_budget_renders_nothing_but_counts_the_loss(self):
        r = _hub_result(5)
        assert render_impact_section(r, max_chars=0) == ("", len(r.entries))

    def test_unsafe_path_names_are_counted_never_rendered(self):
        hostile = ["../escape.py", "/etc/passwd", "a/../b.py", "evil\nname.py",
                   "back`tick.py", "q\"uote.py", "C:/win.py"]
        entries = [_entry("hub.py"), _entry("fine.py")] + [_entry(h) for h in hostile]
        edges = [("fine.py", "hub.py")] + [(h, "hub.py") for h in hostile]
        r = compute_impact(_index(entries, edges), ["hub.py"])
        text, omitted = render_impact_section(r)
        assert "- fine.py [direct, hop 1, via hub.py]" in text
        for bad in ("escape", "passwd", "evil", "tick", "uote", "win.py"):
            assert bad not in text, bad
        assert omitted == len(hostile)
        assert f"{len(hostile)} affected path(s) not listed (unprintable name)" in text

    def test_no_absolute_path_ever_appears(self):
        entries = [_entry("hub.py"), _entry("/abs/user.py")]
        r = compute_impact(_index(entries, [("/abs/user.py", "hub.py")]),
                           ["hub.py"])
        text, omitted = render_impact_section(r)
        assert text == "" and omitted == 1

    def test_secret_shaped_path_names_are_redacted(self):
        secret = "keys/ghp_abcdefghijklmnopqrstuvwxyz0123456789.py"
        r = compute_impact(_index([_entry("hub.py"), _entry(secret)],
                                  [(secret, "hub.py")]), ["hub.py"])
        text, _ = render_impact_section(r)
        assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in text
        assert "[REDACTED]" in text
