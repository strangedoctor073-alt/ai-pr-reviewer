"""Tests for V4-E02 context selection (ADR-017 selection contract).

Pins the contract guarantees:
  * closed reason set; deterministic ordering (reason -> rank -> path)
  * every selected file answers "why"; every exclusion carries a reason
  * budget_state is reported, never silent
  * with no index => None (caller keeps today's behaviour + warns)
  * impact (V4-E03) folds in as weaker-rank context (E03-T03)
  * deterministic across runs; bounded by the file cap
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.diff_parser import parse_unified_diff  # noqa: E402
from ai_pr_reviewer.index import FileEntry, RepoIndex  # noqa: E402
from ai_pr_reviewer.impact import ImpactEntry, ImpactResult, compute_impact  # noqa: E402
from ai_pr_reviewer.models import PRContext  # noqa: E402
from ai_pr_reviewer.selection import (  # noqa: E402
    ALLOWED_REASONS,
    DEFAULT_MAX_SELECTED,
    REASON_CHANGED,
    REASON_CONFIG_OF,
    REASON_IMPORT,
    REASON_IMPORTER,
    REASON_TEST_OF,
    ContextSelection,
    ExcludedFile,
    SelectedFile,
    select_context,
)


def _entry(path, imports=(), changed=False):
    return FileEntry(path=path, size=10, language="py", changed=changed,
                     imports=tuple(imports))


def _index(entries, edges=(), budget_state="ok"):
    return RepoIndex(root=".", files=tuple(entries), edges=tuple(edges),
                     budget_state=budget_state, warnings=())


def _demo_index():
    """src/app.py (changed) imports src/db.py; src/api.py imports src/app.py;
    tests/test_app.py tests it; pyproject.toml is config."""
    entries = [
        _entry("src/app.py", changed=True),
        _entry("src/db.py"),
        _entry("src/api.py"),
        _entry("tests/test_app.py"),
        _entry("pyproject.toml"),
    ]
    edges = [("src/app.py", "src/db.py"), ("src/api.py", "src/app.py")]
    return _index(entries, edges)


class TestSelectionContractShape:
    def test_none_without_index(self):
        """ADR-017: no index => no selection (caller warns, keeps behaviour)."""
        assert select_context(None, ["src/app.py"]) is None

    def test_changed_file_is_selected_first_with_reason(self):
        sel = select_context(_demo_index(), ["src/app.py"])
        assert sel.selected_files[0].path == "src/app.py"
        assert sel.selected_files[0].reason == REASON_CHANGED
        assert sel.selected_files[0].rank == 0

    def test_every_selected_file_answers_why(self):
        sel = select_context(_demo_index(), ["src/app.py"])
        for f in sel.selected_files:
            assert f.reason in ALLOWED_REASONS
            assert f.relationship              # non-empty explanation
            assert isinstance(f.rank, int)

    def test_imports_and_importers_are_pulled_in(self):
        sel = select_context(_demo_index(), ["src/app.py"])
        reasons = {f.path: f.reason for f in sel.selected_files}
        assert reasons["src/db.py"] == REASON_IMPORT
        assert reasons["src/api.py"] == REASON_IMPORTER

    def test_test_and_config_files_are_selected(self):
        sel = select_context(_demo_index(), ["src/app.py"])
        reasons = {f.path: f.reason for f in sel.selected_files}
        assert reasons["tests/test_app.py"] == REASON_TEST_OF
        assert reasons["pyproject.toml"] == REASON_CONFIG_OF


class TestDeterministicOrdering:
    def test_ordering_is_reason_then_rank_then_path(self):
        sel = select_context(_demo_index(), ["src/app.py"])
        keys = [(f.priority, f.rank, f.path) for f in sel.selected_files]
        assert keys == sorted(keys)

    def test_same_input_same_output(self):
        idx = _demo_index()
        a = select_context(idx, ["src/app.py"]).to_dict()
        b = select_context(idx, ["src/app.py"]).to_dict()
        assert a == b

    def test_changed_ordering_of_input_does_not_change_result(self):
        idx = _demo_index()
        a = select_context(idx, ["src/app.py", "src/db.py"]).to_dict()
        b = select_context(idx, ["src/db.py", "src/app.py"]).to_dict()
        assert a == b


class TestBudgetStateAndExclusions:
    def test_budget_state_present_and_valid(self):
        sel = select_context(_demo_index(), ["src/app.py"])
        assert sel.budget_state in ("ok", "truncated", "exhausted")

    def test_file_cap_truncates_and_records_exclusions(self):
        small = select_context(_demo_index(), ["src/app.py"], max_selected=2)
        assert len(small.selected_files) == 2
        assert small.budget_state == "truncated"
        assert any(e.reason == "over_cap" for e in small.excluded_files)

    def test_exhausted_index_state_is_carried_through(self):
        idx = _index([_entry("src/app.py", changed=True)], budget_state="exhausted")
        sel = select_context(idx, ["src/app.py"])
        assert sel.budget_state == "exhausted"

    def test_budget_chars_drops_non_changed_but_never_changed(self):
        # 10 bytes each; ceiling of 15 keeps changed + one more.
        sel = select_context(_demo_index(), ["src/app.py"], budget_chars=15)
        assert "src/app.py" in sel.paths           # diff is never dropped
        assert any(e.reason == "budget" for e in sel.excluded_files)
        assert sel.budget_state == "truncated"


class TestImpactFoldsIn:
    """V4-E03-T03: the impact closure reaches selection as weaker context."""

    def test_impact_entries_become_selected_files(self):
        idx = _demo_index()
        impact = compute_impact(idx, ["src/db.py"])
        # app.py imports db.py (direct, also found by the 1-hop walk);
        # api.py imports app.py -> only reachable via the impact closure.
        assert "src/app.py" in impact.paths and "src/api.py" in impact.paths
        sel = select_context(idx, ["src/db.py"], impact=impact)
        by_path = {f.path: f for f in sel.selected_files}
        assert by_path["src/api.py"].reason == REASON_IMPORTER
        assert by_path["src/api.py"].rank >= 2          # weaker than direct
        assert "impact" in by_path["src/api.py"].relationship
        # a directly-reachable file keeps its stronger (lower) rank
        assert by_path["src/app.py"].rank <= by_path["src/api.py"].rank

    def test_absent_impact_changes_nothing(self):
        without = select_context(_demo_index(), ["src/app.py"])
        with_none = select_context(_demo_index(), ["src/app.py"], impact=None)
        assert without.to_dict() == with_none.to_dict()

    def test_impact_result_is_deterministic(self):
        idx = _demo_index()
        impact = compute_impact(idx, ["src/db.py"])
        a = select_context(idx, ["src/db.py"], impact=impact).to_dict()
        b = select_context(idx, ["src/db.py"], impact=impact).to_dict()
        assert a == b


class TestClosedReasonSetIsLaw:
    def test_allowed_reasons_are_exactly_the_contract(self):
        assert ALLOWED_REASONS == {
            REASON_CHANGED, REASON_IMPORT, REASON_IMPORTER, REASON_TEST_OF,
            REASON_CONFIG_OF, "adjacent", "manual",
        }

    def test_unindexed_dependency_is_excluded_not_selected(self):
        # an import edge to a file the index skipped (not inventoried)
        entries = [_entry("src/app.py", changed=True)]
        edges = [("src/app.py", "src/missing.py")]
        sel = select_context(_index(entries, edges), ["src/app.py"])
        assert "src/missing.py" not in sel.paths
        assert any(e.path == "src/missing.py" and e.reason == "not_indexed"
                   for e in sel.excluded_files)


class TestSerialization:
    def test_selection_to_dict_shape(self):
        sel = select_context(_demo_index(), ["src/app.py"])
        d = sel.to_dict()
        assert set(d) == {"selected_files", "excluded_files", "budget_state"}
        assert d["selected_files"][0].keys() == {
            "path", "reason", "rank", "relationship", "size"}

    def test_is_empty(self):
        empty = ContextSelection(selected_files=(), excluded_files=(),
                                 budget_state="ok")
        assert empty.is_empty and empty.paths == ()


# ---------------------------------------------------------------------------
# V4-E02-T03 · wiring: selection drives the fenced repo-context block
#
# The index-backed selection feeds repo_context.collect_repository_context
# as explicit (path, reason) candidates. These tests pin the contract on
# both sides of the boundary: WITH an index the entries carry ADR-017
# relationship text; WITHOUT an index the original diff-scoped ordering and
# reasons are used byte-for-byte (ADR-017 fallback rule).
# ---------------------------------------------------------------------------

_DIFF = (
    "diff --git a/app/main.py b/app/main.py\n"
    "--- a/app/main.py\n"
    "+++ b/app/main.py\n"
    "@@ -1,3 +1,4 @@\n"
    " import os\n"
    "+from utils.helpers import run\n"
    " import sys\n"
    " print(os.getcwd())\n"
)

_TREE = {
    "app/main.py": "import os\nfrom utils.helpers import run\nimport sys\n"
                   "print(os.getcwd())\n",
    "utils/helpers.py": "def run():\n    return 1\n",
    "tests/test_main.py": "def test_main():\n    assert True\n",
    "pyproject.toml": "[project]\nname = \"demo\"\n",
}


class _FakeGH:
    """Contents-API double: only ``get_file``, exactly like GitHubClient."""

    def __init__(self, files=None):
        self.files = dict(files or {})
        self.calls: list[tuple[str, str]] = []

    def get_file(self, path: str, ref: str) -> str:
        self.calls.append((path, ref))
        from ai_pr_reviewer.github_client import GitHubError
        if path not in self.files:
            raise GitHubError("not found", status_code=404)
        return self.files[path]


def _write_tree(root: Path, files: dict) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def _git_checkout(root: Path,
                  origin="https://github.com/acme/api.git") -> None:
    (root / ".git").mkdir(exist_ok=True)
    if origin is not None:
        (root / ".git" / "config").write_text(
            '[core]\n\tbare = false\n'
            '[remote "origin"]\n'
            f"\turl = {origin}\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8")


def _build_ctx(tmp_path, monkeypatch, *, checkout: bool, gh=None):
    from ai_pr_reviewer.config import Config
    from ai_pr_reviewer.context import build_context
    from ai_pr_reviewer.models import PRContext

    _write_tree(tmp_path, _TREE)
    if checkout:
        _git_checkout(tmp_path)
    monkeypatch.chdir(tmp_path)
    pr = PRContext(repo="acme/api", pr_number=7, base_sha="b" * 40,
                   head_sha="h" * 40)
    gh = gh if gh is not None else _FakeGH(files=dict(_TREE))
    return build_context(pr, parse_unified_diff(_DIFF), Config(),
                         storage=None, gh=gh)


class TestSelectionWiresIntoRepoContext:
    def test_with_index_entries_carry_selection_relationship_text(
            self, tmp_path, monkeypatch):
        ctx = _build_ctx(tmp_path, monkeypatch, checkout=True)
        assert ctx.repo_index is not None
        assert ctx.context_selection is not None
        reasons = {e.path: e.reason for e in ctx.repo_context}
        # closed-set relationship text, not the legacy diff-scoped phrase
        assert reasons["utils/helpers.py"] == "imported by a changed file (app/main.py)"
        assert reasons["tests/test_main.py"] == "test of a changed module"
        assert reasons["pyproject.toml"] == "project configuration"
        assert reasons["app/main.py"] == "changed in this PR"
        # the selection and the fetched set agree (content == chosen files)
        assert set(ctx.context_selection.paths) == set(reasons)

    def test_without_index_legacy_reasons_unchanged(self, tmp_path, monkeypatch):
        ctx = _build_ctx(tmp_path, monkeypatch, checkout=False)
        assert ctx.repo_index is None
        assert ctx.context_selection is None
        reasons = {e.path: e.reason for e in ctx.repo_context}
        # the original V3 diff-scoped phrases, byte-for-byte
        assert reasons["utils/helpers.py"] == "imported by app/main.py"
        assert reasons["pyproject.toml"] == "project configuration"
        assert reasons["app/main.py"] == "changed in this PR"

    def test_selection_fetches_only_chosen_paths_at_base_ref(
            self, tmp_path, monkeypatch):
        gh = _FakeGH(files=dict(_TREE))
        ctx = _build_ctx(tmp_path, monkeypatch, checkout=True, gh=gh)
        fetched = [p for p, _ref in gh.calls]
        assert set(fetched) == set(ctx.context_selection.paths)
        assert all(ref == "b" * 40 for _p, ref in gh.calls)   # base revision

    def test_index_decline_by_origin_mismatch_falls_back_to_legacy(
            self, tmp_path, monkeypatch):
        # wrong origin -> index declined -> selection None -> legacy path
        from ai_pr_reviewer.config import Config
        from ai_pr_reviewer.context import build_context
        from ai_pr_reviewer.models import PRContext
        _write_tree(tmp_path, _TREE)
        _git_checkout(tmp_path, origin="https://github.com/other/repo.git")
        monkeypatch.chdir(tmp_path)
        pr = PRContext(repo="acme/api", pr_number=7, base_sha="b" * 40,
                       head_sha="h" * 40)
        ctx = build_context(pr, parse_unified_diff(_DIFF), Config(),
                            storage=None, gh=_FakeGH(files=dict(_TREE)))
        assert ctx.repo_index is None and ctx.context_selection is None
        reasons = {e.path: e.reason for e in ctx.repo_context}
        assert reasons["utils/helpers.py"] == "imported by app/main.py"

    def test_selection_failure_degrades_to_no_selection(self, tmp_path,
                                                        monkeypatch, caplog):
        """A selection crash must never break a review (ADR-017)."""
        from ai_pr_reviewer import context as context_mod

        def boom(files, repo_index):
            raise RuntimeError("hostile index data")

        monkeypatch.setattr(context_mod, "_select_repository_context", boom)
        with caplog.at_level("WARNING"):
            ctx = _build_ctx(tmp_path, monkeypatch, checkout=True)
        assert ctx.context_selection is None       # degraded, not raised
        assert ctx.repo_index is not None          # index itself unaffected
        # collection still produced legacy context (candidates None)
        assert any(e.path == "utils/helpers.py" for e in ctx.repo_context)


class TestCollectorCandidatesParameter:
    """collect_repository_context(candidates=...) honors explicit order and
    reasons; default (None) keeps select_candidates' original behavior."""

    def test_custom_candidates_drive_order_and_reasons(self):
        from ai_pr_reviewer.repo_context import collect_repository_context

        files = parse_unified_diff(_DIFF)
        pr = PRContext(repo="acme/api", pr_number=7, base_sha="b" * 40,
                       head_sha="h" * 40)
        gh = _FakeGH(files=dict(_TREE))
        entries, warnings = collect_repository_context(
            gh, pr, files, None,
            candidates=[("utils/helpers.py", "custom reason A"),
                        ("app/main.py", "custom reason B")])
        assert [e.path for e in entries] == ["utils/helpers.py", "app/main.py"]
        assert [e.reason for e in entries] == ["custom reason A",
                                               "custom reason B"]
        assert warnings == []

    def test_default_candidates_are_the_legacy_selector(self):
        from ai_pr_reviewer.repo_context import collect_repository_context

        files = parse_unified_diff(_DIFF)
        pr = PRContext(repo="acme/api", pr_number=7, base_sha="b" * 40,
                       head_sha="h" * 40)
        default, _ = collect_repository_context(_FakeGH(files=dict(_TREE)),
                                                pr, files, None)
        explicit, _ = collect_repository_context(
            _FakeGH(files=dict(_TREE)), pr, files, None, candidates=None)
        key = lambda e: (e.path, e.content, e.reason)  # noqa: E731
        assert [key(e) for e in default] == [key(e) for e in explicit]
