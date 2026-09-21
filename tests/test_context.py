"""Tests for ai_pr_reviewer/context.py — find_relevant_files, build_context,
and the ContextBudget trim.

"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.config import Config
from ai_pr_reviewer.context import (MAX_RELEVANT_FILES, ReviewContext,
                                    build_context, find_relevant_files)
from ai_pr_reviewer.diff_parser import FileDiff, Hunk, HunkLine
from ai_pr_reviewer.models import PRContext
from ai_pr_reviewer.rules import ReviewPolicy


def _pr(repo="acme/widgets", pr_number=42):
    return PRContext(repo=repo, pr_number=pr_number, pr_title="Test PR",
                     head_sha="deadbeef" * 5)


def _file(path: str, added_lines: list[str] | None = None) -> FileDiff:
    """Build a FileDiff with one hunk of `added_lines` added text, big
    enough that its diff text has a predictable, sizeable length."""
    added_lines = added_lines or [f"line {i}" for i in range(20)]
    lines = [HunkLine("+", None, i + 1, text) for i, text in enumerate(added_lines)]
    hunk = Hunk(old_start=1, old_count=0, new_start=1,
               new_count=len(added_lines), lines=lines)
    return FileDiff(old_path=path, new_path=path, hunks=[hunk])


# --------------------------------------------------------------- find_relevant_files
def test_same_directory_match():
    changed = "src/payments/api.py"
    repo_files = [
        "src/payments/api.py",       # the changed file itself — must be excluded
        "src/payments/refunds.py",   # same dir
        "src/payments/models.py",    # same dir
        "src/unrelated/other.py",    # different dir
    ]
    found = find_relevant_files(changed, repo_files)
    assert "src/payments/refunds.py" in found
    assert "src/payments/models.py" in found
    assert "src/payments/api.py" not in found
    assert "src/unrelated/other.py" not in found


def test_test_naming_convention_match_when_no_same_dir_candidates():
    changed = "payments.py"
    repo_files = ["tests/test_payments.py", "unrelated/thing.py"]
    found = find_relevant_files(changed, repo_files)
    assert found == ["tests/test_payments.py"]


def test_test_file_change_finds_its_implementation():
    changed = "tests/test_payments.py"
    repo_files = ["payments.py", "unrelated/thing.py"]
    found = find_relevant_files(changed, repo_files)
    assert "payments.py" in found


def test_respects_five_file_cap():
    changed = "pkg/mod.py"
    repo_files = [f"pkg/sibling_{i}.py" for i in range(30)]
    found = find_relevant_files(changed, repo_files)
    assert len(found) == MAX_RELEVANT_FILES
    assert len(set(found)) == MAX_RELEVANT_FILES  # no duplicates


def test_import_grep_strategy_matches_local_module():
    changed = "app/main.py"
    repo_files = ["app/utils.py", "app/other_unrelated.py"]
    diff_text = "+from .utils import helper\n+helper()\n"
    found = find_relevant_files(changed, repo_files, diff_text=diff_text)
    assert "app/utils.py" in found


def test_no_matches_returns_empty_list():
    assert find_relevant_files("standalone.py", ["totally/different.py"]) == []


# ------------------------------------------------------------------- build_context
def test_build_context_basic_no_storage_no_rules_file(tmp_path):
    cfg = Config(focus_areas=["performance"])
    cfg.repo_root = str(tmp_path)  # no .ai-pr-reviewer.yml here -> defaults
    files = [_file("a.py")]

    ctx = build_context(_pr(), files, cfg)

    assert isinstance(ctx, ReviewContext)
    assert ctx.project_rules == ReviewPolicy()
    assert ctx.previous_findings == []
    assert ctx.relevant_files == {}
    assert ctx.memory_notes == []
    assert ctx.focus_areas == ["performance"]
    assert ctx.token_budget == cfg.batch_chars


def test_build_context_loads_project_rules_from_repo_root(tmp_path):
    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        "review:\n  mode: maximum\nfocus:\n  - security\n", encoding="utf-8")
    cfg = Config()
    cfg.repo_root = str(tmp_path)

    ctx = build_context(_pr(), [_file("a.py")], cfg)

    assert ctx.project_rules.mode == "maximum"
    assert "security" in ctx.focus_areas


def test_build_context_dedupes_focus_areas(tmp_path):
    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        "focus:\n  - security\n  - tests\n", encoding="utf-8")
    cfg = Config(focus_areas=["security", "performance"])
    cfg.repo_root = str(tmp_path)

    ctx = build_context(_pr(), [_file("a.py")], cfg)

    assert ctx.focus_areas == ["security", "performance", "tests"]


def test_build_context_calls_storage_for_memory_notes(tmp_path):
    cfg = Config()
    cfg.repo_root = str(tmp_path)

    class FakeStorage:
        def get_repo_memory(self, repo, files):
            calls.append((repo, list(files)))
            return ["payments.py: SQL-injection pattern dismissed 3x"]

    calls: list = []
    ctx = build_context(_pr(repo="acme/widgets"), [_file("payments.py")], cfg,
                        storage=FakeStorage())

    assert calls == [("acme/widgets", ["payments.py"])]
    assert "payments.py: SQL-injection pattern dismissed 3x" in ctx.memory_notes
    assert ctx.previous_findings == []  # no shared-contract storage method for this yet


def test_build_context_survives_storage_error(tmp_path):
    cfg = Config()
    cfg.repo_root = str(tmp_path)

    class BrokenStorage:
        def get_repo_memory(self, repo, files):
            raise RuntimeError("db is down")

    ctx = build_context(_pr(), [_file("a.py")], cfg, storage=BrokenStorage())
    assert ctx.memory_notes == []  # degrades gracefully, doesn't raise


def test_build_context_populates_relevant_files_when_contents_given(tmp_path):
    cfg = Config()
    cfg.repo_root = str(tmp_path)
    files = [_file("src/payments/api.py")]
    contents = {
        "src/payments/api.py": "<the changed file itself>",
        "src/payments/refunds.py": "def refund(): ...",
        "unrelated/thing.py": "x = 1",
    }

    ctx = build_context(_pr(), files, cfg, repo_file_contents=contents)

    assert ctx.relevant_files == {"src/payments/refunds.py": "def refund(): ..."}


# ------------------------------------------------------------- ContextBudget
def test_build_context_respects_token_budget_by_trimming(tmp_path):
    cfg = Config(batch_chars=200)  # deliberately tiny budget
    cfg.repo_root = str(tmp_path)
    files = [_file(f"file_{i}.py", [f"some added line number {j}" for j in range(50)])
            for i in range(5)]
    contents = {f.path: "x" * 500 for f in files}

    untrimmed_total = sum(len(f.to_diff_text()) for f in files)
    assert untrimmed_total > cfg.batch_chars  # sanity: this really is oversized

    ctx = build_context(_pr(), files, cfg, repo_file_contents=contents)

    trimmed_total = (sum(len(f.to_diff_text()) for f in ctx.files)
                     + sum(len(v) for v in ctx.relevant_files.values()))
    assert trimmed_total <= cfg.batch_chars
    assert ctx.token_budget == cfg.batch_chars
    # relevant-file content is dropped before changed-code hunks are touched
    assert ctx.relevant_files == {}
    assert any("context budget" in note for note in ctx.memory_notes)


def test_build_context_budget_does_not_mutate_caller_files(tmp_path):
    cfg = Config(batch_chars=50)
    cfg.repo_root = str(tmp_path)
    files = [_file("big.py", [f"line {i}" for i in range(200)])]
    original_hunk_count = len(files[0].hunks[0].lines)

    build_context(_pr(), files, cfg)

    assert len(files[0].hunks[0].lines) == original_hunk_count  # untouched


def test_build_context_small_input_is_not_trimmed(tmp_path):
    cfg = Config()  # default batch_chars is large
    cfg.repo_root = str(tmp_path)
    files = [_file("a.py", ["one added line"])]

    ctx = build_context(_pr(), files, cfg)

    assert len(ctx.files) == 1
    assert len(ctx.files[0].hunks[0].lines) == 1
