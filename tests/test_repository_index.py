"""V4-E01-T06 · V4-E08-T03 — the ephemeral repository index.

Coverage by ticket:

* **E08-T03** (this file's first section): path containment, symlink
  escape, vendor/minified skips, exclusion parity with the review-file
  filter, config clamping, and the no-execution/no-network invariant;
* **E01-T01** file inventory: bounded, deterministic, language detection,
  changed-file marking, privacy exclusions;
* **E01-T02** symbol-lite extraction (Python, JS/TS, Java, config files,
  unknown languages, giant files);
* **E01-T03** import graph: resolution into indexed files, bounded
  edges, determinism;
* **E01-T04** budgets: ``context.max_files`` / ``context.max_bytes``
  beneath the existing ``repo_context_chars`` outer ceiling; defaults
  preserve V3 behavior;
* **E01-T05** wiring: ``build_context`` exposes the index without
  changing any prompt-visible field.
"""
from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import ai_pr_reviewer
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.index import limits as lim
from ai_pr_reviewer.index.limits import (HARD_MAX_BYTES, HARD_MAX_FILES,
                                         IndexLimits, is_contained,
                                         is_excluded, is_vendor_or_minified)

# ============================================================ E08-T03 · limits

@pytest.mark.parametrize("bad", [
    "", ".", "..", "../secrets.env", "a/../../etc/passwd",
    "/etc/passwd", "C:/repo/x.py", "C:\\repo\\x.py",
])
def test_containment_rejects_escaping_paths(tmp_path, bad):
    assert is_contained(str(tmp_path), bad) is False


@pytest.mark.parametrize("good", [
    "src/main.py", "nested/dir/mod.py", "sub/../real/module.py",
    "src\\windows\\style.py", ".github/workflows/ci.yml",
])
def test_containment_accepts_paths_inside_the_checkout(tmp_path, good):
    assert is_contained(str(tmp_path), good) is True


def test_symlink_pointing_outside_the_checkout_is_rejected(tmp_path):
    """Threat model §1: a symlink inside the tree that resolves outside it
    must never pass containment (the escape test for indexed reads)."""
    outside = tmp_path.parent / "outside_target.py"
    outside.write_text("SECRET = 1\n", encoding="utf-8")
    root = tmp_path / "repo"
    root.mkdir()
    link = root / "escape.py"
    try:
        os.symlink(outside, link)
    except OSError:
        pytest.skip("symlink creation not permitted on this host")
    assert is_contained(str(root), "escape.py") is False


@pytest.mark.parametrize("p", [
    "node_modules/react/index.js",
    "packages/app/vendor/lib.rb",
    "third_party/protobuf/message.c",
    "src/app.min.js",
    "styles/site.min.css",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "src/__pycache__/mod.cpython-312.pyc",
    "dist/bundle.js",
    "coverage/lcov-report/index.html",
    "assets/app.js.map",
])
def test_vendor_minified_and_lockfile_paths_are_never_indexed(p):
    assert is_vendor_or_minified(p) is True


@pytest.mark.parametrize("p", [
    "src/main.py", "web/app.ts", ".github/workflows/ci.yml",
    "app/vendor.py", "web/build_tools/helper.py", "docs/README.md",
    "src/packageworker.py", "vendor_rules/allow.py",
])
def test_ordinary_project_paths_are_indexed(p):
    assert is_vendor_or_minified(p) is False


def test_exclusion_matching_parity_with_the_review_file_filter():
    """The privacy baseline must filter index reads and review files with
    *identical* semantics — one fnmatch rule, never a drifting copy."""
    from ai_pr_reviewer.orchestrator import _is_excluded
    from ai_pr_reviewer.rules import SENSITIVE_EXCLUDE_GLOBS

    patterns = [*SENSITIVE_EXCLUDE_GLOBS, "generated/**", "**/*.lock", " "]
    paths = [".env", "sub/.env", "secrets/key.pem", "src/app.py",
             "generated/x.py", "a/b.lock", "config/settings.yml", "n"]
    for p in paths:
        assert is_excluded(p, patterns) == _is_excluded(p, patterns), p


def test_limits_clamp_configured_values_to_the_hard_caps():
    class Hostile:
        context_max_files = 10 ** 9
        context_max_bytes = HARD_MAX_BYTES + 1
    limits = IndexLimits.from_policy(Hostile())
    assert limits.max_files == HARD_MAX_FILES
    assert limits.max_bytes == HARD_MAX_BYTES

    class Zero:
        context_max_files = 0
        context_max_bytes = -5
    zero = IndexLimits.from_policy(Zero())
    assert zero.max_files == lim.DEFAULT_MAX_FILES   # <1 → default, never 0
    assert zero.max_bytes == lim.DEFAULT_MAX_BYTES


def test_limits_from_a_bare_object_fall_back_to_defaults():
    """Missing attributes (test doubles, older policies) must work —
    defensive getattr, never AttributeError."""
    assert IndexLimits.from_policy(object()) == IndexLimits()


def test_index_package_never_imports_execution_or_network_modules():
    """Hard rule 2 (no repository code execution) + E08-T03 (no network
    fetching, no model dependency): the index package is stdlib-filesystem
    only. An AST scan pins the whole package, new modules included."""
    forbidden = {
        "subprocess", "socket", "ssl", "urllib", "http", "httpx", "requests",
        "ftplib", "telnetlib", "asyncio", "ctypes", "importlib", "shutil",
        "anthropic", "openai", "google",
    }
    pkg = Path(ai_pr_reviewer.__file__).parent / "index"
    checked = 0
    for file in sorted(pkg.glob("*.py")):
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    names = [node.module.split(".")[0]]
            for name in names:
                assert name not in forbidden, (
                    f"{file.name} imports {name!r} — the index build must "
                    f"never execute code or reach the network")
            checked += 1
    assert checked > 0  # the scan really ran


# ================================================== fixtures for index builds

def _write_tree(root: Path, files: dict) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def _git_checkout(root: Path,
                  origin="https://github.com/acme/api.git") -> None:
    """Fake a checkout by *writing* ``.git`` config — the index build must
    never run ``git``, so the fixture doesn't either (unless a test shells
    out explicitly for a symlink/gitfile case)."""
    (root / ".git").mkdir(exist_ok=True)
    if origin is not None:
        (root / ".git" / "config").write_text(
            '[core]\n\tbare = false\n'
            '[remote "origin"]\n'
            f"\turl = {origin}\n"
            "\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
            encoding="utf-8")


# ==================================================== E01-T01 · inventory

def test_inventory_is_sorted_deterministic_and_marks_changed_files(tmp_path):
    from ai_pr_reviewer.index import build_index

    _write_tree(tmp_path, {"b.py": "x = 1\n", "a.py": "y = 2\n",
                           "sub/c.py": "z = 3\n"})
    _git_checkout(tmp_path)

    first = build_index(str(tmp_path), expected_repo="acme/api",
                        changed_paths=["b.py"])
    second = build_index(str(tmp_path), expected_repo="acme/api",
                         changed_paths=["b.py"])

    assert first is not None and first == second      # byte-for-byte deterministic
    assert first.paths == ("a.py", "b.py", "sub/c.py")  # sorted, not walk order
    assert first.budget_state == "ok"
    assert first.warnings == ()
    assert {f.path: f.changed for f in first.files} == {
        "a.py": False, "b.py": True, "sub/c.py": False}


@pytest.mark.parametrize("path, lang", [
    ("app/main.py", "python"),
    ("web/app.js", "javascript"),
    ("web/app.tsx", "typescript"),
    ("Svc.java", "java"),
    ("mod.kt", "kotlin"),
    ("main.rs", "rust"),
    ("lib.go", "go"),
    ("script.sh", "shell"),
    ("Dockerfile", "dockerfile"),
    ("Makefile", "make"),
    ("conf/app.yaml", "yaml"),
    ("package.json", "json"),
    ("data.blob", "unknown"),
    ("README", "unknown"),
])
def test_language_detection_by_extension_and_special_names(path, lang):
    from ai_pr_reviewer.index.inventory import detect_language
    assert detect_language(path) == lang


def test_vendor_trees_lockfiles_and_excluded_paths_never_enter_the_index(tmp_path):
    from ai_pr_reviewer.index import build_index

    _write_tree(tmp_path, {
        "src/app.py": "def main(): pass\n",
        "node_modules/react/index.js": "module.exports = 1\n",
        "package-lock.json": "{}\n",
        "src/app.min.js": "var a=1;\n",
        "secrets/key.pem": "PRIVATE\n",
        ".env": "TOKEN=x\n",
        "generated/big.py": "x = 1\n",
    })
    _git_checkout(tmp_path)

    index = build_index(str(tmp_path), expected_repo="acme/api",
                        exclusions=["**/*.pem", ".env", ".env.*",
                                    "generated/**"])
    assert index is not None
    assert index.paths == ("src/app.py",)


def test_depth_cap_truncates_loudly(tmp_path):
    from ai_pr_reviewer.index import IndexLimits, build_index

    deep = tmp_path / ("d1/" * 10)
    _write_tree(tmp_path, {"top.py": "x = 1\n",
                           "d1/" * 10 + "deep.py": "y = 2\n"})
    _git_checkout(tmp_path)

    index = build_index(str(tmp_path), expected_repo="acme/api",
                        limits=IndexLimits(max_depth=3))
    assert index is not None
    assert index.budget_state == "truncated"
    assert any("depth" in w for w in index.warnings)
    assert "top.py" in index.paths and "d1/" * 10 + "deep.py" not in index.paths
    assert deep.exists()  # the fixture itself is intact


# ===================================================== E01-T02 · symbols

PY_TREE = {
    "app/main.py": (
        "import os\n"
        "from utils.helpers import helper\n"
        "\n"
        "class Worker:\n"
        "    def run(self):\n"
        "        return helper()\n"
        "\n"
        "async def main():\n"
        "    pass\n"
    ),
    "utils/helpers.py": "def helper():\n    return 1\n",
}


def test_python_symbols_and_imports(tmp_path):
    from ai_pr_reviewer.index import build_index

    _write_tree(tmp_path, PY_TREE)
    _git_checkout(tmp_path)
    index = build_index(str(tmp_path), expected_repo="acme/api")
    entry = index.file("app/main.py")

    names = {(s.kind, s.name) for s in entry.symbols}
    assert ("class", "Worker") in names
    assert ("function", "main") in names
    assert ("function", "run") in names
    assert entry.imports == ("os", "utils.helpers")   # line order, deduped
    assert entry.symbols_truncated is False
    # every symbol line is a real line of the file
    assert all(1 <= s.line <= len(PY_TREE["app/main.py"].splitlines())
               for s in entry.symbols)


def test_javascript_typescript_and_java_symbols(tmp_path):
    from ai_pr_reviewer.index import build_index

    _write_tree(tmp_path, {
        "web/app.js": (
            'import { helper } from "./lib";\n'
            "const start = () => {};\n"
            "function boot() {}\n"
            "class Engine {}\n"
            'const x = require("./lib");\n'
        ),
        "web/lib.js": "export function helper() {}\n",
        "java/Svc.java": (
            "package com.acme;\n"
            "import com.acme.util.Helpers;\n"
            "public class Svc {\n"
            "}\n"
        ),
    })
    _git_checkout(tmp_path)
    index = build_index(str(tmp_path), expected_repo="acme/api")

    js = index.file("web/app.js")
    js_names = {(s.kind, s.name) for s in js.symbols}
    assert ("function", "start") in js_names     # arrow const
    assert ("function", "boot") in js_names
    assert ("class", "Engine") in js_names
    assert js.imports == ("./lib",)

    java = index.file("java/Svc.java")
    assert [(s.kind, s.name) for s in java.symbols] == [("class", "Svc")]
    assert java.imports == ("com.acme.util.Helpers",)


def test_config_and_unknown_files_are_inventoried_without_symbols(tmp_path):
    from ai_pr_reviewer.index import build_index

    _write_tree(tmp_path, {"conf/app.yaml": "key: value\n",
                           "package.json": '{"name": "x"}\n',
                           "data.blob": "\x00\x01binary-ish\n"})
    _git_checkout(tmp_path)
    index = build_index(str(tmp_path), expected_repo="acme/api")

    for path, lang in (("conf/app.yaml", "yaml"),
                       ("package.json", "json"),
                       ("data.blob", "unknown")):
        entry = index.file(path)
        assert entry is not None and entry.language == lang
        assert entry.symbols == () and entry.imports == ()


def test_giant_files_stay_in_the_inventory_but_are_not_parsed(tmp_path):
    from ai_pr_reviewer.index import IndexLimits, build_index

    _write_tree(tmp_path, {"small.py": "def ok(): pass\n",
                           "giant.py": "def hidden(): pass\n" + "# pad\n" * 5000})
    _git_checkout(tmp_path)
    limits = IndexLimits(max_file_bytes=1024)

    index = build_index(str(tmp_path), expected_repo="acme/api", limits=limits)
    giant = index.file("giant.py")
    assert giant is not None and giant.size > 1024
    assert giant.symbols == ()                     # never read
    assert index.file("small.py").symbols          # normal file unaffected
    assert index.budget_state == "ok"              # size cap ≠ budget exhaustion


def test_byte_budget_exhaustion_is_a_controlled_state(tmp_path):
    """Threat model §1: exhaustion is loud + partial, never a crash —
    the inventory stays complete while symbol reads stop."""
    from ai_pr_reviewer.index import IndexLimits, build_index

    _write_tree(tmp_path, {"a.py": "def first(): pass\n",
                           "b.py": "def second(): pass\n",
                           "c.py": "def third(): pass\n"})
    _git_checkout(tmp_path)

    index = build_index(str(tmp_path), expected_repo="acme/api",
                        limits=IndexLimits(max_bytes=20))
    assert index is not None
    assert index.budget_state == "exhausted"
    assert any("byte budget" in w for w in index.warnings)
    assert len(index.files) == 3                       # inventory complete
    assert index.file("a.py").symbols                  # 18 bytes fit
    assert index.file("b.py").symbols == ()            # budget gone
    assert index.file("c.py").symbols == ()            # stays gone (terminal)


def test_warning_lists_are_bounded_however_pathological_the_tree():
    """Bounded expansion applies to diagnostics too: a hostile tree that
    produces hundreds of per-path warnings gets a capped list."""
    from ai_pr_reviewer.index.builder import MAX_WARNINGS, _cap_warnings

    assert _cap_warnings(["one"]) == ("one",)
    capped = _cap_warnings([f"w{i}" for i in range(100)])
    assert len(capped) == MAX_WARNINGS + 1
    assert "suppressed" in capped[-1]


def test_symbol_and_import_caps_produce_a_truncation_flag(tmp_path):
    from ai_pr_reviewer.index import IndexLimits, build_index

    _write_tree(tmp_path, {"many.py": "".join(
        f"def fn_{i}(): pass\n" for i in range(50))})
    _git_checkout(tmp_path)

    index = build_index(str(tmp_path), expected_repo="acme/api",
                        limits=IndexLimits(max_symbols_per_file=10))
    entry = index.file("many.py")
    assert len(entry.symbols) == 10
    assert entry.symbols_truncated is True


# ======================================================= E01-T03 · graph

def test_import_graph_resolves_inside_files_and_ignores_external_packages(tmp_path):
    from ai_pr_reviewer.index import build_index

    _write_tree(tmp_path, {
        "app/main.py": "from utils.helpers import helper\nimport os\n",
        "utils/helpers.py": "def helper(): pass\n",
        "web/app.js": 'import { other } from "./lib";\n',
        "web/lib.js": "export function other() {}\n",
        "java/Svc.java": "import com.acme.util.Helpers;\npublic class Svc {}\n",
    })
    _git_checkout(tmp_path)
    index = build_index(str(tmp_path), expected_repo="acme/api")

    assert ("app/main.py", "utils/helpers.py") in index.edges
    assert ("web/app.js", "web/lib.js") in index.edges
    # external packages produce NO invented edges
    assert not any(dst == "os" for _, dst in index.edges)
    assert not any("Helpers" in dst for _, dst in index.edges)
    # reverse map
    assert index.importers("utils/helpers.py") == ("app/main.py",)
    assert index.importers("app/main.py") == ()


def test_graph_edges_are_capped_loudly(tmp_path):
    from ai_pr_reviewer.index import IndexLimits, build_index

    files = {f"m{i}.py": "import m0\n" for i in range(1, 6)}
    files["m0.py"] = "x = 1\n"
    _write_tree(tmp_path, files)
    _git_checkout(tmp_path)

    index = build_index(str(tmp_path), expected_repo="acme/api",
                        limits=IndexLimits(max_edges=2))
    assert len(index.edges) == 2
    assert any("edge cap" in w for w in index.warnings)
    assert index.budget_state == "ok"   # graph cap ≠ inventory/read budget


def test_edges_are_deterministic_and_self_imports_are_dropped(tmp_path):
    from ai_pr_reviewer.index import build_index

    _write_tree(tmp_path, {"a.py": "import a\nimport b\n",
                           "b.py": "x = 1\n"})
    _git_checkout(tmp_path)

    index = build_index(str(tmp_path), expected_repo="acme/api")
    assert index.edges == (("a.py", "b.py"),)
    assert index == build_index(str(tmp_path), expected_repo="acme/api")


# ================================================ E01-T05 · pipeline wiring

_DIFF = (
    "diff --git a/app/main.py b/app/main.py\n"
    "--- a/app/main.py\n"
    "+++ b/app/main.py\n"
    "@@ -1 +1 @@\n"
    "-old\n"
    "+new\n"
)

#: Every field of ReviewContext that providers/report actually consume.
_PROMPT_VISIBLE_FIELDS = (
    "files", "previous_findings", "memory_notes", "focus_areas",
    "token_budget", "repo_context", "context_warnings",
)


def _build_ctx(tmp_path, monkeypatch, *, repo="acme/api", cfg=None, gh=None):
    from ai_pr_reviewer.config import Config
    from ai_pr_reviewer.context import build_context
    from ai_pr_reviewer.diff_parser import parse_unified_diff
    from ai_pr_reviewer.models import PRContext

    monkeypatch.chdir(tmp_path)
    pr = PRContext(repo=repo, pr_number=7, base_sha="b" * 40,
                   head_sha="h" * 40)
    return build_context(pr, parse_unified_diff(_DIFF), cfg or Config(),
                         storage=None, gh=gh)


def test_build_context_exposes_the_index_when_the_checkout_matches(tmp_path,
                                                                   monkeypatch):
    _write_tree(tmp_path, {"app/main.py": "def run(): pass\n"})
    _git_checkout(tmp_path)                       # origin = acme/api
    ctx = _build_ctx(tmp_path, monkeypatch)

    assert ctx.repo_index is not None
    assert ctx.repo_index.paths == ("app/main.py",)
    assert ctx.repo_index.file("app/main.py").changed is True   # diff marking
    assert ctx.repo_index.budget_state == "ok"


def test_index_is_declined_for_a_checkout_of_a_different_repository(
        tmp_path, monkeypatch, caplog):
    """Trust boundary: an index of the wrong tree must never be available
    to context selection."""
    _write_tree(tmp_path, {"app/main.py": "x = 1\n"})
    _git_checkout(tmp_path, origin="https://github.com/other/repo.git")
    with caplog.at_level("INFO"):
        ctx = _build_ctx(tmp_path, monkeypatch)          # reviewing acme/api
    assert ctx.repo_index is None
    assert any("origin" in r.getMessage() and "acme/api" in r.getMessage()
               for r in caplog.records)


def test_index_is_declined_without_a_git_checkout(tmp_path, monkeypatch,
                                                  caplog):
    _write_tree(tmp_path, {"a.py": "x = 1\n"})
    with caplog.at_level("INFO"):
        ctx = _build_ctx(tmp_path, monkeypatch)
    assert ctx.repo_index is None
    assert any("no git checkout" in r.getMessage() for r in caplog.records)


def test_repo_context_chars_zero_disables_the_index(tmp_path, monkeypatch,
                                                    caplog):
    """The outer ceiling is the master switch: ``0`` means no repository
    reads beyond the diff — so the index build is skipped too, silently
    (an explicit opt-out is not a degradation)."""
    _write_tree(tmp_path, {"a.py": "x = 1\n"})
    _git_checkout(tmp_path)
    cfg = Config()
    cfg.repo_context_chars = 0
    with caplog.at_level("WARNING"):
        ctx = _build_ctx(tmp_path, monkeypatch, cfg=cfg)
    assert ctx.repo_index is None
    assert not any("repository index" in r.getMessage()
                   for r in caplog.records)


def test_privacy_baseline_filters_index_reads_through_the_pipeline(
        tmp_path, monkeypatch):
    """Threat model §1 (E01-T04): the non-removable exclusion baseline in
    ``rules.py`` filters index reads — a sensitive file never appears in
    the index even with no explicit exclusions configured."""
    _write_tree(tmp_path, {".env": "TOKEN=x\n", "secrets/key.pem": "PRIVATE\n",
                           "app.py": "x = 1\n"})
    _git_checkout(tmp_path)
    ctx = _build_ctx(tmp_path, monkeypatch)      # default policy = baseline

    assert ctx.repo_index is not None
    assert ctx.repo_index.paths == ("app.py",)


def test_index_wiring_leaves_every_prompt_visible_field_unchanged(
        tmp_path, monkeypatch):
    """E01-T05: existing review behavior is preserved — the index is the
    ONLY thing that differs between an unavailable and an available run."""
    _write_tree(tmp_path, {"app/main.py": "def run(): pass\n",
                           "extra.py": "y = 2\n"})
    _git_checkout(tmp_path, origin="https://github.com/other/repo.git")
    without = _build_ctx(tmp_path, monkeypatch)          # declined
    _git_checkout(tmp_path, origin="https://github.com/acme/api.git")
    with_index = _build_ctx(tmp_path, monkeypatch)       # built

    assert without.repo_index is None
    assert with_index.repo_index is not None
    for name in _PROMPT_VISIBLE_FIELDS:
        assert getattr(without, name) == getattr(with_index, name), name
    assert (without.project_rules.rules == with_index.project_rules.rules
            and without.project_rules.focus == with_index.project_rules.focus)


def test_index_budgets_operate_beneath_the_outer_ceiling(tmp_path,
                                                         monkeypatch):
    """E01-T04: ``context.max_files`` / ``context.max_bytes`` only change
    the index itself — shrinking them to a corner changes no prompt-
    visible field (one budget system: ``repo_context_chars`` remains the
    outer ceiling, and nothing here can enlarge what reaches a prompt)."""
    _write_tree(tmp_path, {"a.py": "x = 1\n", "b.py": "y = 2\n",
                           "c.py": "z = 3\n"})
    _git_checkout(tmp_path)

    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        "context:\n  max_files: 1\n  max_bytes: 1048576\n", encoding="utf-8")
    tiny = _build_ctx(tmp_path, monkeypatch)
    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        "context:\n  max_files: 9999\n  max_bytes: 9999999\n", encoding="utf-8")
    huge = _build_ctx(tmp_path, monkeypatch)

    assert tiny.repo_index.budget_state == "truncated"
    assert len(tiny.repo_index.files) == 1                  # capped at one file
    assert huge.repo_index.budget_state == "ok"
    assert len([f for f in huge.repo_index.files
                if f.path.endswith(".py")]) == 3             # everything fit
    for name in _PROMPT_VISIBLE_FIELDS:
        assert getattr(tiny, name) == getattr(huge, name), name
    assert (tiny.project_rules.rules == huge.project_rules.rules
            and tiny.project_rules.focus == huge.project_rules.focus)


def test_no_provider_reads_the_index(tmp_path):
    """Pin for "no prompt change" (E01-T05): the AI providers never
    reference ``repo_index`` — selection that consumes it is E02's
    contract, not E01's."""
    from ai_pr_reviewer.ai import claude, gemini, openai

    for module in (claude, openai, gemini):
        source = Path(module.__file__).read_text(encoding="utf-8")
        assert "repo_index" not in source, module.__name__
