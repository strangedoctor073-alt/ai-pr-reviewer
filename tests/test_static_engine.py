"""Tests for ai_pr_reviewer.static.

Layout:
  1. Regression — every rule_id that fired on the existing demo fixtures
     before the split still fires after it (same inputs as test_pipeline.py
     uses, via demo.make_fixtures.build_all()).
  2. New AST-based Python checks (AST001-AST006).
  3. New JavaScript checks (JS001-JS002).
  4. New shell checks (SH001-SH003).
  5. Test-gap heuristic (TEST001).
  6. RuleRegistry / StaticEngine plumbing.
  7. heuristics.py backward-compatibility shim.

"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import heuristics
from ai_pr_reviewer.diff_parser import FileDiff, parse_unified_diff
from ai_pr_reviewer.static import javascript_rules, python_rules, security_rules, shell_rules
from ai_pr_reviewer.static import test_rules as test_gap_rules
from ai_pr_reviewer.static.engine import StaticEngine, build_default_registry
from ai_pr_reviewer.static.registry import Rule, RuleRegistry
from demo.make_fixtures import build_all


# --------------------------------------------------------------------- helpers
def _files(diff_text: str) -> list[FileDiff]:
    p = Path(diff_text)
    if p.exists():                       # fixtures carry diff file paths
        diff_text = p.read_text(encoding="utf-8")
    return parse_unified_diff(diff_text)


def _new_file_diff(path: str, content: str) -> str:
    """Build a minimal unified diff that adds `path` as a brand-new file
    with `content`, so every line is an added ('+') line — the simplest
    way to get precise, predictable line numbers for targeted rule tests."""
    lines = content.splitlines()
    header = [
        f"diff --git a/{path} b/{path}",
        "new file mode 100644",
        "index 0000000..1111111",
        "--- /dev/null",
        f"+++ b/{path}",
        f"@@ -0,0 +1,{len(lines)} @@",
    ]
    body = [f"+{l}" for l in lines]
    return "\n".join(header + body) + "\n"


def _ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


@pytest.fixture(scope="module")
def fixtures():
    return {fx["name"]: fx for fx in build_all()}


# =========================================================== 1 · regression
# Same sample diffs tests/test_pipeline.py exercises via MockAnalyzer/
# analyze_with_rules — asserting on rule_id (not just title substrings) is a
# stricter check that every relocated rule fires on exactly the same inputs
# it did before the move from the flat heuristics.py RULES list.

def test_python_fixture_rule_ids_unchanged(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    ids = _ids(StaticEngine().run(files))
    expected_minimum = {
        "SEC001",   # f-string SQL injection (refunds.py)
        "ERR001",   # bare `except:` (refunds.py)
        "ERR002",   # `except Exception: pass` (api.py)
        "ERR006",   # mutable default arg (refunds.py, regex)
        "HYG001",   # print() (refunds.py)
    }
    assert expected_minimum <= ids
    # and the new AST layer should independently reach the same two bugs
    assert "AST001" in ids   # mutable default, AST-detected
    assert "AST004" in ids   # bare except / except-pass, AST-detected


def test_js_fixture_rule_ids_unchanged(fixtures):
    files = _files(fixtures["frontend_checkout"]["diff"])
    ids = _ids(StaticEngine().run(files))
    assert {"ERR004", "ERR005", "SEC005", "SEC006", "HYG002"} <= ids


def test_shell_fixture_rule_ids_unchanged(fixtures):
    files = _files(fixtures["infra_deploy"]["diff"])
    ids = _ids(StaticEngine().run(files))
    assert {"SEC002", "ERR007", "SEC008"} <= ids
    # new: unquoted $BUILD_DIR on the `rm -rf` line
    assert "SH001" in ids
    # chmod -R 777 is exactly the SEC008 case — SH003 must NOT double-fire
    assert "SH003" not in ids


def test_all_relocated_rule_ids_present_exactly_once(fixtures):
    """No rule_id was dropped, and none was accidentally duplicated across
    two rule modules (e.g. by both defining a SEC* rule)."""
    registry = build_default_registry()
    ids = [r.rule_id for r in registry.line_rules]
    assert len(ids) == len(set(ids)), f"duplicate rule_id(s) in registry: {ids}"

    original_21 = {
        "SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006", "SEC007", "SEC008",
        "ERR001", "ERR002", "ERR003", "ERR004", "ERR005", "ERR006", "ERR007",
        "RES001", "RES002",
        "HYG001", "HYG002", "HYG003", "HYG004",
    }
    assert original_21 <= set(ids)


# ============================================== 2 · AST-based Python checks

def test_ast_mutable_default_and_bare_except():
    diff = _new_file_diff("pkg/audit.py", (
        '"""module docstring."""\n'
        "def record(event, entries=[]):\n"
        "    entries.append(event)\n"
        "    return entries\n"
    ))
    findings = python_rules.ast_checks(_files(diff)[0])
    ids = _ids(findings)
    assert "AST001" in ids
    mutable = next(f for f in findings if f.rule_id == "AST001")
    assert mutable.line == 2   # the `def record(...)` line


def test_ast_eval_and_exec():
    diff = _new_file_diff("pkg/danger.py", (
        "def run(user_input, payload):\n"
        "    result = eval(user_input)\n"
        "    exec(payload)\n"
        "    return result\n"
    ))
    findings = python_rules.ast_checks(_files(diff)[0])
    assert sum(1 for f in findings if f.rule_id == "AST002") == 2


def test_ast_subprocess_shell_true():
    diff = _new_file_diff("pkg/runner.py", (
        "import subprocess\n\n"
        "def deploy(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
    ))
    findings = python_rules.ast_checks(_files(diff)[0])
    assert "AST003" in _ids(findings)


def test_ast_bare_except_standalone():
    diff = _new_file_diff("pkg/safe.py", (
        "def load(path):\n"
        "    try:\n"
        "        return open(path).read()\n"
        "    except:\n"
        "        return None\n"
    ))
    findings = python_rules.ast_checks(_files(diff)[0])
    assert "AST004" in _ids(findings)


def test_ast_unsafe_pickle_and_yaml():
    diff = _new_file_diff("pkg/loaders.py", (
        "import pickle, yaml\n\n"
        "def load_all(f, stream):\n"
        "    obj = pickle.load(f)\n"
        "    cfg = yaml.load(stream)\n"
        "    return obj, cfg\n"
    ))
    findings = python_rules.ast_checks(_files(diff)[0])
    ids = _ids(findings)
    assert "AST005" in ids   # pickle.load
    assert "AST006" in ids   # yaml.load without Loader=


def test_ast_yaml_safe_load_with_loader_not_flagged():
    diff = _new_file_diff("pkg/loaders_ok.py", (
        "import yaml\n\n"
        "def load_all(stream):\n"
        "    return yaml.load(stream, Loader=yaml.SafeLoader)\n"
    ))
    findings = python_rules.ast_checks(_files(diff)[0])
    assert "AST006" not in _ids(findings)


def test_ast_skips_unparseable_fragment_silently():
    """A hunk whose added lines alone aren't syntactically coherent (here:
    an added `else:` clause with no matching `if` in the added text) must
    not raise — it's silently skipped, per the documented limitation."""
    diff_text = (
        "--- a/pkg/x.py\n+++ b/pkg/x.py\n"
        "@@ -1,2 +1,4 @@\n"
        " if flag:\n"
        "     do_a()\n"
        "+else:\n"
        "+    do_b()\n"
    )
    fd = parse_unified_diff(diff_text)[0]
    # else: alone (no `if`) is a SyntaxError when parsed standalone — must
    # not raise out of ast_checks().
    findings = python_rules.ast_checks(fd)
    assert isinstance(findings, list)


# ================================================== 3 · new JavaScript rules

def test_js001_template_literal_sql():
    diff = _new_file_diff("src/db.js", (
        "export function findUser(userId) {\n"
        "  return db.raw(`SELECT * FROM users WHERE id = ${userId}`);\n"
        "}\n"
    ))
    findings = StaticEngine().run(_files(diff))
    assert "JS001" in _ids(findings)


def test_js001_not_flagged_for_plain_template_literal():
    diff = _new_file_diff("src/greet.js", (
        "export function greet(name) {\n"
        "  return `Hello, ${name}!`;\n"
        "}\n"
    ))
    findings = StaticEngine().run(_files(diff))
    assert "JS001" not in _ids(findings)


def test_js002_document_write():
    diff = _new_file_diff("src/legacy.js", (
        "export function bannerFrom(html) {\n"
        "  document.write(html);\n"
        "}\n"
    ))
    findings = StaticEngine().run(_files(diff))
    assert "JS002" in _ids(findings)


# ======================================================= 4 · new shell rules

def test_sh001_unquoted_var_outside_quotes():
    diff = _new_file_diff("deploy/cleanup.sh", (
        "#!/usr/bin/env bash\n"
        "cp $SRC $DST\n"
    ))
    findings = shell_rules.unquoted_var_findings(_files(diff)[0])
    assert {f.rule_id for f in findings} == {"SH001"}


def test_sh001_not_flagged_when_quoted():
    diff = _new_file_diff("deploy/cleanup_ok.sh", (
        "#!/usr/bin/env bash\n"
        'cp "$SRC" "$DST"\n'
    ))
    findings = shell_rules.unquoted_var_findings(_files(diff)[0])
    assert findings == []


def test_sh002_curl_pipe_to_shell():
    diff = _new_file_diff("deploy/install.sh", (
        "#!/usr/bin/env bash\n"
        "curl -sSL https://get.example.com/install.sh | bash\n"
    ))
    findings = StaticEngine().run(_files(diff))
    assert "SH002" in _ids(findings)


def test_sh003_chmod_world_writable_not_777():
    diff = _new_file_diff("deploy/perms.sh", (
        "#!/usr/bin/env bash\n"
        "chmod 757 /srv/shared\n"
    ))
    findings = StaticEngine().run(_files(diff))
    assert "SH003" in _ids(findings)


# =================================================== 5 · test-gap heuristic

def test_gap_flagged_when_no_test_file_changed():
    diff = _new_file_diff("payments/charge.py", (
        "def charge(order_id, amount_cents):\n"
        "    return process(order_id, amount_cents)\n"
    ))
    findings = test_gap_rules.gap_findings(_files(diff))
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "TEST001"
    assert f.line is None
    assert f.title == "possible missing test coverage"


def test_gap_not_flagged_when_matching_test_present():
    combined = (
        _new_file_diff("payments/charge.py", (
            "def charge(order_id, amount_cents):\n"
            "    return process(order_id, amount_cents)\n"
        )) +
        _new_file_diff("tests/test_charge.py", (
            "def test_charge():\n"
            "    assert charge(1, 100) is not None\n"
        ))
    )
    files = parse_unified_diff(combined)
    findings = test_gap_rules.gap_findings(files)
    assert findings == []


def test_gap_ignores_test_config_and_doc_files():
    combined = (
        _new_file_diff("tests/test_charge.py", (
            "def test_nothing():\n"
            "    assert True\n"
        )) +
        _new_file_diff("README.md", "# Docs\n") +
        _new_file_diff(".ai-pr-reviewer.yml", "review:\n  mode: balanced\n")
    )
    files = parse_unified_diff(combined)
    findings = test_gap_rules.gap_findings(files)
    assert findings == []


# ====================================================== 6 · registry/engine

def test_registry_buckets_are_populated():
    registry = build_default_registry()
    assert registry.line_rules
    assert registry.file_rules   # AST checks + unquoted-var checks
    assert registry.diff_rules   # test-gap heuristic
    assert "SEC001" in registry.rule_ids()


def test_engine_run_sorts_by_severity_descending():
    diff = _new_file_diff("mix/bugs.py", (
        "def handler(items=[]):\n"          # high  (ERR006/AST001)
        "    print(items)\n"                # low   (HYG001)
        "    return items\n"
    ))
    findings = StaticEngine().run(_files(diff))
    from ai_pr_reviewer.models import SEVERITY_ORDER
    ranks = [SEVERITY_ORDER[f.severity] for f in findings]
    assert ranks == sorted(ranks, reverse=True)


def test_custom_registry_can_isolate_one_module():
    registry = RuleRegistry()
    security_rules.register(registry)
    assert registry.rule_ids() == {
        "SEC001", "SEC002", "SEC003", "SEC004",
        "SEC005", "SEC006", "SEC007", "SEC008",
    }
    assert registry.file_rules == []
    assert registry.diff_rules == []


# =========================================== 7 · heuristics.py compat shim

def test_heuristics_shim_matches_engine_output(fixtures):
    files = _files(fixtures["payments_refunds"]["diff"])
    via_shim = _ids(heuristics.analyze_with_rules(files))
    via_engine = _ids(StaticEngine().run(files))
    assert via_shim == via_engine


def test_heuristics_rule_reexported_and_rules_list_empty():
    assert heuristics.Rule is Rule
    assert heuristics.RULES == []


# =============================================== 8 · AIProvider conformance
def test_analyze_context_builds_analysis_outcome(fixtures):
    class _Ctx:
        def __init__(self, files):
            self.files = files

    files = _files(fixtures["payments_refunds"]["diff"])
    outcome = StaticEngine().analyze(_Ctx(files))
    assert outcome.mode == "static"
    assert outcome.model == "static-rules-v1"
    assert outcome.engine == "static"
    assert outcome.fallback_used is False
    assert outcome.batch_count == 1
    assert outcome.findings
