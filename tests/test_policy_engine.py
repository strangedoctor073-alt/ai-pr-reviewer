"""V4.2-E07 policy engine v1: schema (T01), evaluator (T02), findings
pipeline (T03), v1 compatibility + non-removable baseline (T04).

Offline, deterministic, synthetic fixtures only.
"""
from __future__ import annotations

import ast
import logging
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import pytest

from ai_pr_reviewer.config import Config
from ai_pr_reviewer.diff_parser import parse_unified_diff
from ai_pr_reviewer.models import PRContext
from ai_pr_reviewer.orchestrator import ReviewOrchestrator
from ai_pr_reviewer.policy import (CLAUSE_TYPES, STATUS_FAIL, STATUS_PASS,
                                   STATUS_UNKNOWN, PolicyConfig,
                                   clause_locator, evaluate_policy,
                                   load_policy_config, parse_policy_section,
                                   policy_findings, review_policy)
from ai_pr_reviewer.policy import evaluate as evaluate_mod
from ai_pr_reviewer.rules import (SENSITIVE_EXCLUDE_GLOBS, ReviewPolicy,
                                  load_project_rules)


def _diff(*files: tuple[str, list[str]]) -> str:
    """Synthetic unified diff: (path, added lines) per file."""
    out = []
    for path, added in files:
        out.append(f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
                   f"@@ -1,1 +1,{1 + len(added)} @@\n context\n"
                   + "".join(f"+{line}\n" for line in added))
    return "".join(out)


def _files(*files):
    return parse_unified_diff(_diff(*files))


def _cfg(*clauses, **extra):
    return parse_policy_section({"version": 2, "clauses": list(clauses), **extra})


AUTH = {"id": "AUTH-TESTS", "type": "require_change", "severity": "high",
        "message": "Auth changes need tests.",
        "when_paths": ["src/auth/**"], "require_paths": ["tests/**"]}


# ------------------------------------------------------------------ T01
def test_valid_section_parses_all_clause_types():
    cfg = _cfg(
        AUTH,
        {"id": "NO-MIG", "type": "forbid_change", "paths": ["db/migrations/**"]},
        {"id": "NO-EVAL", "type": "forbid_added_text", "paths": ["**/*.py"],
         "contains": ["eval("]},
        {"id": "FILES", "type": "max_changed_files", "limit": 3},
        {"id": "LINES", "type": "max_added_lines", "limit": 10, "paths": ["src/**"]},
    )
    assert [c.id for c in cfg.clauses] == ["AUTH-TESTS", "NO-MIG", "NO-EVAL",
                                           "FILES", "LINES"]
    assert {c.type for c in cfg.clauses} == set(CLAUSE_TYPES)
    assert cfg.clauses[0].severity == "high"
    assert cfg.enabled and not cfg.warnings


def test_absent_or_empty_section_is_no_policy():
    assert parse_policy_section(None) == PolicyConfig()
    assert not parse_policy_section({}).enabled
    assert not parse_policy_section({"clauses": []}).enabled


def test_unknown_clause_type_degrades_to_guidance_with_warning():
    cfg = _cfg({"id": "FUTURE", "type": "quantum_check", "message": "someday"})
    assert [c.type for c in cfg.clauses] == ["guidance"]
    assert any("unknown clause type" in w for w in cfg.warnings)


@pytest.mark.parametrize("bad", [
    "not a mapping",
    {"type": "forbid_change", "paths": ["a"]},                       # no id
    {"id": "1bad", "type": "forbid_change", "paths": ["a"]},         # bad id
    {"id": "X", "type": "forbid_change"},                            # no paths
    {"id": "X", "type": "require_change", "when_paths": ["a"]},      # no require
    {"id": "X", "type": "max_changed_files", "limit": "ten"},
    {"id": "X", "type": "max_changed_files", "limit": True},
    {"id": "X", "type": "max_changed_files", "limit": -1},
])
def test_malformed_clause_is_skipped_never_fatal(bad):
    cfg = _cfg(bad)
    assert cfg.clauses == ()
    assert cfg.warnings


def test_duplicate_ids_and_bad_severity_and_stray_keys():
    cfg = _cfg(
        {"id": "A", "type": "forbid_change", "paths": ["x"], "severity": "dire",
         "oops": 1},
        {"id": "A", "type": "forbid_change", "paths": ["y"]},
    )
    assert len(cfg.clauses) == 1 and cfg.clauses[0].severity == "medium"
    joined = " ".join(cfg.warnings)
    assert "duplicate clause id" in joined and "invalid severity" in joined
    assert "unknown key(s) ignored: oops" in joined


def test_bounds_caps():
    many = [{"id": f"C{i}", "type": "forbid_change", "paths": ["p"]}
            for i in range(80)]
    assert len(_cfg(*many).clauses) == 50
    cfg = _cfg({"id": "L", "type": "forbid_change",
                "paths": [f"p{i}" for i in range(80)],
                "message": "m" * 1000})
    assert len(cfg.clauses[0].params["paths"]) == 50
    assert len(cfg.clauses[0].message) == 300


def test_non_mapping_section_ignored_with_warning():
    cfg = parse_policy_section(["x"])
    assert not cfg.enabled and cfg.warnings


def test_loader_missing_malformed_and_valid(tmp_path):
    assert load_policy_config(str(tmp_path)) == PolicyConfig()
    (tmp_path / ".ai-pr-reviewer.yml").write_text("policy: [unclosed\n  - {",
                                                  encoding="utf-8")
    bad = load_policy_config(str(tmp_path))
    assert not bad.enabled and bad.warnings      # fail-closed: baseline only
    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        "review:\n  mode: balanced\npolicy:\n  clauses:\n"
        "    - {id: A, type: forbid_change, paths: ['x/**']}\n", encoding="utf-8")
    assert [c.id for c in load_policy_config(str(tmp_path)).clauses] == ["A"]


# ------------------------------------------------------------------ T02
def _status(clause, files):
    return evaluate_policy(_cfg(clause), files).results[0]


def test_require_change_truth_table():
    not_triggered = _files(("docs/readme.md", ["x"]))
    satisfied = _files(("src/auth/login.py", ["x"]), ("tests/test_login.py", ["x"]))
    violated = _files(("src/auth/login.py", ["x"]), ("docs/a.md", ["x"]))
    assert _status(AUTH, not_triggered).status == STATUS_PASS
    assert _status(AUTH, satisfied).status == STATUS_PASS
    r = _status(AUTH, violated)
    assert r.status == STATUS_FAIL
    assert r.locations == (("src/auth/login.py", None),)
    assert r.clause_id == "AUTH-TESTS" and r.locator == clause_locator("AUTH-TESTS")


def test_forbid_change_truth_table():
    c = {"id": "NO-MIG", "type": "forbid_change", "paths": ["db/migrations/**"]}
    assert _status(c, _files(("src/a.py", ["x"]))).status == STATUS_PASS
    r = _status(c, _files(("db/migrations/001.sql", ["x"])))
    assert r.status == STATUS_FAIL and r.locations[0][0] == "db/migrations/001.sql"


def test_forbid_added_text_truth_table_and_line_numbers():
    c = {"id": "NO-EVAL", "type": "forbid_added_text", "paths": ["**/*.py"],
         "contains": ["eval("]}
    assert _status(c, _files(("a.py", ["safe()"]))).status == STATUS_PASS
    r = _status(c, _files(("pkg/a.py", ["ok", "y = eval(x)"])))
    assert r.status == STATUS_FAIL and r.locations == (("pkg/a.py", 3),)
    # out-of-scope path never matches
    assert _status(c, _files(("a.txt", ["eval(x)"]))).status == STATUS_PASS


def test_forbid_added_text_unknown_for_uninspectable_binary():
    c = {"id": "NO-EVAL", "type": "forbid_added_text", "paths": ["assets/**"],
         "contains": ["eval("]}
    files = parse_unified_diff(
        "diff --git a/assets/x.bin b/assets/x.bin\n"
        "index 1..2 100644\nBinary files a/assets/x.bin and b/assets/x.bin differ\n")
    assert files and files[0].is_binary
    assert _status(c, files).status == STATUS_UNKNOWN


def test_max_clauses_truth_table():
    files = _files(("a.py", ["1", "2"]), ("b.py", ["1"]), ("c.py", ["1"]))
    assert _status({"id": "F", "type": "max_changed_files", "limit": 3}, files).status == STATUS_PASS
    assert _status({"id": "F", "type": "max_changed_files", "limit": 2}, files).status == STATUS_FAIL
    assert _status({"id": "L", "type": "max_added_lines", "limit": 4}, files).status == STATUS_PASS
    assert _status({"id": "L", "type": "max_added_lines", "limit": 3}, files).status == STATUS_FAIL
    scoped = {"id": "L", "type": "max_added_lines", "limit": 1, "paths": ["b.py"]}
    assert _status(scoped, files).status == STATUS_PASS


def test_guidance_clause_is_unknown_never_pass_or_fail():
    r = _status({"id": "G", "type": "mystery"}, _files(("a.py", ["x"])))
    assert r.status == STATUS_UNKNOWN


def test_evaluation_is_deterministic_and_order_independent():
    cfg = _cfg(AUTH, {"id": "F", "type": "max_changed_files", "limit": 1})
    files = _files(("src/auth/a.py", ["x"]), ("src/auth/b.py", ["x"]),
                   ("docs/z.md", ["x"]))
    first = evaluate_policy(cfg, files)
    for seed in range(5):
        shuffled = list(files)
        random.Random(seed).shuffle(shuffled)
        assert evaluate_policy(cfg, shuffled) == first
    assert [r.clause_id for r in first.results] == ["AUTH-TESTS", "F"]


def test_no_clauses_is_a_noop():
    assert evaluate_policy(PolicyConfig(), _files(("a.py", ["x"]))).results == ()


# ------------------------------------------------------------------ T03
def test_failed_clause_becomes_reported_only_finding():
    ev = evaluate_policy(_cfg(AUTH), _files(("src/auth/login.py", ["x"])))
    findings, warnings = policy_findings(ev)
    assert warnings == [] and len(findings) == 1
    f = findings[0]
    assert f.rule_id == "POL:AUTH-TESTS"
    assert f.severity == "high" and f.category == "testing"
    assert f.suggestion is None                      # never auto-remediation
    assert f.file == "src/auth/login.py"
    assert "AUTH-TESTS" in f.title and clause_locator("AUTH-TESTS") in f.explanation
    assert f.provenance_engine == "policy-v1" and f.provenance_origin == "rule"
    kinds = {e.kind: e for e in f.evidence}
    assert kinds["rule_ref"].locator == clause_locator("AUTH-TESTS")
    assert kinds["rule_ref"].integrity_ok
    assert f.to_dict()["category"] == "testing"      # survives the report boundary


def test_unknown_becomes_warning_not_finding_and_pass_is_silent():
    cfg = _cfg({"id": "G", "type": "mystery"},
               {"id": "OK", "type": "forbid_change", "paths": ["nope/**"]})
    findings, warnings = policy_findings(evaluate_policy(cfg, _files(("a.py", ["x"]))))
    assert findings == [] and len(warnings) == 1 and "G" in warnings[0]


def test_scrub_is_applied_to_pr_derived_text():
    ev = evaluate_policy(_cfg({"id": "NO-MIG", "type": "forbid_change",
                               "paths": ["db/**"]}),
                         _files(("db/TOPSECRET-token.sql", ["x"])))
    f, _ = policy_findings(ev, scrub=lambda t: t.replace("TOPSECRET", "[redacted]"))
    blob = repr([(x.file, x.title, x.explanation, x.evidence) for x in f])
    assert "TOPSECRET" not in blob and "[redacted]" in blob


def test_review_policy_end_to_end_and_no_policy_is_empty(tmp_path):
    files = _files(("src/auth/login.py", ["x"]))
    assert review_policy(str(tmp_path), ".ai-pr-reviewer.yml", files) == ([], [])
    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        "policy:\n  clauses:\n    - id: AUTH-TESTS\n      type: require_change\n"
        "      severity: high\n      when_paths: ['src/auth/**']\n"
        "      require_paths: ['tests/**']\n", encoding="utf-8")
    found, warns = review_policy(str(tmp_path), ".ai-pr-reviewer.yml", files)
    assert [f.rule_id for f in found] == ["POL:AUTH-TESTS"] and warns == []


def test_policy_package_cannot_write_spawn_or_reach_network():
    banned = {"subprocess", "socket", "httpx", "requests", "urllib", "http",
              "shutil", "ftplib", "smtplib", "asyncio"}
    for path in (ROOT / "ai_pr_reviewer" / "policy").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                mods = [(node.module or "").split(".")[0]]
            assert not banned & set(mods), (path.name, mods)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"exec", "eval", "compile"}, path.name
        # the only write-capable open() allowed is the read-only YAML load
        src = path.read_text(encoding="utf-8")
        assert "'w'" not in src and '"w"' not in src and "os.remove" not in src


# ------------------------------------------------------------------ T04
V1_YAML = (ROOT / ".ai-pr-reviewer.yml").read_text(encoding="utf-8")


def test_v1_only_config_behaves_as_before(tmp_path):
    (tmp_path / ".ai-pr-reviewer.yml").write_text(V1_YAML, encoding="utf-8")
    assert not load_policy_config(str(tmp_path)).enabled
    files = _files(("src/auth/login.py", ["x"]))
    assert review_policy(str(tmp_path), ".ai-pr-reviewer.yml", files) == ([], [])


def test_policy_section_does_not_change_v1_parsing_or_warn(tmp_path, caplog):
    (tmp_path / ".ai-pr-reviewer.yml").write_text(V1_YAML, encoding="utf-8")
    before = load_project_rules(str(tmp_path))
    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        V1_YAML + "\npolicy:\n  clauses:\n"
        "    - {id: A, type: forbid_change, paths: ['x/**']}\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        after = load_project_rules(str(tmp_path))
    assert after == before
    assert not any("unknown top-level" in r.getMessage() for r in caplog.records)


def test_baseline_present_first_whatever_policy_says(tmp_path):
    (tmp_path / ".ai-pr-reviewer.yml").write_text(
        "exclude: ['docs/**']\npolicy:\n  exclude: []\n  clauses: []\n",
        encoding="utf-8")
    pol = load_project_rules(str(tmp_path))
    assert pol.exclude[:len(SENSITIVE_EXCLUDE_GLOBS)] == list(SENSITIVE_EXCLUDE_GLOBS)
    assert ReviewPolicy().exclude == list(SENSITIVE_EXCLUDE_GLOBS)


@pytest.mark.parametrize("key", ["exclude", "baseline", "disable_baseline",
                                 "allow_paths", "include"])
def test_baseline_keys_in_policy_are_rejected(key):
    cfg = parse_policy_section({key: [".env"], "clauses": []})
    assert any("privacy baseline" in w for w in cfg.warnings)
    cfg = _cfg({"id": "A", "type": "forbid_change", "paths": ["x"],
                key: [".env"]})
    assert any("privacy baseline" in w for w in cfg.warnings)
    assert key not in cfg.clauses[0].params


def test_baseline_paths_are_never_evaluated_or_cited():
    secret_paths = [".env", "config/.env.production", "keys/server.pem",
                    "secrets/db.json", "deploy/id_rsa", "infra/prod.tfstate"]
    cfg = _cfg(
        {"id": "ANY", "type": "forbid_change", "paths": ["**"]},
        {"id": "TXT", "type": "forbid_added_text", "paths": ["**"], "contains": ["x"]},
        {"id": "CNT", "type": "max_changed_files", "limit": 0},
        {"id": "LNS", "type": "max_added_lines", "limit": 0},
        {"id": "REQ", "type": "require_change", "when_paths": ["**"],
         "require_paths": ["never/**"]},
    )
    files = _files(*[(p, ["x"]) for p in secret_paths])
    ev = evaluate_policy(cfg, files)
    assert all(r.status == STATUS_PASS for r in ev.results if r.clause_id != "REQ")
    assert ev.by_id("REQ").status == STATUS_PASS          # nothing triggers
    cited = [loc for r in ev.results for loc in r.locations]
    assert cited == []
    # the same files plus one ordinary file: only the ordinary one is ever cited
    ev = evaluate_policy(cfg, _files(*[(p, ["x"]) for p in secret_paths],
                                     ("src/app.py", ["x"])))
    assert {p for r in ev.results for p, _ in r.locations} == {"src/app.py"}


def test_extra_excludes_can_only_add():
    cfg = _cfg({"id": "ANY", "type": "forbid_change", "paths": ["**"]})
    files = _files(("docs/a.md", ["x"]), ("src/a.py", ["x"]))
    ev = evaluate_policy(cfg, files, extra_excludes=["docs/**"])
    assert [p for p, _ in ev.results[0].locations] == ["src/a.py"]
    ev = evaluate_policy(cfg, _files((".env", ["x"])), extra_excludes=[])
    assert ev.results[0].status == STATUS_PASS


def test_evaluator_enforces_baseline_independently_of_caller(monkeypatch):
    # Even if a caller hands over raw, unfiltered files, the evaluator drops
    # baseline paths itself (double enforcement).
    monkeypatch.setattr(evaluate_mod, "SENSITIVE_EXCLUDE_GLOBS", (".env",))
    cfg = _cfg({"id": "ANY", "type": "forbid_change", "paths": ["**"]})
    assert evaluate_policy(cfg, _files((".env", ["x"]))).results[0].status == STATUS_PASS
    assert evaluate_policy(cfg, _files(("keys/a.pem", ["x"]))).results[0].status == STATUS_FAIL


# -------------------------------------------- merge pass: real orchestrator
# Requested by Helper 6's merge note: a fixture repo with a failing clause
# yields a finding with rule_id "POL:<id>" in ReviewResult.findings, and a
# v1 config yields byte-identical results (the hook spliced into
# ReviewOrchestrator.run() after the architecture hook, before dedup).

def _write_tree(root: Path, files: dict) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def _fake_checkout(root: Path, origin="https://github.com/acme/api.git"):
    (root / ".git").mkdir(exist_ok=True)
    (root / ".git" / "config").write_text(
        '[core]\n\tbare = false\n[remote "origin"]\n'
        f"\turl = {origin}\n", encoding="utf-8")


def _orch_diff(path: str, added: list[str]) -> str:
    body = "".join(f"+{line}\n" for line in added)
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,1 +1,{1 + len(added)} @@\n context\n{body}")


POLICY_YAML = (
    "policy:\n  clauses:\n    - id: AUTH-TESTS\n      type: require_change\n"
    "      severity: high\n      when_paths: ['src/auth/**']\n"
    "      require_paths: ['tests/**']\n"
)


def _review(tmp_path: Path, rules: str | None, diff: str):
    root = tmp_path / "checkout"
    root.mkdir(parents=True, exist_ok=True)
    _write_tree(root, {"src/auth/login.py": "x = 1\n"})
    _fake_checkout(root)
    if rules is not None:
        (root / ".ai-pr-reviewer.yml").write_text(rules, encoding="utf-8")
    cfg = Config(repo="acme/api", pr_number=42, mock=True, no_comment=True,
                 severity_threshold="low")
    cfg.repo_root = str(root)
    pr = PRContext(repo="acme/api", pr_number=42, head_sha="a" * 40)
    return ReviewOrchestrator(cfg, None, None, pr=pr, diff_text=diff).run()


def _snapshot(result):
    return ([f.to_dict() for f in result.findings], list(result.warnings))


def test_orchestrator_reports_a_failing_clause_as_a_pol_finding(tmp_path):
    diff = _orch_diff("src/auth/login.py", ["def new_login(): pass"])
    result = _review(tmp_path, POLICY_YAML, diff)
    pol = [f for f in result.findings if f.rule_id == "POL:AUTH-TESTS"]
    assert len(pol) == 1
    assert pol[0].provenance_origin == "rule"


def test_orchestrator_output_is_byte_identical_for_v1_only_config(tmp_path):
    diff = _orch_diff("src/auth/login.py", ["def new_login(): pass"])
    reference = _snapshot(_review(tmp_path / "a", None, diff))
    v1_only = _review(tmp_path / "b", "review:\n  mode: balanced\n", diff)
    assert _snapshot(v1_only) == reference
    assert not any(f["rule_id"] == "POL:AUTH-TESTS" for f in reference[0])
