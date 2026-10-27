"""V4.2-E04 · architecture intelligence (T01 schema, T02 checker, T03 drift,
T04 violation findings) plus pipeline integration.

Every fixture is synthetic and offline; nothing here touches the network,
a real diff, or real repository data.

Coverage map:

* **T01** opt-in/default-off, additive key, bounds, fail-closed-to-no-op,
  v1-config compatibility;
* **T02** layer judging, determinism under edge permutation, honest
  unlayered/excluded accounting, partial labelling proven by cap
  exhaustion, no-network/no-exec import scan;
* **T03** snapshot contract (round-trip, tamper/foreign rejection),
  drift semantics (not comparable across model changes, no "resolved"
  claims from a partial analysis);
* **T04** finding shape, evidence-or-dropped, provenance, redaction at the
  boundary, no remediation/certification wording;
* **integration** absent/disabled ⇒ byte-identical orchestrator output; an
  enabled section yields anchored findings through the real orchestrator.
"""
from __future__ import annotations

import ast
import json
import logging
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.architecture import (  # noqa: E402
    ArchitectureSnapshot, Edge, build_snapshot, check_layers, compute_drift,
    parse_architecture_section, project_layer_edges, run_architecture_check,
    snapshot_from_dict, snapshot_to_dict, violation_findings)
from ai_pr_reviewer.architecture.checker import (  # noqa: E402
    ORIGIN_BASE, ORIGIN_DIFF, Violation)
from ai_pr_reviewer.architecture.runner import NOOP  # noqa: E402
from ai_pr_reviewer.config import Config  # noqa: E402
from ai_pr_reviewer.diff_parser import parse_unified_diff  # noqa: E402
from ai_pr_reviewer.index import FileEntry, RepoIndex  # noqa: E402
from ai_pr_reviewer.models import (VALID_CATEGORIES, Finding,  # noqa: E402
                                   PRContext)
from ai_pr_reviewer.orchestrator import ReviewOrchestrator  # noqa: E402
from ai_pr_reviewer.rules import load_project_rules  # noqa: E402

# ----------------------------------------------------------------- fixtures

RAW = {
    "enabled": True,
    "layers": [
        {"name": "api", "paths": ["src/api/**"]},
        {"name": "domain", "paths": ["src/domain/**"]},
        {"name": "db", "paths": ["src/db/**"]},
    ],
    "allow": {"api": ["domain"], "domain": ["db"]},
}

YML = """\
review:
  mode: balanced
architecture:
  enabled: true
  layers:
    - name: api
      paths: ["src/api/**"]
    - name: domain
      paths: ["src/domain/**"]
    - name: db
      paths: ["src/db/**"]
  allow:
    api: [domain]
    domain: [db]
"""


def model(**overrides):
    raw = {**RAW, **overrides}
    parsed = parse_architecture_section(raw)
    assert parsed.model is not None, parsed.warnings
    return parsed.model


def make_index(paths, edges, budget="ok"):
    return RepoIndex(
        root=".",
        files=tuple(FileEntry(path=p, size=1, language="python", changed=False)
                    for p in sorted(paths)),
        edges=tuple(sorted(edges)), budget_state=budget, warnings=())


def diff_for(path: str, added: list[str]) -> str:
    body = "".join(f"+{line}\n" for line in added)
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,1 +1,{1 + len(added)} @@\n import os\n{body}")


def write_tree(root: Path, files: dict) -> None:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")


def fake_checkout(root: Path, origin="https://github.com/acme/api.git"):
    (root / ".git").mkdir(exist_ok=True)
    (root / ".git" / "config").write_text(
        '[core]\n\tbare = false\n[remote "origin"]\n'
        f"\turl = {origin}\n", encoding="utf-8")


# ================================================================ T01 schema

def test_absent_or_disabled_section_is_a_silent_noop():
    for raw in (None, {}, {"enabled": False, "layers": RAW["layers"]},
                {"layers": RAW["layers"]}, {"enabled": "true"},
                {"enabled": 1, "layers": RAW["layers"]}):
        parsed = parse_architecture_section(raw)
        assert parsed.model is None and parsed.warnings == ()


def test_valid_section_parses_with_documented_defaults():
    m = model()
    assert [l.name for l in m.layers] == ["api", "domain", "db"]
    assert m.severity == "medium" and m.max_findings == 20
    assert m.allowed_targets("api") == ("domain",)
    assert m.allows("api", "api")            # same layer: always allowed
    assert m.allows("api", "domain")
    assert not m.allows("api", "db")         # not listed ⇒ denied
    assert not m.allows("db", "api")         # layer with no entry ⇒ denied
    assert m.layer_of("src/api/x/y.py") == "api"
    assert m.layer_of("README.md") is None


def test_overlapping_globs_resolve_by_declaration_order():
    m = model(layers=[{"name": "first", "paths": ["src/**"]},
                      {"name": "second", "paths": ["src/api/**"]}], allow={})
    assert m.layer_of("src/api/x.py") == "first"


def test_severity_can_never_be_critical_and_bounds_are_enforced():
    p = parse_architecture_section({**RAW, "severity": "critical"})
    assert p.model.severity == "medium"
    assert any("severity" in w for w in p.warnings)
    assert parse_architecture_section(
        {**RAW, "severity": "HIGH"}).model.severity == "high"
    for bad in (True, 0, -3, "5", 2.5):
        assert parse_architecture_section(
            {**RAW, "max_findings": bad}).model.max_findings == 20
    assert parse_architecture_section(
        {**RAW, "max_findings": 10_000}).model.max_findings == 100


def test_structural_problems_fail_closed_to_noop_with_a_warning():
    cases = [
        "not a mapping",
        {"enabled": True, "layers": "nope"},
        {"enabled": True, "layers": [{"name": "only", "paths": ["a/**"]}]},
        {"enabled": True, "layers": [{"name": "a b", "paths": ["a/**"]},
                                     {"name": "c", "paths": ["c/**"]}]},
        {"enabled": True, "layers": [{"name": "a"}, {"name": "b"}]},
    ]
    for raw in cases:
        p = parse_architecture_section(raw)
        assert p.model is None, raw
        assert p.warnings, raw


def test_bad_entries_are_skipped_but_good_ones_survive():
    p = parse_architecture_section({
        "enabled": True,
        "layers": [
            {"name": "a", "paths": ["a/**"]},
            {"name": "a", "paths": ["dup/**"]},               # duplicate
            {"name": "b", "paths": ["../escape/**", "/abs/**", "b/**"]},
            {"name": "c", "paths": ["c/**"]},
            "junk",
        ],
        "allow": {"a": ["b", "ghost"], "ghost": ["a"], "b": "not-a-list"},
        "mystery": 1,
    })
    m = p.model
    assert [l.name for l in m.layers] == ["a", "b", "c"]
    assert m.layers[0].paths == ("a/**",)                    # first 'a' wins
    assert m.layers[1].paths == ("b/**",)                    # unsafe dropped
    assert m.allowed_targets("a") == ("b",)
    assert m.allowed_targets("b") == ()
    joined = " ".join(p.warnings)
    for needle in ("duplicate", "unknown layer 'ghost'", "unknown key"):
        assert needle in joined


def test_layer_and_pattern_counts_are_capped():
    layers = [{"name": f"l{i}", "paths": ["x/**"]} for i in range(60)]
    assert len(parse_architecture_section(
        {"enabled": True, "layers": layers}).model.layers) == 32
    many = [f"p{i}/**" for i in range(50)]
    m = parse_architecture_section({"enabled": True, "layers": [
        {"name": "a", "paths": many}, {"name": "b", "paths": ["b/**"]}]}).model
    assert len(m.layers[0].paths) == 20


def test_junk_values_never_raise():
    junk = [None, 0, 1.5, "x", [], [1, 2], {}, {"enabled": True},
            {"enabled": True, "layers": [None, 1, [], {}]},
            {"enabled": True, "layers": [{"name": 5, "paths": 7}] * 3},
            {"enabled": True, "layers": RAW["layers"], "allow": 5},
            {"enabled": True, "layers": RAW["layers"], "allow": {1: 2}},
            {"enabled": True, "layers": [{"name": "a", "paths": [None, 3]},
                                         {"name": "b", "paths": ["b/**"]}]}]
    for raw in junk:
        parse_architecture_section(raw)       # must not raise


def test_digest_tracks_semantics_not_incidentals():
    base = model().digest()
    assert model().digest() == base
    assert model(severity="high").digest() == base       # severity ≠ rules
    assert model(allow={"api": ["domain", "db"]}).digest() != base


def test_v1_config_behaves_identically_and_new_key_is_not_unknown(tmp_path):
    plain = tmp_path / "plain"
    with_arch = tmp_path / "arch"
    plain.mkdir(); with_arch.mkdir()
    v1 = "review:\n  mode: balanced\nrules:\n  - keep secrets out\n"
    (plain / ".ai-pr-reviewer.yml").write_text(v1, encoding="utf-8")
    (with_arch / ".ai-pr-reviewer.yml").write_text(
        v1 + YML[YML.index("architecture:"):], encoding="utf-8")

    records: list[str] = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = Capture()
    logger = logging.getLogger("ai_pr_reviewer.rules")
    logger.addHandler(handler)
    try:
        a = load_project_rules(str(plain))
        b = load_project_rules(str(with_arch))
    finally:
        logger.removeHandler(handler)
    assert a == b
    assert not any("unknown top-level" in r for r in records)


# ============================================================== T02 checker

PATHS = ["src/api/h.py", "src/domain/r.py", "src/db/c.py", "README.md"]


def test_checker_flags_only_disallowed_directions():
    m = model()
    edges = [Edge("src/api/h.py", "src/domain/r.py"),      # allowed
             Edge("src/domain/r.py", "src/db/c.py"),       # allowed
             Edge("src/api/h.py", "src/db/c.py"),          # api -> db: no
             Edge("src/db/c.py", "src/api/h.py"),          # db -> api: no
             Edge("src/api/h.py", "README.md")]            # unlayered
    r = check_layers(m, edges)
    assert [(v.importer, v.imported, v.importer_layer, v.imported_layer)
            for v in r.violations] == [
        ("src/api/h.py", "src/db/c.py", "api", "db"),
        ("src/db/c.py", "src/api/h.py", "db", "api")]
    assert (r.edges_considered, r.edges_unlayered, r.edges_excluded) == (5, 1, 0)
    assert not r.partial and not r.truncated


def test_checker_is_order_independent():
    m = model()
    edges = [Edge(f"src/api/f{i}.py", f"src/db/g{i % 3}.py",
                  line=i, spec=f"s{i}",
                  origin=ORIGIN_DIFF if i % 2 else ORIGIN_BASE)
             for i in range(25)]
    expected = check_layers(m, edges)
    rng = random.Random(1234)
    for _ in range(10):
        shuffled = edges[:]
        rng.shuffle(shuffled)
        assert check_layers(m, shuffled) == expected


def test_duplicate_edges_collapse_and_the_line_anchored_one_wins():
    m = model()
    r = check_layers(m, [
        Edge("src/api/h.py", "src/db/c.py", origin=ORIGIN_BASE),
        Edge("src/api/h.py", "src/db/c.py", line=7, spec="src.db.c",
             origin=ORIGIN_DIFF)])
    assert len(r.violations) == 1
    v = r.violations[0]
    assert (v.line, v.spec, v.origin) == (7, "src.db.c", ORIGIN_DIFF)


def test_privacy_baseline_paths_are_excluded_and_never_reported():
    m = model(layers=[{"name": "api", "paths": ["src/api/**"]},
                      {"name": "keys", "paths": ["**/*.pem", "secrets/**",
                                                 "src/db/**"]}], allow={})
    r = check_layers(m, [Edge("src/api/h.py", "certs/server.pem"),
                         Edge("src/api/h.py", "secrets/token.py"),
                         Edge("secrets/a.py", "src/api/h.py"),
                         Edge("src/api/h.py", "src/db/c.py")])
    assert r.edges_excluded == 3
    assert [v.imported for v in r.violations] == ["src/db/c.py"]
    assert project_layer_edges(m, [Edge("src/api/h.py", "certs/server.pem")]) == {}


def test_cap_exhaustion_is_labelled_partial_not_silently_short():
    m = model(max_findings=3)
    edges = [Edge(f"src/api/f{i}.py", "src/db/c.py") for i in range(8)]
    r = check_layers(m, edges)
    assert len(r.violations) == 3 and r.total_violations == 8
    assert r.truncated and r.partial
    assert "3 of 8" in r.partial_reasons[0]


def test_truncated_index_marks_the_result_partial():
    r = check_layers(model(), [Edge("src/api/h.py", "src/db/c.py")],
                     index_complete=False)
    assert r.partial and "index was truncated" in r.partial_reasons[0]
    assert len(r.violations) == 1                 # still reported, labelled


def test_package_has_no_network_or_process_execution_imports():
    forbidden = {"subprocess", "socket", "http", "urllib", "requests", "httpx",
                 "ftplib", "smtplib", "asyncio", "multiprocessing", "ctypes"}
    for path in (ROOT / "ai_pr_reviewer" / "architecture").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [(node.module or "").split(".")[0]]
            assert not (set(names) & forbidden), (path.name, names)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in {"eval", "exec", "compile"}, path.name


# ================================================================ T03 drift

BASE_EDGES = [Edge("src/api/h.py", "src/domain/r.py"),
              Edge("src/domain/r.py", "src/db/c.py")]


def test_snapshot_is_deterministic_and_round_trips():
    m = model()
    a = build_snapshot(m, BASE_EDGES)
    b = build_snapshot(m, list(reversed(BASE_EDGES)))
    assert a == b and a.digest == b.digest
    assert a.layer_edges == (("api", "domain", 1), ("domain", "db", 1))
    assert a.violations == () and a.complete
    payload = json.loads(json.dumps(snapshot_to_dict(a)))   # JSON-safe
    assert snapshot_from_dict(payload) == a


def test_foreign_tampered_or_oversized_snapshots_are_treated_as_absent():
    good = snapshot_to_dict(build_snapshot(model(), BASE_EDGES))
    tampered = json.loads(json.dumps(good))
    tampered["layer_edges"].append(["api", "db", 1])
    wrong_version = {**good, "version": 99}
    bad_types = {**good, "complete": "yes"}
    too_big = {**good, "violations": [["a", "b"]] * 501}
    long_path = {**good, "violations": [["a" * 400, "b"]]}
    for payload in (tampered, wrong_version, bad_types, too_big, long_path,
                    None, [], "x", {}, {"version": 1}):
        assert snapshot_from_dict(payload) is None


def test_drift_reports_new_violations_and_resolutions():
    m = model()
    before = build_snapshot(m, [*BASE_EDGES,
                                Edge("src/api/old.py", "src/db/c.py")])
    after = build_snapshot(m, [*BASE_EDGES,
                               Edge("src/api/new.py", "src/db/c.py")])
    d = compute_drift(after, before)
    assert d.comparable
    assert d.new_violations == (("src/api/new.py", "src/db/c.py"),)
    assert d.resolved_violations == (("src/api/old.py", "src/db/c.py"),)
    assert d.new_layer_edges == () and d.removed_layer_edges == ()


def test_new_layer_direction_is_detected_and_removed_one_too():
    m = model(allow={"api": ["domain", "db"], "domain": ["db"]})
    before = build_snapshot(m, BASE_EDGES)
    after = build_snapshot(m, [Edge("src/api/h.py", "src/db/c.py"),
                               Edge("src/domain/r.py", "src/db/c.py")])
    d = compute_drift(after, before)
    assert d.new_layer_edges == (("api", "db"),)
    assert d.removed_layer_edges == (("api", "domain"),)


def test_drift_is_not_comparable_without_a_baseline_or_across_model_changes():
    cur = build_snapshot(model(), BASE_EDGES)
    none = compute_drift(cur, None)
    assert not none.comparable and none.new_violations == ()
    other = build_snapshot(model(allow={"api": ["domain", "db"]}), BASE_EDGES)
    changed = compute_drift(cur, other)
    assert not changed.comparable and "changed" in changed.reason


def test_partial_current_snapshot_never_claims_resolutions():
    m = model()
    before = build_snapshot(m, [Edge("src/api/old.py", "src/db/c.py")])
    partial = ArchitectureSnapshot(model_digest=m.digest(), complete=False)
    d = compute_drift(partial, before)
    assert d.comparable
    assert d.resolved_violations == () and d.removed_layer_edges == ()
    assert "partial" in d.reason


def test_snapshot_marks_itself_incomplete_when_the_index_was_truncated():
    assert not build_snapshot(model(), BASE_EDGES, complete=False).complete


# ============================================================ T04 findings

def violation(**kw):
    base = dict(importer="src/api/h.py", imported="src/db/c.py",
                importer_layer="api", imported_layer="db", line=2,
                spec="src.db.c", origin=ORIGIN_DIFF)
    base.update(kw)
    return Violation(**base)


def result_for(*vs, partial=False):
    from ai_pr_reviewer.architecture.checker import CheckResult
    return CheckResult(violations=tuple(vs), total_violations=len(vs),
                       partial=partial,
                       partial_reasons=("index was truncated",) if partial else ())


def test_finding_shape_evidence_provenance_and_no_remediation():
    m = model(severity="high")
    [f] = violation_findings(result_for(violation()), m)
    assert isinstance(f, Finding)
    assert (f.file, f.line, f.severity, f.rule_id) == (
        "src/api/h.py", 2, "high", "ARCH001")
    assert f.category in VALID_CATEGORIES
    assert f.suggestion is None                    # never prescribes a fix
    assert f.confidence == "high"
    assert (f.provenance_engine, f.provenance_model, f.provenance_origin,
            f.provenance_agent) == ("static", "architecture-v1", "rule", None)
    assert [s.engine for s in f.provenance_sources] == ["static"]
    kinds = [(e.kind, e.check_type) for e in f.evidence]
    assert kinds == [("file_excerpt", "architecture_edge"),
                     ("rule_ref", "architecture_rule")]
    edge, rule = f.evidence
    assert edge.locator == "src/api/h.py:2"        # resolvable path:line
    assert "src/api/h.py" in edge.summary and "src/db/c.py" in edge.summary
    assert rule.locator == ".ai-pr-reviewer.yml#architecture.allow.api"
    assert all(e.integrity_ok for e in f.evidence)
    d = f.to_dict()
    assert d["rule_id"] == "ARCH001" and len(d["evidence"]) == 2
    assert "introduced by this change" in f.explanation


def test_base_origin_edges_are_file_level_and_medium_confidence():
    [f] = violation_findings(
        result_for(violation(line=None, spec=None, origin=ORIGIN_BASE)),
        model())
    assert f.line is None and f.confidence == "medium"
    assert f.evidence[0].locator == "src/api/h.py"
    assert "present in the base revision" in f.explanation


def test_partial_analysis_is_stated_and_lowers_confidence():
    [f] = violation_findings(result_for(violation(), partial=True), model())
    assert f.confidence == "medium"
    assert "partial" in f.explanation


def test_two_violations_in_one_file_stay_two_distinct_findings():
    from ai_pr_reviewer.findings import fingerprint_finding
    fs = violation_findings(result_for(
        violation(imported="src/db/a.py"),
        violation(imported="src/db/b.py", line=3)), model())
    assert len({fingerprint_finding(f) for f in fs}) == 2


def test_new_since_snapshot_is_noted_on_the_finding():
    [f] = violation_findings(
        result_for(violation()), model(),
        new_since_snapshot=frozenset({("src/api/h.py", "src/db/c.py")}))
    assert "not in the previous snapshot" in f.explanation


def test_text_never_makes_certification_claims_or_fix_prescriptions():
    [f] = violation_findings(result_for(violation()), model())
    text = " ".join([f.title, f.explanation,
                     *(e.summary for e in f.evidence)]).lower()
    for banned in ("complies", "compliant", "conforms", "certif", "approved",
                   "safe to merge", "you should", "refactor", "fix by"):
        assert banned not in text, banned


def test_paths_are_redacted_single_line_and_scrubbed_at_the_boundary():
    key = "AKIAIOSFODNN7EXAMPLE"                       # synthetic, redacted
    nasty = f"src/api/{key}\nINJECT: **bold**.py"
    secret = "hunter2-run-credential"
    v = violation(importer=nasty, imported=f"src/db/{secret}.py")
    [f] = violation_findings(result_for(v), model(),
                             scrub=lambda t: t.replace(secret, "[SCRUBBED]"))
    # ``Finding.file`` must stay equal to the diff path so the finding can
    # anchor (every engine's findings do the same; the report-boundary
    # redaction chokepoint owns that field). Everything *authored here* is
    # clean: title, explanation, evidence and the rest of the record.
    authored = {k: v for k, v in f.to_dict().items() if k != "file"}
    blob = json.dumps(authored)
    assert key not in blob and secret not in blob
    for field in (f.title, f.explanation, *(e.summary for e in f.evidence),
                  *(e.locator for e in f.evidence)):
        assert "\n" not in field and "\r" not in field


def test_a_finding_without_buildable_evidence_is_dropped_not_emitted_bare():
    assert violation_findings(
        result_for(violation(importer="", line=None)), model()) == []


# ======================================================= runner / integration

def write_rules(root: Path, text: str = YML) -> None:
    (root / ".ai-pr-reviewer.yml").write_text(text, encoding="utf-8")


def runner(root: Path, index, diff_text: str | None, **kw):
    files = parse_unified_diff(diff_text) if diff_text else []
    return run_architecture_check(repo_root=str(root),
                                  rules_file=".ai-pr-reviewer.yml",
                                  index=index, files=files, **kw)


INDEX_PATHS = ["src/api/h.py", "src/api/other.py", "src/domain/r.py",
               "src/db/c.py"]


def test_absent_disabled_or_unreadable_rules_are_the_noop_singleton(tmp_path):
    idx = make_index(INDEX_PATHS, [("src/api/h.py", "src/db/c.py")])
    d = diff_for("src/api/h.py", ["import src.db.c"])
    assert runner(tmp_path, idx, d) is NOOP                 # no rules file
    write_rules(tmp_path, YML.replace("enabled: true", "enabled: false"))
    assert runner(tmp_path, idx, d) is NOOP                 # off
    write_rules(tmp_path, "architecture: [unclosed\n")
    assert runner(tmp_path, idx, d) is NOOP                 # broken YAML
    write_rules(tmp_path, "review:\n  mode: economy\n")
    assert runner(tmp_path, idx, d) is NOOP                 # v1 config


def test_enabled_without_an_index_warns_and_returns_no_findings(tmp_path):
    write_rules(tmp_path)
    out = runner(tmp_path, None, diff_for("src/api/h.py", ["import os"]))
    assert out.findings == () and "index unavailable" in out.warnings[0]


def test_malformed_enabled_section_is_a_warning_never_a_crash(tmp_path):
    write_rules(tmp_path, "architecture:\n  enabled: true\n  layers: 7\n")
    out = runner(tmp_path, make_index(INDEX_PATHS, []),
                 diff_for("src/api/h.py", ["import os"]))
    assert out.findings == () and out.warnings


def test_added_import_is_anchored_to_its_line(tmp_path):
    write_rules(tmp_path)
    idx = make_index(INDEX_PATHS, [])         # base graph knows nothing of it
    out = runner(tmp_path, idx,
                 diff_for("src/api/h.py", ["import src.db.c"]))
    [f] = out.findings
    assert (f.file, f.line, f.rule_id) == ("src/api/h.py", 2, "ARCH001")
    assert f.confidence == "high"
    assert f.evidence[0].locator == "src/api/h.py:2"


def test_base_graph_edge_in_a_changed_file_is_reported_file_level(tmp_path):
    write_rules(tmp_path)
    idx = make_index(INDEX_PATHS, [("src/api/h.py", "src/db/c.py"),
                                   ("src/api/other.py", "src/db/c.py")])
    out = runner(tmp_path, idx, diff_for("src/api/h.py", ["x = 1"]))
    [f] = out.findings                  # other.py is untouched ⇒ not re-reported
    assert f.file == "src/api/h.py" and f.line is None
    assert f.confidence == "medium"


def test_allowed_and_unresolvable_imports_produce_nothing(tmp_path):
    write_rules(tmp_path)
    idx = make_index(INDEX_PATHS, [])
    out = runner(tmp_path, idx, diff_for(
        "src/api/h.py", ["import src.domain.r", "import requests",
                         "from json import loads"]))
    assert out.findings == ()


def test_truncated_index_yields_findings_plus_a_partial_warning(tmp_path):
    write_rules(tmp_path)
    idx = make_index(INDEX_PATHS, [], budget="truncated")
    out = runner(tmp_path, idx, diff_for("src/api/h.py", ["import src.db.c"]))
    assert len(out.findings) == 1
    assert any("partial" in w for w in out.warnings)


def test_previous_snapshot_is_optional_and_drives_the_drift_note(tmp_path):
    write_rules(tmp_path)
    clean = build_snapshot(model(), [Edge("src/api/h.py", "src/domain/r.py")])
    idx = make_index(INDEX_PATHS, [("src/api/h.py", "src/db/c.py")])
    d = diff_for("src/api/h.py", ["x = 1"])
    none = runner(tmp_path, idx, d)
    assert none.snapshot is None                      # inert without baseline
    out = runner(tmp_path, idx, d, previous_snapshot=snapshot_to_dict(clean))
    assert "not in the previous snapshot" in out.findings[0].explanation
    assert out.snapshot is not None
    bad = runner(tmp_path, idx, d, previous_snapshot={"junk": 1})
    assert any("drift not computed" in w for w in bad.warnings)
    assert "not in the previous snapshot" not in bad.findings[0].explanation


def test_runner_never_raises_on_hostile_inputs(tmp_path):
    write_rules(tmp_path)

    class Boom:
        budget_state = "ok"
        paths = ()

        @property
        def edges(self):
            raise RuntimeError("boom")

    out = runner(tmp_path, Boom(), diff_for("src/api/h.py", ["import os"]))
    assert out.findings == () and "failed" in out.warnings[0]


# ------------------------------------------------- real orchestrator pipeline

def _review(tmp_path: Path, rules: str | None, diff: str):
    root = tmp_path / "checkout"
    root.mkdir(parents=True, exist_ok=True)
    write_tree(root, {
        "src/api/h.py": "import os\n",
        "src/domain/r.py": "x = 1\n",
        "src/db/c.py": "y = 2\n",
    })
    fake_checkout(root)
    if rules is not None:
        write_rules(root, rules)
    cfg = Config(repo="acme/api", pr_number=42, mock=True, no_comment=True,
                 severity_threshold="low")
    cfg.repo_root = str(root)
    pr = PRContext(repo="acme/api", pr_number=42, head_sha="a" * 40)
    return ReviewOrchestrator(cfg, None, None, pr=pr, diff_text=diff).run()


def _snapshot(result):
    return ([f.to_dict() for f in result.findings], list(result.warnings))


def test_orchestrator_output_is_byte_identical_when_feature_is_off(tmp_path):
    diff = diff_for("src/api/h.py", ["import src.db.c"])
    v1 = "review:\n  mode: balanced\n"
    off = YML.replace("enabled: true", "enabled: false")
    reference = _snapshot(_review(tmp_path / "a", v1, diff))
    for i, rules in enumerate((None, off)):
        assert _snapshot(_review(tmp_path / f"b{i}", rules, diff)) == reference
    assert not any(f["rule_id"] == "ARCH001" for f in reference[0])


def test_orchestrator_reports_an_added_violating_import_when_enabled(tmp_path):
    diff = diff_for("src/api/h.py", ["import src.db.c"])
    result = _review(tmp_path, YML, diff)
    arch = [f for f in result.findings if f.rule_id == "ARCH001"]
    assert len(arch) == 1
    f = arch[0]
    assert (f.file, f.line) == ("src/api/h.py", 2)
    assert f.fingerprint                      # lifecycle ran over it
    assert f.provenance_origin == "rule"
    assert [e.kind for e in f.evidence] == ["file_excerpt", "rule_ref"]


def test_orchestrator_is_quiet_for_an_allowed_import(tmp_path):
    result = _review(tmp_path, YML,
                     diff_for("src/api/h.py", ["import src.domain.r"]))
    assert not [f for f in result.findings if f.rule_id == "ARCH001"]
