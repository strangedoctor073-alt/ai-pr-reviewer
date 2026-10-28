"""V4.6-E05-T01 — infra parsers: parse-never-execute, bounded, never-raise.

Fixtures are deterministic synthetic files. The hostile cases pin the
degradation contract: every cap trip or malformed input returns a labeled
``ok=False`` result, never an exception and never echoed file content.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

from ai_pr_reviewer.infra_intel import (MAX_DOCKERFILE_LINES, MAX_FILE_CHARS,
                                        MAX_YAML_DEPTH, MAX_YAML_NODES,
                                        BuildVar, DockerfileDoc, FromInstruction,
                                        PermissionGrant, UseRef, WorkflowDoc,
                                        parse_dockerfile, parse_workflow)

MODULE_PATH = (Path(__file__).resolve().parents[1]
               / "ai_pr_reviewer" / "infra_intel.py")

WORKFLOW = """name: ci
on:
  push:
    branches: [main]
  pull_request_target:
permissions:
  write-all
jobs:
  build:
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - name: run
        run: make
  call:
    uses: org/repo/.github/workflows/reusable.yml@main
"""

DOCKERFILE = """# syntax=docker/dockerfile:1
FROM python:3.12-slim AS builder
ARG NODE_ENV
ENV APP_TOKEN=abc123 APP_PORT=8080
ENV LEGACY_VAR some_value
RUN echo one \\
 && echo two
FROM builder
FROM scratch
FROM alpine
FROM --platform=linux/amd64 registry.example.com:5000/app:1.2
"""


def _line_of(text: str, needle: str) -> int:
    """1-based line of the first occurrence of ``needle``."""
    return text[:text.index(needle)].count("\n") + 1


# ------------------------------------------------------------- workflows

def test_workflow_extracts_facts_with_anchored_lines():
    doc = parse_workflow(WORKFLOW, path=".github/workflows/ci.yml")
    assert doc.ok and doc.error is None
    assert doc.path == ".github/workflows/ci.yml"
    assert doc.triggers == (
        ("push", _line_of(WORKFLOW, "push:")),
        ("pull_request_target", _line_of(WORKFLOW, "pull_request_target:")),
    )
    assert doc.permissions == (
        PermissionGrant(job="", scalar="write-all",
                        line=_line_of(WORKFLOW, "write-all")),
        PermissionGrant(job="build", scopes=(("contents", "write"),),
                        line=_line_of(WORKFLOW, "contents: write")),
    )
    assert doc.uses == (
        UseRef(job="build", value="actions/checkout@v4",
               line=_line_of(WORKFLOW, "uses: actions/checkout")),
        UseRef(job="call",
               value="org/repo/.github/workflows/reusable.yml@main",
               line=_line_of(WORKFLOW, "uses: org/repo")),
    )


def test_on_key_is_read_as_written_not_as_a_yaml_11_bool():
    # A safe_load-based reader resolves the unquoted key ``on`` to True
    # and loses it; the compose-only reader keeps the written text.
    doc = parse_workflow("on: push")
    assert doc.ok and doc.triggers == (("push", 1),)

    doc = parse_workflow("on: [push, schedule]")
    assert doc.ok and {t for t, _ in doc.triggers} == {"push", "schedule"}


def test_malformed_yaml_degrades_to_a_label_and_never_echoes_content():
    doc = parse_workflow("jobs:\n  password: hunter2\n  steps: [unclosed")
    assert doc.ok is False
    assert doc.error and doc.error.startswith("yaml parse failed")
    assert "hunter2" not in doc.error
    assert doc.triggers == () and doc.permissions == () and doc.uses == ()


@pytest.mark.parametrize("text", [
    "root: &a\n  self: *a",       # mapping containing itself
    "a: &x [*x]",                  # sequence containing itself
    "&a [*a]",                     # cyclic root
])
def test_alias_cycles_degrade_instead_of_recursing(text):
    doc = parse_workflow(text)
    assert doc.ok is False and "cyclic alias" in (doc.error or "")


def test_depth_and_node_bombs_hit_their_caps():
    depth = MAX_YAML_DEPTH + 70        # composes fine, exceeds our cap
    doc = parse_workflow("a: " + "[" * depth + "]" * depth)
    assert doc.ok is False and "depth cap" in (doc.error or "")

    doc = parse_workflow(
        "x: [" + ",".join(["1"] * (MAX_YAML_NODES + 100)) + "]")
    assert doc.ok is False and "node cap" in (doc.error or "")


def test_pathological_nesting_at_the_parser_limit_degrades():
    # Beyond Python's recursion limit PyYAML itself raises RecursionError;
    # the broad except turns it into a type-only label.
    doc = parse_workflow("a: " + "[" * 3_000 + "]" * 3_000)
    assert doc.ok is False
    assert doc.error == "workflow parse failed (RecursionError)"


def test_size_cap_is_checked_before_parsing():
    doc = parse_workflow("x" * (MAX_FILE_CHARS + 1))
    assert doc.ok is False and doc.error == "workflow exceeds size cap"

    doc = parse_dockerfile("y" * (MAX_FILE_CHARS + 1))
    assert doc.ok is False and doc.error == "dockerfile exceeds size cap"


def test_non_mapping_and_empty_documents_degrade_predictably():
    empty = parse_workflow("")
    assert empty.ok is True and empty.triggers == ()

    doc = parse_workflow("just a string")
    assert doc.ok is False and doc.error == "workflow root is not a mapping"


def test_shared_anchor_fact_is_reported_once():
    doc = parse_workflow(
        "on: push\npermissions: &p\n  contents: read\npermissions: *p\n")
    assert doc.ok
    assert doc.triggers == (("push", 1),)
    assert len(doc.permissions) == 1    # one fact, reached via a reused anchor


@pytest.mark.parametrize("text", [
    "a: [1, 2",              # truncated block sequence
    "a:\n\tb: 1",            # tab indentation
    "\x00\x01 unexpected",   # control characters
    "a: 'unterminated",      # unterminated quote
    "%YAML 1.4\n---\na: 1",  # unsupported directive
    "a: \x1b[31mred\x1b[0m",  # escape sequences in plain scalars
])
def test_hostile_workflow_fragments_never_raise(text):
    doc = parse_workflow(text)
    assert isinstance(doc, WorkflowDoc)
    assert doc.ok or doc.error          # labeled either way, never a raise


# ------------------------------------------------------------ dockerfiles

def test_dockerfile_extracts_from_instructions_and_build_vars():
    doc = parse_dockerfile(DOCKERFILE, path="Dockerfile")
    assert doc.ok and doc.error is None and doc.path == "Dockerfile"
    assert doc.froms == (
        FromInstruction(image="python:3.12-slim", stage="builder", line=2),
        FromInstruction(image="builder", line=8),
        FromInstruction(image="scratch", line=9),
        FromInstruction(image="alpine", line=10),
        FromInstruction(image="registry.example.com:5000/app:1.2", line=11),
    )
    assert doc.build_vars == (
        BuildVar(kind="ARG", key="NODE_ENV", has_value=False, line=3),
        BuildVar(kind="ENV", key="APP_TOKEN", has_value=True, line=4),
        BuildVar(kind="ENV", key="APP_PORT", has_value=True, line=4),
        BuildVar(kind="ENV", key="LEGACY_VAR", has_value=True, line=5),
    )


def test_values_are_never_stored_only_their_presence():
    doc = parse_dockerfile('ENV "MY_SECRET"="hunter2"\nARG EMPTY=\n')
    assert doc.build_vars == (
        BuildVar(kind="ENV", key="MY_SECRET", has_value=True, line=1),
        BuildVar(kind="ARG", key="EMPTY", has_value=False, line=2),
    )
    assert "hunter2" not in repr(doc.build_vars)


def test_dockerfile_line_cap():
    doc = parse_dockerfile("\n".join(["FROM x"] * (MAX_DOCKERFILE_LINES + 1)))
    assert doc.ok is False and doc.error == "dockerfile exceeds line cap"


@pytest.mark.parametrize("text", [
    "FROM x\x00y",              # NUL in an image ref
    "\tFROM python",            # tab-indented instruction
    "FROM python \\",           # continuation at EOF
    "",                         # empty file
    "not a dockerfile",         # prose
    "FROM a\nRUN b \\\n",       # truncated continuation
    "# only a comment",         # nothing to parse
    "FROM x\r\nENV k=v\r\n",    # CRLF line endings
])
def test_hostile_dockerfiles_never_raise(text):
    doc = parse_dockerfile(text)
    assert isinstance(doc, DockerfileDoc)
    assert doc.ok or doc.error


# ---------------------------------------------------- parse-only contract

_BANNED_IMPORTS = {"subprocess", "socket", "ssl", "urllib", "httpx",
                   "requests", "aiohttp", "multiprocessing", "ctypes"}
# compose-only: every construct-*or*-load entry point is off contract, even
# the "safe" one — building Python objects from PR YAML is not parsing.
_BANNED_YAML_LOADS = {"load", "safe_load", "full_load", "unsafe_load"}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__"}


def _is_safe_loader(node) -> bool:
    return (isinstance(node, ast.Attribute) and node.attr == "SafeLoader"
            and isinstance(node.value, ast.Name) and node.value.id == "yaml")


def _violations(source: str) -> list[str]:
    """Contract violations: network/process access, object construction
    from YAML, dynamic execution, any non-safe Loader argument."""
    tree = ast.parse(source)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if name.split(".")[0] in _BANNED_IMPORTS:
                hits.append(f"import {name}")
        if isinstance(node, ast.Attribute):
            base = node.value
            if (node.attr in _BANNED_YAML_LOADS and isinstance(base, ast.Name)
                    and base.id == "yaml"):
                hits.append(f"yaml.{node.attr}")
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) \
                    and node.func.id in _BANNED_CALLS:
                hits.append(f"call {node.func.id}()")
            for kw in node.keywords:
                if kw.arg == "Loader" and not _is_safe_loader(kw.value):
                    hits.append("unsafe yaml Loader")
    return hits


def test_parser_module_is_parse_only_and_offline():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert _violations(source) == []
    assert "yaml.compose(" in source        # the sanctioned entry point

    # self-check: the scan flags what it exists to catch
    assert _violations("import yaml\nyaml.load('x: 1')\n")
    assert _violations("import subprocess\n")
    assert _violations("eval('1')\n")
    assert _violations("yaml.compose(x, Loader=yaml.UnsafeLoader)\n")
    assert not _violations("yaml.compose(x, Loader=yaml.SafeLoader)\n")


# ============================================================ V4.6-E05-T02
# Misconfiguration rules + runner. Same fixture files, same hostile posture:
# every degradation is a labeled warning, the flag is default-OFF, and the
# runner never raises.

from ai_pr_reviewer.cli import parse_args                        # noqa: E402
from ai_pr_reviewer.config import load_config                    # noqa: E402
from ai_pr_reviewer.diff_parser import (FileDiff, Hunk, HunkLine)  # noqa: E402
from ai_pr_reviewer.infra_intel import (INFRA001, INFRA002, INFRA003,  # noqa: E402
                                        INFRA004, INFRA005, InfraHit,
                                        InfraOutcome, _check_dockerfile,
                                        _check_workflow, _image_pinned,
                                        _ref_pinned, finding_from_hit,
                                        run_infra_check)

# ------------------------------------------------------------- unit matrices

@pytest.mark.parametrize("value,expected", [
    ("./local-action", True),
    ("actions/checkout@" + "a" * 40, True),
    ("docker://alpine@sha256:" + "b" * 64, True),
    ("actions/checkout@v4", False),
    ("org/repo/.github/workflows/x.yml@main", False),
    ("actions/checkout", False),
    ("docker://alpine:3.19", False),
    ("actions/checkout@" + "a" * 39, False),   # 39 hex is not a full SHA
    ("", False),
])
def test_ref_pinned_matrix(value, expected):
    assert _ref_pinned(value) is expected


@pytest.mark.parametrize("image,expected", [
    ("scratch", True),
    ("python:3.12-slim", True),
    ("python", False),
    ("python:latest", False),
    ("registry:5000/app", False),          # registry port, not a tag
    ("registry:5000/app:1.2", True),
    ("app@sha256:" + "c" * 64, True),
    ("alpine:V2", True),
    ("", False),
])
def test_image_pinned_matrix(image, expected):
    assert _image_pinned(image, stages={"builder"}) is expected


def test_stage_reference_counts_as_pinned():
    assert _image_pinned("builder", stages={"builder"})
    assert _image_pinned("BUILDER", stages={"builder"})   # case-insensitive


# ------------------------------------------------------- rule check ordering

def test_workflow_rule_hits_order_and_anchors():
    doc = parse_workflow(WORKFLOW, path=".github/workflows/ci.yml")
    hits = _check_workflow(doc)
    assert [h.rule_id for h in hits] == [INFRA001, INFRA002,
                                         INFRA003, INFRA003]
    # write-all grant line, write-all grant line, both unpinned uses
    assert [h.line for h in hits] == [7, 7, 13, 17]
    assert hits[0].title == "Workflow permissions set to write-all"
    assert "pull_request_target" in hits[1].explanation


def test_pull_request_target_without_write_grant_is_not_flagged():
    doc = parse_workflow("on: pull_request_target\npermissions: read-all\n")
    assert _check_workflow(doc) == []

    doc = parse_workflow(
        "on: pull_request_target\npermissions:\n  contents: read\n")
    assert _check_workflow(doc) == []


def test_pinned_and_local_uses_are_not_flagged():
    sha = "d" * 40
    doc = parse_workflow(
        "on: push\njobs:\n  b:\n    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      - uses: ./local-action\n")
    assert _check_workflow(doc) == []


def test_dockerfile_froms_checked_before_vars():
    doc = parse_dockerfile(DOCKERFILE, path="Dockerfile")
    hits = _check_dockerfile(doc)
    # froms first (the unpinned 'FROM alpine' at line 10), then the
    # secret-named ENV literal at line 4.
    assert [(h.rule_id, h.line) for h in hits] == [(INFRA005, 10),
                                                   (INFRA004, 4)]

    doc = parse_dockerfile(
        "# syntax=docker/dockerfile:1\n"
        "FROM python:3.12-slim AS builder\n"
        "ARG BUILDKIT_INLINE_CACHE\n"
        "ENV API_TOKEN=literal-value\n"
        "RUN echo hi\n"
        "FROM builder\n"
        "FROM scratch\n"
        "FROM alpine:3.19\n"
        "FROM registry.example.com:5000/app:1.2\n"
        "FROM alpine\n", path="Dockerfile")
    hits = _check_dockerfile(doc)
    assert [(h.rule_id, h.line) for h in hits] == [(INFRA005, 10),
                                                   (INFRA004, 4)]


def test_secret_key_name_without_literal_value_is_not_flagged():
    doc = parse_dockerfile("ARG API_TOKEN\nENV EMPTY_SECRET=\n")
    assert _check_dockerfile(doc) == []


# ------------------------------------------------------- finding construction

def test_finding_from_hit_carries_closed_vocab_and_provenance():
    hit = InfraHit(INFRA001, ".github/workflows/ci.yml", 7,
                   "Workflow permissions set to write-all",
                   "Workflow sets permissions: write-all at line 7.",
                   "permissions: write-all (line 7)")
    f = finding_from_hit(hit, anchor_line=7)
    assert f is not None
    assert (f.file, f.line) == (".github/workflows/ci.yml", 7)
    assert (f.severity, f.category, f.confidence) == ("high", "security",
                                                      "high")
    assert f.rule_id == INFRA001
    assert f.suggestion is None                 # describe, never remediate
    assert (f.provenance_engine, f.provenance_model,
            f.provenance_origin) == ("static", "infra-v1", "rule")
    assert f.provenance_sources[0].model == "infra-v1"
    kinds = [(ev.kind, ev.locator) for ev in f.evidence]
    assert kinds == [("file_excerpt", ".github/workflows/ci.yml:7"),
                     ("rule_ref", f"rule:{INFRA001}")]


def test_finding_anchor_none_is_file_level():
    hit = InfraHit(INFRA003, ".github/workflows/ci.yml", 40,
                   "Unpinned action reference 'x@v1'",
                   "references x@v1 at line 40 without a full commit SHA.",
                   "uses: x@v1")
    f = finding_from_hit(hit, anchor_line=None)
    assert f.line is None
    # the evidence locator keeps the exact position either way
    assert f.evidence[0].locator == ".github/workflows/ci.yml:40"


def test_finding_text_is_scrubbed_and_redacted():
    hit = InfraHit(INFRA004, "Dockerfile", 3,
                   "Secret-named ENV 'API_TOKEN' assigned a literal value",
                   "ENV API_TOKEN=hunter2 at line 3; the value is not "
                   "reproduced here.",
                   "ENV API_TOKEN assigned a value")
    f = finding_from_hit(hit, anchor_line=3,
                         scrub=lambda t: t.replace("hunter2", "[GONE]"))
    assert "hunter2" not in f.explanation
    assert "[GONE]" in f.explanation
    assert all("hunter2" not in ev.summary for ev in f.evidence)


# --------------------------------------------------------------- diff helpers

def _added(path: str, text: str) -> FileDiff:
    lines = text.split("\n")
    return FileDiff(old_path="", new_path=path, is_new=True, hunks=[
        Hunk(old_start=0, old_count=0, new_start=1, new_count=len(lines),
             lines=[HunkLine(tag="+", old_no=None, new_no=i, text=t)
                    for i, t in enumerate(lines, 1)])])


def _modified(path: str, hunk_lines, *, old_start: int = 1,
              new_start: int = 1) -> FileDiff:
    """``hunk_lines``: (tag, old_no, new_no, text) tuples."""
    old_count = sum(1 for t, _, _, _ in hunk_lines if t in (" ", "-"))
    new_count = sum(1 for t, _, _, _ in hunk_lines if t in (" ", "+"))
    return FileDiff(old_path=path, new_path=path, hunks=[
        Hunk(old_start=old_start, old_count=old_count,
             new_start=new_start, new_count=new_count,
             lines=[HunkLine(tag=t, old_no=o, new_no=n, text=x)
                    for t, o, n, x in hunk_lines])])


DEPLOY = """name: deploy
on:
  pull_request_target:
permissions:
  write-all
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - run: make
"""

# Base revision content (what the documented base checkout leaves on disk).
BASE_CI = """name: ci
on:
  push:
permissions:
  contents: read
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: make
"""

# The PR switches push -> pull_request_target and read -> write.
CI_MODIFICATION = [
    (" ", 1, 1, "name: ci"),
    (" ", 2, 2, "on:"),
    ("-", 3, None, "  push:"),
    ("+", None, 3, "  pull_request_target:"),
    (" ", 4, 4, "permissions:"),
    ("-", 5, None, "  contents: read"),
    ("+", None, 5, "  contents: write"),
    (" ", 6, 6, "jobs:"),
    (" ", 7, 7, "  build:"),
    (" ", 8, 8, "    steps:"),
    (" ", 9, 9, "      - uses: actions/checkout@v4"),
    (" ", 10, 10, "      - run: make"),
]


def _write_base(root, relpath: str, text: str) -> None:
    path = Path(root) / relpath
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ------------------------------------------------------- runner end-to-end

def test_added_workflow_yields_overpermission_findings_with_path_evidence():
    """Exit criterion: the over-permissioned fixture produces findings that
    cite the offending key with path evidence."""
    out = run_infra_check(repo_root=".",
                          files=[_added(".github/workflows/deploy.yml",
                                        DEPLOY)])
    assert out.warnings == ()
    assert [f.rule_id for f in out.findings] == [INFRA001, INFRA002,
                                                 INFRA003, INFRA003]
    assert [f.line for f in out.findings] == [5, 5, 9, 10]
    first = out.findings[0]
    assert first.evidence[0].locator == ".github/workflows/deploy.yml:5"
    assert first.evidence[1].locator == f"rule:{INFRA001}"
    for f in out.findings:
        assert all(ev.integrity_ok for ev in f.evidence)


def test_modified_workflow_is_spliced_from_base_copy(tmp_path):
    """The documented deployment checks out the BASE revision: the runner
    must reconstruct the proposed content from the on-disk copy plus the
    hunks and anchor findings in new-file coordinates."""
    _write_base(tmp_path, ".github/workflows/ci.yml", BASE_CI)
    out = run_infra_check(repo_root=str(tmp_path), files=[
        _modified(".github/workflows/ci.yml", CI_MODIFICATION)])
    assert out.warnings == ()
    assert [(f.rule_id, f.line) for f in out.findings] == [(INFRA002, 5),
                                                           (INFRA003, 9)]


def test_disk_copy_mismatch_degrades_to_a_warning(tmp_path):
    # Disk holds a THIRD state the diff does not describe (stale checkout):
    # judge nothing, label the degradation.
    _write_base(tmp_path, ".github/workflows/ci.yml",
                BASE_CI.replace("build", "buidl"))
    out = run_infra_check(repo_root=str(tmp_path), files=[
        _modified(".github/workflows/ci.yml", CI_MODIFICATION)])
    assert out.findings == ()
    assert out.warnings == (
        "infra file not reviewed (on-disk copy does not match the diff): "
        ".github/workflows/ci.yml",)


def test_missing_base_copy_is_a_warning(tmp_path):
    out = run_infra_check(repo_root=str(tmp_path), files=[
        _modified(".github/workflows/ci.yml", CI_MODIFICATION)])
    assert out.findings == ()
    assert out.warnings == (
        "infra file not reviewed (on-disk copy unavailable): "
        ".github/workflows/ci.yml",)


def test_deleted_and_binary_files_are_silent(tmp_path):
    _write_base(tmp_path, ".github/workflows/ci.yml", BASE_CI)
    deleted = _modified(".github/workflows/ci.yml", CI_MODIFICATION)
    deleted.is_deleted = True
    out = run_infra_check(repo_root=str(tmp_path), files=[deleted])
    assert out == InfraOutcome()

    binary = _modified(".github/workflows/ci.yml", CI_MODIFICATION)
    binary.is_binary = True
    out = run_infra_check(repo_root=str(tmp_path), files=[binary])
    assert out == InfraOutcome()


def test_path_traversal_old_copy_is_refused(tmp_path):
    out = run_infra_check(repo_root=str(tmp_path), files=[
        _modified(".github/workflows/../../../outside.yml",
                  CI_MODIFICATION)])
    assert out.findings == ()
    assert out.warnings == (
        "infra file not reviewed (path escapes the repository): "
        ".github/workflows/../../../outside.yml",)


def test_sensitive_paths_are_skipped_silently(tmp_path):
    """Privacy baseline: a Dockerfile under secrets/ is never read."""
    out = run_infra_check(repo_root=str(tmp_path), files=[
        _added("secrets/Dockerfile", "FROM alpine\nENV API_TOKEN=x\n")])
    assert out == InfraOutcome()


def test_malformed_proposed_yaml_degrades_to_a_warning(tmp_path):
    out = run_infra_check(repo_root=".", files=[
        _added(".github/workflows/bad.yml", "jobs:\n  steps: [unclosed\n")])
    assert out.findings == ()
    assert len(out.warnings) == 1
    assert out.warnings[0].startswith("infra file degraded (")
    assert out.warnings[0].endswith(".github/workflows/bad.yml")


def test_infra_file_cap_stops_and_warns():
    many = [_added(f".github/workflows/w{i}.yml", "on: push")
            for i in range(51)]
    out = run_infra_check(repo_root=".", files=many)
    assert out.warnings == (
        "infra file cap (50) reached; remaining infra files not reviewed",)


def test_warnings_are_scrubbed(tmp_path):
    out = run_infra_check(
        repo_root=str(tmp_path),
        files=[_modified(".github/workflows/hunter2.yml", CI_MODIFICATION)],
        scrub=lambda t: t.replace("hunter2", "[GONE]"))
    assert len(out.warnings) == 1
    assert "hunter2" not in out.warnings[0]
    assert "[GONE]" in out.warnings[0]


def test_runner_never_raises(monkeypatch):
    from ai_pr_reviewer import infra_intel

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(infra_intel, "_run", boom)
    out = run_infra_check(repo_root=".", files=[])
    assert out.findings == ()
    assert out.warnings == ("infra check failed (RuntimeError); skipped",)


def test_non_infra_files_are_a_true_noop(tmp_path):
    out = run_infra_check(repo_root=str(tmp_path), files=[
        _modified("a.py", [(" ", 1, 1, "x = 1"), ("+", None, 2, "y = 2")]),
        _added("docs/readme.md", "# hi\n")])
    assert out == InfraOutcome()


# ------------------------------------------------------------------- config

def test_infra_intel_flag_is_plain_env_default_off(monkeypatch):
    monkeypatch.delenv("INFRA_INTEL", raising=False)
    assert load_config(parse_args([])).infra_intel is False

    monkeypatch.setenv("INFRA_INTEL", "true")
    assert load_config(parse_args([])).infra_intel is True

    # Deliberately NOT an action input: INPUT_* must not enable it.
    monkeypatch.delenv("INFRA_INTEL", raising=False)
    monkeypatch.setenv("INPUT_INFRA_INTEL", "1")
    assert load_config(parse_args([])).infra_intel is False

    # And no CLI flag exists.
    with pytest.raises(SystemExit):
        parse_args(["--infra-intel"])


# ------------------------------------------------------- orchestrator hook

def test_hook_is_off_by_default_and_never_runs_the_check(monkeypatch):
    from test_orchestrator import Wired

    def bomb(**kwargs):
        raise AssertionError("infra check must not run when the flag is off")

    import ai_pr_reviewer.infra_intel as infra_intel
    monkeypatch.setattr(infra_intel, "run_infra_check", bomb)
    w = Wired(monkeypatch)
    result = w.run()
    assert not [x for x in result.warnings if "infra" in x]


def test_hook_joins_findings_and_warnings_when_enabled(monkeypatch):
    from test_orchestrator import Wired, _finding

    canned_finding = _finding(file="a.py", line=2, title="INFRA canned",
                              severity="high")

    def canned(**kwargs):
        return InfraOutcome(findings=(canned_finding,),
                            warnings=("canned infra warning",))

    import ai_pr_reviewer.infra_intel as infra_intel
    monkeypatch.setattr(infra_intel, "run_infra_check", canned)
    w = Wired(monkeypatch)
    w.cfg.infra_intel = True
    result = w.run()
    assert any(f.title == "INFRA canned" for f in result.findings)
    assert "canned infra warning" in result.warnings
