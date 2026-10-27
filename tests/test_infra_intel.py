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
