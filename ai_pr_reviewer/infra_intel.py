"""V4.6-E05-T01 — infrastructure file parsers (parse, never execute).

Workflow YAML and Dockerfile parsing for the misconfiguration rules of
E05-T02. These files are attacker-controlled PR content, so the contract
is deliberately narrow:

* **parse, never interpret** — workflow YAML goes through
  ``yaml.compose(..., Loader=yaml.SafeLoader)``: a parse-only call that
  builds a node graph and never constructs Python objects (no ``!!python/``
  instantiation path, and no YAML-1.1 ``on:`` → ``True`` key surprise —
  keys keep their written text as scalar nodes). The Dockerfile parser is
  a bounded line scanner over instructions. Nothing here interprets or
  executes content;
* **never resolve ``uses:``** — action references are collected as opaque
  strings with their line numbers; nothing here asks what they point at;
* **bounded** — a size cap before parsing, node/depth/alias-cycle caps
  after it, a line cap for Dockerfiles. Every cap trip is a labeled
  degradation (``ok=False`` + short ``error``), never an exception;
* **never raises** — hostile input (malformed YAML, alias cycles, depth
  bombs, control characters) degrades to a label. Error strings are built
  from exception *types* and line numbers only, never document content,
  so a parse failure cannot echo the file it failed on.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import yaml
from yaml.nodes import MappingNode, SequenceNode, ScalarNode

# ------------------------------------------------------------------ caps
# Hard bounds on hostile input: checked before (size) or during (nodes,
# depth, Dockerfile lines) parsing, so a PR cannot make this module burn
# CPU, memory or stack proportional to an unbounded file.

MAX_FILE_CHARS = 262_144         # 256 KiB — generous for workflows/Dockerfiles
MAX_YAML_NODES = 20_000
MAX_YAML_DEPTH = 50
MAX_DOCKERFILE_LINES = 2_000
MAX_PARSE_ERROR_CHARS = 160


# ------------------------------------------------------------------- docs

@dataclass(frozen=True)
class PermissionGrant:
    """One ``permissions:`` block: workflow level (``job=""``) or one job.

    ``scalar`` holds the whole-block form (``write-all``/``read-all``);
    ``scopes`` holds the per-scope form as ``(scope, level)`` pairs, e.g.
    ``("contents", "write")``. ``line`` is where the block's content
    starts (1-based), for evidence locators.
    """

    job: str = ""
    scalar: str | None = None
    scopes: tuple[tuple[str, str], ...] = ()
    line: int = 0


@dataclass(frozen=True)
class UseRef:
    """One ``uses:`` reference, kept opaque — never resolved (E05)."""

    job: str = ""
    value: str = ""
    line: int = 0


@dataclass(frozen=True)
class WorkflowDoc:
    """Result of :func:`parse_workflow`: extracted facts or a degrade label."""

    path: str = ""
    triggers: tuple[tuple[str, int], ...] = ()
    permissions: tuple[PermissionGrant, ...] = ()
    uses: tuple[UseRef, ...] = ()
    ok: bool = False
    error: str | None = None


@dataclass(frozen=True)
class FromInstruction:
    """One ``FROM``: the image ref as written, an ``AS`` stage alias."""

    image: str = ""
    stage: str | None = None
    line: int = 0


@dataclass(frozen=True)
class BuildVar:
    """One ``ARG``/``ENV`` declaration. The *value* is deliberately not
    stored — only whether one was assigned — so a secret literal can never
    travel from here into a finding, warning or log line."""

    kind: str = ""               # "ARG" | "ENV"
    key: str = ""
    has_value: bool = False
    line: int = 0


@dataclass(frozen=True)
class DockerfileDoc:
    """Result of :func:`parse_dockerfile`: extracted facts or a degrade label."""

    path: str = ""
    froms: tuple[FromInstruction, ...] = ()
    build_vars: tuple[BuildVar, ...] = ()
    ok: bool = False
    error: str | None = None


# ----------------------------------------------------------------- labels

def _yaml_error_label(exc: Exception) -> str:
    """Exception *type* + line only — never document content."""
    mark = getattr(exc, "problem_mark", None)
    where = f" line {mark.line + 1}" if mark is not None else ""
    return f"yaml parse failed ({type(exc).__name__}{where})"[:MAX_PARSE_ERROR_CHARS]


def _crash_label(what: str, exc: Exception) -> str:
    return f"{what} parse failed ({type(exc).__name__})"[:MAX_PARSE_ERROR_CHARS]


# -------------------------------------------------------- workflow YAML

def _scalar_text(node) -> str | None:
    return node.value if isinstance(node, ScalarNode) else None


def _line(node, fallback: int = 0) -> int:
    """1-based line of a node's start mark (PyYAML marks are 0-based)."""
    mark = getattr(node, "start_mark", None)
    return (mark.line + 1) if mark is not None else fallback


def _children(node) -> list:
    if isinstance(node, MappingNode):
        out: list = []
        for key, val in node.value:
            out.append(key)
            out.append(val)
        return out
    if isinstance(node, SequenceNode):
        return list(node.value)
    return []


def _validate_yaml(root) -> str | None:
    """Caps for a composed node graph; ``None`` = within bounds.

    The on-path set catches alias cycles: PyYAML composes ``&a [*a]``
    into a genuinely self-referential graph, so a naive walk would
    recurse forever. A shared, *non*-cyclic anchor leaves the set between
    branches and stays legal.
    """
    on_path: set[int] = set()
    count = 0

    def visit(node, depth: int) -> str | None:
        nonlocal count
        count += 1
        if count > MAX_YAML_NODES:
            return "workflow exceeds node cap"
        if depth > MAX_YAML_DEPTH:
            return "workflow exceeds depth cap"
        if id(node) in on_path:
            return "workflow has a cyclic alias"
        on_path.add(id(node))
        for child in _children(node):
            err = visit(child, depth + 1)
            if err is not None:
                return err
        on_path.discard(id(node))
        return None

    return visit(root, 0)


def _trigger_entries(val) -> list[tuple[str, int]]:
    """Trigger names from ``on:`` — mapping keys, sequence items or a
    scalar (``on: push``). Branch config under each trigger is structure
    we do not interpret."""
    if isinstance(val, MappingNode):
        pairs = [(_scalar_text(k), k) for k, _ in val.value]
    elif isinstance(val, SequenceNode):
        pairs = [(_scalar_text(item), item) for item in val.value]
    else:
        pairs = [(_scalar_text(val), val)]
    return [(name, _line(node)) for name, node in pairs if name]


def _grant(val, *, job: str, fallback: int) -> PermissionGrant:
    if isinstance(val, ScalarNode):
        return PermissionGrant(job=job, scalar=val.value.strip() or None,
                               line=_line(val, fallback))
    if isinstance(val, MappingNode):
        scopes = []
        for key, item in val.value:
            scope, level = _scalar_text(key), _scalar_text(item)
            if scope and level:
                scopes.append((scope.strip(), level.strip()))
        return PermissionGrant(job=job, scopes=tuple(scopes),
                               line=_line(val, fallback))
    # null or structurally odd value: a grant with nothing to judge
    return PermissionGrant(job=job, line=fallback)


def _extract_steps(steps, job: str, uses: list[UseRef]) -> None:
    for step in steps.value:
        if not isinstance(step, MappingNode):
            continue
        for key, val in step.value:
            if _scalar_text(key) == "uses":
                ref = _scalar_text(val)
                if ref:
                    uses.append(UseRef(job=job, value=ref.strip(),
                                       line=_line(val)))


def _extract_jobs(jobs, grants: list[PermissionGrant],
                  uses: list[UseRef]) -> None:
    for jkey, jval in jobs.value:
        job = (_scalar_text(jkey) or "").strip()
        if not isinstance(jval, MappingNode):
            continue
        for key, val in jval.value:
            name = _scalar_text(key)
            if name == "uses":
                ref = _scalar_text(val)
                if ref:
                    uses.append(UseRef(job=job, value=ref.strip(),
                                       line=_line(val)))
            elif name == "permissions":
                grants.append(_grant(val, job=job, fallback=_line(key)))
            elif name == "steps" and isinstance(val, SequenceNode):
                _extract_steps(val, job, uses)


def _extract_workflow(root: MappingNode
                      ) -> tuple[tuple[tuple[str, int], ...],
                                 tuple[PermissionGrant, ...],
                                 tuple[UseRef, ...]]:
    triggers: list[tuple[str, int]] = []
    grants: list[PermissionGrant] = []
    uses: list[UseRef] = []
    for key, val in root.value:
        name = _scalar_text(key)
        if name == "on":
            triggers.extend(_trigger_entries(val))
        elif name == "permissions":
            grants.append(_grant(val, job="", fallback=_line(key)))
        elif name == "jobs" and isinstance(val, MappingNode):
            _extract_jobs(val, grants, uses)
    # A shared (non-cyclic) anchor can surface the identical fact twice;
    # first occurrence wins, order stays deterministic.
    return (tuple(dict.fromkeys(triggers)), tuple(dict.fromkeys(grants)),
            tuple(dict.fromkeys(uses)))


def parse_workflow(text: str, *, path: str = "") -> WorkflowDoc:
    """Parse a workflow YAML document into bounded facts. Never raises.

    A document that parses but breaks a cap, or that is not a mapping at
    its root, degrades to ``ok=False`` with a short label; an empty
    document is ``ok=True`` with no facts (nothing to judge).
    """
    if len(text) > MAX_FILE_CHARS:
        return WorkflowDoc(path=path, error="workflow exceeds size cap")
    try:
        # Parse-only: a node graph, no Python object construction. The
        # broad except is the hostile-input contract — RecursionError from
        # pathological nesting must degrade like any other bad input.
        root = yaml.compose(text, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        return WorkflowDoc(path=path, error=_yaml_error_label(exc))
    except Exception as exc:  # noqa: BLE001 — hostile input must never raise
        return WorkflowDoc(path=path, error=_crash_label("workflow", exc))
    if root is None:
        return WorkflowDoc(path=path, ok=True)
    err = _validate_yaml(root)
    if err is not None:
        return WorkflowDoc(path=path, error=err)
    if not isinstance(root, MappingNode):
        return WorkflowDoc(path=path, error="workflow root is not a mapping")
    triggers, grants, uses = _extract_workflow(root)
    return WorkflowDoc(path=path, triggers=triggers, permissions=grants,
                       uses=uses, ok=True)


# ------------------------------------------------------------ Dockerfile

_INSTR_RE = re.compile(r"\s*([A-Za-z][A-Za-z0-9_]*)\b\s*(.*)")


def _logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Instruction lines with ``\\`` continuations joined; the tuple's
    line is the instruction's first physical line (1-based). Comments and
    blank lines outside continuations are skipped."""
    out: list[tuple[int, str]] = []
    buf = ""
    start = 0
    for lineno, line in enumerate(lines, 1):
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if not buf:
            start = lineno
        piece = line.rstrip()
        if piece.endswith("\\"):
            buf += piece[:-1] + " "
            continue
        out.append((start, (buf + piece).strip()))
        buf = ""
    if buf:
        out.append((start, buf.strip()))
    return out


def _strip_quotes(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _parse_from(rest: str, lineno: int) -> FromInstruction | None:
    tokens = rest.split()
    while tokens and tokens[0].startswith("--"):   # --platform=... flags
        tokens.pop(0)
    if not tokens:
        return None
    upper = [t.upper() for t in tokens]
    stage = None
    if "AS" in upper[1:]:
        idx = upper.index("AS", 1)
        if idx + 1 < len(tokens):
            stage = tokens[idx + 1]
    return FromInstruction(image=tokens[0], stage=stage, line=lineno)


def _parse_vars(instr: str, rest: str, lineno: int) -> list[BuildVar]:
    """``ARG k[=v]``, ``ENV k=v k2=v2`` and the legacy ``ENV k v``.
    Records key + value *presence* only — never the value itself."""
    if not rest:
        return []
    tokens = rest.split()
    if instr == "ARG":
        key, _, val = tokens[0].partition("=")
        key = _strip_quotes(key)
        if not key:
            return []
        return [BuildVar(kind="ARG", key=key, has_value=bool(val.strip()),
                         line=lineno)]
    if "=" not in tokens[0]:                      # legacy: ENV key value
        key = _strip_quotes(tokens[0])
        if not key:
            return []
        return [BuildVar(kind="ENV", key=key, has_value=len(tokens) > 1,
                         line=lineno)]
    out: list[BuildVar] = []
    for token in tokens:                          # ENV k=v k2=v2
        key, sep, val = token.partition("=")
        if not sep:
            continue                              # broken tail token: skip
        key = _strip_quotes(key)
        if key:
            out.append(BuildVar(kind="ENV", key=key,
                                has_value=bool(val.strip()), line=lineno))
    return out


def parse_dockerfile(text: str, *, path: str = "") -> DockerfileDoc:
    """Parse a Dockerfile into bounded facts. Never raises.

    A bounded line scanner, not a build: instructions are matched by name
    and the values we keep are key names, image refs and line numbers —
    no variable expansion, no stage resolution, no ``RUN`` interpretation.
    """
    if len(text) > MAX_FILE_CHARS:
        return DockerfileDoc(path=path, error="dockerfile exceeds size cap")
    if len(text.splitlines()) > MAX_DOCKERFILE_LINES:
        return DockerfileDoc(path=path, error="dockerfile exceeds line cap")
    froms: list[FromInstruction] = []
    build_vars: list[BuildVar] = []
    for lineno, raw in _logical_lines(text.splitlines()):
        match = _INSTR_RE.match(raw)
        if match is None:
            continue
        instr, rest = match.group(1).upper(), match.group(2).strip()
        if instr == "FROM":
            parsed = _parse_from(rest, lineno)
            if parsed is not None:
                froms.append(parsed)
        elif instr in ("ARG", "ENV"):
            build_vars.extend(_parse_vars(instr, rest, lineno))
    return DockerfileDoc(path=path, froms=tuple(froms),
                         build_vars=tuple(build_vars), ok=True)
