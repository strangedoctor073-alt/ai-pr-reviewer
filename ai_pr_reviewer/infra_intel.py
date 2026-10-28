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

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import yaml
from yaml.nodes import MappingNode, SequenceNode, ScalarNode

from .diff_parser import FileDiff
from .index.limits import is_contained, is_excluded
from .models import (STATIC_ENGINE_ID, EvidenceRecord, Finding,
                     ProvenanceSource)
from .repo_context import _safe_repo_path
from .rules import SENSITIVE_EXCLUDE_GLOBS
from .security import redact_secrets

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


# ------------------------------------------------- misconfiguration rules
# V4.6-E05-T02. Closed vocabulary: rule id, severity, category and
# confidence come from the table below, never from file content.

INFRA001 = "INFRA001"    # permissions: write-all
INFRA002 = "INFRA002"    # pull_request_target + any write-level grant
INFRA003 = "INFRA003"    # uses: not pinned to a full commit SHA
INFRA004 = "INFRA004"    # secret-named ARG/ENV assigned a literal value
INFRA005 = "INFRA005"    # FROM with neither a specific tag nor a digest


@dataclass(frozen=True)
class InfraRuleMeta:
    severity: str
    category: str
    confidence: str
    contract: str      # factual statement of what the check accepts


_INFRA_RULES: dict[str, InfraRuleMeta] = {
    INFRA001: InfraRuleMeta(
        "high", "security", "high",
        "checked: a permissions block whose whole-block value is write-all"),
    INFRA002: InfraRuleMeta(
        "high", "security", "high",
        "checked: a pull_request_target trigger together with a write-level "
        "grant (scope level 'write', or a write-all block)"),
    INFRA003: InfraRuleMeta(
        "medium", "security", "high",
        "checked: a local './' path, a full 40-hex commit SHA after '@', or "
        "a full digest for docker:// references; tags and branches do not "
        "count"),
    INFRA004: InfraRuleMeta(
        "high", "security", "medium",
        "checked: a secret-named key (secret, token, password, api key, "
        "private key, credential) assigned a non-empty literal value; the "
        "name alone does not match"),
    INFRA005: InfraRuleMeta(
        "medium", "security", "high",
        "checked: 'scratch', an earlier stage reference, a digest, or a "
        "specific tag other than 'latest' counts as pinned"),
}


@dataclass(frozen=True)
class InfraHit:
    """One rule match in proposed-content line coordinates.

    ``line`` is the offending line itself; the finding built from it may
    anchor at ``None`` (file level) when that line is outside the diff —
    the evidence locator keeps the exact position either way.
    """

    rule_id: str
    path: str
    line: int | None
    title: str
    explanation: str
    detail: str


_SECRET_KEY_RE = re.compile(
    r"(?i)(secret|token|password|passwd|api[_-]?key|private[_-]?key|credential)")


def _ref_pinned(value: str) -> bool:
    """Local actions and full-SHA/full-digest pins are accepted; a tag or
    branch can be moved after this review, so it is not a pin."""
    if value.startswith("./"):
        return True
    if "@" not in value:
        return False
    tail = value.rsplit("@", 1)[1].strip()
    return re.fullmatch(r"[0-9a-fA-F]{40}", tail) is not None \
        or re.fullmatch(r"sha256:[0-9a-fA-F]{64}", tail) is not None


def _image_pinned(image: str, stages: set[str]) -> bool:
    low = image.lower()
    if low == "scratch" or low in stages:
        return True
    if re.search(r"@[A-Za-z0-9._-]+:[0-9a-fA-F]{32,}", image):
        return True                          # digest pin
    cut = image.rfind(":")
    if cut == -1:
        return False                         # no tag at all
    tag = image[cut + 1:]
    if "/" in tag:
        return False                         # registry port, not a tag
    return bool(tag) and tag.lower() != "latest"


def _grant_writes(grant: PermissionGrant) -> bool:
    if grant.scalar and grant.scalar.lower() == "write-all":
        return True
    return any(level.lower() == "write" for _, level in grant.scopes)


def _check_workflow(doc: WorkflowDoc) -> list[InfraHit]:
    hits: list[InfraHit] = []
    prwt_line = next((line for name, line in doc.triggers
                      if name == "pull_request_target"), None)
    first_write: PermissionGrant | None = None
    for grant in doc.permissions:
        subject = f"Job '{grant.job}'" if grant.job else "Workflow"
        if grant.scalar and grant.scalar.lower() == "write-all":
            hits.append(InfraHit(
                INFRA001, doc.path, grant.line,
                title=f"{subject} permissions set to write-all",
                explanation=(f"{subject} sets permissions: write-all at line "
                             f"{grant.line}, granting the workflow token "
                             f"every scope GitHub defines."),
                detail=f"permissions: write-all (line {grant.line})"))
        if first_write is None and _grant_writes(grant):
            first_write = grant
    if prwt_line is not None and first_write is not None:
        grant = first_write
        where = f"job '{grant.job}'" if grant.job else "the workflow"
        grants = (grant.scalar if grant.scalar
                  and grant.scalar.lower() == "write-all"
                  else ", ".join(f"{scope}: {level}"
                                 for scope, level in grant.scopes
                                 if level.lower() == "write"))
        # One statement per file: the combination, not one per grant.
        hits.append(InfraHit(
            INFRA002, doc.path, grant.line,
            title="pull_request_target trigger combined with write permissions",
            explanation=(
                f"Trigger pull_request_target is declared at line "
                f"{prwt_line} while {where} holds write permissions "
                f"({grants}); pull_request_target runs this workflow for "
                f"pull-request events in the base repository, so the "
                f"reviewed change is processed by a run holding a "
                f"write-capable token."),
            detail=(f"permissions of {where} at line {grant.line}: "
                    f"{grants}, trigger pull_request_target at line "
                    f"{prwt_line}")))
    for ref in doc.uses:
        if _ref_pinned(ref.value):
            continue
        where = f"Job '{ref.job}'" if ref.job else "The workflow"
        hits.append(InfraHit(
            INFRA003, doc.path, ref.line,
            title=f"Unpinned action reference '{ref.value}'",
            explanation=(f"{where} references {ref.value} at line {ref.line} "
                         f"without a full 40-hex commit SHA; a tag or branch "
                         f"can be moved after this review."),
            detail=f"uses: {ref.value}"))
    return hits


def _check_dockerfile(doc: DockerfileDoc) -> list[InfraHit]:
    hits: list[InfraHit] = []
    stages: set[str] = set()
    for fr in doc.froms:
        if not _image_pinned(fr.image, stages):
            hits.append(InfraHit(
                INFRA005, doc.path, fr.line,
                title=f"Unpinned base image '{fr.image}'",
                explanation=(f"FROM {fr.image} at line {fr.line} has neither "
                             f"a digest nor a specific tag other than "
                             f"'latest'; the build resolves it when it runs."),
                detail=f"FROM {fr.image}"))
        if fr.stage:
            stages.add(fr.stage.lower())
    for var in doc.build_vars:
        if var.has_value and _SECRET_KEY_RE.search(var.key):
            subject = f"{var.kind} {var.key}"
            hits.append(InfraHit(
                INFRA004, doc.path, var.line,
                title=f"Secret-named {var.kind} '{var.key}' assigned a "
                      f"literal value",
                explanation=(f"{subject} is assigned a literal value at line "
                             f"{var.line}; build files travel with the build "
                             f"context. The value itself is not reproduced "
                             f"here."),
                detail=f"{subject} assigned a value"))
    return hits


# ------------------------------------------------------------ findings
# V4.6-E05-T02 mirrors architecture.findings: evidence-or-dropped,
# deterministic provenance stamped here (these findings join the pipeline
# AFTER the orchestrator's provenance/redaction chokepoints), no
# remediation, no certification wording, every string redacted,
# control-free, single-line and bounded.

_PROVENANCE_MODEL = "infra-v1"
MAX_TITLE_CHARS = 160
MAX_EVIDENCE_SUMMARY_CHARS = 400   # mirrors models.MAX_EVIDENCE_SUMMARY_CHARS
MAX_EXPLANATION_CHARS = 900
MAX_WARNING_CHARS = 300
_CONTROL = {c: " " for c in (*range(0x20), 0x7F, *range(0x80, 0xA0),
                              0x2028, 0x2029)}


def _clean(text: object, limit: int,
           scrub: Callable[[str], str] | None = None) -> str:
    out = redact_secrets(str(text))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    return out[:limit].strip()


def _evidence(hit: InfraHit, rule: InfraRuleMeta,
              scrub: Callable[[str], str] | None
              ) -> tuple[EvidenceRecord, ...] | None:
    try:
        excerpt = EvidenceRecord.create(
            kind="file_excerpt",
            locator=f"{hit.path}:{hit.line}" if hit.line else hit.path,
            summary=_clean(hit.detail, MAX_EVIDENCE_SUMMARY_CHARS, scrub),
            check_type="infra_rule_hit", scrub=scrub)
        ref = EvidenceRecord.create(
            kind="rule_ref", locator=f"rule:{hit.rule_id}",
            summary=_clean(rule.contract, MAX_EVIDENCE_SUMMARY_CHARS, scrub),
            check_type="infra_rule", scrub=scrub)
    except ValueError:
        return None
    return (excerpt, ref)


def finding_from_hit(hit: InfraHit, *, anchor_line: int | None,
                     scrub: Callable[[str], str] | None = None
                     ) -> Finding | None:
    """Turn a hit into an ordinary pipeline finding — or drop it when its
    evidence cannot be constructed (evidence-or-dropped)."""
    rule = _INFRA_RULES[hit.rule_id]
    evidence = _evidence(hit, rule, scrub)
    if evidence is None:
        return None
    finding = Finding(
        file=hit.path, line=anchor_line, severity=rule.severity,
        category=rule.category,
        title=_clean(hit.title, MAX_TITLE_CHARS, scrub),
        explanation=_clean(hit.explanation, MAX_EXPLANATION_CHARS, scrub),
        suggestion=None, confidence=rule.confidence, rule_id=hit.rule_id,
        evidence=evidence,
    )
    source = ProvenanceSource(engine=STATIC_ENGINE_ID,
                              model=_PROVENANCE_MODEL, origin="rule")
    finding.provenance_engine = source.engine
    finding.provenance_model = source.model
    finding.provenance_agent = None
    finding.provenance_origin = source.origin
    finding.provenance_sources = (source,)
    return finding


# ---------------------------------------------------------------- runner

MAX_INFRA_FILES = 50
MAX_INFRA_WARNINGS = 10
# Disk copies face the same cap the parsers enforce on text (256 KiB):
# stat first so an oversized file is a label, never a full read.
MAX_FILE_BYTES = 262_144

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class InfraOutcome:
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()


NOOP = InfraOutcome()


def _workflow_path(path: str) -> bool:
    low = path.replace("\\", "/").lower()
    return low.startswith(".github/workflows/") and low.endswith((".yml", ".yaml"))


def _is_infra_path(path: str) -> bool:
    if _workflow_path(path):
        return True
    low = path.replace("\\", "/").lower()
    return low.rsplit("/", 1)[-1].startswith("dockerfile")


def _split_disk(text: str) -> list[str]:
    # Split on \n only (str.splitlines() would also break on form feed,
    # NUL-adjacent and U+2028 characters and shift every line number);
    # read_text() already normalized CRLF/CR to \n on the way in.
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _disk_copy(fd: FileDiff, repo_root: str
               ) -> tuple[str | None, str | None]:
    """The diff's OLD side, from disk — the documented deployment checks
    out the PR base revision. Added files need no copy. Every read is
    containment- and size-guarded first: an untrusted path name can never
    drive a read outside the worktree (threat model §1/§2)."""
    if fd.is_new or not fd.old_path:
        return "", None
    rel = fd.old_path
    if not is_contained(repo_root, rel):
        return None, "path escapes the repository"
    path = Path(repo_root) / rel
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None, "file exceeds size cap"
        return path.read_text(encoding="utf-8", errors="replace"), None
    except OSError:
        return None, "on-disk copy unavailable"


def _proposed_text(fd: FileDiff, disk_text: str | None
                   ) -> tuple[str | None, str | None]:
    """The content the PR *proposes* (new side), or a degrade label.

    Added files: the diff alone carries the whole file. Modified files:
    the on-disk copy supplies everything outside the hunks (indexed with
    old-side numbering — in a unified diff those regions are identical on
    both sides), the diff supplies the hunks, and every context AND
    removed line is checked against the disk copy first. A checkout on
    some other commit, or a diff stale against it, degrades to a label
    instead of judging content the PR never proposed. ``(None, None)``
    means there is nothing to judge (deleted/binary) — a silent skip.
    """
    if fd.is_deleted or fd.is_binary:
        return None, None
    if fd.is_new or not fd.old_path:
        out: list[str] = []
        for hunk in fd.hunks:
            for line in hunk.lines:
                if line.tag in ("+", " "):
                    out.append(line.text)
        return "\n".join(out), None
    if not fd.hunks:
        return None, "diff carries no hunks"
    if disk_text is None:
        return None, "on-disk copy unavailable"
    disk = _split_disk(disk_text)
    out = []
    cursor = 1                      # next old-side line, 1-based
    for hunk in fd.hunks:
        # Region before the hunk, identical on both sides. old_count == 0
        # means "insert after old_start" (git's EOF-append form, -N,0).
        keep_end = hunk.old_start - 1 if hunk.old_count else hunk.old_start
        if keep_end < cursor - 1:
            return None, "hunks are not in order or overlap"
        out.extend(disk[cursor - 1:keep_end])
        for line in hunk.lines:
            if line.tag == "+":
                out.append(line.text)
            elif line.tag in (" ", "-"):
                # The disk copy must be the diff's OLD side: context and
                # removed lines live at their old positions there. (Side
                # invariant for " "; the deletion check additionally pins
                # a modified checkout to the base revision.)
                idx = (line.old_no or 0) - 1
                if idx < 0 or idx >= len(disk) or disk[idx] != line.text:
                    return None, "on-disk copy does not match the diff"
                if line.tag == " ":
                    out.append(line.text)
        if hunk.old_count:
            cursor = max(cursor, hunk.old_start + hunk.old_count)
        else:
            cursor = max(cursor, hunk.old_start + 1)
    out.extend(disk[cursor - 1:])
    return "\n".join(out), None


def run_infra_check(*, repo_root: str, files, index=None,
                    scrub: Callable[[str], str] | None = None
                    ) -> InfraOutcome:
    """Single entry point for the review pipeline (V4.6-E05-T02).

    Composes proposed-content reconstruction -> schema-aware parsing ->
    rules -> findings and **never raises**: any failure becomes one
    warning and zero findings. No-op guarantee: with no changed
    infrastructure file the outcome is empty, so output is byte-identical
    (and with the ``INFRA_INTEL`` flag off — the default — the
    orchestrator never calls this at all). ``index`` is accepted here and
    consumed by the deploy-path context of E05-T03.
    """
    try:
        return _run(repo_root, files, index, scrub)
    except Exception as exc:  # noqa: BLE001 — opt-in feature never fails a review
        log.warning("infra check failed: %s", type(exc).__name__)
        return InfraOutcome(warnings=(
            f"infra check failed ({type(exc).__name__}); skipped",))


def _run(repo_root: str, files, index,
         scrub: Callable[[str], str] | None) -> InfraOutcome:
    warnings: list[str] = []
    findings: list[Finding] = []

    def warn(msg: str) -> None:
        warnings.append(_clean(msg, MAX_WARNING_CHARS, scrub))

    line_maps = {fd.path: fd.new_line_numbers() for fd in files}
    reviewed = 0
    for fd in files:
        if not _is_infra_path(fd.path) or fd.is_deleted or fd.is_binary:
            continue
        if (is_excluded(fd.path, SENSITIVE_EXCLUDE_GLOBS)
                or (fd.old_path
                    and is_excluded(fd.old_path, SENSITIVE_EXCLUDE_GLOBS))):
            continue                      # privacy baseline: never read it
        if reviewed >= MAX_INFRA_FILES:
            warn(f"infra file cap ({MAX_INFRA_FILES}) reached; remaining "
                 f"infra files not reviewed")
            break
        disk, err = _disk_copy(fd, repo_root)
        if err is None:
            text, err = _proposed_text(fd, disk)
        else:
            text = None
        if text is None:
            if err is not None:
                warn(f"infra file not reviewed ({err}): {fd.path}")
            continue                      # nothing proposed: silent skip
        reviewed += 1
        doc = (parse_workflow(text, path=fd.path) if _workflow_path(fd.path)
               else parse_dockerfile(text, path=fd.path))
        if not doc.ok:
            warn(f"infra file degraded ({doc.error}): {fd.path}")
            continue
        hits = (_check_workflow(doc) if isinstance(doc, WorkflowDoc)
                else _check_dockerfile(doc))
        for hit in hits:
            anchor = (hit.line
                      if hit.line in line_maps.get(fd.path, ()) else None)
            finding = finding_from_hit(hit, anchor_line=anchor, scrub=scrub)
            if finding is not None:
                findings.append(finding)
    # V4.6-E05-T03: one aggregate deploy-path context finding over the
    # whole change set (path classification only — no content read). It
    # joins the rule findings additively; a missing index degrades to no
    # inventory sentence, never an error.
    ctx = deploy_path_context(files=files, index=index, scrub=scrub)
    findings.extend(ctx.findings)
    return InfraOutcome(findings=tuple(findings),
                        warnings=tuple(warnings[:MAX_INFRA_WARNINGS]))


# --------------------------------------------------- deploy-path context
# V4.6-E05-T03. Not a misconfiguration rule: ONE aggregate context finding
# ("this change touches deployment-relevant paths") so the reviewer sees
# the blast radius, plus one inventory sentence when the repository index
# is available. Path-based only — no content is read for classification,
# and an unnameable path (traversal, absolute) is never classified.

MAX_DEPLOY_LIST = 10
DEPLOY_RULE_ID = "INFRA_DEPLOY_PATH"
DEPLOY_CONTRACT = (
    "checked: changed paths under .github/workflows/ (*.yml|*.yaml), "
    "Dockerfile*, docker-compose*.yml|*.yaml, *.tf and *.tf.json — "
    "classification context, not a rule violation")


def _deploy_path(path: str) -> bool:
    """True for a path that influences deployment configuration.

    Bounded closed vocabulary (suffix/basename only — never content), and
    a path that ``_safe_repo_path`` rejects (``..``, absolute, drive
    letter) is not classifiable at all: it could not be checked out, so
    calling it deploy-relevant would be a fiction. Classification runs on
    the NORMALIZED path, so ``.github/workflows/../x.py`` is ``x.py``.
    """
    if not path:
        return False
    norm = _safe_repo_path(path)
    if norm is None:
        return False
    low = norm.lower()
    if _workflow_path(low):
        return True
    base = low.rsplit("/", 1)[-1]
    if base.startswith("dockerfile"):
        return True
    if base.startswith("docker-compose") and base.endswith((".yml", ".yaml")):
        return True
    return low.endswith(".tf") or low.endswith(".tf.json")


def _inventory_sentence(index) -> str:
    """One bounded sentence about the repository's deploy-relevant paths,
    or ``""`` when no index is available (silent degrade — the finding
    itself is still emitted; a missing index is not an error)."""
    paths = getattr(index, "paths", None)
    if paths is None:
        return ""
    try:
        count = sum(1 for p in paths if _deploy_path(str(p)))
    except Exception:  # noqa: BLE001 — a broken index must not fail a review
        return ""
    return (f"The repository index lists {count} deployment-relevant "
            f"path{'s' if count != 1 else ''} in total.")


def deploy_path_context(*, files, index=None,
                        scrub: Callable[[str], str] | None = None
                        ) -> InfraOutcome:
    """The E05-T03 aggregate deploy-path finding, or a true NOOP.

    Evidence-or-dropped and redaction posture mirror
    :func:`finding_from_hit`; severity/category are closed-vocabulary
    constants (low / maintainability — this is context for the reviewer,
    never a claim that anything is wrong).
    """
    changed: list[str] = []
    anchor_file = ""
    anchor_line: int | None = None
    for fd in files:
        if not fd.path or is_excluded(fd.path, SENSITIVE_EXCLUDE_GLOBS):
            continue
        if not _deploy_path(fd.path):
            continue
        if not changed:
            anchor_file = fd.path
            added = fd.added_lines()
            anchor_line = added[0][0] if added else None
        changed.append(fd.path)
    if not changed:
        return NOOP
    listed = changed[:MAX_DEPLOY_LIST]
    more = len(changed) - len(listed)
    plural = "s" if len(changed) != 1 else ""
    listing = ", ".join(listed) + (f" (+{more} more)" if more else "")
    inventory = _inventory_sentence(index)
    explanation = (
        f"This change modifies {len(changed)} deployment-relevant "
        f"path{plural}: {listing}. Deployment configuration takes effect "
        f"on the next workflow run or deployment." +
        (f" {inventory}" if inventory else ""))
    try:
        excerpt = EvidenceRecord.create(
            kind="file_excerpt", locator=anchor_file,
            summary=_clean(f"{len(changed)} deploy-relevant path"
                           f"{'s' if len(changed) != 1 else ''} changed",
                           MAX_EVIDENCE_SUMMARY_CHARS, scrub),
            check_type="deploy_path_context", scrub=scrub)
        ref = EvidenceRecord.create(
            kind="rule_ref", locator=f"rule:{DEPLOY_RULE_ID}",
            summary=_clean(DEPLOY_CONTRACT, MAX_EVIDENCE_SUMMARY_CHARS,
                           scrub),
            check_type="deploy_path_context", scrub=scrub)
    except ValueError:
        return NOOP                     # evidence-or-dropped
    finding = Finding(
        file=anchor_file, line=anchor_line, severity="low",
        category="maintainability",
        title=_clean(f"Change touches {len(changed)} deployment-relevant "
                     f"path{plural}", MAX_TITLE_CHARS, scrub),
        explanation=_clean(explanation, MAX_EXPLANATION_CHARS, scrub),
        suggestion=None, confidence="high", rule_id=DEPLOY_RULE_ID,
        evidence=(excerpt, ref),
    )
    source = ProvenanceSource(engine=STATIC_ENGINE_ID,
                              model=_PROVENANCE_MODEL, origin="rule")
    finding.provenance_engine = source.engine
    finding.provenance_model = source.model
    finding.provenance_agent = None
    finding.provenance_origin = source.origin
    finding.provenance_sources = (source,)
    return InfraOutcome(findings=(finding,))
