"""V3-E03-T01 — corpus loading with a **strict** label schema.

One directory per case (``TESTING_EVALUATION_PLAN.md`` §5.1)::

    eval/corpus/<layer>/<case-id>/case.yaml + pr.diff [+ files/]

Every field is validated before a case can run: a malformed label file
raises :class:`CorpusError` with the offending path and field — the
harness fails loudly rather than silently scoring a half-understood
expectation (a silently-dropped label would turn into a fake recall
number, which the plan forbids: "no data beats a fabricated number").

Security properties enforced here:

* referenced files must stay **inside their case directory** (no ``..``,
  no absolute paths, no symlink escape) — a corpus case can never read
  or execute anything outside its own directory;
* ``provenance`` must be ``hand-authored``/``synthetic`` — a real-PR
  provenance value is rejected outright, mechanically enforcing the
  "synthetic only, no real PR diffs" constraint;
* ``title_match`` must compile as a regex (anchored at match time, never
  executed);
* duplicate case ids fail the load (ids are the stable comparison key
  for baselines, so they must be unique).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

import yaml

from ai_pr_reviewer.models import SEVERITY_ORDER

# Layers from TESTING_EVALUATION_PLAN.md §5.1 (directory name == layer).
VALID_LAYERS = (
    "regression",
    "known-bug",
    "false-positive",
    "false-negative",
    "injection",
    "quality",
)
# "synthetic only — no real PRs": these are the only provenance values a
# case may declare; anything implying real-world origin is rejected.
VALID_PROVENANCE = ("hand-authored", "synthetic")
VALID_BUCKETS = ("reported", "below_threshold")
# Ascending severity order derived from the engine's own map (single
# source of truth — models.SEVERITY_ORDER).
SEVERITIES: tuple[str, ...] = tuple(
    sorted(SEVERITY_ORDER, key=lambda s: SEVERITY_ORDER[s]))

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

_TOP_REQUIRED = ("id", "layer", "title", "provenance", "diff", "expect")
_TOP_ALLOWED = _TOP_REQUIRED + (
    "context", "engine_matrix", "xfail", "notes", "config", "previous")
_EXPECT_KEYS = ("findings", "no_findings", "must_not_report",
                "report_order", "config_error")
_LABEL_KEYS = ("file", "line_hint", "tolerance", "category", "severity_min",
               "title_match", "bucket", "state", "reason")


class CorpusError(Exception):
    """A corpus/case file is invalid. The message names the file and field."""


# ------------------------------------------------------------------ labels
@dataclass(frozen=True)
class Label:
    """One expected finding (or one trap/benign scope entry)."""

    file: str
    line_hint: int | None = None
    tolerance: int = 0
    category: str | None = None
    severity_min: str | None = None
    title_match: str | None = None
    bucket: str = "reported"
    state: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class CaseConfig:
    """Deterministic engine settings a case pins for itself.

    Explicit by default: ``severity_threshold`` is always set *explicitly*
    so the host repository's ``.ai-pr-reviewer.yml`` policy can never
    silently change what a case measures (host-policy independence keeps
    the score a function of the corpus + code alone).
    """

    severity_threshold: str = "medium"
    max_comments: int = 20
    exclude: tuple[str, ...] = ()


@dataclass(frozen=True)
class Expect:
    findings: tuple[Label, ...] = ()
    no_findings: tuple[Label, ...] = ()
    must_not_report: tuple[Label, ...] = ()
    report_order: tuple[str, ...] = ()
    config_error: bool = False

    def __bool__(self) -> bool:
        return bool(self.findings or self.no_findings or self.must_not_report
                    or self.report_order or self.config_error)


@dataclass(frozen=True)
class Case:
    id: str
    layer: str
    title: str
    provenance: str
    diff_path: Path
    expect: Expect
    case_dir: Path
    context_files: tuple[Path, ...] = ()
    engine_matrix: tuple[str, ...] = ("static",)
    xfail: bool = False
    notes: str = ""
    config: CaseConfig = field(default_factory=CaseConfig)
    previous_findings: tuple[dict, ...] = ()


# ---------------------------------------------------------------- helpers
def _safe_join(case_dir: Path, value: object, field_name: str) -> Path:
    """Resolve ``value`` inside ``case_dir`` — refuse absolute paths,
    ``..`` traversal and anything that escapes the case directory."""
    if not isinstance(value, str) or not value.strip():
        raise CorpusError(f"{field_name} must be a non-empty relative path, "
                          f"got {value!r}")
    if value.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", value):
        raise CorpusError(f"{field_name} must be relative, got {value!r}")
    base = case_dir.resolve()
    target = (case_dir / value).resolve()
    if not target.is_relative_to(base):
        raise CorpusError(f"{field_name} escapes the case directory: {value!r}")
    return target


def _require_dict(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise CorpusError(f"{where} must be a mapping, got "
                          f"{type(value).__name__}")
    return value


def _check_enum(value: object, allowed: Sequence[str], where: str) -> str:
    if value not in allowed:
        raise CorpusError(f"{where} must be one of {tuple(allowed)}, "
                          f"got {value!r}")
    return str(value)


def _label(raw: object, where: str, *, require_reason: bool = False) -> Label:
    data = _require_dict(raw, where)
    unknown = set(data) - set(_LABEL_KEYS)
    if unknown:
        raise CorpusError(f"{where}: unknown label field(s) "
                          f"{sorted(unknown)}; allowed: {_LABEL_KEYS}")
    file = data.get("file")
    if not isinstance(file, str) or not file.strip():
        raise CorpusError(f"{where}.file must be a non-empty string")
    if file.startswith(("/", "\\")) or ".." in Path(file).parts:
        raise CorpusError(f"{where}.file must stay inside the change: {file!r}")

    def _int(key: str, default: int | None) -> int | None:
        val = data.get(key, default)
        if val is None:
            return None
        if not isinstance(val, int) or isinstance(val, bool) or val < 0:
            raise CorpusError(f"{where}.{key} must be a non-negative int, "
                              f"got {val!r}")
        return val

    line_hint = _int("line_hint", None)
    tolerance = _int("tolerance", 0) or 0
    category = data.get("category")
    if category is not None and (not isinstance(category, str)
                                 or not category.strip()):
        raise CorpusError(f"{where}.category must be a non-empty string")
    severity_min = None
    if data.get("severity_min") is not None:
        severity_min = _check_enum(data["severity_min"], SEVERITIES,
                                   f"{where}.severity_min")
    title_match = data.get("title_match")
    if title_match is not None:
        if not isinstance(title_match, str) or not title_match:
            raise CorpusError(f"{where}.title_match must be a non-empty "
                              f"regex string")
        try:
            re.compile(title_match, re.I)
        except re.error as exc:
            raise CorpusError(
                f"{where}.title_match is not a valid regex: {exc}") from exc
    bucket = _check_enum(data.get("bucket", "reported"), VALID_BUCKETS,
                         f"{where}.bucket")
    state = data.get("state")
    if state is not None and (not isinstance(state, str) or not state):
        raise CorpusError(f"{where}.state must be a non-empty string")
    reason = data.get("reason")
    if require_reason:
        if not isinstance(reason, str) or not reason.strip():
            raise CorpusError(f"{where}.reason is required for "
                              f"must_not_report entries (traps must explain "
                              f"why the content may never be reported)")
    elif reason is not None and not isinstance(reason, str):
        raise CorpusError(f"{where}.reason must be a string")
    return Label(file=file, line_hint=line_hint, tolerance=tolerance,
                 category=category, severity_min=severity_min,
                 title_match=title_match, bucket=bucket, state=state,
                 reason=reason)


def _labels(raw: object, where: str, *, require_reason: bool = False,
            ) -> tuple[Label, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise CorpusError(f"{where} must be a list of labels, got "
                          f"{type(raw).__name__}")
    return tuple(_label(item, f"{where}[{i}]",
                        require_reason=require_reason)
                 for i, item in enumerate(raw))


def _expect(raw: object) -> Expect:
    data = _require_dict(raw, "expect")
    unknown = set(data) - set(_EXPECT_KEYS)
    if unknown:
        raise CorpusError(f"expect: unknown field(s) {sorted(unknown)}; "
                          f"allowed: {_EXPECT_KEYS}")
    if "config_error" in data and not isinstance(data["config_error"], bool):
        raise CorpusError(f"expect.config_error must be a boolean, got "
                          f"{data['config_error']!r}")
    expect = Expect(
        findings=_labels(data.get("findings"), "expect.findings"),
        no_findings=_labels(data.get("no_findings"), "expect.no_findings"),
        must_not_report=_labels(data.get("must_not_report"),
                                "expect.must_not_report",
                                require_reason=True),
        report_order=_report_order(data.get("report_order")),
        config_error=bool(data.get("config_error", False)),
    )
    if not expect:
        raise CorpusError(
            "expect must declare at least one of: findings, no_findings, "
            "must_not_report, report_order, config_error — an empty "
            "expectation would score as data-less, never as 'pass'")
    return expect


def _report_order(raw: object) -> tuple[str, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list) or not all(
            isinstance(x, str) and x for x in raw):
        raise CorpusError("expect.report_order must be a list of non-empty "
                          "file paths")
    return tuple(raw)


def _config(raw: object) -> CaseConfig:
    if raw is None:
        return CaseConfig()
    data = _require_dict(raw, "config")
    unknown = set(data) - {"severity_threshold", "max_comments", "exclude"}
    if unknown:
        raise CorpusError(f"config: unknown field(s) {sorted(unknown)}")
    severity = data.get("severity_threshold", "medium")
    _check_enum(severity, SEVERITIES, "config.severity_threshold")
    max_comments = data.get("max_comments", 20)
    if (not isinstance(max_comments, int) or isinstance(max_comments, bool)
            or max_comments < 1):
        raise CorpusError(f"config.max_comments must be a positive int, "
                          f"got {max_comments!r}")
    exclude = data.get("exclude", [])
    if not isinstance(exclude, list) or not all(
            isinstance(x, str) and x for x in exclude):
        raise CorpusError("config.exclude must be a list of glob strings")
    return CaseConfig(severity_threshold=str(severity),
                      max_comments=int(max_comments),
                      exclude=tuple(exclude))


def _previous(raw: object) -> tuple[dict, ...]:
    """Seeded prior-review findings (D2 lifecycle cases)."""
    if raw is None:
        return ()
    if not isinstance(raw, list) or not raw:
        raise CorpusError("previous must be a non-empty list of finding "
                          "mappings")
    allowed = {"file", "line", "severity", "category", "title", "state",
               "explanation"}
    out: list[dict] = []
    for i, item in enumerate(raw):
        data = _require_dict(item, f"previous[{i}]")
        unknown = set(data) - allowed
        if unknown:
            raise CorpusError(f"previous[{i}]: unknown field(s) "
                              f"{sorted(unknown)}; allowed: {sorted(allowed)}")
        for key in ("file", "title"):
            if not isinstance(data.get(key), str) or not data[key]:
                raise CorpusError(f"previous[{i}].{key} must be a non-empty "
                                  f"string")
        if "severity" in data:
            _check_enum(data["severity"], SEVERITIES, f"previous[{i}].severity")
        if "state" in data and not isinstance(data["state"], str):
            raise CorpusError(f"previous[{i}].state must be a string")
        out.append(dict(data))
    return tuple(out)


# ----------------------------------------------------------------- public
def load_case(case_dir: Path) -> Case:
    """Validate and load a single case directory (loudly on any defect)."""
    case_dir = Path(case_dir)
    manifest = case_dir / "case.yaml"
    if not manifest.is_file():
        raise CorpusError(f"{case_dir}: missing case.yaml")
    try:
        raw = yaml.safe_load(manifest.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CorpusError(f"{manifest}: YAML parse error: {exc}") from exc
    data = _require_dict(raw, str(manifest))

    missing = [k for k in _TOP_REQUIRED if k not in data]
    if missing:
        raise CorpusError(f"{manifest}: missing required field(s) {missing}")
    unknown = set(data) - set(_TOP_ALLOWED)
    if unknown:
        raise CorpusError(f"{manifest}: unknown field(s) {sorted(unknown)}; "
                          f"allowed: {_TOP_ALLOWED}")

    case_id = data["id"]
    if not isinstance(case_id, str) or not _ID_RE.match(case_id):
        raise CorpusError(f"{manifest}: id must match {_ID_RE.pattern}, "
                          f"got {case_id!r}")
    layer = _check_enum(data["layer"], VALID_LAYERS, f"{manifest}: layer")
    title = data["title"]
    if not isinstance(title, str) or not title.strip():
        raise CorpusError(f"{manifest}: title must be a non-empty string")
    provenance = _check_enum(data["provenance"], VALID_PROVENANCE,
                             f"{manifest}: provenance")

    diff_path = _safe_join(case_dir, data["diff"], f"{manifest}: diff")
    if not diff_path.is_file():
        raise CorpusError(f"{manifest}: diff file not found: {data['diff']!r}")

    context_files: list[Path] = []
    context = data.get("context")
    if context is not None:
        ctx = _require_dict(context, f"{manifest}: context")
        unknown_ctx = set(ctx) - {"files"}
        if unknown_ctx:
            raise CorpusError(f"{manifest}: context: unknown field(s) "
                              f"{sorted(unknown_ctx)}")
        files = ctx.get("files", [])
        if not isinstance(files, list):
            raise CorpusError(f"{manifest}: context.files must be a list")
        for i, value in enumerate(files):
            path = _safe_join(case_dir, value,
                              f"{manifest}: context.files[{i}]")
            if not path.is_file():
                raise CorpusError(f"{manifest}: context file not found: "
                                  f"{value!r}")
            context_files.append(path)

    matrix = data.get("engine_matrix", ["static"])
    if (not isinstance(matrix, list) or not matrix
            or not all(isinstance(x, str) and x for x in matrix)):
        raise CorpusError(f"{manifest}: engine_matrix must be a non-empty "
                          f"list of engine names")
    xfail = data.get("xfail", False)
    if not isinstance(xfail, bool):
        raise CorpusError(f"{manifest}: xfail must be a boolean")
    notes = data.get("notes", "")
    if not isinstance(notes, str):
        raise CorpusError(f"{manifest}: notes must be a string")

    return Case(
        id=str(case_id), layer=layer, title=title, provenance=provenance,
        diff_path=diff_path, expect=_expect(data["expect"]),
        case_dir=case_dir.resolve(), context_files=tuple(context_files),
        engine_matrix=tuple(matrix), xfail=xfail, notes=notes,
        config=_config(data.get("config")),
        previous_findings=_previous(data.get("previous")),
    )


def load_corpus(root: Path, layers: Sequence[str] | None = None,
                ) -> tuple[Case, ...]:
    """Load every case under ``root`` (``<layer>/<case-id>/``).

    Deterministic order (layer, then case id) — the score is a function of
    the corpus, never of filesystem iteration order. Unknown layer
    directories and duplicate ids fail loudly.
    """
    root = Path(root)
    if not root.is_dir():
        raise CorpusError(f"corpus root not found: {root}")
    wanted = tuple(layers) if layers else VALID_LAYERS
    for layer in wanted:
        if layer not in VALID_LAYERS:
            raise CorpusError(f"unknown layer {layer!r}; valid: {VALID_LAYERS}")

    cases: list[Case] = []
    seen: dict[str, Path] = {}
    # A typo'd layer directory (``regresion/``) would silently never run —
    # fail loudly instead of letting a case think it was evaluated.
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if entry.name.startswith(".") or entry.name == "__pycache__":
            continue
        if not entry.is_dir():
            raise CorpusError(f"{entry}: unexpected file — the corpus root "
                              f"contains only layer directories")
        if entry.name not in VALID_LAYERS:
            raise CorpusError(f"{entry}: unknown layer directory "
                              f"{entry.name!r}; valid layers: {VALID_LAYERS}")
    for layer in wanted:
        layer_dir = root / layer
        if not layer_dir.is_dir():
            continue
        for entry in sorted(layer_dir.iterdir(), key=lambda p: p.name):
            if entry.name.startswith(".") or entry.name == "__pycache__":
                continue
            if not entry.is_dir():
                raise CorpusError(f"{entry}: unexpected file — cases are "
                                  f"directories containing case.yaml")
            case = load_case(entry)
            if case.layer != layer:
                raise CorpusError(
                    f"{entry}: case.yaml declares layer {case.layer!r} but "
                    f"lives under {layer!r} (directory and manifest must "
                    f"agree)")
            if case.id in seen:
                raise CorpusError(
                    f"duplicate case id {case.id!r}: {seen[case.id]} and "
                    f"{entry} (ids are the baseline comparison key and must "
                    f"be unique)")
            seen[case.id] = entry
            cases.append(case)
    if not cases:
        raise CorpusError(f"no cases found under {root} — an empty corpus "
                          f"would score nothing and must never pass as "
                          f"'all green'")
    return tuple(cases)
