"""V4.2-E06-T01 — deterministic dependency-manifest parsers.

Ecosystems covered (explicit, closed list — adding one is a contract
change, not an accident of whatever file shows up):

* ``pip`` — ``requirements*.txt`` and ``requirements/*.txt`` style files;
* ``npm`` — ``package.json``.

Everything here is deterministic and read-only: no model, no network, no
execution, no ``pip``/``npm`` invocation, no ``-r`` include following. A
manifest is *parsed*, never interpreted.

Trust model. Manifest content is untrusted repository content (a PR can
edit it). The parsers therefore:

* never raise on hostile input — every failure degrades to a labelled
  :class:`ManifestResult` (``malformed`` / ``too_large`` / ``unreadable`` /
  ``excluded``);
* never echo raw manifest text into warnings (warnings carry a line number
  and a fixed reason only);
* redact secrets and strip URL userinfo from every stored specifier;
* bound every dimension (bytes, line length, dependency count, warnings).

Privacy. :func:`read_manifest` re-applies the non-removable privacy
baseline (``rules.SENSITIVE_EXCLUDE_GLOBS``) on top of whatever
exclusions the caller passes, so a caller that forgets the policy list
still cannot read an excluded path. An excluded path yields a result with
an *empty* ``path`` — the excluded name is never carried forward.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

from ..index.limits import (cap_line, is_contained, is_excluded,
                            is_vendor_or_minified)
from ..rules import SENSITIVE_EXCLUDE_GLOBS
from ..security import redact_secrets

#: Closed ecosystem list (T01 exit criterion: "ecosystem coverage stated
#: explicitly").
SUPPORTED_ECOSYSTEMS = ("pip", "npm")

MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFESTS = 50
MAX_DEPENDENCIES_PER_MANIFEST = 2_000
MAX_WARNINGS_PER_MANIFEST = 10
MAX_NAME_CHARS = 214            # npm's own package-name ceiling
MAX_SPEC_CHARS = 200
MAX_MARKER_CHARS = 120
MAX_CONTINUATION_LINES = 50
MAX_LOGICAL_LINE_CHARS = 4_000

STATUS_OK = "ok"
STATUS_PARTIAL = "partial"        # some entries skipped, each with a warning
STATUS_MALFORMED = "malformed"    # nothing usable
STATUS_TOO_LARGE = "too_large"
STATUS_UNREADABLE = "unreadable"
STATUS_EXCLUDED = "excluded"      # privacy baseline / vendor path — never read

SCOPES = ("runtime", "dev", "optional", "peer")
SOURCES = ("registry", "url", "vcs", "path", "alias")


@dataclass(frozen=True)
class Dependency:
    """One declared dependency with manifest+line evidence coordinates."""

    ecosystem: str
    name: str                   # pip: PEP 503 normalized; npm: as declared
    spec: str                   # constraint as declared (redacted, bounded)
    scope: str                  # one of SCOPES
    source: str                 # one of SOURCES
    manifest: str               # repository-relative manifest path
    line: int | None            # 1-based line in the manifest (None: unknown)
    extras: tuple[str, ...] = ()
    marker: str = ""            # pip environment marker, if any

    @property
    def pinned(self) -> bool:
        """True for an exact registry pin (``==1.2.3`` / npm ``1.2.3``)."""
        if self.source != "registry" or not self.spec:
            return False
        if self.ecosystem == "pip":
            return bool(re.fullmatch(r"===?[A-Za-z0-9.+!_-]+", self.spec))
        return bool(re.fullmatch(r"=?v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?",
                                 self.spec))

    @property
    def key(self) -> tuple[str, str, str, str]:
        """Identity used by diff-aware change detection."""
        return (self.manifest, self.ecosystem, self.name, self.scope)


@dataclass(frozen=True)
class ManifestResult:
    """Outcome of parsing one manifest (never raises, always labelled)."""

    path: str
    ecosystem: str
    status: str
    dependencies: tuple[Dependency, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def usable(self) -> bool:
        return self.status in (STATUS_OK, STATUS_PARTIAL)


@dataclass(frozen=True)
class DependencySnapshot:
    """All manifests of one run. ``index_available`` False => the index
    could not be built, so nothing was inspected (labelled, not an error)."""

    manifests: tuple[ManifestResult, ...] = ()
    index_available: bool = True
    truncated: bool = False
    excluded_count: int = 0     # a count only — excluded names never surface
    warnings: tuple[str, ...] = ()

    @property
    def dependencies(self) -> tuple[Dependency, ...]:
        return tuple(d for m in self.manifests for d in m.dependencies)


# ------------------------------------------------------------- discovery

def manifest_ecosystem(relpath: str) -> str | None:
    """Ecosystem for a manifest path, or ``None`` when it is not one."""
    norm = relpath.replace("\\", "/")
    parts = [p for p in norm.split("/") if p]
    if not parts:
        return None
    base = parts[-1].lower()
    if base == "package.json":
        return "npm"
    if base.endswith(".txt"):
        stem = base[:-4]
        if stem == "requirements" or stem.startswith(("requirements-", "requirements_")) \
                or stem.endswith(("-requirements", "_requirements")):
            return "pip"
        if len(parts) >= 2 and parts[-2].lower() in ("requirements", "reqs"):
            return "pip"
    return None


def discover_manifests(paths) -> list[str]:
    """Manifest paths among ``paths`` (sorted, deduplicated, capped).

    ``paths`` should come from the repository index, which already applies
    the privacy baseline, vendor skips and containment."""
    found = sorted({p.replace("\\", "/") for p in paths
                    if manifest_ecosystem(p) is not None})
    return found[:MAX_MANIFESTS]


# ----------------------------------------------------------- shared helpers

_USERINFO = re.compile(r"(?<=://)[^/@\s]+@")


def _clean_spec(text: str, limit: int = MAX_SPEC_CHARS) -> str:
    """Redacted, userinfo-stripped, single-line, bounded specifier text."""
    text = _USERINFO.sub("", text)
    text = redact_secrets(text)
    text = " ".join(text.split())
    return text[:limit]


def _source_of(spec: str) -> str:
    low = spec.lower()
    if low.startswith(("git+", "hg+", "svn+", "bzr+", "git://", "git@",
                       "github:", "gitlab:", "bitbucket:")):
        return "vcs"
    if low.startswith(("http://", "https://")):
        return "url"
    if low.startswith(("file:", "link:", "./", "../", "/", "~")) \
            or re.match(r"^[A-Za-z]:[\\/]", spec):
        return "path"
    return "registry"


class _Warn:
    """Bounded warning collector (one loud overflow line, never a flood)."""

    def __init__(self) -> None:
        self.items: list[str] = []
        self.dropped = 0

    def add(self, message: str) -> None:
        if len(self.items) < MAX_WARNINGS_PER_MANIFEST:
            self.items.append(message)
        else:
            self.dropped += 1

    def result(self) -> tuple[str, ...]:
        if self.dropped:
            return (*self.items, f"(+{self.dropped} more warning(s) suppressed)")
        return tuple(self.items)


# --------------------------------------------------------------------- pip

_PIP_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")
_PIP_CLAUSE = re.compile(r"^(?:===|==|~=|!=|<=|>=|<|>)[A-Za-z0-9.*+!_-]+$")
_PIP_COMMENT = re.compile(r"(^|\s)#.*$")
_PIP_INCLUDE_OPTS = ("-r", "--requirement", "-c", "--constraint")


def normalize_pip_name(name: str) -> str:
    """PEP 503 normalization (``Foo_Bar.baz`` -> ``foo-bar-baz``)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _logical_pip_lines(text: str) -> list[tuple[int, str]]:
    """``(first_lineno, joined_text)`` per logical line, honouring ``\\``
    continuations within explicit bounds."""
    out: list[tuple[int, str]] = []
    raw = text.splitlines()
    i = 0
    while i < len(raw):
        start = i + 1
        buf = cap_line(raw[i])
        joined = 0
        while buf.rstrip().endswith("\\") and i + 1 < len(raw) \
                and joined < MAX_CONTINUATION_LINES \
                and len(buf) < MAX_LOGICAL_LINE_CHARS:
            buf = buf.rstrip()[:-1] + " " + cap_line(raw[i + 1])
            i += 1
            joined += 1
        out.append((start, buf[:MAX_LOGICAL_LINE_CHARS]))
        i += 1
    return out


def _parse_pip_requirement(body: str) -> tuple[str, tuple[str, ...], str, str, str] | None:
    """``body`` (no comment/marker/options) -> ``(name, extras, spec,
    source, marker_placeholder)`` or ``None`` when unparseable."""
    body = body.strip()
    if not body:
        return None
    low = body.lower()
    # bare URL / VCS / path line: only usable with an #egg= fragment
    if low.startswith(("http://", "https://", "git+", "hg+", "svn+", "bzr+",
                       "file:", "./", "../", "/")):
        m = re.search(r"[#&]egg=([A-Za-z0-9][A-Za-z0-9._-]*)", body)
        if not m:
            return None
        return (normalize_pip_name(m.group(1)), (), _clean_spec(body),
                _source_of(body), "")
    m = _PIP_NAME.match(body)
    if not m:
        return None
    name = m.group(0)
    if not name[-1].isalnum():
        return None
    rest = body[m.end():].lstrip()
    extras: tuple[str, ...] = ()
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            return None
        extras = tuple(sorted({e.strip().lower()
                               for e in rest[1:close].split(",") if e.strip()}))
        rest = rest[close + 1:].lstrip()
    if rest.startswith("@"):                       # PEP 508 direct reference
        url = rest[1:].strip()
        if not url:
            return None
        return (normalize_pip_name(name), extras, _clean_spec(url),
                _source_of(url), "")
    if rest.startswith("(") and rest.endswith(")"):  # legacy "(>=1.0)" form
        rest = rest[1:-1]
    rest = rest.replace(" ", "")
    if not rest:
        return (normalize_pip_name(name), extras, "", "registry", "")
    clauses = rest.split(",")
    if not all(_PIP_CLAUSE.match(c) for c in clauses):
        return None
    return (normalize_pip_name(name), extras, ",".join(clauses), "registry", "")


def parse_pip_requirements(relpath: str, text: str) -> ManifestResult:
    """Parse one ``requirements``-style file (never raises)."""
    warn = _Warn()
    deps: list[Dependency] = []
    skipped = 0
    scope = "dev" if re.search(r"(^|[/_.-])(dev|test|tests|lint|docs)([/_.-]|$)",
                               relpath.lower()) else "runtime"
    try:
        for lineno, logical in _logical_pip_lines(text):
            line = _PIP_COMMENT.sub("", logical).strip()
            if not line:
                continue
            if line.startswith("-"):
                head = line.split(None, 1)[0].split("=", 1)[0]
                if head in _PIP_INCLUDE_OPTS:
                    warn.add(f"line {lineno}: include directive not followed "
                             f"(only this file is analysed)")
                elif head in ("-e", "--editable"):
                    target = line.split(None, 1)[1] if " " in line else ""
                    parsed = _parse_pip_requirement(target) if target else None
                    if parsed is None:
                        skipped += 1
                        warn.add(f"line {lineno}: editable requirement skipped "
                                 f"(no resolvable package name)")
                        continue
                    name, extras, spec, source, _ = parsed
                    deps.append(Dependency("pip", name, spec, scope,
                                           source if source != "registry" else "path",
                                           relpath, lineno, extras))
                # index/trusted-host/find-links style options: not dependencies
                continue
            marker = ""
            if ";" in line:
                line, _, marker = line.partition(";")
                marker = _clean_spec(marker, MAX_MARKER_CHARS)
            cut = re.search(r"\s--[A-Za-z]", line)
            if cut:
                line = line[:cut.start()]
            parsed = _parse_pip_requirement(line)
            if parsed is None:
                skipped += 1
                warn.add(f"line {lineno}: unparseable requirement skipped")
                continue
            if len(deps) >= MAX_DEPENDENCIES_PER_MANIFEST:
                warn.add(f"dependency cap ({MAX_DEPENDENCIES_PER_MANIFEST}) "
                         f"reached — remaining entries ignored")
                return ManifestResult(relpath, "pip", STATUS_PARTIAL,
                                      tuple(deps), warn.result())
            name, extras, spec, source, _ = parsed
            if len(name) > MAX_NAME_CHARS:
                skipped += 1
                warn.add(f"line {lineno}: package name too long, skipped")
                continue
            deps.append(Dependency("pip", name, spec, scope, source, relpath,
                                   lineno, extras, marker))
    except Exception:                                # noqa: BLE001 — never raise
        return ManifestResult(relpath, "pip", STATUS_MALFORMED, (),
                              ("manifest could not be parsed",))
    if not deps and skipped:
        return ManifestResult(relpath, "pip", STATUS_MALFORMED, (), warn.result())
    status = STATUS_PARTIAL if skipped else STATUS_OK
    return ManifestResult(relpath, "pip", status, tuple(deps), warn.result())


# --------------------------------------------------------------------- npm

_NPM_SECTIONS = {
    "dependencies": "runtime",
    "devDependencies": "dev",
    "optionalDependencies": "optional",
    "peerDependencies": "peer",
}
_NPM_NAME = re.compile(
    r"^(?:@[A-Za-z0-9~][A-Za-z0-9._~-]*/)?[A-Za-z0-9~][A-Za-z0-9._~-]*$")


def _json_key_lines(text: str) -> dict[tuple[str, str], int]:
    """``(section, dependency) -> 1-based line`` for depth-2 keys under the
    four dependency sections, via a linear string-aware scan (``json``
    gives no positions). Last duplicate wins, matching ``json.loads``."""
    result: dict[tuple[str, str], int] = {}
    stack: list[list] = []
    line, i, n = 1, 0, len(text)
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
        elif c == '"':
            start_line, j, buf = line, i + 1, []
            while j < n and text[j] != '"':
                if text[j] == "\\":
                    buf.append(text[j:j + 2])
                    j += 2
                    continue
                if text[j] == "\n":
                    line += 1
                buf.append(text[j])
                j += 1
            i = j
            k = j + 1
            while k < n and text[k] in " \t\r\n":
                k += 1
            if k < n and text[k] == ":" and stack and stack[-1][0] == "obj":
                try:
                    key = json.loads('"' + "".join(buf) + '"')
                except ValueError:
                    key = "".join(buf)
                stack[-1][1] = key
                if (len(stack) == 2 and stack[0][0] == "obj"
                        and stack[0][1] in _NPM_SECTIONS):
                    result[(stack[0][1], key)] = start_line
        elif c == "{":
            stack.append(["obj", None])
        elif c == "[":
            stack.append(["arr", None])
        elif c in "}]" and stack:
            stack.pop()
        i += 1
    return result


def parse_package_json(relpath: str, text: str) -> ManifestResult:
    """Parse one ``package.json`` (never raises)."""
    warn = _Warn()
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        return ManifestResult(relpath, "npm", STATUS_MALFORMED, (),
                              ("manifest is not valid JSON",))
    if not isinstance(data, dict):
        return ManifestResult(relpath, "npm", STATUS_MALFORMED, (),
                              ("top-level JSON value is not an object",))
    try:
        lines = _json_key_lines(text)
    except Exception:                                # noqa: BLE001
        lines = {}
    deps: list[Dependency] = []
    skipped = 0
    for section, scope in _NPM_SECTIONS.items():
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            skipped += 1
            warn.add(f"'{section}' is not an object — ignored")
            continue
        for name, spec in block.items():
            if len(deps) >= MAX_DEPENDENCIES_PER_MANIFEST:
                warn.add(f"dependency cap ({MAX_DEPENDENCIES_PER_MANIFEST}) "
                         f"reached — remaining entries ignored")
                return ManifestResult(relpath, "npm", STATUS_PARTIAL,
                                      tuple(deps), warn.result())
            if not isinstance(name, str) or len(name) > MAX_NAME_CHARS \
                    or not _NPM_NAME.match(name):
                skipped += 1
                warn.add(f"invalid package name in '{section}' skipped")
                continue
            if not isinstance(spec, str):
                skipped += 1
                warn.add(f"non-string specifier in '{section}' skipped")
                continue
            clean = _clean_spec(spec)
            source = "alias" if clean.lower().startswith("npm:") else _source_of(clean)
            if clean.lower().startswith("workspace:"):
                source = "path"
            deps.append(Dependency("npm", name, clean, scope, source, relpath,
                                   lines.get((section, name))))
    deps.sort(key=lambda d: (d.line if d.line is not None else 10 ** 9,
                             d.scope, d.name))
    status = STATUS_PARTIAL if skipped else STATUS_OK
    return ManifestResult(relpath, "npm", status, tuple(deps), warn.result())


# ------------------------------------------------------------- entry points

def parse_manifest_text(relpath: str, text: str) -> ManifestResult:
    """Pure parse of already-read ``text`` (no I/O, no exclusion check).

    Unknown manifest names return ``malformed`` with the supported list —
    never a guess."""
    eco = manifest_ecosystem(relpath)
    if eco == "pip":
        return parse_pip_requirements(relpath, text)
    if eco == "npm":
        return parse_package_json(relpath, text)
    return ManifestResult(relpath, "unknown", STATUS_MALFORMED, (),
                          (f"unsupported manifest (supported ecosystems: "
                           f"{', '.join(SUPPORTED_ECOSYSTEMS)})",))


def _excluded_result(ecosystem: str = "") -> ManifestResult:
    return ManifestResult("", ecosystem, STATUS_EXCLUDED)


def read_manifest_text(root: str, relpath: str, *, exclusions=()):
    """Guarded read of one manifest: ``(text, failure)``.

    Exactly one of the two is ``None``. ``failure`` is a ready-made
    :class:`ManifestResult` (excluded / unreadable / too_large / malformed
    encoding / unsupported type) — callers that only need the parse use
    :func:`read_manifest`; diff-aware detection uses the text directly.

    Order matters: privacy baseline + caller exclusions + vendor skip run
    *before* containment and before any ``open()``, so an excluded file is
    never opened. The baseline is unioned in here (double enforcement)."""
    norm = relpath.replace("\\", "/").strip()
    eco = manifest_ecosystem(norm)
    if eco is None:
        return None, ManifestResult(norm, "unknown", STATUS_MALFORMED, (),
                                    ("unsupported manifest type",))
    patterns = [*SENSITIVE_EXCLUDE_GLOBS, *exclusions]
    if is_excluded(norm, patterns) or is_vendor_or_minified(norm):
        return None, _excluded_result(eco)
    if not is_contained(root, norm):
        return None, ManifestResult(norm, eco, STATUS_UNREADABLE, (),
                                    ("path rejected (outside checkout)",))
    full = os.path.join(root, norm)
    try:
        with open(full, "rb") as fh:
            data = fh.read(MAX_MANIFEST_BYTES + 1)
    except OSError:
        return None, ManifestResult(norm, eco, STATUS_UNREADABLE, (),
                                    ("manifest could not be read",))
    if len(data) > MAX_MANIFEST_BYTES:
        return None, ManifestResult(
            norm, eco, STATUS_TOO_LARGE, (),
            (f"manifest exceeds {MAX_MANIFEST_BYTES} bytes — not parsed",))
    try:
        return data.decode("utf-8-sig"), None
    except UnicodeDecodeError:
        return None, ManifestResult(norm, eco, STATUS_MALFORMED, (),
                                    ("manifest is not valid UTF-8",))


def read_manifest(root: str, relpath: str, *, exclusions=()) -> ManifestResult:
    """Read and parse ``relpath`` under ``root`` (never raises)."""
    text, failure = read_manifest_text(root, relpath, exclusions=exclusions)
    if failure is not None:
        return failure
    return parse_manifest_text(relpath.replace("\\", "/").strip(), text)


def collect_dependencies(index, *, exclusions=()) -> DependencySnapshot:
    """Parse every manifest the repository ``index`` knows about.

    ``index`` is a :class:`~ai_pr_reviewer.index.RepoIndex` (or ``None``:
    labelled ``index_available=False``, not an error). Read-only consumer
    of the index; file bytes are read only through :func:`read_manifest`."""
    if index is None:
        return DependencySnapshot(index_available=False, warnings=(
            "dependency analysis skipped: repository index unavailable",))
    candidates = discover_manifests(index.paths)
    manifests: list[ManifestResult] = []
    excluded = 0
    for rel in candidates:
        res = read_manifest(index.root, rel, exclusions=exclusions)
        if res.status == STATUS_EXCLUDED:
            excluded += 1
            continue
        manifests.append(res)
    manifests.sort(key=lambda m: m.path)
    warnings: list[str] = []
    truncated = index.budget_state != "ok"
    if truncated:
        warnings.append("repository index is partial — some manifests may be missing")
    return DependencySnapshot(tuple(manifests), True, truncated, excluded,
                              tuple(warnings))
