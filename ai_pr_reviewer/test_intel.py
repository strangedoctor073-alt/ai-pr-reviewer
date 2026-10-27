"""V4.2-E03 — test intelligence over the repository index.

What exists (T01), what a change touches (T02), what is missing (T03), and
a stable evidence format for verification tier T2 (T04).

Hard rules for this module (V4.2 charter, ADR-002/004/012):

* **read-only consumer of the index** — everything is a pure function of a
  :class:`~ai_pr_reviewer.index.RepoIndex` (plus diff data); the module does
  no file, process or network I/O (``tests/test_test_intelligence.py``
  AST-scans for that) and never modifies the index;
* **deterministic, no model, zero tokens** — identical input gives
  identical output; nothing here is surfaced into a prompt;
* **honest absence** — no index => an unavailable taxonomy and no findings
  (never a crash); capped/partial inputs are labelled ``partial`` and
  downgrade confidence instead of being presented as complete;
* **privacy baseline is double-enforced** — the index already filters
  excluded paths; this module re-applies ``SENSITIVE_EXCLUDE_GLOBS`` (plus
  caller exclusions) so a hand-built or stale index can never surface a
  secret path as a test, a module or a finding;
* **never executes tests and never trusts claims about tests** (ADR-012).

Not wired into the pipeline on purpose: calling :func:`analyze_test_gaps`
from the orchestrator is a Wave-2 integration step (it would change default
output, which needs human sign-off). Nothing in this module is imported by
existing code.

Index limits that shape the answers (document, do not fix):

* the index is the **base** checkout, so symbol lines are *base* lines; a
  diff's added lines are *head* lines. Evidence locators say which
  (``path@base:N`` / ``path@head:N``);
* symbols are regex-lite with no end line: a changed line is attributed to
  the nearest preceding definition only when a *removed* line or an
  insertion strictly inside one symbol says so — otherwise it stays silent;
* JS/TS/Java/Rust test *counts* are unknown (``None``): ``it()`` calls and
  ``#[test]`` attributes are not symbols.

T04 — test evidence record format ``tev1`` (STABLE; later epics build on it)
----------------------------------------------------------------------------
A :class:`TestEvidence` is stored as an ordinary V4-E04
:class:`~ai_pr_reviewer.models.EvidenceRecord` — no new evidence kind, no new
store:

* ``kind``       = ``"test_result"``
* ``check_type`` = ``"test_evidence.v1"`` (exact match required to parse)
* ``locator``    = ``<test_path>`` or ``<test_path>::<test_name>`` (display)
* ``summary``    = one line of space-separated ``key=value`` tokens in this
  fixed order (values percent-encoded outside ``[A-Za-z0-9_./:@#+~-]``)::

      tev1 path=<p> [name=<n>] origin=<o> outcome=<x> [covers=<c1,c2,c3>]
           [covers_n=<total>] [dur_ms=<n>] [run=<ref>]

  ``origin`` is a closed set. ``static_mapping`` is derived from the index
  and is **not an observation**; ``ci_ingest`` and ``test_report`` are
  *observed* origins and may only be minted by trusted ingest code.
  ``outcome`` is ``mapped`` iff the origin is ``static_mapping``; observed
  origins carry ``passed|failed|skipped|errored``. The combination is
  enforced at construction, so a static mapping can never read as a pass.

A reader (verification tier T2) must use :func:`observed_test_evidence`,
which fails closed: wrong kind/check_type, a failed ``integrity_ok``, a
non-canonical summary, or a static origin all yield nothing. Evidence is
pipeline-owned (``Finding.from_untrusted_dict`` strips it), so model output
cannot supply a record. Bumping the grammar means a new ``tev2`` token and
``test_evidence.v2`` check_type; v1 stays parseable.
"""
from __future__ import annotations

import bisect
import posixpath
import re
from dataclasses import dataclass
from functools import cached_property
from typing import Callable, Iterable, Mapping

from .impact import _printable_path, compute_impact
from .index import IndexLimits, RepoIndex
from .index.inventory import detect_language
from .index.limits import is_excluded
from .index.symbols import extract_symbols
from .models import (MAX_EVIDENCE_PER_FINDING, MAX_EVIDENCE_SUMMARY_CHARS,
                     EvidenceRecord, Finding)
from .rules import SENSITIVE_EXCLUDE_GLOBS
from .security import redact_secrets

# ------------------------------------------------------------------ bounds
MAX_TEST_FILES = 5_000          # classified test/support files kept
MAX_LINKS = 10_000              # test -> module links kept
MAX_TEST_NAMES_PER_FILE = 50
MAX_CHANGED_FILES = 200         # changed files analysed per run
MAX_TESTS_LISTED = 10           # direct/indirect tests kept per changed file
MAX_ADDED_LINES_SCANNED = 2_000
MAX_GAP_FINDINGS = 25
DEFAULT_MAX_HOPS = 2

GAP_RULE_ID = "TIN001"
GAP_TITLE = "Changed code has no mapped test"

ROLE_TEST = "test"
ROLE_SUPPORT = "support"

BASIS_IMPORT = "import"
BASIS_NAMING = "naming"
BASIS_BOTH = "import+naming"

# Languages for which "does a test exist?" is a meaningful question here.
TESTABLE_LANGUAGES = frozenset({
    "python", "javascript", "typescript", "java", "kotlin", "csharp",
    "go", "ruby", "php", "rust",
})

_TEST_DIRS = frozenset({"test", "tests", "__tests__", "spec"})
_NAME_SKIP_DIRS = _TEST_DIRS | {"main", "src", "lib"}


def _family(language: str) -> str:
    if language in ("javascript", "typescript"):
        return "js"
    if language in ("java", "kotlin"):
        return "jvm"
    return language


# ------------------------------------------------------- path conventions
_PY_TEST = re.compile(r"^(?:test_.+|.+_test|tests?)\.py$")
_JS_TEST = re.compile(r"^.+\.(?:test|spec)\.(?:js|jsx|ts|tsx|mjs|cjs)$")
_GO_TEST = re.compile(r"^.+_test\.go$")
_JVM_TEST = re.compile(
    r"^(?:.+(?:TestCase|ITCase|Tests|Test|IT)|Test.+)\.(?:java|kt|kts|cs)$")
_RB_TEST = re.compile(r"^.+_(?:spec|test)\.rb$")
_PHP_TEST = re.compile(r"^.+Test\.php$")


def classify_path(path: str, language: str | None = None) -> str | None:
    """``"test"`` | ``"support"`` | ``None`` from the path alone.

    ``support`` = fixtures/helpers/conftest living with the tests (never
    counted as tests, never a mapping target). Works for paths that are not
    in the index (e.g. a test the PR itself adds).
    """
    p = path.replace("\\", "/").strip("/")
    parts = p.split("/")
    base, dirs = parts[-1], parts[:-1]
    lang = language or detect_language(p)
    in_test_dir = any(d in _TEST_DIRS for d in dirs)
    if lang == "python":
        if _PY_TEST.match(base):
            return ROLE_TEST
        return ROLE_SUPPORT if (base == "conftest.py" or in_test_dir) else None
    if lang in ("javascript", "typescript"):
        if _JS_TEST.match(base) or "__tests__" in dirs:
            return ROLE_TEST
        return ROLE_SUPPORT if ("__mocks__" in dirs or in_test_dir) else None
    if lang == "go":
        return ROLE_TEST if _GO_TEST.match(base) else None
    if lang in ("java", "kotlin", "csharp"):
        if _JVM_TEST.match(base):
            return ROLE_TEST
        return ROLE_SUPPORT if "test" in dirs else None
    if lang == "ruby":
        if _RB_TEST.match(base):
            return ROLE_TEST
        return ROLE_SUPPORT if base in ("spec_helper.rb", "test_helper.rb") else None
    if lang == "php":
        return ROLE_TEST if _PHP_TEST.match(base) else None
    if lang == "rust":
        return ROLE_TEST if "tests" in dirs else None
    return None


def _stem(base: str, language: str) -> str | None:
    """The module name a test file's *name* points at (``None`` = none)."""
    if language == "python":
        n = base[:-3] if base.endswith(".py") else base
        if n.startswith("test_") and len(n) > 5:
            return n[5:]
        if n.endswith("_test") and len(n) > 5:
            return n[:-5]
        return None
    if language in ("javascript", "typescript"):
        m = re.match(r"^(.+)\.(?:test|spec)\.\w+$", base)
        return m.group(1) if m else None
    if language == "go":
        return base[:-8] if base.endswith("_test.go") and len(base) > 8 else None
    if language in ("java", "kotlin", "csharp"):
        n = posixpath.splitext(base)[0]
        for suffix in ("TestCase", "ITCase", "Tests", "Test", "IT"):
            if n.endswith(suffix) and len(n) > len(suffix):
                return n[:-len(suffix)]
        if n.startswith("Test") and len(n) > 4:
            return n[4:]
        return None
    if language == "ruby":
        m = re.match(r"^(.+)_(?:spec|test)\.rb$", base)
        return m.group(1) if m else None
    if language == "php":
        return base[:-8] if base.endswith("Test.php") and len(base) > 8 else None
    if language == "rust":
        return posixpath.splitext(base)[0]
    return None


def _module_stem(base: str) -> str:
    return posixpath.splitext(base)[0]


# -------------------------------------------------------------- frameworks
_PY_FRAMEWORKS = {"pytest": "pytest", "unittest": "unittest", "nose": "nose"}
_JS_FRAMEWORKS = {
    "vitest": "vitest", "@jest/globals": "jest", "jest": "jest",
    "mocha": "mocha", "jasmine": "jasmine", "node:test": "node:test",
    "ava": "ava", "@playwright/test": "playwright", "cypress": "cypress",
}
_JVM_PREFIXES = (
    ("org.junit.jupiter", "junit5"), ("org.junit", "junit4"),
    ("org.testng", "testng"), ("kotlin.test", "kotlin.test"),
    ("io.kotest", "kotest"),
)
_REPO_HINTS = (
    (re.compile(r"^(?:pytest\.ini|conftest\.py)$"), "python", "pytest"),
    (re.compile(r"^jest\.config\.\w+$"), "js", "jest"),
    (re.compile(r"^vitest\.(?:config|workspace)\.\w+$"), "js", "vitest"),
    (re.compile(r"^\.mocharc(?:\.\w+)?$"), "js", "mocha"),
    (re.compile(r"^karma\.conf\.\w+$"), "js", "karma"),
)


def _framework(path: str, language: str, imports: Iterable[str],
               hints: Mapping[str, frozenset]) -> tuple[str, str]:
    """``(framework, basis)``; ``basis`` is import | convention |
    repo-config | unknown — never a guess dressed as a fact."""
    specs = tuple(imports)
    base = path.rsplit("/", 1)[-1]
    if language == "python":
        for spec in specs:
            fw = _PY_FRAMEWORKS.get(spec.split(".")[0])
            if fw:
                return fw, "import"
    elif language in ("javascript", "typescript"):
        for spec in specs:
            fw = _JS_FRAMEWORKS.get(spec)
            if fw:
                return fw, "import"
    elif language in ("java", "kotlin"):
        for spec in specs:
            for prefix, fw in _JVM_PREFIXES:
                if spec == prefix or spec.startswith(prefix + "."):
                    return fw, "import"
    elif language == "go":
        return "go-test", "convention"
    elif language == "ruby":
        return ("rspec" if base.endswith("_spec.rb") else "minitest"), "convention"
    elif language == "php":
        return "phpunit", "convention"
    elif language == "rust":
        return "cargo-test", "convention"
    found = hints.get(_family(language), frozenset())
    if len(found) == 1:
        return next(iter(found)), "repo-config"
    return "unknown", "unknown"


def _test_names(path: str, language: str, symbols) -> tuple[str, ...] | None:
    """Test function names where the index can see them, else ``None``."""
    fns = [s.name for s in symbols if s.kind == "function"]
    if language == "python":
        names = [n for n in fns if n.startswith("test")]
    elif language == "go":
        names = [n for n in fns if re.match(r"^Test(?:[A-Z0-9_]|$)", n)]
    elif language == "ruby" and path.endswith("_test.rb"):
        names = [n for n in fns if n.startswith("test")]
    elif language == "php":
        names = [n for n in fns if n.startswith("test")]
    else:
        return None
    return tuple(names)


# ----------------------------------------------------------- untrusted text
_NAME_RE = re.compile(r"[A-Za-z_$][A-Za-z0-9_$?!:.]{0,79}")


def _safe_name(name: str) -> str:
    return name if _NAME_RE.fullmatch(name or "") else "<unprintable name>"


def _safe_path(path: str) -> str:
    return path if _printable_path(path) else "<unprintable path>"


def _norm(path: str) -> str:
    p = (path or "").replace("\\", "/").strip()
    return p[2:] if p.startswith("./") else p


# =============================================================== T01
@dataclass(frozen=True)
class TestFile:
    """One test (or test-support) file in the taxonomy."""

    __test__ = False            # not a pytest class

    path: str
    language: str
    role: str                               # test | support
    framework: str                          # pytest | jest | go-test | ... | unknown
    framework_basis: str                    # import | convention | repo-config | unknown
    test_count: int | None = None           # None = not derivable from the index
    test_names: tuple[str, ...] = ()        # capped; names the index can see
    symbols_truncated: bool = False

    def to_dict(self) -> dict:
        return {"path": self.path, "language": self.language, "role": self.role,
                "framework": self.framework,
                "framework_basis": self.framework_basis,
                "test_count": self.test_count,
                "test_names": list(self.test_names),
                "symbols_truncated": self.symbols_truncated}


@dataclass(frozen=True)
class TestLink:
    """``test`` is mapped to ``module`` (both indexed paths)."""

    __test__ = False

    test: str
    module: str
    basis: str          # import | naming | import+naming
    confidence: str     # high (both) | medium (import) | low (naming)

    def to_dict(self) -> dict:
        return {"test": self.test, "module": self.module,
                "basis": self.basis, "confidence": self.confidence}


@dataclass(frozen=True)
class TestTaxonomy:
    """Test files, frameworks and the test -> module map of one index."""

    __test__ = False

    available: bool
    files: tuple[TestFile, ...] = ()
    links: tuple[TestLink, ...] = ()
    ambiguous: tuple[str, ...] = ()         # tests whose name matched >1 module
    partial: bool = False
    partial_reasons: tuple[str, ...] = ()

    @property
    def frameworks(self) -> tuple[str, ...]:
        return tuple(sorted({f.framework for f in self.files
                             if f.role == ROLE_TEST and f.framework != "unknown"}))

    @cached_property
    def _roles(self) -> dict[str, str]:
        return {f.path: f.role for f in self.files}

    @cached_property
    def _by_module(self) -> dict[str, tuple[TestLink, ...]]:
        out: dict[str, list[TestLink]] = {}
        for link in self.links:
            out.setdefault(link.module, []).append(link)
        return {k: tuple(v) for k, v in out.items()}

    @cached_property
    def test_families(self) -> frozenset[str]:
        return frozenset(_family(f.language) for f in self.files
                         if f.role == ROLE_TEST)

    def role(self, path: str) -> str | None:
        return self._roles.get(path)

    def links_for(self, module: str) -> tuple[TestLink, ...]:
        return self._by_module.get(module, ())

    def to_dict(self) -> dict:
        return {"available": self.available,
                "files": [f.to_dict() for f in self.files],
                "frameworks": list(self.frameworks),
                "links": [x.to_dict() for x in self.links],
                "ambiguous": list(self.ambiguous),
                "partial": self.partial,
                "partial_reasons": list(self.partial_reasons)}


def _exclusion_list(exclusions) -> tuple[str, ...]:
    return (*SENSITIVE_EXCLUDE_GLOBS, *[e for e in (exclusions or ()) if e])


def build_taxonomy(index: RepoIndex | None, *, exclusions=(),
                   max_files: int = MAX_TEST_FILES,
                   max_links: int = MAX_LINKS) -> TestTaxonomy:
    """T01 — classify the index's files and map tests to modules.

    ``index is None`` -> ``TestTaxonomy(available=False)``: no claims.
    """
    if index is None:
        return TestTaxonomy(available=False)
    excl = _exclusion_list(exclusions)
    entries = sorted((f for f in index.files if not is_excluded(f.path, excl)),
                     key=lambda f: f.path)
    reasons: list[str] = []
    if index.budget_state != "ok":
        reasons.append(f"index budget_state={index.budget_state}")

    # repo-level framework hints from config-file presence (paths only)
    hint_sets: dict[str, set[str]] = {}
    for f in entries:
        base = f.path.rsplit("/", 1)[-1]
        for pattern, fam, fw in _REPO_HINTS:
            if pattern.match(base):
                hint_sets.setdefault(fam, set()).add(fw)
    hints = {k: frozenset(v) for k, v in hint_sets.items()}

    roles: dict[str, str | None] = {
        f.path: classify_path(f.path, f.language) for f in entries}
    test_entries = [f for f in entries if roles[f.path] == ROLE_TEST]
    suite: list[TestFile] = []
    truncated_syms = 0
    for f in entries:
        role = roles[f.path]
        if role is None:
            continue
        if len(suite) >= max_files:
            reasons.append(f"test-file cap ({max_files}) reached")
            break
        fw, basis = _framework(f.path, f.language, f.imports, hints)
        names = _test_names(f.path, f.language, f.symbols) if role == ROLE_TEST else None
        if f.symbols_truncated and role == ROLE_TEST:
            truncated_syms += 1
        suite.append(TestFile(
            path=f.path, language=f.language, role=role,
            framework=fw if role == ROLE_TEST else "unknown",
            framework_basis=basis if role == ROLE_TEST else "unknown",
            test_count=None if names is None else len(names),
            test_names=() if names is None else names[:MAX_TEST_NAMES_PER_FILE],
            symbols_truncated=f.symbols_truncated))
    if truncated_syms:
        reasons.append(f"symbols truncated in {truncated_syms} test file(s)")

    # ---- links: import edges first, naming second
    by_path = {f.path: f for f in entries}
    test_paths = {f.path for f in test_entries}
    edges_from: dict[str, list[str]] = {}
    for src, dst in index.edges:
        if src in test_paths and dst in by_path and roles.get(dst) is None:
            edges_from.setdefault(src, []).append(dst)

    candidates: dict[tuple[str, str], list[str]] = {}
    for f in entries:
        if roles[f.path] is None and f.language in TESTABLE_LANGUAGES:
            candidates.setdefault(
                (_family(f.language), _module_stem(f.path.rsplit("/", 1)[-1])),
                []).append(f.path)

    flags: dict[tuple[str, str], set[str]] = {}
    ambiguous: list[str] = []
    for t in test_entries:
        for dst in edges_from.get(t.path, ()):
            flags.setdefault((t.path, dst), set()).add(BASIS_IMPORT)
        stem = _stem(t.path.rsplit("/", 1)[-1], t.language)
        if not stem:
            continue
        cands = [c for c in candidates.get((_family(t.language), stem), ())
                 if c != t.path]
        if not cands:
            continue
        if len(cands) > 1:
            tdirs = [d for d in t.path.split("/")[:-1] if d not in _NAME_SKIP_DIRS]

            def score(c: str, tdirs=tdirs) -> int:
                cdirs = [d for d in c.split("/")[:-1] if d not in _NAME_SKIP_DIRS]
                n = 0
                while n < min(len(tdirs), len(cdirs)) and tdirs[-1 - n] == cdirs[-1 - n]:
                    n += 1
                return n
            best = max(score(c) for c in cands)
            top = [c for c in cands if score(c) == best]
            if len(top) != 1:
                ambiguous.append(t.path)
                continue
            cands = top
        flags.setdefault((t.path, cands[0]), set()).add(BASIS_NAMING)

    links: list[TestLink] = []
    for (t, m) in sorted(flags):
        if len(links) >= max_links:
            reasons.append(f"link cap ({max_links}) reached")
            break
        f = flags[(t, m)]
        if len(f) == 2:
            links.append(TestLink(t, m, BASIS_BOTH, "high"))
        elif BASIS_IMPORT in f:
            links.append(TestLink(t, m, BASIS_IMPORT, "medium"))
        else:
            links.append(TestLink(t, m, BASIS_NAMING, "low"))

    return TestTaxonomy(
        available=True, files=tuple(suite), links=tuple(links),
        ambiguous=tuple(sorted(ambiguous))[:50],
        partial=bool(reasons), partial_reasons=tuple(reasons))


# =============================================================== T02
STATUS_TESTED = "tested"
STATUS_TESTED_INDIRECT = "tested_indirectly"
STATUS_CHANGED_TESTS_ONLY = "changed_tests_only"
STATUS_UNTESTED = "untested"
STATUS_NOT_IN_INDEX = "not_in_index"
STATUS_TEST_FILE = "test_file"
STATUS_NOT_APPLICABLE = "not_applicable"
STATUS_EXCLUDED = "excluded"
STATUS_UNAVAILABLE = "unavailable"

REASON_NO_TEST_FILES = "no_test_files_for_language"
REASON_NO_MAPPED_TESTS = "no_mapped_tests"


@dataclass(frozen=True)
class IndirectTest:
    """A test reached through a dependent of the changed file."""

    test: str
    via: str        # the dependent module (or importer) it was reached through
    hop: int

    def to_dict(self) -> dict:
        return {"test": self.test, "via": self.via, "hop": self.hop}


@dataclass(frozen=True)
class ChangedFileTests:
    """What the existing suite says about one changed file."""

    path: str
    status: str
    reason: str = ""
    direct: tuple[TestLink, ...] = ()
    indirect: tuple[IndirectTest, ...] = ()
    in_change: tuple[str, ...] = ()     # tests the PR itself changes for it
    direct_total: int = 0

    def to_dict(self) -> dict:
        return {"path": self.path, "status": self.status, "reason": self.reason,
                "direct": [d.to_dict() for d in self.direct],
                "indirect": [i.to_dict() for i in self.indirect],
                "in_change": list(self.in_change),
                "direct_total": self.direct_total}


@dataclass(frozen=True)
class ChangeTestMap:
    available: bool
    entries: tuple[ChangedFileTests, ...] = ()
    partial: bool = False
    partial_reasons: tuple[str, ...] = ()

    def get(self, path: str) -> ChangedFileTests | None:
        for e in self.entries:
            if e.path == path:
                return e
        return None

    def to_dict(self) -> dict:
        return {"available": self.available,
                "entries": [e.to_dict() for e in self.entries],
                "partial": self.partial,
                "partial_reasons": list(self.partial_reasons)}


def map_changes_to_tests(taxonomy: TestTaxonomy, index: RepoIndex | None,
                         changed_paths: Iterable[str], *, exclusions=(),
                         max_hops: int = DEFAULT_MAX_HOPS,
                         max_changed: int = MAX_CHANGED_FILES,
                         max_tests: int = MAX_TESTS_LISTED) -> ChangeTestMap:
    """T02 — for each changed file: existing tests, or an explicit none.

    Order of evidence: direct existing links > tests the PR itself changes
    (by naming; never a "missing test" claim while the PR adds one) >
    indirect tests through bounded import dependents > explicit ``untested``.
    """
    paths = sorted({_norm(p) for p in changed_paths if p})
    if not taxonomy.available or index is None:
        return ChangeTestMap(
            available=False,
            entries=tuple(ChangedFileTests(p, STATUS_UNAVAILABLE) for p in paths[:max_changed]))
    excl = _exclusion_list(exclusions)
    reasons = list(taxonomy.partial_reasons)
    if len(paths) > max_changed:
        reasons.append(f"changed-file cap ({max_changed}) reached; "
                       f"{len(paths) - max_changed} file(s) not analysed")
    paths = paths[:max_changed]
    by_path = {f.path: f for f in index.files}
    pr_tests = [(p, detect_language(p)) for p in paths
                if not is_excluded(p, excl)
                and classify_path(p) == ROLE_TEST]

    out: list[ChangedFileTests] = []
    for p in paths:
        if is_excluded(p, excl):
            out.append(ChangedFileTests(p, STATUS_EXCLUDED))
            continue
        lang = detect_language(p)
        role = taxonomy.role(p) or classify_path(p, lang)
        if role is not None:
            out.append(ChangedFileTests(p, STATUS_TEST_FILE))
            continue
        if lang not in TESTABLE_LANGUAGES:
            out.append(ChangedFileTests(p, STATUS_NOT_APPLICABLE))
            continue
        direct_all = taxonomy.links_for(p)
        direct = direct_all[:max_tests]
        stem = _module_stem(p.rsplit("/", 1)[-1])
        in_change = tuple(
            t for t, tl in pr_tests
            if _family(tl) == _family(lang)
            and _stem(t.rsplit("/", 1)[-1], tl) == stem)[:max_tests]
        if direct:
            out.append(ChangedFileTests(
                p, STATUS_TESTED, direct=direct, in_change=in_change,
                direct_total=len(direct_all)))
            continue
        if in_change:
            out.append(ChangedFileTests(p, STATUS_CHANGED_TESTS_ONLY,
                                        in_change=in_change))
            continue
        entry = by_path.get(p)
        if entry is None:
            out.append(ChangedFileTests(p, STATUS_NOT_IN_INDEX))
            continue
        impact = compute_impact(index, [p], max_hops=max_hops)
        if impact.truncated:
            reasons.append(f"impact traversal truncated ({impact.truncation}) for {_safe_path(p)}")
        direct_tests = {l.test for l in direct_all}
        found: dict[str, IndirectTest] = {}
        for e in impact.entries:
            if taxonomy.role(e.path) == ROLE_TEST:
                if e.hop >= 2 and e.path not in direct_tests:
                    found.setdefault(e.path, IndirectTest(e.path, e.via or "", e.hop))
                continue
            for link in taxonomy.links_for(e.path):
                if link.test in direct_tests:
                    continue
                cur = found.get(link.test)
                if cur is None or e.hop < cur.hop:
                    found[link.test] = IndirectTest(link.test, e.path, e.hop)
        indirect = tuple(sorted(found.values(), key=lambda i: (i.hop, i.test)))[:max_tests]
        if indirect:
            out.append(ChangedFileTests(p, STATUS_TESTED_INDIRECT, indirect=indirect))
            continue
        reason = (REASON_NO_TEST_FILES if _family(lang) not in taxonomy.test_families
                  else REASON_NO_MAPPED_TESTS)
        out.append(ChangedFileTests(p, STATUS_UNTESTED, reason=reason))
    uniq = tuple(dict.fromkeys(reasons))
    return ChangeTestMap(available=True, entries=tuple(out),
                         partial=bool(uniq), partial_reasons=uniq)


# =============================================================== T03
@dataclass(frozen=True)
class ChangedRegions:
    """Change data of one file in the two revision coordinate systems."""

    removed: frozenset[int] = frozenset()                 # base lines removed
    insertions: tuple[tuple[int, int], ...] = ()          # (prev, next) base lines around an added run
    added: tuple[tuple[int, str], ...] = ()               # (head line, text)
    is_new: bool = False


def changed_regions_from_diffs(files) -> dict[str, ChangedRegions]:
    """``FileDiff`` list -> per-path :class:`ChangedRegions` (duck-typed)."""
    out: dict[str, ChangedRegions] = {}
    for fd in files:
        if getattr(fd, "is_binary", False) or getattr(fd, "is_deleted", False):
            continue
        removed: set[int] = set()
        ins: list[tuple[int, int]] = []
        added: list[tuple[int, str]] = []
        for h in fd.hunks:
            lines = [l for l in h.lines if l.tag in (" ", "-", "+")]
            prev: int | None = None
            for i, l in enumerate(lines):
                if l.tag == " " and l.old_no is not None:
                    prev = l.old_no
                elif l.tag == "-" and l.old_no is not None:
                    removed.add(l.old_no)
                    prev = l.old_no
                elif l.tag == "+" and l.new_no is not None:
                    added.append((l.new_no, l.text))
                    if i + 1 >= len(lines) or lines[i + 1].tag != "+":   # end of an added run
                        nxt = lines[i + 1].old_no if i + 1 < len(lines) else None
                        if prev is not None and nxt is not None:
                            ins.append((prev, nxt))
        out[fd.path] = ChangedRegions(
            removed=frozenset(removed), insertions=tuple(ins),
            added=tuple(added), is_new=bool(getattr(fd, "is_new", False)))
    return out


@dataclass(frozen=True)
class _Changed:
    kind: str
    name: str
    line: int
    ref: str        # base | head
    reason: str     # added | signature | body


def _enclosing(symbols, lines, n: int):
    i = bisect.bisect_right(lines, n) - 1
    return symbols[i] if i >= 0 else None


def _changed_symbols(entry, regions: ChangedRegions, language: str) -> list[_Changed]:
    found: dict[str, _Changed] = {}
    signature_names: set[str] = set()
    if entry is not None and entry.symbols:
        syms = sorted(entry.symbols, key=lambda s: s.line)
        lines = [s.line for s in syms]
        for b in sorted(regions.removed):
            s = _enclosing(syms, lines, b)
            if s is None:
                continue
            reason = "signature" if s.line == b else "body"
            cur = found.get(s.name)
            if cur is None or (reason == "signature" and cur.reason != "signature"):
                found[s.name] = _Changed(s.kind, s.name, s.line, "base", reason)
            if reason == "signature":
                signature_names.add(s.name)
        for prev, nxt in regions.insertions:
            sp, sn = _enclosing(syms, lines, prev), _enclosing(syms, lines, nxt)
            if sp is not None and sp is sn and sp.name not in found:
                found[sp.name] = _Changed(sp.kind, sp.name, sp.line, "base", "body")
    limits = IndexLimits()
    for n, text in regions.added[:MAX_ADDED_LINES_SCANNED]:
        syms, _imports, _trunc = extract_symbols("added", language, text, limits)
        for kind, name, _ln in syms:
            if name in signature_names or name in found:
                continue
            found[name] = _Changed(kind, name, n, "head", "added")
    order = {"signature": 0, "added": 1, "body": 2}
    return sorted(found.values(), key=lambda c: (order[c.reason], c.line, c.name))


def coverage_gap_findings(taxonomy: TestTaxonomy, index: RepoIndex | None,
                          change_map: ChangeTestMap,
                          regions: Mapping[str, ChangedRegions], *,
                          base_ref: str = "base", head_ref: str = "head",
                          scrub: Callable[[str], str] | None = None,
                          max_findings: int = MAX_GAP_FINDINGS) -> list[Finding]:
    """T03 — one ``testing`` finding per changed file the suite does not
    cover, citing the changed *symbols* as ``symbol_def`` evidence.

    Silent (``[]``) without an index; silent for files with no attributable
    symbol. Never recommends disabling or weakening a test (``suggestion``
    is always ``None``). Findings are redacted/sanitised and carry
    pipeline-owned evidence only.
    """
    if index is None or not taxonomy.available or not change_map.available:
        return []
    by_path = {f.path: f for f in index.files}
    partial = bool(change_map.partial or taxonomy.partial)
    base_ref, head_ref = _ref(base_ref, "base"), _ref(head_ref, "head")
    out: list[Finding] = []
    for ent in change_map.entries:
        if len(out) >= max_findings:
            break
        reg = regions.get(ent.path)
        if reg is None:
            continue
        new_file = ent.status == STATUS_NOT_IN_INDEX and reg.is_new
        if ent.status != STATUS_UNTESTED and not new_file:
            continue
        lang = detect_language(ent.path)
        changed = _changed_symbols(by_path.get(ent.path), reg, lang)
        if not changed:
            continue
        shown = changed[:MAX_EVIDENCE_PER_FINDING - 1]
        records = [EvidenceRecord.create(
            kind="rule_ref", locator=f"rule:{GAP_RULE_ID}",
            summary=f"{GAP_RULE_ID}: {GAP_TITLE}", check_type="testing",
            scrub=scrub)]
        for c in shown:
            verb = {"added": "added by the diff", "signature":
                    "definition changed by the diff",
                    "body": "body changed by the diff"}[c.reason]
            records.append(EvidenceRecord.create(
                kind="symbol_def",
                locator=f"{ent.path}@{base_ref if c.ref == 'base' else head_ref}:{c.line}",
                summary=f"{c.kind} {_safe_name(c.name)}: {verb}; no mapped test",
                check_type="test_gap", scrub=scrub))
        strong = any(c.reason in ("added", "signature") for c in changed)
        confident = strong and not partial and not new_file
        names = ", ".join(_safe_name(c.name) for c in changed[:5])
        more = f" (+{len(changed) - 5} more)" if len(changed) > 5 else ""
        fws = ", ".join(taxonomy.frameworks) or "no recognised framework"
        scope = ("This is a new file, so no existing test can cover it."
                 if new_file else
                 f"No test among {sum(1 for f in taxonomy.files if f.role == ROLE_TEST)} "
                 f"indexed test file(s) ({fws}) maps to {_safe_path(ent.path)} by "
                 f"import or naming convention, including dependents within "
                 f"{DEFAULT_MAX_HOPS} hop(s).")
        text = (f"{scope} Changed symbols without a mapped test: {names}{more}. "
                "This is a static inference from the repository index: tests "
                "were not executed and a test this analysis cannot see may "
                "exist. Consider adding or extending a test that exercises "
                "these symbols.")
        if partial:
            text += (" Partial analysis: " + "; ".join(
                (*taxonomy.partial_reasons, *change_map.partial_reasons)
                [:3]) + ". Confidence is reduced.")
        added_lines = [c.line for c in changed if c.ref == "head"]
        explanation = redact_secrets(text)
        if scrub is not None:
            explanation = scrub(explanation)
        out.append(Finding(
            file=ent.path, line=min(added_lines) if added_lines else None,
            severity="low" if confident else "info", category="testing",
            title=GAP_TITLE, explanation=explanation, suggestion=None,
            confidence="medium" if confident else "low",
            rule_id=GAP_RULE_ID, evidence=tuple(records)))
    return out


def _ref(value: str, default: str) -> str:
    v = re.sub(r"[^A-Za-z0-9_./-]", "", str(value or ""))[:60]
    return v or default


def analyze_test_gaps(index: RepoIndex | None, files, *, exclusions=(),
                      scrub: Callable[[str], str] | None = None,
                      max_hops: int = DEFAULT_MAX_HOPS) -> list[Finding]:
    """One call for T01 -> T03 over parsed ``FileDiff`` objects.

    The Wave-2 integration seam; default-off wiring is a human decision.
    """
    if index is None:
        return []
    paths = [fd.path for fd in files
             if not getattr(fd, "is_binary", False)
             and not getattr(fd, "is_deleted", False)]
    taxonomy = build_taxonomy(index, exclusions=exclusions)
    cmap = map_changes_to_tests(taxonomy, index, paths, exclusions=exclusions,
                                max_hops=max_hops)
    return coverage_gap_findings(
        taxonomy, index, cmap, changed_regions_from_diffs(files), scrub=scrub)


# =============================================================== T04
EVIDENCE_KIND = "test_result"           # existing V4-E04 kind; nothing new
EVIDENCE_CHECK_TYPE = "test_evidence.v1"
EVIDENCE_TAG = "tev1"

ORIGIN_STATIC_MAPPING = "static_mapping"
OBSERVED_ORIGINS = ("ci_ingest", "test_report")
ORIGINS = (ORIGIN_STATIC_MAPPING, *OBSERVED_ORIGINS)
OUTCOME_MAPPED = "mapped"
OBSERVED_OUTCOMES = ("passed", "failed", "skipped", "errored")

MAX_EVIDENCE_COVERS = 3
_MAX_PATH, _MAX_NAME, _MAX_COVER, _MAX_RUN = 120, 80, 80, 40
_SAFE_CHAR = re.compile(r"[A-Za-z0-9_./:@#+~-]")


def _enc(value: str) -> str:
    return "".join(c if _SAFE_CHAR.fullmatch(c)
                   else "".join(f"%{b:02X}" for b in c.encode("utf-8"))
                   for c in value)


def _dec(value: str) -> str | None:
    try:
        raw = re.sub(rb"%([0-9A-F]{2})",
                     lambda m: bytes([int(m.group(1), 16)]),
                     value.encode("ascii"))
        return raw.decode("utf-8")
    except (UnicodeError, ValueError):
        return None


@dataclass(frozen=True)
class TestEvidence:
    """One test-evidence fact in the ``tev1`` format (module docstring)."""

    __test__ = False

    test_path: str
    outcome: str
    origin: str
    test_name: str | None = None
    covers: tuple[str, ...] = ()
    covers_total: int | None = None
    duration_ms: int | None = None
    run_ref: str | None = None

    def __post_init__(self) -> None:
        if self.origin not in ORIGINS:
            raise ValueError(f"unknown test-evidence origin {self.origin!r}")
        if self.origin == ORIGIN_STATIC_MAPPING:
            if self.outcome != OUTCOME_MAPPED:
                raise ValueError("a static mapping can only have outcome 'mapped'")
            if self.run_ref is not None or self.duration_ms is not None:
                raise ValueError("a static mapping has no run or duration")
        elif self.outcome not in OBSERVED_OUTCOMES:
            raise ValueError(f"observed outcome must be one of {OBSERVED_OUTCOMES}")
        if not self.test_path or len(self.test_path) > _MAX_PATH:
            raise ValueError("test_path empty or too long")
        if self.test_name is not None and not (0 < len(self.test_name) <= _MAX_NAME):
            raise ValueError("test_name empty or too long")
        if len(self.covers) > MAX_EVIDENCE_COVERS or any(
                not c or len(c) > _MAX_COVER for c in self.covers):
            raise ValueError("covers: too many, empty or too long")
        total = self.covers_total
        if total is not None and (isinstance(total, bool) or total < len(self.covers)):
            raise ValueError("covers_total smaller than covers")
        if self.duration_ms is not None and (
                isinstance(self.duration_ms, bool)
                or not 0 <= self.duration_ms <= 86_400_000):
            raise ValueError("duration_ms out of range")
        if self.run_ref is not None and not (0 < len(self.run_ref) <= _MAX_RUN):
            raise ValueError("run_ref empty or too long")

    @property
    def observed(self) -> bool:
        return self.origin in OBSERVED_ORIGINS

    def _summary(self) -> str:
        toks = [EVIDENCE_TAG, f"path={_enc(self.test_path)}"]
        if self.test_name is not None:
            toks.append(f"name={_enc(self.test_name)}")
        toks += [f"origin={self.origin}", f"outcome={self.outcome}"]
        if self.covers:
            toks.append("covers=" + ",".join(_enc(c) for c in self.covers))
        if self.covers_total is not None and self.covers_total != len(self.covers):
            toks.append(f"covers_n={self.covers_total}")
        if self.duration_ms is not None:
            toks.append(f"dur_ms={self.duration_ms}")
        if self.run_ref is not None:
            toks.append(f"run={_enc(self.run_ref)}")
        return " ".join(toks)

    def to_record(self, scrub: Callable[[str], str] | None = None) -> EvidenceRecord:
        """Validated, redacted record. Raises ``ValueError`` when the
        summary exceeds the evidence bound or redaction altered it (a
        record that would not parse back is never emitted)."""
        summary = self._summary()
        if len(summary) > MAX_EVIDENCE_SUMMARY_CHARS:
            raise ValueError("test evidence summary exceeds the evidence bound")
        locator = self.test_path + (f"::{self.test_name}" if self.test_name else "")
        rec = EvidenceRecord.create(
            kind=EVIDENCE_KIND, locator=locator, summary=summary,
            check_type=EVIDENCE_CHECK_TYPE, scrub=scrub)
        if TestEvidence.from_record(rec) != self:
            raise ValueError("test evidence was altered by redaction or bounds")
        return rec

    @classmethod
    def from_record(cls, rec) -> "TestEvidence | None":
        """Strict, fail-closed parser; ``None`` for anything that is not a
        canonical, intact ``tev1`` record."""
        try:
            if (getattr(rec, "kind", None) != EVIDENCE_KIND
                    or getattr(rec, "check_type", None) != EVIDENCE_CHECK_TYPE
                    or not rec.integrity_ok):
                return None
            summary = rec.summary
            toks = summary.split(" ")
            if not toks or toks[0] != EVIDENCE_TAG:
                return None
            kv: dict[str, str] = {}
            for t in toks[1:]:
                key, sep, val = t.partition("=")
                if not sep or key in kv:
                    return None
                kv[key] = val
            if not {"path", "origin", "outcome"} <= kv.keys() or not kv.keys() <= {
                    "path", "name", "origin", "outcome", "covers", "covers_n",
                    "dur_ms", "run"}:
                return None

            def dec(key: str) -> str | None:
                return _dec(kv[key]) if key in kv else None
            path, name, run = dec("path"), dec("name"), dec("run")
            covers = tuple(_dec(c) for c in kv["covers"].split(",")) if "covers" in kv else ()
            if path is None or None in covers or ("name" in kv and name is None) \
                    or ("run" in kv and run is None):
                return None
            total = int(kv["covers_n"]) if "covers_n" in kv else None
            dur = int(kv["dur_ms"]) if "dur_ms" in kv else None
            obj = cls(test_path=path, outcome=kv["outcome"], origin=kv["origin"],
                      test_name=name, covers=covers, covers_total=total,
                      duration_ms=dur, run_ref=run)
            return obj if obj._summary() == summary else None
        except (ValueError, TypeError, AttributeError):
            return None


def observed_test_evidence(records: Iterable) -> tuple[TestEvidence, ...]:
    """What verification tier T2 may consume: intact, canonical, **observed**
    ``tev1`` records. Static mappings, forged or tampered records yield
    nothing. ``records`` is ``Finding.evidence`` (pipeline-owned)."""
    out = []
    for rec in records or ():
        ev = TestEvidence.from_record(rec)
        if ev is not None and ev.observed:
            out.append(ev)
    return tuple(out)


def static_mapping_evidence(entry: ChangedFileTests, *,
                            max_records: int = MAX_EVIDENCE_PER_FINDING,
                            scrub: Callable[[str], str] | None = None
                            ) -> tuple[EvidenceRecord, ...]:
    """``tev1`` records (origin ``static_mapping``, outcome ``mapped``) for the
    tests mapped to one changed file. Display/context only: not an
    observation and never eligible for T2."""
    tests = [l.test for l in entry.direct] + [i.test for i in entry.indirect] \
        + list(entry.in_change)
    out: list[EvidenceRecord] = []
    for t in dict.fromkeys(tests):
        if len(out) >= max_records:
            break
        try:
            out.append(TestEvidence(
                test_path=t, outcome=OUTCOME_MAPPED, origin=ORIGIN_STATIC_MAPPING,
                covers=(entry.path,)).to_record(scrub=scrub))
        except ValueError:
            continue        # unrepresentable (long/redacted path): omitted, not faked
    return tuple(out)


__all__ = [
    "BASIS_BOTH", "BASIS_IMPORT", "BASIS_NAMING", "ChangeTestMap",
    "ChangedFileTests", "ChangedRegions", "EVIDENCE_CHECK_TYPE",
    "EVIDENCE_KIND", "EVIDENCE_TAG", "GAP_RULE_ID", "GAP_TITLE",
    "IndirectTest", "OBSERVED_ORIGINS", "OBSERVED_OUTCOMES",
    "ORIGIN_STATIC_MAPPING", "OUTCOME_MAPPED", "ROLE_SUPPORT", "ROLE_TEST",
    "TestEvidence", "TestFile", "TestLink", "TestTaxonomy",
    "analyze_test_gaps", "build_taxonomy", "changed_regions_from_diffs",
    "classify_path", "coverage_gap_findings", "map_changes_to_tests",
    "observed_test_evidence", "static_mapping_evidence",
]
