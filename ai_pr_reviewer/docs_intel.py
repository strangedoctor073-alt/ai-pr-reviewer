"""V4.6-E04 — documentation intelligence (deterministic, offline, read-only).

Answers two questions without a model: *what documentation does this
repository have* and *did this change leave it describing code that no
longer looks that way*.

* **T01** :func:`build_doc_inventory` — doc files and their structure
  (sections, code references, relative links) from the repository index.
* **T02** :func:`link_docs_to_code` — code↔doc linkage with an explicit
  confidence. Ambiguous linkage is reported as ``uncertain`` and never
  becomes a claim.
* **T03** :func:`find_doc_drift` — drift findings for a PR diff, each
  citing **both sides** (the code definition and the documentation
  location) as evidence records.
* **T04** — the exclusion and wording guarantees below, enforced by
  ``tests/test_docs_intel.py``.

Trust model. Documentation is untrusted repository content (a PR can edit
it): text taken from it is redacted (:func:`~ai_pr_reviewer.security.
redact_secrets`), fence-neutralized, single-line and bounded before it is
stored; identifiers are regex-constrained. Nothing is executed or fetched.

Privacy. Every read and every diff path goes through the non-removable
baseline (``rules.SENSITIVE_EXCLUDE_GLOBS``) plus caller exclusions. An
excluded path is never opened, never named in a finding, warning or
evidence record, and is only ever *counted*.

Wording rule (family-wide "no compliance claim"). Findings describe
drift or possible staleness in hedged terms. This module never states
that documentation is accurate, complete, up to date, verified or
compliant; absence of a finding means only "nothing was detected".
:func:`claims_compliance` is the test oracle for that rule.

Not wired into the pipeline: library surface only (no Action input, no
report field, no new finding category — :meth:`DocFinding.to_finding`
maps onto the existing ``maintainability`` category).
"""
from __future__ import annotations

import os
import posixpath
import re
from dataclasses import dataclass

from .index.limits import (cap_line, is_contained, is_excluded,
                           is_vendor_or_minified)
from .models import EvidenceRecord, Finding
from .rules import SENSITIVE_EXCLUDE_GLOBS
from .security import redact_secrets, safe_label

# ------------------------------------------------------------------ limits

MAX_DOCS = 200
MAX_DOC_BYTES = 256 * 1024
MAX_TOTAL_DOC_BYTES = 4 * 1024 * 1024
MAX_SECTIONS_PER_DOC = 300
MAX_REFS_PER_DOC = 500
MAX_CANDIDATES = 5
MAX_FINDINGS = 50
MAX_TEXT_CHARS = 120
MAX_WARNINGS = 20

DOC_LANGUAGES = ("markdown",)           # index language tag for .md / .rst
_EXTENSIONLESS_DOCS = ("readme", "contributing", "changelog", "authors", "security")

CONF_HIGH, CONF_MEDIUM, CONF_UNCERTAIN = "high", "medium", "uncertain"
LINK_LINKED, LINK_UNCERTAIN = "linked", "uncertain"

KIND_SIGNATURE_DRIFT = "doc_signature_drift"
KIND_REMOVED_SYMBOL = "doc_references_removed_symbol"
KIND_REMOVED_FILE = "doc_links_removed_file"
RULE_IDS = {KIND_SIGNATURE_DRIFT: "DOC001", KIND_REMOVED_SYMBOL: "DOC002",
            KIND_REMOVED_FILE: "DOC003"}

#: Names too generic to link on their own (no qualifier, no call shape).
COMMON_NAMES = frozenset({
    "main", "run", "get", "set", "init", "test", "setup", "close", "open", "read",
    "write", "update", "name", "value", "data", "id", "key", "list", "add", "remove",
    "start", "stop", "load", "save", "parse", "build", "create", "delete", "find",
    "check", "handle", "process", "call", "apply", "send", "help", "config", "app",
    "index", "item", "items", "result", "response", "request", "error", "log",
})

#: Phrases a finding must never contain (T04 wording rule).
BANNED_CLAIM_PHRASES = (
    "compliant", "compliance", "up to date", "up-to-date", "is accurate", "are accurate",
    "is correct", "are correct", "verified", "certified", "guarantee", "complete and",
    "fully documented", "no drift", "docs are fine", "documentation is fine",
)


def claims_compliance(text: str) -> bool:
    """True when ``text`` makes a positive accuracy/compliance claim."""
    low = text.lower()
    return any(p in low for p in BANNED_CLAIM_PHRASES)


def _clean(value, limit: int = MAX_TEXT_CHARS) -> str:
    return safe_label(redact_secrets(str(value)), limit).strip()


# ------------------------------------------------------------------ T01 model

@dataclass(frozen=True)
class DocSection:
    title: str
    level: int
    line: int


@dataclass(frozen=True)
class DocRef:
    """One code reference found in a doc."""

    kind: str               # inline | fence | link | path
    name: str               # identifier (last dotted segment) or repo path
    qualifiers: tuple[str, ...]
    args: tuple[str, ...] | None    # parsed arg/param tokens when call-shaped
    text: str               # sanitized excerpt as written (bounded)
    line: int
    section: str


@dataclass(frozen=True)
class DocFile:
    path: str
    size: int
    status: str                         # ok | too_large | unreadable | truncated
    sections: tuple[DocSection, ...] = ()
    refs: tuple[DocRef, ...] = ()


@dataclass(frozen=True)
class DocInventory:
    docs: tuple[DocFile, ...] = ()
    index_available: bool = True
    truncated: bool = False
    excluded_count: int = 0
    warnings: tuple[str, ...] = ()

    def doc(self, path: str) -> DocFile | None:
        return next((d for d in self.docs if d.path == path), None)


# ------------------------------------------------------------------ parsing

_ATX = re.compile(r"^ {0,3}(#{1,6})\s+(.+?)\s*#*\s*$")
_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})\s*([\w+#.-]*)")
_SETEXT1 = re.compile(r"^ {0,3}=+\s*$")
_SETEXT2 = re.compile(r"^ {0,3}-+\s*$")
_INLINE = re.compile(r"(`{1,2})([^`\n]{1,200}?)\1")
_LINK = re.compile(r"\[[^\]\n]{0,200}\]\(([^)\s]{1,300})(?:\s+\"[^\"]*\")?\)")
_CALL = re.compile(r"^((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\s*\(([^()]*)\)$")
_IDENT = re.compile(r"^((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)$")
_PATHY = re.compile(r"^[\w./@-]+\.[A-Za-z0-9]{1,6}$")
_FENCE_CALL = re.compile(r"(?:\bdef\s+|\bfunction\s+)?\b((?:[A-Za-z_]\w*\.)*[A-Za-z_]\w*)\s*\(([^()\n]*)\)")
_RST_UNDERLINE = re.compile(r"^([=\-~^\"'#*+`:.])\1{2,}\s*$")
_KEYWORDS = frozenset({
    "if", "for", "while", "return", "def", "class", "function", "print", "import", "from",
    "with", "assert", "lambda", "range", "len", "str", "int", "float", "bool", "list",
    "dict", "set", "tuple", "type", "isinstance", "elif", "except", "catch", "switch",
    "echo", "cd", "ls", "pip", "npm", "git", "sudo", "export", "console", "require",
})


def is_doc_path(path: str, language: str = "") -> bool:
    """Doc files: Markdown/RST (index language ``markdown``) and the
    conventional extensionless project docs (README, CONTRIBUTING…)."""
    base = posixpath.basename(path.replace("\\", "/")).lower()
    if language in DOC_LANGUAGES:
        return True
    return "." not in base and base in _EXTENSIONLESS_DOCS


def split_args(text: str) -> tuple[str, ...]:
    """Top-level comma split of a parameter/argument list (brackets and
    quotes respected). Defaults and annotations are cut off, so
    ``a: int = 3`` -> ``a``; ``*args``/``**kw`` keep their stars."""
    out: list[str] = []
    depth, cur, quote = 0, [], ""
    for ch in text:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    out.append("".join(cur))
    names = []
    for raw in out:
        tok = raw.strip()
        if not tok:
            continue
        tok = re.split(r"[:=]", tok, maxsplit=1)[0].strip()
        if tok in ("*", "/"):
            continue
        names.append(tok[:60])
    return tuple(names)


def _identifier_args(args: tuple[str, ...]) -> bool:
    """True when every token is a plain parameter name (signature-shaped),
    i.e. comparable by name — literals/expressions are call *examples*."""
    return all(re.fullmatch(r"\*{0,2}[A-Za-z_]\w*", a) for a in args)


def _rel_target(doc_path: str, target: str) -> str | None:
    t = target.partition("#")[0].partition("?")[0].strip()
    if not t or re.match(r"^[A-Za-z][A-Za-z0-9+.-]*:", t) or t.startswith(("//", "#")):
        return None
    base = posixpath.dirname(doc_path)
    norm = posixpath.normpath(posixpath.join(base, t)) if not t.startswith("/") \
        else posixpath.normpath(t.lstrip("/"))
    if norm.startswith("..") or norm in (".", ""):
        return None
    return norm


def parse_doc_text(path: str, text: str) -> DocFile:
    """Pure structural parse of one doc (never raises)."""
    sections: list[DocSection] = []
    refs: list[DocRef] = []
    status = "ok"
    try:
        lines = [cap_line(l) for l in text.splitlines()]
        in_fence, fence_mark = False, ""
        current = ""
        is_rst = path.lower().endswith(".rst")

        def add_ref(kind, name, quals, args, excerpt, lineno):
            nonlocal status
            if len(refs) >= MAX_REFS_PER_DOC:
                status = "truncated"
                return
            refs.append(DocRef(kind, name, quals, args, _clean(excerpt), lineno, current))

        for i, line in enumerate(lines, 1):
            fm = _FENCE.match(line)
            if fm:
                mark = fm.group(1)[0]
                if not in_fence:
                    in_fence, fence_mark = True, mark
                elif mark == fence_mark:
                    in_fence = False
                continue
            if in_fence:
                for m in _FENCE_CALL.finditer(line):
                    name = m.group(1)
                    last = name.split(".")[-1]
                    if last in _KEYWORDS or name.split(".")[0] in _KEYWORDS:
                        continue
                    # Only an actual signature line (def/function) is
                    # comparable by parameter name; a plain example call is
                    # linked by name but never compared (adding an optional
                    # parameter does not invalidate a call example).
                    is_sig = re.match(r"\s*(?:async\s+)?(?:def|function)\b", line) is not None
                    args = split_args(m.group(2)) if is_sig else None
                    add_ref("fence", last, tuple(name.split(".")[:-1]), args,
                            m.group(0), i)
                continue
            # headings (ATX, then setext/RST underline looking at the next line)
            h = _ATX.match(line)
            nxt = lines[i] if i < len(lines) else ""
            level = 0
            title = ""
            if h:
                level, title = len(h.group(1)), h.group(2)
            elif line.strip() and not line.startswith((" ", "\t")):
                if _SETEXT1.match(nxt):
                    level, title = 1, line.strip()
                elif _SETEXT2.match(nxt) and not line.lstrip().startswith(("-", "*", "+", ">")):
                    level, title = 2, line.strip()
                elif is_rst and _RST_UNDERLINE.match(nxt) and len(nxt.strip()) >= len(line.strip()):
                    level, title = 2, line.strip()
            if level and len(sections) < MAX_SECTIONS_PER_DOC:
                current = _clean(title)
                sections.append(DocSection(current, level, i))
                if h:
                    continue
            for m in _LINK.finditer(line):
                target = _rel_target(path, m.group(1))
                if target:
                    add_ref("link", target, (), None, m.group(1), i)
            for m in _INLINE.finditer(line):
                span = m.group(2).strip()
                call = _CALL.match(span)
                if call:
                    parts = call.group(1).split(".")
                    if parts[-1] in _KEYWORDS:
                        continue
                    add_ref("inline", parts[-1], tuple(parts[:-1]),
                            split_args(call.group(2)), span, i)
                elif _IDENT.match(span):
                    parts = span.split(".")
                    if parts[-1] in _KEYWORDS:
                        continue
                    add_ref("inline", parts[-1], tuple(parts[:-1]), None, span, i)
                elif _PATHY.match(span) and ("/" in span or "." in span):
                    target = _rel_target(path, span) if "/" in span else span
                    if target:
                        add_ref("path", target, (), None, span, i)
    except Exception:                                    # noqa: BLE001 — never raise
        return DocFile(path, len(text), "unreadable")
    return DocFile(path, len(text), status, tuple(sections), tuple(refs))


def _read_doc(root: str, rel: str, exclusions) -> tuple[str | None, str]:
    """Guarded read: baseline + exclusions, containment, size cap."""
    if is_excluded(rel, [*SENSITIVE_EXCLUDE_GLOBS, *exclusions]) or is_vendor_or_minified(rel):
        return None, "excluded"
    if not is_contained(root, rel):
        return None, "unreadable"
    try:
        with open(os.path.join(root, rel), "rb") as fh:
            data = fh.read(MAX_DOC_BYTES + 1)
    except OSError:
        return None, "unreadable"
    if len(data) > MAX_DOC_BYTES:
        return None, "too_large"
    try:
        return data.decode("utf-8-sig"), "ok"
    except UnicodeDecodeError:
        return None, "unreadable"


def build_doc_inventory(index, *, exclusions=()) -> DocInventory:
    """T01 — inventory + structure of the docs in ``index``.

    ``index`` is a :class:`~ai_pr_reviewer.index.RepoIndex` (``None`` =>
    labelled unavailable). Read-only consumer: file bytes are read only
    through the guarded reader; no docs => empty inventory, not an error."""
    if index is None:
        return DocInventory(index_available=False, warnings=(
            "documentation analysis skipped: repository index unavailable",))
    cands = sorted(f.path for f in index.files if is_doc_path(f.path, f.language))
    truncated = len(cands) > MAX_DOCS
    docs: list[DocFile] = []
    warnings: list[str] = []
    excluded = 0
    total = 0
    for rel in cands[:MAX_DOCS]:
        if total >= MAX_TOTAL_DOC_BYTES:
            truncated = True
            warnings.append("documentation byte budget reached — remaining docs not read")
            break
        text, status = _read_doc(index.root, rel, exclusions)
        if status == "excluded":
            excluded += 1
            continue
        if text is None:
            docs.append(DocFile(rel, 0, status))
            continue
        total += len(text)
        docs.append(parse_doc_text(rel, text))
    if truncated and len(cands) > MAX_DOCS:
        warnings.append(f"doc cap ({MAX_DOCS}) reached — remaining docs not inventoried")
    if index.budget_state != "ok":
        truncated = True
        warnings.append("repository index is partial — documentation inventory may be incomplete")
    return DocInventory(tuple(docs), True, truncated, excluded, tuple(warnings[:MAX_WARNINGS]))


# ------------------------------------------------------------------ T02 linkage

@dataclass(frozen=True)
class DocLink:
    ref: DocRef
    doc_path: str
    status: str                     # linked | uncertain
    confidence: str                 # high | medium | uncertain
    code_path: str = ""             # set when status == linked
    code_line: int | None = None
    candidates: tuple[tuple[str, int], ...] = ()    # uncertain: where it *might* be
    reason: str = ""


@dataclass(frozen=True)
class LinkageReport:
    links: tuple[DocLink, ...] = ()
    unlinked_count: int = 0         # refs matching nothing — counted, never reported

    def linked(self) -> tuple[DocLink, ...]:
        return tuple(l for l in self.links if l.status == LINK_LINKED)

    def uncertain(self) -> tuple[DocLink, ...]:
        return tuple(l for l in self.links if l.status == LINK_UNCERTAIN)


def _distinctive(name: str) -> bool:
    return ("_" in name or len(name) >= 8
            or (any(c.isupper() for c in name) and any(c.islower() for c in name)))


def link_docs_to_code(inventory: DocInventory, index, *, exclusions=()) -> LinkageReport:
    """T02 — link doc references to indexed code with explicit confidence.

    Rules (deterministic, in order):

    * path/link refs: ``high`` when the target is an indexed file, else
      unlinked;
    * identifier refs: exactly one defining symbol in the index and either
      a call shape, a qualifier, or a distinctive name => ``high``; a
      short/plain name => ``medium``; a name from :data:`COMMON_NAMES`
      without call shape/qualifier => ``uncertain`` (no claim);
    * a dotted qualifier that names exactly one candidate's module or
      class narrows the candidates;
    * more than one candidate left => ``uncertain`` with up to
      :data:`MAX_CANDIDATES` locations listed — never a claim.

    A partial index (budget exhausted) caps every ``high`` at ``medium``.

    Files excluded by the privacy baseline (or ``exclusions``) are dropped
    here even if the supplied index still lists them, so an excluded path
    can never become a link target or a listed candidate."""
    if index is None or not inventory.docs:
        return LinkageReport()
    patterns = [*SENSITIVE_EXCLUDE_GLOBS, *exclusions]
    visible = [f for f in index.files if not is_excluded(f.path, patterns)]
    paths = {f.path for f in visible}
    by_name: dict[str, list[tuple[str, int]]] = {}
    classes: dict[str, set[str]] = {}
    for f in visible:
        for s in f.symbols:
            if s.kind in ("function", "class", "type"):
                by_name.setdefault(s.name, []).append((f.path, s.line))
            if s.kind in ("class", "type"):
                classes.setdefault(f.path, set()).add(s.name)
    partial = index.budget_state != "ok"
    links: list[DocLink] = []
    unlinked = 0

    def cap(conf: str) -> str:
        return CONF_MEDIUM if (partial and conf == CONF_HIGH) else conf

    for doc in inventory.docs:
        for ref in doc.refs:
            if ref.kind in ("link", "path"):
                if ref.name in paths:
                    links.append(DocLink(ref, doc.path, LINK_LINKED, cap(CONF_HIGH),
                                         ref.name, 1, reason="path exists in the index"))
                else:
                    unlinked += 1
                continue
            cands = by_name.get(ref.name, [])
            if not cands:
                unlinked += 1
                continue
            narrowed = list(cands)
            if len(cands) > 1 and ref.qualifiers:
                hit = [c for c in cands
                       if any(q == posixpath.splitext(posixpath.basename(c[0]))[0]
                              or q in classes.get(c[0], ()) for q in ref.qualifiers)]
                if len(hit) == 1:
                    narrowed = hit
            if len(narrowed) > 1:
                links.append(DocLink(
                    ref, doc.path, LINK_UNCERTAIN, CONF_UNCERTAIN,
                    candidates=tuple(sorted(narrowed)[:MAX_CANDIDATES]),
                    reason=f"{len(narrowed)} definitions share this name"))
                continue
            path, line = narrowed[0]
            callish = ref.args is not None or ref.kind == "fence"   # call shape
            if ref.name in COMMON_NAMES and not callish and not ref.qualifiers:
                links.append(DocLink(ref, doc.path, LINK_UNCERTAIN, CONF_UNCERTAIN,
                                     candidates=((path, line),),
                                     reason="name is too generic to link without context"))
                continue
            conf = CONF_HIGH if (callish or ref.qualifiers or _distinctive(ref.name)) \
                else CONF_MEDIUM
            links.append(DocLink(ref, doc.path, LINK_LINKED, cap(conf), path, line,
                                 reason="single matching definition in the index"))
    links.sort(key=lambda l: (l.doc_path, l.ref.line, l.ref.kind, l.ref.name))
    return LinkageReport(tuple(links), unlinked)


# ------------------------------------------------------------------ T03 drift

_PY_DEF = re.compile(r"^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
_JS_DEF = re.compile(r"^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*"
                     r"([A-Za-z_$][\w$]*)\s*\(([^)]*)\)")
_JS_ARROW = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                       r"(?:async\s*)?\(([^)]*)\)\s*=>")
_DEF_LANGS = {"python": (_PY_DEF,), "javascript": (_JS_DEF, _JS_ARROW),
              "typescript": (_JS_DEF, _JS_ARROW)}
_SKIP_PARAMS = frozenset({"self", "cls"})


def _def_in(line: str, language: str):
    for rx in _DEF_LANGS.get(language, ()):
        m = rx.match(cap_line(line))
        if m:
            params = tuple(p for p in split_args(m.group(2)) if p not in _SKIP_PARAMS)
            return m.group(1), params
    return None


@dataclass(frozen=True)
class DocFinding:
    kind: str
    severity: str                   # info | low (never higher: docs are advisory)
    confidence: str                 # high | medium | low
    title: str
    explanation: str
    doc_path: str
    doc_line: int
    code_path: str
    code_line: int | None           # line in the NEW file when the code still exists
    evidence: tuple[EvidenceRecord, ...] = ()

    @property
    def rule_id(self) -> str:
        return RULE_IDS[self.kind]

    def to_finding(self) -> Finding:
        """Map onto the existing report schema (category ``maintainability``;
        no new category, no new key). Not called by the pipeline."""
        return Finding(
            file=self.code_path, line=self.code_line, severity=self.severity,
            category="maintainability", title=self.title,
            explanation=self.explanation, confidence=self.confidence,
            rule_id=self.rule_id, evidence=self.evidence)


@dataclass(frozen=True)
class DriftReport:
    findings: tuple[DocFinding, ...] = ()
    uncertain_skipped: int = 0      # uncertain links: counted, never claimed
    excluded_count: int = 0
    warnings: tuple[str, ...] = ()
    truncated: bool = False


@dataclass(frozen=True)
class _DefChange:
    name: str
    path: str
    old_params: tuple[str, ...] | None
    new_params: tuple[str, ...] | None
    old_line: int | None
    new_line: int | None
    old_text: str
    new_text: str


def _collect_def_changes(file_diffs, language_of, patterns) -> tuple[list[_DefChange], list[tuple], int]:
    """Definition changes per file plus removed/renamed paths."""
    changes: list[_DefChange] = []
    gone: list[tuple[str, str, bool]] = []      # (old_path, new_path, deleted)
    excluded = 0
    for fd in file_diffs or ():
        try:
            new_p = (getattr(fd, "new_path", "") or "").replace("\\", "/")
            old_p = (getattr(fd, "old_path", "") or "").replace("\\", "/")
            path = new_p if new_p and new_p != "/dev/null" else old_p
            if is_excluded(path, patterns) or is_excluded(old_p, patterns):
                excluded += 1
                continue
            if getattr(fd, "is_binary", False):
                continue
            if getattr(fd, "is_deleted", False) or getattr(fd, "is_rename", False):
                if old_p and old_p != new_p:
                    gone.append((old_p, new_p, bool(getattr(fd, "is_deleted", False))))
            lang = language_of(old_p or path)
            if lang not in _DEF_LANGS:
                continue
            removed: dict[str, list] = {}
            added: dict[str, list] = {}
            for hunk in fd.hunks:
                for hl in hunk.lines:
                    if hl.tag not in ("+", "-"):
                        continue
                    d = _def_in(hl.text, lang)
                    if d is None:
                        continue
                    (removed if hl.tag == "-" else added).setdefault(d[0], []).append(
                        (d[1], hl.old_no if hl.tag == "-" else hl.new_no, hl.text))
            for name in sorted(set(removed) | set(added)):
                r, a = removed.get(name, []), added.get(name, [])
                if len(r) > 1 or len(a) > 1:
                    continue                     # overloads/duplicates: ambiguous, no claim
                changes.append(_DefChange(
                    name, old_p or path,
                    r[0][0] if r else None, a[0][0] if a else None,
                    r[0][1] if r else None, a[0][1] if a else None,
                    _clean(r[0][2].strip()) if r else "", _clean(a[0][2].strip()) if a else ""))
        except Exception:                            # noqa: BLE001
            continue
    return changes, gone, excluded


def _touched_old_lines(file_diffs, doc_path: str) -> set[int]:
    out: set[int] = set()
    for fd in file_diffs or ():
        if (getattr(fd, "old_path", "") or getattr(fd, "new_path", "")) .replace("\\", "/") == doc_path \
                or (getattr(fd, "new_path", "") or "").replace("\\", "/") == doc_path:
            for h in fd.hunks:
                out.update(hl.old_no for hl in h.lines if hl.tag == "-" and hl.old_no)
    return out


def _ev(kind: str, locator: str, summary: str, check: str):
    try:
        return EvidenceRecord.create(kind=kind, locator=locator, summary=summary,
                                     check_type=check)
    except ValueError:
        return None


def find_doc_drift(inventory: DocInventory, linkage: LinkageReport, index,
                   file_diffs, *, exclusions=()) -> DriftReport:
    """T03 — doc findings for the PR in ``file_diffs`` (parsed unified diff).

    Reports only changes this PR *introduces*: a documented signature that
    matched the old definition and no longer matches the new one, a
    documented symbol whose definition the diff removes, or a documented
    link to a file the diff deletes/renames. A reference the PR itself
    edits is skipped. Uncertain links never produce a finding. Findings
    cite the code side and the doc side as separate evidence records."""
    if index is None or not inventory.docs or not file_diffs:
        return DriftReport()
    patterns = [*SENSITIVE_EXCLUDE_GLOBS, *exclusions]
    lang = {f.path: f.language for f in index.files}
    from .index.inventory import detect_language
    language_of = lambda p: lang.get(p) or detect_language(p)       # noqa: E731
    changes, gone, excluded = _collect_def_changes(file_diffs, language_of, patterns)
    by_key = {(c.path, c.name): c for c in changes}
    findings: list[DocFinding] = []
    uncertain = 0
    seen: set[tuple] = set()

    for link in linkage.links:
        if link.status != LINK_LINKED:
            uncertain += 1
            continue
        if is_excluded(link.doc_path, patterns) or is_excluded(link.code_path, patterns):
            continue
        ref = link.ref
        touched = _touched_old_lines(file_diffs, link.doc_path)
        if ref.line in touched:
            continue                                  # this PR edits that doc line
        doc_loc = f"{link.doc_path}:{ref.line}"

        if ref.kind in ("link", "path"):
            for old_p, new_p, deleted in gone:
                if old_p != link.code_path:
                    continue
                key = (KIND_REMOVED_FILE, link.doc_path, ref.line, old_p)
                if key in seen:
                    continue
                seen.add(key)
                what = "deletes" if deleted else f"moves it to a different path"
                findings.append(DocFinding(
                    KIND_REMOVED_FILE, "low", "high",
                    "Documentation links to a file this change removes or moves",
                    f"{doc_loc} points to a file that this change {what}. The "
                    f"documentation was not changed at that location, so the "
                    f"link may no longer resolve.",
                    link.doc_path, ref.line, old_p, None,
                    tuple(e for e in (
                        _ev("file_excerpt", f"{old_p}:1",
                            f"file {'deleted' if deleted else 'renamed'} by this change",
                            "doc_drift_code"),
                        _ev("file_excerpt", doc_loc, f"doc reference: {ref.text}",
                            "doc_drift_doc")) if e)))
            continue

        change = by_key.get((link.code_path, ref.name))
        if change is None:
            continue
        removed_def = change.old_params is not None and change.new_params is None
        if removed_def:
            key = (KIND_REMOVED_SYMBOL, link.doc_path, ref.line, ref.name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(DocFinding(
                KIND_REMOVED_SYMBOL, "low", _conf3(link.confidence),
                f"Documentation references '{ref.name}', whose definition this change removes",
                f"{doc_loc} refers to '{ref.name}'. This change removes its definition "
                f"from {link.code_path}; if it was renamed or moved, the documentation "
                f"may still use the old name. Linkage confidence: {link.confidence}.",
                link.doc_path, ref.line, link.code_path, None,
                tuple(e for e in (
                    _ev("symbol_def", f"{link.code_path}:{change.old_line or 1}",
                        f"removed definition: {change.old_text}", "doc_drift_code"),
                    _ev("file_excerpt", doc_loc, f"doc reference: {ref.text}",
                        "doc_drift_doc")) if e)))
            continue
        # signature drift: only for signature-shaped doc refs that matched the OLD def
        if change.old_params is None or change.new_params is None \
                or ref.args is None or not _identifier_args(ref.args):
            continue
        doc_params = tuple(p for p in ref.args if p not in _SKIP_PARAMS)
        if doc_params == change.old_params and doc_params != change.new_params:
            key = (KIND_SIGNATURE_DRIFT, link.doc_path, ref.line, ref.name)
            if key in seen:
                continue
            seen.add(key)
            findings.append(DocFinding(
                KIND_SIGNATURE_DRIFT, "low", _conf3(link.confidence),
                f"Documentation may not match the changed signature of '{ref.name}'",
                f"{doc_loc} shows parameters ({', '.join(doc_params)}), which matched "
                f"the definition before this change. The definition at "
                f"{link.code_path} now takes ({', '.join(change.new_params)}), and the "
                f"documentation was not changed at that location. "
                f"Linkage confidence: {link.confidence}.",
                link.doc_path, ref.line, link.code_path, change.new_line,
                tuple(e for e in (
                    _ev("symbol_def", f"{link.code_path}:{change.new_line or 1}",
                        f"new definition: {change.new_text}", "doc_drift_code"),
                    _ev("file_excerpt", doc_loc, f"doc reference: {ref.text}",
                        "doc_drift_doc")) if e)))

    findings.sort(key=lambda f: (f.doc_path, f.doc_line, f.kind, f.code_path))
    truncated = len(findings) > MAX_FINDINGS
    return DriftReport(tuple(findings[:MAX_FINDINGS]), uncertain, excluded,
                       (), truncated)


def _conf3(link_confidence: str) -> str:
    """Finding confidence from link confidence (``uncertain`` never gets here)."""
    return {CONF_HIGH: "high", CONF_MEDIUM: "medium"}.get(link_confidence, "low")
