"""V4.2-E06-T02 — diff-aware dependency change detection.

Given the PR's parsed unified diff (``diff_parser.FileDiff`` objects) and
the checked-out **base** tree, report which dependencies a change adds,
removes, updates or moves between scopes — with manifest + line evidence.

Method: parse the manifest at base (guarded read, privacy baseline
enforced), reconstruct the head text by applying the diff hunks to the
base text, parse both with the T01 parsers and compare. Reconstruction
verifies every context/removed line against the base text; any mismatch
makes that manifest ``unverified`` (labelled, no change claims) instead of
guessing. Nothing is executed, fetched or written.

The module never quotes raw manifest text: evidence summaries are built
from the parsed, sanitized fields (and ``EvidenceRecord.create`` redacts
again).
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import EvidenceRecord
from ..rules import SENSITIVE_EXCLUDE_GLOBS
from ..index.limits import is_excluded
from .manifests import (MAX_MANIFEST_BYTES, STATUS_EXCLUDED, Dependency,
                        manifest_ecosystem, parse_manifest_text,
                        read_manifest_text)

KIND_ADDED = "added"
KIND_REMOVED = "removed"
KIND_UPDATED = "updated"
KIND_SCOPE_CHANGED = "scope_changed"
CHANGE_KINDS = (KIND_ADDED, KIND_REMOVED, KIND_UPDATED, KIND_SCOPE_CHANGED)

MAX_CHANGES = 500
MAX_PATCH_LINES = 20_000
MAX_MANIFEST_DIFFS = 50

_VERSION = re.compile(r"\d+(?:\.\d+)*")


@dataclass(frozen=True)
class DependencyChange:
    kind: str                       # one of CHANGE_KINDS
    ecosystem: str
    name: str
    manifest: str                   # head path (base path for removals)
    scope: str                      # head scope (base scope for removals)
    old_spec: str = ""
    new_spec: str = ""
    old_scope: str = ""
    old_source: str = ""
    new_source: str = ""
    direction: str = ""             # updated only: upgrade|downgrade|changed
    old_line: int | None = None     # line in the BASE revision
    new_line: int | None = None     # line in the HEAD revision
    evidence: tuple[EvidenceRecord, ...] = ()

    @property
    def source_changed(self) -> bool:
        return bool(self.old_source and self.new_source
                    and self.old_source != self.new_source)

    @property
    def locator(self) -> str:
        line = self.old_line if self.kind == KIND_REMOVED else self.new_line
        return f"{self.manifest}:{line}" if line else self.manifest


@dataclass(frozen=True)
class ChangeReport:
    changes: tuple[DependencyChange, ...] = ()
    unverified: tuple[str, ...] = ()    # manifests whose head text could not be rebuilt
    warnings: tuple[str, ...] = ()
    excluded_count: int = 0             # count only — excluded names never surface
    truncated: bool = False


# ------------------------------------------------------------- patch apply

def apply_hunks(base_text: str, hunks) -> str | None:
    """Apply parsed hunks to ``base_text``; ``None`` when anything does not
    line up (wrong context, overlapping hunks, oversize patch)."""
    base = base_text.split("\n")
    if base and base[-1] == "":
        base.pop()
    out: list[str] = []
    pos = 0
    budget = MAX_PATCH_LINES
    for hunk in hunks:
        target = hunk.old_start - 1 if hunk.old_count > 0 else hunk.old_start
        if target < pos or target > len(base):
            return None
        out.extend(base[pos:target])
        pos = target
        for hl in hunk.lines:
            budget -= 1
            if budget < 0:
                return None
            if hl.tag == "+":
                out.append(hl.text)
            elif hl.tag in (" ", "-"):
                if pos >= len(base) or base[pos].rstrip("\r") != hl.text.rstrip("\r"):
                    return None
                if hl.tag == " ":
                    out.append(base[pos])
                pos += 1
    out.extend(base[pos:])
    return "\n".join(out) + "\n"


# ------------------------------------------------------------- comparison

def _first_version(spec: str):
    m = _VERSION.search(spec)
    return tuple(int(x) for x in m.group(0).split(".")) if m else None


def _direction(old: str, new: str) -> str:
    a, b = _first_version(old), _first_version(new)
    if a is None or b is None or a == b:
        return "changed"
    return "upgrade" if b > a else "downgrade"


def _ident(d: Dependency) -> tuple[str, str, str, str]:
    return (d.ecosystem, d.name, d.scope, d.marker)


def _index(deps) -> dict:
    out: dict = {}
    for d in deps:
        out.setdefault(_ident(d), d)    # first declaration wins, deterministic
    return out


def _evidence(kind: str, d_new: Dependency | None, d_old: Dependency | None,
              change_kind: str) -> tuple[EvidenceRecord, ...]:
    d = d_new or d_old
    line = d.line
    locator = f"{d.manifest}:{line}" if line else d.manifest
    revision = "head" if d_new is not None else "base"
    if change_kind == KIND_UPDATED:
        summary = (f"{d.ecosystem} dependency '{d.name}' ({d.scope}) spec "
                   f"'{d_old.spec or '*'}' -> '{d_new.spec or '*'}'")
    elif change_kind == KIND_SCOPE_CHANGED:
        summary = (f"{d.ecosystem} dependency '{d.name}' moved "
                   f"{d_old.scope} -> {d_new.scope}")
    else:
        summary = (f"{d.ecosystem} dependency '{d.name}' ({d.scope}) {change_kind} "
                   f"with spec '{d.spec or '*'}' ({revision} revision)")
    try:
        return (EvidenceRecord.create(kind="file_excerpt", locator=locator,
                                      summary=summary,
                                      check_type="dependency_change"),)
    except ValueError:
        return ()


def compare_dependencies(base_deps, head_deps) -> list[DependencyChange]:
    """Pure comparison of two parsed dependency lists (same manifest)."""
    base, head = _index(base_deps), _index(head_deps)
    changes: list[DependencyChange] = []
    removed = {k: v for k, v in base.items() if k not in head}
    added = {k: v for k, v in head.items() if k not in base}

    # scope moves: same (ecosystem, name, marker) removed in one scope and
    # added in another — one change, not a misleading add + remove pair
    by_name_removed = {(k[0], k[1], k[3]): k for k in removed}
    for k in sorted(added):
        probe = (k[0], k[1], k[3])
        if probe in by_name_removed:
            rk = by_name_removed.pop(probe)
            o, n = removed.pop(rk), added.pop(k)
            changes.append(DependencyChange(
                KIND_SCOPE_CHANGED, n.ecosystem, n.name, n.manifest, n.scope,
                o.spec, n.spec, o.scope, o.source, n.source,
                old_line=o.line, new_line=n.line,
                evidence=_evidence("", n, o, KIND_SCOPE_CHANGED)))

    for k in sorted(added, key=lambda k: (added[k].line or 0, k)):
        n = added[k]
        changes.append(DependencyChange(
            KIND_ADDED, n.ecosystem, n.name, n.manifest, n.scope,
            new_spec=n.spec, new_source=n.source, new_line=n.line,
            evidence=_evidence("", n, None, KIND_ADDED)))
    for k in sorted(removed, key=lambda k: (removed[k].line or 0, k)):
        o = removed[k]
        changes.append(DependencyChange(
            KIND_REMOVED, o.ecosystem, o.name, o.manifest, o.scope,
            old_spec=o.spec, old_source=o.source, old_line=o.line,
            evidence=_evidence("", None, o, KIND_REMOVED)))
    for k in sorted(set(base) & set(head)):
        o, n = base[k], head[k]
        if (o.spec, o.source, o.extras) != (n.spec, n.source, n.extras):
            changes.append(DependencyChange(
                KIND_UPDATED, n.ecosystem, n.name, n.manifest, n.scope,
                o.spec, n.spec, o.scope, o.source, n.source,
                direction=_direction(o.spec, n.spec),
                old_line=o.line, new_line=n.line,
                evidence=_evidence("", n, o, KIND_UPDATED)))
    changes.sort(key=lambda c: (c.manifest, c.ecosystem, c.name, c.kind, c.scope))
    return changes


# ------------------------------------------------------------- detection

def detect_dependency_changes(root: str, file_diffs, *, exclusions=()) -> ChangeReport:
    """Dependency changes in ``file_diffs`` relative to the base tree at
    ``root``. Never raises; non-manifest files are ignored; excluded paths
    are counted, never named."""
    patterns = [*SENSITIVE_EXCLUDE_GLOBS, *exclusions]
    changes: list[DependencyChange] = []
    unverified: list[str] = []
    warnings: list[str] = []
    excluded = 0
    seen = 0
    truncated = False
    for fd in file_diffs or ():
        new_path = (getattr(fd, "new_path", "") or "").replace("\\", "/")
        old_path = (getattr(fd, "old_path", "") or "").replace("\\", "/")
        head_path = new_path if new_path and new_path != "/dev/null" else old_path
        if manifest_ecosystem(head_path) is None:
            continue
        if is_excluded(head_path, patterns) or is_excluded(old_path, patterns):
            excluded += 1
            continue
        if getattr(fd, "is_binary", False):
            continue
        seen += 1
        if seen > MAX_MANIFEST_DIFFS:
            truncated = True
            warnings.append(f"manifest-diff cap ({MAX_MANIFEST_DIFFS}) reached — "
                            f"remaining manifest changes not analysed")
            break
        try:
            is_new = bool(getattr(fd, "is_new", False))
            is_deleted = bool(getattr(fd, "is_deleted", False))
            base_path = old_path or head_path
            if is_new:
                base_text = ""
            else:
                base_text, failure = read_manifest_text(root, base_path,
                                                        exclusions=exclusions)
                if failure is not None:
                    if failure.status == STATUS_EXCLUDED:
                        excluded += 1
                    else:
                        unverified.append(head_path)
                        warnings.append(f"{head_path}: base manifest unavailable "
                                        f"({failure.status}) — changes not analysed")
                    continue
            head_text = "" if is_deleted else apply_hunks(base_text, fd.hunks)
            if head_text is None or len(head_text) > MAX_MANIFEST_BYTES:
                unverified.append(head_path)
                warnings.append(f"{head_path}: diff does not apply cleanly to the "
                                f"base revision — changes not analysed")
                continue
            base_res = parse_manifest_text(base_path, base_text) if base_text else None
            head_res = parse_manifest_text(head_path, head_text) if head_text else None
            if (base_res is not None and not base_res.usable) or \
                    (head_res is not None and not head_res.usable):
                unverified.append(head_path)
                warnings.append(f"{head_path}: manifest not parseable — "
                                f"dependency changes not analysed")
                continue
            base_deps = base_res.dependencies if base_res else ()
            head_deps = head_res.dependencies if head_res else ()
            if base_path != head_path:      # rename: compare under the head path
                base_deps = tuple(
                    Dependency(d.ecosystem, d.name, d.spec, d.scope, d.source,
                               head_path, d.line, d.extras, d.marker)
                    for d in base_deps)
            changes.extend(compare_dependencies(base_deps, head_deps))
        except Exception:                           # noqa: BLE001 — never break a review
            unverified.append(head_path)
            warnings.append(f"{head_path}: dependency analysis failed — skipped")
    if len(changes) > MAX_CHANGES:
        changes = changes[:MAX_CHANGES]
        truncated = True
        warnings.append(f"change cap ({MAX_CHANGES}) reached — list truncated")
    changes.sort(key=lambda c: (c.manifest, c.ecosystem, c.name, c.kind, c.scope))
    return ChangeReport(tuple(changes), tuple(unverified), tuple(warnings),
                        excluded, truncated)
