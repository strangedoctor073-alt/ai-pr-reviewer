"""Deterministic policy evaluator (V4.2-E07-T02).

Interface reused — never re-implemented — by V4.6-E05 (infrastructure
intelligence) and V4.8-E02 (org policy), so it is deliberately small and
data-in/data-out::

    evaluate_policy(config: PolicyConfig, files: Sequence[FileDiff],
                    *, extra_excludes: Sequence[str] = ()) -> PolicyEvaluation

* Pure and deterministic: no I/O, no clock, no randomness, no network, no
  model. Same inputs -> identical ``PolicyEvaluation`` (results keep clause
  order; locations are sorted and bounded).
* Three-valued: every clause yields ``pass``, ``fail`` or ``unknown``.
  ``unknown`` means the clause could not be decided (guidance-only clause,
  or binary files that could not be inspected) — never silently ``pass``.
* Clause provenance: every :class:`ClauseResult` carries the clause id, its
  type and the config locator (:func:`clause_locator`) it came from.
* Privacy baseline, double-enforced: files matching
  ``rules.SENSITIVE_EXCLUDE_GLOBS`` are dropped *here* before any clause
  sees them, regardless of what the caller already filtered and regardless
  of what any clause's globs say. A clause can therefore never read, match
  or cite a baseline-excluded path. ``extra_excludes`` can only add.
* No remediation: the evaluator returns verdicts only. It performs no
  writes, spawns nothing and attaches no suggestions.
"""
from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Sequence

from ..diff_parser import FileDiff
from ..rules import SENSITIVE_EXCLUDE_GLOBS
from .schema import (CLAUSE_FORBID_ADDED_TEXT, CLAUSE_FORBID_CHANGE,
                     CLAUSE_GUIDANCE, CLAUSE_MAX_ADDED_LINES,
                     CLAUSE_MAX_CHANGED_FILES, CLAUSE_REQUIRE_CHANGE,
                     PolicyClause, PolicyConfig)

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_UNKNOWN = "unknown"
STATUSES = (STATUS_PASS, STATUS_FAIL, STATUS_UNKNOWN)

MAX_LOCATIONS = 5

Location = tuple[str, "int | None"]


@dataclass(frozen=True)
class ClauseResult:
    clause_id: str
    clause_type: str
    severity: str
    status: str
    detail: str
    message: str = ""
    locations: tuple[Location, ...] = ()

    @property
    def locator(self) -> str:
        return clause_locator(self.clause_id)


@dataclass(frozen=True)
class PolicyEvaluation:
    results: tuple[ClauseResult, ...] = ()

    @property
    def failures(self) -> tuple[ClauseResult, ...]:
        return tuple(r for r in self.results if r.status == STATUS_FAIL)

    def by_id(self, clause_id: str) -> ClauseResult | None:
        return next((r for r in self.results if r.clause_id == clause_id), None)


def clause_locator(clause_id: str) -> str:
    """Stable pointer to a clause in the policy file (evidence locator)."""
    return f".ai-pr-reviewer.yml#policy.clauses.{clause_id}"


def _norm(path: str) -> str:
    p = (path or "").replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.lstrip("/")


def path_matches(path: str, pattern: str) -> bool:
    """fnmatch with the repo's ``**/`` convention: ``**/x`` also matches a
    top-level ``x`` (same behaviour the privacy baseline relies on)."""
    p, pat = _norm(path), _norm(pattern)
    if fnmatch.fnmatchcase(p, pat):
        return True
    return pat.startswith("**/") and fnmatch.fnmatchcase(p, pat[3:])


def _any_match(path: str, patterns: Sequence[str]) -> bool:
    return any(path_matches(path, pat) for pat in patterns)


def _eligible(files: Sequence[FileDiff],
              extra_excludes: Sequence[str]) -> list[FileDiff]:
    """Privacy baseline first, then caller additions; sorted by path so
    evaluation order never depends on diff order."""
    out = [f for f in files
           if not _any_match(f.path, SENSITIVE_EXCLUDE_GLOBS)
           and not _any_match(f.path, extra_excludes)]
    return sorted(out, key=lambda f: _norm(f.path))


def _locs(items: Sequence[Location]) -> tuple[Location, ...]:
    return tuple(sorted(set(items), key=lambda t: (t[0], t[1] or 0)))[:MAX_LOCATIONS]


def _result(clause: PolicyClause, status: str, detail: str,
            locations: Sequence[Location] = ()) -> ClauseResult:
    return ClauseResult(clause_id=clause.id, clause_type=clause.type,
                        severity=clause.severity, status=status,
                        detail=detail, message=clause.message,
                        locations=_locs(locations))


def _in_scope(files: Sequence[FileDiff], paths: Sequence[str]) -> list[FileDiff]:
    return [f for f in files if not paths or _any_match(f.path, paths)]


def _require_change(c: PolicyClause, files: list[FileDiff]) -> ClauseResult:
    triggered = [f for f in files if _any_match(f.path, c.param("when_paths", ()))]
    if not triggered:
        return _result(c, STATUS_PASS, "not triggered: no changed file matches when_paths")
    required = [f for f in files if _any_match(f.path, c.param("require_paths", ()))]
    locs = [(f.path, None) for f in triggered]
    if required:
        return _result(c, STATUS_PASS,
                       f"{len(triggered)} triggering file(s); "
                       f"{len(required)} required file(s) changed", locs)
    return _result(c, STATUS_FAIL,
                   f"{len(triggered)} file(s) match when_paths but no changed "
                   "file matches require_paths", locs)


def _forbid_change(c: PolicyClause, files: list[FileDiff]) -> ClauseResult:
    hits = [f for f in files if _any_match(f.path, c.param("paths", ()))]
    if hits:
        return _result(c, STATUS_FAIL,
                       f"{len(hits)} changed file(s) match forbidden paths",
                       [(f.path, None) for f in hits])
    return _result(c, STATUS_PASS, "no changed file matches forbidden paths")


def _forbid_added_text(c: PolicyClause, files: list[FileDiff]) -> ClauseResult:
    needles = c.param("contains", ())
    scope = _in_scope(files, c.param("paths", ()))
    hits: list[Location] = []
    binary = 0
    for f in scope:
        if f.is_binary:
            binary += 1
            continue
        for line_no, text in f.added_lines():
            if any(n in text for n in needles):
                hits.append((f.path, line_no))
    if hits:
        return _result(c, STATUS_FAIL,
                       f"{len(hits)} added line(s) contain forbidden text", hits)
    if binary:
        return _result(c, STATUS_UNKNOWN,
                       f"{binary} binary file(s) in scope could not be inspected")
    return _result(c, STATUS_PASS, "no added line contains forbidden text")


def _max_changed_files(c: PolicyClause, files: list[FileDiff]) -> ClauseResult:
    scope = _in_scope(files, c.param("paths", ()))
    limit = c.param("limit")
    if len(scope) > limit:
        return _result(c, STATUS_FAIL,
                       f"{len(scope)} changed file(s) exceed the limit of {limit}",
                       [(f.path, None) for f in scope])
    return _result(c, STATUS_PASS, f"{len(scope)} changed file(s); limit {limit}")


def _max_added_lines(c: PolicyClause, files: list[FileDiff]) -> ClauseResult:
    scope = _in_scope(files, c.param("paths", ()))
    limit = c.param("limit")
    total = sum(f.additions for f in scope)
    if total > limit:
        return _result(c, STATUS_FAIL,
                       f"{total} added line(s) exceed the limit of {limit}",
                       [(f.path, None) for f in scope if f.additions])
    return _result(c, STATUS_PASS, f"{total} added line(s); limit {limit}")


_HANDLERS = {
    CLAUSE_REQUIRE_CHANGE: _require_change,
    CLAUSE_FORBID_CHANGE: _forbid_change,
    CLAUSE_FORBID_ADDED_TEXT: _forbid_added_text,
    CLAUSE_MAX_CHANGED_FILES: _max_changed_files,
    CLAUSE_MAX_ADDED_LINES: _max_added_lines,
}


def evaluate_policy(config: PolicyConfig, files: Sequence[FileDiff],
                    *, extra_excludes: Sequence[str] = ()) -> PolicyEvaluation:
    if not config.clauses:
        return PolicyEvaluation()
    eligible = _eligible(files, extra_excludes)
    results = []
    for clause in config.clauses:
        handler = _HANDLERS.get(clause.type)
        if clause.type == CLAUSE_GUIDANCE or handler is None:
            results.append(_result(clause, STATUS_UNKNOWN,
                                   "guidance only: clause type is not evaluated"))
            continue
        results.append(handler(clause, eligible))
    return PolicyEvaluation(results=tuple(results))
