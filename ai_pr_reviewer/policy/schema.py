"""Policy schema v2 (V4.2-E07-T01): structured, machine-checkable clauses.

The ``policy:`` section of ``.ai-pr-reviewer.yml`` is TRUSTED repository-owner
configuration, read from the base revision exactly like the rest of the file
(ADR-015): a PR cannot rewrite its own policy under the documented workflow.
Because it is trusted it needs no untrusted-input fencing; everything it
*produces* about PR content is redacted where findings are built
(``policy.findings``).

Schema (all keys optional; an absent section means "no policy")::

    policy:
      version: 2
      clauses:
        - id: AUTH-NEEDS-TESTS          # unique, [A-Za-z][A-Za-z0-9_.-]{0,63}
          type: require_change          # see CLAUSE_TYPES
          severity: high                # info|low|medium|high|critical
          message: "Auth changes must ship with tests."
          when_paths: ["src/auth/**"]
          require_paths: ["tests/**"]

Compatibility rules:

* A v1 config (no ``policy`` key) parses to an empty :class:`PolicyConfig`.
* Unknown clause types degrade to ``guidance`` (kept, never evaluated, always
  ``unknown``) with a warning — forward compatible, never fatal.
* A malformed clause is skipped with a warning; it never fails a review.
* The privacy exclusion baseline (``rules.SENSITIVE_EXCLUDE_GLOBS``) is not
  expressible here. Keys that try to alter it (``exclude``, ``baseline``,
  ``disable_baseline`` ...) are rejected with a warning.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field

from ..config import SEVERITIES

log = logging.getLogger(__name__)

SCHEMA_VERSION = 2
POLICY_KEY = "policy"

CLAUSE_REQUIRE_CHANGE = "require_change"
CLAUSE_FORBID_CHANGE = "forbid_change"
CLAUSE_FORBID_ADDED_TEXT = "forbid_added_text"
CLAUSE_MAX_CHANGED_FILES = "max_changed_files"
CLAUSE_MAX_ADDED_LINES = "max_added_lines"
CLAUSE_GUIDANCE = "guidance"          # unknown type, kept as prose only

CLAUSE_TYPES = (CLAUSE_REQUIRE_CHANGE, CLAUSE_FORBID_CHANGE,
                CLAUSE_FORBID_ADDED_TEXT, CLAUSE_MAX_CHANGED_FILES,
                CLAUSE_MAX_ADDED_LINES)

# Per-type parameter keys. Anything else in a clause is warned about and
# ignored, so a typo can never silently widen what a clause matches.
_COMMON_KEYS = frozenset({"id", "type", "severity", "message"})
_TYPE_KEYS = {
    CLAUSE_REQUIRE_CHANGE: frozenset({"when_paths", "require_paths"}),
    CLAUSE_FORBID_CHANGE: frozenset({"paths"}),
    CLAUSE_FORBID_ADDED_TEXT: frozenset({"paths", "contains"}),
    CLAUSE_MAX_CHANGED_FILES: frozenset({"limit", "paths"}),
    CLAUSE_MAX_ADDED_LINES: frozenset({"limit", "paths"}),
}

# Keys that would touch the non-removable privacy baseline. They are never
# honoured at any level of the policy section.
_BASELINE_KEYS = frozenset({"exclude", "excludes", "exclusions", "baseline",
                            "disable_baseline", "allow_paths", "include"})

KNOWN_POLICY_KEYS = frozenset({"version", "clauses"})

MAX_CLAUSES = 50
MAX_LIST_ENTRIES = 50
MAX_STRING_CHARS = 200
MAX_MESSAGE_CHARS = 300
MAX_LIMIT = 1_000_000
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class PolicyClause:
    """One validated clause. ``params`` holds only the keys the clause type
    declares, already coerced (tuples of str / int)."""

    id: str
    type: str
    severity: str = "medium"
    message: str = ""
    params: dict = field(default_factory=dict)

    def param(self, name: str, default=None):
        return self.params.get(name, default)


@dataclass(frozen=True)
class PolicyConfig:
    """Normalized policy section. Empty (``clauses == ()``) means no policy:
    the evaluator is then a no-op and review output is unchanged."""

    clauses: tuple[PolicyClause, ...] = ()
    version: int = SCHEMA_VERSION
    warnings: tuple[str, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.clauses)


def _warn(warnings: list[str], source: str, msg: str) -> None:
    text = f"{source}: policy: {msg}"
    warnings.append(text)
    log.warning("%s", text)


def _str_tuple(value: object, name: str, source: str,
               warnings: list[str]) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        _warn(warnings, source, f"'{name}' should be a list — ignored")
        return ()
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            _warn(warnings, source, f"non-string entry in '{name}' skipped")
            continue
        out.append(item.strip()[:MAX_STRING_CHARS])
    if len(out) > MAX_LIST_ENTRIES:
        _warn(warnings, source, f"'{name}' capped at {MAX_LIST_ENTRIES} entries")
        out = out[:MAX_LIST_ENTRIES]
    return tuple(dict.fromkeys(out))


def _parse_clause(raw: object, index: int, seen: set[str], source: str,
                  warnings: list[str]) -> PolicyClause | None:
    where = f"clauses[{index}]"
    if not isinstance(raw, dict):
        _warn(warnings, source, f"{where} must be a mapping — skipped")
        return None
    hit = sorted(str(k) for k in raw if str(k).lower() in _BASELINE_KEYS)
    if hit:
        _warn(warnings, source,
              f"{where} key(s) {', '.join(hit)} cannot alter the privacy "
              "baseline — ignored")

    cid = raw.get("id")
    if not isinstance(cid, str) or not _ID_RE.match(cid):
        _warn(warnings, source, f"{where} has a missing/invalid id — skipped")
        return None
    if cid in seen:
        _warn(warnings, source, f"duplicate clause id {cid!r} — skipped")
        return None

    sev = raw.get("severity", "medium")
    if not isinstance(sev, str) or sev.lower() not in SEVERITIES:
        _warn(warnings, source,
              f"{cid}: invalid severity {sev!r} — defaulting to 'medium'")
        sev = "medium"
    sev = sev.lower()

    msg = raw.get("message", "")
    msg = msg.strip()[:MAX_MESSAGE_CHARS] if isinstance(msg, str) else ""
    if "message" in raw and not isinstance(raw["message"], str):
        _warn(warnings, source, f"{cid}: 'message' should be a string — ignored")

    ctype = raw.get("type")
    ctype = ctype.strip().lower() if isinstance(ctype, str) else ""
    if ctype not in CLAUSE_TYPES:
        _warn(warnings, source,
              f"{cid}: unknown clause type {raw.get('type')!r} — kept as "
              "guidance only, never evaluated")
        seen.add(cid)
        return PolicyClause(id=cid, type=CLAUSE_GUIDANCE, severity=sev,
                            message=msg)

    allowed = _TYPE_KEYS[ctype] | _COMMON_KEYS
    stray = sorted(str(k) for k in raw
                   if k not in allowed and str(k).lower() not in _BASELINE_KEYS)
    if stray:
        _warn(warnings, source,
              f"{cid}: unknown key(s) ignored: {', '.join(stray)}")

    params: dict = {}
    for name in ("when_paths", "require_paths", "paths", "contains"):
        if name in _TYPE_KEYS[ctype]:
            params[name] = _str_tuple(raw.get(name), name, source, warnings)
    if "limit" in _TYPE_KEYS[ctype]:
        limit = raw.get("limit")
        if isinstance(limit, bool) or not isinstance(limit, int) \
                or not 0 <= limit <= MAX_LIMIT:
            _warn(warnings, source,
                  f"{cid}: 'limit' must be an integer in [0, {MAX_LIMIT}] "
                  "— clause skipped")
            return None
        params["limit"] = limit

    required = {
        CLAUSE_REQUIRE_CHANGE: ("when_paths", "require_paths"),
        CLAUSE_FORBID_CHANGE: ("paths",),
        CLAUSE_FORBID_ADDED_TEXT: ("paths", "contains"),
    }.get(ctype, ())
    missing = [n for n in required if not params.get(n)]
    if missing:
        _warn(warnings, source,
              f"{cid}: missing {', '.join(missing)} — clause skipped")
        return None

    seen.add(cid)
    return PolicyClause(id=cid, type=ctype, severity=sev, message=msg,
                        params=params)


def parse_policy_section(raw: object, source: str = "policy") -> PolicyConfig:
    """Normalize the value of the top-level ``policy`` key. Never raises."""
    if raw is None:
        return PolicyConfig()
    warnings: list[str] = []
    if not isinstance(raw, dict):
        _warn(warnings, source, "section should be a mapping — ignored")
        return PolicyConfig(warnings=tuple(warnings))

    hit = sorted(str(k) for k in raw if str(k).lower() in _BASELINE_KEYS)
    if hit:
        _warn(warnings, source,
              f"key(s) {', '.join(hit)} cannot alter the privacy baseline "
              "— ignored")
    unknown = sorted(str(k) for k in raw
                     if k not in KNOWN_POLICY_KEYS
                     and str(k).lower() not in _BASELINE_KEYS)
    if unknown:
        _warn(warnings, source, f"unknown key(s) ignored: {', '.join(unknown)}")

    version = raw.get("version", SCHEMA_VERSION)
    if version != SCHEMA_VERSION or isinstance(version, bool):
        _warn(warnings, source,
              f"unsupported version {version!r} — parsing as v{SCHEMA_VERSION}")

    clauses_raw = raw.get("clauses")
    if clauses_raw is None:
        clauses_raw = []
    if not isinstance(clauses_raw, list):
        _warn(warnings, source, "'clauses' should be a list — ignored")
        clauses_raw = []
    if len(clauses_raw) > MAX_CLAUSES:
        _warn(warnings, source, f"capped at {MAX_CLAUSES} clauses")
        clauses_raw = clauses_raw[:MAX_CLAUSES]

    seen: set[str] = set()
    clauses = tuple(c for i, item in enumerate(clauses_raw)
                    if (c := _parse_clause(item, i, seen, source, warnings)))
    return PolicyConfig(clauses=clauses, warnings=tuple(warnings))


def load_policy_config(repo_root: str = ".",
                       filename: str = ".ai-pr-reviewer.yml") -> PolicyConfig:
    """Read the ``policy`` section from the trusted policy file.

    Separate loader by design (same precedent as ``feedback.load_feedback_
    config``): ``rules.load_project_rules`` keeps loading the v1 schema
    untouched. Never raises; fail-closed per ADR-015 — an unreadable file
    means *no policy* (baseline-only review) plus a warning.
    """
    path = os.path.join(repo_root, filename)
    try:
        if not os.path.isfile(path):
            return PolicyConfig()
        import yaml

        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001 — config must never fail a review
        msg = (f"{path}: could not read policy ({type(exc).__name__}); "
               "reviewing with the built-in baseline only")
        log.warning("%s", msg)
        return PolicyConfig(warnings=(msg,))
    if not isinstance(data, dict):
        return PolicyConfig()
    return parse_policy_section(data.get(POLICY_KEY), path)
