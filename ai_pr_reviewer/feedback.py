"""V4-E09 — engine-side feedback & suppression: READ-ONLY by design.

What this module can do: load the *active* suppression rules a human
created in the dashboard/CLI for **one repository**, and park (state
``muted``) and *count* the findings those rules select. That is all.

What it structurally cannot do (see ``docs/planning/V4_THREAT_MODEL.md``
§4 and :mod:`ai_pr_reviewer.feedback_admin`):

* create, modify, extend, approve or delete a rule or a vote — it imports
  nothing from the write side, and the storage methods it calls
  (``get_suppression_rules``) are read-only;
* act on its own — it never decides a finding is wrong; a rule is a
  human decision recorded elsewhere, applied here;
* erase a finding — a suppressed finding stays in the result as a ``muted``
  finding (V3's existing dismissal state) and is counted in
  ``suppressed_count`` / ``suppression_rule_hits``;
* change anything when ``feedback.enabled`` is false (the default): the
  single entry point :func:`apply_feedback_suppression` returns its input
  list *unchanged* and touches no storage before reading the flag.

The configuration key is ``feedback.enabled`` in ``.ai-pr-reviewer.yml``
(the trusted base-revision policy file), defaulting to ``false``.
"""
from __future__ import annotations

import fnmatch
import logging
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any, Callable

from . import storage_schema as S
from .findings import fingerprint_finding
from .models import Finding

log = logging.getLogger(__name__)

#: ``feedback.enabled`` default. Flipping this default would change V3
#: behavior for everyone — a test pins it.
FEEDBACK_ENABLED_DEFAULT = False

#: States a finding can already be in that suppression leaves alone: a
#: resolved finding is a different fact from a muted one (same rule as
#: ``findings.mark_dismissed``), and an already-dismissed/muted finding is
#: parked, so it must not be re-counted as "suppressed by a rule".
_UNTOUCHED_STATES = frozenset({"resolved", "dismissed", "muted"})
_SUPPRESSED_STATE = "muted"


# ------------------------------------------------------------------ config
@dataclass(frozen=True)
class FeedbackConfig:
    """Engine-side feedback settings. One knob: ``enabled`` (default off)."""

    enabled: bool = FEEDBACK_ENABLED_DEFAULT


def parse_feedback_section(raw: object) -> FeedbackConfig:
    """Parse the ``feedback:`` mapping of ``.ai-pr-reviewer.yml``.

    Strict on purpose: only the YAML boolean ``true`` enables the feature.
    A string ("true", "yes"), a number or a malformed section leaves it
    OFF — a typo can never silently turn on behavior that changes review
    output. Never raises.
    """
    if not isinstance(raw, dict):
        return FeedbackConfig()
    return FeedbackConfig(enabled=raw.get("enabled") is True)


def load_feedback_config(repo_root: str = ".",
                         filename: str = ".ai-pr-reviewer.yml"
                         ) -> FeedbackConfig:
    """Read ``feedback.enabled`` from the trusted policy file. Never raises;
    a missing/unreadable/malformed file means "disabled" (V3 behavior).

    The file is the *base-revision* policy (see ``rules.py``): a PR cannot
    rewrite it under the documented workflow. And even a PR that did flip
    this flag could only *activate* rules a human already created — it
    cannot create one (the write side is unreachable from here).
    """
    import os

    path = os.path.join(repo_root, filename)
    try:
        if not os.path.isfile(path):
            return FeedbackConfig()
        import yaml

        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except Exception as exc:  # noqa: BLE001 — config must never fail a review
        log.warning("%s: could not read feedback settings (%s); "
                    "feedback stays disabled", path, type(exc).__name__)
        return FeedbackConfig()
    if not isinstance(data, dict):
        return FeedbackConfig()
    return parse_feedback_section(data.get("feedback"))


# ------------------------------------------------------------------- rules
@dataclass(frozen=True)
class SuppressionRule:
    """A validated, read-only view of one stored rule row."""

    id: str
    repo: str
    match_kind: str
    fingerprint: str
    rule_id: str
    path_glob: str
    origin: str
    created_at: str
    expires_at: str

    @classmethod
    def from_row(cls, row: Any, repo: str) -> "SuppressionRule | None":
        """Validate one stored row; ``None`` means "ignore this row".

        A store is trusted to have written well-formed rows, but the engine
        does not rely on it: a row is applied only if it is for *this*
        repository, carries a legal origin, a legal shape, a legal id and
        is not disabled. Tampered rows (wrong repo, origin ``model``,
        match-everything shape, junk fields) are skipped — they can only
        ever cause *less* suppression, never more.
        """
        if not isinstance(row, dict):
            return None
        try:
            if row.get("repo") != repo:
                return None                                 # isolation
            if row.get("origin") not in S.RULE_ORIGINS:
                return None                                 # provenance
            if row.get("disabled_at"):
                return None
            rid = row.get("id")
            if not isinstance(rid, str) or not S.RULE_ROW_ID_RE.fullmatch(rid):
                return None
            kind = row.get("match_kind")
            fp = row.get("fingerprint") or ""
            rule_id = row.get("rule_id") or ""
            glob = row.get("path_glob") or ""
            if kind == S.RULE_MATCH_FINGERPRINT:
                if not S.FINGERPRINT_RE.fullmatch(fp) or rule_id or glob:
                    return None
            elif kind == S.RULE_MATCH_RULE_PATH:
                if (fp or not S.RULE_ID_RE.fullmatch(rule_id)
                        or not S.PATH_GLOB_RE.fullmatch(glob)
                        or glob.startswith("/") or ".." in glob.split("/")):
                    return None
            else:
                return None
            created, expires = row.get("created_at"), row.get("expires_at")
            if not isinstance(created, str) or not isinstance(expires, str):
                return None
            return cls(id=rid, repo=repo, match_kind=kind, fingerprint=fp,
                       rule_id=rule_id, path_glob=glob,
                       origin=row["origin"], created_at=created,
                       expires_at=expires)
        except Exception:  # noqa: BLE001 — a bad row is skipped, never fatal
            return None

    def is_active(self, now: datetime) -> bool:
        """In force at ``now``. An unparseable expiry reads as expired."""
        expires = S.parse_feedback_iso(self.expires_at)
        return expires is not None and expires > now

    def matches(self, finding: Finding, fingerprint: str | None = None) -> bool:
        """True when this rule selects ``finding``.

        Both selectors are *exact*: one v1 fingerprint, or one exact
        ``rule_id`` limited to a path glob. There is no selector that
        matches every finding.
        """
        if self.match_kind == S.RULE_MATCH_FINGERPRINT:
            fp = fingerprint or fingerprint_finding(finding)
            return fp == self.fingerprint
        if (finding.rule_id or "") != self.rule_id:
            return False
        path = (finding.file or "").replace("\\", "/")
        while path.startswith("./"):
            path = path[2:]
        return fnmatch.fnmatchcase(path, self.path_glob)


# ------------------------------------------------------------- application
@dataclass
class SuppressionOutcome:
    """Result of applying rules: the findings (suppressed ones parked) and
    what was suppressed. ``hits`` maps rule row id -> findings it parked
    (ids only — never free text)."""

    findings: list[Finding]
    suppressed_count: int = 0
    hits: dict[str, int] = field(default_factory=dict)

    def report_fields(self) -> dict:
        """The additive report keys. Only ever built when feedback is on."""
        return {"suppressed_count": self.suppressed_count,
                "suppression_rule_hits": dict(sorted(self.hits.items()))}


def apply_suppression(findings: list[Finding],
                      rules: list[SuppressionRule],
                      now: datetime) -> SuppressionOutcome:
    """Park every open finding a rule selects. Pure: no I/O, no mutation of
    the input list or its findings (selected findings are replaced by a
    ``muted`` copy, like ``findings.mark_dismissed``).

    First matching rule (by creation time, then id — deterministic) takes
    the credit, so one finding is counted exactly once.
    """
    live = sorted((r for r in rules if r.is_active(now)),
                  key=lambda r: (r.created_at, r.id))
    if not live:
        return SuppressionOutcome(list(findings))
    out: list[Finding] = []
    hits: dict[str, int] = {}
    count = 0
    for f in findings:
        if f.state in _UNTOUCHED_STATES:
            out.append(f)
            continue
        fp = fingerprint_finding(f)
        winner = next((r for r in live if r.matches(f, fp)), None)
        if winner is None:
            out.append(f)
            continue
        out.append(replace(f, fingerprint=fp, state=_SUPPRESSED_STATE))
        count += 1
        hits[winner.id] = hits.get(winner.id, 0) + 1
    return SuppressionOutcome(out, count, hits)


def load_active_rules(storage: Any, repo: str, now: datetime,
                      warnings: list[str],
                      scrub: Callable[[str], str] | None = None
                      ) -> list[SuppressionRule]:
    """Rules to apply this run, or ``[]`` with a report warning.

    Fails *open toward more findings*: any problem (no storage, backend
    without the capability, a failing read, junk rows, too many rules)
    means fewer rules apply — never an exception, never a lost review.
    """
    from .storage import has_capability  # local: storage imports models

    def say(message: str) -> None:
        warnings.append(scrub(message) if scrub else message)

    if storage is None:
        say("feedback.enabled is on but this run has no storage; no "
            "suppression rules were applied.")
        return []
    if not has_capability(storage, S.CAP_SUPPRESSION_RULES):
        say(f"feedback.enabled is on but storage backend "
            f"{type(storage).__name__} cannot supply suppression rules; "
            f"none were applied.")
        return []
    try:
        rows = storage.get_suppression_rules(repo) or []
    except Exception as exc:  # noqa: BLE001 — storage must never lose a review
        say(f"suppression rules could not be loaded ({type(exc).__name__}); "
            f"none were applied this run.")
        return []
    rules = [r for r in (SuppressionRule.from_row(row, repo) for row in rows)
             if r is not None and r.is_active(now)]
    skipped = len(rows) - len(rules)
    if skipped:
        log.warning("feedback: ignored %d stored rule row(s) that were "
                    "inactive, malformed, or not for repo %s", skipped, repo)
    if len(rules) > S.MAX_RULES_APPLIED_PER_RUN:
        say(f"{len(rules)} suppression rules are active; only the "
            f"{S.MAX_RULES_APPLIED_PER_RUN} oldest were applied.")
        rules = sorted(rules, key=lambda r: (r.created_at, r.id))[
            :S.MAX_RULES_APPLIED_PER_RUN]
    return rules


def apply_feedback_suppression(
        *, enabled: bool, storage: Any, repo: str, findings: list[Finding],
        warnings: list[str], scrub: Callable[[str], str] | None = None,
        now: datetime | None = None) -> tuple[list[Finding], dict]:
    """The single orchestrator integration point for feedback suppression.

    * ``enabled`` false -> returns ``(findings, {})`` immediately: the
      *same list object*, no storage access, no report fields. This is the
      byte-identical-to-V3 guarantee.
    * ``enabled`` true  -> loads this repository's active rules, parks the
      findings they select, returns ``(findings, report_fields)`` where
      ``report_fields`` is ``{"suppressed_count", "suppression_rule_hits"}``
      (present even when 0, so "feedback ran, nothing matched" is
      distinguishable from "feedback is off").
    """
    if not enabled:
        return findings, {}
    moment = S.feedback_now(now)
    rules = load_active_rules(storage, repo, moment, warnings, scrub)
    outcome = apply_suppression(findings, rules, moment)
    return outcome.findings, outcome.report_fields()
