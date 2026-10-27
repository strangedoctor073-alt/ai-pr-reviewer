"""Policy findings pipeline integration (V4.2-E07-T03).

Turns failed clauses into ordinary :class:`~ai_pr_reviewer.models.Finding`
objects so they ride the existing lifecycle, dedup, threshold, report and
comment paths unchanged. Report/Finding schemas are untouched (additive-only
contract): policy findings use existing fields only —

* ``rule_id``  ``POL:<clause id>`` (clause provenance in the identifier)
* ``category`` an existing category (``testing`` for ``require_change``,
  otherwise ``maintainability``)
* ``evidence`` a ``rule_ref`` record whose locator is the clause's location in
  the policy file, plus one ``diff_hunk`` record per cited location
* provenance ``engine=policy-v1`` / ``origin=rule``

Hard rules:

* **Never auto-remediation.** ``suggestion`` is always ``None`` and nothing
  here writes, commits, comments or calls out. Findings are reported only.
* Only ``fail`` verdicts become findings; ``unknown`` is surfaced as a
  warning string, never as a finding, so the engine cannot claim a violation
  it could not establish.
* Text derived from PR content (paths) is redacted via ``EvidenceRecord`` and
  the caller-supplied ``scrub`` before it is stored.

Hook (one call, between provenance/evidence stamping and ``deduplicate`` in
``ReviewOrchestrator.run``; intentionally *not* wired from this module so the
orchestrator seam stays a single reviewed edit)::

    policy_findings, policy_warnings = review_policy(
        cfg_repo_root, rules_file, files, scrub=lambda t: _scrub(t, cfg),
        extra_excludes=policy.exclude)
    outcome.findings.extend(policy_findings)
    warnings.extend(policy_warnings)

With no ``policy:`` section the call returns ``([], [])`` and the review is
byte-identical to a v1 run.
"""
from __future__ import annotations

from typing import Callable, Sequence

from ..diff_parser import FileDiff
from ..models import EvidenceRecord, Finding, ProvenanceSource
from .evaluate import (STATUS_FAIL, STATUS_UNKNOWN, ClauseResult,
                       PolicyEvaluation, clause_locator, evaluate_policy)
from .schema import (CLAUSE_REQUIRE_CHANGE, PolicyConfig, load_policy_config)

POLICY_ENGINE_ID = "policy-v1"
RULE_ID_PREFIX = "POL:"
MAX_TITLE_CHARS = 120


def _identity(text: str) -> str:
    return text


def _finding_for(result: ClauseResult,
                 scrub: Callable[[str], str]) -> Finding:
    anchor_path, anchor_line = (result.locations[0] if result.locations
                                else ("", None))
    category = ("testing" if result.clause_type == CLAUSE_REQUIRE_CHANGE
                else "maintainability")
    headline = result.message or result.detail
    title = scrub(f"Policy {result.clause_id}: {headline}")[:MAX_TITLE_CHARS]
    cited = ", ".join(f"{p}:{n}" if n else p for p, n in result.locations)
    explanation = scrub(
        f"Policy clause `{result.clause_id}` ({result.clause_type}) was not "
        f"satisfied: {result.detail}."
        + (f" Cited location(s): {cited}." if cited else "")
        + f" Defined at {clause_locator(result.clause_id)}. "
        "Reported only; no change was made.")

    evidence = [EvidenceRecord.create(
        kind="rule_ref", locator=clause_locator(result.clause_id),
        summary=f"{result.clause_type}: {result.detail}",
        check_type=result.clause_type, scrub=scrub)]
    for path, line in result.locations[:4]:
        evidence.append(EvidenceRecord.create(
            kind="diff_hunk", locator=f"{path}:{line}" if line else path,
            summary=f"cited by policy clause {result.clause_id}",
            check_type=result.clause_type, scrub=scrub))

    src = ProvenanceSource(engine=POLICY_ENGINE_ID, model=None,
                           origin="rule", agent=None)
    f = Finding(
        file=scrub(anchor_path), line=anchor_line,
        severity=result.severity, category=category, title=title,
        explanation=explanation, suggestion=None, confidence="high",
        rule_id=f"{RULE_ID_PREFIX}{result.clause_id}",
        provenance_engine=src.engine, provenance_model=src.model,
        provenance_origin=src.origin, provenance_sources=(src,),
        evidence=tuple(evidence))
    return f


def policy_findings(evaluation: PolicyEvaluation, *,
                    scrub: Callable[[str], str] | None = None
                    ) -> tuple[list[Finding], list[str]]:
    """``(findings, warnings)`` for an evaluation. Findings only for ``fail``;
    ``unknown`` verdicts become one-line warnings."""
    scrub = scrub or _identity
    findings = [_finding_for(r, scrub) for r in evaluation.results
                if r.status == STATUS_FAIL]
    warnings = [scrub(f"Policy clause {r.clause_id} could not be decided: "
                      f"{r.detail}")
                for r in evaluation.results if r.status == STATUS_UNKNOWN]
    return findings, warnings


def review_policy(repo_root: str, rules_file: str,
                  files: Sequence[FileDiff], *,
                  scrub: Callable[[str], str] | None = None,
                  extra_excludes: Sequence[str] = (),
                  config: PolicyConfig | None = None
                  ) -> tuple[list[Finding], list[str]]:
    """Load (trusted base-revision) policy, evaluate it against ``files`` and
    return findings + warnings. No policy section -> ``([], [])``."""
    cfg = config if config is not None else load_policy_config(
        repo_root, rules_file)
    scrub = scrub or _identity
    warnings = [scrub(w) for w in cfg.warnings]
    if not cfg.enabled:
        return [], warnings
    found, more = policy_findings(
        evaluate_policy(cfg, files, extra_excludes=extra_excludes), scrub=scrub)
    return found, warnings + more
