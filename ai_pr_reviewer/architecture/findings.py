"""V4.2-E04-T04 — violation findings with offending-edge evidence.

Turns a :class:`~.checker.CheckResult` into ordinary pipeline
:class:`~ai_pr_reviewer.models.Finding` objects. Design rules:

* **evidence or dropped** — every finding carries two machine-checkable
  records (the offending edge, and the rule it breaks); if evidence cannot
  be constructed the finding is dropped rather than emitted bare;
* **deterministic, no model** — provenance is stamped here as
  ``static`` / ``architecture-v1`` / ``rule`` (pipeline-owned fields, never
  model-supplied; ``from_untrusted_dict`` strips them like all others);
* **no remediation** — ``suggestion`` is always ``None``; findings describe
  the dependency, they never prescribe or apply a rewrite;
* **no certification wording** — text states what was found; it never says
  a repository or change "complies" or "conforms";
* **redacted at the boundary** — paths come from the repository tree, so
  every string is secret-redacted, control-character-free, single-line and
  bounded here (plus the run's configured-credential ``scrub``), because
  these findings are created *after* the orchestrator's engine-output
  redaction chokepoint.

Identity: ``fingerprint_finding`` hashes (category, file, normalized
title); the title therefore names the imported file, so two violations in
one file stay two findings.
"""
from __future__ import annotations

from typing import Callable

from ..models import (STATIC_ENGINE_ID, EvidenceRecord, Finding,
                      ProvenanceSource)
from ..security import redact_secrets
from .checker import ORIGIN_DIFF, CheckResult, Violation
from .schema import ArchitectureModel

RULE_VIOLATION = "ARCH001"
PROVENANCE_MODEL = "architecture-v1"
CATEGORY = "maintainability"   # existing closed category; no new contract

MAX_TITLE_CHARS = 160
MAX_EVIDENCE_SUMMARY_CHARS = 400   # mirrors models.MAX_EVIDENCE_SUMMARY_CHARS
MAX_EXPLANATION_CHARS = 900

_CONTROL = {c: " " for c in (*range(0x20), 0x7F, *range(0x80, 0xA0),
                             0x2028, 0x2029)}


def _clean(text: object, limit: int,
           scrub: Callable[[str], str] | None = None) -> str:
    out = redact_secrets(str(text))
    if scrub is not None:
        out = scrub(out)
    out = " ".join(out.translate(_CONTROL).split())
    return out[:limit].strip()


def _explanation(v: Violation, model: ArchitectureModel, result: CheckResult,
                 new_since_snapshot: bool,
                 scrub: Callable[[str], str] | None) -> str:
    allowed = model.allowed_targets(v.importer_layer)
    allowed_txt = ", ".join(allowed) if allowed else "no other layer"
    where = ("introduced by this change" if v.origin == ORIGIN_DIFF
             else "present in the base revision")
    parts = [
        f"{v.importer} (layer '{v.importer_layer}') depends on "
        f"{v.imported} (layer '{v.imported_layer}'), {where}. "
        f"The architecture description lets layer '{v.importer_layer}' "
        f"depend on: {allowed_txt}.",
        f"Offending edge: {v.importer} -> {v.imported}"
        + (f" (import '{v.spec}')." if v.spec else "."),
    ]
    if new_since_snapshot:
        parts.append("This edge is not in the previous snapshot.")
    if result.partial:
        parts.append("The analysis was partial; other violations may exist.")
    return _clean(" ".join(parts), MAX_EXPLANATION_CHARS, scrub)


def _evidence(v: Violation, model: ArchitectureModel, rules_file: str,
              scrub: Callable[[str], str] | None
              ) -> tuple[EvidenceRecord, ...] | None:
    locator = f"{v.importer}:{v.line}" if v.line else v.importer
    allowed = model.allowed_targets(v.importer_layer)
    try:
        edge = EvidenceRecord.create(
            kind="file_excerpt", locator=locator,
            summary=_clean(
                f"offending edge {v.importer} ({v.importer_layer}) -> "
                f"{v.imported} ({v.imported_layer})"
                + (f" via import '{v.spec}'" if v.spec else ""),
                MAX_EVIDENCE_SUMMARY_CHARS, scrub),
            check_type="architecture_edge", scrub=scrub)
        rule = EvidenceRecord.create(
            kind="rule_ref",
            locator=f"{rules_file}#architecture.allow.{v.importer_layer}",
            summary=_clean(
                f"layer '{v.importer_layer}' may depend on: "
                f"{', '.join(allowed) if allowed else 'no other layer'}",
                MAX_EVIDENCE_SUMMARY_CHARS, scrub),
            check_type="architecture_rule", scrub=scrub)
    except ValueError:
        return None
    return (edge, rule)


def violation_findings(result: CheckResult, model: ArchitectureModel, *,
                       rules_file: str = ".ai-pr-reviewer.yml",
                       new_since_snapshot=frozenset(),
                       scrub: Callable[[str], str] | None = None
                       ) -> list[Finding]:
    """One finding per violation, in the checker's deterministic order."""
    out: list[Finding] = []
    source = ProvenanceSource(engine=STATIC_ENGINE_ID,
                              model=PROVENANCE_MODEL, origin="rule")
    for v in result.violations:
        evidence = _evidence(v, model, rules_file, scrub)
        if evidence is None:
            continue
        # A diff-anchored edge in a complete analysis is a direct reading
        # of an added import line; anything else is inferred from the graph.
        confidence = ("high" if v.origin == ORIGIN_DIFF and not result.partial
                      else "medium")
        finding = Finding(
            file=v.importer,
            line=v.line,
            severity=model.severity,
            category=CATEGORY,
            title=_clean(f"Disallowed layer dependency on {v.imported}",
                         MAX_TITLE_CHARS, scrub),
            explanation=_explanation(
                v, model, result, (v.importer, v.imported) in
                new_since_snapshot, scrub),
            suggestion=None,
            confidence=confidence,
            rule_id=RULE_VIOLATION,
            evidence=evidence,
        )
        finding.provenance_engine = source.engine
        finding.provenance_model = source.model
        finding.provenance_agent = None
        finding.provenance_origin = source.origin
        finding.provenance_sources = (source,)
        out.append(finding)
    return out
