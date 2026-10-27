"""Deterministic specialist slots (V4.0-E02-T03).

Execution half of the specialist contract: a contract declares
:class:`~ai_pr_reviewer.orchestration.specialists.DeterministicSlot`s and
this module runs them. A slot *scopes* the existing static rule engine to
its declared packs — a thin scope, never a copy: every rule lives in
``ai_pr_reviewer/static/`` and stays there (the V4.0 non-goal "a security
specialist may exist only as a thin scope over existing static SEC
rules").

Boundaries this module keeps:

* **Pure function of the parsed diff.** No network, no GitHub, no
  storage, no config reads — a specialist step can never post or persist
  anything (the conformance suite greps this file for it).
* **Trusted construction, untrusted input.** Findings are built by the
  static engine's own chokepoint (``StaticEngine._attach_evidence`` →
  ``EvidenceRecord.create``, redacted and bounded there) from diff text
  an attacker controls. They are deliberately *not* round-tripped through
  ``Finding.from_untrusted_dict`` on the way out: that constructor strips
  pipeline-owned fields — including ``evidence``, which is ours, not a
  model's. The untrusted re-entry happens where specialist output crosses
  to the *next* consumer (the merger, V4.0-E03); the conformance suite
  pins that path with a hostile-field test.
* **Deterministic output.** Slots run in contract declaration order;
  findings de-duplicate on ``(file, line, rule_id, title)`` and sort by
  severity with a stable tie-break, so nothing about timing or slot order
  can change the result.

Not wired into the review path yet: activating specialist tasks needs the
merger (V4.0-E03) and the council config flag. Until then only tests and
future epics call these functions, which is exactly why no config flag or
orchestrator hook exists here.
"""
from __future__ import annotations

from ..diff_parser import FileDiff
from ..models import (AnalysisOutcome, Finding, SEVERITY_ORDER,
                      STATIC_RULE_ENGINE_VERSION)
from ..security import scan_prompt_injection
from ..static import (javascript_rules, python_rules, security_rules,
                      shell_rules, test_rules)
from ..static.engine import StaticEngine
from ..static.registry import RuleRegistry
from .specialists import RULE_PACKS, SpecialistContract, validate_contract

#: Every rule pack a slot may name, mapped to the ``static/`` module that
#: registers it. Kept in lockstep with ``specialists.RULE_PACKS`` (pinned
#: by test) so a declared pack always resolves to real rules.
PACK_MODULES = {
    "security": security_rules,
    "javascript": javascript_rules,
    "python": python_rules,
    "shell": shell_rules,
    "test": test_rules,
}


def build_registry(packs: tuple[str, ...]) -> RuleRegistry:
    """A rule registry holding exactly the named packs (in order)."""
    registry = RuleRegistry()
    for pack in packs:
        PACK_MODULES[pack].register(registry)
    return registry


def run_deterministic_slots(contract: SpecialistContract,
                            files: list[FileDiff]) -> list[Finding]:
    """Run every declared slot of ``contract`` over ``files``.

    The contract is validated on entry: execution never runs a schema it
    would have refused to accept.
    """
    validate_contract(contract)
    merged: list[Finding] = []
    seen: set[tuple[str, int | None, str | None, str]] = set()
    for slot in contract.deterministic_slots:
        engine = StaticEngine(build_registry(slot.packs))
        for finding in engine.run(files):
            key = (finding.file, finding.line, finding.rule_id, finding.title)
            if key in seen:
                continue          # two slots scoping overlapping packs
            seen.add(key)
            merged.append(finding)
    merged.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    return merged


def run_deterministic(contract: SpecialistContract,
                      files: list[FileDiff]) -> AnalysisOutcome:
    """A deterministic specialist end-to-end: declared slots, one outcome.

    The outcome satisfies the shared output contract
    (:func:`specialists.validate_specialist_outcome`): honest
    ``engine="static"`` labelling (a deterministic specialist can never
    claim an AI review), findings with rule-engine provenance the pipeline
    derives in V4-E04 style, and the same prompt-injection forensic trail
    the static engine records.
    """
    findings = run_deterministic_slots(contract, files)

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    pretty = ", ".join(f"{v} {k}" for k, v in sorted(
        counts.items(), key=lambda kv: -SEVERITY_ORDER[kv[0]])) or "no issues"
    packs = tuple(dict.fromkeys(
        pack for slot in contract.deterministic_slots for pack in slot.packs))
    summary = (
        f"Deterministic specialist '{contract.name}' (rule engine — not AI) "
        f"ran {len(contract.deterministic_slots)} slot(s) over "
        f"{len(packs)} rule pack(s) and {len(files)} changed file(s), "
        f"matching {len(findings)} rule(s): {pretty}."
    )

    warnings: list[str] = []
    diff_text = "\n\n".join(fd.to_diff_text() for fd in files)
    for hit in scan_prompt_injection(diff_text):
        warnings.append(f"prompt-injection screen: {hit}")

    return AnalysisOutcome(
        findings=findings, summary=summary, mode="static",
        model=STATIC_RULE_ENGINE_VERSION, warnings=warnings,
        engine="static", fallback_used=False, batch_count=1,
    )
