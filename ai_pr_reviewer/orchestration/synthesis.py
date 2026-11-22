"""Council review synthesis and disagreement resolution (V4.0-E06).

Combines merged findings and conflict records produced by multiple specialist
reviewers into an executive synthesis narrative:

* **Consensus & Narrative (T01/T02)**: synthesized review overview acknowledging
  specialist perspectives and evidence citations.
* **Finding Mutation Guard (T03)**: synthesis is strictly an annotation/summarization
  layer; it CANNOT add, drop, or alter findings or lifecycle fields (pipeline-owned).
* **Disagreement Accounting (T04)**: explicit section derived from :class:`ConflictRecord`s
  documenting specialist disagreements and their deterministic reconciliation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from ..models import Finding, describe_provenance
from ..security import redact_secrets, sanitize_warning
from .merger import ConflictRecord, MergeResult

MAX_SYNTHESIS_CHARS = 4000
MAX_DISAGREEMENTS = 20


@dataclass
class SynthesisOutcome:
    """The structured result of synthesizing a council review (V4.0-E06)."""

    summary: str
    disagreements: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence_citations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": redact_secrets(self.summary),
            "disagreements": [redact_secrets(d) for d in self.disagreements],
            "findings": [f.to_dict() for f in self.findings],
            "evidence_citations": list(self.evidence_citations),
            "warnings": [redact_secrets(w) for w in self.warnings],
        }


def _format_conflict_line(conflict: ConflictRecord) -> str:
    """Format one conflict record into a human-readable summary line."""
    loc = f"{conflict.file}:{conflict.line}" if conflict.line else conflict.file
    specs = ", ".join(conflict.specialists)
    vals = ", ".join(str(v) for v in conflict.values)
    return (
        f"- `{loc}` ({conflict.conflict_type}): {specs} disagreed ({vals}); "
        f"reconciled to **{conflict.resolved_value}**."
    )


def synthesize_council_narrative(
    merged: MergeResult,
    *,
    ai_narrative: str | None = None,
    max_chars: int = MAX_SYNTHESIS_CHARS,
) -> SynthesisOutcome:
    """Synthesize council review findings into one unified narrative (V4.0-E06).

    Invariant: Merged findings are pipeline-owned and are returned verbatim.
    Hostile instructions in ``ai_narrative`` attempting to inject, drop, or modify
    findings are completely ineffective by construction.
    """
    findings = list(merged.findings)
    conflicts = list(merged.conflicts)

    # 1. Collect evidence citations from findings
    citations: list[str] = []
    for f in findings:
        prov = describe_provenance(f)
        for ev in prov.get("evidence", ()):
            cite = f"{ev.get('kind')} `{ev.get('locator')}`"
            if cite not in citations:
                citations.append(cite)

    # 2. Collect explicit disagreement descriptions
    disagreement_lines: list[str] = []
    for c in conflicts[:MAX_DISAGREEMENTS]:
        disagreement_lines.append(_format_conflict_line(c))

    # 3. Assemble narrative sections
    sections: list[str] = ["## 🏛️ Council Synthesis", ""]

    if ai_narrative and ai_narrative.strip():
        # Sanitize and bound provider-supplied text
        clean_ai = sanitize_warning(ai_narrative.strip(), max_chars=max_chars // 2)
        sections.append(clean_ai)
    else:
        # Deterministic fallback summary
        total = len(findings)
        by_sev: dict[str, int] = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        sev_parts = [f"{by_sev[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if by_sev.get(s)]
        sev_str = " · ".join(sev_parts) if sev_parts else "clean"
        sections.append(
            f"The review council completed analysis with {total} finding(s) flagged ({sev_str})."
        )

    if disagreement_lines:
        sections.extend([
            "",
            "### ⚖️ Disagreements & Reconciliations",
            *disagreement_lines,
        ])

    if citations:
        top_cites = citations[:5]
        cite_str = " · ".join(top_cites)
        if len(citations) > 5:
            cite_str += f" · (+{len(citations) - 5} more)"
        sections.extend([
            "",
            f"**Evidence backing findings:** {cite_str}",
        ])

    summary_text = "\n".join(sections)
    if len(summary_text) > max_chars:
        summary_text = summary_text[:max_chars - 1].rstrip() + "…"

    return SynthesisOutcome(
        summary=summary_text,
        disagreements=disagreement_lines,
        findings=findings,  # Guaranteed untouched
        evidence_citations=citations,
    )
