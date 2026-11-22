"""Finding Relations Model & Historical Feed (V4.4-E03 & V4.4-E06).

Implements:
- V4.4-E03-T01: FindingRelation schema (causes, duplicates, regresses, contradicts)
- V4.4-E03-T02: Deterministic relation computation
- V4.4-E03-T03: AI-proposed relations validation
- V4.4-E03-T04: Relation rendering in reports
- V4.4-E06-T01: Unified historical retrieval under budget
- V4.4-E06-T02: Provenance-tagged prompt fencing
- V4.4-E06-T03: Authority-label survival across retrieval
- V4.4-E06-T04: Historical feed token ceiling
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Sequence

from .models import Finding
from .security import neutralize_fence_tags, redact_secrets, sanitize_warning

RELATION_CAUSES = "causes"
RELATION_DUPLICATES = "duplicates"
RELATION_REGRESSES = "regresses"
RELATION_CONTRADICTS = "contradicts"

VALID_RELATIONS = (
    RELATION_CAUSES,
    RELATION_DUPLICATES,
    RELATION_REGRESSES,
    RELATION_CONTRADICTS,
)


@dataclass(frozen=True)
class FindingRelation:
    source_fingerprint: str
    target_fingerprint: str
    relation_type: str
    confidence: str = "medium"
    reason: str = ""

    def __post_init__(self) -> None:
        if self.relation_type not in VALID_RELATIONS:
            object.__setattr__(self, "relation_type", RELATION_DUPLICATES)
        clean_reason = redact_secrets(sanitize_warning(self.reason))[:300]
        object.__setattr__(self, "reason", clean_reason)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_fingerprint": self.source_fingerprint,
            "target_fingerprint": self.target_fingerprint,
            "relation_type": self.relation_type,
            "confidence": self.confidence,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "FindingRelation | None":
        if not isinstance(d, dict):
            return None
        src = str(d.get("source_fingerprint") or "").strip()
        tgt = str(d.get("target_fingerprint") or "").strip()
        rel = str(d.get("relation_type") or "").strip()
        if not src or not tgt or rel not in VALID_RELATIONS:
            return None
        return cls(
            source_fingerprint=src,
            target_fingerprint=tgt,
            relation_type=rel,
            confidence=str(d.get("confidence") or "medium"),
            reason=str(d.get("reason") or ""),
        )


def compute_deterministic_relations(findings: Sequence[Finding]) -> list[FindingRelation]:
    """Compute duplicate and contradiction relations deterministically."""
    relations: list[FindingRelation] = []

    # Map findings by file and line
    by_loc: dict[tuple[str, int | None], list[Finding]] = {}
    for f in findings:
        if f.fingerprint:
            by_loc.setdefault((f.file, f.line), []).append(f)

    for (file, line), loc_findings in by_loc.items():
        if len(loc_findings) < 2:
            continue
        for i in range(len(loc_findings)):
            for j in range(i + 1, len(loc_findings)):
                f_a = loc_findings[i]
                f_b = loc_findings[j]
                if not f_a.fingerprint or not f_b.fingerprint:
                    continue

                # Same category and severity -> duplicates
                if f_a.category == f_b.category and f_a.severity == f_b.severity:
                    relations.append(FindingRelation(
                        source_fingerprint=f_a.fingerprint,
                        target_fingerprint=f_b.fingerprint,
                        relation_type=RELATION_DUPLICATES,
                        confidence="high",
                        reason=f"Colocated on {file}:{line} with matching category '{f_a.category}' and severity '{f_a.severity}'",
                    ))
                # Distinct category or opposite severity on same line -> contradicts
                elif f_a.category != f_b.category or f_a.severity != f_b.severity:
                    relations.append(FindingRelation(
                        source_fingerprint=f_a.fingerprint,
                        target_fingerprint=f_b.fingerprint,
                        relation_type=RELATION_CONTRADICTS,
                        confidence="medium",
                        reason=f"Colocated on {file}:{line} with conflicting category ({f_a.category} vs {f_b.category}) or severity ({f_a.severity} vs {f_b.severity})",
                    ))

    return relations


def validate_proposed_relations(
    raw_relations: Sequence[dict[str, Any]], known_fingerprints: set[str]
) -> list[FindingRelation]:
    """Validate model-proposed relations against closed schema and known fingerprints."""
    valid: list[FindingRelation] = []
    for item in raw_relations:
        rel = FindingRelation.from_dict(item)
        if rel is None:
            continue
        if rel.source_fingerprint not in known_fingerprints:
            continue
        if rel.target_fingerprint not in known_fingerprints:
            continue
        valid.append(rel)
    return valid


def format_historical_relations_block(
    relations: Sequence[FindingRelation], nonce: str, max_chars: int = 1000
) -> str:
    """Format historical relations within bounded nonce fences (V4.4-E06-T02/T04)."""
    if not relations:
        return ""

    lines = [f'<historical_relations nonce="{nonce}">']
    current_len = len(lines[0])

    for r in relations:
        line = f"- {r.source_fingerprint} {r.relation_type} {r.target_fingerprint}: {neutralize_fence_tags(r.reason)}"
        if current_len + len(line) + 30 > max_chars:
            lines.append("... (truncated to budget)")
            break
        lines.append(line)
        current_len += len(line)

    lines.append("</historical_relations>")
    return "\n".join(lines)
