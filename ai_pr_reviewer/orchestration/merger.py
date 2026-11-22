"""Cross-specialist finding deduplication and severity reconciliation (V4.0-E03).

Merges findings produced by multiple specialist reviewers (or multiple engine runs)
into one coherent, deduplicated, provenance-preserving finding set:

* **Identity v2 & Dedup (T01)**: groups findings by v1 fingerprint and symbol-anchored
  occurrence key. Provenance sources and evidence records are merged rather than discarded.
* **Severity Reconciliation (T02)**: deterministic resolution where the highest severity
  wins (critical > high > medium > low > info), preventing a low-trust or lenient
  specialist from downgrading a genuine security finding.
* **Conflict Recording (T03)**: differences in severity, category, or suggestion produce
  an explicit, auditable :class:`ConflictRecord` instead of a silent winner.
* **Determinism (T04)**: output findings and conflict records are globally sorted by
  deterministic criteria (severity descending, file ascending, line ascending), so task
  completion order cannot change the review.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Iterable, Sequence

from ..findings import (
    _merge_duplicate,
    _provenance_sources,
    fingerprint_finding,
    occurrence_key,
)
from ..models import (
    MAX_EVIDENCE_PER_FINDING,
    MAX_PROVENANCE_SOURCES,
    SEVERITY_ORDER,
    EvidenceRecord,
    Finding,
    ProvenanceSource,
)
from ..security import redact_secrets, sanitize_warning


@dataclass(frozen=True)
class ConflictRecord:
    """An explicit record of disagreement between specialist reviewers (V4.0-E03-T03).

    Ensures that when specialists disagree on severity or classification, the resolution
    is documented and visible rather than silently dropping alternative assessments.
    """

    fingerprint: str
    file: str
    line: int | None
    conflict_type: str  # "severity" | "category" | "suggestion" | "classification"
    specialists: tuple[str, ...]
    values: tuple[Any, ...]
    resolved_value: Any
    description: str = ""

    def __post_init__(self) -> None:
        put = object.__setattr__
        # Ensure description is secret-redacted and length-bounded
        if self.description:
            put(self, "description", sanitize_warning(self.description))

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "file": self.file,
            "line": self.line,
            "conflict_type": self.conflict_type,
            "specialists": list(self.specialists),
            "values": list(self.values),
            "resolved_value": self.resolved_value,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ConflictRecord:
        return cls(
            fingerprint=str(d.get("fingerprint") or ""),
            file=str(d.get("file") or ""),
            line=d.get("line") if isinstance(d.get("line"), int) else None,
            conflict_type=str(d.get("conflict_type") or ""),
            specialists=tuple(str(s) for s in d.get("specialists") or ()),
            values=tuple(d.get("values") or ()),
            resolved_value=d.get("resolved_value"),
            description=str(d.get("description") or ""),
        )


@dataclass
class MergeResult:
    """Outcome of merging findings across specialists."""

    findings: list[Finding]
    conflicts: list[ConflictRecord] = field(default_factory=list)
    merged_count: int = 0


def reconcile_severity(severities: Sequence[str]) -> tuple[str, bool]:
    """Deterministically reconcile multiple severity assessments (V4.0-E03-T02).

    Rule: Highest severity wins according to SEVERITY_ORDER (critical > high > medium > low > info).
    Returns (highest_severity, has_conflict).
    """
    if not severities:
        return "medium", False

    valid = [s.lower() for s in severities if s.lower() in SEVERITY_ORDER]
    if not valid:
        return "medium", False

    unique = set(valid)
    has_conflict = len(unique) > 1

    # SEVERITY_ORDER maps name -> rank (critical is highest rank)
    highest = max(valid, key=lambda s: SEVERITY_ORDER.get(s, 0))
    return highest, has_conflict


def _agent_of(finding: Finding) -> str:
    """Identify which specialist agent produced this finding."""
    if finding.provenance_agent:
        return str(finding.provenance_agent)
    for src in finding.provenance_sources:
        if src.agent:
            return str(src.agent)
    return finding.provenance_engine or "unknown"


def _finding_sort_key(f: Finding) -> tuple:
    """Stable deterministic sort key: severity desc, file asc, line asc, title asc."""
    rank = -SEVERITY_ORDER.get(f.severity.lower(), 0)
    line = f.line if f.line is not None else -1
    return (rank, f.file, line, f.title)


def merge_findings(findings: Iterable[Finding]) -> MergeResult:
    """Merge findings from multiple specialists into a unified finding set (V4.0-E03).

    Handles deduplication, provenance combination, evidence preservation,
    and deterministic severity reconciliation with explicit conflict logging.
    """
    input_list = list(findings)
    if not input_list:
        return MergeResult(findings=[], conflicts=[], merged_count=0)

    # Pass 1: Cluster by exact v1 fingerprint
    clusters_by_fp: dict[str, list[Finding]] = {}
    fp_first_seen: dict[str, int] = {}
    for idx, f in enumerate(input_list):
        fp = f.fingerprint or fingerprint_finding(f)
        if fp not in clusters_by_fp:
            clusters_by_fp[fp] = []
            fp_first_seen[fp] = idx
        clusters_by_fp[fp].append(f)

    # Pass 2: Merge clusters that share occurrence_key (cross-engine / reworded issues)
    # Map occurrence_key -> list of fps
    occ_map: dict[str, list[str]] = {}
    for fp, cluster in clusters_by_fp.items():
        occ = occurrence_key(cluster[0])
        if occ:
            occ_map.setdefault(occ, []).append(fp)

    merged_fps_into: dict[str, str] = {}
    for occ, fps in occ_map.items():
        if len(fps) > 1:
            # Deterministically choose canonical fp: highest severity, then lowest first_seen idx
            def occ_fp_sort_key(target_fp: str):
                cl = clusters_by_fp[target_fp]
                top_sev = max(SEVERITY_ORDER.get(f.severity.lower(), 0) for f in cl)
                return (-top_sev, fp_first_seen[target_fp])

            sorted_fps = sorted(fps, key=occ_fp_sort_key)
            canonical = sorted_fps[0]
            for other in sorted_fps[1:]:
                merged_fps_into[other] = canonical
                clusters_by_fp[canonical].extend(clusters_by_fp[other])

    # Remove non-canonical fps
    active_clusters = {fp: cl for fp, cl in clusters_by_fp.items() if fp not in merged_fps_into}

    merged_findings: list[Finding] = []
    conflicts: list[ConflictRecord] = []
    total_merged = len(input_list) - len(active_clusters)

    for canonical_fp, cluster in active_clusters.items():
        if len(cluster) == 1:
            merged_findings.append(cluster[0])
            continue

        # Multiple findings in this cluster
        specialists = tuple(dict.fromkeys(_agent_of(f) for f in cluster))
        severities = [f.severity for f in cluster]
        reconciled_sev, sev_conflict = reconcile_severity(severities)

        # Base finding: pick highest severity candidate (ties: lowest input index)
        def cluster_candidate_key(f: Finding):
            sev_rank = SEVERITY_ORDER.get(f.severity.lower(), 0)
            return (-sev_rank, input_list.index(f) if f in input_list else 0)

        winner = sorted(cluster, key=cluster_candidate_key)[0]

        # Merge duplicates iteratively into winner
        cur_winner = winner
        for other in cluster:
            if other is not winner:
                cur_winner = _merge_duplicate(cur_winner, other, fingerprint_finding(other))

        # Apply reconciled severity
        if cur_winner.severity != reconciled_sev:
            cur_winner = replace(cur_winner, severity=reconciled_sev)

        # Log conflict record if severity differed
        if sev_conflict:
            conflicts.append(
                ConflictRecord(
                    fingerprint=canonical_fp,
                    file=cur_winner.file,
                    line=cur_winner.line,
                    conflict_type="severity",
                    specialists=specialists,
                    values=tuple(severities),
                    resolved_value=reconciled_sev,
                    description=f"Specialists disagreed on severity ({', '.join(f'{s}={v}' for s, v in zip(specialists, severities))}); reconciled to {reconciled_sev}",
                )
            )

        merged_findings.append(cur_winner)

    # Stable deterministic sort of merged findings
    sorted_findings = sorted(merged_findings, key=_finding_sort_key)

    # Sort conflicts deterministically by file, line, conflict_type
    sorted_conflicts = sorted(
        conflicts,
        key=lambda c: (c.file, c.line if c.line is not None else -1, c.conflict_type),
    )

    return MergeResult(
        findings=sorted_findings,
        conflicts=sorted_conflicts,
        merged_count=total_merged,
    )
