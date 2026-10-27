"""V4.2-E04-T03 — architecture drift versus a previous snapshot.

ASSUMPTION (flagged to the merge reviewer): the plan names the V4-E06
digital-twin snapshot as the comparison baseline, but no twin exists in the
tree at this baseline. This module therefore defines the *smallest neutral
snapshot contract* the drift logic needs — a versioned, hash-protected,
JSON-serializable dict — and compares two of them. A future twin adapter
only has to produce/consume :func:`snapshot_to_dict` /
:func:`snapshot_from_dict` payloads; nothing here reads or writes storage,
and the review pipeline passes no previous snapshot today, so drift is
inert (absent baseline ⇒ no-op, never a guess).

Snapshot schema v1 (stable, additive-only after release)::

    {"version": 1, "model_digest": "<16 hex>", "complete": bool,
     "layer_edges": [[src_layer, dst_layer, count], ...],
     "violations": [[importer, imported], ...],      # capped
     "digest": "<16 hex over the fields above>"}

Rules: snapshots built under different architecture models are *not
comparable* (the owner changed the rules, which is not code drift);
"resolved" claims are only made when the current snapshot is complete, so
a truncated analysis can never congratulate itself.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .checker import Edge, check_layers, project_layer_edges
from .schema import ArchitectureModel

SNAPSHOT_VERSION = 1
MAX_SNAPSHOT_VIOLATIONS = 500
MAX_SNAPSHOT_LAYER_EDGES = 1024
MAX_PATH_CHARS = 300


@dataclass(frozen=True)
class ArchitectureSnapshot:
    model_digest: str
    complete: bool
    layer_edges: tuple[tuple[str, str, int], ...] = ()
    violations: tuple[tuple[str, str], ...] = ()
    version: int = SNAPSHOT_VERSION

    def _payload(self) -> dict:
        return {
            "version": self.version,
            "model_digest": self.model_digest,
            "complete": self.complete,
            "layer_edges": [list(e) for e in self.layer_edges],
            "violations": [list(v) for v in self.violations],
        }

    @property
    def digest(self) -> str:
        blob = json.dumps(self._payload(), sort_keys=True,
                          separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class DriftReport:
    comparable: bool
    reason: str = ""
    new_layer_edges: tuple[tuple[str, str], ...] = ()
    removed_layer_edges: tuple[tuple[str, str], ...] = ()
    new_violations: tuple[tuple[str, str], ...] = ()
    resolved_violations: tuple[tuple[str, str], ...] = ()


def build_snapshot(model: ArchitectureModel, edges, *,
                   complete: bool = True) -> ArchitectureSnapshot:
    """Project the whole base graph onto layers. Deterministic and bounded;
    privacy-baseline edges are excluded exactly as in a review run. The
    snapshot is marked incomplete when the index was truncated or the
    violation list hit its own cap."""
    edges = list(edges)
    result = check_layers(model, edges, index_complete=complete,
                          max_violations=MAX_SNAPSHOT_VIOLATIONS)
    counts = project_layer_edges(model, edges)
    layer_edges = tuple((s, d, n) for (s, d), n in sorted(counts.items())
                        )[:MAX_SNAPSHOT_LAYER_EDGES]
    return ArchitectureSnapshot(
        model_digest=model.digest(),
        complete=complete and not result.truncated
        and len(counts) <= MAX_SNAPSHOT_LAYER_EDGES,
        layer_edges=layer_edges,
        violations=tuple(sorted((v.importer, v.imported)
                                for v in result.violations)))


def snapshot_to_dict(snap: ArchitectureSnapshot) -> dict:
    d = snap._payload()
    d["digest"] = snap.digest
    return d


def snapshot_from_dict(data: object) -> ArchitectureSnapshot | None:
    """Lenient, validating reader for a payload from an outside store.
    Returns ``None`` (never raises) for anything malformed, over-sized, of
    an unknown version, or whose integrity hash does not match — a tampered
    or foreign snapshot is treated as absent, not trusted."""
    try:
        if not isinstance(data, dict) or data.get("version") != SNAPSHOT_VERSION:
            return None
        md = data.get("model_digest")
        if not isinstance(md, str) or not (1 <= len(md) <= 64):
            return None
        complete = data.get("complete")
        if not isinstance(complete, bool):
            return None
        le = data.get("layer_edges")
        vs = data.get("violations")
        if not isinstance(le, list) or not isinstance(vs, list):
            return None
        if len(le) > MAX_SNAPSHOT_LAYER_EDGES or len(vs) > MAX_SNAPSHOT_VIOLATIONS:
            return None
        layer_edges = []
        for item in le:
            if (not isinstance(item, list) or len(item) != 3
                    or not isinstance(item[0], str)
                    or not isinstance(item[1], str)
                    or isinstance(item[2], bool)
                    or not isinstance(item[2], int) or item[2] < 0):
                return None
            layer_edges.append((item[0], item[1], item[2]))
        violations = []
        for item in vs:
            if (not isinstance(item, list) or len(item) != 2
                    or not all(isinstance(x, str) and len(x) <= MAX_PATH_CHARS
                               for x in item)):
                return None
            violations.append((item[0], item[1]))
        snap = ArchitectureSnapshot(
            model_digest=md, complete=complete,
            layer_edges=tuple(layer_edges), violations=tuple(violations))
        if data.get("digest") != snap.digest:
            return None
        return snap
    except Exception:  # noqa: BLE001 — a bad stored snapshot is "absent"
        return None


def compute_drift(current: ArchitectureSnapshot,
                  previous: ArchitectureSnapshot | None) -> DriftReport:
    if previous is None:
        return DriftReport(comparable=False, reason="no previous snapshot")
    if previous.model_digest != current.model_digest:
        return DriftReport(
            comparable=False,
            reason="architecture description changed since the snapshot")
    cur_le = {(s, d) for s, d, _ in current.layer_edges}
    prev_le = {(s, d) for s, d, _ in previous.layer_edges}
    cur_v, prev_v = set(current.violations), set(previous.violations)
    resolved = ()
    removed = ()
    if current.complete:
        removed = tuple(sorted(prev_le - cur_le))
        resolved = tuple(sorted(prev_v - cur_v))
    return DriftReport(
        comparable=True,
        reason="" if current.complete else
        "current analysis is partial: removals/resolutions not reported",
        new_layer_edges=tuple(sorted(cur_le - prev_le)),
        removed_layer_edges=removed,
        new_violations=tuple(sorted(cur_v - prev_v)),
        resolved_violations=resolved)


__all__ = [
    "ArchitectureSnapshot", "DriftReport", "SNAPSHOT_VERSION", "Edge",
    "build_snapshot", "compute_drift", "snapshot_from_dict", "snapshot_to_dict",
]
