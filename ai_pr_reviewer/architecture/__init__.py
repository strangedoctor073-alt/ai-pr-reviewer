"""V4.2-E04 architecture intelligence (opt-in, default OFF).

Declarative layers in trusted ``.ai-pr-reviewer.yml`` (``architecture:``),
a deterministic dependency-direction checker over the repository index
graph, drift against a previous snapshot, and violation findings with
offending-edge evidence. No model, no network, no execution, no file
writes; absent/disabled section ⇒ silent no-op.
"""
from __future__ import annotations

from .checker import (CheckResult, Edge, Violation, check_layers,
                      project_layer_edges)
from .drift import (ArchitectureSnapshot, DriftReport, build_snapshot,
                    compute_drift, snapshot_from_dict, snapshot_to_dict)
from .findings import RULE_VIOLATION, violation_findings
from .runner import ArchitectureOutcome, run_architecture_check
from .schema import (ArchitectureModel, ArchitectureParse, Layer,
                     parse_architecture_section)

__all__ = [
    "ArchitectureModel", "ArchitectureOutcome", "ArchitectureParse",
    "ArchitectureSnapshot", "CheckResult", "DriftReport", "Edge", "Layer",
    "RULE_VIOLATION", "Violation", "build_snapshot", "check_layers",
    "compute_drift", "parse_architecture_section", "project_layer_edges",
    "run_architecture_check", "snapshot_from_dict", "snapshot_to_dict",
    "violation_findings",
]
