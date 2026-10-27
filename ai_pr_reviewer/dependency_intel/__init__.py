"""V4.2-E06 — dependency intelligence (deterministic, offline, read-only).

Library surface only: nothing here is wired into the review pipeline, adds
no Action input and changes no report field (wiring and any new finding
category are a later, human-approved integration step). Tickets: T01
manifest parsers, T02 diff-aware change detection, T03 offline advisory
interface, T04 license/staleness signals.
"""
from __future__ import annotations

from .advisories import (Advisory, AdvisoryLookup, AdvisoryMatch,
                         AdvisorySource, NullAdvisorySource,
                         SnapshotAdvisorySource, load_local_snapshot,
                         lookup_advisories)
from .changes import (ChangeReport, DependencyChange, compare_dependencies,
                      detect_dependency_changes)
from .manifests import (SUPPORTED_ECOSYSTEMS, Dependency, DependencySnapshot,
                        ManifestResult, collect_dependencies,
                        discover_manifests, manifest_ecosystem,
                        parse_manifest_text, read_manifest)
from .signals import (DependencySignal, MetadataSnapshot, SignalReport,
                      build_signals, license_class, load_local_metadata)

__all__ = [
    "Advisory", "AdvisoryLookup", "AdvisoryMatch", "AdvisorySource",
    "ChangeReport", "Dependency", "DependencyChange", "DependencySignal",
    "DependencySnapshot", "ManifestResult", "MetadataSnapshot",
    "NullAdvisorySource", "SUPPORTED_ECOSYSTEMS", "SignalReport",
    "SnapshotAdvisorySource", "build_signals", "collect_dependencies",
    "compare_dependencies", "detect_dependency_changes", "discover_manifests",
    "license_class", "load_local_metadata", "load_local_snapshot",
    "lookup_advisories", "manifest_ecosystem", "parse_manifest_text",
    "read_manifest",
]
