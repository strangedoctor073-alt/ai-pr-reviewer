"""V4.2-E04 — one entry point for the review pipeline.

``run_architecture_check`` is the only function the orchestrator calls. It
composes schema → edge collection → checker → (optional) drift → findings
and **never raises**: any failure becomes a warning and zero findings.

No-op guarantee (byte-identical output): when the ``architecture`` section
is absent, not ``enabled: true``, malformed, or the repository index is
unavailable, the outcome has no findings and — except for malformed-section
or missing-index notices — no warnings. Nothing is read beyond the trusted
rules file the orchestrator already loads.

Edges judged:

* ``base`` edges — the base-tree index graph, restricted to files this PR
  changes (the review is about the change; untouched legacy violations are
  not re-reported on every PR);
* ``diff`` edges — imports on lines the PR adds, resolved against the same
  inventory with the same resolver the index uses. These are the ones the
  base-revision index cannot know about, and they carry a line number so
  the finding anchors inline. Known limit: only the first line of a
  multi-line import statement is seen.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

from ..index.graph import _resolve
from ..index.inventory import detect_language
from ..index.limits import IndexLimits
from ..index.symbols import extract_symbols
from .checker import ORIGIN_BASE, ORIGIN_DIFF, Edge, check_layers
from .drift import (build_snapshot, compute_drift, snapshot_from_dict,
                    snapshot_to_dict)
from .findings import violation_findings
from .schema import SECTION_KEY, ArchitectureParse, parse_architecture_section

log = logging.getLogger(__name__)

MAX_ADDED_LINES_PER_FILE = 5000
MAX_DIFF_EDGES = 2000
MAX_WARNINGS = 10


@dataclass(frozen=True)
class ArchitectureOutcome:
    findings: tuple = ()
    warnings: tuple[str, ...] = ()
    snapshot: dict | None = None   # only when a previous snapshot was given


NOOP = ArchitectureOutcome()


def load_architecture_model(repo_root: str = ".",
                            filename: str = ".ai-pr-reviewer.yml"
                            ) -> ArchitectureParse:
    """Read the trusted rules file and parse only its ``architecture`` key.

    Mirrors ``rules.load_project_rules`` failure behaviour: every problem
    degrades to "no model" (rules.py already warned about unreadable or
    malformed files; this stays quiet to avoid double reporting)."""
    path = os.path.join(repo_root, filename)
    if not os.path.isfile(path):
        return ArchitectureParse(None)
    try:
        import yaml
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except Exception:  # noqa: BLE001 — reported by rules.load_project_rules
        return ArchitectureParse(None)
    if not isinstance(raw, dict) or SECTION_KEY not in raw:
        return ArchitectureParse(None)
    return parse_architecture_section(raw[SECTION_KEY], source=filename)


def base_edges(index, changed_paths) -> list[Edge]:
    changed = set(changed_paths)
    return [Edge(importer=a, imported=b, origin=ORIGIN_BASE)
            for a, b in index.edges if a in changed]


def diff_edges(files, index_paths: set[str],
               limits: IndexLimits | None = None) -> list[Edge]:
    """Edges introduced by added import lines (bounded, deterministic)."""
    limits = limits or IndexLimits()
    out: list[Edge] = []
    for fd in sorted(files, key=lambda f: f.path):
        if getattr(fd, "is_binary", False):
            continue
        language = detect_language(fd.path)
        for line_no, text in fd.added_lines()[:MAX_ADDED_LINES_PER_FILE]:
            _, specs, _ = extract_symbols(fd.path, language, text, limits)
            for spec in specs:
                target = _resolve(spec, fd.path, index_paths)
                if target is None or target == fd.path:
                    continue
                out.append(Edge(importer=fd.path, imported=target,
                                line=line_no, spec=spec,
                                origin=ORIGIN_DIFF))
                if len(out) >= MAX_DIFF_EDGES:
                    return out
    return out


def run_architecture_check(*, repo_root: str, rules_file: str, index, files,
                           scrub=None, previous_snapshot=None
                           ) -> ArchitectureOutcome:
    try:
        parsed = load_architecture_model(repo_root, rules_file)
        warnings = list(parsed.warnings)[:MAX_WARNINGS]
        model = parsed.model
        if model is None:
            return ArchitectureOutcome(warnings=tuple(warnings)) \
                if warnings else NOOP
        if index is None:
            warnings.append("architecture check skipped: repository index "
                            "unavailable")
            return ArchitectureOutcome(warnings=tuple(warnings))

        complete = getattr(index, "budget_state", "ok") == "ok"
        changed = [f.path for f in files]
        edges = [*base_edges(index, changed),
                 *diff_edges(files, set(index.paths))]
        result = check_layers(model, edges, index_complete=complete)

        new_since: frozenset = frozenset()
        snapshot_dict = None
        if previous_snapshot is not None:
            current = build_snapshot(
                model, [Edge(a, b) for a, b in index.edges],
                complete=complete)
            snapshot_dict = snapshot_to_dict(current)
            previous = snapshot_from_dict(previous_snapshot)
            drift = compute_drift(current, previous)
            if not drift.comparable:
                warnings.append(f"architecture drift not computed: "
                                f"{drift.reason}")
            else:
                new_since = frozenset(drift.new_violations)

        findings = violation_findings(
            result, model, rules_file=rules_file,
            new_since_snapshot=new_since, scrub=scrub)
        for reason in result.partial_reasons:
            warnings.append(f"architecture check partial: {reason}")
        return ArchitectureOutcome(findings=tuple(findings),
                                   warnings=tuple(warnings[:MAX_WARNINGS]),
                                   snapshot=snapshot_dict)
    except Exception as exc:  # noqa: BLE001 — opt-in feature never fails a review
        log.warning("architecture check failed: %s", type(exc).__name__)
        return ArchitectureOutcome(warnings=(
            f"architecture check failed ({type(exc).__name__}); skipped",))
