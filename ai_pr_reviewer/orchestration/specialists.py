"""Specialist reviewer contracts (V4.0-E02-T02).

A specialist is declared, not implied: :class:`SpecialistContract` pins a
name, the registry task it serves, what it reads, what it must never do,
and the shape of what it returns. The schema is inert data — nothing here
changes which tasks a review runs. ``orchestration/runner.py`` still builds
exactly one generalist task, and activating a council of specialists needs
the merger (V4.0-E03) plus the council config flag; both are later epics.
This module gives them one validated vocabulary to consume.

Two halves, both enforced by :func:`validate_contract` /
:func:`validate_specialist_outcome`:

* **inputs** — the ``ReviewContext`` surfaces a specialist may read. They
  mirror exactly what the shared prompt-builder (``ai/prompting.py``) can
  put in front of a model, so a declared contract and a real prompt can
  never disagree about what the specialist saw.
* **output** — every specialist, AI or deterministic, returns an
  ``AnalysisOutcome`` whose findings are pipeline ``Finding`` objects with
  provenance the pipeline can derive (V4-E04). A deterministic specialist
  may never claim an AI engine.

Capability claims stay where V4.0-E05 put them — in
``provider_registry.ProviderSpec.tasks`` — and contracts reuse that closed
task vocabulary instead of inventing a second one. A provider may also
*declare* its capabilities instance-side via the optional
``capabilities()`` seam on ``ai/provider.py`` (ADR-007); the registry
remains the source routing consults.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from ..models import (AnalysisOutcome, Finding, derive_provenance_source,
                      describe_provenance)
from ..provider_registry import (TASK_ARCH_REVIEW, TASK_REVIEW,
                                 TASK_SECURITY_REVIEW, TASK_TEST_REVIEW,
                                 TASK_TYPES)

# --------------------------------------------------------------- vocabularies

#: Specialist names: lowercase, hyphenated, bounded — they end up in
#: provenance fields (``Finding.provenance_agent``) and warning text.
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
#: Free-text contract fields are single-line and bounded: they are
#: configuration-adjacent data, rendered by future reporters.
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_FOCUS_MAX = 160
_SCOPE_MAX = 400
_NONGOAL_MAX = 240

#: What a contract may declare it reads — the ``ReviewContext`` surfaces
#: the shared prompt-builder consumes. ``"diff"`` is mandatory: a
#: specialist that never sees the change is not reviewing it.
INPUT_VOCAB = ("diff", "focus_areas", "project_rules", "memory_notes",
               "repo_context", "impact_section")

#: The one output shape a specialist may declare today (additive later).
OUTPUT_SCHEMA_ANALYSIS = "analysis-outcome-v1"
OUTPUT_SCHEMA_VOCAB = (OUTPUT_SCHEMA_ANALYSIS,)

#: Deterministic check families a slot declares. Descriptive metadata for
#: labels/routing — never a branch condition (the static rule engine picks
#: rules by pack, not by this label).
SLOT_KINDS = ("regex", "ast", "api-shape")

#: The static rule packs a slot may scope to (``static/``'s register()
#: modules). Closed so a contract cannot name an arbitrary module.
RULE_PACKS = ("security", "python", "javascript", "shell", "test")

# ----------------------------------------------------- required non-goals
# Every contract must carry these verbatim: they are the invariants the
# conformance suite (V4.0-E02-T04) checks mechanically.

#: Exit criterion: a specialist only analyzes; the orchestrator is the
#: sole writer to GitHub.
NON_GOAL_GITHUB_IO = "no GitHub I/O: a specialist analyzes only, the orchestrator posts"
NON_GOAL_STORAGE = "no direct storage or dashboard writes"
NON_GOAL_RUNTIME_PROMPT_EDIT = "no runtime prompt or rule editing"

_REQUIRED_NON_GOALS = (NON_GOAL_GITHUB_IO,)


class SpecialistContractError(ValueError):
    """A specialist contract (or a specialist outcome) violates the schema."""


# ------------------------------------------------------------------- schema

@dataclass(frozen=True)
class DeterministicSlot:
    """One declared deterministic check family a specialist runs (T03).

    ``packs`` name static rule packs; ``kind`` documents which check
    family the slot's findings belong to (regex/AST/API-shape). The two
    are validated independently against closed vocabularies: one pack can
    implement more than one family (the security pack's ``shell=True``
    check is an API-shape check expressed as a regex), so ``kind`` is a
    label, not a filter.
    """

    name: str
    kind: str
    packs: tuple[str, ...]


@dataclass(frozen=True)
class SpecialistContract:
    """Declared identity, scope and output for one specialist reviewer.

    Frozen on purpose: contracts are configuration-adjacent data compared
    and stored by identity; a mutable contract could be re-scoped between
    validation and execution.
    """

    name: str
    task: str
    focus: str
    scope: str
    non_goals: tuple[str, ...]
    inputs: tuple[str, ...]
    output_schema: str = OUTPUT_SCHEMA_ANALYSIS
    deterministic_slots: tuple[DeterministicSlot, ...] = ()
    #: ``False`` => deterministic-only specialist: it runs its declared
    #: slots and must report ``engine == "static"``.
    ai: bool = True


def _check_text(value: Any, label: str, limit: int, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str):
        raise SpecialistContractError(f"{label} must be a string, got {type(value).__name__}")
    if _CONTROL_RE.search(value):
        raise SpecialistContractError(f"{label} must be single-line (control characters)")
    if not allow_empty and not value.strip():
        raise SpecialistContractError(f"{label} must not be empty")
    if len(value) > limit:
        raise SpecialistContractError(f"{label} exceeds {limit} characters")


def _check_tuple(value: Any, label: str) -> tuple:
    if not isinstance(value, tuple):
        raise SpecialistContractError(f"{label} must be a tuple, got {type(value).__name__}")
    return value


def validate_contract(contract: SpecialistContract) -> None:
    """Raise :class:`SpecialistContractError` unless the contract is sound.

    Everything is checked against a closed vocabulary or a restrictive
    pattern — a contract is configuration-adjacent data (like registry
    specs), never trusted because it came from this repo's code.
    """
    if not isinstance(contract, SpecialistContract):
        raise SpecialistContractError(
            f"expected SpecialistContract, got {type(contract).__name__}")
    name = contract.name
    if not isinstance(name, str) or not _NAME_RE.match(name):
        raise SpecialistContractError(
            "name must match [a-z][a-z0-9-]{0,31}")
    if contract.task not in TASK_TYPES:
        raise SpecialistContractError(
            f"{name}: unknown task {contract.task!r}; known: {list(TASK_TYPES)}")

    _check_text(contract.focus, f"{name}: focus", _FOCUS_MAX)
    _check_text(contract.scope, f"{name}: scope", _SCOPE_MAX)

    non_goals = _check_tuple(contract.non_goals, f"{name}: non_goals")
    if not non_goals:
        raise SpecialistContractError(f"{name}: non_goals must not be empty")
    for goal in non_goals:
        _check_text(goal, f"{name}: non_goals entry", _NONGOAL_MAX)
    for required in _REQUIRED_NON_GOALS:
        if required not in non_goals:
            raise SpecialistContractError(
                f"{name}: non_goals must carry {required!r} verbatim "
                "(the no-GitHub-I/O invariant)")

    inputs = _check_tuple(contract.inputs, f"{name}: inputs")
    if not inputs:
        raise SpecialistContractError(f"{name}: inputs must not be empty")
    unknown = [i for i in inputs if i not in INPUT_VOCAB]
    if unknown:
        raise SpecialistContractError(
            f"{name}: unknown input(s) {unknown}; known: {list(INPUT_VOCAB)}")
    if len(set(inputs)) != len(inputs):
        raise SpecialistContractError(f"{name}: duplicate inputs")
    if "diff" not in inputs:
        raise SpecialistContractError(
            f"{name}: inputs must include 'diff' (a specialist that never "
            "sees the change is not reviewing it)")

    if contract.output_schema not in OUTPUT_SCHEMA_VOCAB:
        raise SpecialistContractError(
            f"{name}: unknown output_schema {contract.output_schema!r}; "
            f"known: {list(OUTPUT_SCHEMA_VOCAB)}")
    if not isinstance(contract.ai, bool):
        raise SpecialistContractError(f"{name}: ai must be a bool")

    slots = _check_tuple(contract.deterministic_slots, f"{name}: deterministic_slots")
    seen: set[str] = set()
    for slot in slots:
        if not isinstance(slot, DeterministicSlot):
            raise SpecialistContractError(
                f"{name}: slot must be DeterministicSlot, got {type(slot).__name__}")
        if not isinstance(slot.name, str) or not _NAME_RE.match(slot.name):
            raise SpecialistContractError(
                f"{name}: slot name {slot.name!r} must match [a-z][a-z0-9-]{{0,31}}")
        if slot.name in seen:
            raise SpecialistContractError(f"{name}: duplicate slot name {slot.name!r}")
        seen.add(slot.name)
        if slot.kind not in SLOT_KINDS:
            raise SpecialistContractError(
                f"{name}: slot {slot.name!r}: unknown kind {slot.kind!r}; "
                f"known: {list(SLOT_KINDS)}")
        packs = _check_tuple(slot.packs, f"{name}: slot {slot.name!r} packs")
        if not packs:
            raise SpecialistContractError(
                f"{name}: slot {slot.name!r} must scope at least one rule pack")
        bad = [p for p in packs if p not in RULE_PACKS]
        if bad:
            raise SpecialistContractError(
                f"{name}: slot {slot.name!r}: unknown pack(s) {bad}; "
                f"known: {list(RULE_PACKS)}")
        if len(set(packs)) != len(packs):
            raise SpecialistContractError(
                f"{name}: slot {slot.name!r} repeats a pack")
    if not contract.ai and not slots:
        raise SpecialistContractError(
            f"{name}: a deterministic specialist (ai=False) needs at least "
            "one deterministic slot — otherwise it does nothing")


def validate_specialist_outcome(outcome: Any,
                                *, contract: SpecialistContract | None = None) -> None:
    """The output half of the contract: every specialist returns one shape.

    Shared by AI and deterministic specialists (T04 conformance runs both
    through here): an ``AnalysisOutcome`` carrying real ``Finding`` objects
    whose provenance the pipeline can derive without raising (V4-E04), and
    — when the contract is deterministic — an engine label that cannot
    claim an AI review it did not do.
    """
    if not isinstance(outcome, AnalysisOutcome):
        raise SpecialistContractError(
            f"specialist outcome must be AnalysisOutcome, got {type(outcome).__name__}")
    if not isinstance(outcome.findings, list) or not all(
            isinstance(f, Finding) for f in outcome.findings):
        raise SpecialistContractError("specialist outcome findings must be Finding objects")
    if not isinstance(outcome.summary, str):
        raise SpecialistContractError("specialist outcome summary must be a string")
    if not isinstance(outcome.warnings, list) or not all(
            isinstance(w, str) for w in outcome.warnings):
        raise SpecialistContractError("specialist outcome warnings must be strings")
    if not isinstance(outcome.engine, str) or not outcome.engine:
        raise SpecialistContractError(
            "specialist outcome must label its engine honestly (non-empty)")
    if not isinstance(outcome.model, str) or not outcome.model:
        raise SpecialistContractError("specialist outcome must name its model")

    # Provenance must be derivable for every finding — this is the check
    # that keeps a specialist's output compatible with the V4-E04 stamping
    # path; it never mutates the finding, it only proves the pipeline can.
    for finding in outcome.findings:
        derive_provenance_source(finding, outcome_engine=outcome.engine,
                                 outcome_model=outcome.model)
        describe_provenance(finding)

    if contract is not None and not contract.ai and outcome.engine != "static":
        raise SpecialistContractError(
            f"specialist {contract.name!r} is deterministic (ai=False) but "
            f"labelled engine={outcome.engine!r} — it must report 'static'")


# ------------------------------------------------------------ built-in set

def _install(contracts: tuple[SpecialistContract, ...]) -> tuple[SpecialistContract, ...]:
    """Validate every contract and reject duplicate names, fail-fast."""
    names: set[str] = set()
    for contract in contracts:
        validate_contract(contract)
        if contract.name in names:
            raise SpecialistContractError(f"duplicate contract name {contract.name!r}")
        names.add(contract.name)
    return contracts


#: The v1 default: exactly the pre-V4.0 single-agent review, declared so the
#: fan-out layer has a contract to name its one task.
GENERALIST = SpecialistContract(
    name="generalist",
    task=TASK_REVIEW,
    focus="whole-change review: every added line, one coherent opinion",
    scope="the full diff plus every untrusted block the pipeline assembles "
          "(memory, repository context, impact, focus areas)",
    non_goals=(NON_GOAL_GITHUB_IO, NON_GOAL_STORAGE, NON_GOAL_RUNTIME_PROMPT_EDIT),
    inputs=INPUT_VOCAB,
)

#: Deterministic security specialist: a thin scope over the existing static
#: SEC rule pack — the V4.0 non-goal "no security deep scan" made explicit.
SECURITY = SpecialistContract(
    name="security",
    task=TASK_SECURITY_REVIEW,
    focus="security patterns in added lines (thin scope over the static "
          "SEC rule pack)",
    scope="added lines the security rule pack matches; no dataflow, no "
          "deep scan — evidence is the matched rule and the matched line",
    non_goals=(NON_GOAL_GITHUB_IO, NON_GOAL_STORAGE, NON_GOAL_RUNTIME_PROMPT_EDIT),
    inputs=("diff",),
    deterministic_slots=(
        DeterministicSlot(name="security-regex", kind="regex",
                          packs=("security",)),
    ),
    ai=False,
)

TESTS = SpecialistContract(
    name="tests",
    task=TASK_TEST_REVIEW,
    focus="test coverage and test-quality signals for this change",
    scope="the diff and the sibling test files it introduces; the AI pass "
          "judges coverage, the deterministic test pack stays available as "
          "a slot",
    non_goals=(NON_GOAL_GITHUB_IO, NON_GOAL_STORAGE, NON_GOAL_RUNTIME_PROMPT_EDIT),
    inputs=INPUT_VOCAB,
)

ARCHITECTURE = SpecialistContract(
    name="architecture",
    task=TASK_ARCH_REVIEW,
    focus="architectural shape of the change: layering and module boundaries",
    scope="file placement, import direction and public surface touched by "
          "the diff",
    non_goals=(NON_GOAL_GITHUB_IO, NON_GOAL_STORAGE, NON_GOAL_RUNTIME_PROMPT_EDIT),
    inputs=INPUT_VOCAB,
)

#: Every built-in contract, validated at import. ``synthesis`` is absent on
#: purpose: the registry declares that capability when its consumer ships
#: (see ``provider_registry``), and a contract without a consumer would be
#: a promise, not a schema.
BUILTIN_CONTRACTS = _install((GENERALIST, SECURITY, TESTS, ARCHITECTURE))


def contract_names() -> tuple[str, ...]:
    return tuple(c.name for c in BUILTIN_CONTRACTS)


def get_contract(name: str) -> SpecialistContract:
    """One contract by name; unknown names are a configuration error."""
    for contract in BUILTIN_CONTRACTS:
        if contract.name == name:
            return contract
    raise SpecialistContractError(
        f"unknown specialist contract {name!r}; known: {list(contract_names())}")


def contracts_for_task(task: str) -> tuple[SpecialistContract, ...]:
    """Contracts declared for one registry task type (may be empty)."""
    return tuple(c for c in BUILTIN_CONTRACTS if c.task == task)
