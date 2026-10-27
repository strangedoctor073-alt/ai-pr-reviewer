"""V4.0-E02-T02 — specialist contract schema and the capabilities seam.

Pure data + validation: no network, no orchestrator run. The schema tests
are deliberately hostile — a contract is configuration-adjacent data, so
every field is probed with values from outside its vocabulary.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from ai_pr_reviewer.ai.claude import ClaudeProvider
from ai_pr_reviewer.ai.gemini import GeminiProvider
from ai_pr_reviewer.ai.openai import OpenAIProvider
from ai_pr_reviewer.ai.provider import AIProvider, capabilities_of
from ai_pr_reviewer.models import AnalysisOutcome, Finding
from ai_pr_reviewer.model_router import StaticProvider
from ai_pr_reviewer.orchestration.specialists import (
    ARCHITECTURE, BUILTIN_CONTRACTS, GENERALIST, INPUT_VOCAB, NON_GOAL_GITHUB_IO,
    RULE_PACKS, SECURITY, SLOT_KINDS, TESTS, DeterministicSlot, SpecialistContract,
    SpecialistContractError, contract_names, contracts_for_task, get_contract,
    validate_contract, validate_specialist_outcome)
from ai_pr_reviewer.provider_registry import (TASK_REVIEW, TASK_SECURITY_REVIEW,
                                              TASK_TYPES, get_spec)


def _contract(**overrides) -> SpecialistContract:
    base = dict(
        name="demo",
        task=TASK_REVIEW,
        focus="demo focus",
        scope="demo scope",
        non_goals=(NON_GOAL_GITHUB_IO,),
        inputs=("diff",),
    )
    base.update(overrides)
    return SpecialistContract(**base)


# ------------------------------------------------------------- happy paths

def test_every_builtin_contract_is_valid_and_named_once():
    names = contract_names()
    assert len(names) == len(set(names)) == len(BUILTIN_CONTRACTS)
    for contract in BUILTIN_CONTRACTS:
        validate_contract(contract)          # raises on violation
        assert contract.task in TASK_TYPES
        assert NON_GOAL_GITHUB_IO in contract.non_goals
        assert "diff" in contract.inputs


def test_builtins_cover_the_registry_tasks_the_registry_claims():
    """Contracts confirm (or narrow) provider_registry's task claims."""
    assert contracts_for_task(TASK_REVIEW) == (GENERALIST,)
    assert contracts_for_task(TASK_SECURITY_REVIEW) == (SECURITY,)
    assert contracts_for_task("test-review") == (TESTS,)
    assert contracts_for_task("arch-review") == (ARCHITECTURE,)
    assert contracts_for_task("synthesis") == ()     # no consumer yet


def test_security_specialist_is_the_deterministic_thin_scope():
    """V4.0 non-goal: security exists only as a scope over static SEC rules."""
    assert SECURITY.ai is False
    assert SECURITY.inputs == ("diff",)
    assert [s.kind for s in SECURITY.deterministic_slots] == ["regex"]
    assert SECURITY.deterministic_slots[0].packs == ("security",)


def test_get_contract_roundtrip_and_unknown_name():
    assert get_contract("generalist") is GENERALIST
    with pytest.raises(SpecialistContractError, match="unknown specialist"):
        get_contract("nope")


# ---------------------------------------------------- hostile schema inputs

@pytest.mark.parametrize("overrides", [
    {"name": "Security"},                     # uppercase
    {"name": "has space"},                    # space
    {"name": "x" * 33},                       # too long
    {"task": "not-a-task"},                   # outside registry vocabulary
    {"focus": ""},                            # empty
    {"focus": "line\nbreak"},                 # control character
    {"focus": "x" * 161},                     # over bound
    {"scope": "x" * 401},                     # over bound
    {"non_goals": ()},                        # empty
    {"non_goals": ("some prose without the invariant",)},  # missing invariant
    {"non_goals": [NON_GOAL_GITHUB_IO]},       # list, not tuple
    {"inputs": ()},                           # empty
    {"inputs": ("diff", "bogus")},            # unknown surface
    {"inputs": ("focus_areas",)},             # never sees the diff
    {"inputs": ("diff", "diff")},             # duplicate
    {"inputs": ["diff"]},                     # list, not tuple
    {"output_schema": "free-form-v9"},        # unknown schema
    {"ai": "yes"},                            # not a bool
    {"deterministic_slots": ("security-regex",)},  # not DeterministicSlot
    {"deterministic_slots": (DeterministicSlot("s1", "regex", ("security",)),
                             DeterministicSlot("s1", "ast", ("python",)))},  # dup name
    {"deterministic_slots": (DeterministicSlot("s1", "heuristics", ("security",)),)},
    {"deterministic_slots": (DeterministicSlot("s1", "regex", ("bogus",))),},
    {"deterministic_slots": (DeterministicSlot("s1", "regex", ()),)},
    {"deterministic_slots": (DeterministicSlot("s1", "regex", ("security", "security")),)
    },                                        # repeated pack
    {"ai": False, "deterministic_slots": ()},  # deterministic but idle
])
def test_invalid_contracts_are_rejected(overrides):
    with pytest.raises(SpecialistContractError):
        validate_contract(_contract(**overrides))


def test_non_specialist_objects_are_rejected():
    with pytest.raises(SpecialistContractError, match="expected SpecialistContract"):
        validate_contract(SimpleNamespace(name="x"))


def test_vocabularies_are_closed_and_bounded():
    assert INPUT_VOCAB == ("diff", "focus_areas", "project_rules", "memory_notes",
                           "repo_context", "impact_section")
    assert SLOT_KINDS == ("regex", "ast", "api-shape")
    assert set(RULE_PACKS) >= {"security", "python", "test"}
    # every slot of every builtin uses only the closed vocabularies
    for contract in BUILTIN_CONTRACTS:
        for slot in contract.deterministic_slots:
            assert slot.kind in SLOT_KINDS
            assert all(p in RULE_PACKS for p in slot.packs)


# ------------------------------------------------------- outcome contract

def _outcome(*, engine="static", model="static-rules-v1"):
    finding = Finding(file="a.py", line=3, severity="high", title="t",
                      explanation="because")
    return AnalysisOutcome(findings=[finding], summary="done", mode="static",
                           model=model, engine=engine)


def test_a_valid_deterministic_outcome_passes():
    validate_specialist_outcome(_outcome(), contract=SECURITY)


def test_an_ai_labelled_outcome_passes_for_an_ai_contract():
    validate_specialist_outcome(_outcome(engine="claude", model="m"),
                                contract=GENERALIST)


@pytest.mark.parametrize("bad", [
    SimpleNamespace(findings=[], summary="", mode="", model="", engine="static"),
    "not an outcome",
])
def test_non_outcomes_are_rejected(bad):
    with pytest.raises(SpecialistContractError, match="AnalysisOutcome"):
        validate_specialist_outcome(bad)


def test_findings_must_be_finding_objects():
    outcome = _outcome()
    outcome.findings = [SimpleNamespace(file="a.py")]
    with pytest.raises(SpecialistContractError, match="Finding"):
        validate_specialist_outcome(outcome)


def test_engine_label_must_be_present():
    outcome = _outcome()
    outcome.engine = ""
    with pytest.raises(SpecialistContractError, match="engine"):
        validate_specialist_outcome(outcome)


def test_a_deterministic_specialist_cannot_claim_an_ai_engine():
    """Honest labelling: ai=False means the rule engine ran, nothing else."""
    with pytest.raises(SpecialistContractError, match="must report 'static'"):
        validate_specialist_outcome(_outcome(engine="claude", model="m"),
                                    contract=SECURITY)


def test_a_degraded_ai_run_that_truly_fell_back_to_static_is_allowed():
    """engine="static" on an AI contract is the honest all-batches-failed
    label — allowed (the contract only forbids lying upward)."""
    validate_specialist_outcome(_outcome(), contract=GENERALIST)


# ------------------------------------------------------ capabilities seam

class _Declaring:
    def capabilities(self):
        return ["review", "security-review"]     # list: normalized below


class _NonIterable:
    def capabilities(self):
        return "review"


def test_capabilities_of_reads_optional_declarations():
    assert capabilities_of(_Declaring()) == frozenset({"review", "security-review"})


def test_capabilities_of_distinguishes_undeclared_from_empty():
    class _Empty:
        def capabilities(self):
            return frozenset()

    assert capabilities_of(object()) is None          # never declared
    assert capabilities_of(_Empty()) == frozenset()   # declares nothing


def test_capabilities_of_rejects_a_non_iterable_declaration():
    with pytest.raises(TypeError, match="iterable"):
        capabilities_of(_NonIterable())


def test_in_tree_providers_declare_exactly_their_registry_tasks():
    for provider in (ClaudeProvider(api_key="sk-ant-test"),
                     OpenAIProvider(api_key="sk-test", model="gpt-test"),
                     GeminiProvider(api_key="AIza-test", model="gemini-test")):
        spec = get_spec(provider.backend)
        assert spec is not None
        assert provider.capabilities() == frozenset(spec.tasks)
        assert provider.capabilities() <= set(TASK_TYPES)
        assert capabilities_of(provider) == provider.capabilities()


def test_static_provider_declares_nothing_and_still_satisfies_the_protocol():
    static = StaticProvider()
    assert capabilities_of(static) is None       # registry owns its tasks
    assert isinstance(static, AIProvider)        # seam unchanged (E02 must not break it)


def test_capabilities_stays_out_of_the_protocol_members():
    """capabilities() is an optional convention, not a Protocol member —
    runtime_checkable isinstance would otherwise make it mandatory for
    every implementation (StaticProvider included)."""
    assert "analyze" in AIProvider.__dict__           # the one required member
    assert "capabilities" not in AIProvider.__dict__  # optional by design
