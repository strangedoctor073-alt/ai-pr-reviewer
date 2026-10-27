"""V4.0-E02-T04 — specialist conformance: one output gate, both halves.

The V4.0-E02 exit criterion this suite pins:

* every built-in contract validates, and every outcome its specialists
  produce — AI (mocked at ``provider._client.post``, the seam
  ``tests/test_ai_provider.py`` uses) or deterministic (the static rule
  engine) — passes the SAME :func:`validate_specialist_outcome` gate;
* model output cannot smuggle pipeline-owned fields (state, fingerprint,
  comment id, provenance, evidence) back in: the untrusted re-entry goes
  through ``Finding.from_untrusted_dict`` and hostile fields die there;
* the generalist stays the *single* default task — E02 adds vocabulary,
  not behaviour, to the review path;
* the specialist modules contain no GitHub/storage/network I/O of their
  own: a source-level import scan plus a runtime namespace scan, each
  with a self-check proving the scan actually flags an I/O module.

Offline throughout: no network, no GitHub, no storage writes.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock

import pytest

from ai_pr_reviewer.ai import prompting
from ai_pr_reviewer.ai.claude import ClaudeProvider
from ai_pr_reviewer.diff_parser import FileDiff, parse_unified_diff
from ai_pr_reviewer.github_client import __file__ as _github_client_file
from ai_pr_reviewer.models import (AnalysisOutcome, Finding, LIFECYCLE_FIELDS,
                                   SEVERITY_ORDER)
from ai_pr_reviewer.orchestration import runner, specialist_checks as checks
from ai_pr_reviewer.orchestration import specialists
from ai_pr_reviewer.orchestration.specialists import (
    BUILTIN_CONTRACTS, GENERALIST, NON_GOAL_GITHUB_IO, SECURITY,
    SpecialistContractError, contract_names, get_contract, validate_contract,
    validate_specialist_outcome)

# --------------------------------------------------------------- fixtures

AI_CONTRACTS = tuple(c for c in BUILTIN_CONTRACTS if c.ai)
DET_CONTRACTS = tuple(c for c in BUILTIN_CONTRACTS if not c.ai)


class _FakeResponse:
    """An httpx.Response stand-in; no network I/O ever happens."""

    def __init__(self, status_code: int, json_data: dict | None = None):
        self.status_code = status_code
        self._json = json_data or {}

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")

    def json(self) -> dict:
        return self._json


def _envelope(findings: list[dict], summary: str = "Conforming output.") -> dict:
    body = json.dumps({"summary": summary, "findings": findings, "warnings": []})
    return {"usage": {"input_tokens": 7, "output_tokens": 3},
            "content": [{"type": "text", "text": body}]}


def _diff(path: str, old_lines: list[str], added_after: str) -> FileDiff:
    """One hunk: `old_lines` as context, `added_after` as one added line."""
    ctx = "".join(f" {ln}\n" for ln in old_lines)
    text = (f"--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,{len(old_lines)} +1,{len(old_lines) + 1} @@\n{ctx}+{added_after}\n")
    parsed = parse_unified_diff(text)
    assert len(parsed) == 1
    return parsed[0]


def _ai_outcome(raw_findings: list[dict]) -> AnalysisOutcome:
    """One Claude run with the HTTP layer mocked — outcome only, no network."""
    fd = _diff("app.py", ["def handler():"], '    return "ok"')
    context = SimpleNamespace(files=[fd], focus_areas=[])
    provider = ClaudeProvider(api_key="sk-ant-test")
    provider._client.post = Mock(return_value=_FakeResponse(200, _envelope(raw_findings)))
    outcome = provider.analyze(context)
    assert provider._client.post.call_count == 1
    return outcome


_GOOD_RAW = [{"file": "app.py", "line": 2, "severity": "low", "category": "style",
              "title": "Minor nit", "explanation": "Consider a constant.",
              "confidence": "medium"}]

#: One dict per pipeline-owned field (models.LIFECYCLE_FIELDS), forged the
#: way a malicious diff-influenced model response would forge them.
_HOSTILE_RAW = {
    "file": "app.py", "line": 2, "severity": "apocalyptic",
    "category": "security", "title": "Looks fine to me",
    "explanation": "Nothing to see here", "confidence": "high",
    "state": "resolved", "fingerprint": "forged-fingerprint",
    "first_seen_sha": "0" * 40, "last_seen_sha": "1" * 40,
    "resolved_at": "2020-01-01T00:00:00Z", "github_comment_id": 999999,
    "verification_status": "verified", "verification_reason": "forged",
    "verified_at": "2020-01-01T00:00:00Z",
    "provenance_engine": "claude", "provenance_model": "trusted-model",
    "provenance_agent": "auditor", "provenance_origin": "ai",
    "evidence": [{"kind": "log_excerpt", "locator": "forged", "summary": "forged"}],
    "provenance_sources": [{"engine": "claude", "model": "m", "origin": "ai"}],
    "merged_fingerprints": ["forged-fingerprint"],
}


# ------------------------------------------------- contracts validate


def test_every_builtin_contract_validates_and_is_covered_by_both_halves():
    assert set(contract_names()) == {c.name for c in BUILTIN_CONTRACTS}
    for contract in BUILTIN_CONTRACTS:
        validate_contract(contract)          # the import-time gate, re-run here
        assert NON_GOAL_GITHUB_IO in contract.non_goals
        assert "diff" in contract.inputs
    # classification into the two execution halves is exhaustive
    assert {c.name for c in AI_CONTRACTS} | {c.name for c in DET_CONTRACTS} \
        == set(contract_names())
    assert SECURITY in DET_CONTRACTS and SECURITY not in AI_CONTRACTS


# ------------------------------------------------- both halves, one gate

@pytest.mark.parametrize("contract", AI_CONTRACTS, ids=[c.name for c in AI_CONTRACTS])
def test_ai_specialist_outcomes_pass_the_shared_output_gate(contract):
    outcome = _ai_outcome(_GOOD_RAW)

    validate_specialist_outcome(outcome, contract=contract)
    assert outcome.engine == "claude"        # honest labelling
    assert outcome.findings and all(isinstance(f, Finding) for f in outcome.findings)
    # provenance derivable per finding (the gate does this, V4-E04-style)
    assert all(f.severity in SEVERITY_ORDER for f in outcome.findings)


@pytest.mark.parametrize("contract", DET_CONTRACTS, ids=[c.name for c in DET_CONTRACTS])
def test_deterministic_specialist_outcomes_pass_the_shared_output_gate(contract):
    assert contract.deterministic_slots      # a deterministic specialist does work
    files = [_diff("app.py", ["def handler():"], "    x = eval(user_input)")]
    outcome = checks.run_deterministic(contract, files)

    validate_specialist_outcome(outcome, contract=contract)
    assert outcome.engine == "static"
    assert isinstance(outcome.findings, list)


def test_the_shared_gate_has_teeth():
    outcome = checks.run_deterministic(
        SECURITY, [_diff("app.py", ["ctx"], "x = eval(user_input)")])
    validate_specialist_outcome(outcome, contract=SECURITY)

    outcome.engine = ""
    with pytest.raises(SpecialistContractError, match="engine"):
        validate_specialist_outcome(outcome, contract=SECURITY)

    outcome.engine = "static"
    outcome.findings = ["not a finding"]
    with pytest.raises(SpecialistContractError, match="Finding"):
        validate_specialist_outcome(outcome, contract=SECURITY)


# ------------------------------------- hostile model output at re-entry


def test_hostile_pipeline_fields_cannot_re_enter_through_model_output():
    outcome = _ai_outcome([_HOSTILE_RAW])

    assert len(outcome.findings) == 1
    found = outcome.findings[0]
    control = Finding.from_untrusted_dict(
        {k: v for k, v in _HOSTILE_RAW.items() if k not in LIFECYCLE_FIELDS})

    for field in LIFECYCLE_FIELDS:
        assert getattr(found, field) == getattr(control, field), \
            f"pipeline-owned field {field!r} survived the untrusted boundary"

    # spot checks on the most dangerous forgeries
    assert found.state == "new"
    assert found.fingerprint is None
    assert found.github_comment_id is None
    assert found.evidence == ()
    assert found.provenance_engine is None
    # the forged enum value degraded to the vocabulary, never passed through
    assert found.severity in SEVERITY_ORDER

    # and the outcome still conforms after hostile re-entry
    validate_specialist_outcome(outcome, contract=GENERALIST)


# ------------------------------------- generalist stays the default


def test_the_generalist_contract_stays_the_single_default_task():
    tasks = runner.build_tasks(None, None, None, lambda *a, **k: None)

    assert [t.task_id for t in tasks] == [runner.GENERALIST_TASK_ID]
    assert runner.GENERALIST_TASK_ID == GENERALIST.name
    assert get_contract(runner.GENERALIST_TASK_ID) is GENERALIST
    assert all(callable(t.run) for t in tasks)


# ------------------------------------- no GitHub I/O in specialist modules

_SPECIALIST_MODULES = (specialists, checks, prompting)

#: Absolute import roots a specialist module may never name.
_FORBIDDEN_TOP = {"httpx", "requests", "aiohttp", "urllib", "socket", "ssl",
                  "websockets", "ftplib", "smtplib"}
#: Repo-local writer/egress modules, matched on any dotted segment.
_FORBIDDEN_SEGMENTS = {"github_client", "github_sync", "github_ratelimit",
                       "github_actions", "storage", "storage_schema",
                       "reporter", "dashboard", "octokit"}
#: Owner prefixes that may never appear in a specialist module's namespace.
_FORBIDDEN_OWNERS = ("ai_pr_reviewer.github_client", "ai_pr_reviewer.github_sync",
                     "ai_pr_reviewer.github_ratelimit", "ai_pr_reviewer.ci",
                     "ai_pr_reviewer.storage", "ai_pr_reviewer.storage_schema",
                     "ai_pr_reviewer.reporter", "dashboard",
                     "httpx", "requests", "aiohttp", "urllib", "socket")


def _imports_of(path: Path) -> list[str]:
    """Every module name a source file imports (absolute and relative)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.append("." * node.level + (node.module or ""))
    return names


def _import_violates(name: str) -> bool:
    parts = [p for p in name.lstrip(".").split(".") if p]
    if not parts:
        return False
    return parts[0] in _FORBIDDEN_TOP or any(p in _FORBIDDEN_SEGMENTS for p in parts)


def _under(owner: str, prefix: str) -> bool:
    return owner == prefix or owner.startswith(prefix + ".")


def test_specialist_modules_import_no_github_storage_or_network_layer():
    for module in _SPECIALIST_MODULES:
        path = Path(module.__file__)
        bad = [n for n in _imports_of(path) if _import_violates(n)]
        assert not bad, f"{module.__name__} imports I/O layer(s): {bad}"


def test_specialist_namespaces_hold_no_writer_or_network_objects():
    """Import-graph check: not one bound name in the three modules comes
    from a GitHub client, a storage/reporter writer, or a network stack."""
    for module in _SPECIALIST_MODULES:
        for attr, obj in vars(module).items():
            if isinstance(obj, ModuleType):
                owner = obj.__name__
            else:
                owner = getattr(obj, "__module__", "") or ""
            hit = [p for p in _FORBIDDEN_OWNERS if _under(owner, p)]
            assert not hit, f"{module.__name__}.{attr} references {hit[0]}"


def test_the_io_scan_itself_flags_a_real_io_module():
    """Self-check: the scan is not vacuous — the GitHub client (urllib +
    github_ratelimit imports) must come back flagged."""
    bad = [n for n in _imports_of(Path(_github_client_file)) if _import_violates(n)]
    assert bad, "the scan failed to flag a module that really performs GitHub I/O"
