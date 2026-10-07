"""V3-E06-T04 — README vs the machine-checkable contract.

Documentation claims verified against the same sources the V3-E05
snapshots froze: `action.yml` (inputs/outputs/defaults), the *real*
report pipeline (`models` + `reporter`, not a mock), `config.py`'s
layering, and the example policy file under `load_project_rules`. A
failure here means the README misstates the public contract.

The example workflow's security invariants (`pull_request` trigger,
base checkout, `persist-credentials: false`) are already enforced by
`tests/test_action_contract.py::test_example_workflow_security_invariants`
and `::test_no_shipped_workflow_uses_pull_request_target`; T04 relies on
those rather than duplicating them.
"""
from __future__ import annotations

import re
import sys
import warnings
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

README = (ROOT / "README.md").read_text(encoding="utf-8")

from ai_pr_reviewer.rules import load_project_rules  # noqa: E402


def _section(start: str, text: str = README) -> str:
    """Text between `start` and the next `### ` heading."""
    i = text.index(start)
    j = text.find("\n### ", i)
    return text[i:j if j != -1 else len(text)]


def _inputs() -> dict[str, tuple[bool, str | None]]:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    return {name: (bool(spec.get("required", False)), spec.get("default"))
            for name, spec in action["inputs"].items()}


# --------------------------------------------------------------- inputs table
def test_readme_documents_every_action_input_with_its_default():
    """Every declared input appears in the README table, and every
    non-empty action default is stated on the same row."""
    section = _section("### Inputs")
    rows = re.findall(r"^\| [^|\n]+ \|.*$", section, re.M)

    documented: dict[str, str] = {}
    for row in rows:
        for name in re.findall(r"`([a-z_]+)`", row.split("|")[1]):
            documented[name] = row

    actual = _inputs()
    assert set(documented) == set(actual), (
        "README input table drifted from action.yml:\n"
        f"  missing: {sorted(set(actual) - set(documented))}\n"
        f"  extra:   {sorted(set(documented) - set(actual))}")

    for name, (_required, default) in actual.items():
        if default:  # empty default = engine fallback described in prose
            assert f"`{default}`" in documented[name], (
                f"README row for {name!r} does not state its default "
                f"{default!r}")


def test_readme_documents_every_declared_output():
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    outputs_paragraph = _section("### Inputs").split("### Report JSON")[0]
    for name in action["outputs"]:
        assert f"`{name}`" in outputs_paragraph, name


# ----------------------------------------------------------------- exit codes
def test_exit_codes_are_documented_with_their_meaning():
    line = next(l for l in README.splitlines() if l.startswith("Exit codes:"))
    for token in ("`0`", "`1`", "`2`", "clean", "config error", "fail_on"):
        assert token in line, f"exit-code line missing {token!r}: {line}"


# ------------------------------------------------------------------ report JSON
def test_readme_lists_the_required_report_and_finding_fields():
    """The Report JSON section must document exactly the fields the
    machine guard freezes — built from the real pipeline here."""
    from ai_pr_reviewer import reporter
    from ai_pr_reviewer.models import Finding, PRContext, ReviewResult

    pr = PRContext(repo="acme/api", pr_number=7, head_sha="h" * 40)
    finding = Finding(file="app/main.py", line=5, severity="high",
                      title="T", explanation="E")
    report = reporter.finalize_report(
        ReviewResult(pr=pr, mode="static", model="static-rules-v1",
                     findings=[finding]),
        report_id="readme-contract")

    section = _section("### Report JSON")
    missing = [k for k in set(report) if f"`{k}`" not in section]
    assert not missing, f"report fields undocumented in README: {missing}"

    row = report["findings"][0]
    missing_row = [k for k in set(row) if f"`{k}`" not in section]
    assert not missing_row, f"finding fields undocumented in README: {missing_row}"


# ------------------------------------------------------------ config layering
def test_readme_documents_the_layering_order_and_both_merges():
    section = _section("### Configuration layering")
    cli = section.index("CLI argument")
    env = section.index("`INPUT_*`")
    default = section.index("built-in default")
    assert cli < env < default, "layering order not stated CLI > INPUT_* > default"

    assert "Dashboard rules" in section
    assert "never overridden" in section
    assert ".ai-pr-reviewer.yml" in section
    assert "base" in section  # policy comes from the trusted base revision


# ------------------------------------------------------------- example policy
def test_example_policy_file_parses_without_warnings():
    """`.ai-pr-reviewer.yml.example` must stay schema-valid under the real
    loader: no unknown-key warning, expected values parsed."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        policy = load_project_rules(str(ROOT),
                                    filename=".ai-pr-reviewer.yml.example")

    assert policy.mode == "balanced"
    assert policy.severity_threshold == "medium"
    assert policy.rules and policy.exclude and policy.focus
    assert "**/*.lock" in policy.exclude
    noisy = [str(w.message) for w in caught
             if "unknown" in str(w.message).lower() or "invalid" in str(w.message).lower()]
    assert not noisy, f"example policy produced warnings: {noisy}"
