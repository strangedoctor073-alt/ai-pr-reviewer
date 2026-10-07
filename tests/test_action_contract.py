"""V3-E05-T03 — frozen public contract of the GitHub Action.

Freezes ``action.yml``'s inputs/outputs (names, required flags, defaults)
plus the example workflow's security invariants and the exit-code contract,
so any breaking change fails CI here first:

* **renaming/removing/renumbering a default** fails the snapshot test;
* **adding** an input/output also fails until this snapshot is updated in
  the same change — that is the deliberate, reviewed diff;
* descriptions are *presence*-frozen (must stay non-empty) rather than
  text-frozen, so cosmetic wording edits stay green while a deleted
  description — which is the user-facing contract — does not.

Exit codes are enumerated behaviourally below (0 clean / 1 config error /
2 fail-on threshold). The report-JSON half of the compatibility contract
lives in ``tests/test_report_schema.py``; together they are the
machine-checkable half of ``docs/planning/MIGRATION_PLAN.md`` §1.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

ACTION_YML = ROOT / "action.yml"
EXAMPLE_WORKFLOW = ROOT / "example-workflow.yml"

# The frozen contract: input name -> (required, default).
# `github_token` is the only required input; every other default mirrors
# the engine's fallback (see ai_pr_reviewer/config.py) and is asserted here
# so changing either side without the other fails.
INPUTS_SNAPSHOT: dict[str, tuple[bool, str | None]] = {
    "github_token": (True, None),
    "pr_number": (False, ""),
    "anthropic_api_key": (False, ""),
    "openai_api_key": (False, ""),
    "gemini_api_key": (False, ""),
    "openai_base_url": (False, ""),
    "model": (False, ""),
    "severity_threshold": (False, ""),
    "max_comments": (False, "20"),
    "batch_chars": (False, "80000"),
    "review_mode": (False, "automatic"),
    "exclude": (False, ""),
    "focus": (False, ""),
    "fail_on": (False, "never"),
    "mock": (False, "false"),
    "no_comment": (False, "false"),
    "dashboard_url": (False, ""),
    "dashboard_token": (False, ""),
    "output": (False, "review-report.json"),
    "provider_order": (False, ""),
    "repo_context_chars": (False, "12000"),
}

# The frozen contract: declared outputs (sorted).
OUTPUTS_SNAPSHOT = [
    "critical_count",
    "findings_count",
    "health_grade",
    "health_score",
    "report_path",
]


def _action() -> dict:
    return yaml.safe_load(ACTION_YML.read_text(encoding="utf-8"))


def _inputs() -> dict[str, tuple[bool, str | None]]:
    raw = _action()["inputs"]
    return {name: (bool(spec.get("required", False)), spec.get("default"))
            for name, spec in raw.items()}


# ------------------------------------------------------------------ snapshots
def test_inputs_match_the_frozen_snapshot():
    """Renaming/removing an input, changing `required`, or changing a
    default fails here. Adding one fails too — until INPUTS_SNAPSHOT is
    updated in the same change (the reviewed, deliberate diff)."""
    actual = _inputs()
    assert set(actual) == set(INPUTS_SNAPSHOT), (
        "action.yml inputs changed — update INPUTS_SNAPSHOT deliberately:\n"
        f"  added:   {sorted(set(actual) - set(INPUTS_SNAPSHOT))}\n"
        f"  removed: {sorted(set(INPUTS_SNAPSHOT) - set(actual))}")
    for name, spec in INPUTS_SNAPSHOT.items():
        assert actual[name] == spec, (
            f"input {name!r} contract changed: {actual[name]} != {spec}")


def test_outputs_match_the_frozen_snapshot():
    actual = sorted(_action()["outputs"])
    assert actual == OUTPUTS_SNAPSHOT, (
        "action.yml outputs changed — update OUTPUTS_SNAPSHOT deliberately:\n"
        f"  added:   {sorted(set(actual) - set(OUTPUTS_SNAPSHOT))}\n"
        f"  removed: {sorted(set(OUTPUTS_SNAPSHOT) - set(actual))}")


def test_every_input_and_output_still_documents_itself():
    """Descriptions are the user-facing contract: they must exist and not
    be empty (wording itself stays free for cosmetic edits)."""
    for name, spec in _action()["inputs"].items():
        desc = spec.get("description")
        assert isinstance(desc, str) and desc.strip(), f"input {name!r} has no description"
    for name, spec in _action()["outputs"].items():
        desc = spec.get("description")
        assert isinstance(desc, str) and desc.strip(), f"output {name!r} has no description"


# ------------------------------------------------------------- plumbing pairs
def test_action_inputs_and_env_plumbing_agree():
    """Every declared input is exported as ``INPUT_<NAME>`` for the engine,
    and every exported ``INPUT_*`` belongs to a declared input — a one-way
    wiring (input nobody reads, or env var nobody declared) fails here."""
    action = _action()
    inputs = set(action["inputs"])
    steps = action["runs"]["steps"]
    review = next(s for s in steps if s.get("id") == "review")
    exported = {k for k in review["env"] if k.startswith("INPUT_")}

    assert exported == {f"INPUT_{name.upper()}" for name in inputs}
    assert action["runs"]["using"] == "composite"


def test_cli_writes_exactly_the_declared_outputs():
    """The outputs declared in action.yml must be the ones the engine
    actually writes to ``$GITHUB_OUTPUT`` — a declared-but-never-written
    output (a v2-era bug class) or an undeclared one fails here."""
    source = (ROOT / "ai_pr_reviewer" / "cli.py").read_text(encoding="utf-8")
    written = set(re.findall(r'_set_github_output\(\s*"([a-z_]+)"', source))
    assert written == set(OUTPUTS_SNAPSHOT)


# ------------------------------------------------- example workflow invariants
def test_example_workflow_security_invariants():
    """The example workflow is copy-pasted into user repos, so its security
    posture is part of the contract: `pull_request` trigger (never
    `pull_request_target`), PR-base checkout with no persisted credentials,
    minimal permissions (no `checks: write`), and a major-version pin."""
    text = EXAMPLE_WORKFLOW.read_text(encoding="utf-8")

    data = yaml.safe_load(text)
    # PyYAML parses the bare key `on` as boolean True (YAML 1.1).
    triggers = data.get("on", data.get(True))
    assert set(triggers) == {"pull_request"}
    # The file may *mention* pull_request_target only to forbid it (that's
    # the standing comment at the top) — as a trigger it never appears.
    assert "pull_request_target" not in triggers

    job = data["jobs"]["review"]
    # The example declares permissions at workflow level; accept either
    # scope but assert the exact minimal grant (no `checks: write` etc.).
    perms = data.get("permissions") or job.get("permissions")
    assert perms == {"contents": "read", "pull-requests": "write"}
    assert "checks" not in perms

    checkout = next(s for s in job["steps"]
                    if str(s.get("uses", "")).startswith("actions/checkout"))
    assert checkout["with"]["ref"] == "${{ github.event.pull_request.base.sha }}"
    assert checkout["with"]["persist-credentials"] is False

    runner = next(s for s in job["steps"]
                  if str(s.get("uses", "")).startswith("strangedoctor073-alt/"))
    assert re.fullmatch(r"strangedoctor073-alt/ai-pr-reviewer@v\d+",
                        runner["uses"]), (
        "pin a major version tag, never a branch or a moving ref")


def test_no_shipped_workflow_uses_pull_request_target():
    """Repo-wide: none of our own workflows (nor the example) may ever TRIGGER
    on `pull_request_target` — it executes untrusted code with secrets.
    Structural check (parsed triggers, not text): comments are allowed to
    mention the trigger only to warn against it."""
    offenders = []
    paths = [EXAMPLE_WORKFLOW, *sorted((ROOT / ".github" / "workflows").glob("*.yml"))]
    for path in paths:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        triggers = data.get("on", data.get(True)) or {}
        if isinstance(triggers, str):
            triggers = {triggers}
        if "pull_request_target" in triggers:
            offenders.append(path.name)
    assert not offenders, f"pull_request_target triggered in: {offenders}"


# ------------------------------------------------------------------ exit codes
def test_exit_codes_are_zero_one_two(monkeypatch, tmp_path):
    """Enumerate the exit-code contract (0 clean, 1 config error,
    2 fail_on threshold reached) end to end. Status 1 is also asserted as a
    real process status by tests/test_config.py's subprocess test."""
    from ai_pr_reviewer import cli

    # Hermetic: no leftover env layer may flip these runs.
    for var in ("INPUT_PR_NUMBER", "INPUT_MAX_COMMENTS", "INPUT_BATCH_CHARS",
                "INPUT_REPO_CONTEXT_CHARS", "INPUT_RETENTION_DAYS",
                "INPUT_FAIL_ON", "INPUT_DASHBOARD_URL", "INPUT_DASHBOARD_TOKEN",
                "DASHBOARD_TOKEN"):
        monkeypatch.delenv(var, raising=False)

    diff = tmp_path / "bad.diff"
    diff.write_text(
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -0,0 +1,3 @@\n"
        "+result = eval(user_input)\n"
        "+x = 1\n"
        "+y = 2\n",
        encoding="utf-8")
    out = tmp_path / "report.json"
    base = ["--diff-file", str(diff), "--repo", "a/b", "--pr", "1",
            "--mock", "--no-comment", "--output", str(out)]

    # 0 — clean run (no fail_on configured).
    assert cli.main(list(base)) == 0

    # 2 — fail_on threshold reached (the eval() finding is open + >= info).
    assert cli.main([*base, "--fail-on", "info"]) == 2

    # 1 — config error: string-valued SystemExit ⇒ status 1, no traceback.
    monkeypatch.setenv("INPUT_MAX_COMMENTS", "abc")
    with pytest.raises(SystemExit) as exc:
        cli.main([])
    assert isinstance(exc.value.code, str)
    assert str(exc.value.code).startswith("error: ")
