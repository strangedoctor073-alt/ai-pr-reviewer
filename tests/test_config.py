"""Tests for GitHub Action input configuration."""
from __future__ import annotations

import pytest

from ai_pr_reviewer.cli import parse_args
from ai_pr_reviewer.config import ConfigError, load_config


def test_action_pr_number_and_focus_inputs(monkeypatch):
    monkeypatch.setenv("INPUT_PR_NUMBER", "42")
    monkeypatch.setenv("INPUT_FOCUS", "security\ncorrectness\n")

    cfg = load_config(parse_args([]))

    assert cfg.pr_number == 42
    assert cfg.focus_areas == ["security", "correctness"]


def test_cli_values_override_action_inputs(monkeypatch):
    monkeypatch.setenv("INPUT_PR_NUMBER", "42")
    monkeypatch.setenv("INPUT_FOCUS", "security\ncorrectness")

    cfg = load_config(parse_args(["--pr", "7", "--focus", "performance"]))

    assert cfg.pr_number == 7
    assert cfg.focus_areas == ["performance"]


# ---------------------------------------------------- D6 — numeric input errors
@pytest.mark.parametrize("env,field", [
    ("INPUT_PR_NUMBER", "pr_number"),
    ("INPUT_MAX_COMMENTS", "max_comments"),
    ("INPUT_BATCH_CHARS", "batch_chars"),
])
def test_garbage_numeric_input_is_a_clean_config_error(monkeypatch, env, field):
    """D6 (V3-E01-T06): garbage numeric INPUT_* values used to escape as a
    raw ValueError traceback. They must exit 1 with a message that names the
    field and shows the bad value — no traceback, no silent fallback."""
    monkeypatch.setenv(env, "not-a-number")

    with pytest.raises(SystemExit) as exc:
        load_config(parse_args([]))

    message = str(exc.value.code)
    assert isinstance(message, str)          # string SystemExit ⇒ status 1, no traceback
    assert message.startswith("error: ")
    assert field in message
    assert "not-a-number" in message


def test_config_error_exits_with_status_one_via_main(monkeypatch):
    """End-to-end D6: `INPUT_MAX_COMMENTS=abc` exits 1, names the field, and
    prints no traceback."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    import os
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    env["INPUT_MAX_COMMENTS"] = "abc"
    proc = subprocess.run([sys.executable, "-m", "ai_pr_reviewer"],
                          capture_output=True, text=True, cwd=root, env=env)

    assert proc.returncode == 1
    assert "max_comments" in proc.stderr
    assert "abc" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_valid_numeric_inputs_still_parse_identically(monkeypatch):
    monkeypatch.setenv("INPUT_MAX_COMMENTS", " 12 ")
    monkeypatch.setenv("INPUT_BATCH_CHARS", "5000")

    cfg = load_config(parse_args([]))

    assert cfg.max_comments == 12
    assert cfg.batch_chars == 5000


def test_config_error_is_the_existing_system_exit_error_shape():
    err = ConfigError("max_comments must be an integer (got 'abc')")
    assert isinstance(err, SystemExit)
    assert str(err.code) == "error: max_comments must be an integer (got 'abc')"


# ------------------------------------------- V3-E04-T02 · retention_days input
def test_retention_days_defaults_to_keep_all(monkeypatch):
    monkeypatch.delenv("INPUT_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("RETENTION_DAYS", raising=False)

    cfg = load_config(parse_args([]))

    assert cfg.retention_days == 0          # 0 = keep everything (default)


def test_retention_days_layering_input_over_plain_env(monkeypatch):
    monkeypatch.delenv("INPUT_RETENTION_DAYS", raising=False)
    monkeypatch.setenv("RETENTION_DAYS", "30")
    assert load_config(parse_args([])).retention_days == 30

    monkeypatch.setenv("INPUT_RETENTION_DAYS", "90")   # action input wins
    assert load_config(parse_args([])).retention_days == 90


def test_garbage_retention_days_is_a_clean_config_error(monkeypatch):
    monkeypatch.setenv("INPUT_RETENTION_DAYS", "soon")

    with pytest.raises(SystemExit) as exc:
        load_config(parse_args([]))

    message = str(exc.value.code)
    assert message.startswith("error: ")
    assert "retention_days" in message and "soon" in message


def test_negative_retention_days_is_a_config_error(monkeypatch):
    monkeypatch.setenv("RETENTION_DAYS", "-3")

    with pytest.raises(SystemExit) as exc:
        load_config(parse_args([]))

    assert "retention_days must be >= 0" in str(exc.value.code)


# ============================================================ V3-E05-T05
# Layering precedence matrix: CLI > INPUT_* (action input) > plain env >
# default, pinned pairwise for every layer a field actually has. Each row
# below is one precedence claim; a deliberate flip in config.py (e.g. env
# read before CLI) turns rows red (mutation-checked during implementation).
#
# Field spec: attr, default, and its layers -> {"argv": [...]} for CLI or
# {"env": ..., "raw": ..., "expected": ...} for env layers. "raw" is what
# goes into the environment; "expected" is the resulting Config value.
# Bool layers store a raw string because that is what the environment holds.

FIELD_SPECS: dict[str, dict] = {
    "pr_number": {
        "attr": "pr_number", "default": 0,
        "layers": {
            "cli":   {"argv": ["--pr", "7"], "expected": 7},
            "input": {"env": "INPUT_PR_NUMBER", "raw": "42", "expected": 42},
        }},
    "max_comments": {
        "attr": "max_comments", "default": 20,
        "layers": {
            "cli":   {"argv": ["--max-comments", "5"], "expected": 5},
            "input": {"env": "INPUT_MAX_COMMENTS", "raw": "7", "expected": 7},
        }},
    "batch_chars": {
        "attr": "batch_chars", "default": 80_000,
        "layers": {
            "input": {"env": "INPUT_BATCH_CHARS", "raw": "5000", "expected": 5000},
        }},
    "severity_threshold": {
        "attr": "severity_threshold", "default": "medium",
        "layers": {
            "cli":   {"argv": ["--severity-threshold", "high"], "expected": "high"},
            "input": {"env": "INPUT_SEVERITY_THRESHOLD", "raw": "low",
                      "expected": "low"},
        }},
    "fail_on": {
        "attr": "fail_on", "default": "never",
        "layers": {
            "cli":   {"argv": ["--fail-on", "critical"], "expected": "critical"},
            "input": {"env": "INPUT_FAIL_ON", "raw": "high", "expected": "high"},
        }},
    "output": {
        "attr": "output", "default": "review-report.json",
        "layers": {
            "cli":   {"argv": ["--output", "cli.json"], "expected": "cli.json"},
            "input": {"env": "INPUT_OUTPUT", "raw": "env.json",
                      "expected": "env.json"},
        }},
    "model": {
        "attr": "model", "default": "",
        "layers": {
            "cli":   {"argv": ["--model", "m-cli"], "expected": "m-cli"},
            "input": {"env": "INPUT_MODEL", "raw": "m-env", "expected": "m-env"},
        }},
    "github_token": {
        "attr": "github_token", "default": "",
        "layers": {
            "cli":   {"argv": ["--github-token", "t-cli"], "expected": "t-cli"},
            "input": {"env": "INPUT_GITHUB_TOKEN", "raw": "t-input",
                      "expected": "t-input"},
            "plain": {"env": "GITHUB_TOKEN", "raw": "t-plain",
                      "expected": "t-plain"},
        }},
    "repo": {
        "attr": "repo", "default": "",
        "layers": {
            "cli":   {"argv": ["--repo", "cli/repo"], "expected": "cli/repo"},
            "input": {"env": "INPUT_REPOSITORY", "raw": "input/repo",
                      "expected": "input/repo"},
            "plain": {"env": "GITHUB_REPOSITORY", "raw": "plain/repo",
                      "expected": "plain/repo"},
        }},
    "dashboard_token": {
        "attr": "dashboard_token", "default": "",
        "layers": {
            "cli":   {"argv": ["--dashboard-token", "d-cli"], "expected": "d-cli"},
            "input": {"env": "INPUT_DASHBOARD_TOKEN", "raw": "d-input",
                      "expected": "d-input"},
            "plain": {"env": "DASHBOARD_TOKEN", "raw": "d-plain",
                      "expected": "d-plain"},
        }},
    "provider_order": {
        "attr": "provider_order", "default": "",
        "layers": {
            "cli":   {"argv": ["--provider-order", "claude,openai"],
                      "expected": "claude,openai"},
            "input": {"env": "INPUT_PROVIDER_ORDER", "raw": "openai,gemini",
                      "expected": "openai,gemini"},
            "plain": {"env": "PROVIDER_ORDER", "raw": "gemini,claude",
                      "expected": "gemini,claude"},
        }},
    "repo_context_chars": {
        "attr": "repo_context_chars", "default": 12_000,
        "layers": {
            "cli":   {"argv": ["--repo-context-chars", "9000"], "expected": 9000},
            "input": {"env": "INPUT_REPO_CONTEXT_CHARS", "raw": "7000",
                      "expected": 7000},
            "plain": {"env": "REPO_CONTEXT_CHARS", "raw": "6000",
                      "expected": 6000},
        }},
    "storage_file": {
        "attr": "storage_file", "default": "",
        "layers": {
            "cli":   {"argv": ["--storage-file", "cli.db"], "expected": "cli.db"},
            "input": {"env": "INPUT_STORAGE_FILE", "raw": "input.db",
                      "expected": "input.db"},
            "plain": {"env": "REVIEW_STORAGE_FILE", "raw": "plain.db",
                      "expected": "plain.db"},
        }},
    "retention_days": {
        "attr": "retention_days", "default": 0,
        "layers": {
            "input": {"env": "INPUT_RETENTION_DAYS", "raw": "90", "expected": 90},
            "plain": {"env": "RETENTION_DAYS", "raw": "30", "expected": 30},
        }},
    "review_mode": {
        "attr": "review_mode", "default": "automatic",
        "layers": {
            "input": {"env": "INPUT_REVIEW_MODE", "raw": "economy",
                      "expected": "economy"},
        }},
    "rules_file": {
        "attr": "rules_file", "default": ".ai-pr-reviewer.yml",
        "layers": {
            "input": {"env": "INPUT_RULES_FILE", "raw": "custom.yml",
                      "expected": "custom.yml"},
        }},
    "incremental_enabled": {
        "attr": "incremental_enabled", "default": True,
        "layers": {
            "input": {"env": "INPUT_INCREMENTAL", "raw": "false",
                      "expected": False},
        }},
    "mock": {
        "attr": "mock", "default": False,
        "layers": {
            "cli":   {"argv": ["--mock"], "expected": True},
            # input raw "false" beats plain raw "true" (input > plain), and
            # cli beats input — both directions stay distinguishable.
            "input": {"env": "INPUT_MOCK", "raw": "false", "expected": False},
            "plain": {"env": "MOCK", "raw": "true", "expected": True},
        }},
    "no_comment": {
        "attr": "no_comment", "default": False,
        "layers": {
            "cli":   {"argv": ["--no-comment"], "expected": True},
            "input": {"env": "INPUT_NO_COMMENT", "raw": "false",
                      "expected": False},
        }},
}

_PRECEDENCE = ("cli", "input", "plain")

# Every layering env var, cleared for every row so a developer's shell (or
# CI's) can never bleed into the matrix.
_ALL_LAYER_ENVS = tuple(sorted(
    layer["env"] for spec in FIELD_SPECS.values()
    for layer in spec["layers"].values() if "env" in layer))


def _scenarios(spec: dict):
    """(active layers, expected value) for: the default, every single layer,
    and every precedence pair the field actually has — the full matrix."""
    have = [name for name in _PRECEDENCE if name in spec["layers"]]
    yield frozenset(), spec["default"]
    for name in have:
        yield frozenset({name}), spec["layers"][name]["expected"]
    for i, hi in enumerate(have):
        for lo in have[i + 1:]:
            # hi always outranks lo: _PRECEDENCE is ordered highest first.
            yield frozenset({hi, lo}), spec["layers"][hi]["expected"]


_MATRIX = [
    pytest.param(field_name, active, expected,
                 id=f"{field_name}-{'-'.join(sorted(active)) or 'default'}")
    for field_name, spec in FIELD_SPECS.items()
    for active, expected in _scenarios(spec)
]


@pytest.mark.parametrize("field_name,active,expected", _MATRIX)
def test_layering_precedence_matrix(monkeypatch, field_name, active, expected):
    """CLI > INPUT_* > plain env > default, one row per precedence claim."""
    spec = FIELD_SPECS[field_name]
    for env in _ALL_LAYER_ENVS:
        monkeypatch.delenv(env, raising=False)

    argv: list[str] = []
    for name, layer in spec["layers"].items():
        if name not in active:
            continue
        if "argv" in layer:
            argv += layer["argv"]
        else:
            monkeypatch.setenv(layer["env"], layer["raw"])

    cfg = load_config(parse_args(argv))
    assert getattr(cfg, spec["attr"]) == expected


def test_list_fields_follow_the_same_precedence(monkeypatch):
    """exclude/focus are CLI-append vs newline-split env lists: same order
    (CLI > INPUT_* > default), just a different value shape."""
    monkeypatch.delenv("INPUT_EXCLUDE", raising=False)
    monkeypatch.delenv("INPUT_FOCUS", raising=False)
    assert load_config(parse_args([])).exclude == []
    assert load_config(parse_args([])).focus_areas == []

    monkeypatch.setenv("INPUT_EXCLUDE", "**/*.lock\ngenerated/**")
    monkeypatch.setenv("INPUT_FOCUS", "security\ntests")
    assert load_config(parse_args([])).exclude == ["**/*.lock", "generated/**"]
    assert load_config(parse_args([])).focus_areas == ["security", "tests"]

    cli = load_config(parse_args(["--exclude", "**/*.gen", "--focus", "perf"]))
    assert cli.exclude == ["**/*.gen"]          # CLI beats INPUT_*
    assert cli.focus_areas == ["perf"]


# ------------------------------------------ orthogonal merges (dashboard rules)
class _FakeResp:
    def __init__(self, payload: dict):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _dashboard_cfg(monkeypatch, payload):
    """Config without an explicit severity + a *configured* (so actually
    consulted) dashboard. Credentials must be present: merge_dashboard_rules
    is a no-op without them, which would make any assertion here vacuous."""
    import httpx

    calls: list[str] = []

    def fake_get(url, headers=None, timeout=None):
        calls.append(url)
        return _FakeResp(payload)

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.delenv("INPUT_SEVERITY_THRESHOLD", raising=False)
    monkeypatch.setenv("INPUT_DASHBOARD_URL", "https://dash.example")
    monkeypatch.setenv("INPUT_DASHBOARD_TOKEN", "test-token")
    cfg = load_config(parse_args([]))
    return cfg, calls


def test_dashboard_rules_fill_gaps_but_never_override_local(monkeypatch):
    """Merge semantics: dashboard rules supply what local config left
    defaulted (severity) and only ADD to the list fields."""
    from ai_pr_reviewer.config import merge_dashboard_rules

    cfg, calls = _dashboard_cfg(
        monkeypatch,
        {"severity_threshold": "high", "exclude_globs": ["**/*.gen"],
         "focus_areas": ["performance"]})
    assert cfg.severity_threshold == "medium" and not cfg.severity_threshold_explicit

    merge_dashboard_rules(cfg)

    assert calls, "dashboard must have been consulted"
    assert cfg.severity_threshold == "high"          # unfilled gap, now filled
    assert "**/*.gen" in cfg.exclude                 # additive only
    assert "performance" in cfg.focus_areas


def test_explicit_severity_beats_dashboard_rules(monkeypatch):
    """An explicit CLI/env threshold is a local decision; the dashboard may
    not override it (this is the `_effective_severity_threshold` input side)."""
    import httpx

    from ai_pr_reviewer.config import merge_dashboard_rules

    monkeypatch.setenv("INPUT_SEVERITY_THRESHOLD", "low")
    monkeypatch.setenv("INPUT_DASHBOARD_URL", "https://dash.example")
    monkeypatch.setenv("INPUT_DASHBOARD_TOKEN", "test-token")
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: _FakeResp({"severity_threshold": "high"}))
    cfg = load_config(parse_args([]))
    assert cfg.severity_threshold_explicit

    merge_dashboard_rules(cfg)

    assert cfg.severity_threshold == "low"


def test_invalid_dashboard_severity_is_ignored_but_lists_merge(monkeypatch):
    from ai_pr_reviewer.config import merge_dashboard_rules

    cfg, _calls = _dashboard_cfg(
        monkeypatch, {"severity_threshold": "extreme",
                      "exclude_globs": ["**/*.gen"]})
    merge_dashboard_rules(cfg)

    assert cfg.severity_threshold == "medium"       # junk from the network ignored
    assert "**/*.gen" in cfg.exclude                # the usable parts still merge


def test_unreachable_dashboard_never_breaks_a_review(monkeypatch):
    import httpx

    from ai_pr_reviewer.config import merge_dashboard_rules

    def boom(*_args, **_kwargs):
        raise ConnectionError("dashboard down")

    monkeypatch.setattr(httpx, "get", boom)
    monkeypatch.delenv("INPUT_SEVERITY_THRESHOLD", raising=False)
    monkeypatch.setenv("INPUT_DASHBOARD_URL", "https://dash.example")
    monkeypatch.setenv("INPUT_DASHBOARD_TOKEN", "test-token")
    cfg = load_config(parse_args([]))
    before = (cfg.severity_threshold, list(cfg.exclude), list(cfg.focus_areas))

    merge_dashboard_rules(cfg)                      # must not raise

    assert (cfg.severity_threshold, cfg.exclude, cfg.focus_areas) == before


def test_dashboard_merge_is_a_noop_without_credentials(monkeypatch):
    import httpx

    from ai_pr_reviewer.config import merge_dashboard_rules

    calls: list[str] = []
    monkeypatch.setattr(httpx, "get",
                        lambda *a, **k: calls.append(a) or _FakeResp({}))
    cfg = load_config(parse_args([]))               # no url/token configured

    merge_dashboard_rules(cfg)

    assert calls == []                              # no credentials, no call


# ------------------------------- explicit-vs-policy severity (orchestrator side)
def test_effective_severity_threshold_override_semantics():
    """Pin `_effective_severity_threshold`: an explicit input always wins;
    a non-default repository policy wins only when the input was NOT
    explicit; a policy left at its default never overrides."""
    from ai_pr_reviewer.config import Config
    from ai_pr_reviewer.orchestrator import _effective_severity_threshold
    from ai_pr_reviewer.rules import DEFAULT_SEVERITY, ReviewPolicy

    explicit = Config(severity_threshold="low", severity_threshold_explicit=True)
    policy_high = ReviewPolicy(severity_threshold="critical")
    assert _effective_severity_threshold(explicit, policy_high) == "low"

    implicit = Config(severity_threshold=DEFAULT_SEVERITY,
                      severity_threshold_explicit=False)
    assert _effective_severity_threshold(implicit, policy_high) == "critical"

    assert _effective_severity_threshold(Config(), ReviewPolicy()) == "medium"
    assert _effective_severity_threshold(
        Config(severity_threshold="high", severity_threshold_explicit=True),
        ReviewPolicy()) == "high"


# ------------------------------------------------- forward compatibility (D…
def test_unknown_input_env_warns_without_echoing_its_value(monkeypatch, caplog):
    """Unknown/future INPUT_* variables warn and are ignored — never fatal —
    and the warning must not echo the value (it could be a secret)."""
    import logging

    from ai_pr_reviewer import config as config_mod

    monkeypatch.setenv("INPUT_FUTURE_KNOB", "super-secret-value")

    with caplog.at_level("WARNING", logger="ai_pr_reviewer.config"):
        cfg = load_config(parse_args([]))

    messages = [r.getMessage() for r in caplog.records]
    assert any("INPUT_FUTURE_KNOB" in m for m in messages)
    assert all("super-secret-value" not in m for m in messages)
    assert cfg.max_comments == 20                   # config still loads fine


def test_known_input_env_vars_match_action_and_source():
    """KNOWN_INPUT_ENV_VARS is the contract between action.yml's plumbing and
    this module: every exported INPUT_* is known, and every INPUT_* name the
    source reads is declared (adding a read without declaring it fails)."""
    import re
    from pathlib import Path

    import yaml

    from ai_pr_reviewer import config as config_mod

    action = yaml.safe_load((Path(__file__).resolve().parents[1] / "action.yml")
                            .read_text(encoding="utf-8"))
    review = next(s for s in action["runs"]["steps"] if s.get("id") == "review")
    exported = {k for k in review["env"] if k.startswith("INPUT_")}
    assert exported <= config_mod.KNOWN_INPUT_ENV_VARS

    source = Path(config_mod.__file__).read_text(encoding="utf-8")
    read_in_source = set(re.findall(r'"(INPUT_[A-Z_]+)"', source))
    assert read_in_source == config_mod.KNOWN_INPUT_ENV_VARS


def test_repo_context_chars_garbage_falls_back_to_default(monkeypatch):
    """D6 scope decision (Known Technical Debt item 7) — ANSWERED in V3-E05.

    The context budget deliberately keeps `_int_field`'s silent fallback to
    12000 (unlike pr_number / max_comments / batch_chars, which became strict
    ConfigErrors in V3-E01-T06): a typo'd *budget* must never kill a review.
    Pinned here so making it strict later is a reviewed decision, not an
    accident — and so the fallback can't silently become a crash.
    """
    monkeypatch.delenv("INPUT_REPO_CONTEXT_CHARS", raising=False)
    monkeypatch.delenv("REPO_CONTEXT_CHARS", raising=False)

    monkeypatch.setenv("REPO_CONTEXT_CHARS", "not-a-number")
    assert load_config(parse_args([])).repo_context_chars == 12_000

    monkeypatch.delenv("REPO_CONTEXT_CHARS", raising=False)
    monkeypatch.setenv("INPUT_REPO_CONTEXT_CHARS", "abc")
    assert load_config(parse_args([])).repo_context_chars == 12_000
