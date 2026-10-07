"""Tests for ai_pr_reviewer/rules.py — ReviewPolicy + load_project_rules.

"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.rules import (DEFAULT_MODE, DEFAULT_SEVERITY,
                                  MAX_LIST_ENTRIES, SENSITIVE_EXCLUDE_GLOBS,
                                  ReviewPolicy, load_project_rules)


def _write(tmp_path: Path, text: str, name: str = ".ai-pr-reviewer.yml") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# --------------------------------------------------------------------- missing file
def test_missing_file_returns_defaults(tmp_path):
    policy = load_project_rules(str(tmp_path))
    assert policy == ReviewPolicy()
    assert policy.mode == DEFAULT_MODE
    assert policy.severity_threshold == DEFAULT_SEVERITY
    assert policy.rules == []
    assert policy.exclude == list(SENSITIVE_EXCLUDE_GLOBS)
    assert policy.focus == []


# --------------------------------------------------------------------- valid yaml
def test_valid_yaml_is_parsed_fully(tmp_path):
    _write(tmp_path, """
review:
  mode: balanced
  severity_threshold: high
rules:
  - "All database access must use repositories."
  - "Every API endpoint must have tests."
exclude:
  - "**/*.lock"
  - "generated/**"
focus:
  - security
  - tests
""")
    policy = load_project_rules(str(tmp_path))
    assert policy.mode == "balanced"
    assert policy.severity_threshold == "high"
    assert policy.rules == ["All database access must use repositories.",
                            "Every API endpoint must have tests."]
    # Configured exclusions land on top of the non-removable privacy
    # baseline — assert both are present rather than exact-matching the
    # list, since the baseline's own ordering/contents are rules.py's to
    # define, not this test's.
    assert set(SENSITIVE_EXCLUDE_GLOBS) <= set(policy.exclude)
    assert "**/*.lock" in policy.exclude
    assert "generated/**" in policy.exclude
    assert policy.focus == ["security", "tests"]


def test_configured_exclude_cannot_remove_sensitive_baseline(tmp_path):
    """A malicious or careless .ai-pr-reviewer.yml must not be able to widen
    what gets sent to the model by "overriding" exclude with something that
    omits the sensitive baseline — the baseline always survives regardless
    of what the configured list contains."""
    _write(tmp_path, """
exclude:
  - "**/*.lock"
""")
    policy = load_project_rules(str(tmp_path))
    assert set(SENSITIVE_EXCLUDE_GLOBS) <= set(policy.exclude)
    assert "**/*.lock" in policy.exclude


def test_valid_yaml_defaults_when_review_block_missing(tmp_path):
    _write(tmp_path, 'rules:\n  - "keep it simple"\n')
    policy = load_project_rules(str(tmp_path))
    assert policy.mode == DEFAULT_MODE
    assert policy.severity_threshold == DEFAULT_SEVERITY
    assert policy.rules == ["keep it simple"]


def test_empty_file_returns_defaults(tmp_path):
    _write(tmp_path, "")
    assert load_project_rules(str(tmp_path)) == ReviewPolicy()


def test_custom_rules_filename(tmp_path):
    _write(tmp_path, "review:\n  mode: maximum\n", name="custom-rules.yml")
    # default filename still sees nothing there
    assert load_project_rules(str(tmp_path)).mode == DEFAULT_MODE
    policy = load_project_rules(str(tmp_path), filename="custom-rules.yml")
    assert policy.mode == "maximum"


# --------------------------------------------------------------------- invalid mode
def test_invalid_mode_warns_and_defaults(tmp_path, caplog):
    _write(tmp_path, "review:\n  mode: yolo\n")
    with caplog.at_level("WARNING"):
        policy = load_project_rules(str(tmp_path))
    assert policy.mode == DEFAULT_MODE
    assert any("mode" in r.message for r in caplog.records)


def test_invalid_severity_threshold_warns_and_defaults(tmp_path, caplog):
    _write(tmp_path, "review:\n  severity_threshold: extreme\n")
    with caplog.at_level("WARNING"):
        policy = load_project_rules(str(tmp_path))
    assert policy.severity_threshold == DEFAULT_SEVERITY
    assert any("severity_threshold" in r.message for r in caplog.records)


# --------------------------------------------------------------------- malformed yaml
def test_malformed_yaml_warns_and_defaults_no_crash(tmp_path, caplog):
    _write(tmp_path, "review:\n  mode: [unterminated\nrules: - broken: :::\n")
    with caplog.at_level("WARNING"):
        policy = load_project_rules(str(tmp_path))
    assert policy == ReviewPolicy()
    assert caplog.records  # a warning was logged, review still proceeds


def test_non_mapping_top_level_warns_and_defaults(tmp_path, caplog):
    _write(tmp_path, "- just\n- a\n- list\n")
    with caplog.at_level("WARNING"):
        policy = load_project_rules(str(tmp_path))
    assert policy == ReviewPolicy()
    assert caplog.records


# --------------------------------------------------------------------- list coercion
def test_non_list_rules_field_warns_and_is_ignored(tmp_path, caplog):
    _write(tmp_path, 'rules: "not a list"\n')
    with caplog.at_level("WARNING"):
        policy = load_project_rules(str(tmp_path))
    assert policy.rules == []
    assert caplog.records


def test_non_string_list_entries_are_skipped(tmp_path):
    _write(tmp_path, "focus:\n  - security\n  - 42\n  - correctness\n")
    policy = load_project_rules(str(tmp_path))
    assert policy.focus == ["security", "correctness"]


# ------------------------------------- V3-E05-T01 · single-sourced baseline (D12)
def test_unknown_top_level_keys_warn_but_do_not_break(tmp_path, caplog):
    """Forward compatibility (V3-E05-T05): a config written for a future
    schema (or with a typo'd section) warns and is skipped — the known keys
    still load and the review proceeds. Unknown keys are never fatal."""
    _write(tmp_path, "review:\n  mode: balanced\n"
                     "future_section:\n  shiny_new_thing: true\n")
    with caplog.at_level("WARNING"):
        policy = load_project_rules(str(tmp_path))

    assert policy.mode == "balanced"               # known keys unaffected
    assert any("future_section" in r.getMessage() for r in caplog.records)


def test_dashboard_reuses_the_engine_baseline_object():
    """The dashboard must consume the engine's baseline, not keep a copy.

    D12: ``dashboard/app.py`` used to carry a byte-identical duplicate of the
    privacy exclusion list, synced only by convention. The identity check is
    the single-source enforcement — re-hardcoding a list (even an identical
    one) anywhere in the dashboard breaks this test.
    """
    import dashboard.app as dashboard_app

    assert dashboard_app.SENSITIVE_EXCLUDE_GLOBS is SENSITIVE_EXCLUDE_GLOBS


def test_dashboard_merge_never_drops_the_baseline():
    """Either side merging user input must keep every baseline glob — the
    union can only grow (repo config / dashboard settings can *add*
    exclusions, never remove them)."""
    import dashboard.app as dashboard_app

    merged = dashboard_app._with_sensitive_exclusions(["**/*.lock"])
    assert set(SENSITIVE_EXCLUDE_GLOBS) <= set(merged)
    assert "**/*.lock" in merged

    # Non-list and junk payloads fail closed: the baseline still survives.
    for payload in (None, "not-a-list", ["x", 1, "  ", None]):
        assert set(SENSITIVE_EXCLUDE_GLOBS) <= set(
            dashboard_app._with_sensitive_exclusions(payload))

    # The dashboard's built-in default set is a superset of the baseline.
    assert set(SENSITIVE_EXCLUDE_GLOBS) <= set(dashboard_app.DEFAULT_EXCLUDE_GLOBS)



def test_list_entries_capped_defensively(tmp_path):
    entries = "\n".join(f'  - "rule {i}"' for i in range(MAX_LIST_ENTRIES + 20))
    _write(tmp_path, f"rules:\n{entries}\n")
    policy = load_project_rules(str(tmp_path))
    assert len(policy.rules) == MAX_LIST_ENTRIES


# --------------------------------------------------------------------- never raises
def test_never_raises_on_any_input(tmp_path):
    for bad in ["{{{{", "review: null\nrules: null\n", "\x00\x01binary-ish",
                "review:\n  mode: 123\n  severity_threshold: true\n"]:
        _write(tmp_path, bad)
        load_project_rules(str(tmp_path))  # must not raise
