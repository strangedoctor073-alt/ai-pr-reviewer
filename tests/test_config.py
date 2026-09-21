"""Tests for GitHub Action input configuration."""
from __future__ import annotations

from ai_pr_reviewer.cli import parse_args
from ai_pr_reviewer.config import load_config


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
