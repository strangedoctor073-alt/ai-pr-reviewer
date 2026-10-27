"""Integration tests for the V4.0-E04 risk engine wiring.

Covers: config knobs (default off, plain RISK_* env, invalid values never
weaken review), the additive report contract, and the equivalence gate --
with the engine off the report is identical to pre-V4.0 behaviour, and with it
on only the ``risk`` block gains keys. Offline; mock provider; synthetic diffs.
"""
from __future__ import annotations

import contextlib
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import orchestrator as orch  # noqa: E402
from ai_pr_reviewer.cli import parse_args  # noqa: E402
from ai_pr_reviewer.config import Config, load_config  # noqa: E402
from ai_pr_reviewer.models import PRContext, _risk_json  # noqa: E402
from ai_pr_reviewer.risk import REPORT_RISK_KEYS, assess_risk  # noqa: E402

_RISK_ENV = ("RISK_ENGINE", "RISK_DEPTH_CAP", "RISK_MAX_SPECIALISTS")


@contextlib.contextmanager
def _env(**values):
    saved = {k: os.environ.get(k) for k in _RISK_ENV}
    try:
        for k in _RISK_ENV:
            os.environ.pop(k, None)
        os.environ.update({k: str(v) for k, v in values.items()})
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _cfg():
    return load_config(parse_args([]))


def _diff(path, line="x = 1"):
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,2 +1,3 @@\n ctx\n+{line}\n ctx2\n")


DIFF = _diff("src/auth/login.py", "token = None") + _diff("README.md", "hi")


def _report(**cfg_kwargs) -> dict:
    cfg = Config(mock=True, repo="local/p", rules_file="/nonexistent.yml",
                 **cfg_kwargs)
    pr = PRContext(repo="local/p", pr_number=0, pr_title="t")
    report = orch.ReviewOrchestrator(cfg, None, pr=pr, diff_text=DIFF).run()
    data = report.to_dict()
    data.pop("reviewed_at", None)
    data.pop("duration_ms", None)
    return data


class TestConfig:
    def test_defaults_are_off(self):
        with _env():
            cfg = _cfg()
        assert cfg.risk_engine is False
        assert cfg.risk_depth_cap == "" and cfg.risk_max_specialists == 0

    def test_dataclass_defaults_are_off_without_load_config(self):
        cfg = Config()
        assert cfg.risk_engine is False and cfg.risk_max_specialists == 0

    def test_env_enables_and_sets_caps(self):
        with _env(RISK_ENGINE="true", RISK_DEPTH_CAP="Standard",
                  RISK_MAX_SPECIALISTS="3"):
            cfg = _cfg()
        assert cfg.risk_engine is True
        assert cfg.risk_depth_cap == "standard"
        assert cfg.risk_max_specialists == 3

    def test_invalid_values_degrade_to_no_cap_never_to_an_error(self):
        with _env(RISK_ENGINE="yes", RISK_DEPTH_CAP="shallow",
                  RISK_MAX_SPECIALISTS="lots"):
            cfg = _cfg()
        assert cfg.risk_depth_cap == "" and cfg.risk_max_specialists == 0

    def test_negative_specialist_cap_means_none(self):
        with _env(RISK_MAX_SPECIALISTS="-4"):
            assert _cfg().risk_max_specialists == 0

    def test_no_action_input_was_added(self):
        # action.yml is frozen without sign-off: the knobs are env-only.
        text = (ROOT / "action.yml").read_text("utf-8").lower()
        assert "risk_engine" not in text and "risk-engine" not in text
        assert "risk_depth" not in text and "risk_max" not in text
        src = (ROOT / "ai_pr_reviewer" / "config.py").read_text("utf-8")
        assert "INPUT_RISK" not in src


class TestReportContract:
    def test_no_assessment_leaves_the_risk_block_exactly_as_before(self):
        risk = SimpleNamespace(level="high", reasons=["touches auth"])
        assert _risk_json(risk) == {"level": "high", "reasons": ["touches auth"]}
        assert _risk_json(risk, None) == _risk_json(risk)

    def test_assessment_extends_the_block_additively(self):
        risk = SimpleNamespace(level="low", reasons=[])
        a = assess_risk([SimpleNamespace(path="a.py", additions=1, deletions=0)])
        block = _risk_json(risk, a)
        assert block["level"] == "low" and block["reasons"] == []
        assert set(block) == {"level", "reasons"} | REPORT_RISK_KEYS
        assert block["informational"] is True
        assert block["score"] == sum(c["points"] for c in block["contributions"])

    def test_foreign_keys_from_a_bad_assessment_are_dropped(self):
        class Rogue:
            def to_report_dict(self):
                return {"score": 1, "api_key": "sk-nope", "evil": "x"}
        block = _risk_json(SimpleNamespace(level="low", reasons=[]), Rogue())
        assert set(block) == {"level", "reasons", "score"}

    def test_non_dict_assessment_is_ignored(self):
        class Bad:
            def to_report_dict(self):
                return "not a dict"
        assert _risk_json(SimpleNamespace(level="low", reasons=[]), Bad()) == {
            "level": "low", "reasons": []}

    def test_uncomputed_risk_stays_null_even_with_an_assessment(self):
        a = assess_risk([])
        assert _risk_json(None, a) is None


class TestEquivalenceGate:
    def test_flag_off_is_the_default_behaviour(self):
        assert _report() == _report(risk_engine=False)

    def test_flag_off_adds_no_keys_to_the_risk_block(self):
        assert set(_report()["risk"]) == {"level", "reasons"}

    def test_flag_on_changes_only_the_risk_block_and_only_by_adding(self):
        off, on = _report(), _report(risk_engine=True)
        assert {k: v for k, v in on.items() if k != "risk"} == {
            k: v for k, v in off.items() if k != "risk"}
        assert {k: v for k, v in on["risk"].items()
                if k in ("level", "reasons")} == off["risk"]
        assert REPORT_RISK_KEYS <= set(on["risk"])

    def test_sensitive_pr_is_floored_even_when_config_asks_for_low(self):
        on = _report(risk_engine=True, risk_depth_cap="low",
                     risk_max_specialists=1)
        depth = on["risk"]["depth"]
        assert depth["level"] in ("standard", "deep")
        assert depth["budget_percent"] == 100
        assert "security" in depth["specialists"]
        assert depth["static_rules"] is True

    def test_report_with_assessment_is_json_serialisable_and_stable(self):
        a = _report(risk_engine=True)
        assert json.loads(json.dumps(a)) == a
        assert _report(risk_engine=True) == a

    def test_an_engine_failure_never_fails_or_alters_the_review(self):
        import ai_pr_reviewer.risk as risk_mod
        real = risk_mod.assess_risk

        def boom(*a, **k):
            raise RuntimeError("synthetic failure")
        risk_mod.assess_risk = boom
        try:
            broken = _report(risk_engine=True)
        finally:
            risk_mod.assess_risk = real
        baseline = _report()
        assert set(broken["risk"]) == {"level", "reasons"}
        assert any("Risk engine unavailable" in w for w in broken["warnings"])
        assert "synthetic" not in json.dumps(broken)      # no exception text
        broken["warnings"] = [w for w in broken["warnings"]
                              if "Risk engine unavailable" not in w]
        assert broken == baseline
