"""Tests for V4.0-E04-T03 (depth routing policy) and T04 (security-depth floor).

T04 is enforced three ways: (1) a DepthDecision cannot be *constructed*
below its own floor, (2) an exhaustive sweep over the whole configuration
space and several PR shapes proves decide_depth never emits one, and (3) the
set of knobs a config can turn is pinned so a new knob is a reviewed change.
Synthetic fixtures only.
"""
from __future__ import annotations

import dataclasses
import itertools
import re
import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import risk  # noqa: E402
from ai_pr_reviewer.risk import (  # noqa: E402
    BASELINE_BUDGET_PERCENT, BASELINE_DEPTH, BUDGET_PERCENT, DEPTH_ORDER,
    DEPTH_REASONS, MANDATORY_ROLES, DepthDecision, DepthPolicyConfig,
    assess_risk, decide_depth, extract_risk_features, score_features,
    security_floor, select_specialists)


def _file(path, add=1):
    return SimpleNamespace(path=path, additions=add, deletions=0)


def _decide(files, policy=None, focus=()):
    fs = extract_risk_features(files, focus=focus)
    return decide_depth(score_features(fs), fs, policy), fs


def _idx(depth):
    return DEPTH_ORDER.index(depth)


# PR shapes spanning every band, with and without a sensitive surface.
SHAPES = {
    "tiny_docs": [_file("README.md")],
    "small_code": [_file("src/util.py", 20)],
    "large_code": [_file(f"src/m{i}.py", 300) for i in range(8)],
    "one_auth": [_file("src/auth/login.py", 3)],
    "huge_sensitive": [_file(f"billing/m{i}.py", 500) for i in range(6)],
    "docs_about_auth": [_file("docs/auth.md")],
    "ci_only": [_file(".github/workflows/ci.yml", 2)],
    "empty": [],
}
CAPS = ["", "low", "standard", "deep", "LOW", "junk", None]
SPECIALIST_LIMITS = [0, 1, 2, 3, 4, 5, 99, -1, None, True]
FOCUSES = [(), ("naming style",), ("security review",), ("SQL injection",)]


class TestDepthMapping:
    def test_band_maps_to_depth_without_config(self):
        assert _decide(SHAPES["tiny_docs"])[0].depth == "low"
        assert _decide(SHAPES["large_code"])[0].depth in ("standard", "deep")
        assert _decide(SHAPES["huge_sensitive"])[0].depth == "deep"

    def test_budget_never_exceeds_the_configured_ceiling(self):
        for files in SHAPES.values():
            assert _decide(files)[0].budget_percent <= BASELINE_BUDGET_PERCENT
        assert max(BUDGET_PERCENT.values()) == BASELINE_BUDGET_PERCENT

    def test_low_risk_pr_gets_reduced_budget_baseline_gets_full(self):
        assert _decide(SHAPES["tiny_docs"])[0].budget_percent == 70
        assert _decide(SHAPES["one_auth"])[0].budget_percent == 100

    def test_deeper_depth_never_has_fewer_roles(self):
        sizes = [len(select_specialists(d)) for d in DEPTH_ORDER]
        assert sizes == sorted(sizes)

    def test_reasons_are_closed_vocabulary_and_start_with_the_band(self):
        for files in SHAPES.values():
            d = _decide(files)[0]
            assert d.reasons[0].startswith("band_")
            assert set(d.reasons) <= set(DEPTH_REASONS)

    def test_depth_is_a_pure_function_of_features(self):
        a = _decide(SHAPES["large_code"])[0]
        b = _decide(list(reversed(SHAPES["large_code"])))[0]
        assert a == b


class TestConfigCaps:
    def test_cap_lowers_depth_for_a_non_sensitive_pr(self):
        d = _decide(SHAPES["large_code"], DepthPolicyConfig(depth_cap="low"))[0]
        assert d.depth == "low" and "depth_cap_applied" in d.reasons

    def test_cap_above_current_depth_is_a_no_op(self):
        d = _decide(SHAPES["tiny_docs"], DepthPolicyConfig(depth_cap="deep"))[0]
        assert d.depth == "low" and "depth_cap_applied" not in d.reasons

    def test_specialist_cap_trims_but_keeps_mandatory_roles(self):
        d = _decide(SHAPES["huge_sensitive"],
                    DepthPolicyConfig(max_specialists=3))[0]
        assert len(d.specialists) == 3
        assert set(MANDATORY_ROLES) <= set(d.specialists)
        d1 = _decide(SHAPES["huge_sensitive"],
                     DepthPolicyConfig(max_specialists=1))[0]
        assert d1.specialists == MANDATORY_ROLES
        assert "specialist_cap_raised_to_mandatory" in d1.reasons

    def test_unknown_cap_is_ignored_like_no_cap(self):
        base = _decide(SHAPES["large_code"])[0]
        for junk in ("junk", "LOW", None, 7):
            assert _decide(SHAPES["large_code"],
                           DepthPolicyConfig(depth_cap=junk))[0] == base


class TestSecurityFloor:
    def test_floor_rises_for_a_sensitive_path_or_sensitive_focus(self):
        for files, focus in ((SHAPES["one_auth"], ()), (SHAPES["ci_only"], ()),
                             (SHAPES["docs_about_auth"], ()),
                             (SHAPES["tiny_docs"], ("security",))):
            fs = extract_risk_features(files, focus=focus)
            floor = security_floor(fs)
            assert floor.depth == BASELINE_DEPTH
            assert floor.budget_percent == BASELINE_BUDGET_PERCENT

    def test_floor_is_low_when_nothing_sensitive(self):
        floor = security_floor(extract_risk_features(SHAPES["small_code"]))
        assert floor.depth == "low" and floor.budget_percent == 70

    def test_floor_ignores_unavailable_signals(self):
        # No index/history must neither raise nor lower the floor.
        fs = extract_risk_features(SHAPES["one_auth"], impact=None,
                                   history=None)
        assert security_floor(fs).depth == BASELINE_DEPTH

    def test_exhaustive_sweep_never_goes_below_the_floor(self):
        checked = 0
        for (name, files), cap, limit, focus in itertools.product(
                SHAPES.items(), CAPS, SPECIALIST_LIMITS, FOCUSES):
            cfg = DepthPolicyConfig(depth_cap=cap, max_specialists=limit)
            d, fs = _decide(files, cfg, focus)
            floor = security_floor(fs)
            ctx = (name, cap, limit, focus)
            assert _idx(d.depth) >= _idx(floor.depth), ctx
            assert d.budget_percent >= floor.budget_percent, ctx
            assert d.budget_percent <= BASELINE_BUDGET_PERCENT, ctx
            assert set(MANDATORY_ROLES) <= set(d.specialists), ctx
            assert d.specialists[:2] == MANDATORY_ROLES, ctx
            assert d.static_rules is True, ctx
            if (fs.get("sensitive_files").value
                    or fs.get("focus_sensitive_entries").value):
                assert _idx(d.depth) >= _idx(BASELINE_DEPTH), ctx
                assert d.budget_percent == BASELINE_BUDGET_PERCENT, ctx
            checked += 1
        assert checked == (len(SHAPES) * len(CAPS)
                           * len(SPECIALIST_LIMITS) * len(FOCUSES))

    def test_hostile_config_cannot_force_a_sensitive_pr_to_low(self):
        cfg = DepthPolicyConfig(depth_cap="low", max_specialists=1)
        d = _decide(SHAPES["one_auth"], cfg)[0]
        assert d.depth == "standard" and d.budget_percent == 100
        assert "security_floor_applied" in d.reasons
        assert "security" in d.specialists

    def test_floor_budget_holds_even_if_the_depth_budget_table_is_lowered(self):
        # The floor's own budget, not the depth table, is what protects a
        # sensitive PR: lowering the table later must not leak through.
        original = dict(risk.BUDGET_PERCENT)
        risk.BUDGET_PERCENT.update({"standard": 80, "deep": 80})
        try:
            files = SHAPES["one_auth"]
            fs = extract_risk_features(files)
            d = decide_depth(score_features(fs), fs,
                             DepthPolicyConfig(depth_cap="low"))
            assert d.budget_percent == BASELINE_BUDGET_PERCENT
        finally:
            risk.BUDGET_PERCENT.clear()
            risk.BUDGET_PERCENT.update(original)

    def test_floor_lifted_pr_gets_the_roles_of_its_final_depth(self):
        d = _decide(SHAPES["one_auth"], DepthPolicyConfig(depth_cap="low"))[0]
        assert d.specialists == select_specialists(d.depth)


class TestDecisionCannotBeBuiltBelowItsFloor:
    def _ok(self, **over):
        base = dict(depth="standard", specialists=select_specialists("standard"),
                    budget_percent=100, floor_depth="standard",
                    floor_budget_percent=100)
        base.update(over)
        return DepthDecision(**base)

    def _rejects(self, **over):
        try:
            self._ok(**over)
        except ValueError:
            return
        raise AssertionError(f"accepted invalid decision {over}")

    def test_valid_decision_constructs(self):
        assert self._ok().depth == "standard"

    def test_rejects_depth_below_floor(self):
        self._rejects(depth="low", specialists=MANDATORY_ROLES)

    def test_rejects_budget_below_floor_or_above_ceiling(self):
        self._rejects(budget_percent=99)
        self._rejects(budget_percent=101)
        self._rejects(budget_percent=0)

    def test_rejects_missing_mandatory_role(self):
        self._rejects(specialists=("correctness", "test"))
        self._rejects(specialists=("security",))

    def test_rejects_disabled_static_rules(self):
        self._rejects(static_rules=False)

    def test_rejects_unknown_depth_or_reason(self):
        self._rejects(depth="shallow")
        self._rejects(reasons=("because",))


class TestKnobSurface:
    def test_policy_config_fields_are_pinned(self):
        # A new knob that can influence depth must be a deliberate change:
        # update this list together with the floor tests above.
        assert [f.name for f in dataclasses.fields(DepthPolicyConfig)] == [
            "depth_cap", "max_specialists"]

    def test_policy_config_is_frozen(self):
        cfg = DepthPolicyConfig()
        try:
            cfg.depth_cap = "low"
        except dataclasses.FrozenInstanceError:
            return
        raise AssertionError("policy config must be immutable")


class TestNoCostOrLatencyRouting:
    def test_depth_code_names_no_cost_or_latency_identifier(self):
        # V4 invariant: no routing decision depends on cost or latency.
        # Identifiers only (prose in comments may mention the words).
        import ast
        tree = ast.parse((ROOT / "ai_pr_reviewer" / "risk.py").read_text("utf-8"))
        pattern = re.compile(r"cost|price|latenc|duration|elapsed", re.I)
        names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        names |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        names |= {a.arg for n in ast.walk(tree) if isinstance(n, ast.arguments)
                  for a in n.args + n.kwonlyargs}
        names |= {n.name for n in ast.walk(tree)
                  if isinstance(n, (ast.FunctionDef, ast.ClassDef))}
        assert not [n for n in names if pattern.search(n)]


class TestAssessment:
    def test_assess_risk_composes_the_three_layers(self):
        a = assess_risk(SHAPES["one_auth"])
        assert a.features.version == "risk-features-v1"
        assert a.score.band in risk.BANDS
        assert a.depth.depth in DEPTH_ORDER

    def test_report_dict_is_closed_and_marked_informational(self):
        d = assess_risk(SHAPES["one_auth"]).to_report_dict()
        assert set(d) == risk.REPORT_RISK_KEYS
        assert d["informational"] is True
        assert set(d["depth"]) == {"level", "specialists", "budget_percent",
                                   "floor_level", "reasons", "static_rules"}

    def test_report_dict_carries_no_paths_or_text(self):
        d = assess_risk([_file("src/auth/login.py")]).to_report_dict()
        assert "login" not in repr(d) and "src/" not in repr(d)

    def test_report_dict_is_deterministic(self):
        a = assess_risk(SHAPES["large_code"]).to_report_dict()
        b = assess_risk(list(reversed(SHAPES["large_code"]))).to_report_dict()
        assert a == b
