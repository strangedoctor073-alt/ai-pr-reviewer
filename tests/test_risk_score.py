"""Tests for V4.0-E04-T02: the explainable risk score (risk.score_features).

Contract: the score is a deterministic function of only the shown features;
it equals the sum of the shown contributions; every rule is monotonic and
capped; unavailable signals contribute nothing and are listed as such.
Synthetic fixtures only.
"""
from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.risk import (  # noqa: E402
    BAND_HIGH_MIN, BAND_MEDIUM_MIN, BANDS, FEATURE_NAMES, MAX_SCORE,
    SCORE_RULES, RiskContribution, RiskFeature, RiskFeatureSet, RiskScore,
    band_for, extract_risk_features, score_features)


def _fs(**values):
    """Feature set with the given values; everything else 0, available."""
    feats = []
    for name in FEATURE_NAMES:
        unavailable = name in values and values[name] is None
        feats.append(RiskFeature(
            name, "x", 0 if unavailable else values.get(name, 0),
            available=not unavailable,
            reason="no_index" if unavailable else ""))
    return RiskFeatureSet(tuple(feats))


def _file(path, add=1):
    return SimpleNamespace(path=path, additions=add, deletions=0)


class TestRules:
    def test_rule_table_is_pinned(self):
        assert [(r.feature, r.step, r.points_per_step, r.cap)
                for r in SCORE_RULES] == [
            ("files_changed", 5, 1, 6), ("lines_changed", 100, 1, 8),
            ("sensitive_files", 1, 4, 12), ("focus_sensitive_entries", 1, 1, 3),
            ("impact_direct_dependents", 2, 1, 6),
            ("impact_indirect_dependents", 5, 1, 3),
            ("impact_truncated", 1, 2, 2), ("impact_unknown_seeds", 3, 1, 2),
            ("history_max_file_churn", 10, 1, 5)]
        assert MAX_SCORE == 47

    def test_every_rule_names_a_real_feature(self):
        for rule in SCORE_RULES:
            assert rule.feature in FEATURE_NAMES

    def test_per_category_counts_are_not_double_scored(self):
        scored = {r.feature for r in SCORE_RULES}
        assert not any(n.startswith("sensitive_") and n != "sensitive_files"
                       for n in scored)

    def test_every_rule_is_monotonic_and_capped(self):
        for rule in SCORE_RULES:
            last = 0
            for value in range(0, 400):
                points = rule.points(value)
                assert points >= last, (rule.feature, value)
                assert 0 <= points <= rule.cap
                last = points
            assert rule.points(10 ** 9) == rule.cap

    def test_negative_value_cannot_reduce_points(self):
        for rule in SCORE_RULES:
            assert rule.points(-5) == 0


class TestScoreIsExplainable:
    def test_score_equals_sum_of_shown_points(self):
        s = score_features(_fs(files_changed=12, lines_changed=450,
                               sensitive_files=2))
        assert s.score == sum(c.points for c in s.contributions)
        assert s.score == 2 + 4 + 8

    def test_score_recomputes_from_contributions_alone(self):
        fs = _fs(files_changed=30, lines_changed=900, sensitive_files=1,
                 impact_direct_dependents=5, history_max_file_churn=25)
        s = score_features(fs)
        by_rule = {r.feature: r for r in SCORE_RULES}
        recomputed = sum(by_rule[c.feature].points(c.value)
                         for c in s.contributions if c.available)
        assert recomputed == s.score

    def test_contributions_follow_rule_order(self):
        s = score_features(_fs())
        assert [c.feature for c in s.contributions] == [
            r.feature for r in SCORE_RULES]

    def test_a_score_that_disagrees_with_its_contributions_cannot_exist(self):
        contribs = (RiskContribution("files_changed", 10, 2),)
        try:
            RiskScore(3, "medium", contribs)    # shown terms sum to 2
        except ValueError:
            return
        raise AssertionError("constructed an inconsistent score")

    def test_band_must_follow_score(self):
        contribs = (RiskContribution("files_changed", 10, 2),)
        try:
            RiskScore(2, "high", contribs)
        except ValueError:
            return
        raise AssertionError("band/score mismatch accepted")

    def test_repeat_calls_are_identical(self):
        fs = _fs(files_changed=9, sensitive_files=3)
        assert score_features(fs) == score_features(fs)


class TestUnavailable:
    def test_unavailable_contributes_zero_and_is_listed(self):
        s = score_features(_fs(impact_direct_dependents=None,
                               sensitive_files=1))
        c = [x for x in s.contributions
             if x.feature == "impact_direct_dependents"][0]
        assert c.available is False and c.points == 0
        assert s.score == 4

    def test_unavailable_is_not_discounted_below_available_zero(self):
        a = score_features(_fs(impact_truncated=None))
        b = score_features(_fs(impact_truncated=0))
        assert a.score == b.score


class TestBands:
    def test_thresholds(self):
        assert band_for(0) == "low"
        assert band_for(BAND_MEDIUM_MIN - 1) == "low"
        assert band_for(BAND_MEDIUM_MIN) == "medium"
        assert band_for(BAND_HIGH_MIN - 1) == "medium"
        assert band_for(BAND_HIGH_MIN) == "high"
        assert band_for(MAX_SCORE) == "high"

    def test_bands_are_a_closed_ordered_vocabulary(self):
        assert BANDS == ("low", "medium", "high")

    def test_band_never_decreases_as_score_increases(self):
        order = {b: i for i, b in enumerate(BANDS)}
        last = 0
        for score in range(0, MAX_SCORE + 1):
            assert order[band_for(score)] >= last
            last = order[band_for(score)]


class TestRealisticInputs:
    def test_tiny_docs_change_is_low(self):
        fs = extract_risk_features([_file("README.md")])
        assert score_features(fs).band == "low"

    def test_one_auth_file_is_at_least_medium(self):
        fs = extract_risk_features([_file("src/auth/login.py")])
        assert score_features(fs).band in ("medium", "high")

    def test_large_sensitive_change_is_high(self):
        files = [_file(f"billing/m{i}.py", 400) for i in range(4)]
        assert score_features(extract_risk_features(files)).band == "high"

    def test_adding_a_file_never_lowers_the_score(self):
        base = [_file("src/a.py", 50), _file("src/b.py", 50)]
        more = base + [_file("src/auth/c.py", 50)]
        assert (score_features(extract_risk_features(more)).score
                >= score_features(extract_risk_features(base)).score)

    def test_file_order_does_not_change_score(self):
        files = [_file("a.py", 120), _file("auth/b.py", 7), _file("c.md", 1)]
        a = score_features(extract_risk_features(files))
        b = score_features(extract_risk_features(list(reversed(files))))
        assert a == b
