"""Tests for V4.2-E08: Security Evaluation Corpus & Harness.

Coverage:
- V4.2-E08-T01: Labeled vulnerable + benign-twin corpus per E01/E02 rules
- V4.2-E08-T02: Detection and false-positive rate metrics in harness
- V4.2-E08-T03: CI thresholds + baseline file for security detection
- V4.2-E08-T04: Adversarial AI-security cases
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from eval.harness.security_eval import (
    ADVERSARIAL_CASES,
    DEFAULT_SECURITY_THRESHOLDS,
    SECURITY_TWIN_CORPUS,
    SecurityEvalScorecard,
    check_security_gate,
    score_adversarial_ai_security,
    score_security_corpus,
)
from ai_pr_reviewer.security_engine import SecurityEngineV2


def test_labeled_vulnerable_and_benign_twin_corpus():
    """V4.2-E08-T01: Corpus contains paired vulnerable and benign-twin cases."""
    assert len(SECURITY_TWIN_CORPUS) >= 10, "Corpus must have twin cases for each major security rule"
    for pair in SECURITY_TWIN_CORPUS:
        assert pair.rule_id, "Twin pair must have rule_id"
        assert pair.vulnerable_diff, "Twin pair must have vulnerable diff"
        assert pair.benign_diff, "Twin pair must have benign twin diff"


def test_detection_and_false_positive_metrics():
    """V4.2-E08-T02: Compute detection rate, false positive rate, precision, recall."""
    engine = SecurityEngineV2()
    scorecard = score_security_corpus(engine, SECURITY_TWIN_CORPUS)

    assert isinstance(scorecard, SecurityEvalScorecard)
    assert scorecard.total_pairs == len(SECURITY_TWIN_CORPUS)
    assert scorecard.true_positives > 0
    assert scorecard.true_negatives > 0
    assert scorecard.false_positives == 0

    assert scorecard.detection_rate >= 0.90
    assert scorecard.false_positive_rate <= 0.05
    assert scorecard.precision >= 0.90

    d = scorecard.to_dict()
    assert "detection_rate" in d
    assert "false_positive_rate" in d
    assert "precision" in d


def test_ci_thresholds_and_gate_check():
    """V4.2-E08-T03: CI thresholds and gate evaluation."""
    engine = SecurityEngineV2()
    scorecard = score_security_corpus(engine, SECURITY_TWIN_CORPUS)

    passed, failures = check_security_gate(scorecard, DEFAULT_SECURITY_THRESHOLDS)
    assert passed is True, f"Security gate check failed: {failures}"
    assert len(failures) == 0

    # Test failure on unrealistic strict thresholds
    impossible_thresholds = {"min_detection_rate": 1.05}
    passed_fail, failures_fail = check_security_gate(scorecard, impossible_thresholds)
    assert passed_fail is False
    assert len(failures_fail) >= 1


def test_adversarial_ai_security_cases():
    """V4.2-E08-T04: Adversarial AI security cases (injection + exfiltration)."""
    assert len(ADVERSARIAL_CASES) >= 4
    results = score_adversarial_ai_security(ADVERSARIAL_CASES)

    assert results["adversarial_detected_count"] == results["adversarial_total"]
    assert results["adversarial_detection_rate"] == 1.0
    assert results["benign_false_positives"] == 0
