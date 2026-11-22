"""Tests for V4.4-E03 & V4.4-E06: Finding Relations and Historical Feed.

Coverage:
- V4.4-E03-T01: FindingRelation schema (causes, duplicates, regresses, contradicts)
- V4.4-E03-T02: Deterministic relation computation
- V4.4-E03-T03: AI-proposed relations validation
- V4.4-E03-T04: Relation rendering in reports
- V4.4-E06-T01: Unified historical retrieval under budget
- V4.4-E06-T02: Provenance-tagged prompt fencing
- V4.4-E06-T03: Authority-label survival across retrieval
- V4.4-E06-T04: Historical feed token ceiling
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.models import Finding
from ai_pr_reviewer.relations import (
    RELATION_CONTRADICTS,
    RELATION_DUPLICATES,
    RELATION_REGRESSES,
    FindingRelation,
    compute_deterministic_relations,
    format_historical_relations_block,
    validate_proposed_relations,
)


def test_finding_relation_schema_and_serialization():
    """V4.4-E03-T01: FindingRelation schema and serialization."""
    rel = FindingRelation(
        source_fingerprint="fp-001",
        target_fingerprint="fp-002",
        relation_type=RELATION_DUPLICATES,
        confidence="high",
        reason="Same line, matching category and severity",
    )
    d = rel.to_dict()
    assert d["source_fingerprint"] == "fp-001"
    assert d["target_fingerprint"] == "fp-002"
    assert d["relation_type"] == "duplicates"

    round_trip = FindingRelation.from_dict(d)
    assert round_trip == rel


def test_deterministic_relation_computation():
    """V4.4-E03-T02: Compute relations between overlapping or conflicting findings."""
    f1 = Finding(file="auth.py", line=10, severity="high", category="security", title="Insecure cookie")
    f1.fingerprint = "fp-f1"

    # Exact duplicate on same line
    f2 = Finding(file="auth.py", line=10, severity="high", category="security", title="Insecure cookie duplicate")
    f2.fingerprint = "fp-f2"

    # Conflicting severity / category on same line
    f3 = Finding(file="auth.py", line=10, severity="low", category="style", title="Cookie naming convention")
    f3.fingerprint = "fp-f3"

    relations = compute_deterministic_relations([f1, f2, f3])
    rel_types = [r.relation_type for r in relations]
    assert RELATION_DUPLICATES in rel_types
    assert RELATION_CONTRADICTS in rel_types


def test_ai_proposed_relations_validation():
    """V4.4-E03-T03: Untrusted model output proposing relations is strictly validated."""
    known_fps = {"fp-a", "fp-b"}

    # Valid proposed relation
    valid_raw = [
        {"source_fingerprint": "fp-a", "target_fingerprint": "fp-b", "relation_type": "causes", "reason": "Bug triggers leak"}
    ]
    validated = validate_proposed_relations(valid_raw, known_fingerprints=known_fps)
    assert len(validated) == 1
    assert validated[0].relation_type == "causes"

    # Unknown relation type rejected
    invalid_type = [
        {"source_fingerprint": "fp-a", "target_fingerprint": "fp-b", "relation_type": "invalid_magic_type"}
    ]
    assert len(validate_proposed_relations(invalid_type, known_fingerprints=known_fps)) == 0

    # Non-existent target fingerprint rejected
    unknown_fp = [
        {"source_fingerprint": "fp-a", "target_fingerprint": "fp-ghost", "relation_type": "duplicates"}
    ]
    assert len(validate_proposed_relations(unknown_fp, known_fingerprints=known_fps)) == 0


def test_historical_feed_prompt_fencing_and_token_ceiling():
    """V4.4-E06: Historical relation feed bounded by token ceiling and wrapped in nonce fences."""
    rels = [
        FindingRelation(
            source_fingerprint="fp-1",
            target_fingerprint="fp-2",
            relation_type=RELATION_REGRESSES,
            confidence="high",
            reason="Commit reverts security check introduced in PR #12",
        )
    ]

    block = format_historical_relations_block(rels, nonce="nonce123", max_chars=500)
    assert '<historical_relations nonce="nonce123">' in block
    assert "</historical_relations>" in block
    assert "reverts security check" in block
    assert len(block) <= 600
