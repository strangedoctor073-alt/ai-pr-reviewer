"""Tests for V4-E04: evidence engine & provenance.

Provenance fields are pipeline-owned (like lifecycle fields) — they must be
set by the orchestrator from AnalysisOutcome, never from model output.
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.models import (
    LIFECYCLE_FIELDS,
    MAX_EVIDENCE_PER_FINDING,
    MAX_EVIDENCE_LOCATOR_CHARS,
    MAX_EVIDENCE_SUMMARY_CHARS,
    MAX_PROVENANCE_SOURCES,
    EvidenceRecord,
    Finding,
    ProvenanceSource,
    VERIFICATION_STATUSES,
)
from ai_pr_reviewer.findings import (deduplicate, fingerprint_finding,
                                     occurrence_key)
from ai_pr_reviewer.security import redact_secrets


class TestProvenanceFieldsOnFinding:
    """Provenance fields exist on Finding and serialize correctly."""

    def test_provenance_fields_exist_on_finding(self):
        f = Finding(file="x.py", line=1)
        assert f.provenance_engine is None
        assert f.provenance_model is None
        assert f.provenance_agent is None
        assert f.provenance_origin is None

    def test_provenance_fields_in_to_dict(self):
        f = Finding(
            file="x.py", line=1,
            provenance_engine="claude",
            provenance_model="claude-sonnet-4-6",
            provenance_agent=None,
            provenance_origin="ai",
        )
        d = f.to_dict()
        assert d["provenance_engine"] == "claude"
        assert d["provenance_model"] == "claude-sonnet-4-6"
        assert d["provenance_agent"] is None
        assert d["provenance_origin"] == "ai"

    def test_provenance_fields_in_from_dict(self):
        d = {
            "file": "x.py", "line": 1,
            "provenance_engine": "openai",
            "provenance_model": "gpt-4",
            "provenance_agent": None,
            "provenance_origin": "ai",
        }
        f = Finding.from_dict(d)
        assert f.provenance_engine == "openai"
        assert f.provenance_model == "gpt-4"
        assert f.provenance_origin == "ai"

    def test_provenance_round_trip(self):
        """to_dict → from_dict preserves provenance."""
        f = Finding(
            file="x.py", line=1,
            provenance_engine="gemini",
            provenance_model="gemini-2.5-pro",
            provenance_agent=None,
            provenance_origin="ai",
        )
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        assert f2.provenance_engine == "gemini"
        assert f2.provenance_model == "gemini-2.5-pro"
        assert f2.provenance_origin == "ai"


class TestProvenanceStrippedFromModelOutput:
    """from_untrusted_dict must strip provenance — model output cannot forge it."""

    def test_provenance_in_lifecycle_fields(self):
        """Provenance fields are pipeline-owned, like lifecycle fields."""
        assert "provenance_engine" in LIFECYCLE_FIELDS
        assert "provenance_model" in LIFECYCLE_FIELDS
        assert "provenance_agent" in LIFECYCLE_FIELDS
        assert "provenance_origin" in LIFECYCLE_FIELDS

    def test_from_untrusted_dict_strips_provenance(self):
        """Model output cannot set provenance fields."""
        d = {
            "file": "x.py", "line": 1,
            "provenance_engine": "claude",
            "provenance_model": "claude-sonnet-4-6",
            "provenance_agent": "security-reviewer",
            "provenance_origin": "ai",
        }
        f = Finding.from_untrusted_dict(d)
        assert f.provenance_engine is None
        assert f.provenance_model is None
        assert f.provenance_agent is None
        assert f.provenance_origin is None

    def test_from_untrusted_dict_strips_all_lifecycle_fields(self):
        """All lifecycle + provenance fields are stripped from model output."""
        d = {
            "file": "x.py", "line": 1,
            "fingerprint": "abc123",
            "state": "resolved",
            "github_comment_id": 42,
            "verification_status": "resolved",
            "provenance_engine": "claude",
            "provenance_model": "claude-sonnet-4-6",
            "provenance_agent": "security-reviewer",
            "provenance_origin": "ai",
        }
        f = Finding.from_untrusted_dict(d)
        assert f.fingerprint is None
        assert f.state == "new"  # default, not "resolved"
        assert f.github_comment_id is None
        assert f.verification_status is None
        assert f.provenance_engine is None
        assert f.provenance_model is None
        assert f.provenance_agent is None
        assert f.provenance_origin is None

    def test_from_untrusted_dict_preserves_content_fields(self):
        """Content fields (file, line, severity, etc.) are preserved."""
        d = {
            "file": "x.py", "line": 1,
            "severity": "high",
            "category": "security",
            "title": "SQL injection",
            "explanation": "User input concatenated into query",
            "suggestion": "Use parameterized queries",
            "confidence": "high",
            "provenance_engine": "claude",
        }
        f = Finding.from_untrusted_dict(d)
        assert f.file == "x.py"
        assert f.line == 1
        assert f.severity == "high"
        assert f.category == "security"
        assert f.title == "SQL injection"
        assert f.explanation == "User input concatenated into query"
        assert f.suggestion == "Use parameterized queries"
        assert f.confidence == "high"
        assert f.provenance_engine is None


class TestProvenanceRedaction:
    """Evidence content may quote code/secrets — redaction must apply."""

    def test_redact_secrets_on_evidence_payload(self):
        """A finding that quotes a secret must have it redacted."""
        f = Finding(
            file="config.py", line=1,
            explanation="The API key is sk-abc123def456ghi789jkl012mno345pqr",
            provenance_engine="claude",
            provenance_model="claude-sonnet-4-6",
            provenance_origin="ai",
        )
        d = f.to_dict()
        # The explanation in the dict should still contain the secret
        # (redaction happens at persistence/post time, not in to_dict).
        # But redact_secrets() must catch it.
        redacted = redact_secrets(d["explanation"])
        assert "sk-abc123def456ghi789jkl012mno345pqr" not in redacted
        assert "[REDACTED]" in redacted

    def test_redact_secrets_on_provenance_model(self):
        """Provenance model field should not contain secrets (but redact anyway)."""
        f = Finding(
            file="x.py", line=1,
            provenance_model="model-with-ghp_abc123def456ghi789jkl",
        )
        d = f.to_dict()
        redacted = redact_secrets(str(d["provenance_model"]))
        assert "ghp_abc123def456ghi789jkl" not in redacted


class TestProvenanceOrigin:
    """Provenance origin is derived from engine type."""

    @pytest.mark.parametrize("engine,expected_origin", [
        ("claude", "ai"),
        ("openai", "ai"),
        ("gemini", "ai"),
        ("static", "static"),
        ("claude+static", "ai"),
        ("", "ai"),
    ])
    def test_origin_derivation(self, engine, expected_origin):
        """Origin is 'static' only for pure static engine."""
        origin = "static" if engine == "static" else "ai"
        assert origin == expected_origin


class TestProvenanceBackwardCompatibility:
    """Old findings without provenance must not crash."""

    def test_from_dict_without_provenance(self):
        """A finding dict without provenance fields loads fine."""
        d = {
            "file": "x.py", "line": 1,
            "severity": "medium",
            "category": "bug",
            "title": "Null pointer",
        }
        f = Finding.from_dict(d)
        assert f.provenance_engine is None
        assert f.provenance_model is None
        assert f.provenance_agent is None
        assert f.provenance_origin is None

    def test_to_dict_without_provenance_has_none_values(self):
        """to_dict includes provenance keys with None values."""
        f = Finding(file="x.py", line=1)
        d = f.to_dict()
        assert "provenance_engine" in d
        assert "provenance_model" in d
        assert "provenance_agent" in d
        assert "provenance_origin" in d
        assert d["provenance_engine"] is None
        assert d["provenance_model"] is None
        assert d["provenance_agent"] is None
        assert d["provenance_origin"] is None

    def test_from_untrusted_dict_without_provenance(self):
        """Model output without provenance fields loads fine."""
        d = {"file": "x.py", "line": 1, "severity": "low"}
        f = Finding.from_untrusted_dict(d)
        assert f.provenance_engine is None
        assert f.provenance_model is None

    # -- V4-E08-T05: the deserialize path enforces the same bound as the
    #    merge path — an over-long stored list is capped, never trusted.

    @staticmethod
    def _sources(n):
        return [{"engine": f"eng-{i}", "model": "m", "origin": "ai",
                 "agent": None} for i in range(n)]

    def test_provenance_sources_are_capped_on_deserialize(self):
        f = Finding.from_dict({"file": "x.py", "line": 1,
                               "provenance_sources": self._sources(12)})
        assert len(f.provenance_sources) == MAX_PROVENANCE_SOURCES

    def test_provenance_sources_cap_boundary(self):
        """Exactly at the cap is kept in full; one under stays untouched."""
        at = Finding.from_dict({"file": "x.py", "line": 1,
                                "provenance_sources": self._sources(
                                    MAX_PROVENANCE_SOURCES)})
        under = Finding.from_dict({"file": "x.py", "line": 1,
                                   "provenance_sources": self._sources(
                                       MAX_PROVENANCE_SOURCES - 1)})
        assert len(at.provenance_sources) == MAX_PROVENANCE_SOURCES
        assert len(under.provenance_sources) == MAX_PROVENANCE_SOURCES - 1
        # none of the kept records are malformed
        assert all(s.engine for s in at.provenance_sources)

    def test_provenance_sources_lenient_on_malformed_input(self):
        assert Finding.from_dict({"file": "x.py", "line": 1,
                                  "provenance_sources": "not-a-list"}
                                 ).provenance_sources == ()
        mixed = Finding.from_dict({
            "file": "x.py", "line": 1,
            "provenance_sources": ["junk", {"engine": "claude"}]}).provenance_sources
        assert len(mixed) == 1 and mixed[0].engine == "claude"


# ---------------------------------------------------------------------------
# V4-E04-T02 · embedded evidence records (ADR-004)
# ---------------------------------------------------------------------------

_DIFF = """diff --git a/app/payments.py b/app/payments.py
--- a/app/payments.py
+++ b/app/payments.py
@@ -1,3 +1,4 @@
 def charge(card):
+    api_key = "sk-abc123def456ghi789jkl012mno345pqr"
     query = "SELECT * FROM users"
     return db.run(query)
"""


class TestEvidenceRecord:
    """EvidenceRecord: closed kinds, redaction at construction, integrity."""

    def test_create_produces_valid_record(self):
        e = EvidenceRecord.create(
            kind="rule_ref", locator="rule:SEC002",
            summary="Hardcoded credential", check_type="security")
        assert e.kind == "rule_ref"
        assert e.locator == "rule:SEC002"
        assert e.check_type == "security"
        assert e.content_hash and e.integrity_ok

    def test_unknown_kind_is_rejected(self):
        """The kind set is closed — a new kind is a contract change."""
        with pytest.raises(ValueError):
            EvidenceRecord.create(kind="made_up", locator="x", summary="y")

    def test_empty_locator_is_rejected(self):
        with pytest.raises(ValueError):
            EvidenceRecord.create(kind="rule_ref", locator="   ", summary="y")

    def test_construction_redacts_planted_secret(self):
        """Redaction is inside the write path (construction), not at callers."""
        e = EvidenceRecord.create(
            kind="diff_hunk", locator="a.py:1-1",
            summary='api_key = "sk-abc123def456ghi789jkl012mno345pqr"')
        assert "sk-abc123def456ghi789jkl012mno345pqr" not in e.summary
        assert "[REDACTED]" in e.summary

    def test_summary_is_bounded(self):
        e = EvidenceRecord.create(
            kind="log_excerpt", locator="log:1", summary="x" * 5000)
        assert len(e.summary) <= MAX_EVIDENCE_SUMMARY_CHARS

    def test_tamper_breaks_integrity(self):
        from dataclasses import replace
        e = EvidenceRecord.create(kind="rule_ref", locator="rule:R", summary="s")
        assert e.integrity_ok
        tampered = replace(e, summary="tampered")
        assert not tampered.integrity_ok

    def test_round_trip_preserves_record(self):
        e = EvidenceRecord.create(kind="diff_hunk", locator="a.py:2-3",
                                  summary="line", check_type="bug")
        again = EvidenceRecord.from_dict(e.to_dict())
        assert again == e

    def test_from_dict_is_lenient_on_malformed_entries(self):
        assert EvidenceRecord.from_dict({"kind": "rule_ref"}) is None  # no locator
        assert EvidenceRecord.from_dict("not-a-dict") is None
        assert EvidenceRecord.from_dict({"locator": "x"}) is None       # no kind

    def test_from_dict_re_redacts(self):
        """Defense in depth: a stored row is re-redacted on read."""
        e = EvidenceRecord.from_dict({
            "kind": "diff_hunk", "locator": "a.py:1-1",
            "summary": 'password = "supersecretvalue"',
            "content_hash": "deadbeefdeadbeef",
        })
        assert "supersecretvalue" not in e.summary
        # stored hash is preserved so tampering surfaces via integrity_ok
        assert e.content_hash == "deadbeefdeadbeef"
        assert not e.integrity_ok

    def test_from_dict_re_redacts_the_locator(self):
        """V4-E08-T05: the reader applies the write path's redaction to the
        locator too, not just the summary — a tampered row cannot smuggle
        a credential past ``create``."""
        secret = "sk-aBcD1234eFgH5678iJkL9012mNoP"     # synthetic, ≥20-char tail
        e = EvidenceRecord.from_dict({
            "kind": "diff_hunk", "locator": f"audit/{secret}:1",
            "summary": "clean", "content_hash": "cafecafecafecafe",
        })
        assert e is not None
        assert secret not in e.locator
        assert "[REDACTED]" in e.locator

    def test_from_dict_bounds_the_locator(self):
        e = EvidenceRecord.from_dict({
            "kind": "diff_hunk", "locator": "a" * 500,
            "summary": "x", "content_hash": "cafecafecafecafe",
        })
        assert e is not None
        assert len(e.locator) <= MAX_EVIDENCE_LOCATOR_CHARS

    def test_from_dict_rejects_unknown_kind(self):
        """Closed kind set on read, exactly like on write (V4-E08-T05)."""
        assert EvidenceRecord.from_dict({
            "kind": "made_up", "locator": "x:1", "summary": "y",
        }) is None
        # a supported kind still round-trips (no regression for real rows)
        ok = EvidenceRecord.from_dict({
            "kind": "diff_hunk", "locator": "x:1", "summary": "y",
        })
        assert ok is not None
        assert ok.kind == "diff_hunk"


class TestEvidenceOnFinding:
    """Finding.evidence is pipeline-owned, serializable, bounded."""

    def test_evidence_in_to_dict_and_round_trip(self):
        f = Finding(file="a.py", line=1, evidence=(
            EvidenceRecord.create(kind="rule_ref", locator="rule:SEC001",
                                  summary="sql"),
            EvidenceRecord.create(kind="diff_hunk", locator="a.py:1-1",
                                  summary="code"),
        ))
        d = f.to_dict()
        assert [e["kind"] for e in d["evidence"]] == ["rule_ref", "diff_hunk"]
        again = Finding.from_dict(d)
        assert again.evidence == f.evidence

    def test_from_untrusted_dict_strips_evidence(self):
        """Model output cannot forge evidence claims (roadmap V4 security
        implication: 'model output must not forge evidence: X claims')."""
        forged = {
            "file": "a.py", "line": 1, "title": "x",
            "evidence": [{"kind": "rule_ref", "locator": "rule:FAKE",
                          "summary": "trust me"}],
        }
        f = Finding.from_untrusted_dict(forged)
        assert f.evidence == ()

    def test_from_untrusted_dict_strips_sources_and_merge_trail(self):
        forged = {
            "file": "a.py", "line": 1, "title": "x",
            "provenance_sources": [{"engine": "claude"}],
            "merged_fingerprints": ["deadbeefdeadbeef"],
        }
        f = Finding.from_untrusted_dict(forged)
        assert f.provenance_sources == ()
        assert f.merged_fingerprints == ()

    def test_from_dict_skips_malformed_evidence(self):
        f = Finding.from_dict({
            "file": "a.py", "line": 1,
            "evidence": ["not-a-dict", {"kind": "rule_ref"}, {"locator": "x"}],
        })
        assert f.evidence == ()

    def test_from_dict_caps_evidence_list(self):
        many = [{"kind": "rule_ref", "locator": f"rule:R{i}",
                 "summary": f"s{i}", "content_hash": "h"} for i in range(50)]
        f = Finding.from_dict({"file": "a.py", "line": 1, "evidence": many})
        assert len(f.evidence) <= MAX_EVIDENCE_PER_FINDING


class TestDedupMergesProvenanceAndEvidence:
    """V4-E04-T03: dedup keeps the first occurrence AND merges provenance
    and evidence (C3 fix); V4-E05-T03: cross-engine occurrence merge."""

    @staticmethod
    def _ai(title, file="a.py", line=1, model="m1"):
        f = Finding(file=file, line=line, title=title, category="security",
                    severity="high")
        f.provenance_engine = "claude"
        f.provenance_model = model
        f.provenance_origin = "ai"
        f.provenance_sources = (ProvenanceSource(
            engine="claude", model=model, origin="ai", agent=None),)
        return f

    @staticmethod
    def _static(title, file="a.py", line=1):
        f = Finding(file=file, line=line, title=title, category="security",
                    severity="high")
        f.provenance_engine = "static"
        f.provenance_model = "static-rules-v1"
        f.provenance_origin = "static"
        f.provenance_sources = (ProvenanceSource(
            engine="static", model="static-rules-v1", origin="static",
            agent=None),)
        return f

    def test_same_fingerprint_merges_both_attributions(self):
        a = self._ai("SQL injection in query()")
        b = self._static("SQL injection in query()")
        out = deduplicate([a, b])
        assert len(out) == 1
        kept = out[0]
        engines = {s.engine for s in kept.provenance_sources}
        assert engines == {"claude", "static"}
        # scalar provenance mirrors the first (winning) source
        assert kept.provenance_engine == "claude"

    def test_merge_dedupes_identical_sources(self):
        a = self._ai("SQL injection in query()")
        b = self._ai("SQL injection in query()")
        out = deduplicate([a, b])
        assert len(out[0].provenance_sources) == 1

    def test_cross_engine_occurrence_merge_keeps_winner_fingerprint(self):
        """Two engines, different v1 fingerprints, same occurrence key:
        one survivor keeps its v1 storage key, loser recorded in the trail.

        The realistic C4 scenario: both engines flag the same SQL-injection
        issue, but quote the table name differently -- v1 (title-based)
        treats the quote characters as part of the title and mints two
        fingerprints; the occurrence key abstracts the literal and merges.
        """
        a = self._ai("Possible SQL injection in 'users' table")
        b = self._static('Possible SQL injection in "users" table')
        assert fingerprint_finding(a) != fingerprint_finding(b)  # C4 gap
        assert occurrence_key(a) == occurrence_key(b) != ""
        out = deduplicate([a, b])
        assert len(out) == 1
        kept = out[0]
        # The winner's v1 fingerprint stays the storage/comment/mute key.
        assert fingerprint_finding(kept) == fingerprint_finding(a)
        assert fingerprint_finding(b) in kept.merged_fingerprints
        engines = {s.engine for s in kept.provenance_sources}
        assert engines == {"claude", "static"}

    def test_no_symbol_anchor_refuses_cross_engine_merge(self):
        """Conservative miss: findings with no code-like symbol anchor never
        merge across engines even when wordings are similar (a wrong merge
        is worse than a missed one). v1 still dedups exact repeats."""
        a = self._ai("The logic looks wrong here")
        b = self._static("This logic looks broken to me")
        assert fingerprint_finding(a) != fingerprint_finding(b)   # not v1-dups
        assert occurrence_key(a) == "" == occurrence_key(b)       # no anchor
        out = deduplicate([a, b])
        assert len(out) == 2

    def test_exact_repeats_still_collapse_without_any_anchor(self):
        """v1 pass is unchanged: identical titles collapse (same fingerprint)."""
        a = self._ai("The logic looks wrong here")
        b = self._static("The logic looks wrong here")
        assert len(deduplicate([a, b])) == 1

    def test_different_files_never_merge(self):
        a = self._ai("Possible SQL injection in query(", file="a.py")
        b = self._static("Possible SQL injection in query(", file="b.py")
        assert len(deduplicate([a, b])) == 2

    def test_dedup_is_deterministic(self):
        items = [self._ai("Possible SQL injection in query("),
                 self._static("Possible SQL injection in query("),
                 self._ai("eval( used on input")]
        first = [f.to_dict() for f in deduplicate(items)]
        second = [f.to_dict() for f in deduplicate(items)]
        assert first == second


class TestStaticEngineEvidence:
    """V4-E04-T05: static findings normalize onto the evidence contract."""

    def test_static_findings_carry_rule_and_hunk_evidence(self):
        from ai_pr_reviewer.diff_parser import parse_unified_diff
        from ai_pr_reviewer.static.engine import StaticEngine
        files = parse_unified_diff(_DIFF)
        findings = StaticEngine().run(files)
        assert findings, "SEC002 must match the hardcoded credential"
        f = next(x for x in findings if x.rule_id == "SEC002")
        kinds = [e.kind for e in f.evidence]
        assert "rule_ref" in kinds and "diff_hunk" in kinds
        rule_ev = next(e for e in f.evidence if e.kind == "rule_ref")
        assert rule_ev.locator == "rule:SEC002"

    def test_static_evidence_redacts_the_quoted_secret(self):
        from ai_pr_reviewer.diff_parser import parse_unified_diff
        from ai_pr_reviewer.static.engine import StaticEngine
        findings = StaticEngine().run(parse_unified_diff(_DIFF))
        f = next(x for x in findings if x.rule_id == "SEC002")
        joined = " ".join(e.summary for e in f.evidence)
        assert "sk-abc123def456ghi789jkl012mno345pqr" not in joined

    def test_static_finding_without_anchor_has_no_hunk_evidence(self):
        from ai_pr_reviewer.diff_parser import parse_unified_diff
        from ai_pr_reviewer.static.engine import StaticEngine
        files = parse_unified_diff(_DIFF)
        for f in StaticEngine().run(files):
            if f.line is None:
                assert all(e.kind != "diff_hunk" for e in f.evidence)


class TestOrchestratorEvidenceWiring:
    """V4-E04-T03: the orchestrator stamps provenance before dedup and
    attaches diff-hunk evidence to AI findings that lack records."""

    def test_stamp_provenance_sets_scalars_and_sources(self):
        from ai_pr_reviewer.models import AnalysisOutcome
        from ai_pr_reviewer.orchestrator import _stamp_provenance
        outcome = AnalysisOutcome(findings=[], summary="", mode="claude",
                                  model="claude-sonnet-4-6", engine="claude")
        f = Finding(file="a.py", line=1, title="x")
        _stamp_provenance([f], outcome)
        assert f.provenance_engine == "claude"
        assert len(f.provenance_sources) == 1
        assert f.provenance_sources[0].origin == "ai"

    def test_attach_diff_evidence_quotes_the_anchored_line(self):
        from ai_pr_reviewer.diff_parser import parse_unified_diff
        from ai_pr_reviewer.orchestrator import _attach_diff_evidence
        files = parse_unified_diff(_DIFF)
        f = Finding(file="app/payments.py", line=2, title="AI says so")
        _attach_diff_evidence([f], files)
        assert len(f.evidence) == 1
        assert f.evidence[0].kind == "diff_hunk"
        assert f.evidence[0].locator == "app/payments.py:2-2"

    def test_attach_diff_evidence_skips_existing_and_unanchored(self):
        from ai_pr_reviewer.diff_parser import parse_unified_diff
        from ai_pr_reviewer.orchestrator import _attach_diff_evidence
        files = parse_unified_diff(_DIFF)
        with_ev = Finding(file="app/payments.py", line=2, title="x", evidence=(
            EvidenceRecord.create(kind="rule_ref", locator="rule:R", summary="s"),))
        unanchored = Finding(file="app/payments.py", line=None, title="file note")
        _attach_diff_evidence([with_ev, unanchored], files)
        assert len(with_ev.evidence) == 1          # untouched
        assert unanchored.evidence == ()            # honest absence


class TestReporterProvenanceSurfacing:
    """V4-E04-T04: 'why was I told this?' is answerable in the summary."""

    def test_suffix_renders_engine_evidence_and_merge(self):
        from ai_pr_reviewer.reporter import _provenance_suffix
        f = Finding(file="a.py", line=1, title="x",
                    provenance_engine="claude", provenance_model="m1",
                    evidence=(EvidenceRecord.create(
                        kind="rule_ref", locator="rule:SEC002", summary="s"),),
                    merged_fingerprints=("deadbeefdeadbeef",))
        s = _provenance_suffix(f)
        assert "source: claude (m1)" in s
        assert "rule:SEC002" in s
        assert "merged 1 duplicate(s)" in s

    def test_suffix_is_empty_without_provenance(self):
        """Backcompat: pre-V4 findings render byte-identically."""
        from ai_pr_reviewer.reporter import _provenance_suffix
        assert _provenance_suffix(Finding(file="a.py", line=1, title="x")) == ""


# ===========================================================================
# V4-E04 hardening pass (audit-driven). Everything below was added after the
# as-built audit; the tests above are unchanged.
# ===========================================================================

import dataclasses
import hashlib
import json
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

from ai_pr_reviewer.models import (
    MAX_EVIDENCE_CHECK_TYPE_CHARS,
    MAX_EVIDENCE_HASH_CHARS,
    MAX_PROVENANCE_FIELD_CHARS,
    PROVENANCE_UNAVAILABLE_REASON,
    STATIC_RULE_ENGINE_VERSION,
    PRContext,
    ReviewResult,
    derive_provenance_source,
    describe_provenance,
)

_PLANT = "sk-abc123def456ghi789jkl012mno345pqr"          # synthetic key
_ANCHOR = {"file": "x.py", "line": 1, "title": "t"}


def _owned_by_convention() -> set[str]:
    """Finding fields that are pipeline-owned by NAME: every provenance_*
    field plus the evidence/merge-trail fields. Derived by introspection, so
    a field added tomorrow under the same convention is covered without
    anyone remembering to extend a test list."""
    return {f.name for f in dataclasses.fields(Finding)
            if f.name.startswith("provenance_")
            or f.name in ("evidence", "merged_fingerprints")}


_FORGED = {
    "fingerprint": "feedfacefeedface", "state": "resolved",
    "first_seen_sha": "f" * 40, "last_seen_sha": "f" * 40,
    "resolved_at": "2099-01-01T00:00:00Z", "github_comment_id": 999,
    "verification_status": "resolved", "verification_reason": "FORGED",
    "verified_at": "2099-01-01T00:00:00Z",
    "provenance_sources": [{"engine": "FORGED-ENGINE", "model": "FORGED",
                            "origin": "ai", "agent": "FORGED-AGENT"}],
    "evidence": [{"kind": "rule_ref", "locator": "rule:FORGED",
                  "summary": "FORGED-EVIDENCE", "content_hash": "0" * 16}],
    "merged_fingerprints": ["feedfacefeedface"],
}


def _forged_value(name: str):
    # unknown / future fields still get a (string) forgery attempt
    return _FORGED.get(name, f"FORGED-{name}")


class TestPipelineOwnedFieldsCannotBeForged:
    """THE highest-risk regression in V4-E04: V5's multi-agent merge keys on
    provenance, so model output must never be able to set it."""

    def test_convention_is_not_vacuous(self):
        assert {"provenance_engine", "provenance_model", "provenance_agent",
                "provenance_origin", "provenance_sources", "evidence",
                "merged_fingerprints"} <= _owned_by_convention()

    def test_every_pipeline_owned_field_is_stripped_by_name(self):
        """Drift guard: a new provenance_* / evidence field added to Finding
        but forgotten in LIFECYCLE_FIELDS fails HERE, not in production."""
        missing = _owned_by_convention() - set(LIFECYCLE_FIELDS)
        assert not missing, (
            f"pipeline-owned Finding fields not in LIFECYCLE_FIELDS: "
            f"{sorted(missing)} -- from_untrusted_dict would let a model set them")

    def test_lifecycle_fields_are_all_real_finding_fields(self):
        """No phantom protection: a typo'd name in LIFECYCLE_FIELDS strips
        nothing while looking safe."""
        real = {f.name for f in dataclasses.fields(Finding)}
        assert set(LIFECYCLE_FIELDS) <= real

    def test_exhaustive_forgery_of_every_owned_field_is_fully_stripped(self):
        clean = Finding.from_dict(dict(_ANCHOR))
        payload = {**_ANCHOR,
                   **{n: _forged_value(n) for n in LIFECYCLE_FIELDS}}
        got = Finding.from_untrusted_dict(payload)
        for name in LIFECYCLE_FIELDS:
            assert getattr(got, name) == getattr(clean, name), (
                f"{name} survived from_untrusted_dict")
        assert got.to_dict() == clean.to_dict()
        assert "FORGED" not in json.dumps(got.to_dict())

    @pytest.mark.parametrize("key", [
        "Evidence", "EVIDENCE", " evidence", "evidence ", "evidence​",
        "provenance-engine", "provenanceEngine", "PROVENANCE_ENGINE",
        "provenance_engine​", "Provenance_Sources", "merged-fingerprints",
    ])
    def test_key_variants_are_inert(self, key):
        """from_dict reads exact keys only. If anyone adds key normalization
        (case/whitespace folding) these variants become a forgery path."""
        got = Finding.from_untrusted_dict(
            {**_ANCHOR, key: "FORGED" if "evidence" not in key.lower()
             and "sources" not in key.lower()
             and "fingerprints" not in key.lower() else [{"kind": "rule_ref",
                                                          "locator": "FORGED"}]})
        assert got.to_dict() == Finding.from_dict(dict(_ANCHOR)).to_dict()

    def test_forged_rule_id_cannot_pose_as_the_rule_engine(self):
        """rule_id is plain content a model can emit; attribution must not
        key on it (it keys on pipeline-owned rule_ref evidence)."""
        f = Finding.from_untrusted_dict({
            **_ANCHOR, "rule_id": "SEC002",
            "evidence": [{"kind": "rule_ref", "locator": "rule:SEC002",
                          "summary": "trust me"}]})
        assert f.rule_id == "SEC002"                  # content survives...
        src = derive_provenance_source(
            f, outcome_engine="claude+static", outcome_model="m1")
        assert (src.engine, src.origin) == ("claude", "ai")   # ...but is not static

    # -- the real provider parse paths (not a re-implementation of them) ----

    @staticmethod
    def _forged_finding() -> dict:
        return {
            "file": "app/service.py", "line": 2, "severity": "high",
            "category": "security", "title": "t", "explanation": "e",
            "confidence": "high",
            **{n: _forged_value(n) for n in LIFECYCLE_FIELDS},
            "provenance_engine": "FORGED-ENGINE",
            "provenance_model": "FORGED-MODEL",
            "provenance_agent": "FORGED-AGENT",
            "provenance_origin": "FORGED-ORIGIN",
        }

    @staticmethod
    def _envelope(kind: str, finding: dict) -> dict:
        body = json.dumps({"summary": "s", "findings": [finding],
                           "warnings": []})
        if kind == "claude":
            return {"usage": {"input_tokens": 1, "output_tokens": 1},
                    "content": [{"type": "text", "text": body}]}
        if kind == "openai":
            return {"usage": {"prompt_tokens": 1, "completion_tokens": 1},
                    "choices": [{"message": {"content": body}}]}
        return {"candidates": [{"content": {"parts": [{"text": body}]}}]}

    @pytest.mark.parametrize("kind", ["claude", "openai", "gemini"])
    def test_every_provider_parse_path_strips_forged_provenance(self, kind):
        from ai_pr_reviewer.ai.claude import ClaudeProvider
        from ai_pr_reviewer.ai.gemini import GeminiProvider
        from ai_pr_reviewer.ai.openai import OpenAIProvider
        from ai_pr_reviewer.diff_parser import parse_unified_diff

        provider = {"claude": lambda: ClaudeProvider(api_key="sk-ant-test"),
                    "openai": lambda: OpenAIProvider(api_key="sk-test",
                                                     model="gpt-test"),
                    "gemini": lambda: GeminiProvider(api_key="AIza-test",
                                                     model="gemini-test"),
                    }[kind]()
        response = SimpleNamespace(
            status_code=200, raise_for_status=lambda: None,
            json=lambda: self._envelope(kind, self._forged_finding()))
        provider._client.post = Mock(return_value=response)
        files = parse_unified_diff(
            "--- a/app/service.py\n+++ b/app/service.py\n"
            "@@ -1,1 +1,2 @@\n def run():\n+    return 1\n")
        context = SimpleNamespace(files=files, focus_areas=[],
                                  memory_notes=[], previous_findings=[])

        outcome = provider.analyze(context)

        assert outcome.findings, "sanity: the finding was parsed, not dropped"
        for f in outcome.findings:
            for name in _owned_by_convention():
                assert getattr(f, name) in (None, ()), (
                    f"{kind}: model-forged {name} reached the pipeline")
            assert f.state == "new" and f.fingerprint is None
            assert "FORGED" not in json.dumps(f.to_dict())

    def test_forgery_never_reaches_the_final_report(self, monkeypatch):
        """Full pipeline: a model's forged provenance/evidence is replaced by
        the pipeline's own stamping; the report carries only real values."""
        from ai_pr_reviewer import orchestrator as orch, reporter
        from ai_pr_reviewer.config import Config
        from ai_pr_reviewer.model_router import reset_circuits
        from ai_pr_reviewer.models import AnalysisOutcome

        class _Engine:
            backend = "claude"

            def analyze(self, context):
                return AnalysisOutcome(
                    findings=[Finding.from_untrusted_dict(
                        TestPipelineOwnedFieldsCannotBeForged._forged_finding())],
                    summary="s", mode="claude", model="claude-test",
                    engine="claude", fallback_used=False, batch_count=1)

        reset_circuits()
        monkeypatch.setattr(orch, "build_context",
                            lambda pr, files, cfg, storage=None, gh=None:
                            SimpleNamespace(pr=pr, files=files,
                                            previous_findings=[]))
        monkeypatch.setattr(orch, "get_provider", lambda cfg, ctx: _Engine())
        cfg = Config(repo="acme/api", pr_number=7, severity_threshold="low",
                     max_comments=20)
        diff = ("diff --git a/app/service.py b/app/service.py\n"
                "--- a/app/service.py\n+++ b/app/service.py\n"
                "@@ -1,2 +1,3 @@\n ctx\n+    return 1\n ctx2\n")
        result = orch.ReviewOrchestrator(
            cfg, None, None, pr=PRContext(repo="acme/api", pr_number=7,
                                          head_sha="h" * 40),
            diff_text=diff).run()

        report = reporter.finalize_report(result, report_id="forgery")
        row = report["findings"][0]
        assert (row["provenance_engine"], row["provenance_model"],
                row["provenance_origin"]) == ("claude", "claude-test", "ai")
        assert row["provenance_agent"] is None
        assert [s["engine"] for s in row["provenance_sources"]] == ["claude"]
        assert row["merged_fingerprints"] == []
        # the only evidence is what the PIPELINE attached from the real diff
        assert [(e["kind"], e["locator"]) for e in row["evidence"]] == [
            ("diff_hunk", "app/service.py:2-2")]
        assert "FORGED" not in json.dumps(report)


# ---------------------------------------------------------------------------
# V4-E04-T05 · redaction is structural, not a convention of well-behaved callers
# ---------------------------------------------------------------------------

# (label, text that embeds the secret, the substring that must NEVER survive)
_SECRET_SHAPES = [
    ("github-token", "tok ghp_A1b2C3d4E5f6G7h8I9j0K1l2 end",
     "ghp_A1b2C3d4E5f6G7h8I9j0K1l2"),
    ("api-sk-key", f"key {_PLANT} end", _PLANT),
    ("aws-access-key", "id AKIAABCDEFGHIJKLMNOP end", "AKIAABCDEFGHIJKLMNOP"),
    ("bearer-header", "Authorization: Bearer abcdefghijklmnop1234567890",
     "abcdefghijklmnop1234567890"),
    ("key-value", 'password = "hunter2hunter2"', "hunter2hunter2"),
    ("jwt", "t eyJabcdefghij.eyJklmnopqrst.abcdefghijklm x",
     "eyJabcdefghij.eyJklmnopqrst.abcdefghijklm"),
    ("database-url", "postgres://admin:SuperSecretPw@db.internal/app",
     "SuperSecretPw"),
    ("private-key-block",
     "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLI\n"
     "-----END RSA PRIVATE KEY-----", "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLI"),
    ("hex-digest", "d " + "0123456789abcdef" * 3 + " d",
     "0123456789abcdef" * 3),
]
_SHAPE_IDS = [s[0] for s in _SECRET_SHAPES]


def _tainted_records(text: str) -> dict[str, EvidenceRecord]:
    """The same hostile text pushed through every way a record can come into
    being. Redaction must hold for ALL of them, including the ones that
    bypass ``create`` (the audit found the direct constructor leaked)."""
    clean = EvidenceRecord.create(kind="rule_ref", locator="rule:R",
                                  summary="ok")
    return {
        "create": EvidenceRecord.create(
            kind="diff_hunk", locator=f"a.py {text}", summary=text,
            check_type=text),
        "direct-constructor": EvidenceRecord(
            kind="diff_hunk", locator=f"a.py {text}", summary=text,
            content_hash=text, check_type=text),
        "dataclasses.replace": dataclasses.replace(
            clean, summary=text, locator=f"a.py {text}", check_type=text,
            content_hash=text),
        "from_dict": EvidenceRecord.from_dict({
            "kind": "diff_hunk", "locator": f"a.py {text}", "summary": text,
            "content_hash": text, "check_type": text}),
    }


class TestEvidenceRedactionIsStructural:
    @pytest.mark.parametrize("label,text,needle", _SECRET_SHAPES, ids=_SHAPE_IDS)
    def test_no_construction_route_can_store_the_secret(self, label, text, needle):
        for route, rec in _tainted_records(text).items():
            assert rec is not None, route
            blob = json.dumps(rec.to_dict())
            assert needle not in blob, f"{label} leaked via {route}"

    @pytest.mark.parametrize("label,text,needle", _SECRET_SHAPES, ids=_SHAPE_IDS)
    def test_secret_is_absent_from_every_output_sink(self, label, text, needle):
        """Finding.to_dict (report JSON / dashboard payload / stored row),
        the markdown summary comment, and the display view."""
        from ai_pr_reviewer.reporter import build_summary_markdown, finalize_report

        for route, rec in _tainted_records(text).items():
            f = Finding(file="a.py", line=1, title="t", evidence=(rec,),
                        provenance_engine=text, provenance_model=text,
                        provenance_agent=text, provenance_origin=text,
                        provenance_sources=(ProvenanceSource(
                            engine=text, model=text, origin=text, agent=text),))
            result = ReviewResult(
                pr=PRContext(repo="o/r", pr_number=1), findings=[f])
            sinks = {
                "to_dict": json.dumps(f.to_dict()),
                "report": json.dumps(finalize_report(result, report_id="x")),
                "markdown": build_summary_markdown(result),
                "describe": json.dumps(describe_provenance(f)),
            }
            for sink, blob in sinks.items():
                assert needle not in blob, f"{label}: {route} -> {sink}"

    def test_direct_construction_breaks_integrity_instead_of_hiding_it(self):
        """A record whose text had to be redacted no longer matches the hash
        it was built with: tamper-evidence stays honest."""
        rec = EvidenceRecord(
            kind="diff_hunk", locator="a.py:1-1",
            summary=f'k = "{_PLANT}"',
            content_hash=hashlib.sha256(
                f'k = "{_PLANT}"'.encode()).hexdigest()[:16])
        assert _PLANT not in rec.summary
        assert rec.integrity_ok is False

    def test_clean_records_are_byte_identical_through_every_route(self):
        summary = "    total = compute_refund(order_id, amount)"
        want = {
            "kind": "diff_hunk", "locator": "app/payments.py:2-2",
            "check_type": "security", "summary": summary,
            "content_hash": hashlib.sha256(summary.encode()).hexdigest()[:16],
        }
        e = EvidenceRecord.create(kind="diff_hunk", locator="app/payments.py:2-2",
                                  summary=summary, check_type="security")
        assert e.to_dict() == want
        assert EvidenceRecord.from_dict(want).to_dict() == want
        assert dataclasses.replace(e).to_dict() == want
        assert e.integrity_ok

    def test_create_commits_to_the_final_stored_text_even_at_the_bound(self):
        """Redact-then-truncate can leave a string that NOW matches a secret
        pattern (cut a longer token at exactly 16+4 chars). The fixed point
        keeps hash and text consistent, and the record stable under
        reconstruction."""
        # exactly "AKIA" + 16 chars remain after the cut (380 + 4 + 16 = 400)
        text = ("x" * (MAX_EVIDENCE_SUMMARY_CHARS - 21) + " "
                + "AKIA" + "B" * 40)
        assert redact_secrets(text) == text          # 1st pass: no match
        e = EvidenceRecord.create(kind="log_excerpt", locator="log:1",
                                  summary=text)
        assert e.integrity_ok
        assert dataclasses.replace(e) == e                # __post_init__ no-op
        assert EvidenceRecord.from_dict(e.to_dict()) == e
        assert "AKIA" + "B" * 16 not in e.summary

    def test_locator_is_one_line(self):
        """A locator that starts a new markdown line is an injection vector
        (file paths come from the untrusted diff)."""
        e = EvidenceRecord.create(kind="diff_hunk",
                                  locator="a.py\n## injected\r\n- [x](http://e)\x00:1",
                                  summary="s")
        assert not any(c in e.locator for c in "\n\r\x00 ")
        d = EvidenceRecord.from_dict({"kind": "diff_hunk", "summary": "s",
                                      "locator": "a.py\n## injected"})
        assert d is not None and "\n" not in d.locator

    def test_control_only_locator_is_still_rejected(self):
        with pytest.raises(ValueError):
            EvidenceRecord.create(kind="rule_ref", locator="\x00\x01", summary="s")

    def test_metadata_fields_are_bounded(self):
        e = EvidenceRecord.from_dict({
            "kind": "diff_hunk", "locator": "a.py:1", "summary": "s",
            "check_type": "c" * 9000, "content_hash": "h" * 9000})
        assert len(e.check_type) <= MAX_EVIDENCE_CHECK_TYPE_CHARS
        assert len(e.content_hash) <= MAX_EVIDENCE_HASH_CHARS
        direct = EvidenceRecord(kind="diff_hunk", locator="l" * 9000,
                                summary="s" * 9000, content_hash="h" * 9000,
                                check_type="c" * 9000)
        assert len(direct.locator) <= MAX_EVIDENCE_LOCATOR_CHARS
        assert len(direct.summary) <= MAX_EVIDENCE_SUMMARY_CHARS


class TestProvenanceStringsAreSanitized:
    """provenance_* strings / sources from a tampered stored row."""

    def test_tampered_row_is_redacted_single_line_and_bounded(self):
        row = {**_ANCHOR,
               "provenance_engine": "claude\n## injected",
               "provenance_model": _PLANT + "y" * 5000,
               "provenance_origin": "ai\r\nINJECT",
               "provenance_agent": "a" * 9999,
               "provenance_sources": [{"engine": "e", "model": _PLANT,
                                       "origin": "ai\nX", "agent": "b" * 9999}]}
        d = Finding.from_dict(row).to_dict()
        blob = json.dumps(d)
        assert _PLANT not in blob
        for key in ("provenance_engine", "provenance_model",
                    "provenance_origin", "provenance_agent"):
            assert "\n" not in (d[key] or "") and "\r" not in (d[key] or "")
            assert len(d[key] or "") <= MAX_PROVENANCE_FIELD_CHARS
        src = d["provenance_sources"][0]
        assert "\n" not in src["origin"]
        assert len(src["agent"]) <= MAX_PROVENANCE_FIELD_CHARS

    def test_directly_assigned_attributes_are_sanitized_at_to_dict(self):
        """The orchestrator assigns these attributes directly, so no
        constructor or from_dict ever saw them; to_dict is the boundary."""
        f = Finding(file="a.py", line=1)
        f.provenance_model = f"m-{_PLANT}"
        assert _PLANT not in json.dumps(f.to_dict())

    def test_to_dict_is_a_second_boundary_even_if_assignment_is_bypassed(self):
        """Defense in depth: something that sidesteps ``Finding.__setattr__``
        (object.__setattr__, a subclass, a future slots refactor) still
        cannot get a raw string into the report row."""
        f = Finding(file="a.py", line=1)
        object.__setattr__(f, "provenance_engine", f"e-{_PLANT}")
        assert _PLANT not in json.dumps(f.to_dict())

    def test_clean_values_pass_through_unchanged(self):
        f = Finding(file="a.py", line=1, provenance_engine="claude",
                    provenance_model="claude-sonnet-4-6",
                    provenance_origin="ai")
        d = f.to_dict()
        assert (d["provenance_engine"], d["provenance_model"],
                d["provenance_origin"], d["provenance_agent"]) == (
            "claude", "claude-sonnet-4-6", "ai", None)
        again = Finding.from_dict(d)
        assert (again.provenance_engine, again.provenance_model) == (
            "claude", "claude-sonnet-4-6")


# ---------------------------------------------------------------------------
# V4-E04-T03 · per-finding attribution of a (possibly blended) outcome
# ---------------------------------------------------------------------------

def _rule_engine_finding() -> Finding:
    return Finding(file="a.py", line=1, title="static", rule_id="SEC002",
                   evidence=(EvidenceRecord.create(
                       kind="rule_ref", locator="rule:SEC002", summary="s"),))


def _legacy_stamp(engine: str, model: str):
    """What the orchestrator stamped before this pass, per finding."""
    return (engine or None, model or None,
            "static" if engine == "static" else "ai")


class TestDeriveProvenanceSource:
    """Replaces the vacuous TestProvenanceOrigin (it asserted an expression
    written inside the test itself and never called product code)."""

    @pytest.mark.parametrize("engine,model", [
        ("static", "static-rules-v1"), ("claude", "m1"), ("openai", "m2"),
        ("gemini", "m3"), ("", ""),
    ])
    def test_non_blended_outcomes_stamp_exactly_as_before(self, engine, model):
        src = derive_provenance_source(
            Finding(file="a.py", line=1), outcome_engine=engine,
            outcome_model=model)
        assert (src.engine, src.model, src.origin) == _legacy_stamp(engine, model)
        assert src.agent is None

    def test_blended_outcome_attributes_static_findings_to_the_rule_engine(self):
        """The audit's H1: a claude+static run stamped EVERY finding as
        engine='claude+static', model=<the AI model>, origin='ai' -- crediting
        rule-engine output to the AI model (and labelling it an AI review)."""
        src = derive_provenance_source(
            _rule_engine_finding(), outcome_engine="claude+static",
            outcome_model="claude-x")
        assert (src.engine, src.model, src.origin) == (
            "static", STATIC_RULE_ENGINE_VERSION, "static")

    def test_blended_outcome_attributes_ai_findings_to_the_concrete_engine(self):
        src = derive_provenance_source(
            Finding(file="a.py", line=1, title="ai"),
            outcome_engine="claude+static", outcome_model="claude-x")
        assert (src.engine, src.model, src.origin) == ("claude", "claude-x", "ai")

    @pytest.mark.parametrize("engine", ["claude+static", "openai+static",
                                        "gemini+static", "Claude+Static"])
    def test_no_composite_engine_ever_reaches_a_source_key(self, engine):
        """V5 merge dedups on (engine, model, origin, agent): a composite
        'claude+static' would split one engine's findings across two keys."""
        for f in (_rule_engine_finding(), Finding(file="a.py", line=1)):
            src = derive_provenance_source(f, outcome_engine=engine,
                                           outcome_model="m")
            assert "+" not in (src.engine or "")
            assert src.origin in ("ai", "static")

    def test_origin_is_static_only_for_rule_engine_output(self):
        for engine in ("claude", "openai", "gemini", "claude+static", ""):
            src = derive_provenance_source(
                Finding(file="a.py", line=1), outcome_engine=engine,
                outcome_model="m")
            assert src.origin == "ai"

    def test_hostile_outcome_strings_are_sanitized(self):
        src = derive_provenance_source(
            Finding(file="a.py", line=1),
            outcome_engine="claude", outcome_model=f"m\n## x {_PLANT}")
        assert _PLANT not in (src.model or "") and "\n" not in (src.model or "")


# ---------------------------------------------------------------------------
# V4-E04-T04 · display-safe view for renderers
# ---------------------------------------------------------------------------

class TestDescribeProvenance:
    def test_finding_without_provenance_is_explicitly_unavailable(self):
        v = describe_provenance(Finding(file="a.py", line=1))
        assert v["available"] is False
        assert v["reason"] == PROVENANCE_UNAVAILABLE_REASON
        assert v["sources"] == [] and v["evidence"] == []
        assert v["merged_count"] == 0

    @pytest.mark.parametrize("obj", [
        object(), SimpleNamespace(), None,
        SimpleNamespace(provenance_sources="junk", evidence=5,
                        merged_fingerprints="x", provenance_engine=3),
        SimpleNamespace(evidence=[object(), None, {"kind": "x"}]),
    ])
    def test_never_raises_on_anything_finding_like(self, obj):
        v = describe_provenance(obj)           # must not raise
        assert v["available"] in (True, False)
        json.dumps(v)                          # and is serializable

    def test_available_finding_exposes_sources_and_citations_only(self):
        e = EvidenceRecord.create(kind="diff_hunk", locator="a.py:1-1",
                                  summary="SUMMARY-MARKER-NEVER-RENDERED",
                                  check_type="security")
        f = Finding(file="a.py", line=1, provenance_engine="claude",
                    provenance_model="m1", provenance_origin="ai",
                    provenance_sources=(ProvenanceSource(
                        engine="claude", model="m1", origin="ai"),),
                    evidence=(e,), merged_fingerprints=("deadbeefdeadbeef",))
        v = describe_provenance(f)
        assert v["available"] is True and v["reason"] is None
        assert (v["engine"], v["model"], v["origin"]) == ("claude", "m1", "ai")
        assert v["evidence"] == [{"kind": "diff_hunk", "locator": "a.py:1-1",
                                  "check_type": "security",
                                  "integrity_ok": True}]
        assert v["merged_count"] == 1
        assert "SUMMARY-MARKER" not in json.dumps(v)   # cited, never quoted

    def test_locator_cannot_escape_a_markdown_code_span(self):
        e = EvidenceRecord.create(kind="diff_hunk",
                                  locator="a`b`.py:1", summary="s")
        v = describe_provenance(Finding(file="a.py", line=1, evidence=(e,)))
        assert "`" not in v["evidence"][0]["locator"]

    def test_tampered_evidence_is_flagged_not_hidden(self):
        e = dataclasses.replace(
            EvidenceRecord.create(kind="rule_ref", locator="rule:R",
                                  summary="s"), summary="changed")
        v = describe_provenance(Finding(file="a.py", line=1, evidence=(e,)))
        assert v["evidence"][0]["integrity_ok"] is False

    def test_evidence_and_sources_are_bounded(self):
        many = tuple(EvidenceRecord.create(kind="rule_ref", locator=f"rule:R{i}",
                                           summary="s") for i in range(20))
        f = Finding(file="a.py", line=1, evidence=many)
        v = describe_provenance(f)
        assert len(v["evidence"]) == MAX_EVIDENCE_PER_FINDING
        assert v["evidence_total"] == 20


# ---------------------------------------------------------------------------
# V4-E04 exit criterion · "evidence persists and reloads byte-identically"
# ---------------------------------------------------------------------------

def _rich_finding() -> Finding:
    return Finding(
        file="app/payments.py", line=2, end_line=3, severity="high",
        category="security", title="Hardcoded credential",
        explanation="e", suggestion="s", confidence="high", rule_id="SEC002",
        fingerprint="0123456789abcdef", state="active",
        first_seen_sha="a" * 40, last_seen_sha="b" * 40,
        provenance_engine="static", provenance_model="static-rules-v1",
        provenance_origin="static",
        provenance_sources=(
            ProvenanceSource(engine="static", model="static-rules-v1",
                             origin="static"),
            ProvenanceSource(engine="claude", model="m1", origin="ai"),
        ),
        evidence=(
            EvidenceRecord.create(kind="rule_ref", locator="rule:SEC002",
                                  summary="SEC002: Hardcoded credential",
                                  check_type="security"),
            EvidenceRecord.create(kind="diff_hunk",
                                  locator="app/payments.py:2-2",
                                  summary="    token = load(order)",
                                  check_type="security"),
        ),
        merged_fingerprints=("fedcba9876543210",),
    )


class TestRoundTrip:
    def test_json_round_trip_is_byte_identical(self):
        f = _rich_finding()
        first = json.dumps(f.to_dict())
        again = Finding.from_dict(json.loads(first))
        assert json.dumps(again.to_dict()) == first
        assert again.evidence == f.evidence
        assert again.provenance_sources == f.provenance_sources
        assert again.merged_fingerprints == f.merged_fingerprints
        assert all(e.integrity_ok for e in again.evidence)

    def test_double_round_trip_is_a_fixed_point(self):
        d1 = _rich_finding().to_dict()
        d2 = Finding.from_dict(Finding.from_dict(d1).to_dict()).to_dict()
        assert d1 == d2

    def test_pre_v4_row_loads_and_renders_as_unavailable(self):
        """A stored row from before any provenance existed."""
        old = {"file": "a.py", "line": 3, "severity": "low", "category": "bug",
               "title": "old", "explanation": "e", "suggestion": None,
               "confidence": "medium", "rule_id": None, "fingerprint": "ab",
               "state": "active"}
        f = Finding.from_dict(old)
        assert f.evidence == () and f.provenance_sources == ()
        assert describe_provenance(f)["available"] is False
        d = f.to_dict()                       # additive keys, empty/None
        assert d["evidence"] == [] and d["provenance_sources"] == []
        assert d["merged_fingerprints"] == [] and d["provenance_engine"] is None


class TestPersistedThroughRealStorage:
    """Evidence/provenance survive every storage backend unchanged, and a
    secret that reached a record never comes back out of storage."""

    @staticmethod
    def _open(name, tmp_path):
        from ai_pr_reviewer.storage import LocalReviewStorage
        from dashboard.storage import DbStorage, JsonStorage
        if name == "local":
            return LocalReviewStorage(tmp_path / "state.db")
        if name == "db":
            s = DbStorage(f"sqlite:///{tmp_path / 'd.db'}")
        else:
            s = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
        s.init()
        return s

    @pytest.mark.parametrize("backend", ["local", "db", "json"])
    def test_round_trip_through_storage(self, backend, tmp_path):
        from ai_pr_reviewer.storage_schema import format_review_id
        storage = self._open(backend, tmp_path)
        f = _rich_finding()
        # hostile record built by a route that bypasses create()
        tainted = EvidenceRecord(
            kind="log_excerpt", locator="log:1", summary=f"k={_PLANT}",
            content_hash="0" * 16)
        f = dataclasses.replace(f, evidence=(*f.evidence, tainted))
        want = f.to_dict()

        storage.save_findings(format_review_id("acme/w", 5, "abc123456789"),
                              [dict(want)])
        loaded = storage.get_previous_findings("acme/w", 5)

        assert len(loaded) == 1
        item = loaded[0]
        got = Finding.from_dict(
            item.to_dict() if isinstance(item, Finding) else item).to_dict()
        assert got == want
        assert _PLANT not in json.dumps(got)

    def test_local_store_bytes_contain_no_secret(self, tmp_path):
        from ai_pr_reviewer.storage_schema import format_review_id
        storage = self._open("local", tmp_path)
        tainted = EvidenceRecord(kind="log_excerpt", locator=f"log:{_PLANT}",
                                 summary=f"k={_PLANT}", content_hash="0" * 16,
                                 check_type=_PLANT)
        f = Finding(file="a.py", line=1, title="t", provenance_model=_PLANT,
                    evidence=(tainted,))
        storage.save_findings(format_review_id("acme/w", 5, "abc123456789"),
                              [f])
        with sqlite3.connect(tmp_path / "state.db") as conn:
            payloads = [r[0] for r in conn.execute(
                "SELECT payload FROM finding_history")]
        assert payloads and all(_PLANT not in p for p in payloads)


# ---------------------------------------------------------------------------
# V4-E04-T03 acceptance · "no finding in any report lacks provenance"
# ---------------------------------------------------------------------------

class TestEveryReportedFindingCarriesProvenance:
    @pytest.fixture(autouse=True)
    def _hermetic(self, monkeypatch):
        for var in ("INPUT_PR_NUMBER", "INPUT_MAX_COMMENTS", "INPUT_BATCH_CHARS",
                    "INPUT_REPO_CONTEXT_CHARS", "INPUT_RETENTION_DAYS",
                    "INPUT_FAIL_ON", "INPUT_DASHBOARD_URL",
                    "INPUT_DASHBOARD_TOKEN", "DASHBOARD_TOKEN"):
            monkeypatch.delenv(var, raising=False)

    def test_static_reports_cite_their_rules_and_reload_identically(
            self, fixtures, tmp_path):
        from ai_pr_reviewer import cli
        checked = 0
        for name, fx in fixtures.items():
            out = tmp_path / f"{name}.json"
            cli.main(["--diff-file", str(fx["diff"]), "--repo", "a/b",
                      "--pr", "1", "--mock", "--no-comment",
                      "--output", str(out)])
            report = json.loads(out.read_text(encoding="utf-8"))
            for row in (*report["findings"], *report["below_threshold"]):
                checked += 1
                where = f"{name}:{row['file']}:{row['line']}"
                # attribution: scalar mirror + list, all static, never AI
                assert row["provenance_engine"] == "static", where
                assert row["provenance_origin"] == "static", where
                assert row["provenance_model"] == STATIC_RULE_ENGINE_VERSION
                assert [s["origin"] for s in row["provenance_sources"]] == [
                    "static"], where
                # evidence: the rule that fired is cited by id, and every
                # record is intact and secret-free
                kinds = {e["kind"]: e for e in row["evidence"]}
                assert kinds["rule_ref"]["locator"] == f"rule:{row['rule_id']}"
                for e in row["evidence"]:
                    assert hashlib.sha256(
                        e["summary"].encode()).hexdigest()[:16] == e["content_hash"]
                # the artifact reloads byte-identically through the model
                keys = Finding.from_dict(row).to_dict().keys()
                assert Finding.from_dict(row).to_dict() == {
                    k: row[k] for k in keys}, where
        assert checked >= 5, "fixtures produced too few findings to mean anything"
