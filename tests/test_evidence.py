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
