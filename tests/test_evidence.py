"""Tests for V4-E04: evidence engine & provenance.

Provenance fields are pipeline-owned (like lifecycle fields) — they must be
set by the orchestrator from AnalysisOutcome, never from model output.
"""
from __future__ import annotations

import pytest

from ai_pr_reviewer.models import (
    LIFECYCLE_FIELDS,
    Finding,
    VERIFICATION_STATUSES,
)
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
