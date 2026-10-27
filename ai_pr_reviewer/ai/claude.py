"""ClaudeProvider — the AI-backed :class:`~ai_pr_reviewer.ai.provider.AIProvider`
implementation.

This is ``ClaudeAnalyzer``'s logic, moved out of ``analyzer.py`` now that a
second provider (the static-analysis fallback, wired up in
``model_router.py``) has to satisfy the same contract. The prompt text and
JSON parsing live in :mod:`.prompting` (V4.0-E02-T01) — no provider module
holds prompt text; the names are re-imported here so the existing
``from ...claude import`` paths keep working. What's new:

* ``analyze()`` takes a :class:`ReviewContext` (``context.files``,
  ``context.focus_areas``) instead of a raw file list, so this is a
  drop-in for the orchestrator via ``context.py``.
* ``context.memory_notes`` is screened and nonce-fenced like the diff
  (see ``build_untrusted_memory_block``) before it reaches a prompt.
* the Anthropic POST is retried with backoff+jitter before a batch is
  given up on.
* a batch that still fails after retries is handed to the deterministic
  static analyzer instead of being silently dropped, and the
  outcome honestly records that with ``engine="claude+static"`` and
  ``fallback_used=True``.
"""
from __future__ import annotations

import time
from typing import TYPE_CHECKING

# `AnalysisOutcome` and `StaticAnalyzer` are imported through analyzer.py, the
# compatibility facade, so this provider keeps working if either moves.
from ..analyzer import AnalysisOutcome, StaticAnalyzer
from ..diff_parser import FileDiff
from ..models import Finding
from ..retry import RetryPolicy
from ..context import build_untrusted_impact_block
from ..security import scan_prompt_injection, wrap_untrusted_diff
from ..telemetry import RunTelemetry, UsageRecord, summarize_calls
# V4.0-E02-T01: prompt text + JSON parsing are single-sourced in prompting.py
# (no provider module may contain prompt text). Re-imported under their
# historical names so `from ...claude import` call sites keep working.
from .prompting import (SYSTEM_PROMPT, assemble_user_prompt,
                        build_untrusted_memory_block,
                        build_untrusted_repo_context_block, extract_json)

if TYPE_CHECKING:
    from ..context import ReviewContext  # provided by context.py


def _memory_notes(context) -> list[str]:
    """Pull ``context.memory_notes`` defensively.

    Only a real list/tuple counts: contexts from older callers (or test
    doubles) that don't carry memory behave exactly like "no memory"
    instead of raising mid-review.
    """
    notes = getattr(context, "memory_notes", None)
    if not isinstance(notes, (list, tuple)):
        return []
    return [str(n) for n in notes if n]


def _repo_context_entries(context) -> list[tuple[str, str, str]]:
    """``(path, content, reason)`` triples from ``context.repo_context``.

    Accepts dicts and attribute objects alike (test doubles and future
    backends), and degrades to "no repository context" rather than raising.
    """
    entries = getattr(context, "repo_context", None)
    if not isinstance(entries, (list, tuple)):
        return []
    out: list[tuple[str, str, str]] = []
    for entry in entries:
        if isinstance(entry, dict):
            path, content = entry.get("path", ""), entry.get("content", "")
            reason = entry.get("reason", "")
        else:
            path = getattr(entry, "path", "")
            content = getattr(entry, "content", "")
            reason = getattr(entry, "reason", "")
        if path and content:
            out.append((str(path), str(content), str(reason or "")))
    return out


def _impact_section(context) -> str:
    """``context.impact_section`` iff it is a real string (duck-typed or
    mock contexts without one must leave the prompt untouched)."""
    section = getattr(context, "impact_section", "")
    return section if isinstance(section, str) else ""


class ClaudeProvider:
    """Reviews diff batches with Claude via the Anthropic Messages API.

    Implements :class:`ai_pr_reviewer.ai.provider.AIProvider`.
    """

    API_URL = "https://api.anthropic.com/v1/messages"
    MAX_FINDINGS_PER_BATCH = 200
    backend = "claude"

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-6",
                max_tokens: int = 4096, batch_chars: int = 80_000,
                focus_areas: list[str] | None = None, timeout: float = 240.0,
                retry: RetryPolicy | None = None):
        import httpx

        self._client = httpx.Client(timeout=timeout)
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.batch_chars = batch_chars
        self.focus_areas = focus_areas or []
        self.total_input_tokens = 0
        self.total_output_tokens = 0
        # V3-E02-T01: one shared record per call — counts and durations
        # only, never prompt content. Absence of usage is a typed state.
        self.usage_records: list[UsageRecord] = []
        self._retry = retry or RetryPolicy()
        self._static = StaticAnalyzer()
        # Populated by model_router.get_provider() for informational
        # warnings that don't come from a specific batch (e.g. a
        # high-risk-PR note) — merged into the outcome's warnings so callers
        # don't need a second channel to learn about them.
        self.startup_warnings: list[str] = []

    def analyze(self, context: ReviewContext) -> AnalysisOutcome:
        files: list[FileDiff] = context.files
        focus_areas: list[str] = context.focus_areas
        policy = getattr(context, "project_rules", None)
        project_rules = list(getattr(policy, "rules", None) or [])

        batches = _batch_with_files(files, max_chars=self.batch_chars)
        findings: list[Finding] = []
        summaries: list[str] = []
        warnings: list[str] = list(self.startup_warnings)
        fallback_used = False
        any_claude_success = False

        # Repository memory is PR-adjacent text: screen + fence it once,
        # then send the same block with every batch (see
        # build_untrusted_memory_block). Repository context gets the same
        # treatment, in its own fence (see build_untrusted_repo_context_block).
        memory_block = build_untrusted_memory_block(_memory_notes(context), warnings)
        repo_block = build_untrusted_repo_context_block(
            _repo_context_entries(context), warnings)
        # V4-E03-T03: bounded impact section, same untrusted-fence contract.
        impact_block = build_untrusted_impact_block(
            _impact_section(context), warnings)

        for idx, (batch_text, batch_files) in enumerate(batches, 1):
            # Screen BEFORE sending — cheap local defense + forensic trail.
            for hit in scan_prompt_injection(batch_text):
                warnings.append(f"batch {idx}: prompt-injection screen: {hit}")
            try:
                result = self._review_batch(batch_text, len(batches), idx, focus_areas,
                                            project_rules, memory_block, repo_block,
                                            impact_block=impact_block)
            except Exception as exc:  # noqa: BLE001 — a bad batch shouldn't kill the review
                # E08-T04: exception messages can carry request bodies/secrets,
                # so the warning names only the exception type; sink-side
                # redact_secrets() remains the second layer.
                warnings.append(
                    f"Batch {idx}/{len(batches)} failed after retries "
                    f"({type(exc).__name__}) — "
                    f"ran the deterministic static analyzer for this batch instead."
                )
                fallback_used = True
                findings.extend(self._static_fallback_findings(batch_files))
                continue

            any_claude_success = True
            summaries.append(result.get("summary", ""))
            warnings.extend(str(w) for w in result.get("warnings", [])[:10])
            batch_findings = result.get("findings", [])[:self.MAX_FINDINGS_PER_BATCH]
            for raw in batch_findings:
                try:
                    # from_untrusted_dict: model output is attacker-steerable
                    # (a malicious diff can be in this response), so pipeline-
                    # owned fields — state, fingerprint, github_comment_id,
                    # verification — are always dropped here.
                    findings.append(Finding.from_untrusted_dict(raw))
                except Exception:
                    warnings.append(f"Batch {idx}: skipped malformed finding: {raw!r}")

        summary = summaries[0] if len(summaries) == 1 else " ".join(s for s in summaries if s)
        if fallback_used and not summary:
            summary = ("Claude was unavailable for part of this review; the "
                      "deterministic static-analysis fallback covered the rest.")

        engine = "static" if (fallback_used and not any_claude_success) else \
                 "claude+static" if fallback_used else "claude"

        outcome = AnalysisOutcome(findings, summary, mode="claude", model=self.model,
                                  warnings=warnings)
        outcome.engine = engine
        outcome.fallback_used = fallback_used
        outcome.batch_count = len(batches)
        # V3-E02-T02: per-run telemetry rides the outcome. Retry events are
        # read from the policy (they only exist from V3-E02-T03 on).
        outcome.telemetry = RunTelemetry(
            provider=self.backend, model=self.model, batch_count=len(batches),
            fallback_used=fallback_used, usage=self.usage_summary(),
            calls=list(self.usage_records),
            events=list(getattr(self._retry, "events", [])))
        return outcome

    def usage_summary(self) -> UsageRecord:
        """Run-level aggregate over this provider's per-call records
        (V3-E02-T01)."""
        return summarize_calls(self.backend, self.model, self.usage_records)

    @property
    def telemetry_events(self) -> list[dict]:
        """Structured events this provider produced (retry attempts —
        V3-E02-T03). Counts, status classes and exception *type names*
        only; copied from the retry policy."""
        return list(getattr(self._retry, "events", []))

    def capabilities(self) -> frozenset[str]:
        """Declared task types (V4.0-E02-T02, ADR-007 optional seam).

        Delegates to the provider registry — one source of capability
        truth (``ProviderSpec.tasks``); routing reads the same entry. An
        out-of-tree provider may instead declare its own subset without
        registering (see ``ai.provider.capabilities_of``).
        """
        from ..provider_registry import get_spec

        spec = get_spec(self.backend)
        return frozenset(spec.tasks) if spec is not None else frozenset()

    def _static_fallback_findings(self, batch_files: list[FileDiff]) -> list[Finding]:
        """Run the deterministic rule engine over just the files in a batch
        that Claude failed to review, so one bad batch doesn't throw away
        the whole review."""
        if not batch_files:
            return []
        return self._static.analyze(batch_files).findings

    def _review_batch(self, batch: str, total_batches: int, idx: int,
                      focus_areas: list[str], project_rules: list[str],
                      memory_block: str = "", repo_block: str = "",
                      impact_block: str = "") -> dict:
        fenced, nonce = wrap_untrusted_diff(batch)
        user = assemble_user_prompt(
            batch_text=batch, idx=idx, total_batches=total_batches,
            focus_areas=focus_areas, project_rules=project_rules,
            memory_block=memory_block, repo_block=repo_block,
            impact_block=impact_block, fenced=fenced)

        # Retried: exponential backoff + jitter on transient failures
        # (429/5xx/timeouts/network errors); gives up immediately on
        # permanent ones (401/403/other 4xx) — see RetryPolicy.is_retryable.
        started = time.monotonic()
        resp = self._retry.call(
            self._client.post,
            self.API_URL,
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": self.max_tokens,
                "system": SYSTEM_PROMPT,
                "messages": [{"role": "user", "content": user}],
            },
        )
        resp.raise_for_status()
        data = resp.json()
        # V3-E02-T01: per-call usage into one shared record type. A
        # response without a usage block is the typed "unavailable"
        # state — never a fake 0. Counts only; no prompt content is kept.
        usage = data.get("usage") if isinstance(data.get("usage"), dict) else {}
        self.usage_records.append(UsageRecord.for_call(
            self.backend, self.model, usage.get("input_tokens"),
            usage.get("output_tokens"),
            duration_ms=int((time.monotonic() - started) * 1000)))
        self.total_input_tokens += data.get("usage", {}).get("input_tokens", 0)
        self.total_output_tokens += data.get("usage", {}).get("output_tokens", 0)

        text = "".join(block.get("text", "") for block in data.get("content", []))
        result = extract_json(text)
        if not isinstance(result, dict):
            raise ValueError("model response was not a JSON object")
        return result


def _batch_with_files(files: list[FileDiff], max_chars: int,
                      max_lines_per_file: int = 3_000
                      ) -> list[tuple[str, list[FileDiff]]]:
    """Greedily pack file diffs into (batch_text, batch_files) pairs under a
    character budget — same packing algorithm as ``diff_parser.chunk_files``,
    but also retains which ``FileDiff`` objects landed in each batch.

    ``chunk_files()`` only returns batch text, which was enough for the
    original flow (send text, get findings back), but per-batch static
    fallback needs the actual ``FileDiff`` objects for a batch that
    failed, and re-parsing the rendered diff text back into ``FileDiff``
    objects is not reliably lossless for multi-file batches —
    ``to_diff_text()`` doesn't emit a ``diff --git`` header per file, which
    ``parse_unified_diff()`` relies on to detect a new file boundary; without
    it, a second file's own ``--- a/...`` header line gets misread as a
    removed line inside the first file's last hunk. Duplicating the packing
    logic here (rather than changing ``chunk_files``'s signature) avoids
    changing the public ``diff_parser.py`` API.
    """
    batches: list[tuple[str, list[FileDiff]]] = []
    current_text: list[str] = []
    current_files: list[FileDiff] = []
    size = 0

    for f in files:
        text = f.to_diff_text()
        lines = text.splitlines()
        if len(lines) > max_lines_per_file:
            lines = lines[:max_lines_per_file]
            lines.append("... [diff truncated: file too large for review]")
        text = "\n".join(lines)
        oversized = len(text) > max_chars
        if oversized:
            if current_text:
                batches.append(("\n\n".join(current_text), current_files))
                current_text, current_files, size = [], [], 0
            batches.append((text, [f]))
            continue
        if size + len(text) > max_chars and current_text:
            batches.append(("\n\n".join(current_text), current_files))
            current_text, current_files, size = [], [], 0
        current_text.append(text)
        current_files.append(f)
        size += len(text) + 2

    if current_text:
        batches.append(("\n\n".join(current_text), current_files))
    return batches
