"""Security helpers for the review pipeline.

Three jobs, all defense-in-depth around the fact that a pull-request diff is
*untrusted attacker-controlled text*:

1. ``wrap_untrusted_diff``  — fence the diff between nonce-tagged markers and
   neutralize spoofed markers, so the model can be told precisely which text
   is data and which is instruction; ``wrap_untrusted_repo_file`` applies the
   same contract per repository file (V4-E08-T02).
2. ``scan_prompt_injection`` — screen diffs for instruction-impersonation
   phrases; matches are surfaced as warnings on the review run.
3. ``redact_secrets`` — scrub credential-looking strings out of anything we
   post back to GitHub or persist on the dashboard, so a finding that quotes a
   secret from the diff doesn't itself leak it.
4. ``sanitize_warning(s)`` / ``markdown_safe_inline`` — make untrusted text that
   ends up in a run *warning* (provider output, exception text, hostile file
   names) bounded, single-line, redacted, fence-neutral and markdown-inert
   (V4-E08-T04, closes debt #11).
5. The feedback-poisoning guard (``FeedbackLimits`` / ``admit_rule`` / ...,
   V4-E08-T06): schema-agnostic caps, repository scoping and persistence-time
   redaction that the feedback store (V4-E09) enforces by construction.

This module imports nothing from the package (no import cycles): every
redaction/fencing boundary in the engine and the dashboard can share it.
"""
from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Iterable

# ---------------------------------------------------------------------------
# 1 · Untrusted-diff fencing
# ---------------------------------------------------------------------------

OPEN_TAG_RE = re.compile(r"<\s*/?\s*untrusted_diff[^>]*>", re.I)
#: V4-E08-T02: per-file fence markers (``<untrusted_repo_file>``). Same
#: spoofing contract as the diff fence: repository text that tries to emit
#: these tags is neutralized before we add ours, and the injection screen
#: flags the attempt.
REPO_FILE_TAG_RE = re.compile(r"<\s*/?\s*untrusted_repo_file[^>]*>", re.I)


def new_nonce() -> str:
    return secrets.token_hex(8)


# V4-E08-T02 hardening. The plain tag regexes above (kept unchanged: the
# injection screen and telemetry import them) only catch well-formed tags.
# Measured bypasses of the original neutralizer: zero-width characters
# splitting the tag name, fullwidth angle brackets, and an unclosed opening
# tag — each reached the prompt verbatim with ZERO screen hits. The
# neutralizer below tolerates all three. The per-run nonce stays the
# authoritative boundary; this keeps the prompt free of look-alike markers.
_INVISIBLES = "\u200b\u200c\u200d\u200e\u200f\u2060\ufeff\u00ad"
_INV = f"[{_INVISIBLES}]*"
_WS = f"[\\s{_INVISIBLES}]*"
FENCE_FAMILIES = ("untrusted_diff", "untrusted_repo_file")
NEUTRALIZED_TAG = "[neutralized-fence-tag]"


@lru_cache(maxsize=8)
def _fence_regexes(families: tuple) -> tuple:
    names = "(?:" + "|".join(
        _INV.join(re.escape(c) for c in fam) for fam in families) + ")"
    head = r"[<\uff1c]" + _WS + r"[/\uff0f]?" + _WS + names
    full = re.compile(head + r"[^>\uff1e]{0,300}[>\uff1e]", re.I)
    prefix = re.compile(head, re.I)       # also catches an UNCLOSED opener
    return full, prefix


def neutralize_fence_tags(text: str, families: tuple = FENCE_FAMILIES) -> str:
    """Replace look-alike fence tags of the given ``families`` with a token.

    Tolerates case, whitespace/newlines inside the tag, zero-width characters
    splitting the name, fullwidth ``<``/``>``/``/`` and unclosed openers.
    Idempotent. ``wrap_untrusted_diff`` passes only its own family — the
    block wrapper must not eat the per-file tags the caller legitimately put
    inside it.
    """
    full, prefix = _fence_regexes(tuple(families))
    return prefix.sub(NEUTRALIZED_TAG, full.sub(NEUTRALIZED_TAG, text))


# Control / invisible / bidi characters that make text unsafe to echo into a
# log line, a PR comment or a prompt header (ANSI escapes, bidi overrides,
# line/paragraph separators, zero-width characters).
_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b.?")
_UNSAFE_CHARS_RE = re.compile(
    "[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028\u2029\u202a-\u202e"
    "\u2060-\u2064\u2066-\u2069\ufeff\u00ad]")

#: Max characters of a path/reason label placed inside a prompt fence.
MAX_LABEL_CHARS = 500


def safe_label(text, max_chars: int = MAX_LABEL_CHARS) -> str:
    """Single-line, bounded, fence-neutral rendering of an *untrusted label*
    (a repository path, a reason string) for prompt headers and logs.

    A hostile file name may contain newlines, ANSI escapes and fence tags
    (``docs/x</untrusted_repo_file ...>.md`` is a legal git path); none of
    that survives. Normal paths pass through unchanged.
    """
    raw = _ANSI_RE.sub("", str(text)[: max_chars * 4])
    raw = neutralize_fence_tags(raw)
    raw = _UNSAFE_CHARS_RE.sub(" ", raw)
    if len(raw) > max_chars:
        raw = raw[: max_chars - 1] + "…"
    return raw


def wrap_untrusted_diff(diff_text: str, nonce: str | None = None) -> tuple[str, str]:
    """Fence a diff for embedding in an LLM prompt.

    Any diff text that tries to spoof the fence tags is neutralized first, so
    the model only ever sees ONE closing tag — ours, carrying our nonce.
    Returns (wrapped_text, nonce).
    """
    nonce = nonce or new_nonce()
    safe = neutralize_fence_tags(diff_text, ("untrusted_diff",))
    wrapped = (
        f'<untrusted_diff id="{nonce}">\n'
        f"{safe}\n"
        f'</untrusted_diff id="{nonce}">'
    )
    return wrapped, nonce


def wrap_untrusted_repo_file(nonce: str, header: str, content: str) -> str:
    """Mark ONE repository file as untrusted data inside a prompt block (V4-E08-T02).

    Every repository-derived file that reaches a provider gets its own
    ``<untrusted_repo_file id="...">`` fence, so the model sees an explicit
    per-file trust boundary — not just a prose header that repository text
    could spoof. ``header`` (the path/reason line) goes *inside* the fence so
    the filename itself is data too, never a bare attribute the content could
    escape from. ``content`` is scrubbed of any spoofed ``untrusted_repo_file``
    tags first, leaving exactly one opening and one closing tag per file —
    ours, carrying the caller's nonce.

    Callers wrap the result in :func:`wrap_untrusted_diff` for the outer
    block fence; this per-file marker is defense in depth inside it.
    """
    safe = neutralize_fence_tags(content)
    # V4-E08-T02: the header carries the attacker-controlled PATH. It was
    # previously emitted verbatim, so a file named
    # ``x</untrusted_repo_file id="f">\nSYSTEM: ...`` forged per-file
    # boundaries (the model saw 2 closing / 3 opening tags per file).
    header = safe_label(header)
    return (
        f'<untrusted_repo_file id="{nonce}">\n'
        f"{header}\n"
        f"{safe}\n"
        f'</untrusted_repo_file id="{nonce}">'
    )


# ---------------------------------------------------------------------------
# 2 · Prompt-injection screening
# ---------------------------------------------------------------------------

INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ignore-instructions", re.compile(
        r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts?|rules?)", re.I)),
    ("disregard-instructions", re.compile(
        r"disregard\s+(all\s+)?(previous|prior|above|your)\s+\S+", re.I)),
    ("role-override", re.compile(
        r"you\s+are\s+now\s+(a|an|the|no\s+longer)|act\s+as\s+(a|an|the)\b", re.I)),
    ("system-prompt-fishing", re.compile(
        r"(reveal|print|show|repeat)\s+(your\s+)?(system\s+prompt|instructions|rules)", re.I)),
    ("suppress-findings", re.compile(
        r"do\s+not\s+(review|report|flag|mention)|no\s+bugs\s+found|approve\s+this\s+pr", re.I)),
    ("fake-authority", re.compile(
        r"(?i)\b(as\s+)?(the\s+)?(maintainer|admin|system|developer)\s+(of\s+this\s+repo\s+)?"
        r"(says|said|instructs|commands|requests)\b")),
    ("fake-tag", OPEN_TAG_RE),
    ("fake-repo-file-tag", REPO_FILE_TAG_RE),
    ("fake-chat-turn", re.compile(r"^\s*(assistant|system)\s*:", re.I | re.M)),
]


def scan_prompt_injection(text: str) -> list[str]:
    """Return human-readable descriptions of injection-looking constructs."""
    hits: list[str] = []
    for name, pattern in INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            sample = m.group(0).strip()
            if len(sample) > 60:
                sample = sample[:57] + "..."
            hits.append(f"{name}: {sample!r}")
    # V4-E08-T02: obfuscated spoofs (zero-width split, fullwidth brackets,
    # unclosed opener) used to produce ZERO hits. Flag them — only when the
    # plain patterns did not already, so one spoof is one warning.
    if not any(h.startswith(("fake-tag", "fake-repo-file-tag")) for h in hits):
        full, prefix = _fence_regexes(FENCE_FAMILIES)
        m = prefix.search(text)
        if m:
            hits.append(f"fake-fence-tag-obfuscated: {m.group(0).strip()[:57]!r}")
    return hits


# ---------------------------------------------------------------------------
# 3 · Secret redaction
# ---------------------------------------------------------------------------

_REDACT_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("api-sk-key", re.compile(r"\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("private-key-block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----")),
    ("bearer-header", re.compile(
        r"(?i)\b(bearer|authorization\s*:\s*bearer)\s+([A-Za-z0-9._~+/=-]{16,})")),
    ("key-value-secret", re.compile(
        r"(?i)\b((?:api[_-]?key|apikey|secret|token|password|passwd|access[_-]?key)"
        r"\s*[:=]\s*)([\"']?)[A-Za-z0-9._~/+=-]{8,}\2")),
    # --- additional token formats ---
    ("google-oauth-token", re.compile(r"\bya29\.[A-Za-z0-9_-]{20,}\b")),
    ("jwt-like-token", re.compile(
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("database-url", re.compile(r"(?i)\b(\w+://)([^:\s@/]+):([^@\s]+)@")),
    ("high-entropy-hex", re.compile(r"\b[0-9a-fA-F]{40,64}\b")),
]

_REDACTED = "[REDACTED]"


def redact_secrets(text: str) -> str:
    """Replace credential-looking substrings with [REDACTED]."""
    if not text:
        return text
    for name, pattern in _REDACT_PATTERNS:
        if name == "bearer-header":
            text = pattern.sub(lambda m: f"{m.group(1)} {_REDACTED}", text)
        elif name == "key-value-secret":
            text = pattern.sub(lambda m: f"{m.group(1)}{_REDACTED}", text)
        elif name == "database-url":
            # Keep the scheme and host visible (they're not secret on their
            # own); redact only the embedded user:password.
            text = pattern.sub(lambda m: f"{m.group(1)}{_REDACTED}@", text)
        else:
            text = pattern.sub(_REDACTED, text)
    return text


def scrub_with_config(text: str, cfg) -> str:
    """``redact_secrets`` PLUS the exact credentials this run was configured
    with, so no engine output, stored row or HTTP error can echo them into
    a comment, report, step summary or log line.

    Lives here (not in the orchestrator) so every redaction boundary —
    output chokepoint, previous-findings load, GitHub-sync warnings,
    dashboard reads — shares one policy without import cycles: this module
    imports nothing from the package. Configured credentials are removed by
    exact match (multiline-safe), which also catches values that match no
    pattern above. Values shorter than 6 chars are ignored — too likely to
    be ordinary words.
    """
    text = redact_secrets(text)
    for name in ("github_token", "anthropic_api_key", "openai_api_key",
                 "gemini_api_key", "dashboard_token"):
        secret = getattr(cfg, name, "") or ""
        if len(secret) >= 6:
            text = text.replace(secret, "[REDACTED]")
    return text


# ---------------------------------------------------------------------------
# 4 · Warning sanitization (V4-E08-T04 — closes debt #11)
# ---------------------------------------------------------------------------
# Run warnings are built from UNTRUSTED text: provider-supplied "warnings",
# echoed malformed model output, exception messages, hostile repository file
# names. They reach the PR comment, the step summary, the report JSON, the
# dashboard and the console. ``redact_secrets`` alone did not bound their
# size, remove control characters (log/workflow-command injection) or make
# them inert in markdown.

#: Max characters of one warning after sanitization (PROPOSED baseline).
MAX_WARNING_CHARS = 400
#: Max warnings per run after sanitization; the overflow is *counted*, never
#: silently dropped (PROPOSED baseline).
MAX_RUN_WARNINGS = 50
#: Room reserved for the truncation note so the total stays <= max_chars
#: (that bound is what makes the sanitizer idempotent).
_TRUNC_RESERVE = 32
#: Input is pre-sliced before the regex passes so a multi-megabyte warning
#: cannot become a CPU sink. Generous vs. the output bound: a secret cut by
#: this slice sits far beyond the final window and is dropped by it.
_PRESLICE_FACTOR = 50
_WS_RUN_RE = re.compile(r"\s+")


def sanitize_warning(text, cfg=None, max_chars: int = MAX_WARNING_CHARS) -> str:
    """Bounded, single-line, redacted, fence-neutral text for a run warning.

    Order matters: redact first (on a bounded slice), then neutralize fence
    tags, strip control/ANSI/bidi/zero-width characters, collapse whitespace
    (a newline in a console warning could start a ``::command::`` line), and
    finally truncate *loudly* (``… [truncated N]``). ``cfg`` additionally
    removes the exact credentials this run was configured with. Idempotent:
    sanitizing sanitized text changes nothing.
    """
    raw = str(text)
    total = len(raw)
    raw = raw[: max_chars * _PRESLICE_FACTOR]
    raw = scrub_with_config(raw, cfg) if cfg is not None else redact_secrets(raw)
    raw = neutralize_fence_tags(_ANSI_RE.sub("", raw))
    raw = _WS_RUN_RE.sub(" ", _UNSAFE_CHARS_RE.sub(" ", raw)).strip()
    if len(raw) > max_chars:
        keep = max(0, max_chars - _TRUNC_RESERVE)
        dropped = max(total - keep, len(raw) - keep)
        raw = raw[:keep].rstrip() + f"… [truncated {dropped}]"
    return raw


def sanitize_warnings(warnings, cfg=None, max_items: int = MAX_RUN_WARNINGS,
                      max_chars: int = MAX_WARNING_CHARS) -> list[str]:
    """Sanitize a whole warning list and cap its length LOUDLY.

    Non-list input (``None``) yields ``[]``; empty entries are dropped. When
    the list exceeds ``max_items`` the overflow is replaced by one explicit
    ``(+N more warning(s) suppressed)`` line — never a silent truncation.
    The result never exceeds ``max_items`` entries, so re-applying it is a
    no-op (the sinks and the orchestrator may both call it).
    """
    if not isinstance(warnings, (list, tuple)):
        return []
    clean = [w for w in (sanitize_warning(w, cfg, max_chars) for w in warnings) if w]
    if len(clean) <= max_items:
        return clean
    hidden = len(clean) - (max_items - 1)
    return [*clean[: max_items - 1], f"(+{hidden} more warning(s) suppressed)"]


def markdown_safe_inline(text: str) -> str:
    """Make already-single-line text inert in GitHub-flavoured markdown.

    Escapes HTML (``& < >``), backticks, ``@`` mentions (notification spam)
    and link/image syntax (``![x](url)`` is a request beacon). Used by the
    markdown sink on top of :func:`sanitize_warning`; not idempotent by
    design — apply once, at render time.
    """
    out = (str(text).replace("&", "&amp;").replace("<", "&lt;")
           .replace(">", "&gt;").replace("`", "'"))
    out = out.replace("@", "@&#8203;").replace("![", "&#33;[")
    return out.replace("](", "]&#8203;(")


# ---------------------------------------------------------------------------
# 5 · Feedback-poisoning guard (V4-E08-T06)
# ---------------------------------------------------------------------------
# Enforcement SHAPE for the feedback store (V4-E09). Schema-agnostic and
# storage-free: callers pass counts / timestamps in, and get a decision out,
# so the same checks serve the dashboard route, the CLI and any backend.
# The structural half of the control ("no ingest path from diff, model
# output or PR content") is not code here — it is the *absence* of any
# engine-side writer, pinned by tests/test_v4_security_regressions.py.
#
# Every number below is a PROPOSED baseline to reconcile with V4-E09's
# schema; they are constants + one dataclass so reconciliation is one edit.

_REPO_SCOPE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_RATE_WINDOW_SECONDS = 3600


@dataclass(frozen=True)
class FeedbackLimits:
    """Caps on rule/feedback growth (all PROPOSED; see module note)."""

    max_rules_per_repo: int = 200
    max_rule_creations_per_hour: int = 30
    max_events_per_hour: int = 300
    max_text_chars: int = 500
    default_ttl_days: int = 90
    max_ttl_days: int = 365


@dataclass(frozen=True)
class GuardDecision:
    """Outcome of an admission check. ``message`` is sanitized and loud."""

    allowed: bool
    reason: str = "ok"
    message: str = ""


def normalize_repo_scope(repo) -> str | None:
    """Canonical ``owner/name`` (lower-case) or ``None`` when malformed.

    Rows are repository-scoped; spelling variants (case, stray whitespace,
    path tricks) must not create or hide a scope, so every store/query
    normalizes through here and rejects what does not parse.
    """
    if not isinstance(repo, str):
        return None
    cleaned = repo.strip()
    if not _REPO_SCOPE_RE.fullmatch(cleaned) or ".." in cleaned:
        return None
    return cleaned.lower()


def _epoch(value) -> float | None:
    if isinstance(value, datetime):
        return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).timestamp()
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _recent(times: Iterable, now) -> int:
    cutoff = (_epoch(now) or 0.0) - _RATE_WINDOW_SECONDS
    return sum(1 for t in times if (e := _epoch(t)) is not None and e > cutoff)


def admit_rule(repo, *, existing_rules: int, recent_rule_times: Iterable,
               now, limits: FeedbackLimits = FeedbackLimits()) -> GuardDecision:
    """May a NEW suppression rule be created for ``repo`` right now?

    Refuses a malformed scope, a repository already at its rule cap, and a
    creation burst. A refusal is explicit (``reason`` + human ``message``) —
    the caller surfaces it; nothing is dropped silently.
    """
    if normalize_repo_scope(repo) is None:
        return GuardDecision(False, "repo-scope-invalid",
                             "rule refused: repository scope is not a valid owner/name")
    if existing_rules >= limits.max_rules_per_repo:
        return GuardDecision(False, "rule-count-cap",
                             f"rule refused: repository already has "
                             f"{existing_rules} rules (cap {limits.max_rules_per_repo})")
    if _recent(recent_rule_times, now) >= limits.max_rule_creations_per_hour:
        return GuardDecision(False, "rule-rate-cap",
                             f"rule refused: more than {limits.max_rule_creations_per_hour} "
                             f"rules created in the last hour")
    return GuardDecision(True)


def admit_event(repo, *, recent_event_times: Iterable, now,
                limits: FeedbackLimits = FeedbackLimits()) -> GuardDecision:
    """May one more feedback EVENT (vote/mute click) be recorded now?"""
    if normalize_repo_scope(repo) is None:
        return GuardDecision(False, "repo-scope-invalid",
                             "feedback refused: repository scope is not a valid owner/name")
    if _recent(recent_event_times, now) >= limits.max_events_per_hour:
        return GuardDecision(False, "event-rate-cap",
                             f"feedback refused: more than {limits.max_events_per_hour} "
                             f"events in the last hour")
    return GuardDecision(True)


def clamp_ttl_days(requested, limits: FeedbackLimits = FeedbackLimits()) -> int:
    """Rules always expire: missing/invalid/non-positive -> default, and a
    request can never exceed the hard maximum ("never expires" is not a value
    this function can return)."""
    if isinstance(requested, bool) or not isinstance(requested, int) or requested < 1:
        return limits.default_ttl_days
    return min(requested, limits.max_ttl_days)


def expiry_for(now: datetime, ttl_days=None,
               limits: FeedbackLimits = FeedbackLimits()) -> datetime:
    """Expiry timestamp for a rule created at ``now``."""
    return now + timedelta(days=clamp_ttl_days(ttl_days, limits))


def is_expired(expires_at, now) -> bool:
    """True when the rule is past expiry. A row with NO usable expiry is
    treated as expired (fail closed): a legacy row can't suppress forever."""
    exp, cur = _epoch(expires_at), _epoch(now)
    return exp is None or cur is None or exp <= cur


def sanitize_feedback_text(text, limits: FeedbackLimits = FeedbackLimits()) -> str:
    """Persistence-time redaction + bound for feedback free text: secrets
    redacted, control characters removed, hard length cap (loud marker)."""
    return sanitize_warning(text, None, limits.max_text_chars)


#: Free-text keys redacted by :func:`sanitize_feedback_event` by default.
FEEDBACK_TEXT_FIELDS = ("note", "comment", "reason", "text", "message")


def sanitize_feedback_event(event: dict, text_fields=FEEDBACK_TEXT_FIELDS,
                            limits: FeedbackLimits = FeedbackLimits()) -> dict:
    """Copy of ``event`` with free-text fields sanitized for storage.

    Structural fields (ids, kind, repo, timestamps) are left to the store's
    own validation; only the named free-text fields are rewritten.
    """
    out = dict(event)
    for key in text_fields:
        if isinstance(out.get(key), str):
            out[key] = sanitize_feedback_text(out[key], limits)
    return out
