"""Security helpers for the review pipeline.

Three jobs, all defense-in-depth around the fact that a pull-request diff is
*untrusted attacker-controlled text*:

1. ``wrap_untrusted_diff``  — fence the diff between nonce-tagged markers and
   neutralize spoofed markers, so the model can be told precisely which text
   is data and which is instruction.
2. ``scan_prompt_injection`` — screen diffs for instruction-impersonation
   phrases; matches are surfaced as warnings on the review run.
3. ``redact_secrets`` — scrub credential-looking strings out of anything we
   post back to GitHub or persist on the dashboard, so a finding that quotes a
   secret from the diff doesn't itself leak it.
"""
from __future__ import annotations

import re
import secrets

# ---------------------------------------------------------------------------
# 1 · Untrusted-diff fencing
# ---------------------------------------------------------------------------

OPEN_TAG_RE = re.compile(r"<\s*/?\s*untrusted_diff[^>]*>", re.I)


def new_nonce() -> str:
    return secrets.token_hex(8)


def wrap_untrusted_diff(diff_text: str, nonce: str | None = None) -> tuple[str, str]:
    """Fence a diff for embedding in an LLM prompt.

    Any diff text that tries to spoof the fence tags is neutralized first, so
    the model only ever sees ONE closing tag — ours, carrying our nonce.
    Returns (wrapped_text, nonce).
    """
    nonce = nonce or new_nonce()
    safe = OPEN_TAG_RE.sub("[neutralized-fence-tag]", diff_text)
    wrapped = (
        f'<untrusted_diff id="{nonce}">\n'
        f"{safe}\n"
        f'</untrusted_diff id="{nonce}">'
    )
    return wrapped, nonce


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
