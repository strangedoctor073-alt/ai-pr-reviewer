"""AI Security v2 (V4.2-E02).

Perimeter defense and adversarial screening for AI-assisted review:
- V4.2-E02-T01: Injection detection for retrieved/context content
- V4.2-E02-T02: Model-output attack patterns (exfiltration, tool abuse, image pings)
- V4.2-E02-T03: Prompt-perimeter hardening at shared prompt-builder
- V4.2-E02-T04: Per-stage untrusted-surface checklist enforced by tests
"""
from __future__ import annotations

import re
from typing import Any

from .security import neutralize_fence_tags, scan_prompt_injection

UNTRUSTED_SURFACES = (
    "diff",
    "pr_metadata",
    "retrieved_files",
    "model_output",
    "user_comments",
    "memory_notes",
)

MODEL_OUTPUT_ABUSE_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("image-pingback-exfiltration", re.compile(r"!\[[^\]]*\]\((https?://[^\s\)]+)\)|<img[^>]+src=[\"'](https?://[^\"']+)[\"']", re.I)),
    ("curl-wget-exfiltration", re.compile(r"\b(curl\s+-[^\n]*(@|--data|--post-data)|wget\s+--post-data|bash\s+-i\s+>&|/dev/tcp/)", re.I)),
    ("data-uri-script-injection", re.compile(r"data:(text/html|application/javascript)[^\"'>]*", re.I)),
    ("webhook-exfiltration", re.compile(r"https?://(?:webhook\.site|pipedream\.net|requestbin\.)[^\s\"'>)]*", re.I)),
]


def scan_context_injection(context_text: str, source_label: str = "context") -> list[str]:
    """Screen PR-adjacent or retrieved context for prompt injection patterns."""
    hits = scan_prompt_injection(context_text)
    labeled_hits = [f"[{source_label}] {h}" for h in hits]
    return labeled_hits


def scan_model_output_abuse(model_output: str) -> list[str]:
    """Screen model output for covert exfiltration or tool-abuse payload attempts."""
    warnings: list[str] = []
    for name, pattern in MODEL_OUTPUT_ABUSE_PATTERNS:
        match = pattern.search(model_output)
        if match:
            sample = match.group(0)[:60]
            warnings.append(f"{name}: {sample!r}")
    return warnings


def harden_prompt_perimeter(text: str, nonce: str) -> str:
    """Neutralize fence tags and wrap text inside authoritative nonce perimeter."""
    neutralized = neutralize_fence_tags(text)
    return f'<untrusted_content nonce="{nonce}">\n{neutralized}\n</untrusted_content>'


def verify_untrusted_surface(surface: str, content: str) -> dict[str, Any]:
    """Validate that an untrusted ingestion surface passes screening checks."""
    if surface not in UNTRUSTED_SURFACES:
        raise ValueError(f"Unknown surface '{surface}'; allowed: {UNTRUSTED_SURFACES}")

    warnings: list[str] = []
    if surface == "model_output":
        warnings.extend(scan_model_output_abuse(content))
    else:
        warnings.extend(scan_context_injection(content, source_label=surface))

    status = "flagged" if warnings else "passed"
    return {
        "surface": surface,
        "status": status,
        "screened": True,
        "warnings": warnings,
    }
