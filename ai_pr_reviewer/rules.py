"""Repository-owner review configuration.

Parses and validates `.ai-pr-reviewer.yml` into a normalized
:class:`ReviewPolicy`. This file is TRUSTED repository-owner configuration —
the opposite of a PR diff, which is untrusted attacker-controlled text (see
security.py). Keeping ``ReviewPolicy`` as its own dataclass, separate from
the diff text that ``ReviewContext.files`` carries, is what lets whoever
builds the actual Claude prompt put trusted rules and untrusted PR
content in separate prompt sections instead of one merged fence.

A broken, missing or malicious ``.ai-pr-reviewer.yml`` must never be able to
crash a review: every failure mode here logs a warning and falls back to
``ReviewPolicy()`` defaults.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

from .config import SEVERITIES
from .index.limits import (DEFAULT_MAX_BYTES as DEFAULT_CONTEXT_MAX_BYTES,
                           DEFAULT_MAX_FILES as DEFAULT_CONTEXT_MAX_FILES,
                           HARD_MAX_BYTES as HARD_CONTEXT_MAX_BYTES,
                           HARD_MAX_FILES as HARD_CONTEXT_MAX_FILES)

log = logging.getLogger(__name__)

MODES = ("economy", "balanced", "maximum", "automatic")
DEFAULT_MODE = "automatic"
DEFAULT_SEVERITY = "medium"
DEFAULT_RULES_FILE = ".ai-pr-reviewer.yml"
SENSITIVE_EXCLUDE_GLOBS = (
    ".env", ".env.*", "**/.env", "**/.env.*",
    ".npmrc", ".pypirc", "**/.npmrc", "**/.pypirc",
    "*.pem", "**/*.pem", "*.key", "**/*.key",
    "*.p12", "**/*.p12", "*.pfx", "**/*.pfx",
    "*.tfstate", "**/*.tfstate", "*.keystore", "**/*.keystore",
    ".ssh/**", "**/.ssh/**", ".aws/**", "**/.aws/**",
    ".gcp/**", "**/.gcp/**", "secrets/**", "**/secrets/**",
    "credentials/**", "**/credentials/**",
    "service-account*.json", "**/service-account*.json",
)

# Defensive cap on rules/exclude/focus — a huge (or malicious) YAML file
# must not be able to balloon the prompt or the file-matching work.
MAX_LIST_ENTRIES = 50

# V3-E05-T05: keys this parser understands. Anything else at the top level
# (or a future section) is warned about and skipped — never fatal — so
# config written for a newer schema still reviews on an older engine.
# ``context`` (V4-E01-T04) holds the repository-index budgets.
KNOWN_TOP_LEVEL_KEYS = frozenset({"review", "rules", "exclude", "focus",
                                  "context"})


@dataclass
class ReviewPolicy:
    """Normalized project review configuration (shared with
    ``ai_pr_reviewer/context.py``)."""

    mode: str = DEFAULT_MODE
    severity_threshold: str = DEFAULT_SEVERITY
    rules: list[str] = field(default_factory=list)
    exclude: list[str] = field(default_factory=lambda: list(SENSITIVE_EXCLUDE_GLOBS))
    focus: list[str] = field(default_factory=list)
    # V4-E01-T04: repository-index budgets. These bound what the index
    # *reads* from the checkout; they sit BENEATH the Action's
    # ``repo_context_chars`` input, which stays the outer ceiling on how
    # much repository context can ever reach a prompt (and whose <= 0
    # disables the index build entirely). Defaults preserve V3 behavior.
    context_max_files: int = DEFAULT_CONTEXT_MAX_FILES
    context_max_bytes: int = DEFAULT_CONTEXT_MAX_BYTES


def _with_sensitive_exclusions(values: list[str]) -> list[str]:
    return list(dict.fromkeys([*SENSITIVE_EXCLUDE_GLOBS, *values]))[:MAX_LIST_ENTRIES]


def _as_str_list(value: object, field_name: str, source: str) -> list[str]:
    """Coerce a YAML value into a capped ``list[str]``, warning (never
    raising) on anything malformed."""
    if value is None:
        return []
    if not isinstance(value, list):
        log.warning("%s: '%s' should be a list, got %s — ignoring",
                    source, field_name, type(value).__name__)
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str):
            s = item.strip()
            if s:
                out.append(s)
        else:
            log.warning("%s: non-string entry in '%s' (%r) — skipped",
                        source, field_name, item)
    if len(out) > MAX_LIST_ENTRIES:
        log.warning("%s: '%s' has %d entries — capping at %d",
                    source, field_name, len(out), MAX_LIST_ENTRIES)
        out = out[:MAX_LIST_ENTRIES]
    return out


def _bounded_int(value: object, *, default: int, high: int, name: str,
                 source: str) -> int:
    """Parse a bounded positive-integer budget (V4-E01-T04).

    Warns and falls back for anything unusable — a typo'd budget must
    never fail a review — and caps at the hard ceiling so config can only
    move budgets *down* within ``[1, high]`` (``0`` does not mean
    "disable": disabling repository context is ``repo_context_chars: 0``,
    the outer ceiling).
    """
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        log.warning("%s: '%s' should be an integer — defaulting to %d",
                    source, name, default)
        return default
    if value < 1:
        log.warning("%s: '%s' must be >= 1 (got %d) — defaulting to %d "
                    "(set repo_context_chars to 0 to disable repository "
                    "context entirely)", source, name, value, default)
        return default
    if value > high:
        log.warning("%s: '%s' %d exceeds the hard cap — capping at %d",
                    source, name, value, high)
        return high
    return value


def _normalize(raw: dict, source: str) -> ReviewPolicy:
    # Forward compatibility (V3-E05-T05): unknown top-level keys warn and are
    # skipped, so future/misspelled sections surface as a notice instead of
    # silently vanishing (and never crash the review).
    unknown = sorted({str(k) for k in raw} - KNOWN_TOP_LEVEL_KEYS)
    if unknown:
        log.warning("%s: unknown top-level key(s) ignored: %s "
                    "(known: %s)", source, ", ".join(unknown),
                    ", ".join(sorted(KNOWN_TOP_LEVEL_KEYS)))

    review = raw.get("review")
    review = review if isinstance(review, dict) else {}

    mode = review.get("mode", DEFAULT_MODE)
    if not isinstance(mode, str) or mode.lower() not in MODES:
        log.warning("%s: invalid review.mode %r — defaulting to %r",
                    source, mode, DEFAULT_MODE)
        mode = DEFAULT_MODE
    else:
        mode = mode.lower()

    sev = review.get("severity_threshold", DEFAULT_SEVERITY)
    if not isinstance(sev, str) or sev.lower() not in SEVERITIES:
        log.warning("%s: invalid review.severity_threshold %r — defaulting to %r",
                    source, sev, DEFAULT_SEVERITY)
        sev = DEFAULT_SEVERITY
    else:
        sev = sev.lower()

    ctx = raw.get("context")
    if ctx is None:
        ctx = {}
    elif not isinstance(ctx, dict):
        log.warning("%s: 'context' should be a mapping — ignoring it", source)
        ctx = {}
    context_max_files = _bounded_int(
        ctx.get("max_files"), default=DEFAULT_CONTEXT_MAX_FILES,
        high=HARD_CONTEXT_MAX_FILES, name="context.max_files", source=source)
    context_max_bytes = _bounded_int(
        ctx.get("max_bytes"), default=DEFAULT_CONTEXT_MAX_BYTES,
        high=HARD_CONTEXT_MAX_BYTES, name="context.max_bytes", source=source)

    return ReviewPolicy(
        mode=mode,
        severity_threshold=sev,
        rules=_as_str_list(raw.get("rules"), "rules", source),
        exclude=_with_sensitive_exclusions(
            _as_str_list(raw.get("exclude"), "exclude", source)),
        focus=_as_str_list(raw.get("focus"), "focus", source),
        context_max_files=context_max_files,
        context_max_bytes=context_max_bytes,
    )


def load_project_rules(repo_root: str = ".",
                       filename: str = DEFAULT_RULES_FILE) -> ReviewPolicy:
    """Load and validate ``<repo_root>/<filename>``.

    ``filename`` is an optional extra kwarg beyond the shared-contract
    signature (``load_project_rules(repo_root=".")``) so callers that know
    about ``Config.rules_file`` (see ``build_context``) can point at a
    non-default path; every existing call site that only passes
    ``repo_root`` keeps working unchanged.

    Never raises. Returns ``ReviewPolicy()`` defaults, with a logged
    warning, for: a missing file, a missing PyYAML dependency, malformed
    YAML, a non-mapping top-level document, or any other unexpected error
    while normalizing the parsed content.
    """
    path = os.path.join(repo_root, filename)
    if not os.path.isfile(path):
        return ReviewPolicy()

    try:
        import yaml
    except ImportError:
        log.warning("%s: PyYAML is not installed — skipping project rules "
                    "(add PyYAML to requirements.txt)", path)
        return ReviewPolicy()

    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh)
    except Exception as exc:  # malformed YAML, bad encoding, permissions, ...
        log.warning("%s: failed to parse — using defaults (%s)", path, exc)
        return ReviewPolicy()

    if raw is None:  # empty file
        return ReviewPolicy()
    if not isinstance(raw, dict):
        log.warning("%s: top-level YAML must be a mapping — using defaults", path)
        return ReviewPolicy()

    try:
        return _normalize(raw, path)
    except Exception as exc:  # belt-and-braces — normalization must not crash a review
        log.warning("%s: unexpected error normalizing rules — using defaults (%s)",
                    path, exc)
        return ReviewPolicy()
