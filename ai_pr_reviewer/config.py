"""Configuration: CLI args > action inputs (INPUT_* env) > plain env vars,
optionally merged with review rules fetched from the dashboard."""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)

SEVERITIES = ("info", "low", "medium", "high", "critical")

# V3-E05-T05: every INPUT_-prefixed environment variable the engine reads.
# action.yml exports the Action's inputs under these names; the extras are
# engine-only knobs settable directly from a workflow env block. Anything
# else starting with INPUT_ comes from a future or misspelled surface and is
# warned about — never fatal — so forward compatibility degrades to a notice
# instead of a crash. tests/test_config.py pins this set against action.yml
# and against the names actually read in this module.
KNOWN_INPUT_ENV_VARS = frozenset({
    "INPUT_GITHUB_TOKEN", "INPUT_ANTHROPIC_API_KEY", "INPUT_OPENAI_API_KEY",
    "INPUT_GEMINI_API_KEY", "INPUT_OPENAI_BASE_URL", "INPUT_REPOSITORY",
    "INPUT_PR_NUMBER", "INPUT_MOCK", "INPUT_MODEL", "INPUT_SEVERITY_THRESHOLD",
    "INPUT_MAX_COMMENTS", "INPUT_EXCLUDE", "INPUT_FOCUS", "INPUT_FAIL_ON",
    "INPUT_NO_COMMENT", "INPUT_DASHBOARD_URL", "INPUT_DASHBOARD_TOKEN",
    "INPUT_OUTPUT", "INPUT_BATCH_CHARS", "INPUT_REVIEW_MODE",
    "INPUT_INCREMENTAL", "INPUT_RULES_FILE", "INPUT_STORAGE_FILE",
    "INPUT_PROVIDER_ORDER", "INPUT_REPO_CONTEXT_CHARS", "INPUT_RETENTION_DAYS",
})


def _warn_unknown_inputs() -> None:
    """Forward compatibility (V3-E05-T05): unknown future inputs warn, don't
    crash. Never echoes values — only the variable names — so a stray
    secret-looking input cannot leak through this message."""
    unknown = sorted(name for name in os.environ
                     if name.startswith("INPUT_")
                     and name not in KNOWN_INPUT_ENV_VARS)
    if unknown:
        log.warning("unknown INPUT_* variable(s) ignored: %s "
                    "(known inputs: ai_pr_reviewer.config."
                    "KNOWN_INPUT_ENV_VARS)", ", ".join(unknown))

# D13 (V3-E05-T02): default inline-comment cap. Quality ceiling: past this
# many comments the extra findings are summarized instead of posted one per
# line; the Action's `max_comments` default (action.yml) mirrors this value
# and is frozen by tests/test_action_contract.py.
DEFAULT_MAX_COMMENTS = 20


def sev_rank(s: str) -> int:
    return SEVERITIES.index(s) if s in SEVERITIES else 2


def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


def _env_bool(*names: str, default: bool) -> bool:
    for n in names:
        v = os.environ.get(n)
        if v is not None and v != "":
            return v.strip().lower() in ("1", "true", "yes", "on")
    return default


def _bool_field(cli_value: bool | None, *env_names: str, default: bool) -> bool:
    """Same CLI > INPUT_*/env > default layering as every other field.
    ``cli_value`` should be ``None`` when the CLI didn't set it (as opposed
    to explicitly False) so an unset flag doesn't shadow the env var."""
    if cli_value is not None:
        return bool(cli_value)
    return _env_bool(*env_names, default=default)


def _str_field(cli_value: str | None, *env_names: str, default: str = "") -> str:
    """CLI > env > default for a free-form string (blank CLI = unset)."""
    if cli_value is not None and str(cli_value).strip():
        return str(cli_value).strip()
    return _env(*env_names, default=default)


def _int_field(cli_value: Any, *env_names: str, default: int) -> int:
    """CLI > env > default for an integer; unparsable input falls back to
    ``default`` rather than raising — a typo'd budget must not kill a review."""
    raw = _str_field(cli_value, *env_names, default=str(default))
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        return default


class ConfigError(SystemExit):
    """Invalid configuration: prints ``error: …`` to stderr and exits **1**.

    This is the CLI's existing configuration-failure shape (``cli.run``
    already reports config problems via ``raise SystemExit("error: …")``):
    a string-valued SystemExit prints the message with no traceback and
    exits with status 1 — distinct from exit 2 (fail-on threshold reached)
    and from argparse's own CLI-usage errors. D6: garbage numeric ``INPUT_*``
    values used to escape as a raw ``ValueError`` traceback.
    """

    def __init__(self, message: str) -> None:
        super().__init__(f"error: {message}")


def _strict_int(raw: Any, name: str) -> int:
    """Parse a numeric ``INPUT_*``/derived value, failing cleanly (D6).

    ``name`` is the input's public name (``pr_number``, ``max_comments``, …)
    so the message names exactly which input was bad; the offending value is
    echoed for debugging (numeric inputs never carry secrets — callers must
    not pass secret material here). Raises :class:`ConfigError` (exit 1)
    instead of leaking a ``ValueError`` traceback.
    """
    try:
        return int(str(raw).strip())
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be an integer (got {raw!r})") from None


@dataclass
class Config:
    # Sources
    github_token: str = ""
    anthropic_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""
    openai_base_url: str = ""
    repo: str = ""                     # owner/name
    pr_number: int = 0
    diff_file: str = ""                # local mode: read diff from file
    mock: bool = False

    # Review knobs
    model: str = ""                    # empty = provider default (Claude only)
    severity_threshold: str = "medium"
    severity_threshold_explicit: bool = False
    max_comments: int = DEFAULT_MAX_COMMENTS
    exclude: list[str] = field(default_factory=list)   # glob patterns
    focus_areas: list[str] = field(default_factory=list)  # extra prompt hints
    batch_chars: int = 80_000
    fail_on: str = "never"             # never | critical | high | medium | low | info
    no_comment: bool = False           # don't post to GitHub (report only)

    # Dashboard sync
    dashboard_url: str = ""
    dashboard_token: str = ""

    # Outputs
    output: str = ""                   # where to write report JSON

    # V2 knobs (context.py / rules.py / storage.py)
    review_mode: str = "automatic"     # economy | balanced | maximum | automatic
    incremental_enabled: bool = True   # review only changes since last reviewed SHA
    rules_file: str = ".ai-pr-reviewer.yml"  # project rules file, relative to repo root
    storage_file: str = ""             # local SQLite file for stateful reviews;
                                        # empty = stateless unless dashboard_url/token set

    # V3 knobs
    provider_order: str = ""           # comma-separated failover order, e.g.
                                        # "claude,openai"; empty = default provider
    repo_context_chars: int = 12_000   # repo-context character budget; <= 0 disables it
    retention_days: int = 0            # V3-E04-T02: 0 = keep everything (default);
                                        # >0 prunes aged finding-history + telemetry


def load_config(args) -> Config:
    _warn_unknown_inputs()
    severity_input = args.severity_threshold or _env("INPUT_SEVERITY_THRESHOLD")
    cfg = Config(
        github_token=args.github_token or _env("INPUT_GITHUB_TOKEN", "GITHUB_TOKEN",
                                               "GH_TOKEN"),
        anthropic_api_key=args.anthropic_api_key or _env(
            "INPUT_ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY"),
        openai_api_key=getattr(args, "openai_api_key", None) or _env("INPUT_OPENAI_API_KEY", "OPENAI_API_KEY"),
        gemini_api_key=getattr(args, "gemini_api_key", None) or _env("INPUT_GEMINI_API_KEY", "GEMINI_API_KEY"),
        openai_base_url=getattr(args, "openai_base_url", None) or _env("INPUT_OPENAI_BASE_URL", "OPENAI_BASE_URL"),
        repo=args.repo or _env("INPUT_REPOSITORY", "GITHUB_REPOSITORY"),
        pr_number=_strict_int(args.pr or _env("INPUT_PR_NUMBER", default="0"),
                              "pr_number"),
        diff_file=args.diff_file or "",
        mock=args.mock or _env("INPUT_MOCK", "MOCK").lower() in ("1", "true", "yes"),
        model=args.model or _env("INPUT_MODEL", default=""),
        severity_threshold=(severity_input or "medium").lower(),
        severity_threshold_explicit=bool(severity_input),
        max_comments=_strict_int(args.max_comments or _env(
            "INPUT_MAX_COMMENTS", default=str(DEFAULT_MAX_COMMENTS)),
            "max_comments"),
        exclude=[e for e in (args.exclude or _env("INPUT_EXCLUDE").splitlines()) if e.strip()],
        focus_areas=[area for area in (getattr(args, "focus", None) or
                                       _env("INPUT_FOCUS").splitlines()) if area.strip()],
        fail_on=(args.fail_on or _env("INPUT_FAIL_ON", default="never")).lower(),
        no_comment=args.no_comment or _env("INPUT_NO_COMMENT").lower() in ("1", "true", "yes"),
        dashboard_url=(args.dashboard_url or _env("INPUT_DASHBOARD_URL")).rstrip("/"),
        dashboard_token=args.dashboard_token or _env("INPUT_DASHBOARD_TOKEN", "DASHBOARD_TOKEN"),
        output=args.output or _env("INPUT_OUTPUT", default="review-report.json"),
    )
    cfg.batch_chars = _strict_int(_env("INPUT_BATCH_CHARS", default="80000"),
                                  "batch_chars")
    cfg.review_mode = (getattr(args, "review_mode", None) or _env(
        "INPUT_REVIEW_MODE", default="automatic")).lower()
    cfg.incremental_enabled = _bool_field(getattr(args, "incremental", None),
                                          "INPUT_INCREMENTAL", default=True)
    cfg.rules_file = getattr(args, "rules_file", None) or _env(
        "INPUT_RULES_FILE", default=".ai-pr-reviewer.yml")
    cfg.storage_file = getattr(args, "storage_file", None) or _env(
        "INPUT_STORAGE_FILE", "REVIEW_STORAGE_FILE", default="")
    cfg.provider_order = _str_field(getattr(args, "provider_order", None),
                                    "INPUT_PROVIDER_ORDER", "PROVIDER_ORDER")
    cfg.repo_context_chars = _int_field(getattr(args, "repo_context_chars", None),
                                        "INPUT_REPO_CONTEXT_CHARS",
                                        "REPO_CONTEXT_CHARS", default=12_000)
    cfg.retention_days = _strict_int(_env("INPUT_RETENTION_DAYS", "RETENTION_DAYS",
                                          default="0"),
                                     "retention_days")
    if cfg.retention_days < 0:
        raise ConfigError("retention_days must be >= 0 (0 = keep everything)")
    return cfg


def merge_dashboard_rules(cfg: Config) -> None:
    """Pull shared review rules from the dashboard (if configured) and fold
    them in. CLI/env values win over dashboard rules."""
    if not cfg.dashboard_url or not cfg.dashboard_token:
        return
    try:
        import httpx

        r = httpx.get(f"{cfg.dashboard_url}/api/config",
                      headers={"X-Dashboard-Token": cfg.dashboard_token}, timeout=15)
        r.raise_for_status()
        rules = r.json()
    except Exception:
        return  # dashboard unreachable — proceed with local config

    if rules.get("severity_threshold") in SEVERITIES and not cfg.severity_threshold_explicit:
        cfg.severity_threshold = rules["severity_threshold"]
    for pat in rules.get("exclude_globs") or []:
        if pat and pat not in cfg.exclude:
            cfg.exclude.append(pat)
    for area in rules.get("focus_areas") or []:
        if area and area not in cfg.focus_areas:
            cfg.focus_areas.append(area)
