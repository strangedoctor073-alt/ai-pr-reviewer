"""Configuration: CLI args > action inputs (INPUT_* env) > plain env vars,
optionally merged with review rules fetched from the dashboard."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

SEVERITIES = ("info", "low", "medium", "high", "critical")


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
    max_comments: int = 20
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
    fallback_enabled: bool = True      # allow static-analysis fallback on Claude failure
    incremental_enabled: bool = True   # review only changes since last reviewed SHA
    memory_enabled: bool = True        # pull repository memory/feedback into context
    rules_file: str = ".ai-pr-reviewer.yml"  # project rules file, relative to repo root
    storage_file: str = ""             # local SQLite file for stateful reviews;
                                        # empty = stateless unless dashboard_url/token set


def load_config(args) -> Config:
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
        pr_number=int(args.pr or _env("INPUT_PR_NUMBER", default="0")),
        diff_file=args.diff_file or "",
        mock=args.mock or _env("INPUT_MOCK", "MOCK").lower() in ("1", "true", "yes"),
        model=args.model or _env("INPUT_MODEL", default=""),
        severity_threshold=(severity_input or "medium").lower(),
        severity_threshold_explicit=bool(severity_input),
        max_comments=int(args.max_comments or _env("INPUT_MAX_COMMENTS", default="20")),
        exclude=[e for e in (args.exclude or _env("INPUT_EXCLUDE").splitlines()) if e.strip()],
        focus_areas=[area for area in (getattr(args, "focus", None) or
                                       _env("INPUT_FOCUS").splitlines()) if area.strip()],
        fail_on=(args.fail_on or _env("INPUT_FAIL_ON", default="never")).lower(),
        no_comment=args.no_comment or _env("INPUT_NO_COMMENT").lower() in ("1", "true", "yes"),
        dashboard_url=(args.dashboard_url or _env("INPUT_DASHBOARD_URL")).rstrip("/"),
        dashboard_token=args.dashboard_token or _env("INPUT_DASHBOARD_TOKEN", "DASHBOARD_TOKEN"),
        output=args.output or _env("INPUT_OUTPUT", default="review-report.json"),
    )
    cfg.batch_chars = int(_env("INPUT_BATCH_CHARS", default="80000"))
    cfg.review_mode = (getattr(args, "review_mode", None) or _env(
        "INPUT_REVIEW_MODE", default="automatic")).lower()
    cfg.fallback_enabled = _bool_field(getattr(args, "fallback", None),
                                       "INPUT_FALLBACK", default=True)
    cfg.incremental_enabled = _bool_field(getattr(args, "incremental", None),
                                          "INPUT_INCREMENTAL", default=True)
    cfg.memory_enabled = _bool_field(getattr(args, "memory", None),
                                     "INPUT_MEMORY", default=True)
    cfg.rules_file = getattr(args, "rules_file", None) or _env(
        "INPUT_RULES_FILE", default=".ai-pr-reviewer.yml")
    cfg.storage_file = getattr(args, "storage_file", None) or _env(
        "INPUT_STORAGE_FILE", "REVIEW_STORAGE_FILE", default="")
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
