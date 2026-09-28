"""Output layer: review-report.json artifact, GitHub Step Summary markdown,
and pushing the finished report to the dashboard."""
from __future__ import annotations

import datetime as _dt
import json
import os
import uuid

from .models import ReviewResult, SEVERITY_EMOJI, SEVERITY_ORDER

# Finding lifecycle states that no longer need a developer's attention.
CLOSED_STATES = frozenset({"resolved", "dismissed", "muted"})

# Report header text per engine. Static-only output is NEVER labelled as AI
# (README promise): the rule engine is deterministic static analysis.
_ENGINE_TITLE = {
    "claude": "Claude",
    "openai": "OpenAI",
    "gemini": "Gemini",
    "static": "Static Fallback",
    "claude+static": "Claude + Static Fallback",
    "openai+static": "OpenAI + Static Fallback",
    "gemini+static": "Gemini + Static Fallback",
}
_ENGINE_FOOTER = {
    "claude": "review by Claude (AI)",
    "openai": "review by OpenAI (AI)",
    "gemini": "review by Google Gemini (AI)",
    "static": "rule-based static analysis — not an AI review",
    "claude+static": ("review by Claude (AI); batches Claude could not review "
                      "were covered by rule-based static analysis (not AI)"),
    "openai+static": ("review by OpenAI (AI); batches OpenAI could not review "
                      "were covered by rule-based static analysis (not AI)"),
    "gemini+static": ("review by Google Gemini (AI); batches Gemini could not review "
                      "were covered by rule-based static analysis (not AI)"),
}

# Optional Finding attributes carried into the report JSON when the Finding
# has them and Finding.to_dict() did not already emit them.
#  * suggestion metadata — groundwork for a future "apply fix" feature.
#  * lifecycle fields    — so per-finding state matches the *_findings_count
#                          totals below.
_FINDING_PASSTHROUGH = (
    "suggestion_type", "start_line", "end_line",
    "fingerprint", "state", "first_seen_sha", "last_seen_sha",
    "resolved_at", "github_comment_id",
)


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_report_id(repo: str, pr_number: int) -> str:
    slug = repo.replace("/", "-").lower() or "local"
    return f"{slug}-pr{pr_number}-{_dt.datetime.now():%Y%m%d}-{uuid.uuid4().hex[:6]}"


# ------------------------------------------------------- engine / state helpers

def resolve_engine(obj) -> str:
    engine = str(getattr(obj, "engine", "") or "").lower()
    if engine in _ENGINE_TITLE:
        return engine
    mode = str(getattr(obj, "mode", "") or "").lower()
    if mode in ("claude", "openai", "gemini"):
        return mode
    return "static"


def finding_state(f) -> str:
    """Lifecycle state of a finding ("new" when the Finding has none)."""
    state = getattr(f, "state", "new")
    return str(getattr(state, "value", state) or "new").lower()


def open_findings(findings) -> list:
    """Findings that still need attention (not resolved/dismissed/muted)."""
    return [f for f in findings if finding_state(f) not in CLOSED_STATES]


def count_by_state(findings) -> dict[str, int]:
    out: dict[str, int] = {}
    for f in findings:
        s = finding_state(f)
        out[s] = out.get(s, 0) + 1
    return out


def severity_counts(findings) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def report_title(result: ReviewResult) -> str:
    return f"\U0001f916 PR Review \u2014 {_ENGINE_TITLE[resolve_engine(result)]}"


def _review_state(result: ReviewResult, fallback_used: bool) -> str:
    state = getattr(result, "review_state", None)
    if state:
        return str(getattr(state, "value", state))
    return "fallback" if fallback_used else "completed"


# ---------------------------------------------------------------------- report

def finalize_report(result: ReviewResult, report_id: str | None = None) -> dict:
    data = result.to_dict()
    data["id"] = report_id or new_report_id(result.pr.repo, result.pr.pr_number)

    fallback_used = bool(getattr(result, "fallback_used", False))
    by_state = count_by_state(result.findings)
    data["review_state"] = _review_state(result, fallback_used)
    data["engine"] = resolve_engine(result)
    data["fallback_used"] = fallback_used
    data["new_findings_count"] = by_state.get("new", 0)
    data["resolved_findings_count"] = by_state.get("resolved", 0)
    # A reopened finding is by definition still open, so it counts as active.
    data["active_findings_count"] = by_state.get("active", 0) + by_state.get("reopened", 0)

    _carry_finding_fields(result, data)
    return data


def _carry_finding_fields(result: ReviewResult, data: dict) -> None:
    """Copy optional Finding attributes into each finding dict (never
    overwrites what Finding.to_dict() already produced)."""
    rows = data.get("findings") or []
    if len(rows) != len(result.findings):
        return
    for f, row in zip(result.findings, rows):
        for key in _FINDING_PASSTHROUGH:
            if key not in row and hasattr(f, key):
                value = getattr(f, key)
                row[key] = getattr(value, "value", value)


def write_report(path: str, report: dict) -> str:
    # `--output some/new/dir/report.json` must work on a fresh clone, where
    # git does not track empty directories such as demo/out/.
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    return path


def push_to_dashboard(dashboard_url: str, dashboard_token: str,
                      report: dict) -> tuple[bool, str]:
    import httpx

    try:
        r = httpx.post(f"{dashboard_url}/api/reports", json=report,
                       headers={"X-Dashboard-Token": dashboard_token}, timeout=20)
        if r.status_code in (200, 201):
            rid = r.json().get("id", report.get("id"))
            return True, f"report stored on dashboard (id={rid})"
        return False, f"dashboard rejected report ({r.status_code}): {r.text[:200]}"
    except Exception as exc:  # noqa: BLE001
        return False, f"dashboard unreachable: {exc}"


# --------------------------------------------------------------------- markdown

def _finding_line_md(result: ReviewResult, f) -> str:
    sha = result.pr.head_sha
    loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
    link = loc
    if sha and f.file:
        from .github_client import GitHubClient
        url = GitHubClient.file_url(result.pr.repo, sha, f.file, f.line)
        link = f"[{loc}]({url})"
    sug = ""
    if f.suggestion:
        fence = "```suggestion\n" + f.suggestion + "\n```"
        sug = "\n\n" + fence
    return (f"{SEVERITY_EMOJI.get(f.severity, '\u26aa')} **[{f.severity.upper()}]** "
            f"**{f.title}** ({f.category}) — {link}\n\n{f.explanation}{sug}")


def build_summary_markdown(result: ReviewResult, top_n: int = 8) -> str:
    open_ = open_findings(result.findings)
    resolved = count_by_state(result.findings).get("resolved", 0)
    counts = severity_counts(open_)
    bits = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info")
            if counts.get(s)]
    engine = resolve_engine(result)
    score = getattr(result, "health_score", 100)
    grade = getattr(result, "health_grade", "A+")
    if score >= 90:
        gauge = "🟢"
    elif score >= 70:
        gauge = "🟡"
    else:
        gauge = "🔴"
    
    score_label = f"{gauge} **{score}/100** ({grade})"
    
    lines = [
        f"## 🤖 AI PR Review · Health Score: {score_label}",
        "",
        f"> {result.summary or 'No summary available.'}",
        "",
        "| 📊 Metric | Value |",
        "|---|---|",
        f"| **Health Grade** | `{grade} ({score}/100)` |",
        f"| **Issues Flagged** | {len(open_)} ({' · '.join(bits) if bits else 'none'}) |",
        f"| **Files Reviewed** | {result.stats.files} (+{result.stats.additions} / −{result.stats.deletions} lines) |",
        f"| **Review Engine** | `{result.model or engine}` ({result.duration_ms} ms) |",
    ]
    
    shown = open_[:top_n]
    if shown:
        lines.append("")
        lines.append("<details>")
        lines.append(f"<summary><strong>Top findings ({len(shown)} of {len(open_)})</strong></summary>")
        lines.append("")
        for f in shown:
            lines.append(_finding_line_md(result, f))
            lines.append("")
        lines.append("</details>")
    
    if resolved:
        lines.append(f"\n> ✅ {resolved} previously reported finding(s) resolved.")
    if result.suppressed:
        lines.append(f"\n> ℹ️ {result.suppressed} finding(s) below the comment threshold or "
                     f"over the inline-comment cap were summarized here instead of annotated inline.")
    if result.warnings:
        lines.append("\n> ⚠️ Warnings: " + "; ".join(result.warnings))
    lines.append(f"\n<sub>Posted by AI PR Reviewer — {_ENGINE_FOOTER.get(engine, engine)}</sub>")
    return "\n".join(lines)


def write_step_summary(result: ReviewResult) -> str | None:
    import os

    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return None
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(build_summary_markdown(result) + "\n")
    return path
