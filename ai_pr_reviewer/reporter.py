"""Output layer: review-report.json artifact, GitHub Step Summary markdown,
and pushing the finished report to the dashboard."""
from __future__ import annotations

import datetime as _dt
import json
import os
import uuid

from .models import (ReviewResult, SEVERITY_EMOJI, SEVERITY_ORDER,
                     describe_provenance)
from .security import markdown_safe_inline, sanitize_warnings

# Finding lifecycle states that no longer need a developer's attention.
CLOSED_STATES = frozenset({"resolved", "dismissed", "muted"})

# D13 (V3-E05-T02): how many open findings (and how many resolved entries)
# one job step-summary lists. Quality ceiling: a large PR's summary truncates
# here — totals are still shown ("… and N more") — which bounds the size of
# every job's step summary.
MAX_MARKDOWN_FINDINGS = 8

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
    "verification_status", "verification_reason", "verified_at",
    "provenance_engine", "provenance_model", "provenance_agent",
    "provenance_origin",
    # V4-E04 (T02/T03): multi-source provenance, embedded evidence and the
    # dedup merge trail, carried for the same reason as the fields above.
    "provenance_sources", "evidence", "merged_fingerprints",
)

# How each verification outcome is appended to a resolved finding in the
# summary: a fix that survived a re-review is labelled as verified, and one
# we could not confirm is never allowed to read as "fixed".
_VERIFICATION_MARKS = {
    "resolved": " · ✅ verified fixed",
    "still_present": " · 🔍 re-reported by this review",
    "unable_to_verify": " · ❓ unable to verify",
}

# Severity emoji used when a finding carries an unknown severity. Kept outside
# the f-string below: Python 3.11 rejects a backslash escape inside an f-string
# expression part (only 3.12+ allows it).
_UNKNOWN_SEVERITY_EMOJI = "\u26aa"

def _engine_note(engine: str) -> str:
    """Suffix that keeps static output from ever reading as an AI review."""
    if engine in ("static",):
        return " — not an AI review"
    if engine.endswith("+static"):
        return " (partly static fallback)"
    return ""


def _verification_mark(status) -> str:
    return _VERIFICATION_MARKS.get(str(status or ""), "")


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
    # D3: below-threshold findings are retained and counted explicitly — they
    # are NOT part of findings_count / Issues Flagged (threshold semantics
    # unchanged), just no longer invisible.
    data["below_threshold_count"] = len(data.get("below_threshold") or [])
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
    return (f"{SEVERITY_EMOJI.get(f.severity, _UNKNOWN_SEVERITY_EMOJI)} **[{f.severity.upper()}]** "
            f"**{f.title}** ({f.category}) — {link}\n\n{f.explanation}{sug}"
            f"{_provenance_suffix(f)}")


def _provenance_suffix(f) -> str:
    """V4-E04-T04: one compact, deterministic `<sub>` line answering
    "why was I told this?" -- which engine(s) produced the finding and which
    evidence records back it (locators only; evidence *content* is never
    rendered here, only cited).

    Everything comes from ``models.describe_provenance``: redacted,
    single-line, bounded, backtick-neutralised, and never raising on an old
    or hand-built finding. Returns "" when a finding carries neither
    provenance nor evidence, so pre-V4 reports render byte-identically
    (structured consumers -- the dashboard -- say "provenance unavailable").
    """
    v = describe_provenance(f)
    bits: list[str] = []
    srcs = [s for s in v["sources"] if s.get("engine")]
    if len(srcs) > 1:                       # merged across engines (V4-E05)
        bits.append("sources: " + " + ".join(
            s["engine"] + (f" ({s['model']})" if s.get("model") else "")
            for s in srcs))
    elif v["engine"]:
        bits.append(f"source: {v['engine']}"
                    + (f" ({v['model']})" if v["model"] else ""))
    if v["evidence"]:
        cites = " · ".join(f"{e['kind']} `{e['locator']}`"
                           for e in v["evidence"][:3])
        more = (f" · +{v['evidence_total'] - 3} more"
                if v["evidence_total"] > 3 else "")
        bits.append(f"evidence: {cites}{more}")
    if v["merged_count"]:
        bits.append(f"merged {v['merged_count']} duplicate(s)")
    if not bits:
        return ""
    return "\n\n<sub>_" + " · ".join(bits) + "_</sub>"


def _risk_row(result: ReviewResult) -> list[str]:
    """PR-level risk line (V3 C8). Only shown when the orchestrator computed
    a risk for this run, so hand-built summaries stay byte-identical."""
    risk = getattr(result, "risk", None)
    if risk is None:
        return []
    level = str(getattr(risk, "level", "low") or "low")
    reasons = [str(r) for r in (getattr(risk, "reasons", None) or [])]
    detail = "; ".join(reasons) if reasons else "no sensitive paths detected"
    icon = "⚠️" if level == "high" else "🟢"
    return [f"| **Risk** | {icon} {level} — {detail.replace('|', '/')} |"]


def _verification_row(result: ReviewResult) -> list[str]:
    """Counts from V3 C4's fix verification, so a developer can tell verified
    fixes from findings that simply were not re-reported."""
    ver = getattr(result, "verification", None)
    if not isinstance(ver, dict):
        return []
    parts = []
    for key, label in (("resolved", "✅ fixed & verified"),
                       ("still_present", "🔍 re-reported"),
                       ("unable_to_verify", "❓ unable to verify")):
        count = int(ver.get(key, 0) or 0)
        if count:
            parts.append(f"{count} {label}")
    if not parts:
        return []
    return [f"| **Verification** | {' · '.join(parts)} |"]


def _resolved_list_md(result: ReviewResult, top_n: int) -> list[str]:
    """Resolved findings, listed WITHOUT their severity.

    A closed finding must not be counted (or labelled) among the issues a
    developer still has to act on — the list only says *where* it was and
    whether verification could confirm the fix.
    """
    rows = [f for f in result.findings if finding_state(f) == "resolved"]
    if not rows:
        return []
    out = ["", "<details>",
           f"<summary><strong>Resolved findings ({len(rows)})</strong></summary>",
           ""]
    for f in rows[:top_n]:
        loc = f"`{f.file}:{f.line}`" if f.line else f"`{f.file}`"
        mark = _verification_mark(getattr(f, "verification_status", None))
        out.append(f"- ✅ {loc} — {f.title}{mark}")
    if len(rows) > top_n:
        out.append(f"- … and {len(rows) - top_n} more")
    out.append("</details>")
    return out


def build_summary_markdown(result: ReviewResult,
                           top_n: int = MAX_MARKDOWN_FINDINGS) -> str:
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
    engine_label = _ENGINE_TITLE.get(engine, engine)

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
        f"| **Review Engine** | `{result.model or engine}` · {engine_label}"
        f"{_engine_note(engine)} ({result.duration_ms} ms) |",
    ]
    lines.extend(_risk_row(result))
    lines.extend(_verification_row(result))
    
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
        lines.extend(_resolved_list_md(result, top_n))
    if result.suppressed:
        # Truthful since D3/D4's fix: cap-overflow findings are genuinely in
        # this report (counts + JSON) — only the inline annotation was skipped.
        lines.append(f"\n> ℹ️ {result.suppressed} finding(s) over the inline-comment cap "
                     f"are included in this report instead of annotated inline.")
    fb_count = (getattr(result, "feedback_report_fields", None) or {}).get("suppressed_count")
    if fb_count:
        lines.append(f"\n> ℹ️ {fb_count} finding(s) matched a human-created suppression "
                     f"rule and are listed as muted in the report.")
    if getattr(result, "below_threshold", None):
        lines.append(f"\n> ℹ️ {len(result.below_threshold)} finding(s) below the severity "
                     f"threshold are listed under `below_threshold` in the report "
                     f"and are not counted as issues.")
    if result.warnings:
        # V4-E08-T04: bounded, single-line, redacted, markdown-inert.
        safe = [markdown_safe_inline(w) for w in sanitize_warnings(result.warnings)]
        lines.append("\n> ⚠️ Warnings: " + "; ".join(safe))
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


# ============================================================ sticky summary
# V4-E10-T02. Everything below is NEW and self-contained: it does not touch
# build_summary_markdown / finalize_report / any other path above, so other
# epics can keep extending those without a merge conflict here.
#
# Security contract (same posture as prompt assembly, because GitHub renders
# this text straight to people):
#   * the renderer takes the finalized, already-redacted report *dict* and
#     only reads closed-vocabulary and numeric fields as trusted;
#   * the only untrusted text it ever emits is finding titles and file paths,
#     and those appear ONLY inside one dynamic-length code fence, one line each,
#     after redaction, control/bidi stripping, truncation and neutralising of
#     HTML-comment syntax - so nothing in them can render as markdown, HTML,
#     a link, a mention, or a marker;
#   * the model-written ``summary`` and the free-text ``warnings`` are NOT
#     echoed at all (warnings are shown as a count).

#: Open findings listed in the sticky summary (the rest are counted).
STICKY_MAX_FINDINGS = 5
#: Per-line budget for untrusted text inside the fence.
STICKY_MAX_LINE_CHARS = 140
#: Hard ceiling for the whole body (far below GitHub's own comment limit).
STICKY_MAX_BODY_CHARS = 6000

_STICKY_SEVERITIES = ("critical", "high", "medium", "low", "info")
_STICKY_STATES = ("new", "active", "resolved", "reopened", "dismissed", "muted")


def _sticky_int(value, default: int = 0, ceiling: int = 1_000_000) -> int:
    if isinstance(value, bool):
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(n, ceiling))


def _sticky_clean(value, limit: int = STICKY_MAX_LINE_CHARS) -> str:
    """One safe line of untrusted text (redact -> strip -> truncate -> defuse)."""
    import re

    from .security import redact_secrets

    text = redact_secrets(str(value if value is not None else ""))
    # control chars (incl. newlines) and bidi / zero-width characters that can
    # visually reorder or hide text.
    text = re.sub(r"[\x00-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]+", " ", text)
    text = re.sub(r" {2,}", " ", text).strip()
    if len(text) > limit:
        text = text[: max(0, limit - 1)].rstrip() + "\u2026"
    return text.replace("<!--", "&lt;!--").replace("-->", "--&gt;")


def _sticky_fence(text: str) -> str:
    """A backtick fence strictly longer than any backtick run inside ``text``."""
    import re

    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    return "`" * max(3, longest + 1)


def render_sticky_summary(report: dict) -> str:
    """The sticky PR summary comment body (without its hidden marker).

    ``report`` is ``finalize_report(result)``. Missing or malformed fields
    degrade to neutral defaults; nothing here can raise on odd input. Output
    is deterministic for equal input, so an unchanged review rewrites nothing.
    """
    import re

    report = report if isinstance(report, dict) else {}
    rows = [r for r in (report.get("findings") or []) if isinstance(r, dict)]

    def state_of(row: dict) -> str:
        s = str(row.get("state") or "new").lower()
        return s if s in _STICKY_STATES else "new"

    def sev_of(row: dict) -> str:
        s = str(row.get("severity") or "").lower()
        return s if s in _STICKY_SEVERITIES else "info"

    open_rows = [r for r in rows if state_of(r) not in CLOSED_STATES]
    by_state: dict[str, int] = {}
    for r in rows:
        by_state[state_of(r)] = by_state.get(state_of(r), 0) + 1
    sev_counts = {s: 0 for s in _STICKY_SEVERITIES}
    for r in open_rows:
        sev_counts[sev_of(r)] += 1
    sev_bits = [f"{sev_counts[s]} {s}" for s in _STICKY_SEVERITIES if sev_counts[s]]
    # (kept outside the f-string: Python 3.11 rejects a backslash in an f-string
    # expression part -- see test_no_source_file_puts_a_backslash_in_an_fstring_expression)
    sev_text = " \u00b7 ".join(sev_bits) if sev_bits else "none"

    score = _sticky_int(report.get("health_score"), 100, 100)
    grade = str(report.get("health_grade") or "")
    grade = grade if re.fullmatch(r"[A-F][+-]?", grade) else "?"
    gauge = "\U0001f7e2" if score >= 90 else ("\U0001f7e1" if score >= 70 else "\U0001f534")

    engine = str(report.get("engine") or "")
    engine_label = _ENGINE_TITLE.get(engine, "unknown")
    pr = report.get("pr") if isinstance(report.get("pr"), dict) else {}
    sha = str(pr.get("head_sha") or "")
    sha_row = [f"| **Reviewed commit** | `{sha[:7]}` |"] if re.fullmatch(r"[0-9a-f]{7,40}", sha) else []

    new_n = _sticky_int(report.get("new_findings_count"), by_state.get("new", 0))
    active_n = _sticky_int(report.get("active_findings_count"),
                           by_state.get("active", 0) + by_state.get("reopened", 0))
    resolved_n = _sticky_int(report.get("resolved_findings_count"), by_state.get("resolved", 0))
    suppressed = _sticky_int(report.get("suppressed"))
    below = _sticky_int(report.get("below_threshold_count"))
    warn_n = len(report.get("warnings") or []) if isinstance(report.get("warnings"), list) else 0

    lines = [
        f"## \U0001f916 AI PR Review \u00b7 {gauge} **{score}/100** ({grade})",
        "",
        "| \U0001f4ca Metric | Value |",
        "|---|---|",
        f"| **Open findings** | {len(open_rows)} ({sev_text}) |",
        f"| **New \u00b7 Active \u00b7 Resolved** | {new_n} \u00b7 {active_n} \u00b7 {resolved_n} |",
        f"| **Review engine** | {engine_label} |",
        *sha_row,
    ]
    if suppressed:
        lines.append(f"| **Over the inline-comment cap** | {suppressed} |")
    if below:
        lines.append(f"| **Below the severity threshold** | {below} |")
    if warn_n:
        lines.append(f"| **Warnings** | {warn_n} (see the report artifact) |")

    ranked = sorted(open_rows, key=lambda r: -SEVERITY_ORDER.get(sev_of(r), 0))
    shown = ranked[:STICKY_MAX_FINDINGS]
    if shown:
        fenced_lines = []
        for r in shown:
            line = r.get("line")
            where = _sticky_clean(r.get("file"), 80)
            if isinstance(line, int) and not isinstance(line, bool) and line > 0:
                where += f":{line}"
            fenced_lines.append(
                f"[{sev_of(r).upper()}] {where} \u2014 {_sticky_clean(r.get('title'))}")
        block = "\n".join(fenced_lines)
        fence = _sticky_fence(block)
        lines += [
            "",
            f"**Top open findings ({len(shown)} of {len(open_rows)})** \u2014 the text "
            "below comes from the pull request and the model; it is shown as data "
            "and is never an instruction:",
            "",
            f"{fence}text",
            block,
            fence,
        ]
    lines += [
        "",
        "<sub>One summary per pull request, updated in place on every review. "
        "Generated by AI PR Reviewer \u2014 it only comments; it never approves "
        "or merges.</sub>",
    ]
    body = "\n".join(lines)
    return body if len(body) <= STICKY_MAX_BODY_CHARS else body[:STICKY_MAX_BODY_CHARS].rstrip()
