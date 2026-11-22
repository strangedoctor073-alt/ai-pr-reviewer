"""CLI ecosystem subcommands (V4.10-E04).

Provides specialized developer commands alongside the standard review flow:
- explain: describe rules, severity rationale and remediation guidance (T02)
- query: filter and search findings from local report artifacts (T03)
- eval: trigger evaluation harness checks locally (T01)
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from typing import Sequence

from .security import redact_secrets


def run_explain(argv: Sequence[str]) -> int:
    """Explain a static analysis rule or security pattern (V4.10-E04-T02)."""
    p = argparse.ArgumentParser(
        prog="ai-pr-reviewer explain",
        description="Explain a review rule, severity rationale, and recommended fix.",
    )
    p.add_argument("rule_id", help="Rule identifier to explain (e.g. SEC001, JS001)")
    p.add_argument("--json", action="store_true", help="Output as JSON")
    args = p.parse_args(argv)

    from .static.engine import StaticEngine

    eng = StaticEngine()
    rule = None
    all_rules = list(eng.registry.line_rules) + list(eng.registry.file_rules) + list(eng.registry.diff_rules)
    for r in all_rules:
        if getattr(r, "rule_id", "").upper() == args.rule_id.upper():
            rule = r
            break

    if not rule:
        known = sorted(eng.registry.rule_ids())
        print(f"error: unknown rule {args.rule_id!r}. Known rules: {', '.join(known)}", file=sys.stderr)
        return 1

    if args.json:
        payload = {
            "rule_id": rule.rule_id,
            "title": rule.title,
            "severity": rule.severity,
            "category": rule.category,
            "explanation": rule.explanation,
            "suggestion": getattr(rule, "suggestion", None),
            "languages": list(getattr(rule, "languages", ())),
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(f"## [ai-pr-reviewer] Rule Explanation: {rule.rule_id}")
    print(f"Title:       {rule.title}")
    print(f"Severity:    {rule.severity.upper()}")
    print(f"Category:    {rule.category}")
    langs = ", ".join(getattr(rule, "languages", ())) or "all"
    print(f"Languages:   {langs}")
    print(f"\nExplanation:\n{rule.explanation}")
    sug = getattr(rule, "suggestion", None)
    if sug:
        print(f"\nRecommended Remediation:\n```\n{sug}\n```")
    return 0


def run_query(argv: Sequence[str]) -> int:
    """Filter and query findings from report artifacts (V4.10-E04-T03)."""
    p = argparse.ArgumentParser(
        prog="ai-pr-reviewer query",
        description="Query findings from a review report JSON artifact.",
    )
    p.add_argument("--report", default="review-report.json", help="Path to report JSON (default: review-report.json)")
    p.add_argument("--severity", help="Filter by severity (critical, high, medium, low, info)")
    p.add_argument("--category", help="Filter by category (security, bug, etc.)")
    p.add_argument("--file", help="Filter by file path or glob")
    p.add_argument("--json", action="store_true", help="Output filtered findings as JSON")
    args = p.parse_args(argv)

    if not os.path.isfile(args.report):
        print(f"error: report file not found: {args.report}", file=sys.stderr)
        return 1

    try:
        with open(args.report, "r", encoding="utf-8") as fh:
            report_data = json.load(fh)
    except Exception as exc:
        print(f"error: failed to read report {args.report}: {exc}", file=sys.stderr)
        return 1

    findings = report_data.get("findings") or []
    filtered = []

    for f in findings:
        if args.severity and str(f.get("severity") or "").lower() != args.severity.lower():
            continue
        if args.category and str(f.get("category") or "").lower() != args.category.lower():
            continue
        if args.file:
            path = str(f.get("file") or "")
            if not (fnmatch.fnmatch(path, args.file) or args.file in path):
                continue
        filtered.append(f)

    if args.json:
        print(json.dumps(filtered, indent=2))
        return 0

    print(f"[ai-pr-reviewer query] Found {len(filtered)} matching finding(s) in {args.report}:")
    for f in filtered:
        file_loc = f"{f.get('file')}:{f.get('line')}" if f.get("line") else f.get("file")
        sev = str(f.get("severity", "medium")).upper()
        title = redact_secrets(str(f.get("title", "")))
        print(f"- [{sev}] {file_loc} — {title}")

    return 0


def run_eval(argv: Sequence[str]) -> int:
    """Run evaluation harness checks (V4.10-E04-T01)."""
    from eval.harness.__main__ import main as eval_main

    return eval_main(list(argv))
