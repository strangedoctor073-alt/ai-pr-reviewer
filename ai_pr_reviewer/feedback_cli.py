"""V4-E09 — operator CLI for suppression rules (the "CLI" authenticated origin).

    python -m ai_pr_reviewer.feedback_cli rules add --repo owner/name \\
        --fingerprint 0123456789abcdef --ttl-days 14 --reason "known benign"
    python -m ai_pr_reviewer.feedback_cli rules add --repo owner/name \\
        --rule-id SEC-001 --path-glob 'tests/**'
    python -m ai_pr_reviewer.feedback_cli rules list --repo owner/name [--all]
    python -m ai_pr_reviewer.feedback_cli rules disable --repo owner/name --id sup_...
    python -m ai_pr_reviewer.feedback_cli rules disable-all --repo owner/name
    python -m ai_pr_reviewer.feedback_cli effectiveness --repo owner/name

It is a thin HTTP client of the dashboard routes — there is exactly ONE
write implementation (the dashboard's), so the CLI cannot diverge from the
rules the dashboard enforces. It authenticates with ``DASHBOARD_ADMIN_TOKEN``
(read from the environment only, never from argv, so it stays out of shell
history) sent as ``X-Dashboard-Admin-Token`` — a credential the review
Action does not hold.

This module is NOT reachable from the Action's entry point (``cli.py`` /
``__main__``): a test walks the import graph to prove it. As defense in
depth it also refuses to run inside GitHub Actions (``GITHUB_ACTIONS=true``);
that is a tripwire against wiring it into a workflow by accident, not a
security boundary — the boundary is the admin token.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

ADMIN_HEADER = "X-Dashboard-Admin-Token"
ORIGIN_HEADER = "X-Feedback-Origin"


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ai_pr_reviewer.feedback_cli",
                                description=__doc__.split("\n\n")[0])
    p.add_argument("--url", default="", help="dashboard base URL "
                   "(default: $DASHBOARD_URL)")
    sub = p.add_subparsers(dest="cmd", required=True)

    rules = sub.add_parser("rules", help="manage suppression rules")
    rsub = rules.add_subparsers(dest="action", required=True)

    add = rsub.add_parser("add", help="create a rule (expires; default 30d)")
    add.add_argument("--repo", required=True)
    add.add_argument("--fingerprint", default="")
    add.add_argument("--rule-id", default="")
    add.add_argument("--path-glob", default="")
    add.add_argument("--ttl-days", type=int, default=30)
    add.add_argument("--reason", default="")

    lst = rsub.add_parser("list", help="list rules")
    lst.add_argument("--repo", required=True)
    lst.add_argument("--all", action="store_true",
                     help="include expired/disabled rules")

    dis = rsub.add_parser("disable", help="disable one rule")
    dis.add_argument("--repo", required=True)
    dis.add_argument("--id", required=True)

    dall = rsub.add_parser("disable-all", help="disable every rule of a repo")
    dall.add_argument("--repo", required=True)

    eff = sub.add_parser("effectiveness", help="before/after repeat-FP counts")
    eff.add_argument("--repo", required=True)
    return p


def _call(client: Any, method: str, path: str, token: str, body=None, params=None):
    headers = {ADMIN_HEADER: token, ORIGIN_HEADER: "cli"}
    return client.request(method, path, headers=headers, json=body, params=params)


def main(argv: list[str] | None = None, *, client: Any = None,
         env: dict | None = None) -> int:
    env = os.environ if env is None else env
    args = _parser().parse_args(argv)
    if env.get("GITHUB_ACTIONS", "").lower() == "true":
        print("error: the feedback CLI must not run inside GitHub Actions",
              file=sys.stderr)
        return 1
    token = (env.get("DASHBOARD_ADMIN_TOKEN") or "").strip()
    if not token:
        print("error: set DASHBOARD_ADMIN_TOKEN (the dashboard's admin "
              "token) in the environment", file=sys.stderr)
        return 1
    if client is None:
        url = (args.url or env.get("DASHBOARD_URL", "")).rstrip("/")
        if not url:
            print("error: pass --url or set DASHBOARD_URL", file=sys.stderr)
            return 1
        import httpx

        client = httpx.Client(base_url=url, timeout=20)

    base = f"/api/repos/{args.repo}/feedback"
    if args.cmd == "effectiveness":
        resp = _call(client, "GET", f"{base}/effectiveness", token)
    elif args.action == "add":
        body: dict = {"ttl_days": args.ttl_days, "reason": args.reason}
        if args.fingerprint:
            body.update(match_kind="fingerprint", fingerprint=args.fingerprint)
        else:
            body.update(match_kind="rule_path", rule_id=args.rule_id,
                        path_glob=args.path_glob)
        resp = _call(client, "POST", f"{base}/rules", token, body)
    elif args.action == "list":
        resp = _call(client, "GET", f"{base}/rules", token,
                     params={"include_inactive": "1"} if args.all else None)
    elif args.action == "disable":
        resp = _call(client, "POST", f"{base}/rules/{args.id}/disable", token)
    else:
        resp = _call(client, "POST", f"{base}/rules/disable-all", token)

    try:
        payload = resp.json()
    except Exception:  # noqa: BLE001
        payload = {"detail": resp.text[:200]}
    print(json.dumps(payload, indent=2))
    return 0 if resp.status_code < 400 else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
