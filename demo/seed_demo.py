#!/usr/bin/env python3
"""Seed the dashboard with demo reviews: generates the fixture diffs, runs
each one through the REAL review pipeline (mock/heuristic engine, local mode),
and pushes the resulting reports to a running dashboard.

Usage:
    export DASHBOARD_TOKEN=<token printed in the server log on first start>
    python demo/seed_demo.py [--dashboard-url http://localhost:8000]
                             [--dashboard-token <token>]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from demo.make_fixtures import build_all  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dashboard-url", default=os.environ.get(
        "DASHBOARD_URL", "http://localhost:8000"))
    ap.add_argument("--dashboard-token", default=os.environ.get("DASHBOARD_TOKEN", ""))
    args = ap.parse_args()

    # Preflight: server up, and do we have a token that works?
    import httpx
    try:
        health = httpx.get(f"{args.dashboard_url}/api/health", timeout=10).json()
        print(f"dashboard OK (backend: {health['backend']})")
    except Exception as exc:
        print(f"error: dashboard unreachable at {args.dashboard_url}: {exc}")
        return 1
    if not args.dashboard_token:
        print("error: no dashboard token. The token is printed in the server log "
              "on first start (and stored in dashboard/data/settings.json). "
              "Pass --dashboard-token or set DASHBOARD_TOKEN.")
        return 1
    r = httpx.get(f"{args.dashboard_url}/api/config",
                  headers={"X-Dashboard-Token": args.dashboard_token}, timeout=10)
    if r.status_code == 401:
        print("error: token rejected by the dashboard (401). Check the value "
              "printed in the server log.")
        return 1

    fixtures = build_all()
    out_dir = ROOT / "demo" / "out"
    out_dir.mkdir(exist_ok=True)

    rc = 0
    for fx in fixtures:
        output = out_dir / f"{fx['name']}.report.json"
        cmd = [
            sys.executable, "-m", "ai_pr_reviewer",
            "--diff-file", fx["diff"],
            "--repo", fx["repo"], "--pr", str(fx["pr"]),
            "--pr-title", fx["title"], "--pr-author", fx["author"],
            "--pr-branch", fx["branch"],
            "--mock", "--no-comment",
            "--output", str(output),
            "--dashboard-url", args.dashboard_url,
            "--dashboard-token", args.dashboard_token,
        ]
        print(f"\n=== reviewing {fx['repo']}#{fx['pr']} — {fx['title']}")
        proc = subprocess.run(cmd, cwd=ROOT)
        if proc.returncode != 0:
            rc = proc.returncode
    print("\ndone." if rc == 0 else "\nfinished with errors.")
    return rc


if __name__ == "__main__":
    sys.exit(main())
