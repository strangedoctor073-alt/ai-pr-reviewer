#!/usr/bin/env python3
"""Generate realistic buggy PR diffs as real git repos, then export the
unified diffs to demo/samples/*.diff. Used by seed_demo.py and the tests."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent / "samples"

# --------------------------------------------------------------------- repos
PY_BASE = {
    "payments/__init__.py": "",
    "payments/api.py": (
        "from fastapi import FastAPI\n\n"
        "app = FastAPI(title=\"Payments API\")\n\n\n"
        "def get_balance(user_id: int) -> int:\n"
        "    return get_balance_from_db(user_id)\n"
    ),
}

PY_HEAD = {
    "payments/__init__.py": "",
    "payments/api.py": (
        "from fastapi import FastAPI\n\n"
        "app = FastAPI(title=\"Payments API\")\n\n\n"
        "def get_balance(user_id: int) -> int:\n"
        "    try:\n"
        "        return cache_get(user_id) or get_balance_from_db(user_id)\n"
        "    except Exception: pass\n"
        "    return 0\n"
    ),
    "payments/refunds.py": (
        '"""Refund endpoints."""\n'
        "import sqlite3\n\n"
        "from fastapi import APIRouter\n\n"
        "router = APIRouter()\n"
        'DB_PATH = "payments.db"\n'
        "_AUDIT_LOG = []\n\n\n"
        "def record_audit(event, entries=[]):\n"
        "    entries.append(event)\n"
        "    _AUDIT_LOG.extend(entries)\n"
        "    return entries\n\n\n"
        '@router.post("/refunds/{order_id}")\n'
        "def create_refund(order_id: int, amount_cents: int, reason: str):\n"
        "    conn = sqlite3.connect(DB_PATH)\n"
        '    row = conn.execute(f"SELECT * FROM orders WHERE id = {order_id}").fetchone()\n'
        '    print(f"refund requested for order {order_id}")\n'
        "    if not row:\n"
        '        return {"error": "order not found"}\n'
        "    try:\n"
        "        conn.execute(\n"
        "            f\"UPDATE orders SET status = 'refunded' WHERE id = {order_id}\"\n"
        "        )\n"
        "        conn.commit()\n"
        "    except:\n"
        '        return {"error": "refund failed"}\n'
        '    record_audit(f"refund {order_id} amount {amount_cents}")\n'
        '    return {"ok": True, "order_id": order_id}\n'
    ),
}

JS_BASE = {
    "src/checkout.js": (
        "import { api } from './api';\n\n"
        "export async function payNow(order) {\n"
        "  const res = await api.post('/pay', { orderId: order.id });\n"
        "  return res.ok;\n"
        "}\n"
    ),
}

JS_HEAD = {
    "src/checkout.js": (
        "import { api } from './api';\n\n"
        "export async function payNow(order) {\n"
        "  const res = await api.post('/pay', { orderId: order.id });\n"
        "  if (res.status == 'paid') {\n"
        "    renderReceipt(order);\n"
        "  }\n"
        "  return res.ok;\n"
        "}\n\n"
        "export function renderReceipt(order) {\n"
        "  const el = document.getElementById('receipt');\n"
        "  el.innerHTML = `<h2>Thanks, ${order.customerName}!</h2>`;\n"
        "}\n\n"
        "export async function savePaymentMethod(token) {\n"
        "  var retries = 3;\n"
        "  localStorage.setItem('authToken', token);\n"
        "  console.log('saving payment method', token);\n"
        "  while (retries > 0) {\n"
        "    const res = await api.post('/payment-methods', { token });\n"
        "    if (res.ok) return true;\n"
        "    retries--;\n"
        "  }\n"
        "  return false;\n"
        "}\n"
    ),
}

SH_BASE = {
    "deploy.sh": (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n\n"
        "APP_DIR=/srv/app\n\n"
        "echo \"Deploying to $APP_DIR\"\n"
        "mkdir -p \"$APP_DIR\"\n"
    ),
}

SH_HEAD = {
    "deploy.sh": (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n\n"
        "APP_DIR=/srv/app\n"
        "API_KEY=sk-live-4Kd93jsl2mZz8QpwLx1T\n\n"
        "echo \"Deploying to $APP_DIR\"\n"
        "curl -s -H \"Authorization: Bearer $API_KEY\" https://ci.internal/api/deploy\n\n"
        "rm -rf $BUILD_DIR/tmp\n"
        "chmod -R 777 \"$APP_DIR\"\n"
        "mkdir -p \"$APP_DIR\"\n"
    ),
}

FIXTURES = [
    {
        "name": "payments_refunds",
        "repo": "acme/payments",
        "pr": 42,
        "title": "Add refund endpoint + balance cache",
        "author": "dev-maria",
        "branch": "feat/refunds",
        "base": PY_BASE,
        "head": PY_HEAD,
        "base_branch": "main",
        "head_branch": "feat/refunds",
    },
    {
        "name": "frontend_checkout",
        "repo": "webshop/frontend",
        "pr": 57,
        "title": "Checkout: save payment method for faster retries",
        "author": "jules-dev",
        "branch": "feat/save-payment-method",
        "base": JS_BASE,
        "head": JS_HEAD,
        "base_branch": "main",
        "head_branch": "feat/save-payment-method",
    },
    {
        "name": "infra_deploy",
        "repo": "acme/infra",
        "pr": 61,
        "title": "Deploy via CI endpoint, clean old builds",
        "author": "ops-sam",
        "branch": "chore/deploy-ci",
        "base": SH_BASE,
        "head": SH_HEAD,
        "base_branch": "main",
        "head_branch": "chore/deploy-ci",
    },
]


def _git(*args: str, cwd: str) -> None:
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def build_diff(fixture: dict, out_dir: Path = SAMPLES_DIR) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as td:
        _git("init", "-q", "-b", "main", cwd=td)
        _git("config", "user.email", "fixture@example.com", cwd=td)
        _git("config", "user.name", "Fixture", cwd=td)

        for path, content in fixture["base"].items():
            p = Path(td) / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        _git("add", "-A", cwd=td)
        _git("commit", "-q", "-m", "base", cwd=td)

        _git("checkout", "-q", "-b", fixture["head_branch"], cwd=td)
        for path, content in fixture["head"].items():
            p = Path(td) / path
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")
        _git("add", "-A", cwd=td)
        _git("commit", "-q", "-m", fixture["title"], cwd=td)

        diff = subprocess.run(
            ["git", "diff", "main...HEAD"],
            cwd=td, check=True, capture_output=True, text=True,
        ).stdout

    out = out_dir / f"{fixture['name']}.diff"
    out.write_text(diff, encoding="utf-8")
    return out


def build_all() -> list[dict]:
    return [{**fx, "diff": str(build_diff(fx))} for fx in FIXTURES]


if __name__ == "__main__":
    for item in build_all():
        print(f"wrote {item['diff']}  ({item['repo']}#{item['pr']})")
