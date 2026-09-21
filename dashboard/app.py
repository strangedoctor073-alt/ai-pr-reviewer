"""AI PR Reviewer — web dashboard (hardened prototype).

Storage
  SQLAlchemy (SQLite by default, PostgreSQL via DATABASE_URL); legacy JSON
  files are migrated once and kept only as a zero-dependency fallback.

Security posture (prototype-grade, documented in the README):
  * API token — generated on first start (weak defaults refused), compared in
    constant time, required for every write and for the Action config feed.
  * Rate limiting — per-IP sliding window (reads 240/min, writes 30/min).
  * Payload caps — request bodies > 2 MB rejected; reports capped at 500
    stored findings.
  * Audit log — every write appended to dashboard/data/audit.jsonl.
  * Security headers — CSP, nosniff. (No X-Frame-Options: the dev preview
    embeds cross-origin; add it when you deploy for real.)
  * Reads require the API token by default; set
    DASHBOARD_REQUIRE_TOKEN_FOR_READS=0 only for a local demo (the UI prompts
    for the token).

Run:  uvicorn dashboard.app:app --host 127.0.0.1 --port 8000
Auth: X-Dashboard-Token header (token is printed to the server log on first
      start and persisted in dashboard/data/settings.json).
"""
from __future__ import annotations

import datetime as _dt
import hmac
import json
import os
import re
import secrets
import threading
import time
import uuid
from collections import Counter, defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DASHBOARD_DATA_DIR", str(BASE / "data")))
REPORTS_DIR = DATA_DIR / "reports"
SETTINGS_PATH = DATA_DIR / "settings.json"
AUDIT_PATH = DATA_DIR / "audit.jsonl"

MAX_BODY_BYTES = int(os.environ.get("DASHBOARD_MAX_BODY_BYTES", "2000000"))
MAX_FINDINGS = 500


def _parse_limit(raw: str | None, default: str) -> tuple[int, int]:
    spec = raw or default
    m = re.fullmatch(r"(\d+)\s*/\s*(\d+)", spec.strip())
    if not m:
        return 240, 60
    return max(1, int(m.group(1))), max(1, int(m.group(2)))


READ_LIMIT = _parse_limit(os.environ.get("DASHBOARD_RATE_LIMIT_READ"), "240/60")
WRITE_LIMIT = _parse_limit(os.environ.get("DASHBOARD_RATE_LIMIT_WRITE"), "30/60")
REQUIRE_READS_AUTH = os.environ.get(
    "DASHBOARD_REQUIRE_TOKEN_FOR_READS", "1").lower() in ("1", "true", "yes")
SENSITIVE_EXCLUDE_GLOBS = [
    ".env", ".env.*", "**/.env", "**/.env.*",
    ".npmrc", ".pypirc", "**/.npmrc", "**/.pypirc",
    "*.pem", "**/*.pem", "*.key", "**/*.key",
    "*.p12", "**/*.p12", "*.pfx", "**/*.pfx",
    "*.tfstate", "**/*.tfstate", "*.keystore", "**/*.keystore",
    ".ssh/**", "**/.ssh/**", ".aws/**", "**/.aws/**",
    ".gcp/**", "**/.gcp/**", "secrets/**", "**/secrets/**",
    "credentials/**", "**/credentials/**",
    "service-account*.json", "**/service-account*.json",
]
DEFAULT_EXCLUDE_GLOBS = [
    *SENSITIVE_EXCLUDE_GLOBS,
    "**/package-lock.json", "**/yarn.lock", "**/poetry.lock",
    "**/*.min.js", "**/dist/**", "**/build/**", "**/vendor/**",
    "**/*.snap", "**/__snapshots__/**",
]

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
       "img-src 'self' data:; connect-src 'self'; object-src 'none'; "
       "base-uri 'self'; form-action 'self'")

SETTINGS_KEYS = {
    "severity_threshold": "medium",
    "max_comments": 20,
    "exclude_globs": DEFAULT_EXCLUDE_GLOBS,
    "focus_areas": ["security vulnerabilities", "race conditions", "error handling"],
}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
VALID_SEVERITIES = set(SEV_ORDER)
WEAK_TOKENS = {"demo-token", "token", "secret", "changeme", "test", "admin"}

_STARTED = time.time()
_LOCK = threading.Lock()
_storage = None
_api_token: str | None = None
_token_source = "not-initialized"


# ------------------------------------------------------------------ settings
def _with_sensitive_exclusions(values: object) -> list[str]:
    configured = values if isinstance(values, list) else []
    cleaned = [item.strip() for item in configured
               if isinstance(item, str) and item.strip()]
    return list(dict.fromkeys([*SENSITIVE_EXCLUDE_GLOBS, *cleaned]))[:100]


def load_settings() -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if SETTINGS_PATH.exists():
        try:
            data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        settings = {**SETTINGS_KEYS, **{k: v for k, v in data.items()
                                        if k in SETTINGS_KEYS}}
    else:
        settings = dict(SETTINGS_KEYS)
    settings["exclude_globs"] = _with_sensitive_exclusions(settings["exclude_globs"])
    return settings


def save_settings(new: dict) -> dict:
    merged = {**load_settings(), **{k: v for k, v in new.items()
                                    if k in SETTINGS_KEYS}}
    with _LOCK:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _atomic_write_json(SETTINGS_PATH, {**merged, "api_token": _api_token
                                           or load_token_fallback()})
    return merged


def _atomic_write_json(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def load_token_fallback() -> str:
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        return data.get("api_token", "")
    except Exception:
        return ""


# ------------------------------------------------------------- token bootstrap
def bootstrap_token() -> tuple[str, str]:
    """Resolve the API token. Precedence: env > stored > freshly generated.

    Weak/known-default tokens are refused unless the operator explicitly sets
    DASHBOARD_ALLOW_DEMO_TOKEN=1 — an exposed dashboard must never be
    protected by a guessable default.
    """
    env = os.environ.get("DASHBOARD_TOKEN", "").strip()
    if env:
        if env.lower() in WEAK_TOKENS and os.environ.get(
                "DASHBOARD_ALLOW_DEMO_TOKEN", "").lower() not in ("1", "true"):
            raise RuntimeError(
                "DASHBOARD_TOKEN is set to a well-known default value; refusing "
                "to start. Generate a real secret, or set "
                "DASHBOARD_ALLOW_DEMO_TOKEN=1 for a throwaway local demo.")
        return env, "env DASHBOARD_TOKEN"

    stored = load_token_fallback()
    if stored and stored.lower() not in WEAK_TOKENS:
        return stored, "stored in settings.json"

    allow_weak = os.environ.get("DASHBOARD_ALLOW_DEMO_TOKEN", "").lower() in (
        "1", "true")
    if stored and stored.lower() in WEAK_TOKENS and not allow_weak:
        stored = ""   # previously saved insecure default — rotate it

    token = "demo-token" if allow_weak and stored == "demo-token" \
        else secrets.token_urlsafe(24)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    _atomic_write_json(SETTINGS_PATH, {**load_settings(), "api_token": token})
    print(f"\n[dashboard] ============================================================")
    print(f"[dashboard] Generated dashboard API token (first run):\n")
    print(f"[dashboard]     {token}\n")
    print(f"[dashboard] Persisted in {SETTINGS_PATH}. Treat it as a secret.")
    print(f"[dashboard] =========================================================\n",
          flush=True)
    return token, "generated on first run"


# -------------------------------------------------------------------- helpers
def get_storage():
    global _storage
    if _storage is None:
        from .storage import choose_storage

        with _LOCK:
            if _storage is None:
                _storage = choose_storage(DATA_DIR,
                                          os.environ.get("DATABASE_URL"))
                _storage.init()
    return _storage


def get_token() -> str:
    global _api_token, _token_source
    if _api_token is None:
        _api_token, _token_source = bootstrap_token()
    return _api_token


def _authorized(request: Request) -> bool:
    provided = request.headers.get("X-Dashboard-Token", "")
    return bool(provided) and hmac.compare_digest(provided, get_token())


def _check_token(request: Request) -> None:
    if not _authorized(request):
        _audit(request, "auth_rejected", status=401)
        raise HTTPException(401, "invalid or missing X-Dashboard-Token")


def _check_reads(request: Request) -> None:
    if REQUIRE_READS_AUTH:
        _check_token(request)


def _audit(request: Request, action: str, detail: str = "",
           status: int = 200) -> None:
    entry = {
        "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "ip": request.client.host if request.client else "unknown",
        "method": request.method,
        "path": request.url.path,
        "action": action,
        "detail": detail,
        "status": status,
    }
    try:
        with _LOCK:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with AUDIT_PATH.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def _safe(rid: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9._\-]{1,120}", rid):
        raise HTTPException(400, "invalid report id")
    return rid


def _validated_rules(body: dict) -> dict:
    clean: dict = {}
    if "severity_threshold" in body:
        if body["severity_threshold"] not in VALID_SEVERITIES:
            raise HTTPException(400, "severity_threshold must be one of "
                                     f"{sorted(VALID_SEVERITIES)}")
        clean["severity_threshold"] = body["severity_threshold"]
    if "max_comments" in body:
        try:
            mc = int(body["max_comments"])
        except (TypeError, ValueError):
            raise HTTPException(400, "max_comments must be an integer")
        if not 1 <= mc <= 100:
            raise HTTPException(400, "max_comments must be 1..100")
        clean["max_comments"] = mc
    for key, maxlen, maxitems in (("exclude_globs", 200, 100),
                                  ("focus_areas", 200, 50)):
        if key in body:
            if not isinstance(body[key], list) or not all(
                    isinstance(x, str) for x in body[key]):
                raise HTTPException(400, f"{key} must be a list of strings")
            if len(body[key]) > maxitems or any(len(x) > maxlen
                                                for x in body[key]):
                raise HTTPException(400, f"{key} has too many/too long items")
            values = [x.strip() for x in body[key] if x.strip()]
            clean[key] = (_with_sensitive_exclusions(values)
                          if key == "exclude_globs" else values)
    return clean


class SlidingWindowLimiter:
    """Per-key sliding-window rate limiter (in-memory, per process)."""

    def __init__(self) -> None:
        self._events: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, key: str, limit: int, window_seconds: float) -> bool:
        now = time.monotonic()
        with self._lock:
            q = self._events[key]
            while q and now - q[0] > window_seconds:
                q.popleft()
            if len(q) >= limit:
                return False
            q.append(now)
            return True


limiter = SlidingWindowLimiter()


# ----------------------------------------------------------------------- app
@asynccontextmanager
async def lifespan(_: FastAPI):
    get_storage()
    get_token()
    print(f"[dashboard] storage backend: {get_storage().backend}")
    print(f"[dashboard] token source: {_token_source}")
    print(f"[dashboard] reads require token: {REQUIRE_READS_AUTH}")
    yield


app = FastAPI(title="AI PR Reviewer Dashboard", docs_url=None, redoc_url=None,
              lifespan=lifespan)


@app.middleware("http")
async def _guard(request: Request, call_next):
    ip = request.client.host if request.client else "anon"
    is_read = request.method in ("GET", "HEAD", "OPTIONS")
    limit, window = READ_LIMIT if is_read else WRITE_LIMIT
    if not limiter.check(f"{ip}:{'read' if is_read else 'write'}", limit, window):
        return JSONResponse({"detail": "rate limit exceeded"},
                            status_code=429,
                            headers={"Retry-After": str(window)})
    if not is_read:
        content_length = request.headers.get("content-length", "")
        if content_length.isdigit() and int(content_length) > MAX_BODY_BYTES:
            return JSONResponse({"detail": "payload too large"}, status_code=413)
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    return response


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(BASE / "static" / "index.html")


app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")


# ---------------------------------------------------------------------- health
@app.get("/api/health")
def health():
    return {
        "ok": True,
        "backend": get_storage().backend,
        "reads_require_token": REQUIRE_READS_AUTH,
        "rate_limits": {"read_per_min": READ_LIMIT[0], "write_per_min": WRITE_LIMIT[0]},
        "max_body_bytes": MAX_BODY_BYTES,
        "uptime_seconds": int(time.time() - _STARTED),
    }


# --------------------------------------------------------------------- reports
@app.get("/api/reports")
def list_reports(request: Request, limit: int = 50, offset: int = 0):
    _check_reads(request)
    limit = max(1, min(limit, 200))
    offset = max(0, offset)
    return get_storage().list(limit=limit, offset=offset)


@app.get("/api/reports/{rid}")
def get_report(rid: str, request: Request):
    _check_reads(request)
    payload = get_storage().get(_safe(rid))
    if payload is None:
        raise HTTPException(404, "report not found")
    payload["findings"] = sorted(
        payload.get("findings", []),
        key=lambda f: (SEV_ORDER.get(f.get("severity"), 9), f.get("file", ""),
                       f.get("line") or 0))
    return payload


@app.delete("/api/reports/{rid}")
def delete_report(rid: str, request: Request):
    _check_token(request)
    if not get_storage().delete(_safe(rid)):
        raise HTTPException(404, "report not found")
    _audit(request, "delete_report", rid, 200)
    return {"deleted": rid}


@app.post("/api/reports")
async def push_report(request: Request):
    _check_token(request)
    try:
        report = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON")
    if not isinstance(report, dict):
        raise HTTPException(400, "body must be a JSON object")
    pr = report.get("pr") or {}
    if not isinstance(pr, dict) or not pr.get("repo"):
        raise HTTPException(400, "report.pr.repo is required")
    if len(report.get("findings") or []) > MAX_FINDINGS:
        report["truncated_findings"] = True   # storage keeps the worst 500

    rid = _safe(str(report.get("id") or _auto_id(pr.get("repo", "repo"),
                                                 pr.get("number", 0))))
    report["id"] = rid
    report.setdefault("reviewed_at", "")
    rid = get_storage().upsert(report)
    _audit(request, "push_report", rid, 200)
    return {"id": rid, "ok": True}


def _auto_id(repo: str, number) -> str:
    slug = str(repo).replace("/", "-").lower()[:40]
    stamp = _dt.datetime.now().strftime("%Y%m%d")
    return f"{slug}-pr{number or 0}-{stamp}-{uuid.uuid4().hex[:6]}"


# ----------------------------------------------------------------------- stats
@app.get("/api/stats")
def stats(request: Request):
    _check_reads(request)
    return get_storage().stats()


# -------------------------------------------------------------------- settings
@app.get("/api/settings")
def get_settings(request: Request):
    _check_reads(request)
    return load_settings()


@app.put("/api/settings")
async def put_settings(request: Request):
    _check_token(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be a JSON object")
    clean = _validated_rules(body)
    saved = save_settings(clean)
    _audit(request, "update_settings", ",".join(sorted(clean)), 200)
    return saved


@app.get("/api/config")
def get_config(request: Request):
    """Review rules consumed by the GitHub Action before analyzing."""
    _check_token(request)
    s = load_settings()
    return {
        "severity_threshold": s["severity_threshold"],
        "max_comments": s["max_comments"],
        "exclude_globs": s["exclude_globs"],
        "focus_areas": s["focus_areas"],
    }


# --------------------------------------------------------------- review state
@app.get("/api/reviews/{repo_owner}/{repo_name}/{pr_number}/state")
def get_review_state(repo_owner: str, repo_name: str, pr_number: int, request: Request):
    _check_reads(request)
    repo = f"{repo_owner}/{repo_name}"
    last_sha = get_storage().get_last_reviewed_sha(repo, pr_number)
    return {"repo": repo, "pr_number": pr_number, "last_reviewed_sha": last_sha}


@app.put("/api/reviews/{repo_owner}/{repo_name}/{pr_number}/state")
async def put_review_state(repo_owner: str, repo_name: str, pr_number: int, request: Request):
    _check_token(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be a JSON object")
    repo = f"{repo_owner}/{repo_name}"
    get_storage().set_last_reviewed_sha(
        repo, pr_number, body.get("last_reviewed_sha", ""), body.get("base_sha", "")
    )
    _audit(request, "update_review_state", f"{repo}#{pr_number}", 200)
    return {"ok": True}


@app.get("/api/reviews/{repo_owner}/{repo_name}/{pr_number}/findings")
def get_review_findings(repo_owner: str, repo_name: str, pr_number: int, request: Request):
    _check_reads(request)
    repo = f"{repo_owner}/{repo_name}"
    findings = get_storage().get_previous_findings(repo, pr_number)
    return {"repo": repo, "pr_number": pr_number, "findings": findings}


@app.post("/api/reviews/{repo_owner}/{repo_name}/{pr_number}/findings")
async def post_review_findings(repo_owner: str, repo_name: str, pr_number: int, request: Request):
    _check_token(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be a JSON object")
    repo = f"{repo_owner}/{repo_name}"
    review_id = body.get("review_id") or f"{repo}#{pr_number}"
    findings = body.get("findings", [])
    get_storage().save_findings(review_id, findings)
    _audit(request, "save_findings", f"{repo}#{pr_number}", 200)
    return {"ok": True, "count": len(findings)}


@app.get("/api/repos/{repo_owner}/{repo_name}/memory")
def get_repo_memory_endpoint(repo_owner: str, repo_name: str, request: Request):
    _check_reads(request)
    repo = f"{repo_owner}/{repo_name}"
    paths = request.query_params.getlist("paths") or ["*"]
    notes = get_storage().get_repo_memory(repo, paths)
    return {"repo": repo, "memory": [{"note": n, "path_pattern": "*"} for n in notes]}


@app.post("/api/repos/{repo_owner}/{repo_name}/memory")
async def post_repo_memory_endpoint(repo_owner: str, repo_name: str, request: Request):
    _check_token(request)
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "body must be JSON")
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be a JSON object")
    repo = f"{repo_owner}/{repo_name}"
    pat = body.get("path_pattern", "*")
    note = body.get("note", "")
    get_storage().add_repo_memory(repo, pat, note)
    _audit(request, "add_repo_memory", f"{repo}:{pat}", 200)
    return {"ok": True}

