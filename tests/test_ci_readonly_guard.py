"""V4.6-E01-T05 — read-only guard: CI ingestion can never write to GitHub.

The guarantee is asserted structurally, not by trusting reviewers:

* a source-level (``ast``) scan of every module in ``ai_pr_reviewer/ci/`` and
  of the rate limiter: no write-capable calls, no HTTP-library imports;
* the only handle ingestion receives (``ReadOnlyGitHub``) exposes exactly
  ``get_json`` and enforces an endpoint allowlist plus a control-verb denylist;
* a full ingestion is driven against (a) a tripwire client that fails the test
  if anything other than ``get_json`` is touched and (b) a real
  ``GitHubClient`` over a transport that fails on any non-GET request.

Plan stop condition (§H.5): "any write endpoint invoked in tests".
"""
from __future__ import annotations

import ast
import functools
import re
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.ci import github_actions as ga
from ai_pr_reviewer.ci.pipeline import collect_ci_pipeline
from ai_pr_reviewer.ci.readonly import (FORBIDDEN_IMPORTS, READ_ENDPOINTS,
                                        WRITE_CALL_NAMES, ReadOnlyGitHub,
                                        ReadOnlyViolation, check_read_path)
from ai_pr_reviewer.github_client import GitHubClient
from ai_pr_reviewer.storage import LocalReviewStorage

CI_DIR = ROOT / "ai_pr_reviewer" / "ci"
GUARDED_FILES = sorted(CI_DIR.glob("*.py")) + [
    ROOT / "ai_pr_reviewer" / "github_ratelimit.py"]
REPO = "acme/payments"
SHA = "d" * 40


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"))


# ------------------------------------------------------------- source-level
@pytest.mark.parametrize("path", GUARDED_FILES, ids=lambda p: p.name)
def test_no_write_capable_calls_in_ci_modules(path):
    offenders = []
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else (
                func.id if isinstance(func, ast.Name) else "")
            if name in WRITE_CALL_NAMES:
                offenders.append(f"{path.name}:{node.lineno}: {name}()")
    assert offenders == []


@pytest.mark.parametrize("path", GUARDED_FILES, ids=lambda p: p.name)
def test_ci_modules_import_no_http_library(path):
    offenders = []
    for node in ast.walk(_tree(path)):
        mods = []
        if isinstance(node, ast.Import):
            mods = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            mods = [node.module or ""]
        for mod in mods:
            if mod.split(".")[0] in FORBIDDEN_IMPORTS:
                offenders.append(f"{path.name}:{node.lineno}: {mod}")
    assert offenders == []


def test_ci_modules_never_reference_control_endpoints():
    verbs = re.compile(r"/(rerun|rerun-failed-jobs|cancel|force-cancel|"
                       r"approve|dispatches|enable|disable)\b")
    offenders = []
    for path in CI_DIR.glob("*.py"):
        if path.name == "readonly.py":       # the denylist itself lives here
            continue
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) \
                    and verbs.search(node.value):
                offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []


def test_ci_modules_never_name_github_write_methods():
    banned = {"post_review", "create_comment", "update_review_comment",
              "list_review_comments"}
    offenders = []
    for path in CI_DIR.glob("*.py"):
        if path.name == "readonly.py":
            continue
        for node in ast.walk(_tree(path)):
            if isinstance(node, ast.Attribute) and node.attr in banned:
                offenders.append(f"{path.name}:{node.lineno}: {node.attr}")
            if isinstance(node, ast.Name) and node.id in banned:
                offenders.append(f"{path.name}:{node.lineno}: {node.id}")
    assert offenders == []


def test_github_client_get_json_only_issues_get_requests():
    """``get_json`` is the one read path CI uses; its body must never reach
    for a write verb on the HTTP client."""
    tree = _tree(ROOT / "ai_pr_reviewer" / "github_client.py")
    method = next(n for cls in ast.walk(tree) if isinstance(cls, ast.ClassDef)
                  and cls.name == "GitHubClient"
                  for n in cls.body
                  if isinstance(n, ast.FunctionDef) and n.name == "get_json")
    verbs = {c.func.attr for c in ast.walk(method)
             if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
             and isinstance(c.func.value, ast.Attribute)
             and c.func.value.attr == "_http"}
    assert verbs == {"get"}


def test_no_queue_or_worker_machinery_in_the_new_modules():
    """Family architecture guard (V4.6 has no queues/workers/brokers)."""
    banned = re.compile(r"\b(queue|worker|celery|threading|asyncio|"
                        r"multiprocessing)\b", re.I)
    offenders = [p.name for p in GUARDED_FILES
                 if banned.search(p.read_text(encoding="utf-8"))]
    assert offenders == []


# --------------------------------------------------------------- the handle
def test_read_only_handle_exposes_get_json_and_nothing_else():
    class Client:
        def get_json(self, path, params=None):
            return {"ok": True}

        def post(self, *a):                                   # pragma: no cover
            raise AssertionError("write reached")

    handle = ReadOnlyGitHub(Client())
    public = {n for n in dir(handle) if not n.startswith("_")}
    assert public == {"get_json"}
    for name in ("post", "patch", "put", "delete", "request", "post_review",
                 "create_comment", "update_review_comment"):
        assert not hasattr(handle, name), name
    with pytest.raises(AttributeError):
        handle.get_json = lambda *a: None
    with pytest.raises(AttributeError):
        handle.post = lambda *a: None


def test_read_only_handle_requires_a_reader():
    with pytest.raises(TypeError):
        ReadOnlyGitHub(object())


@pytest.mark.parametrize("path", [
    f"/repos/{REPO}/actions/runs",
    f"/repos/{REPO}/actions/runs/123",
    f"/repos/{REPO}/actions/runs/123/jobs",
    f"/repos/{REPO}/actions/runs/123/attempts/2/jobs",
    f"/repos/{REPO}/pulls/7/commits",
])
def test_allowlisted_reads_pass(path):
    assert check_read_path(path) == path


@pytest.mark.parametrize("path", [
    f"/repos/{REPO}/actions/runs/123/rerun",
    f"/repos/{REPO}/actions/runs/123/rerun-failed-jobs",
    f"/repos/{REPO}/actions/runs/123/cancel",
    f"/repos/{REPO}/actions/runs/123/force-cancel",
    f"/repos/{REPO}/actions/runs/123/approve",
    f"/repos/{REPO}/actions/runs/123/pending_deployments",
    f"/repos/{REPO}/actions/runs/123/logs",
    f"/repos/{REPO}/actions/workflows/9/dispatches",
    f"/repos/{REPO}/actions/workflows/9/enable",
    f"/repos/{REPO}/actions/artifacts",
    f"/repos/{REPO}/actions/secrets",
    f"/repos/{REPO}/actions/caches",
    f"/repos/{REPO}/issues/1/comments",
    f"/repos/{REPO}/pulls/7/reviews",
    f"/repos/{REPO}/pulls/7/comments",
    f"/repos/{REPO}/check-runs",
    f"/repos/{REPO}/statuses/{SHA}",
    f"/repos/{REPO}/actions/runs/abc/jobs",
    f"/repos/{REPO}/actions/runs/123/jobs/extra",
    "/user", "/orgs/acme/actions/runners", "", "/",
])
def test_everything_else_is_refused(path):
    with pytest.raises(ReadOnlyViolation):
        check_read_path(path)


def test_non_string_path_is_refused():
    with pytest.raises(ReadOnlyViolation):
        check_read_path(None)


def test_the_handle_enforces_the_allowlist_before_delegating():
    calls = []

    class Client:
        def get_json(self, path, params=None):
            calls.append(path)
            return {}

    handle = ReadOnlyGitHub(Client())
    handle.get_json(f"/repos/{REPO}/actions/runs")
    with pytest.raises(ReadOnlyViolation):
        handle.get_json(f"/repos/{REPO}/actions/runs/1/rerun")
    assert calls == [f"/repos/{REPO}/actions/runs"]


def test_every_endpoint_the_adapters_use_is_on_the_allowlist():
    """The adapters' own path templates must all satisfy the allowlist, so a
    template edit that drifts off it fails here, not in production."""
    for path in (f"/repos/{REPO}/actions/runs",
                 f"/repos/{REPO}/actions/runs/99/jobs",
                 f"/repos/{REPO}/pulls/7/commits"):
        assert any(rx.fullmatch(path) for rx in READ_ENDPOINTS)


def test_a_violation_is_never_swallowed_by_degrade_handlers():
    """ReadOnlyViolation subclasses ValueError; the adapters' broad
    degrade-with-label handlers must still let it through."""
    class Evil:
        def get_json(self, path, params=None):
            raise ReadOnlyViolation("simulated bad endpoint")

    with pytest.raises(ReadOnlyViolation):
        ga.ingest_runs_for_commit(Evil(), REPO, SHA)
    with pytest.raises(ReadOnlyViolation):
        ga.fetch_pr_commit_shas(Evil(), REPO, 7)


# ------------------------------------------------------- end-to-end tripwires
RUNS = {"workflow_runs": [
    {"id": 1, "name": "CI", "event": "pull_request", "status": "completed",
     "conclusion": "failure", "head_sha": SHA, "run_attempt": 1,
     "pull_requests": [{"number": 7}],
     "created_at": "2026-10-20T10:00:00Z"}]}
JOBS = {"jobs": [{"id": 5, "name": "unit", "status": "completed",
                  "conclusion": "failure", "steps": [
                      {"name": "pytest", "conclusion": "failure"}]}]}


class TripwireClient:
    """Anything but ``get_json`` fails the test."""

    def __init__(self):
        self.reads: list[str] = []

    def get_json(self, path, params=None):
        self.reads.append(path)
        if path.endswith("/actions/runs"):
            return RUNS
        if path.endswith("/jobs"):
            return JOBS
        if path.endswith("/commits"):
            return [{"sha": SHA}]
        raise AssertionError(f"unexpected read {path}")

    def __getattr__(self, name):
        raise AssertionError(f"ingestion touched client.{name}")


def test_full_pipeline_touches_only_get_json(tmp_path):
    client = TripwireClient()
    out = collect_ci_pipeline(client, repo=REPO, pr_number=7, head_sha=SHA,
                              storage=LocalReviewStorage(tmp_path / "s.db"))
    assert out.pipeline["current_head"]["failing"] == 1
    assert client.reads and all(any(rx.fullmatch(p) for rx in READ_ENDPOINTS)
                                for p in client.reads)


def test_real_client_pipeline_sends_only_get_requests(monkeypatch, tmp_path):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.method == "GET", f"write verb sent: {request.method}"
        path = request.url.path
        if path.endswith("/actions/runs"):
            return httpx.Response(200, json=RUNS)
        if path.endswith("/jobs"):
            return httpx.Response(200, json=JOBS)
        if path.endswith("/commits"):
            return httpx.Response(200, json=[{"sha": SHA}])
        return httpx.Response(404, json={})

    real_client = httpx.Client
    monkeypatch.setattr(httpx, "Client", functools.partial(
        real_client, transport=httpx.MockTransport(handler)))
    gh = GitHubClient(token="t0ken", repo=REPO)
    out = collect_ci_pipeline(gh, repo=REPO, pr_number=7, head_sha=SHA,
                              storage=LocalReviewStorage(tmp_path / "s.db"))
    assert out.pipeline["current_head"]["failing"] == 1
    assert seen and {r.method for r in seen} == {"GET"}
    for request in seen:
        check_read_path(request.url.path)


def test_workflow_permissions_contract_is_unchanged():
    """Ingestion needs only ``actions: read`` and this change touches no
    workflow/Action file; the published no-write-scope invariants hold."""
    for name in ("example-workflow.yml", "action.yml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "checks: write" not in text
        assert "actions: write" not in text
