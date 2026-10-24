"""Shared pytest fixtures.

Two jobs:

* put the repository root on ``sys.path`` before any test module is
  imported, so ``import ai_pr_reviewer`` / ``import demo`` work no matter
  which file pytest happens to load first;
* build the demo PR-diff fixtures ONCE per session into a pytest temp
  directory. ``demo/samples/*.diff`` is committed reference data — a test
  run must never rewrite it (on Windows a regeneration flips the files
  between LF and CRLF and leaves the worktree dirty), so the suite always
  generates into ``tmp_path_factory`` instead of into the repo.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from demo.make_fixtures import build_all  # noqa: E402  (needs ROOT on sys.path)


@pytest.fixture(scope="session")
def fixtures(tmp_path_factory: pytest.TempPathFactory) -> dict:
    """``{fixture_name: {..., "diff": <generated .diff path>}}``.

    Session-scoped: generating them shells out to ``git`` in temp dirs,
    which is far too slow to repeat per test module.
    """
    out_dir = tmp_path_factory.mktemp("pr_fixtures")
    return {fx["name"]: fx for fx in build_all(out_dir=out_dir)}


@pytest.fixture(autouse=True)
def _fresh_github_ownership_ledger():
    """V4-E10 keeps ONE process-global ownership ledger (one review per
    process in production). Tests must not inherit an engine identity another
    test learned, or fail-closed behaviour becomes order-dependent."""
    from ai_pr_reviewer.github_sync import reset_process_ledger
    reset_process_ledger()
    yield
