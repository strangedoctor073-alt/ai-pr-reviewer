"""V3-E06-T01: legacy-facade deprecation (debt D11).

Two guarantees:

1. Importing ``ai_pr_reviewer.analyzer`` / ``ai_pr_reviewer.heuristics``
   (and calling ``get_analyzer``) emits a ``DeprecationWarning`` that
   states the removal version. Checked in subprocesses so a previously
   imported module (cached in ``sys.modules``) can't mask the emission.
2. The corrected docstrings make no claims contradicted by reality:
   ``get_analyzer``/``ClaudeAnalyzer``/``MockAnalyzer`` have no
   production callers (the CLI pipeline runs through
   ``orchestrator`` + ``model_router``), and ``heuristics``' only
   production caller is ``analyzer.StaticAnalyzer``.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

# Import `module` in a clean interpreter with warnings recorded and assert a
# DeprecationWarning naming both the module and the removal version fired.
_IMPORT_SCRIPT = """
import warnings

with warnings.catch_warnings(record=True) as caught:
    warnings.simplefilter("always")
    import {module}

hits = [
    w for w in caught
    if issubclass(w.category, DeprecationWarning) and {needle!r} in str(w.message)
]
assert hits, (
    "no DeprecationWarning mentioning {needle!r} from importing {module}; got: "
    + repr([str(w.message) for w in caught])
)
assert "v4.0.0" in str(hits[0].message), str(hits[0].message)
"""


def _import_warns(module: str, needle: str) -> None:
    script = _IMPORT_SCRIPT.format(module=module, needle=needle)
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    proc = subprocess.run([sys.executable, "-c", script],
                          capture_output=True, text=True, cwd=ROOT, env=env)
    assert proc.returncode == 0, proc.stderr


def test_importing_analyzer_warns_with_the_removal_version():
    _import_warns("ai_pr_reviewer.analyzer", "ai_pr_reviewer.analyzer")


def test_importing_heuristics_warns_with_the_removal_version():
    _import_warns("ai_pr_reviewer.heuristics", "ai_pr_reviewer.heuristics")


def test_get_analyzer_call_is_deprecated_and_still_works():
    from ai_pr_reviewer import analyzer

    with pytest.warns(DeprecationWarning, match="v4.0.0"):
        backend = analyzer.get_analyzer(api_key=None, model="m", mock=True)
    # Behavior unchanged: no key + mock still yields the static backend.
    assert isinstance(backend, analyzer.StaticAnalyzer)


def test_stale_docstring_claims_are_gone():
    """The pre-T01 docstrings asserted things reality contradicts; the
    rewrite must not reintroduce them (T01 acceptance: a grep for
    docstring claims contradicted by reality returns nothing)."""
    analyzer_src = (ROOT / "ai_pr_reviewer" / "analyzer.py").read_text(
        encoding="utf-8")
    heuristics_src = (ROOT / "ai_pr_reviewer" / "heuristics.py").read_text(
        encoding="utf-8")
    cli_src = (ROOT / "ai_pr_reviewer" / "cli.py").read_text(encoding="utf-8")

    # analyzer.py used to claim cli.py still calls get_analyzer / that the
    # orchestrator "hasn't landed yet" / that AnalysisOutcome's move to
    # models.py was pending — all false today.
    for stale in ("used today by", "hasn't landed yet", "until that move lands",
                  "currently just ``cli.py``", "Kept exactly as before"):
        assert stale not in analyzer_src, stale
    # heuristics.py used to claim cli.py calls analyze_with_rules — it does not.
    assert "cli.py" not in heuristics_src
    # cli.py really doesn't reference the dead entry points it was named in.
    assert "get_analyzer" not in cli_src
    assert "heuristics" not in cli_src


def test_dead_entry_points_have_no_production_callers():
    """D11's premise, now verified by scan instead of assertion: nothing in
    the production packages references the deprecated-only symbols."""
    for pkg in ("ai_pr_reviewer", "dashboard"):
        for path in (ROOT / pkg).rglob("*.py"):
            if path.name in ("analyzer.py",):  # the facade defines them
                continue
            src = path.read_text(encoding="utf-8")
            assert "get_analyzer" not in src, path
            assert "MockAnalyzer" not in src, path
