"""V4.6-E02 — failure correlation (ADR-020, deterministic evidence).

T01: configured-source CI failure ingestion — the extraction ladders,
fail-closed window labels, refuse-to-truncate identity fields, redaction
at the ingest boundary, caps as labeled degradations, absent
configuration is zero surface, read-only module (AST-enforced).

Fixtures are deterministic synthetic CI files; hostile cases pin labeled
warnings, never exceptions and never content echo.
"""
from __future__ import annotations

import ast
import json
import sys
from dataclasses import FrozenInstanceError, fields
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import ci_correlation as cc            # noqa: E402
from ai_pr_reviewer.ci_correlation import (DEFAULT_SOURCES_FILE,  # noqa: E402
                                           CONFIDENCE_HIGH,
                                           CONFIDENCE_LOW,
                                           CONFIDENCE_MEDIUM,
                                           CONFIDENCE_UNKNOWN,
                                           GROUND_INDEX_EDGE,
                                           GROUND_NOT_ASSESSABLE,
                                           GROUND_PATH_CONVENTION,
                                           GROUND_WINDOW_ONLY,
                                           MAX_FAILURES,
                                           MAX_FAILURES_PER_RUN,
                                           MAX_IDENTITY_CHARS,
                                           MAX_RAW_CHARS,
                                           MAX_RUN_ID_CHARS, MAX_RUNS,
                                           RELATION_NEW, RELATION_PERSISTENT,
                                           RELATION_RESOLVED,
                                           UNKNOWN_ERROR_CLASS,
                                           CorrelatedFailure,
                                           FailureRecord, FailureSignature,
                                           WindowComparison,
                                           compare_windows,
                                           correlate, extract_test_id,
                                           ingest_failures,
                                           normalize_error_class)
from ai_pr_reviewer.test_intel import (TestEvidence, TestLink,  # noqa: E402
                                       TestTaxonomy,
                                       observed_test_evidence)

MODULE_PATH = ROOT / "ai_pr_reviewer" / "ci_correlation.py"

FAKE_TOKEN = "ghp_" + "Abcdefghijklmnopqrstuvwxyz012345"


@pytest.fixture(autouse=True)
def _clean_ci_env(monkeypatch):
    monkeypatch.delenv("CI_SOURCES_FILE", raising=False)


def _write(root, payload, name: str = DEFAULT_SOURCES_FILE) -> None:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (root / name).write_text(text, encoding="utf-8")


def _run(run_id: str, window="post", failures=(), **extra) -> dict:
    run = {"run_id": run_id, "window": window,
           "failures": list(failures)}
    run.update(extra)
    return run


# ---------------------------------------------------- extraction ladders

@pytest.mark.parametrize(("raw", "expected"), [
    pytest.param("FAILED tests/test_a.py::test_x - AssertionError",
                 "tests/test_a.py::test_x", id="pysel"),
    pytest.param("ERROR tests/test_p.py::test_x[param=1]",
                 "tests/test_p.py::test_x[param=1]", id="pysel-param"),
    pytest.param("tests.test_auth.AuthTests.test_login ran fine",
                 "tests.test_auth.AuthTests.test_login", id="dotted"),
    pytest.param("failed in test_checkout_flow",
                 "test_checkout_flow", id="bare"),
    pytest.param("connection reset by peer", None, id="unidentifiable"),
    pytest.param("", None, id="empty"),
    pytest.param("at mod.test_alpha then tests/t.py::test_beta",
                 "tests/t.py::test_beta", id="rung1-before-rung2"),
])
def test_test_id_extraction_ladder(tmp_path, raw, expected):
    _write(tmp_path, {"runs": [_run("r1", failures=[{"raw": raw}])]})
    records, warnings = ingest_failures(str(tmp_path))
    if expected is None:
        # unidentifiable failures are dropped — no record, no warning:
        # there is simply nothing anyone can claim about them
        assert records == ()
    else:
        assert len(records) == 1
        assert records[0].signature.test_id == expected
    assert warnings == ()


def test_ladder_run_gaps_are_none_not_guesses():
    assert extract_test_id("") is None
    assert extract_test_id("network unreachable") is None
    assert extract_test_id(None) is None     # type: ignore[arg-type]


def test_structured_test_id_wins_and_empty_falls_back(tmp_path):
    _write(tmp_path, {"runs": [_run("r1", failures=[
        {"test_id": "structured/id test_one",
         "raw": "FAILED tests/t.py::test_raw"},
        {"test_id": "", "raw": "FAILED tests/t.py::test_fallback"},
    ])]})
    records, _ = ingest_failures(str(tmp_path))
    assert [r.signature.test_id for r in records] == [
        "structured/id test_one", "tests/t.py::test_fallback"]


@pytest.mark.parametrize(("value", "expected"), [
    pytest.param("AssertionError", "AssertionError", id="simple"),
    pytest.param("unittest.case.Failure", "Failure", id="dotted"),
    pytest.param("ValueError: bad thing", "ValueError", id="message"),
    pytest.param("first OSError then ValueError", "ValueError",
                 id="last-wins"),
    pytest.param("The suite Failed", "Failed", id="bare-failed"),
    pytest.param("AssertionFailedError", "AssertionFailedError",
                 id="compound"),
    pytest.param("nothing classlike here", "unknown", id="none"),
    pytest.param("lowercase assertionerror", "unknown", id="case"),
    pytest.param("", "unknown", id="empty"),
    pytest.param(None, "unknown", id="null"),
    pytest.param(42, "unknown", id="int"),
])
def test_error_class_ladder(value, expected):
    assert normalize_error_class(value) == expected


def test_unknown_is_the_honest_default_and_never_upgrades():
    assert UNKNOWN_ERROR_CLASS == "unknown"
    assert FailureSignature(test_id="t", suite="").error_class == "unknown"


def test_error_class_falls_back_to_the_records_own_text(tmp_path):
    _write(tmp_path, {"runs": [_run("r1", failures=[
        {"test_id": "tests/t.py::test_a",
         "raw": "FAILED tests/t.py::test_a - ValueError: boom"},
        {"test_id": "tests/t.py::test_b", "error_class": "boom",
         "raw": "FAILED tests/t.py::test_b - OSError: disk"},
        {"test_id": "tests/t.py::test_c", "error_class": "OSError",
         "raw": "FAILED tests/t.py::test_c - ValueError"},
    ])]})
    records, _ = ingest_failures(str(tmp_path))
    assert [r.signature.error_class for r in records] == [
        "ValueError", "OSError", "OSError"]     # structured wins when valid


# ------------------------------------------------- window/run fail-closed

def test_missing_window_key_is_refused(tmp_path):
    run = {"run_id": "r1",
           "failures": [{"test_id": "tests/t.py::test_a"}]}
    _write(tmp_path, {"runs": [run]})
    records, warnings = ingest_failures(str(tmp_path))
    assert records == ()
    assert warnings == ("run skipped (missing or invalid window label): "
                        "r1",)


@pytest.mark.parametrize(("window", "accepted"), [
    pytest.param("pre", True, id="pre"),
    pytest.param("post", True, id="post"),
    pytest.param(" PRE ", True, id="case-padded"),
    pytest.param("POST", True, id="upper"),
    pytest.param("changelog", False, id="invalid"),
    pytest.param("", False, id="empty"),
    pytest.param(None, False, id="null"),
    pytest.param(7, False, id="int"),
    pytest.param(["pre"], False, id="list"),
    pytest.param("pre/post", False, id="combo"),
])
def test_window_labels_are_fail_closed(tmp_path, window, accepted):
    _write(tmp_path, {"runs": [_run(
        "r1", window=window,
        failures=[{"test_id": "tests/t.py::test_a"}])]})
    records, warnings = ingest_failures(str(tmp_path))
    if accepted:
        assert len(records) == 1
        assert records[0].window == window.strip().lower()
        assert warnings == ()
    else:
        # never a default, never inferred from position: skip + label
        assert records == ()
        assert len(warnings) == 1
        assert "missing or invalid window label" in warnings[0]


def test_missing_run_id_is_refused(tmp_path):
    _write(tmp_path, {"runs": [{"window": "post",
                                "failures": [{"test_id": "t"}]}]})
    records, warnings = ingest_failures(str(tmp_path))
    assert records == ()
    assert warnings == ("run skipped (missing run_id)",)


def test_over_long_run_id_is_refused_normal_kept(tmp_path):
    _write(tmp_path, {"runs": [
        _run("x" * (MAX_RUN_ID_CHARS + 1),
             failures=[{"test_id": "tests/t.py::test_a"}]),
        _run("x" * MAX_RUN_ID_CHARS,
             failures=[{"test_id": "tests/t.py::test_b"}]),
    ]})
    records, warnings = ingest_failures(str(tmp_path))
    assert [r.run_id for r in records] == ["x" * MAX_RUN_ID_CHARS]
    assert warnings == ("run skipped (over-long run_id)",)


# ------------------------------------------ identity: refuse-to-truncate

def test_identity_fields_refuse_to_truncate(tmp_path):
    long_id = "t" * (MAX_IDENTITY_CHARS + 1)
    keep_id = "t" * MAX_IDENTITY_CHARS
    long_suite = "s" * (MAX_IDENTITY_CHARS + 1)
    keep_suite = "s" * MAX_IDENTITY_CHARS
    _write(tmp_path, {"runs": [_run("r1", failures=[
        {"test_id": long_id, "suite": "unit"},        # dropped
        {"test_id": keep_id, "suite": "unit"},        # kept verbatim
        {"test_id": "tests/t.py::test_y", "suite": long_suite},   # dropped
        {"test_id": "tests/t.py::test_z", "suite": keep_suite},   # kept
    ])]})
    records, warnings = ingest_failures(str(tmp_path))
    assert [r.signature.test_id for r in records] == [
        keep_id, "tests/t.py::test_z"]
    assert records[1].signature.suite == keep_suite   # never mangled
    assert warnings == ()


def test_over_long_extracted_test_id_is_dropped(tmp_path):
    raw = "x.py::" + "y" * (MAX_IDENTITY_CHARS + 1)
    _write(tmp_path, {"runs": [_run("r1", failures=[{"raw": raw}])]})
    records, warnings = ingest_failures(str(tmp_path))
    assert records == () and warnings == ()


# ------------------------------------------- raw bounds + redaction order

def test_raw_truncates_after_redaction_never_cut_in_half():
    assert len(cc._clean("y" * 4_000, MAX_RAW_CHARS)) == MAX_RAW_CHARS
    straddling = "y" * 1_990 + " " + FAKE_TOKEN      # straddles the bound
    out = cc._clean(straddling, MAX_RAW_CHARS)
    # redaction runs BEFORE the cut: a half token would still contain
    # the "ghp_" prefix and leak the rest of the credential later
    assert FAKE_TOKEN not in out
    assert "ghp_" not in out


def test_extraction_runs_over_the_bounded_text(tmp_path):
    late = "y" * 2_100 + " tests/t.py::test_late"
    _write(tmp_path, {"runs": [_run("r1", failures=[{"raw": late}])]})
    records, warnings = ingest_failures(str(tmp_path))
    assert records == () and warnings == ()          # past the bound: gone

    early = "y" * 100 + " tests/t.py::test_early"
    _write(tmp_path, {"runs": [_run("r1", failures=[{"raw": early}])]})
    records, _ = ingest_failures(str(tmp_path))
    assert [r.signature.test_id for r in records] == ["tests/t.py::test_early"]


# ------------------------------------------------------------ caps + dedup

def test_run_cap_bounds_ingestion(tmp_path):
    runs = [_run(f"r{i}", failures=[{"test_id": f"tests/t.py::test_{i}"}])
            for i in range(MAX_RUNS + 5)]
    _write(tmp_path, {"runs": runs})
    records, warnings = ingest_failures(str(tmp_path))
    assert len(records) == MAX_RUNS
    assert any(f"run cap ({MAX_RUNS}) reached" in w for w in warnings)


def test_per_run_failure_cap(tmp_path):
    failures = [{"test_id": f"tests/t.py::test_{i}"}
                for i in range(MAX_FAILURES_PER_RUN + 10)]
    _write(tmp_path, {"runs": [_run("r1", failures=failures)]})
    records, warnings = ingest_failures(str(tmp_path))
    assert len(records) == MAX_FAILURES_PER_RUN
    assert any(f"failure cap ({MAX_FAILURES_PER_RUN}) reached in run r1"
               in w for w in warnings)


def test_total_failure_cap(tmp_path):
    runs = [_run(f"r{i}", failures=[
        {"test_id": f"tests/t.py::test_{i}_{j}"}
        for j in range(MAX_FAILURES_PER_RUN)]) for i in range(6)]
    _write(tmp_path, {"runs": runs})
    records, warnings = ingest_failures(str(tmp_path))
    assert len(records) == MAX_FAILURES
    assert any(f"failure cap ({MAX_FAILURES}) reached" in w
               for w in warnings)


def test_within_run_duplicates_keep_first_across_runs_keep_both(tmp_path):
    _write(tmp_path, {"runs": [
        _run("r1", failures=[
            {"test_id": "tests/t.py::test_a", "error_class": "OSError"},
            {"test_id": "tests/t.py::test_a", "error_class": "ValueError"},
            {"test_id": "tests/t.py::test_b"}]),
        _run("r2", failures=[
            {"test_id": "tests/t.py::test_a", "error_class": "OSError"}]),
    ]})
    records, warnings = ingest_failures(str(tmp_path))
    assert [(r.run_id, r.signature.test_id, r.signature.error_class)
            for r in records] == [
        ("r1", "tests/t.py::test_a", "OSError"),
        ("r1", "tests/t.py::test_b", "unknown"),
        ("r2", "tests/t.py::test_a", "OSError")]
    assert warnings == ()


# ------------------------------------------------- degradation + zero-surface

@pytest.mark.parametrize("payload", [
    pytest.param('{"runs": "x"}', id="string"),
    pytest.param("[1, 2]", id="top-list"),
    pytest.param('"str"', id="top-str"),
    pytest.param('{"other": []}', id="absent"),
])
def test_payload_without_a_runs_list_warns(tmp_path, payload):
    _write(tmp_path, payload)
    records, warnings = ingest_failures(str(tmp_path))
    assert records == ()
    assert len(warnings) == 1
    assert "has no runs list" in warnings[0]


def test_malformed_entries_degrade_without_exceptions(tmp_path):
    _write(tmp_path, {"runs": [
        42, "not-a-run", None,
        {"run_id": "r1", "window": "post", "failures": {}},
        {"run_id": "r2", "window": "post",
         "failures": [{"raw": "no id anywhere"}]},
        {"run_id": "r3", "window": "post"},   # absent failures = legit empty
    ]})
    records, warnings = ingest_failures(str(tmp_path))
    assert records == ()
    # non-dict entries and unidentifiable failures are silent skips;
    # a wrongly-typed failures field is the one labeled degradation
    assert warnings == ("run has no failures list: r1",)


def test_absent_config_is_zero_surface(tmp_path):
    assert ingest_failures(str(tmp_path)) == ((), ())
    assert ingest_failures(str(tmp_path / "missing-dir")) == ((), ())


def test_env_override_and_filename_parameter(tmp_path, monkeypatch):
    _write(tmp_path, {"runs": [_run("d", failures=[
        {"test_id": "tests/t.py::test_default"}])]})
    _write(tmp_path, {"runs": [_run("c", failures=[
        {"test_id": "tests/t.py::test_custom"}])]},
        name="custom-ci.json")

    records, _ = ingest_failures(str(tmp_path))
    assert [r.run_id for r in records] == ["d"]

    monkeypatch.setenv("CI_SOURCES_FILE", "custom-ci.json")
    records, _ = ingest_failures(str(tmp_path))
    assert [r.run_id for r in records] == ["c"]

    monkeypatch.setenv("CI_SOURCES_FILE", "   ")   # blank -> default
    records, _ = ingest_failures(str(tmp_path))
    assert [r.run_id for r in records] == ["d"]

    monkeypatch.delenv("CI_SOURCES_FILE")
    records, _ = ingest_failures(str(tmp_path),
                                 filename="custom-ci.json")
    assert [r.run_id for r in records] == ["c"]


def test_timestamps_normalize_or_stay_absent(tmp_path):
    _write(tmp_path, {"runs": [
        _run("a", started_at="2026-10-20T09:00:00Z",
             failures=[{"test_id": "tests/t.py::test_ta"}]),
        _run("b", started_at="2026-10-20T09:00:00",
             failures=[{"test_id": "tests/t.py::test_tb"}]),
        _run("c", started_at="2026-10-20T12:30:00+02:00",
             failures=[{"test_id": "tests/t.py::test_tc"}]),
        _run("d", started_at="garbage",
             failures=[{"test_id": "tests/t.py::test_td"}]),
        _run("e", failures=[{"test_id": "tests/t.py::test_te"}]),
    ]})
    records, _ = ingest_failures(str(tmp_path))
    assert {r.run_id: r.started_at for r in records} == {
        "a": "2026-10-20T09:00:00+00:00",
        "b": "2026-10-20T09:00:00+00:00",
        "c": "2026-10-20T10:30:00+00:00",
        "d": "",
        "e": "",
    }


def test_records_are_frozen_and_ingest_is_deterministic(tmp_path):
    _write(tmp_path, {"runs": [_run("r1", failures=[
        {"test_id": "tests/t.py::test_a"}])]})
    first = ingest_failures(str(tmp_path))
    assert first == ingest_failures(str(tmp_path))
    records, warnings = first
    assert warnings == ()
    with pytest.raises(FrozenInstanceError):
        records[0].run_id = "x"          # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        records[0].signature.test_id = "y"   # type: ignore[misc]


# ---------------------------------------------------- security: redaction

def test_leak_corpus_never_survives_records_or_warnings(tmp_path):
    _write(tmp_path, {"runs": [
        _run(f"r1 {FAKE_TOKEN}", window="changelog"),   # warning path
        _run("r2", failures=[
            {"test_id": FAKE_TOKEN, "suite": f"unit {FAKE_TOKEN}"},
            {"test_id": "tests/t.py::test_ok", "suite": "unit",
             "raw": f"FAILED - {FAKE_TOKEN}"}]),
    ]})
    records, warnings = ingest_failures(str(tmp_path))
    blob = "".join(
        f"{r.run_id}|{r.signature.test_id}|{r.signature.suite}|{r.source}"
        for r in records) + "".join(warnings)
    assert FAKE_TOKEN not in blob
    assert "[REDACTED]" in blob                     # redaction happened
    assert len(records) == 2


def test_configured_scrub_layers_on_records_and_warnings(tmp_path):
    secret = "hunter2hunter2"        # matches no redact_secrets pattern
    _write(tmp_path, {"runs": [
        _run(secret, window="changelog"),             # warning path
        _run("r2", failures=[{"test_id": "tests/t.py::test_a",
                              "suite": secret}]),
    ]})
    scrub = lambda t: t.replace(secret, "[REDACTED]")  # noqa: E731
    records, warnings = ingest_failures(str(tmp_path), scrub=scrub)
    assert secret not in records[0].signature.suite
    assert records[0].signature.suite == "[REDACTED]"
    assert secret not in "".join(warnings)
    assert "[REDACTED]" in warnings[0]


# ------------------------------------------------- security: size + paths

def test_file_size_cap_is_a_labeled_refusal(tmp_path):
    big = '{"runs": [], "pad": "' + FAKE_TOKEN + "y" * 300_000 + '"}'
    assert len(big) > cc.MAX_SOURCE_FILE_BYTES
    _write(tmp_path, big)
    records, warnings = ingest_failures(str(tmp_path))
    assert records == ()
    assert len(warnings) == 1
    assert "exceeds size cap" in warnings[0]
    assert FAKE_TOKEN not in warnings[0]            # never read, never echoed


def test_path_escape_is_refused_without_reading(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evil = tmp_path / "evil-ci.json"
    evil.write_text(json.dumps({"runs": [], "token": FAKE_TOKEN}),
                    encoding="utf-8")
    for hostile in ("../evil-ci.json", "sub/../../evil-ci.json"):
        records, warnings = ingest_failures(str(repo), filename=hostile)
        assert records == ()
        assert len(warnings) == 1
        assert "escapes the repository" in warnings[0]
        assert FAKE_TOKEN not in warnings[0]


def test_json_error_warning_does_not_echo_content(tmp_path):
    _write(tmp_path, "{not json and a token " + FAKE_TOKEN)
    records, warnings = ingest_failures(str(tmp_path))
    assert records == ()
    assert len(warnings) == 1
    assert "not valid JSON (JSONDecodeError)" in warnings[0]
    assert FAKE_TOKEN not in warnings[0]


# -------------------------------------------------------- read-only scan

_BANNED_MODULES = {"urllib", "requests", "httpx", "socket", "ssl", "http",
                   "queue", "threading", "multiprocessing", "asyncio",
                   "concurrent", "subprocess"}
# "replace" is deliberately absent: str.replace() is legitimate string
# work (timestamp normalization uses it) and cannot be distinguished
# from Path.replace() by attribute name alone.
_BANNED_CALLS = {"write_text", "write_bytes", "unlink", "rename",
                 "truncate", "mkdir", "rmdir", "touch",
                 "remove", "urlopen", "Popen", "check_call",
                 "check_output"}
_BANNED_NAMES = {"open", "eval", "exec", "compile", "__import__"}


def _violations(source: str) -> list[str]:
    hits: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if name.split(".")[0] in _BANNED_MODULES:
                hits.append(f"import {name}")
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _BANNED_NAMES:
                hits.append(f"call {func.id}")
            elif isinstance(func, ast.Attribute) \
                    and func.attr in _BANNED_CALLS:
                hits.append(f"call {func.attr}")
    return hits


def test_ci_correlation_module_is_read_only():
    assert _violations(MODULE_PATH.read_text(encoding="utf-8")) == []
    # self-check: every shape the contract exists to catch is caught
    for hostile in ("import threading\n", "import urllib.request\n",
                    "from subprocess import run\n", "eval('1')\n",
                    "compile('x', 'f', 'exec')\n", 'p.write_text("x")\n',
                    'urllib.request.urlopen("http://x")\n',
                    'open("f").read()\n'):
        assert _violations(hostile), hostile
    # ...and the legal shapes stay legal
    assert _violations('import json\nfrom pathlib import Path\n'
                       'p.read_text(encoding="utf-8")\n') == []


# ============================================================ V4.6-E02-T02
# Pre/post change-window comparison: pure set algebra over signatures —
# new_in_post / resolved / persistent, deterministic ordering, unique
# signature counts, signature-level (not test-level) honesty, and no
# participation from windows ingestion would have refused.

def _sig(test_id: str, suite: str = "unit",
         error: str = "OSError") -> FailureSignature:
    return FailureSignature(test_id=test_id, suite=suite,
                            error_class=error)


def _rec(signature: FailureSignature, window: str = "post",
         run_id: str = "r") -> FailureRecord:
    return FailureRecord(run_id=run_id, window=window,
                         signature=signature)


def test_three_relations_are_exact_set_algebra():
    a, b, c = _sig("tests/t.py::test_a"), _sig("tests/t.py::test_b"), \
        _sig("tests/t.py::test_c")
    out = compare_windows((
        _rec(a, "pre"), _rec(b, "pre"),      # pre: a, b
        _rec(a, "post"), _rec(c, "post"),    # post: a, c
    ))
    assert out.new_in_post == (c,)
    assert out.resolved == (b,)
    assert out.persistent == (a,)
    assert (out.pre_count, out.post_count) == (2, 2)


def test_same_test_new_error_class_is_resolved_plus_new():
    """Signature-level relations: a changed failure MODE is not
    'persistent' — the old mode stopped, the new one appeared."""
    old = _sig("tests/t.py::test_x", error="OSError")
    new = _sig("tests/t.py::test_x", error="ValueError")
    out = compare_windows([_rec(old, "pre"), _rec(new, "post")])
    assert out.new_in_post == (new,)
    assert out.resolved == (old,)
    assert out.persistent == ()


def test_order_is_sorted_and_duplicates_collapse():
    z, a, m = _sig("tests/t.py::test_z"), _sig("tests/t.py::test_a"), \
        _sig("tests/t.py::test_m")
    records = [_rec(z), _rec(a), _rec(m), _rec(a), _rec(z)]
    out = compare_windows(records)
    assert out.new_in_post == (a, m, z)      # (test_id, suite, class)
    assert out.post_count == 3               # unique, not record count


def test_counts_are_unique_signatures_records_repeat():
    same = _sig("tests/t.py::test_a")
    out = compare_windows([_rec(same, "pre"), _rec(same, "pre"),
                           _rec(same, "post")])
    assert (out.pre_count, out.post_count) == (1, 1)
    assert out.persistent == (same,)


def test_empty_input_and_foreign_windows_do_not_participate():
    assert compare_windows(()) == WindowComparison()
    # ingest refuses non-pre/post runs; a hand-built record with a
    # foreign window changes nothing rather than being guessed into a
    # relation
    foreign = _rec(_sig("tests/t.py::test_f"), window="changelog")
    assert compare_windows([foreign]) == WindowComparison()
    # mixed: only declared windows land in the algebra
    out = compare_windows([foreign, _rec(_sig("t"), "pre"),
                           _rec(_sig("t"), "post")])
    assert out.persistent == (_sig("t"),)
    assert (out.pre_count, out.post_count) == (1, 1)


def test_comparison_is_deterministic_and_frozen():
    records = [_rec(_sig("tests/t.py::test_b"), "pre"),
               _rec(_sig("tests/t.py::test_a"), "post"),
               _rec(_sig("tests/t.py::test_c"), "post")]
    forward = compare_windows(records)
    reverse = compare_windows(list(reversed(records)))
    assert forward == reverse
    with pytest.raises(FrozenInstanceError):
        forward.new_in_post = ()             # type: ignore[misc]


# ============================================================ V4.6-E02-T03
# Confidence model: a closed ladder over named grounds. Code-citing
# grounds (index_edge, path_convention) fire ONLY on real intersections
# with the changed set; window-only/unrelated failures never gain a
# code-citing ground; unknown error class costs exactly one step and
# never upgrades anything. The output schema itself cannot attribute a
# failure to a changed file — the structural half of "no unrelated
# claims" (wording half lands with rendering in T04).

def _tax(*pairs, available=True) -> TestTaxonomy:
    return TestTaxonomy(
        available=available,
        links=tuple(TestLink(test=test, module=module, basis="import",
                             confidence="medium")
                    for test, module in pairs))


def _new(sig: FailureSignature) -> WindowComparison:
    return WindowComparison(new_in_post=(sig,))


def test_index_edge_to_changed_module_is_high():
    sig = _sig("tests/test_payments.py::test_refund")
    out = correlate(
        _new(sig),
        taxonomy=_tax(("tests/test_payments.py", "src/payments.py")),
        changed_paths=["src/payments.py"])
    assert out == (CorrelatedFailure(relation=RELATION_NEW, signature=sig,
                                     confidence=CONFIDENCE_HIGH,
                                     ground=GROUND_INDEX_EDGE),)


def test_edge_to_an_unchanged_module_contributes_nothing():
    """An index edge that misses the changed set must not be dressed up
    as relation: the failure falls to window-only."""
    sig = _sig("tests/test_orders.py::test_total")
    out = correlate(
        _new(sig),
        taxonomy=_tax(("tests/test_orders.py", "src/billing.py")),
        changed_paths=["src/inventory.py"])
    assert out[0].confidence == CONFIDENCE_LOW
    assert out[0].ground == GROUND_WINDOW_ONLY


def test_path_convention_match_is_medium():
    sig = _sig("tests/test_payments.py::test_refund")
    # convention works with NO index at all...
    out = correlate(_new(sig), changed_paths=["src/payments.py"])
    assert (out[0].confidence, out[0].ground) == (
        CONFIDENCE_MEDIUM, GROUND_PATH_CONVENTION)
    # ...and the test file itself being changed is the same ground
    out = correlate(_new(sig),
                    changed_paths=["tests/test_payments.py"])
    assert (out[0].confidence, out[0].ground) == (
        CONFIDENCE_MEDIUM, GROUND_PATH_CONVENTION)


def test_unavailable_taxonomy_caps_at_medium():
    sig = _sig("tests/test_payments.py::test_refund")
    out = correlate(
        _new(sig),
        taxonomy=_tax(("tests/test_payments.py", "src/payments.py"),
                      available=False),
        changed_paths=["src/payments.py"])
    # the edge exists in the tuple but the index reports unavailable:
    # no edge claims — convention still holds
    assert (out[0].confidence, out[0].ground) == (
        CONFIDENCE_MEDIUM, GROUND_PATH_CONVENTION)


def test_unrelated_failure_is_window_only_and_names_no_file():
    sig = _sig("tests/test_orders.py::test_total")
    out = correlate(_new(sig), changed_paths=["src/inventory.py"])
    assert (out[0].confidence, out[0].ground) == (
        CONFIDENCE_LOW, GROUND_WINDOW_ONLY)
    # structural half of "no unrelated claims": the record vocabulary
    # has no field that could name a changed file
    assert {f.name for f in fields(CorrelatedFailure)} == {
        "relation", "signature", "confidence", "ground"}


@pytest.mark.parametrize(("case", "expected_confidence", "expected_ground"), [
    pytest.param("edge", CONFIDENCE_MEDIUM, GROUND_INDEX_EDGE,
                 id="high-to-medium"),
    pytest.param("stem", CONFIDENCE_LOW, GROUND_PATH_CONVENTION,
                 id="medium-to-low"),
    pytest.param("window", CONFIDENCE_UNKNOWN, GROUND_WINDOW_ONLY,
                 id="low-to-unknown"),
    pytest.param("nopath", CONFIDENCE_UNKNOWN, GROUND_NOT_ASSESSABLE,
                 id="floor"),
])
def test_unknown_error_class_downgrades_exactly_one_step(
        case, expected_confidence, expected_ground):
    if case == "edge":
        sig = _sig("tests/test_payments.py::test_a",
                   error=UNKNOWN_ERROR_CLASS)
        kwargs = {"taxonomy": _tax(("tests/test_payments.py",
                                     "src/payments.py"))}
        changed = ["src/payments.py"]
    elif case == "stem":
        sig = _sig("tests/test_payments.py::test_a",
                   error=UNKNOWN_ERROR_CLASS)
        kwargs = {}
        changed = ["src/payments.py"]
    elif case == "window":
        sig = _sig("tests/test_orders.py::test_a",
                   error=UNKNOWN_ERROR_CLASS)
        kwargs = {}
        changed = ["src/inventory.py"]
    else:
        sig = _sig("tests.test_auth.AuthTests.test_login",
                   error=UNKNOWN_ERROR_CLASS)
        kwargs = {}
        changed = ["src/auth.py"]
    out = correlate(_new(sig), changed_paths=changed, **kwargs)
    assert (out[0].confidence, out[0].ground) == (
        expected_confidence, expected_ground)


def test_known_error_class_is_not_downgraded():
    sig = _sig("tests/test_payments.py::test_a", error="OSError")
    out = correlate(_new(sig), changed_paths=["src/payments.py"])
    assert out[0].confidence == CONFIDENCE_MEDIUM   # no penalty


def test_not_assessable_without_a_path_or_without_a_diff():
    dotted = _sig("tests.test_auth.AuthTests.test_login")
    py = _sig("tests/test_auth.py::test_login")
    out = correlate(_new(dotted),
                    taxonomy=_tax(("tests/test_auth.py", "src/auth.py")),
                    changed_paths=["src/auth.py"])
    # the index maps FILES; a dotted unittest id names none — honest
    # refusal, never a guessed mapping
    assert (out[0].confidence, out[0].ground) == (
        CONFIDENCE_UNKNOWN, GROUND_NOT_ASSESSABLE)

    out = correlate(_new(py), changed_paths=[])
    assert (out[0].confidence, out[0].ground) == (
        CONFIDENCE_UNKNOWN, GROUND_NOT_ASSESSABLE)


def test_correlate_labels_all_relations_in_deterministic_order():
    a, b, c, d = (_sig("tests/t.py::test_a"), _sig("tests/t.py::test_b"),
                  _sig("tests/t.py::test_c"), _sig("tests/t.py::test_d"))
    comparison = compare_windows([
        _rec(a, "pre"), _rec(c, "pre"),          # pre: a, c
        _rec(a, "post"), _rec(b, "post"),        # post: a, b, d
        _rec(d, "post"),
    ])
    out = correlate(comparison, changed_paths=["src/nothing_match.py"])
    assert [f.relation for f in out] == [
        RELATION_NEW, RELATION_NEW,          # new: b, d (sorted)
        RELATION_RESOLVED,                   # c
        RELATION_PERSISTENT,                 # a
    ]
    assert [f.signature for f in out] == [b, d, c, a]
    # determinism: same inputs, same output — including argument order
    assert correlate(comparison, changed_paths=["src/nothing_match.py"]) \
        == out
    # no diff: nothing to relate to, everything not-assessable
    assert correlate(comparison) == correlate(
        comparison, changed_paths=[])
    assert all(f.confidence == CONFIDENCE_UNKNOWN for f in
               correlate(comparison, changed_paths=[]))


def test_correlate_tolerates_hostile_changed_path_shapes():
    sig = _sig("tests/test_payments.py::test_a")
    out = correlate(_new(sig), changed_paths=["./src/payments.py", 42,
                                              None, "src\\payments.py"])
    assert out[0].confidence == CONFIDENCE_MEDIUM   # normalized + filtered


def test_correlated_failure_is_frozen():
    out = correlate(_new(_sig("tests/t.py::test_a")),
                    changed_paths=["src/x.py"])
    with pytest.raises(FrozenInstanceError):
        out[0].confidence = "high"            # type: ignore[misc]


# ============================================================ V4.6-E02-T04
# Surfacing: wording pinned to observed relations only (no unrelated
# claims, no causal claims), evidence-or-dropped + the tev1/T2 seam, the
# report section's shape/caps/re-scrub, and the opt-in wiring (plain-env
# flag default OFF, orchestrator hook, reporter key absent when the
# feature did not run).

from ai_pr_reviewer import reporter                          # noqa: E402
from ai_pr_reviewer.cli import parse_args                    # noqa: E402
from ai_pr_reviewer.config import load_config                # noqa: E402
from ai_pr_reviewer.diff_parser import FileDiff              # noqa: E402
from ai_pr_reviewer.models import PRContext, ReviewResult     # noqa: E402
from ai_pr_reviewer.verification import (                    # noqa: E402
    observed_test_evidence_confirms)
from ai_pr_reviewer.ci_correlation import (CORRELATION_RULE_ID,  # noqa: E402
                                           MAX_CORRELATION_FINDINGS,
                                           MAX_REPORT_ROWS_PER_RELATION,
                                           NOOP, CorrelationOutcome,
                                           correlation_findings,
                                           correlations_section,
                                           run_failure_correlation)


def _fd(path: str) -> FileDiff:
    return FileDiff(old_path=path, new_path=path)


def _item(sig: FailureSignature, relation=RELATION_NEW,
          confidence=CONFIDENCE_LOW,
          ground=GROUND_WINDOW_ONLY) -> CorrelatedFailure:
    return CorrelatedFailure(relation=relation, signature=sig,
                             confidence=confidence, ground=ground)


def _render(correlated, *, records=(), files=(), taxonomy=None, scrub=None):
    return correlation_findings(correlated, records=records, files=files,
                                taxonomy=taxonomy, scrub=scrub)


def _blob(findings) -> str:
    """Every human-readable surface a reviewer would see, concatenated."""
    return "|".join(
        f.title + f.explanation
        + "".join(ev.summary for ev in f.evidence)
        for f in findings)


# ------------------------------------------- wording: no unrelated claims

def test_unrelated_wording_never_names_a_changed_file():
    """Window-only and not-assessable findings must not contain ANY
    changed path: the placement anchor is never dressed as a claim."""
    unrelated = _sig("tests/test_orders.py::test_total")
    dotted = _sig("tests.test_auth.AuthTests.test_login")
    comparison = WindowComparison(new_in_post=(unrelated, dotted))
    correlated = correlate(comparison, changed_paths=["src/inventory.py"])
    out = _render(correlated,
                  records=(_rec(unrelated, "post", "r1"),
                           _rec(dotted, "post", "r1")),
                  files=[_fd("src/inventory.py")])
    assert len(out) == 2
    blob = _blob(out)
    assert "src/inventory.py" not in blob
    assert "inventory" not in blob
    assert "no changed file is implicated" in blob       # window_only
    assert "no changed file can be related" in blob      # not_assessable
    assert "never a causal claim" in blob
    # anchors exist (an info row must live somewhere) but are placement
    # only -- the wording above is what the reviewer can claim
    assert {f.file for f in out} == {"src/inventory.py"}


def test_code_citing_wording_names_only_the_proven_match():
    sig = _sig("tests/test_payments.py::test_refund")
    taxonomy = _tax(("tests/test_payments.py", "src/payments.py"))
    # index edge: names the module the INDEX tied to this test
    correlated = correlate(_new(sig), taxonomy=taxonomy,
                           changed_paths=["src/payments.py"])
    (edge_f,) = _render(correlated, records=(_rec(sig, "post", "r1"),),
                        files=[_fd("src/payments.py")], taxonomy=taxonomy)
    assert "the test-to-source index maps tests/test_payments.py" \
        in edge_f.explanation
    assert "which this change modifies" in edge_f.explanation
    assert edge_f.file == "src/payments.py"     # anchor = the proven match
    # path convention (no index at all): names the conventionally matched
    # changed file, never a third file
    (conv_f,) = _render(
        correlate(_new(sig), changed_paths=["src/payments.py", "src/zzz.py"]),
        records=(_rec(sig, "post", "r1"),),
        files=[_fd("src/payments.py"), _fd("src/zzz.py")])
    assert "follows the naming convention of changed file src/payments.py" \
        in conv_f.explanation
    assert "src/zzz.py" not in _blob((conv_f,))
    # the failing test file itself being changed
    (self_f,) = _render(
        correlate(_new(sig), changed_paths=["tests/test_payments.py"]),
        records=(_rec(sig, "post", "r1"),),
        files=[_fd("tests/test_payments.py")])
    assert "is itself modified by this change" in self_f.explanation


def test_resolved_and_persistent_wording_never_claims_causation():
    old = _sig("tests/test_orders.py::test_old")
    gone = _sig("tests/test_orders.py::test_gone")
    comparison = WindowComparison(resolved=(gone,), persistent=(old,))
    correlated = correlate(comparison, changed_paths=["src/inventory.py"])
    records = (_rec(gone, "pre", "r1"), _rec(old, "pre", "r1"),
               _rec(old, "post", "r2"))
    resolved_f, persistent_f = _render(
        correlated, records=records, files=[_fd("src/inventory.py")])
    r_text = (resolved_f.title + resolved_f.explanation).lower()
    assert "absent from post-change window" in resolved_f.title.lower()
    assert "not proof this change fixed it" in r_text
    assert "flaky" in r_text                    # honest alternative causes
    for forbidden in ("caused by", "because of", "this change broke",
                      "regression caused", "fixed by this change",
                      "proves this change"):
        assert forbidden not in r_text
    p_text = persistent_f.title + persistent_f.explanation
    assert "present in both windows" in persistent_f.title
    assert "predates this change" in p_text
    # grounds still never name a changed file for either relation
    assert "inventory" not in r_text and "inventory" not in p_text.lower()


# ------------------------------------------- confidence folding + evidence

@pytest.mark.parametrize(("conf", "expected"), [
    pytest.param(CONFIDENCE_HIGH, "high", id="high"),
    pytest.param(CONFIDENCE_MEDIUM, "medium", id="medium"),
    pytest.param(CONFIDENCE_LOW, "low", id="low"),
    pytest.param(CONFIDENCE_UNKNOWN, "low", id="unknown-folds-down"),
])
def test_confidence_folds_into_the_closed_finding_set(conf, expected):
    unknown = conf == CONFIDENCE_UNKNOWN
    sig = _sig("tests/test_orders.py::test_x",
               error=UNKNOWN_ERROR_CLASS if unknown else "OSError")
    (f,) = _render((_item(sig, confidence=conf),), files=[_fd("src/x.py")])
    assert f.confidence == expected
    assert f.confidence in ("low", "medium", "high")
    # the true label survives in the explanation, and only missing data
    # earns the cap sentence
    assert f"Confidence {conf}." in f.explanation
    assert ("caps confidence" in f.explanation) is unknown


def test_finding_is_info_severity_stamped_and_never_suggests():
    sig = _sig("tests/test_payments.py::test_refund")
    taxonomy = _tax(("tests/test_payments.py", "src/payments.py"))
    correlated = correlate(_new(sig), taxonomy=taxonomy,
                           changed_paths=["src/payments.py"])
    (f,) = _render(correlated, records=(_rec(sig, "post", "ci-4711"),),
                   files=[_fd("src/payments.py")], taxonomy=taxonomy)
    assert f.severity == "info"
    assert f.line is None and f.suggestion is None
    assert f.rule_id == CORRELATION_RULE_ID
    assert f.category == "maintainability"
    assert f.provenance_engine == "static"
    assert f.provenance_model == "ci-correlation-v1"
    assert f.provenance_origin == "rule"
    kinds = [ev.kind for ev in f.evidence]
    assert kinds == ["file_excerpt", "test_result", "rule_ref"]
    assert f.evidence[-1].locator == f"rule:{CORRELATION_RULE_ID}"


def test_test_result_evidence_is_tev1_and_never_confirms():
    """The T2 seam: a correlation's FAILED evidence parses as observed
    tev1, and observed failure evidence never confirms a finding."""
    sig = _sig("tests/test_payments.py::test_refund")
    taxonomy = _tax(("tests/test_payments.py", "src/payments.py"))
    correlated = correlate(_new(sig), taxonomy=taxonomy,
                           changed_paths=["src/payments.py"])
    (f,) = _render(correlated, records=(_rec(sig, "post", "ci-4711"),),
                   files=[_fd("src/payments.py")], taxonomy=taxonomy)
    (rec,) = [ev for ev in f.evidence if ev.kind == "test_result"]
    ev = TestEvidence.from_record(rec)
    assert ev is not None                    # canonical tev1 round-trip
    assert ev.outcome == "failed" and ev.origin == "ci_ingest"
    assert ev.test_path == "tests/test_payments.py"
    assert ev.test_name == "test_refund"
    assert ev.run_ref == "ci-4711"
    assert ev.covers == ("src/payments.py",)  # index edges only
    assert [e.test_path for e in observed_test_evidence(f.evidence)] == \
        ["tests/test_payments.py"]
    assert observed_test_evidence_confirms(f) is False


def test_covers_never_come_from_stem_guesses():
    sig = _sig("tests/test_payments.py::test_refund")
    # path-convention ground (stem match), NO index: covers must stay empty
    (f,) = _render(correlate(_new(sig), changed_paths=["src/payments.py"]),
                   records=(_rec(sig, "post", "r1"),),
                   files=[_fd("src/payments.py")])
    (rec,) = [ev for ev in f.evidence if ev.kind == "test_result"]
    ev = TestEvidence.from_record(rec)
    assert ev is not None and ev.covers == ()
    assert "covers=" not in rec.summary


def test_over_long_identities_fall_back_to_a_plain_record():
    long_file = "tests/" + "t" * 130 + ".py"      # > tev1's path bound
    sig = _sig(f"{long_file}::test_x")
    (f,) = _render((_item(sig),), files=[_fd("src/x.py")])
    (rec,) = [ev for ev in f.evidence if ev.kind == "test_result"]
    assert TestEvidence.from_record(rec) is None  # not tev1...
    assert rec.check_type == "ci_failure.v1"      # ...honest plain fallback
    assert rec.kind == "test_result"


def test_too_long_a_run_id_yields_no_run_ref_never_a_truncated_one():
    sig = _sig("tests/test_orders.py::test_a")
    long_run = "r" * 60                           # > tev1's run_ref bound
    (f,) = _render((_item(sig),), records=(_rec(sig, "post", long_run),),
                   files=[_fd("src/x.py")])
    (rec,) = [ev for ev in f.evidence if ev.kind == "test_result"]
    ev = TestEvidence.from_record(rec)
    assert ev is not None and ev.run_ref is None


def test_evidence_or_dropped_never_half_stamped(monkeypatch):
    sig = _sig("tests/test_payments.py::test_refund")
    taxonomy = _tax(("tests/test_payments.py", "src/payments.py"))
    correlated = correlate(_new(sig), taxonomy=taxonomy,
                           changed_paths=["src/payments.py"])

    def raiser(**kwargs):
        raise ValueError("no evidence today")

    monkeypatch.setattr(cc.EvidenceRecord, "create", raiser)
    out = _render(correlated, records=(_rec(sig, "post", "r1"),),
                  files=[_fd("src/payments.py")], taxonomy=taxonomy)
    assert out == ()


def test_findings_are_capped_in_deterministic_order():
    sigs = tuple(_sig(f"tests/t.py::test_{i:02d}") for i in range(12))
    correlated = correlate(WindowComparison(new_in_post=sigs, post_count=12),
                           changed_paths=["src/x.py"])
    records = tuple(_rec(s, "post", "r") for s in sigs)
    out = _render(correlated, records=records, files=[_fd("src/x.py")])
    assert len(out) == MAX_CORRELATION_FINDINGS
    assert [f.title for f in out] == [
        f"CI failure new in post-change window: tests/t.py::test_{i:02d}"
        for i in range(9)]


# -------------------------------------------------------- report section

def _section(correlated, comparison, scrub=None):
    return correlations_section(comparison, correlated, scrub=scrub)


def test_report_section_shape_determinism_and_json_roundtrip():
    a, b, c = (_sig("tests/t.py::test_a"), _sig("tests/t.py::test_b"),
               _sig("tests/t.py::test_c"))
    comparison = WindowComparison(new_in_post=(a, b), resolved=(c,),
                                  pre_count=2, post_count=3)
    correlated = correlate(comparison, changed_paths=["src/x.py"])
    section = _section(correlated, comparison)
    assert section["pre_count"] == 2 and section["post_count"] == 3
    assert section["new_in_post"]["total"] == 2
    assert [r["test_id"] for r in section["new_in_post"]["rows"]] == [
        "tests/t.py::test_a", "tests/t.py::test_b"]     # sorted, deterministic
    assert section["resolved"]["total"] == 1
    assert section["persistent"] == {"total": 0, "rows": []}
    row = section["new_in_post"]["rows"][0]
    assert set(row) == {"test_id", "suite", "error_class", "confidence",
                        "ground"}
    assert json.loads(json.dumps(section)) == section
    assert _section(correlated, comparison) == section


def test_report_rows_keep_the_true_label_and_state_the_full_total():
    sigs = tuple(_sig(f"tests/t.py::test_{i:02d}") for i in range(25))
    comparison = WindowComparison(new_in_post=sigs, post_count=25)
    correlated = correlate(comparison, changed_paths=["src/x.py"])
    section = _section(correlated, comparison)
    assert section["new_in_post"]["total"] == 25      # totals stay full
    assert len(section["new_in_post"]["rows"]) == MAX_REPORT_ROWS_PER_RELATION
    # unknown survives verbatim here even though Finding folds it to low
    item = _item(_sig("tests/t.py::test_u"), confidence=CONFIDENCE_UNKNOWN,
                 ground=GROUND_NOT_ASSESSABLE)
    section = _section((item,), WindowComparison(new_in_post=(item.signature,),
                                                 post_count=1))
    assert section["new_in_post"]["rows"][0]["confidence"] == "unknown"
    assert section["new_in_post"]["rows"][0]["ground"] == GROUND_NOT_ASSESSABLE


def test_report_rows_are_re_scrubbed_at_the_store_chokepoint():
    secret = "hunter2hunter2"          # matches no redact_secrets pattern
    sig = _sig(f"tests/t.py::test_{secret}")
    item = _item(sig)
    scrub = lambda t: t.replace(secret, "[REDACTED]")  # noqa: E731
    section = _section((item,),
                       WindowComparison(new_in_post=(sig,), post_count=1),
                       scrub=scrub)
    row = section["new_in_post"]["rows"][0]
    assert secret not in row["test_id"]
    assert row["test_id"] == "tests/t.py::test_[REDACTED]"


# -------------------------------------------------- runner + wiring seams

def test_runner_noop_and_warning_only_paths(tmp_path):
    assert run_failure_correlation(repo_root=str(tmp_path),
                                   files=[_fd("a.py")]) == NOOP
    # garbage config: warnings alone, no findings, no section
    _write(tmp_path, "{oops")
    out = run_failure_correlation(repo_root=str(tmp_path), files=[_fd("a.py")])
    assert out.findings == () and out.correlations is None
    assert len(out.warnings) == 1 and "not valid JSON" in out.warnings[0]


def test_runner_without_changed_files_has_no_surface(tmp_path):
    _write(tmp_path, {"runs": [_run("r1", window="post", failures=[
        {"test_id": "tests/t.py::test_a"}])]})
    out = run_failure_correlation(repo_root=str(tmp_path), files=[])
    assert out.findings == () and out.correlations is None
    assert out.warnings == ()


def test_runner_end_to_end_is_deterministic(tmp_path):
    _write(tmp_path, {"runs": [
        _run("r1", window="pre", failures=[
            {"test_id": "tests/test_payments.py::test_old",
             "error_class": "OSError"}]),
        _run("r2", window="post", failures=[
            {"test_id": "tests/test_payments.py::test_new",
             "error_class": "ValueError"},
            {"test_id": "tests/test_payments.py::test_old",
             "error_class": "OSError"}])]})
    files = [_fd("src/payments.py")]
    first = run_failure_correlation(repo_root=str(tmp_path), files=files)
    assert [f.rule_id for f in first.findings] == [CORRELATION_RULE_ID] * 2
    # classified error classes keep the convention ground at medium
    assert {f.confidence for f in first.findings} == {"medium"}
    assert first.correlations["new_in_post"]["total"] == 1
    assert first.correlations["persistent"]["total"] == 1
    assert first == run_failure_correlation(repo_root=str(tmp_path),
                                            files=files)


def test_runner_never_raises(tmp_path, monkeypatch):
    _write(tmp_path, {"runs": [_run("r1", window="post", failures=[
        {"test_id": "tests/t.py::test_a"}])]})

    import ai_pr_reviewer.ci_correlation as module

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(module, "compare_windows", boom)
    out = run_failure_correlation(repo_root=str(tmp_path),
                                  files=[_fd("src/x.py")])
    assert out.findings == () and out.correlations is None
    assert out.warnings == ("failure correlation failed (RuntimeError); "
                            "skipped",)


def test_runner_never_calls_builtin_open(tmp_path, monkeypatch):
    import builtins

    _write(tmp_path, {"runs": [_run("r1", window="post", failures=[
        {"test_id": "tests/t.py::test_a"}])]})
    real_open = builtins.open

    def forbidden(*args, **kwargs):
        raise AssertionError("ci_correlation must not call builtin open()")

    monkeypatch.setattr(builtins, "open", forbidden)
    try:
        out = run_failure_correlation(repo_root=str(tmp_path),
                                      files=[_fd("src/x.py")])
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    assert [f.rule_id for f in out.findings] == [CORRELATION_RULE_ID]


def test_correlation_outcome_is_frozen():
    with pytest.raises(FrozenInstanceError):
        NOOP.warnings = ()                     # type: ignore[misc]


# ------------------------------------------------------------- config flag

def test_ci_correlation_flag_is_plain_env_default_off(monkeypatch):
    monkeypatch.delenv("CI_CORRELATION", raising=False)
    assert load_config(parse_args([])).ci_correlation is False

    monkeypatch.setenv("CI_CORRELATION", "true")
    assert load_config(parse_args([])).ci_correlation is True

    # Deliberately NOT an action input: INPUT_* must not enable it.
    monkeypatch.delenv("CI_CORRELATION", raising=False)
    monkeypatch.setenv("INPUT_CI_CORRELATION", "1")
    assert load_config(parse_args([])).ci_correlation is False

    # And no CLI flag exists.
    with pytest.raises(SystemExit):
        parse_args(["--ci-correlation"])


# ------------------------------------------------------- orchestrator hook

def _shape(result):
    def keyed(findings):
        return [(f.file, f.line, f.title, f.severity, f.rule_id)
                for f in findings]
    return (keyed(result.findings), keyed(result.below_threshold),
            list(result.warnings), result.health_score, result.posted_inline)


def test_hook_is_off_by_default_and_never_runs_the_check(monkeypatch):
    from test_orchestrator import Wired

    def bomb(**kwargs):
        raise AssertionError(
            "failure correlation must not run when the flag is off")

    import ai_pr_reviewer.ci_correlation as module
    monkeypatch.setattr(module, "run_failure_correlation", bomb)
    w = Wired(monkeypatch)
    result = w.run()
    assert not [x for x in result.warnings if "correlation" in x]
    assert not hasattr(result, "correlations")


def test_hook_joins_canned_findings_warnings_and_section(monkeypatch):
    from test_orchestrator import Wired, _finding

    canned_finding = _finding(file="a.py", line=2, title="CI canned",
                              severity="low")     # at Wired's threshold
    canned = CorrelationOutcome(
        findings=(canned_finding,), warnings=("canned ci warning",),
        correlations={"pre_count": 1, "post_count": 2,
                      "new_in_post": {"total": 0, "rows": []},
                      "resolved": {"total": 0, "rows": []},
                      "persistent": {"total": 0, "rows": []}})

    import ai_pr_reviewer.ci_correlation as module
    monkeypatch.setattr(module, "run_failure_correlation", lambda **kw: canned)
    w = Wired(monkeypatch)
    w.cfg.ci_correlation = True
    result = w.run()
    assert "CI canned" in [f.title for f in
                           result.findings + result.below_threshold]
    assert "canned ci warning" in result.warnings
    assert result.correlations["post_count"] == 2
    assert reporter.finalize_report(result)["correlations"] == \
        canned.correlations


def test_absent_config_with_flag_on_is_zero_surface(tmp_path, monkeypatch):
    """Flag ON but no configured CI file: the hook RINS (spied) and the
    review output is identical to the flag-OFF run -- including the
    report, where the correlations key stays ABSENT."""
    from test_orchestrator import Wired

    w_off = Wired(monkeypatch)
    w_off.cfg.repo_root = str(tmp_path)
    reference = w_off.run()

    calls = []
    import ai_pr_reviewer.ci_correlation as module
    real = module.run_failure_correlation

    def spy(**kwargs):
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(module, "run_failure_correlation", spy)
    w_on = Wired(monkeypatch)
    w_on.cfg.ci_correlation = True
    w_on.cfg.repo_root = str(tmp_path)
    result = w_on.run()

    assert len(calls) == 1                       # the hook ran...
    assert not [f for f in result.findings + result.below_threshold
                if f.rule_id == CORRELATION_RULE_ID]   # ...and surfaced nothing
    assert _shape(result) == _shape(reference)
    assert "correlations" not in reporter.finalize_report(result)


def test_hook_end_to_end_surfaces_findings_and_the_report_key(
        tmp_path, monkeypatch):
    from test_orchestrator import Wired

    _write(tmp_path, {"runs": [_run("r1", window="post", failures=[
        {"test_id": "a.py::test_z"}])]})
    w = Wired(monkeypatch)                       # FULL_DIFF: a.py, b.py
    w.cfg.ci_correlation = True
    w.cfg.repo_root = str(tmp_path)
    result = w.run()
    surfaced = [f for f in result.findings + result.below_threshold
                if f.rule_id == CORRELATION_RULE_ID]
    assert len(surfaced) == 1
    f = surfaced[0]
    assert f.file == "a.py"        # the test file itself is in the diff
    assert f.severity == "info"    # info sits below Wired's "low" threshold
    report = reporter.finalize_report(result)
    assert report["correlations"]["post_count"] == 1
    assert report["correlations"]["new_in_post"]["total"] == 1
    assert json.loads(json.dumps(report)) == report

    # flag OFF, same repo: the key disappears entirely (additive contract)
    w2 = Wired(monkeypatch)
    w2.cfg.repo_root = str(tmp_path)
    result2 = w2.run()
    assert "correlations" not in reporter.finalize_report(result2)
    assert not [f for f in result2.findings + result2.below_threshold
                if f.rule_id == CORRELATION_RULE_ID]


# --------------------------------------------------------- reporter seam

def _bare_result() -> ReviewResult:
    pr = PRContext(repo="acme/api", pr_number=7, head_sha="h" * 40)
    return ReviewResult(pr=pr, mode="static", model="static-rules-v1",
                        findings=[])


def test_report_key_is_conditional_and_additive():
    result = _bare_result()
    assert "correlations" not in reporter.finalize_report(result)

    section = {"pre_count": 1, "post_count": 2,
               "new_in_post": {"total": 0, "rows": []},
               "resolved": {"total": 0, "rows": []},
               "persistent": {"total": 0, "rows": []}}
    result.correlations = section
    report = reporter.finalize_report(result)
    assert report["correlations"] == section
    assert json.loads(json.dumps(report)) == report

    # None / empty dict are treated as absent -- no empty-noise block
    result.correlations = None
    assert "correlations" not in reporter.finalize_report(result)
    result.correlations = {}
    assert "correlations" not in reporter.finalize_report(result)
