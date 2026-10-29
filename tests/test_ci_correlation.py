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
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_pr_reviewer import ci_correlation as cc            # noqa: E402
from ai_pr_reviewer.ci_correlation import (DEFAULT_SOURCES_FILE,  # noqa: E402
                                           MAX_FAILURES,
                                           MAX_FAILURES_PER_RUN,
                                           MAX_IDENTITY_CHARS,
                                           MAX_RAW_CHARS,
                                           MAX_RUN_ID_CHARS, MAX_RUNS,
                                           UNKNOWN_ERROR_CLASS,
                                           FailureSignature,
                                           extract_test_id,
                                           ingest_failures,
                                           normalize_error_class)

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
