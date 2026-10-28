"""V4.6-E06 — incident intelligence (read-only, opt-in).

T01: configured-source ingestion — allow-listed paths only, bounded
normalization, redaction at the ingest boundary, absent configuration is
zero surface. Fixtures are deterministic synthetic JSON exports; the
hostile cases pin labeled degradations, never exceptions.
"""
from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.incident_intel import (DEFAULT_SOURCES_FILE,  # noqa: E402
                                           MAX_INCIDENTS,
                                           MAX_SOURCE_FILE_BYTES,
                                           IncidentRecord, IncidentSources,
                                           ingest_incidents,
                                           load_sources_config)

MODULE_PATH = ROOT / "ai_pr_reviewer" / "incident_intel.py"

FAKE_TOKEN = "ghp_" + "Abcdefghijklmnopqrstuvwxyz012345"

EXPORT = {
    "incidents": [
        {"id": "INC-42", "title": "Payments outage",
         "summary": f"Retry storm after deploy; token={FAKE_TOKEN}",
         "severity": "SEV2", "occurred_at": "2026-01-15T10:00:00Z",
         "resolved_at": "2026-01-15T12:30:00+02:00",
         "paths": ["src/payments.py", "src/payments.py", 42, None],
         "change_shas": ["A" * 40, "short", "a" * 39],
         "extra_ignored": "x"},
        {"id": "INC-42", "title": "duplicate id, first wins"},
        {"title": "no id — dropped"},
        "not-a-dict",
        {"id": "INC-7", "occurred_at": "not-a-date", "paths": "not-a-list"},
    ]}


def _write_sources(root, *, sources=("incidents/export.json",),
                   retention_days=365, max_incidents=25) -> None:
    (root / "incidents").mkdir(exist_ok=True)
    (root / "incidents" / "export.json").write_text(
        json.dumps(EXPORT), encoding="utf-8")
    (root / DEFAULT_SOURCES_FILE).write_text(
        json.dumps({"retention_days": retention_days,
                    "max_incidents": max_incidents,
                    "sources": list(sources)}), encoding="utf-8")


# ------------------------------------------------------------- config

def test_sources_config_parses_and_absent_is_none(tmp_path):
    _write_sources(tmp_path)
    cfg = load_sources_config(str(tmp_path))
    assert cfg == IncidentSources(retention_days=365, max_incidents=25,
                                  sources=("incidents/export.json",))

    assert load_sources_config(str(tmp_path / "missing")) is None


@pytest.mark.parametrize("payload", ["{not json", "[1, 2]", '"str"', "null"])
def test_malformed_sources_config_is_none(tmp_path, payload):
    (tmp_path / "bad.json").write_text(payload, encoding="utf-8")
    assert load_sources_config(str(tmp_path), filename="bad.json") is None


def test_sources_config_env_override(tmp_path, monkeypatch):
    (tmp_path / "custom.json").write_text(
        json.dumps({"sources": []}), encoding="utf-8")
    monkeypatch.setenv("INCIDENT_SOURCES_FILE", "custom.json")
    cfg = load_sources_config(str(tmp_path))
    assert cfg == IncidentSources()


# ------------------------------------------------------------- ingestion

def test_ingest_normalizes_bounds_and_redacts(tmp_path):
    _write_sources(tmp_path)
    cfg = load_sources_config(str(tmp_path))
    records, warnings = ingest_incidents(repo_root=str(tmp_path),
                                         sources=cfg)
    assert warnings == ()
    # no-id, non-dict and duplicate-id rows are dropped; two survive
    assert [r.incident_id for r in records] == ["INC-42", "INC-7"]
    first = records[0]
    assert isinstance(first, IncidentRecord)
    assert first.title == "Payments outage"
    assert first.severity == "sev2"                    # normalized lower
    assert first.occurred_at == "2026-01-15T10:00:00+00:00"
    assert first.resolved_at == "2026-01-15T10:30:00+00:00"
    # duplicates dropped, non-strings dropped, bounded
    assert first.paths[0] == "src/payments.py"
    assert len(first.paths) == 1
    # SHAs: strict 40-hex only, lowercased, NOT entropy-redacted
    assert first.change_shas == ("a" * 40,)
    assert first.source == "incidents/export.json"
    # the fake credential never survives ingest anywhere
    assert FAKE_TOKEN not in repr(records)
    assert "[REDACTED]" in first.summary
    # unparseable timestamp -> absent, record kept
    assert records[1].occurred_at == ""


def test_ingest_scrub_callback_layers_over_redaction(tmp_path):
    _write_sources(tmp_path)
    cfg = load_sources_config(str(tmp_path))
    records, _ = ingest_incidents(
        repo_root=str(tmp_path), sources=cfg,
        scrub=lambda t: t.replace("Payments", "[SCRUBBED]"))
    assert records[0].title == "[SCRUBBED] outage"


def test_traversal_source_path_is_refused(tmp_path):
    cfg = IncidentSources(sources=("../outside.json",))
    records, warnings = ingest_incidents(repo_root=str(tmp_path),
                                         sources=cfg)
    assert records == ()
    assert warnings == ("incident source path escapes the repository: "
                        "../outside.json",)


def test_unreadable_malformed_and_shaped_sources_warn_labeled(tmp_path):
    (tmp_path / "incidents").mkdir()
    (tmp_path / "incidents" / "broken.json").write_text("{oops",
                                                        encoding="utf-8")
    (tmp_path / "incidents" / "nolist.json").write_text('{"nope": 1}',
                                                        encoding="utf-8")
    cases = {
        "incidents/missing.json": "incident source unreadable: ",
        "incidents/broken.json": "incident source is not valid JSON "
                                 "(JSONDecodeError): ",
        "incidents/nolist.json": "incident source has no incidents list: ",
    }
    for rel, prefix in cases.items():
        records, warnings = ingest_incidents(
            repo_root=str(tmp_path), sources=IncidentSources(sources=(rel,)))
        assert records == ()
        assert len(warnings) == 1
        assert warnings[0].startswith(prefix)
        assert warnings[0].endswith(rel)


def test_oversized_source_file_is_skipped(tmp_path):
    (tmp_path / "incidents").mkdir()
    (tmp_path / "incidents" / "huge.json").write_text(
        "x" * (MAX_SOURCE_FILE_BYTES + 1), encoding="utf-8")
    records, warnings = ingest_incidents(
        repo_root=str(tmp_path),
        sources=IncidentSources(sources=("incidents/huge.json",)))
    assert records == ()
    assert warnings == ("incident source exceeds size cap: "
                        "incidents/huge.json",)


def test_max_incidents_cap_stops_ingestion(tmp_path):
    _write_sources(tmp_path)
    records, warnings = ingest_incidents(
        repo_root=str(tmp_path), sources=IncidentSources(max_incidents=1,
                                                         sources=(
                                                             "incidents/"
                                                             "export.json",)))
    assert len(records) == 1
    assert warnings == ()


def test_empty_sources_is_zero_surface(tmp_path):
    assert ingest_incidents(repo_root=str(tmp_path),
                            sources=IncidentSources()) == ((), ())


def test_config_max_incidents_is_clamped_to_module_cap(tmp_path):
    (tmp_path / DEFAULT_SOURCES_FILE).write_text(
        json.dumps({"max_incidents": 10_000, "sources": []}),
        encoding="utf-8")
    cfg = load_sources_config(str(tmp_path))
    assert cfg.max_incidents == MAX_INCIDENTS


# ----------------------------------------------------- read-only contract

_BANNED_IMPORTS = {"subprocess", "socket", "ssl", "urllib", "httpx",
                   "requests", "aiohttp", "multiprocessing", "ctypes"}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__"}


def _violations(source: str) -> list[str]:
    """Read-only boundary: no network/process access, no dynamic
    execution, no file writes of any kind."""
    tree = ast.parse(source)
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            if name.split(".")[0] in _BANNED_IMPORTS:
                hits.append(f"import {name}")
        if isinstance(node, ast.Call):
            func = node.func
            fname = func.id if isinstance(func, ast.Name) \
                else func.attr if isinstance(func, ast.Attribute) else ""
            # builtins are flagged only as bare-name calls so that
            # ``re.compile`` stays legal.
            if isinstance(func, ast.Name) and func.id in _BANNED_CALLS:
                hits.append(f"call {func.id}()")
            if fname == "open":
                hits.append("call open()")
            if fname in ("write_text", "write_bytes"):
                hits.append(f"call {fname}()")
    return hits


def test_module_is_read_only_and_offline():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert _violations(source) == []
    # the sanctioned read path is present
    assert "path.read_text(" in source

    # self-check
    assert _violations("import httpx\n")
    assert _violations("open('f', 'w')\n")
    assert _violations("import subprocess\nsubprocess.run(['x'])\n")
    assert _violations("eval('1')\n")
    assert not _violations("path.read_text(encoding='utf-8')\n")
    assert not _violations("import re\nre.compile('x')\n")
