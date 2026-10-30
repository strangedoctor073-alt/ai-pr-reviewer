"""V4.6-E03 — release intelligence (read-only, opt-in).

T01: configured-source release ingestion — bounded normalization,
redaction at the ingest boundary, refuse-to-truncate tag identity,
fail-closed draft/prerelease flags, validated commit shas, absent
configuration is zero surface, read-only module (AST-enforced).

Fixtures are deterministic synthetic release exports; hostile cases pin
labeled degradations, never exceptions and never content echo.
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

from ai_pr_reviewer import release_intel as ri        # noqa: E402
from ai_pr_reviewer.release_intel import (DEFAULT_SOURCES_FILE,  # noqa: E402
                                          MAX_BODY_CHARS, MAX_NAME_CHARS,
                                          MAX_RELEASES, MAX_TAG_CHARS,
                                          ReleaseRecord, ingest_releases)

MODULE_PATH = ROOT / "ai_pr_reviewer" / "release_intel.py"

FAKE_TOKEN = "ghp_" + "Abcdefghijklmnopqrstuvwxyz012345"
SHA_40 = "0123456789abcdef0123456789abcdef01234567"
SHA_64 = "a" * 64


@pytest.fixture(autouse=True)
def _clean_release_env(monkeypatch):
    monkeypatch.delenv("RELEASE_SOURCES_FILE", raising=False)


def _write(root, payload, name: str = DEFAULT_SOURCES_FILE) -> None:
    text = payload if isinstance(payload, str) else json.dumps(payload)
    (root / name).write_text(text, encoding="utf-8")


def _rel(tag: str = "v1.0.0", **extra) -> dict:
    entry = {"tag": tag}
    entry.update(extra)
    return entry


# ----------------------------------------------------------- normalization

def test_release_fields_normalize_deterministically(tmp_path):
    _write(tmp_path, {"releases": [_rel(
        " v1.2.3 ", name="  1.2.3  ",
        published_at="2026-10-20T09:00:00Z",
        commit_sha=SHA_40.upper(), prerelease=False, draft=False,
        body="Highlights:\n* one\n* two")]})
    records, warnings = ingest_releases(str(tmp_path))
    assert warnings == ()
    (rec,) = records
    assert rec.tag == "v1.2.3"
    assert rec.name == "1.2.3"
    assert rec.published_at == "2026-10-20T09:00:00+00:00"
    assert rec.commit_sha == SHA_40            # lowercased, full sha
    assert rec.prerelease is False and rec.draft is False
    assert rec.body == "Highlights: * one * two"   # single-lined
    assert rec.source == DEFAULT_SOURCES_FILE


def test_timestamps_normalize_or_stay_absent(tmp_path):
    _write(tmp_path, {"releases": [
        _rel("a", published_at="2026-10-20T09:00:00"),
        _rel("b", published_at="2026-10-20T12:30:00+02:00"),
        _rel("c", published_at="garbage"),
        _rel("d"),
    ]})
    records, warnings = ingest_releases(str(tmp_path))
    assert warnings == ()
    assert {r.tag: r.published_at for r in records} == {
        "a": "2026-10-20T09:00:00+00:00",
        "b": "2026-10-20T10:30:00+00:00",
        "c": "",
        "d": "",
    }


@pytest.mark.parametrize(("sha", "expected"), [
    pytest.param(SHA_40, SHA_40, id="full-40"),
    pytest.param(SHA_64, SHA_64, id="full-64"),
    pytest.param(SHA_40.upper(), SHA_40, id="case"),
    pytest.param("0123456789abcdef", "", id="short"),
    pytest.param("g" * 40, "", id="non-hex"),
    pytest.param("sha-" + SHA_40, "", id="prefixed"),
    pytest.param("", "", id="empty"),
    pytest.param(None, "", id="null"),
    pytest.param(42, "", id="int"),
])
def test_commit_shas_are_validated_never_guessed(tmp_path, sha, expected):
    _write(tmp_path, {"releases": [_rel("v1", commit_sha=sha)]})
    records, warnings = ingest_releases(str(tmp_path))
    assert warnings == ()
    assert records[0].commit_sha == expected


# ---------------------------------------- identity + selection-critical

def test_tag_refuses_to_truncate(tmp_path):
    keep = "t" * MAX_TAG_CHARS
    over = "t" * (MAX_TAG_CHARS + 1)
    _write(tmp_path, {"releases": [_rel(over), _rel(keep)]})
    records, warnings = ingest_releases(str(tmp_path))
    assert [r.tag for r in records] == [keep]   # never mangled
    assert warnings == ()                       # silent per-record drop


def test_empty_or_absent_tag_is_dropped(tmp_path):
    _write(tmp_path, {"releases": [
        {"name": "no tag at all"}, _rel(""), _rel("v1")]})
    records, warnings = ingest_releases(str(tmp_path))
    assert [r.tag for r in records] == ["v1"]
    assert warnings == ()


@pytest.mark.parametrize(("flag", "value"), [
    pytest.param("draft", "yes", id="draft-str"),
    pytest.param("draft", 1, id="draft-int"),
    pytest.param("prerelease", [], id="prerelease-list"),
    pytest.param("prerelease", None, id="prerelease-null"),
])
def test_malformed_selection_flags_drop_the_release(tmp_path, flag, value):
    """Fail-closed: a malformed draft/prerelease flag must never coerce
    to False — that could promote a prerelease to "last shipped"."""
    bad = _rel("v2.0.0-rc1", **{flag: value})
    _write(tmp_path, {"releases": [bad, _rel("v1.0.0")]})
    records, warnings = ingest_releases(str(tmp_path))
    assert [r.tag for r in records] == ["v1.0.0"]
    assert len(warnings) == 1
    assert "draft/prerelease flag is not a boolean" in warnings[0]


def test_flags_default_to_false_when_absent(tmp_path):
    _write(tmp_path, {"releases": [_rel("v1")]})
    records, warnings = ingest_releases(str(tmp_path))
    assert warnings == ()
    assert records[0].draft is False and records[0].prerelease is False


def test_prerelease_and_draft_true_survive(tmp_path):
    _write(tmp_path, {"releases": [
        _rel("v2.0.0-rc1", prerelease=True),
        _rel("wip", draft=True)]})
    records, _ = ingest_releases(str(tmp_path))
    assert [(r.tag, r.prerelease, r.draft) for r in records] == [
        ("v2.0.0-rc1", True, False), ("wip", False, True)]


# ------------------------------------------------------------- free text

def test_body_truncates_after_redaction_never_cut_in_half():
    straddling = "y" * (MAX_BODY_CHARS - 10) + " " + FAKE_TOKEN
    out = ri._clean(straddling, MAX_BODY_CHARS)
    assert len(out) <= MAX_BODY_CHARS
    assert FAKE_TOKEN not in out
    assert "ghp_" not in out          # redaction ran BEFORE the cut


def test_name_is_bounded_and_cleaned():
    assert len(ri._clean("n" * 500, MAX_NAME_CHARS)) == MAX_NAME_CHARS
    assert ri._clean("a\x00b\t c", 100) == "a b c"


# --------------------------------------------------------------- caps

def test_release_cap_bounds_ingestion(tmp_path):
    _write(tmp_path, {"releases": [
        _rel(f"v{i}") for i in range(MAX_RELEASES + 5)]})
    records, warnings = ingest_releases(str(tmp_path))
    assert len(records) == MAX_RELEASES
    assert any(f"release cap ({MAX_RELEASES}) reached" in w
               for w in warnings)


# ------------------------------------------------- degradation + zero-surface

@pytest.mark.parametrize("payload", [
    pytest.param('{"releases": "x"}', id="string"),
    pytest.param("[1, 2]", id="top-list"),
    pytest.param('"str"', id="top-str"),
    pytest.param('{"other": []}', id="absent"),
])
def test_payload_without_a_releases_list_warns(tmp_path, payload):
    _write(tmp_path, payload)
    records, warnings = ingest_releases(str(tmp_path))
    assert records == ()
    assert len(warnings) == 1
    assert "has no releases list" in warnings[0]


def test_malformed_entries_degrade_without_exceptions(tmp_path):
    _write(tmp_path, {"releases": [
        42, "not-a-release", None, [],
        _rel("v1"), _rel("v2", extra_keys="ignored")]})
    records, warnings = ingest_releases(str(tmp_path))
    assert [r.tag for r in records] == ["v1", "v2"]
    assert warnings == ()


def test_absent_config_is_zero_surface(tmp_path):
    assert ingest_releases(str(tmp_path)) == ((), ())
    assert ingest_releases(str(tmp_path / "missing-dir")) == ((), ())


def test_env_override_and_filename_parameter(tmp_path, monkeypatch):
    _write(tmp_path, {"releases": [_rel("default")]})
    _write(tmp_path, {"releases": [_rel("custom")]},
           name="custom-releases.json")

    records, _ = ingest_releases(str(tmp_path))
    assert [r.tag for r in records] == ["default"]

    monkeypatch.setenv("RELEASE_SOURCES_FILE", "custom-releases.json")
    records, _ = ingest_releases(str(tmp_path))
    assert [r.tag for r in records] == ["custom"]

    monkeypatch.setenv("RELEASE_SOURCES_FILE", "   ")   # blank -> default
    records, _ = ingest_releases(str(tmp_path))
    assert [r.tag for r in records] == ["default"]

    monkeypatch.delenv("RELEASE_SOURCES_FILE")
    records, _ = ingest_releases(str(tmp_path),
                                 filename="custom-releases.json")
    assert [r.tag for r in records] == ["custom"]


def test_records_are_frozen_and_ingest_is_deterministic(tmp_path):
    _write(tmp_path, {"releases": [_rel("v1", published_at="2026-01-01Z")]})
    first, warnings = ingest_releases(str(tmp_path))
    assert (first, warnings) == ingest_releases(str(tmp_path))
    with pytest.raises(FrozenInstanceError):
        first[0].tag = "x"              # type: ignore[misc]


# ---------------------------------------------------- security: redaction

def test_leak_corpus_never_survives_records_or_warnings(tmp_path):
    _write(tmp_path, {"releases": [
        _rel(f"v1-{FAKE_TOKEN}", name=f"name {FAKE_TOKEN}",
             body=f"body {FAKE_TOKEN}"),
        {"releases": "x", "token": FAKE_TOKEN},
    ] + ["skip-me"]})
    # second entry is a dict without a tag (silent); the payload-level
    # garbage comes from the warnings path below
    records, warnings = ingest_releases(str(tmp_path))
    blob = "".join(
        f"{r.tag}|{r.name}|{r.body}|{r.source}" for r in records) \
        + "".join(warnings)
    assert FAKE_TOKEN not in blob
    assert "[REDACTED]" in blob                     # redaction happened
    assert len(records) == 1


def test_configured_scrub_layers_on_records(tmp_path):
    secret = "hunter2hunter2"        # matches no redact_secrets pattern
    _write(tmp_path, {"releases": [_rel("v1", name=secret, body=secret)]})
    scrub = lambda t: t.replace(secret, "[REDACTED]")  # noqa: E731
    records, _ = ingest_releases(str(tmp_path), scrub=scrub)
    assert records[0].name == "[REDACTED]"
    assert records[0].body == "[REDACTED]"


# ------------------------------------------------- security: size + paths

def test_file_size_cap_is_a_labeled_refusal(tmp_path):
    big = '{"releases": [], "pad": "' + FAKE_TOKEN + "y" * 300_000 + '"}'
    assert len(big) > ri.MAX_SOURCE_FILE_BYTES
    _write(tmp_path, big)
    records, warnings = ingest_releases(str(tmp_path))
    assert records == ()
    assert len(warnings) == 1
    assert "exceeds size cap" in warnings[0]
    assert FAKE_TOKEN not in warnings[0]            # never read, never echoed


def test_path_escape_is_refused_without_reading(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    evil = tmp_path / "evil-releases.json"
    evil.write_text(json.dumps({"releases": [], "token": FAKE_TOKEN}),
                    encoding="utf-8")
    for hostile in ("../evil-releases.json", "sub/../../evil-releases.json"):
        records, warnings = ingest_releases(str(repo), filename=hostile)
        assert records == ()
        assert len(warnings) == 1
        assert "escapes the repository" in warnings[0]
        assert FAKE_TOKEN not in warnings[0]


def test_json_error_warning_does_not_echo_content(tmp_path):
    _write(tmp_path, "{not json and a token " + FAKE_TOKEN)
    records, warnings = ingest_releases(str(tmp_path))
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


def test_release_intel_module_is_read_only():
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


def test_no_builtin_open_at_runtime(tmp_path, monkeypatch):
    """Runtime complement: while a configured ingest runs, any direct
    ``open()`` call is a hard failure (reads go through Path.read_text
    -> io.open, a DIFFERENT binding)."""
    import builtins

    _write(tmp_path, {"releases": [_rel("v1")]})
    real_open = builtins.open

    def forbidden(*args, **kwargs):
        raise AssertionError("release_intel must not call builtin open()")

    monkeypatch.setattr(builtins, "open", forbidden)
    try:
        records, warnings = ingest_releases(str(tmp_path))
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    assert [r.tag for r in records] == ["v1"]
    assert warnings == ()


def test_release_record_is_the_normalized_shape():
    rec = ReleaseRecord(tag="v1")
    assert rec.name == "" and rec.published_at == "" and rec.commit_sha == ""
    assert rec.prerelease is False and rec.draft is False
    assert rec.body == "" and rec.source == ""


# ============================================================ V4.6-E03-T02
# Diff-since-last-release: closed selection rules for "last shipped"
# (drafts/prereleases/unorderable never eligible, ties keep file order)
# and a fail-closed anchor ladder over the history index (sha position,
# then published timestamp, then a labeled refusal) with bounded,
# honest listings.

from ai_pr_reviewer.history.builder import (CommitRecord,  # noqa: E402
                                            HistoryIndex)
from ai_pr_reviewer.release_intel import (BASIS_COMMIT_SHA,  # noqa: E402
                                          BASIS_NOT_ASSESSABLE,
                                          BASIS_PUBLISHED_AT, ReleaseDiff,
                                          select_last_release,
                                          shipped_changes)

from datetime import datetime, timezone                  # noqa: E402

# computed, never guessed: the epoch of the ISO strings used below
EPOCH_0 = int(datetime(2026, 10, 9, 8, 53, 20,
                       tzinfo=timezone.utc).timestamp())


def _commit(sha: str, epoch: int, *paths, subject: str = "do thing",
            **extra) -> CommitRecord:
    return CommitRecord(sha=sha, committed_at=epoch, subject=subject,
                        parent_count=1, paths=tuple(paths), **extra)


def _index(commits=(), window_start: int = 0, state: str = "ok",
           **extra) -> HistoryIndex:
    return HistoryIndex(state=state, window_start=window_start,
                        commits=tuple(commits), **extra)


def _release(tag="v1.0.0", ts="2026-10-20T09:00:00+00:00", sha="", **kw):
    return ReleaseRecord(tag=tag, published_at=ts, commit_sha=sha, **kw)


# ------------------------------------------------------------- selection

def test_select_last_release_is_the_newest_shipped_one():
    old = _release("v1", ts="2026-10-01T00:00:00+00:00")
    new = _release("v2", ts="2026-10-20T00:00:00+00:00")
    draft = _release("wip", ts="2026-10-25T00:00:00+00:00", draft=True)
    pre = _release("v3-rc1", ts="2026-10-24T00:00:00+00:00", prerelease=True)
    assert select_last_release((old, new, draft, pre)) is new


def test_selection_tie_keeps_file_order_and_unorderable_never_wins():
    first = _release("a", ts="2026-10-20T00:00:00+00:00")
    second = _release("b", ts="2026-10-20T00:00:00+00:00")
    no_ts = _release("c", ts="")
    garbage_ts = _release("d", ts="garbage")
    assert select_last_release((first, second, no_ts, garbage_ts)) is first
    # only unorderable shipped releases -> nothing selectable, no guess
    assert select_last_release((no_ts, garbage_ts)) is None
    assert select_last_release(()) is None


def test_selection_ignores_malformed_entries_without_raising():
    assert select_last_release(None) is None     # type: ignore[arg-type]


# ----------------------------------------------------------- the anchor

def test_sha_basis_is_positional_over_the_newest_first_index():
    r_old = _commit("a" * 40, EPOCH_0, "src/x.py")
    r_mid = _commit("b" * 40, EPOCH_0 + 10, "src/y.py", "docs/z.md")
    r_new = _commit("c" * 40, EPOCH_0 + 20, "src/x.py")
    index = _index((r_new, r_mid, r_old), window_start=EPOCH_0 - 100)
    diff = shipped_changes(_release(sha="b" * 40), index)
    assert diff.basis == BASIS_COMMIT_SHA
    assert diff.commits_total == 1    # only r_new is NEWER than the sha
    assert diff.commits == (("c" * 40, "do thing"),)
    assert diff.paths == ("src/x.py",)
    assert diff.partial is False       # sha anchor: the window sees it all
    assert diff.reasons == ()


def test_release_at_the_head_means_nothing_shipped_since():
    head = _commit("c" * 40, EPOCH_0)
    diff = shipped_changes(_release(sha="c" * 40), _index((head,)))
    assert diff.basis == BASIS_COMMIT_SHA
    assert diff.commits == () and diff.commits_total == 0
    assert diff.paths == () and diff.paths_total == 0


def test_unmatched_sha_falls_back_to_the_timestamp_with_a_reason():
    commits = (_commit("c" * 40, EPOCH_0 + 100),
               _commit("d" * 40, EPOCH_0 - 100))
    diff = shipped_changes(_release(ts="2026-10-09T08:53:30+00:00",
                                    sha="e" * 40), _index(commits))
    assert diff.basis == BASIS_PUBLISHED_AT
    assert [sha for sha, _ in diff.commits] == ["c" * 40]
    assert any("outside the history window" in r for r in diff.reasons)


def test_timestamp_basis_is_strictly_after_the_release():
    before = _commit("a" * 40, EPOCH_0)
    same = _commit("b" * 40, EPOCH_0 + 1)          # == release second
    after = _commit("c" * 40, EPOCH_0 + 2)
    index = _index((after, same, before),
                   window_start=EPOCH_0 - 50)
    diff = shipped_changes(_release(ts="2026-10-09T08:53:21+00:00"), index)
    assert diff.basis == BASIS_PUBLISHED_AT
    # strictly AFTER: the commit in the same second as the release is
    # not "shipped after" it
    assert [sha for sha, _ in diff.commits] == ["c" * 40]


def test_neither_anchor_is_a_labeled_refusal_not_a_guess():
    diff = shipped_changes(_release(ts="", sha=""), _index(
        (_commit("c" * 40, EPOCH_0),)))
    assert diff.basis == BASIS_NOT_ASSESSABLE
    assert diff.commits == () and diff.paths == ()
    assert any("neither a sha" in r for r in diff.reasons)


@pytest.mark.parametrize("index", [
    pytest.param(None, id="none"),
    pytest.param(_index((), state="unavailable"), id="unavailable"),
])
def test_absent_history_is_a_labeled_refusal(index):
    diff = shipped_changes(_release(), index)
    assert diff.basis == BASIS_NOT_ASSESSABLE
    assert diff.reasons == ("history index unavailable",)


def test_no_release_at_all_is_an_empty_diff():
    assert shipped_changes(None, _index((_commit("c" * 40, EPOCH_0),))) \
        == ReleaseDiff()


def test_partial_marks_a_window_that_starts_after_the_release():
    index = _index((_commit("c" * 40, EPOCH_0 + 500),),
                   window_start=EPOCH_0 + 100)
    diff = shipped_changes(_release(ts="2026-10-09T08:53:20+00:00"), index)
    assert diff.partial is True
    assert any("provably incomplete" in r for r in diff.reasons)
    # a sha anchor inside the window is never "partial"
    head = _commit("c" * 40, EPOCH_0 + 500)
    diff = shipped_changes(_release(ts="", sha="c" * 40),
                           _index((head,), window_start=EPOCH_0 + 100))
    assert diff.partial is False and diff.basis == BASIS_COMMIT_SHA


def test_listings_are_capped_while_totals_stay_full():
    commits = tuple(_commit(f"{i:040x}", EPOCH_0 + 1 + i, f"p/{i}.py",
                            f"q/{i}.py") for i in range(10))
    index = _index(tuple(reversed(commits)), window_start=EPOCH_0 - 10)
    diff = shipped_changes(_release(ts="2026-10-09T08:53:20+00:00"), index,
                           max_commits=3, max_paths=4)
    assert len(diff.commits) == 3
    assert len(diff.paths) == 4
    assert diff.commits_total == 10
    assert diff.paths_total == 20
    assert diff.truncated is True


def test_scan_cap_bounds_a_hostile_index():
    commits = tuple(_commit(f"{i:040x}", EPOCH_0 + i) for i in range(5_001))
    index = _index(tuple(reversed(commits)), window_start=EPOCH_0 - 10)
    diff = shipped_changes(_release(ts="2026-10-09T08:53:20+00:00"), index)
    assert any("scan cap" in r for r in diff.reasons)
    assert diff.commits_total <= 5_000


def test_diff_is_deterministic_and_frozen():
    index = _index((_commit("c" * 40, EPOCH_0 + 5, "b.py", "a.py"),),
                   window_start=EPOCH_0 - 5)
    release = _release(ts="2026-10-09T08:53:20+00:00")
    first = shipped_changes(release, index)
    assert first == shipped_changes(release, index)
    assert first.paths == ("a.py", "b.py")      # sorted union
    with pytest.raises(FrozenInstanceError):
        first.basis = "x"                      # type: ignore[misc]


def test_merge_and_bulk_commits_count_but_ship_no_paths():
    # the history builder empties paths for merge/bulk/boundary commits;
    # the diff must count the commit without inventing paths for it
    merge = _commit("m" * 40, EPOCH_0 + 5, subject="Merge pull request")
    bulk = _commit("k" * 40, EPOCH_0 + 6, is_bulk=True)
    index = _index((bulk, merge), window_start=EPOCH_0 - 5)
    diff = shipped_changes(_release(ts="2026-10-09T08:53:20+00:00"), index)
    assert diff.commits_total == 2
    assert diff.paths == () and diff.paths_total == 0


# ============================================================ V4.6-E03-T03
# Release risk aggregation: shipped-change findings (prophecy-free
# wording, sha-cited history evidence, evidence-or-dropped), the additive
# report section (full totals, capped rows, re-scrub), and the opt-in
# wiring (plain-env flag default OFF, orchestrator hook, reporter key
# absent when the feature did not run).

from ai_pr_reviewer import reporter                          # noqa: E402
from ai_pr_reviewer.cli import parse_args                    # noqa: E402
from ai_pr_reviewer.config import load_config                # noqa: E402
from ai_pr_reviewer.diff_parser import FileDiff              # noqa: E402
from ai_pr_reviewer.models import PRContext, ReviewResult     # noqa: E402
from ai_pr_reviewer.release_intel import (CITED_SHA_CHARS,     # noqa: E402
                                          MAX_CITED_COMMITS,
                                          MAX_RELEASE_FINDINGS,
                                          MAX_REPORT_FILES,
                                          NOOP, RELEASE_RULE_ID,
                                          ReleaseOutcome,
                                          release_findings,
                                          releases_section,
                                          run_release_context)

# the epoch of the ISO strings used below (computed, never guessed --
# the T01/T02 suites pin the same pairing)
ISO_0 = "2026-10-09T08:53:20+00:00"


def _fd(path: str) -> FileDiff:
    return FileDiff(old_path=path, new_path=path)


def _history_after_release():
    """Newest-first index where a.py and b.py shipped after the release
    (sha anchor ``a*40`` sits at the bottom); c.py never shipped."""
    anchor = _commit("a" * 40, EPOCH_0 - 100, "old.py")
    touch_a = _commit("b" * 40, EPOCH_0, "a.py")
    touch_ab = _commit("c" * 40, EPOCH_0 + 1, "a.py", "b.py")
    return _index((touch_ab, touch_a, anchor), window_start=EPOCH_0 - 500)


# ------------------------------------------- findings: intersection + claims

def test_intersection_names_only_changed_files_that_shipped():
    diff = shipped_changes(_release(sha="a" * 40), _history_after_release())
    out = release_findings(diff, [_fd("a.py"), _fd("c.py"), _fd("b.py")])
    assert [f.file for f in out] == ["a.py", "b.py"]   # diff order; c.py not shipped
    assert all(f.rule_id == RELEASE_RULE_ID for f in out)
    assert all(f.severity == "info" and f.line is None and f.suggestion is None
               for f in out)


def test_wording_is_shipped_history_never_a_prediction():
    diff = shipped_changes(_release(sha="a" * 40), _history_after_release())
    (f,) = release_findings(diff, [_fd("a.py")])
    text = (f.title + " " + f.explanation).lower()
    assert "since release" in text
    # cites the shipped shas -- short form: the redaction chokepoint
    # erases full 40-hex tokens, and it is never weakened (see
    # CITED_SHA_CHARS); the full shas live in path_shas for computation
    assert "c" * 7 in f.explanation
    assert "c" * 40 not in f.explanation
    assert "not a claim about this change" in f.explanation
    for forbidden in ("caused by", "because of", "will ", "would ",
                      "introduces", "risk of", "fixes", "prevents",
                      "regression"):
        assert forbidden not in text


def test_confidence_follows_the_anchor_basis():
    history = _history_after_release()
    (high,) = release_findings(
        shipped_changes(_release(sha="a" * 40), history), [_fd("a.py")])
    assert high.confidence == "high"          # sha position is exact
    (medium,) = release_findings(
        shipped_changes(_release(sha="", ts=ISO_0), history), [_fd("a.py")])
    assert medium.confidence == "medium"      # timestamp is weaker
    assert "anchor: published_at" in medium.explanation


def test_unassessable_diff_never_claims_anything():
    diff = shipped_changes(_release(ts="", sha=""),
                           _index((_commit("c" * 40, EPOCH_0, "a.py"),)))
    assert diff.basis == BASIS_NOT_ASSESSABLE
    assert release_findings(diff, [_fd("a.py")]) == ()


def test_partial_diff_says_so_in_the_finding():
    history = _index((_commit("c" * 40, EPOCH_0 + 500, "a.py"),),
                     window_start=EPOCH_0 + 100)
    (f,) = release_findings(shipped_changes(_release(ts=ISO_0), history),
                            [_fd("a.py")])
    assert "incomplete" in f.explanation


# ------------------------------------- findings: evidence + caps + dropped

def test_evidence_is_history_event_citing_shipped_shas():
    diff = shipped_changes(_release(tag="v9.9.9", sha="a" * 40),
                           _history_after_release())
    (f,) = release_findings(diff, [_fd("a.py")])
    assert [ev.kind for ev in f.evidence] == \
        ["file_excerpt", "history_event", "rule_ref"]
    hist = f.evidence[1]
    assert hist.locator == "release:v9.9.9"
    assert "c" * 7 in hist.summary and "b" * 7 in hist.summary
    assert "c" * 40 not in hist.summary       # full hex is redacted at the chokepoint
    assert all(ev.check_type == "release_intel" for ev in f.evidence)
    assert f.evidence[2].locator == f"rule:{RELEASE_RULE_ID}"
    assert f.provenance_engine == "static"
    assert f.provenance_model == "release-intel-v1"
    assert f.provenance_origin == "rule"
    assert f.confidence in ("low", "medium", "high")


def test_evidence_or_dropped_never_half_stamped(monkeypatch):
    diff = shipped_changes(_release(sha="a" * 40), _history_after_release())

    def raiser(**kwargs):
        raise ValueError("no evidence today")

    monkeypatch.setattr(ri.EvidenceRecord, "create", raiser)
    assert release_findings(diff, [_fd("a.py")]) == ()


def test_findings_are_capped_in_diff_order():
    history = _index(tuple(
        _commit(f"{i:040x}", EPOCH_0 + 10 + i, f"f{i:02d}.py")
        for i in reversed(range(8))), window_start=EPOCH_0 - 10)
    diff = shipped_changes(_release(ts=ISO_0), history)
    out = release_findings(diff, [_fd(f"f{i:02d}.py") for i in range(8)])
    assert len(out) == MAX_RELEASE_FINDINGS
    assert [f.file for f in out] == [f"f{i:02d}.py" for i in range(5)]


def test_path_shas_are_newest_first_and_stay_full():
    history = _index(tuple(
        _commit(f"{i:040x}", EPOCH_0 + 1 + i, "hot.py")
        for i in reversed(range(7))), window_start=EPOCH_0 - 10)
    diff = shipped_changes(_release(ts=ISO_0), history)
    shas = diff.path_shas["hot.py"]
    assert shas[0] == f"{6:040x}"             # newest first
    assert len(shas) == 7                     # full count, uncapped
    # render caps never trim the evidence store
    small = shipped_changes(_release(ts=ISO_0), history,
                            max_paths=1, max_commits=3)
    assert small.path_shas == diff.path_shas
    assert small.truncated is True and small.commits_total == 7


# -------------------------------------------------------- report section

def _big_history():
    """7 commits on hot.py + 30 single-file commits, all shipped."""
    singles = [_commit(f"{i:040x}", EPOCH_0 + 8 + i, f"{i:02d}.py")
               for i in range(30)]
    hots = [_commit(f"{100 + i:040x}", EPOCH_0 + 1 + i, "hot.py")
            for i in range(7)]
    ordered = sorted(singles + hots, key=lambda c: -c.committed_at)
    return _index(tuple(ordered), window_start=EPOCH_0 - 10)


def test_section_shape_totals_caps_and_json_roundtrip():
    release = _release(ts=ISO_0)
    diff = shipped_changes(release, _big_history())
    files = [_fd("hot.py")] + [_fd(f"{i:02d}.py") for i in range(30)]
    section = releases_section(release, diff, files)
    assert section["last_release"] == "v1.0.0"
    assert section["basis"] == "published_at"
    assert section["shipped_commits"] == 37      # full totals
    assert section["shipped_paths"] == 31
    assert section["files_total"] == 31          # full intersection
    assert len(section["files"]) == MAX_REPORT_FILES
    hot_row = section["files"][0]
    assert hot_row["path"] == "hot.py"
    assert hot_row["commits"] == 7               # full per-file count
    assert len(hot_row["shas"]) == MAX_CITED_COMMITS   # capped listing
    # short-form citations survive the redaction chokepoint
    assert all(len(sha) == CITED_SHA_CHARS for sha in hot_row["shas"])
    assert section["partial"] is False and section["truncated"] is False
    assert section["reasons"] == []
    assert json.loads(json.dumps(section)) == section
    assert releases_section(release, diff, files) == section


def test_section_rows_and_findings_are_re_scrubbed():
    secret = "hunter2hunter2"        # matches no redact_secrets pattern
    path = f"src/{secret}.py"
    history = _index((_commit("b" * 40, EPOCH_0 + 1, path),),
                     window_start=EPOCH_0 - 10)
    release = _release(ts=ISO_0)
    diff = shipped_changes(release, history)
    scrub = lambda t: t.replace(secret, "[REDACTED]")  # noqa: E731
    section = releases_section(release, diff, [_fd(path)], scrub=scrub)
    row = section["files"][0]
    assert row["path"] == "src/[REDACTED].py"
    assert all(secret not in sha for sha in row["shas"])
    (f,) = release_findings(diff, [_fd(path)], scrub=scrub)
    blob = f.title + f.explanation \
        + "".join(ev.summary for ev in f.evidence)
    assert secret not in blob
    assert "[REDACTED]" in blob


# -------------------------------------------------- runner + wiring seams

def test_runner_noop_and_warning_only_paths(tmp_path):
    assert run_release_context(repo_root=str(tmp_path),
                               files=[_fd("a.py")]) == NOOP
    # garbage config: warnings alone, no findings, no section
    _write(tmp_path, "{oops")
    out = run_release_context(repo_root=str(tmp_path), files=[_fd("a.py")])
    assert out.findings == () and out.releases is None
    assert len(out.warnings) == 1 and "not valid JSON" in out.warnings[0]
    # configured, but nothing selectable (draft only): zero surface
    _write(tmp_path, {"releases": [_rel("wip", draft=True)]})
    assert run_release_context(repo_root=str(tmp_path),
                               files=[_fd("a.py")]) == NOOP


def test_runner_without_changed_files_has_no_surface(tmp_path):
    _write(tmp_path, {"releases": [_rel("v1", published_at=ISO_0,
                                        commit_sha="a" * 40)]})
    out = run_release_context(repo_root=str(tmp_path), files=[],
                              history=_history_after_release())
    assert out == NOOP


def test_runner_without_history_reports_a_labeled_section(tmp_path):
    _write(tmp_path, {"releases": [_rel("v9", published_at=ISO_0)]})
    out = run_release_context(repo_root=str(tmp_path), files=[_fd("a.py")],
                              history=None)
    assert out.findings == ()
    assert out.releases["last_release"] == "v9"
    assert out.releases["basis"] == "not_assessable"
    assert out.releases["files"] == []
    assert "history index unavailable" in out.releases["reasons"]


def test_runner_end_to_end_is_deterministic(tmp_path):
    _write(tmp_path, {"releases": [_rel("v9.9.9", published_at=ISO_0,
                                        commit_sha="a" * 40)]})
    files = [_fd("a.py"), _fd("c.py"), _fd("b.py")]
    first = run_release_context(repo_root=str(tmp_path), files=files,
                                history=_history_after_release())
    assert [f.rule_id for f in first.findings] == [RELEASE_RULE_ID] * 2
    assert [f.file for f in first.findings] == ["a.py", "b.py"]
    assert {f.confidence for f in first.findings} == {"high"}  # sha anchor
    assert first.releases["basis"] == "commit_sha"
    assert first.releases["files_total"] == 2
    assert first == run_release_context(repo_root=str(tmp_path),
                                        files=files,
                                        history=_history_after_release())


def test_runner_never_raises(tmp_path, monkeypatch):
    _write(tmp_path, {"releases": [_rel("v1", published_at=ISO_0)]})

    import ai_pr_reviewer.release_intel as module

    def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(module, "shipped_changes", boom)
    out = run_release_context(repo_root=str(tmp_path), files=[_fd("a.py")],
                              history=_history_after_release())
    assert out.findings == () and out.releases is None
    assert out.warnings == ("release intelligence failed (RuntimeError); "
                            "skipped",)


def test_runner_never_calls_builtin_open(tmp_path, monkeypatch):
    import builtins

    _write(tmp_path, {"releases": [_rel("v1", published_at=ISO_0)]})
    real_open = builtins.open

    def forbidden(*args, **kwargs):
        raise AssertionError("release_intel must not call builtin open()")

    monkeypatch.setattr(builtins, "open", forbidden)
    try:
        out = run_release_context(repo_root=str(tmp_path),
                                  files=[_fd("a.py")], history=_index(()))
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    assert out.releases is not None          # ran entirely on Path reads
    assert out.releases["basis"] == "published_at"


def test_release_outcome_is_frozen():
    with pytest.raises(FrozenInstanceError):
        NOOP.warnings = ()                    # type: ignore[misc]


# ------------------------------------------------------------- config flag

def test_release_intel_flag_is_plain_env_default_off(monkeypatch):
    monkeypatch.delenv("RELEASE_INTEL", raising=False)
    assert load_config(parse_args([])).release_intel is False

    monkeypatch.setenv("RELEASE_INTEL", "true")
    assert load_config(parse_args([])).release_intel is True

    # Deliberately NOT an action input: INPUT_* must not enable it.
    monkeypatch.delenv("RELEASE_INTEL", raising=False)
    monkeypatch.setenv("INPUT_RELEASE_INTEL", "1")
    assert load_config(parse_args([])).release_intel is False

    # And no CLI flag exists.
    with pytest.raises(SystemExit):
        parse_args(["--release-intel"])


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
            "release intelligence must not run when the flag is off")

    import ai_pr_reviewer.release_intel as module
    monkeypatch.setattr(module, "run_release_context", bomb)
    w = Wired(monkeypatch)
    result = w.run()
    assert not [x for x in result.warnings if "release" in x.lower()]
    assert not hasattr(result, "releases")


def test_hook_joins_canned_findings_warnings_and_section(monkeypatch):
    from test_orchestrator import Wired, _finding

    canned_finding = _finding(file="a.py", line=2, title="Release canned",
                              severity="low")
    canned = ReleaseOutcome(
        findings=(canned_finding,), warnings=("canned release warning",),
        releases={"last_release": "v1.0.0", "basis": "commit_sha",
                  "files": [], "files_total": 0})

    import ai_pr_reviewer.release_intel as module
    monkeypatch.setattr(module, "run_release_context", lambda **kw: canned)
    w = Wired(monkeypatch)
    w.cfg.release_intel = True
    result = w.run()
    assert "Release canned" in [f.title for f in
                               result.findings + result.below_threshold]
    assert "canned release warning" in result.warnings
    assert result.releases["last_release"] == "v1.0.0"
    assert reporter.finalize_report(result)["releases"] == canned.releases


def test_absent_config_with_flag_on_is_zero_surface(tmp_path, monkeypatch):
    """Flag ON but no configured releases file: the hook RINS (spied) and
    the review output is identical to the flag-OFF run -- including the
    report, where the releases key stays ABSENT."""
    from test_orchestrator import Wired

    w_off = Wired(monkeypatch)
    w_off.cfg.repo_root = str(tmp_path)
    reference = w_off.run()

    calls = []
    import ai_pr_reviewer.release_intel as module
    real = module.run_release_context

    def spy(**kwargs):
        calls.append(kwargs)
        return real(**kwargs)

    monkeypatch.setattr(module, "run_release_context", spy)
    w_on = Wired(monkeypatch)
    w_on.cfg.release_intel = True
    w_on.cfg.repo_root = str(tmp_path)
    result = w_on.run()

    assert len(calls) == 1                       # the hook ran...
    assert not [f for f in result.findings + result.below_threshold
                if f.rule_id == RELEASE_RULE_ID]   # ...and surfaced nothing
    assert _shape(result) == _shape(reference)
    assert "releases" not in reporter.finalize_report(result)


def test_hook_end_to_end_surfaces_findings_and_the_report_key(
        tmp_path, monkeypatch):
    from test_orchestrator import Wired

    import ai_pr_reviewer.orchestrator as orch

    _write(tmp_path, {"releases": [_rel("v9.9.9", published_at=ISO_0,
                                        commit_sha="a" * 40)]})
    w = Wired(monkeypatch)                       # FULL_DIFF: a.py, b.py
    w.cfg.release_intel = True
    w.cfg.repo_root = str(tmp_path)
    history = _history_after_release()           # ships a.py and b.py
    real_build = w._build_context

    def build_with_history(pr, files, cfg, storage=None, gh=None):
        ctx = real_build(pr, files, cfg, storage, gh=gh)
        ctx.history = history
        return ctx

    monkeypatch.setattr(orch, "build_context", build_with_history)
    result = w.run()
    surfaced = [f for f in result.findings + result.below_threshold
                if f.rule_id == RELEASE_RULE_ID]
    assert {f.file for f in surfaced} == {"a.py", "b.py"}
    assert all(f.severity == "info" for f in surfaced)  # below "low" threshold
    report = reporter.finalize_report(result)
    assert report["releases"]["last_release"] == "v9.9.9"
    assert report["releases"]["basis"] == "commit_sha"
    assert report["releases"]["files_total"] == 2
    assert json.loads(json.dumps(report)) == report

    # flag OFF, same repo: the key disappears entirely (additive contract)
    w2 = Wired(monkeypatch)
    w2.cfg.repo_root = str(tmp_path)
    result2 = w2.run()
    assert "releases" not in reporter.finalize_report(result2)
    assert not [f for f in result2.findings + result2.below_threshold
                if f.rule_id == RELEASE_RULE_ID]


# --------------------------------------------------------- reporter seam

def _bare_result() -> ReviewResult:
    pr = PRContext(repo="acme/api", pr_number=7, head_sha="h" * 40)
    return ReviewResult(pr=pr, mode="static", model="static-rules-v1",
                        findings=[])


def test_report_key_is_conditional_and_additive():
    result = _bare_result()
    assert "releases" not in reporter.finalize_report(result)

    section = {"last_release": "v1.0.0", "basis": "commit_sha",
               "files": [], "files_total": 0}
    result.releases = section
    report = reporter.finalize_report(result)
    assert report["releases"] == section
    assert json.loads(json.dumps(report)) == report

    # None / empty dict are treated as absent -- no empty-noise block
    result.releases = None
    assert "releases" not in reporter.finalize_report(result)
    result.releases = {}
    assert "releases" not in reporter.finalize_report(result)


# ============================================================ V4.6-E03-T04
# Draft release notes (human-triggered only, no publishing): a pure
# bounded markdown draft that labels itself, passes every line through
# the redaction chokepoint, and is AST-pinned so that NO production
# module -- not even release_intel itself -- references the function:
# the pipeline has no path to it (plan §C.4 non-goal: no changelog
# auto-publishing).

import re                                                   # noqa: E402

from ai_pr_reviewer.release_intel import (MAX_NOTE_BULLETS,  # noqa: E402
                                          MAX_NOTE_CHARS,
                                          TRUNCATION_MARK,
                                          draft_release_note)


def _draft(**kw):
    release = kw.pop("release", None) or _release(tag="v9.9.9",
                                                  sha="a" * 40)
    diff = kw.pop("diff", None) or shipped_changes(
        release, _history_after_release())
    files = kw.pop("files", None) or [_fd("a.py"), _fd("c.py")]
    return draft_release_note(release, diff, files, **kw)


def test_draft_is_pure_deterministic_markdown_that_labels_itself():
    draft = _draft()
    assert draft.startswith("# v9.9.9\n")
    assert "nothing is published automatically" in draft
    assert "anchor commit_sha" in draft
    assert "2 commit(s), 2 path(s) shipped since v9.9.9" in draft
    # shipped commits quoted with short-form shas + their subjects
    assert "- ccccccc do thing" in draft
    # the review's files that already shipped (c.py never shipped)
    assert "## Files in this review already shipped since v9.9.9 (1)" in draft
    assert "- a.py — 2 shipped commit(s): ccccccc, bbbbbbb" in draft
    assert "- c.py" not in draft
    # deterministic, and the redaction chokepoint stays intact: no
    # 40-64 hex token can appear anywhere in the draft
    assert draft == _draft()
    assert re.search(r"\b[0-9a-f]{40,64}\b", draft) is None


def test_draft_release_note_is_never_referenced_by_the_pipeline():
    """Human-triggered only: no production module -- not even
    release_intel itself -- may reference the draft function."""
    referenced: list[str] = []
    for path in sorted((ROOT / "ai_pr_reviewer").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Name) \
                    and node.id == "draft_release_note":
                referenced.append(str(path.relative_to(ROOT)))
            elif isinstance(node, ast.Attribute) \
                    and node.attr == "draft_release_note":
                referenced.append(str(path.relative_to(ROOT)))
    assert referenced == []
    # self-check: the scan catches a reference when one exists
    probe = ast.parse("def f(x):\n    return draft_release_note(x)\n")
    assert any(isinstance(n, ast.Name) and n.id == "draft_release_note"
               for n in ast.walk(probe))


def test_draft_caps_bullets_and_total_size_with_honest_markers():
    history = _index(tuple(
        _commit(f"{i:040x}", EPOCH_0 + 1 + i, f"f{i:02d}.py")
        for i in reversed(range(40))), window_start=EPOCH_0 - 10)
    release = _release(ts=ISO_0)
    diff = shipped_changes(release, history)
    draft = draft_release_note(release, diff, [_fd("f00.py")])
    commit_lines = [ln for ln in draft.splitlines()
                    if re.match(r"- [0-9a-f]{7} ", ln)]
    assert len(commit_lines) == MAX_NOTE_BULLETS    # listed bullets capped
    assert "10 further commit(s) not listed" in draft
    assert "40 commit(s)" in draft                  # full total stated
    assert "- f00.py — 1 shipped commit(s): " in draft

    # total size: a hostile draft truncates at a LINE boundary, so no
    # sha is ever cut in half, and the marker says it is incomplete
    big_history = _index(tuple(
        _commit(f"{i:040x}", EPOCH_0 + 1 + i, subject="y" * 300)
        for i in reversed(range(40))), window_start=EPOCH_0 - 10)
    big = draft_release_note(release,
                             shipped_changes(release, big_history),
                             [_fd("f00.py")])
    assert len(big) <= MAX_NOTE_CHARS
    assert big.endswith(TRUNCATION_MARK)
    sha_lines = [ln for ln in big.splitlines()
                 if re.match(r"- [0-9a-f]{7} ", ln)]
    assert sha_lines and all(
        len(ln.split()[1]) == CITED_SHA_CHARS for ln in sha_lines)


def test_draft_lines_pass_the_redaction_chokepoint():
    path = f"src/{FAKE_TOKEN}.py"
    history = _index((_commit("b" * 40, EPOCH_0 + 1, path,
                              subject=f"update {FAKE_TOKEN} for "
                                      f"hunter2hunter2"),),
                     window_start=EPOCH_0 - 10)
    release = _release(ts=ISO_0)
    diff = shipped_changes(release, history)
    scrub = lambda t: t.replace("hunter2hunter2", "[REDACTED]")  # noqa: E731
    draft = draft_release_note(release, diff, [_fd(path)], scrub=scrub)
    assert FAKE_TOKEN not in draft
    assert "ghp_" not in draft
    assert "hunter2hunter2" not in draft
    assert "[REDACTED]" in draft           # both layers fired


def test_draft_of_an_unassessable_diff_says_so():
    release = _release(tag="v9.9.9", ts="", sha="")
    diff = shipped_changes(release,
                           _index((_commit("c" * 40, EPOCH_0, "a.py"),)))
    draft = draft_release_note(release, diff, [_fd("a.py")])
    assert "shipped changes since v9.9.9 are unknown" in draft
    assert "## Shipped commits" not in draft
    assert "## Caveats" in draft            # the labeled reasons carry it
    assert "neither a sha" in draft


def test_draft_release_note_never_touches_io(monkeypatch):
    import builtins

    real_open = builtins.open

    def forbidden(*args, **kwargs):
        raise AssertionError("draft_release_note must not call builtin open()")

    monkeypatch.setattr(builtins, "open", forbidden)
    try:
        draft = _draft()
    finally:
        monkeypatch.setattr(builtins, "open", real_open)
    assert draft.startswith("# v9.9.9")
