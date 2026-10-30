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
