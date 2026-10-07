"""Incremental-review plumbing: GitHubClient.compare_commits / get_pr_files /
get_file, plus the diff-parser guarantees the incremental flow depends on.
No network, no API keys.

The diff fixtures below are verbatim `git diff <base>...<head>` output from a
scratch repository (git 2.43) - the same git-format text GitHub's compare
endpoint returns with the `application/vnd.github.v3.diff` media type. Because
compare and pull-request diffs are produced by the same machinery, the existing
parser consumes both unchanged; these tests pin that down.
"""
from __future__ import annotations

import functools
import inspect
import json
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.diff_parser import chunk_files, diff_stats, parse_unified_diff
from ai_pr_reviewer.github_client import GitHubClient, GitHubError

BASE_SHA = "a" * 40
HEAD_SHA = "b" * 40


# ------------------------------------------------------------------- helpers
def _diff(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def make_client(monkeypatch, handler):
    """A real GitHubClient whose HTTP layer is an in-memory transport.

    Returns (client, requests_seen). The real constructor still runs, so the
    auth / Accept headers and base URL are exactly what production sends.
    """
    seen: list[httpx.Request] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    real_client = httpx.Client
    monkeypatch.setattr(
        httpx, "Client",
        functools.partial(real_client, transport=httpx.MockTransport(recording)))
    return GitHubClient(token="t0ken", repo="acme/payments"), seen


def _by_path(files):
    return {f.path: f for f in files}


# ---------------------------------------------------------- git-format fixtures
# `git diff A...B` over: a binary edit, an added file, a deleted file, a file
# that lost its trailing newline, a plain edit, a removed line that itself
# starts with "-- " (so it renders as "--- ..."), and a rename with edits.
COMPARE_MIXED = _diff(
    'diff --git a/logo.png b/logo.png',
    'index 5aed2d8..2f3a75f 100644',
    'Binary files a/logo.png and b/logo.png differ',
    'diff --git a/src/added.py b/src/added.py',
    'new file mode 100644',
    'index 0000000..19f13b3',
    '--- /dev/null',
    '+++ b/src/added.py',
    '@@ -0,0 +1,2 @@',
    '+def new_thing():',
    '+    return 2',
    'diff --git a/src/gone.txt b/src/gone.txt',
    'deleted file mode 100644',
    'index 290a7fd..0000000',
    '--- a/src/gone.txt',
    '+++ /dev/null',
    '@@ -1,2 +0,0 @@',
    '-to be deleted',
    '-second line',
    'diff --git a/src/no_newline.py b/src/no_newline.py',
    'index 7d4290a..3d2b4b1 100644',
    '--- a/src/no_newline.py',
    '+++ b/src/no_newline.py',
    '@@ -1 +1 @@',
    '-x = 1',
    '+x = 1',
    '\\ No newline at end of file',
    'diff --git a/src/payments.py b/src/payments.py',
    'index e60850d..35389b5 100644',
    '--- a/src/payments.py',
    '+++ b/src/payments.py',
    '@@ -1,7 +1,8 @@',
    ' import os',
    ' ',
    ' ',
    '-def pay(amount):',
    '+def pay(amount, currency="USD"):',
    '+    query = "SELECT * FROM t WHERE a=%s" % amount',
    '     return amount',
    ' ',
    ' ',
    'diff --git a/src/query.sql b/src/query.sql',
    'index 71c10d8..c50c466 100644',
    '--- a/src/query.sql',
    '+++ b/src/query.sql',
    '@@ -1,2 +1,2 @@',
    '--- keep this sql comment',
    '+-- changed sql comment',
    ' SELECT 1;',
    'diff --git a/src/rename_me.py b/src/renamed.py',
    'similarity index 50%',
    'rename from src/rename_me.py',
    'rename to src/renamed.py',
    'index b9d1cc0..8fa6d97 100644',
    '--- a/src/rename_me.py',
    '+++ b/src/renamed.py',
    '@@ -1,2 +1,6 @@',
    ' def old_name():',
    '     return 1',
    '+',
    '+',
    '+def extra():',
    '+    return 3',
)

# `git diff A...B -- assets_icon.png`: a newly added binary file.
BINARY_NEW = _diff(
    'diff --git a/assets_icon.png b/assets_icon.png',
    'new file mode 100644',
    'index 0000000..15a98c9',
    'Binary files /dev/null and b/assets_icon.png differ',
)

# `git diff B2...B3`: a binary file renamed AND slightly changed (96% similar).
BINARY_RENAMED = _diff(
    'diff --git a/blob_same.bin b/renamed_blob.bin',
    'similarity index 96%',
    'rename from blob_same.bin',
    'rename to renamed_blob.bin',
    'index ee0c07f..7331032 100644',
    'Binary files a/blob_same.bin and b/renamed_blob.bin differ',
)

# A 100%-similarity rename plus a chmod +x: entries that carry no hunks.
RENAME_ONLY_AND_MODE_ONLY = _diff(
    'diff --git a/run.sh b/run.sh',
    'old mode 100644',
    'new mode 100755',
    'diff --git a/src/pure_rename.py b/src/pure_renamed.py',
    'similarity index 100%',
    'rename from src/pure_rename.py',
    'rename to src/pure_renamed.py',
)

# `git diff A...D`: three commits later - the same line was rewritten twice.
NET_CHANGE_THREE_COMMITS = _diff(
    'diff --git a/src/payments.py b/src/payments.py',
    'index e60850d..887e56f 100644',
    '--- a/src/payments.py',
    '+++ b/src/payments.py',
    '@@ -1,7 +1,8 @@',
    ' import os',
    ' ',
    ' ',
    '-def pay(amount):',
    '+def pay(amount, currency="USD"):',
    '+    query = "SELECT * FROM t WHERE a=?"',
    '     return amount',
    ' ',
    ' ',
)

# `git diff C...D`: just the last of those three commits.
LAST_COMMIT_ONLY = _diff(
    'diff --git a/src/payments.py b/src/payments.py',
    'index 24f9a97..887e56f 100644',
    '--- a/src/payments.py',
    '+++ b/src/payments.py',
    '@@ -2,7 +2,7 @@ import os',
    ' ',
    ' ',
    ' def pay(amount, currency="USD"):',
    '-    query = f"SELECT * FROM t WHERE a={amount}"',
    '+    query = "SELECT * FROM t WHERE a=?"',
    '     return amount',
    ' ',
    ' ',
)

# `git diff E...F`: two hunks; the insertion in the first shifts the second.
MULTI_HUNK = _diff(
    'diff --git a/src/big.py b/src/big.py',
    'index 60a0b11..da5fdd3 100644',
    '--- a/src/big.py',
    '+++ b/src/big.py',
    '@@ -1,6 +1,7 @@',
    ' line_01 = 1',
    ' line_02 = 2',
    '-line_03 = 3',
    "+line_03 = 'CHANGED'",
    '+inserted_after_03 = True',
    ' line_04 = 4',
    ' line_05 = 5',
    ' line_06 = 6',
    '@@ -33,7 +34,7 @@ line_32 = 32',
    ' line_33 = 33',
    ' line_34 = 34',
    ' line_35 = 35',
    '-line_36 = 36',
    "+line_36 = 'CHANGED TOO'",
    ' line_37 = 37',
    ' line_38 = 38',
    ' line_39 = 39',
)


# =========================================================================
# GitHubClient.compare_commits
# =========================================================================
def test_compare_commits_returns_the_diff_text(monkeypatch):
    def handler(request):
        return httpx.Response(200, text=COMPARE_MIXED)

    gh, seen = make_client(monkeypatch, handler)
    assert gh.compare_commits(BASE_SHA, HEAD_SHA) == COMPARE_MIXED

    (req,) = seen
    assert req.method == "GET"
    assert req.url.path == f"/repos/acme/payments/compare/{BASE_SHA}...{HEAD_SHA}"
    assert req.headers["accept"] == "application/vnd.github.v3.diff"
    assert req.headers["authorization"] == "Bearer t0ken"


def test_compare_output_goes_straight_into_parse_unified_diff(monkeypatch):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(200, text=COMPARE_MIXED))
    files = parse_unified_diff(gh.compare_commits(BASE_SHA, HEAD_SHA))
    assert sorted(f.path for f in files) == [
        "logo.png", "src/added.py", "src/gone.txt", "src/no_newline.py",
        "src/payments.py", "src/query.sql", "src/renamed.py"]


def test_identical_commits_give_an_empty_diff(monkeypatch):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(200, text=""))
    text = gh.compare_commits(HEAD_SHA, HEAD_SHA)
    assert text == ""
    assert parse_unified_diff(text) == []


@pytest.mark.parametrize("status", [404, 406, 422, 500])
def test_compare_commits_failure_raises_github_error_like_get_pr(monkeypatch, status):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(status, text="nope"))
    with pytest.raises(GitHubError, match=rf"GET compare failed \({status}\): nope") as exc:
        gh.compare_commits(BASE_SHA, HEAD_SHA)
    assert exc.value.status_code == status


@pytest.mark.parametrize("base,head", [("", HEAD_SHA), (BASE_SHA, ""), ("", "")])
def test_compare_commits_needs_both_shas_and_sends_nothing_otherwise(monkeypatch, base, head):
    gh, seen = make_client(monkeypatch, lambda r: httpx.Response(200, text=""))
    with pytest.raises(GitHubError):
        gh.compare_commits(base, head)
    assert seen == []


def test_compare_refs_cannot_add_path_segments(monkeypatch):
    gh, seen = make_client(monkeypatch, lambda r: httpx.Response(200, text=""))
    gh.compare_commits("../../orgs/acme", "x/y?z#f")
    raw = seen[0].url.raw_path
    assert raw.startswith(b"/repos/acme/payments/compare/")
    tail = raw[len(b"/repos/acme/payments/compare/"):]
    assert b"/" not in tail and b"?" not in tail and b"#" not in tail


# =========================================================================
# GitHubClient.get_pr_files
# =========================================================================
def _files_handler(pages):
    """pages: {page_number: [file dicts]}; unknown pages are empty."""
    def handler(request):
        page = int(request.url.params.get("page", "1"))
        return httpx.Response(200, json=pages.get(page, []))
    return handler


def test_get_pr_files_follows_pagination_until_an_empty_page(monkeypatch):
    page1 = [{"filename": f"src/f{i}.py", "status": "modified"} for i in range(100)]
    page2 = [{"filename": "src/last.py", "status": "added"}]
    gh, seen = make_client(monkeypatch, _files_handler({1: page1, 2: page2}))

    files = gh.get_pr_files(42)

    assert files == page1 + page2
    assert [r.url.params.get("page") for r in seen] == ["1", "2", "3"]
    assert all(r.url.path == "/repos/acme/payments/pulls/42/files" for r in seen)
    assert all(r.url.params.get("per_page") == "100" for r in seen)


def test_get_pr_files_short_pages_do_not_end_the_loop_early(monkeypatch):
    gh, seen = make_client(monkeypatch, _files_handler(
        {1: [{"filename": "a.py"}], 2: [{"filename": "b.py"}]}))
    assert [f["filename"] for f in gh.get_pr_files(7)] == ["a.py", "b.py"]
    assert len(seen) == 3


def test_get_pr_files_with_no_files_makes_one_request(monkeypatch):
    gh, seen = make_client(monkeypatch, _files_handler({}))
    assert gh.get_pr_files(7) == []
    assert len(seen) == 1


def test_get_pr_files_is_capped_at_ten_pages_and_says_so(monkeypatch, capsys):
    def handler(request):
        page = request.url.params.get("page")
        return httpx.Response(200, json=[{"filename": f"page{page}.py"}])

    gh, seen = make_client(monkeypatch, handler)
    files = gh.get_pr_files(7)

    assert len(seen) == 10
    assert len(files) == 10
    assert "truncated" in capsys.readouterr().err


def test_get_pr_files_error_status_raises(monkeypatch):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(403, text="rate limited"))
    with pytest.raises(GitHubError, match=r"\(403\)") as exc:
        gh.get_pr_files(7)
    assert exc.value.status_code == 403


# =========================================================================
# GitHubClient.get_file
# =========================================================================
def _contents(text: str, **over) -> dict:
    import base64
    raw = base64.b64encode(text.encode("utf-8")).decode("ascii")
    # GitHub wraps base64 at 60 columns with newlines.
    wrapped = "\n".join(raw[i:i + 60] for i in range(0, len(raw), 60)) + "\n"
    data = {"type": "file", "encoding": "base64", "content": wrapped, "size": len(text)}
    data.update(over)
    return data


def test_get_file_decodes_content_at_the_requested_ref(monkeypatch):
    source = "def pay():\n    return 'caf\u00e9'\n" * 20      # long enough to wrap
    gh, seen = make_client(monkeypatch, lambda r: httpx.Response(200, json=_contents(source)))

    assert gh.get_file("src/my dir/payments.py", "deadbeef") == source

    (req,) = seen
    assert req.url.path == "/repos/acme/payments/contents/src/my dir/payments.py"
    assert b"my%20dir" in req.url.raw_path
    assert req.url.params.get("ref") == "deadbeef"


def test_get_file_empty_file_is_an_empty_string(monkeypatch):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(
        200, json={"type": "file", "encoding": "base64", "content": "", "size": 0}))
    assert gh.get_file("empty.py", "main") == ""


def test_get_file_missing_file_is_a_404_github_error(monkeypatch):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(404, json={"message": "Not Found"}))
    with pytest.raises(GitHubError, match=r"GET file failed \(404\)") as exc:
        gh.get_file("tests/test_nope.py", "main")
    assert exc.value.status_code == 404


@pytest.mark.parametrize("payload", [
    [{"type": "file", "name": "a.py"}],                                   # a directory listing
    {"type": "symlink", "target": "../elsewhere"},
    {"type": "submodule"},
    {"type": "file", "encoding": "none", "content": "", "size": 5_000_000},  # > 1 MB
])
def test_get_file_refuses_things_that_are_not_inline_text_files(monkeypatch, payload):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(200, json=payload))
    with pytest.raises(GitHubError):
        gh.get_file("vendor/thing", "main")


@pytest.mark.parametrize("path", [
    "../secrets", "a/../../b", "a/./b", "/abs/path", "a//b", "dir/", "", "..",
])
def test_get_file_refuses_paths_that_could_leave_the_contents_route(monkeypatch, path):
    gh, seen = make_client(monkeypatch, lambda r: httpx.Response(200, json=_contents("x")))
    with pytest.raises(GitHubError, match="unsafe repository path"):
        gh.get_file(path, "main")
    assert seen == []


def test_get_file_path_cannot_smuggle_a_query_string_or_fragment(monkeypatch):
    gh, seen = make_client(monkeypatch, lambda r: httpx.Response(200, json=_contents("x")))
    gh.get_file("weird?name#frag.py", "main")
    raw = seen[0].url.raw_path
    assert b"weird%3Fname%23frag.py" in raw
    assert raw.count(b"?") == 1          # only the real ?ref=main separator


# =========================================================================
# JSON request-body helper shared by the API-shape tests below
# =========================================================================
def _body(request) -> dict:
    return json.loads(request.content)


# =========================================================================
# Existing behaviour must not have moved
# =========================================================================
def test_existing_public_signatures_are_unchanged():
    def params(fn):
        return list(inspect.signature(fn).parameters)

    assert params(GitHubClient.get_pr) == ["self", "number"]
    assert params(GitHubClient.get_event_context) == ["self"]
    assert params(GitHubClient.post_review) == ["self", "number", "commit_id", "body", "comments"]
    assert params(GitHubClient.create_comment) == ["self", "number", "body"]
    assert params(GitHubClient.file_url) == ["repo", "sha", "path", "line"]


def test_get_pr_still_returns_context_and_diff(monkeypatch):
    def handler(request):
        if request.headers["accept"] == "application/vnd.github.v3.diff":
            return httpx.Response(200, text=COMPARE_MIXED)
        return httpx.Response(200, json={
            "title": "Refunds", "user": {"login": "dev"}, "html_url": "https://x/pr/42",
            "head": {"ref": "feature", "sha": HEAD_SHA}, "base": {"ref": "main", "sha": BASE_SHA}})

    gh, seen = make_client(monkeypatch, handler)
    ctx, diff = gh.get_pr(42)

    assert (ctx.repo, ctx.pr_number, ctx.pr_title, ctx.author) == ("acme/payments", 42, "Refunds", "dev")
    assert (ctx.branch, ctx.base, ctx.head_sha) == ("feature", "main", HEAD_SHA)
    assert diff == COMPARE_MIXED
    assert len(seen) == 2


# =========================================================================
# D1 — PRContext.base_sha population (V3-E01-T01)
# =========================================================================
def _pr_api_handler(request):
    if request.headers["accept"] == "application/vnd.github.v3.diff":
        return httpx.Response(200, text=COMPARE_MIXED)
    return httpx.Response(200, json={
        "title": "Refunds", "user": {"login": "dev"}, "html_url": "https://x/pr/42",
        "head": {"ref": "feature", "sha": HEAD_SHA}, "base": {"ref": "main", "sha": BASE_SHA}})


def test_get_pr_populates_base_sha_from_the_base_side(monkeypatch):
    """D1: get_pr() must set base_sha from pull_request.base.sha — the
    fixture goes through the REAL get_pr (fake transport), never a
    hand-built PRContext, so a regression in population fails here."""
    gh, _seen = make_client(monkeypatch, _pr_api_handler)
    ctx, _diff = gh.get_pr(42)

    assert ctx.base_sha == BASE_SHA
    assert ctx.base_sha != ctx.head_sha      # base, never the PR head


def test_get_event_context_populates_base_sha(tmp_path, monkeypatch):
    """D1: the Actions event payload path populates base_sha the same way."""
    event = {"pull_request": {
        "number": 42, "title": "Refunds", "user": {"login": "dev"},
        "html_url": "https://x/pr/42",
        "head": {"ref": "feature", "sha": HEAD_SHA},
        "base": {"ref": "main", "sha": BASE_SHA}}}
    p = tmp_path / "event.json"
    p.write_text(json.dumps(event), encoding="utf-8")
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(p))
    monkeypatch.setenv("GITHUB_REPOSITORY", "acme/payments")

    ctx = GitHubClient(token="t0ken", repo="acme/payments").get_event_context()

    assert ctx is not None
    assert ctx.base_sha == BASE_SHA
    assert ctx.head_sha == HEAD_SHA


def test_repo_context_built_through_get_pr_fetches_at_the_base_revision(monkeypatch):
    """D1 end-to-end: a PRContext produced the way production produces it
    (real get_pr over the wire) drives repository-context fetches at
    base_sha — a PR can never choose the text its own review reads."""
    from ai_pr_reviewer import repo_context as rc
    from ai_pr_reviewer.config import Config

    gh, _seen = make_client(monkeypatch, _pr_api_handler)
    ctx, _diff = gh.get_pr(42)               # production path, not hand-built

    diff = (
        "--- a/app/main.py\n"
        "+++ b/app/main.py\n"
        "@@ -1,2 +1,3 @@\n"
        " import os\n"
        "+from utils.helpers import run\n"
        " print(os.getcwd())\n"
    )

    class _Fetch:
        def __init__(self):
            self.calls: list[tuple[str, str]] = []

        def get_file(self, path: str, ref: str) -> str:
            self.calls.append((path, ref))
            if path == "utils/helpers.py":
                return "def run(): ...\n"
            raise GitHubError("not found", status_code=404)

    fetch = _Fetch()
    rc.collect_repository_context(fetch, ctx, parse_unified_diff(diff), Config())

    assert fetch.calls, "expected at least one repository-context fetch"
    assert all(ref == BASE_SHA for _path, ref in fetch.calls)
    assert ctx.head_sha == HEAD_SHA          # head exists but is never the ref


def test_get_pr_error_message_format_is_unchanged(monkeypatch):
    gh, _ = make_client(monkeypatch, lambda r: httpx.Response(404, text="Not Found"))
    with pytest.raises(GitHubError) as exc:
        gh.get_pr(42)
    assert str(exc.value) == "GET pull request failed (404): Not Found"
    assert exc.value.status_code == 404


def test_post_review_422_recovers_each_valid_inline_comment(monkeypatch):
    requests = []

    def handler(request):
        payload = _body(request)
        requests.append((request.url.path, payload))
        if request.url.path.endswith("/reviews") and payload["comments"]:
            return httpx.Response(422, text="line must be part of the diff")
        if request.url.path.endswith("/comments") and payload["line"] == 9:
            return httpx.Response(422, text="line must be part of the diff")
        return httpx.Response(201, json={"id": len(requests)})

    gh, _ = make_client(monkeypatch, handler)
    good = {"path": "a.py", "line": 3, "side": "RIGHT", "body": "ok"}
    bad = {"path": "a.py", "line": 9, "side": "RIGHT", "body": "rejected"}

    out = gh.post_review(42, HEAD_SHA, "summary", [good, bad])

    assert out["ok"] and out["recovered"] and out["dropped"] == 1
    assert requests[1] == ("/repos/acme/payments/pulls/42/reviews", {
        "commit_id": HEAD_SHA, "event": "COMMENT", "body": "summary", "comments": []
    })
    assert requests[2][0] == "/repos/acme/payments/pulls/42/comments"
    assert requests[2][1] == {"commit_id": HEAD_SHA, **good}
    assert requests[3][0] == "/repos/acme/payments/pulls/42/comments"
    assert requests[3][1] == {"commit_id": HEAD_SHA, **bad}


# =========================================================================
# diff_parser on compare-style (git-format) output
# =========================================================================
def test_added_file():
    f = _by_path(parse_unified_diff(COMPARE_MIXED))["src/added.py"]
    assert f.is_new and not f.is_deleted and not f.is_binary and not f.is_rename
    assert f.old_path == "" and f.new_path == "src/added.py"
    assert f.added_lines() == [(1, "def new_thing():"), (2, "    return 2")]
    assert (f.additions, f.deletions) == (2, 0)


def test_deleted_file():
    f = _by_path(parse_unified_diff(COMPARE_MIXED))["src/gone.txt"]
    assert f.is_deleted and not f.is_new
    assert f.path == "src/gone.txt" and f.new_path == ""
    assert (f.additions, f.deletions) == (0, 2)
    assert f.new_line_numbers() == set()          # nothing left to comment on
    assert [(l.old_no, l.text) for l in f.hunks[0].lines] == [(1, "to be deleted"), (2, "second line")]


def test_modified_file_reports_new_file_line_numbers():
    f = _by_path(parse_unified_diff(COMPARE_MIXED))["src/payments.py"]
    assert not (f.is_new or f.is_deleted or f.is_binary or f.is_rename)
    assert f.added_lines() == [
        (4, 'def pay(amount, currency="USD"):'),
        (5, '    query = "SELECT * FROM t WHERE a=%s" % amount'),
    ]
    removed = [(l.old_no, l.text) for l in f.hunks[0].lines if l.tag == "-"]
    assert removed == [(4, "def pay(amount):")]
    assert f.new_line_numbers() == set(range(1, 9))


def test_renamed_file_with_edits_keeps_both_paths_and_new_line_numbers():
    f = _by_path(parse_unified_diff(COMPARE_MIXED))["src/renamed.py"]
    assert f.is_rename and not f.is_new
    assert f.old_path == "src/rename_me.py"
    assert f.new_path == "src/renamed.py"
    assert [n for n, _ in f.added_lines()] == [3, 4, 5, 6]
    assert f.added_lines()[-1] == (6, "    return 3")


def test_binary_file_is_flagged_and_has_no_lines():
    f = _by_path(parse_unified_diff(COMPARE_MIXED))["logo.png"]
    assert f.is_binary and not f.is_new and not f.is_deleted
    assert (f.additions, f.deletions) == (0, 0)
    assert f.hunks == [] and f.new_line_numbers() == set()


def test_new_binary_file():
    (f,) = parse_unified_diff(BINARY_NEW)
    assert f.is_binary and f.is_new
    assert f.path == "assets_icon.png"


def test_renamed_binary_file_keeps_its_real_paths():
    # Regression: `rename from/to` used to be sliced too early, producing
    # old_path == "from blob_same.bin" and new_path == "to renamed_blob.bin".
    (f,) = parse_unified_diff(BINARY_RENAMED)
    assert f.is_binary and f.is_rename
    assert (f.old_path, f.new_path) == ("blob_same.bin", "renamed_blob.bin")
    assert f.path == "renamed_blob.bin"


@pytest.mark.parametrize("text", ["", "\n", "   \n\n"])
def test_empty_diff_yields_no_files(text):
    assert parse_unified_diff(text) == []


def test_entries_without_content_changes_are_not_returned():
    # Characterisation of long-standing behaviour: a 100%-similarity rename and
    # a mode-only change carry no hunks, so there is nothing to review.
    assert parse_unified_diff(RENAME_ONLY_AND_MODE_ONLY) == []


def test_removed_line_that_looks_like_a_file_header_stays_a_removed_line():
    f = _by_path(parse_unified_diff(COMPARE_MIXED))["src/query.sql"]
    assert [(l.tag, l.text) for l in f.hunks[0].lines] == [
        ("-", "-- keep this sql comment"),
        ("+", "-- changed sql comment"),
        (" ", "SELECT 1;"),
    ]
    assert f.added_lines() == [(1, "-- changed sql comment")]


def test_no_newline_marker_does_not_consume_a_line_number():
    f = _by_path(parse_unified_diff(COMPARE_MIXED))["src/no_newline.py"]
    assert f.added_lines() == [(1, "x = 1")]
    assert (f.additions, f.deletions) == (1, 1)
    assert f.hunks[0].lines[-1].tag == "\\" and f.hunks[0].lines[-1].new_no is None


def test_several_commits_collapse_into_one_net_diff():
    # A...D spans three commits, and the same line was rewritten twice.
    # Only the net change against A appears - not the intermediate versions.
    (f,) = parse_unified_diff(NET_CHANGE_THREE_COMMITS)
    assert f.path == "src/payments.py"
    assert (f.additions, f.deletions) == (2, 1)
    texts = [t for _, t in f.added_lines()]
    assert texts == ['def pay(amount, currency="USD"):', '    query = "SELECT * FROM t WHERE a=?"']
    assert not any("f\"SELECT" in t or "% amount" in t for t in texts)


def test_last_commit_only_range_numbers_lines_against_the_new_file():
    (f,) = parse_unified_diff(LAST_COMMIT_ONLY)
    assert (f.hunks[0].old_start, f.hunks[0].new_start) == (2, 2)
    assert f.added_lines() == [(5, '    query = "SELECT * FROM t WHERE a=?"')]
    assert [(l.old_no, l.text) for l in f.hunks[0].lines if l.tag == "-"] == [
        (5, '    query = f"SELECT * FROM t WHERE a={amount}"')]


def test_second_hunk_line_numbers_include_the_shift_from_the_first():
    (f,) = parse_unified_diff(MULTI_HUNK)
    assert [(h.old_start, h.new_start) for h in f.hunks] == [(1, 1), (33, 34)]
    assert f.added_lines() == [
        (3, "line_03 = 'CHANGED'"),
        (4, "inserted_after_03 = True"),
        (37, "line_36 = 'CHANGED TOO'"),
    ]


# ---- line-number correctness: characters that live INSIDE one source line ----
_SEPARATORS = ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029", "\r"]


def _diff_with_separator_in_line(sep: str) -> str:
    return _diff(
        "diff --git a/x.py b/x.py",
        "index 1111111..2222222 100644",
        "--- a/x.py",
        "+++ b/x.py",
        "@@ -1,3 +1,5 @@",
        " first = 1",
        f"+middle = 'a{sep}b'",
        " second = 2",
        "+after = 3",
        " third = 3",
    )


@pytest.mark.parametrize("sep", _SEPARATORS)
def test_line_separator_characters_inside_a_line_do_not_shift_numbering(sep):
    # Regression: str.splitlines() also splits on these, which cut one source
    # line in two and pushed every later line number in the hunk down by one.
    (f,) = parse_unified_diff(_diff_with_separator_in_line(sep))
    assert f.added_lines() == [(2, f"middle = 'a{sep}b'"), (4, "after = 3")]
    assert f.new_line_numbers() == {1, 2, 3, 4, 5}


@pytest.mark.parametrize("sep", _SEPARATORS)
def test_chunk_files_does_not_reflow_lines_at_those_characters(sep):
    files = parse_unified_diff(_diff_with_separator_in_line(sep))
    (batch,) = chunk_files(files)
    assert f"+middle = 'a{sep}b'" in batch       # still one line in the prompt text


def test_crlf_line_endings_on_the_wire_parse_the_same():
    lf = parse_unified_diff(COMPARE_MIXED)
    crlf = parse_unified_diff(COMPARE_MIXED.replace("\n", "\r\n"))
    assert [(f.path, f.added_lines()) for f in crlf] == [(f.path, f.added_lines()) for f in lf]


# =========================================================================
# diff_stats
# =========================================================================
def test_diff_stats_totals_a_compare_diff():
    files = parse_unified_diff(COMPARE_MIXED)
    assert diff_stats(files) == {"files": 7, "additions": 10, "deletions": 5}


def test_diff_stats_of_nothing_is_zeros():
    assert diff_stats([]) == {"files": 0, "additions": 0, "deletions": 0}
    assert diff_stats(parse_unified_diff("")) == {"files": 0, "additions": 0, "deletions": 0}


def test_diff_stats_counts_binary_files_but_no_lines_for_them():
    assert diff_stats(parse_unified_diff(BINARY_NEW)) == {"files": 1, "additions": 0, "deletions": 0}


def test_diff_stats_matches_the_per_file_properties():
    files = parse_unified_diff(MULTI_HUNK + NET_CHANGE_THREE_COMMITS)
    stats = diff_stats(files)
    assert stats["files"] == len(files) == 2
    assert stats["additions"] == sum(f.additions for f in files) == 5
    assert stats["deletions"] == sum(f.deletions for f in files) == 3
