"""V4.4-E01-T01: bounded git history index (commits, churn, co-change).

Fixture repos are built in temp dirs with real ``git`` and fixed commit
timestamps (the ``demo/make_fixtures`` pattern): no network, no real data,
deterministic. Covers the ticket's acceptance criteria:

  * churn / co-change correct on a crafted fixture repo
  * deterministic: two builds are equal
  * bounded: commit window, day window, bulk commits, path/pair caps,
    output cap and wall-clock timeout all degrade loudly, never crash
  * shallow clones are labelled and their boundary commit is not churn
  * privacy baseline paths never enter the index
  * untrusted commit subjects are redacted/sanitized and cannot forge
    records
  * read-only: the checkout is byte-identical after a build
  * no author/identity field exists anywhere in the index (family
    invariant: role-only, never per-developer)
  * the package never imports network/model modules and only git_read.py
    may start a process
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import ai_pr_reviewer  # noqa: E402
from ai_pr_reviewer.history import (HISTORY_OK, HISTORY_SHALLOW,  # noqa: E402
                                    HISTORY_STATES, HISTORY_TRUNCATED,
                                    HISTORY_UNAVAILABLE, CoChange,
                                    CommitRecord, GitRefused, HistoryIndex,
                                    HistoryLimits, HistoryStats, PathChurn,
                                    build_history_index, clean_subject,
                                    run_git)
from ai_pr_reviewer.history import limits as hist_limits  # noqa: E402

T0 = 1_700_000_000
HOUR = 3_600
DAY = 86_400


# --------------------------------------------------------------------------- fixtures

def _git(cwd: Path, *args: str, when: int | None = None) -> None:
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_NAME": "Fixture Person", "GIT_COMMITTER_NAME": "Fixture Person",
        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
    })
    if when is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = f"{when} +0000"
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True,
                   capture_output=True)


def make_repo(tmp: Path, commits, name: str = "repo") -> Path:
    """``commits``: iterable of ``(when, subject, {path: content})``;
    a ``None`` content deletes the path."""
    repo = tmp / name
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    for when, subject, files in commits:
        for rel, content in files.items():
            target = repo / rel
            if content is None:
                if target.exists():
                    target.unlink()
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8", newline="\n")
        _git(repo, "add", "-A")
        _git(repo, "commit", "-q", "--allow-empty", "-m", subject, when=when)
    return repo


CRAFTED = [
    (T0, "initial", {"app/a.py": "1\n", "app/b.py": "1\n", "docs/readme.md": "x\n"}),
    (T0 + HOUR, "touch a and b", {"app/a.py": "1\n2\n", "app/b.py": "1\n2\n"}),
    (T0 + 2 * HOUR, "touch a only", {"app/a.py": "1\n2\n3\n"}),
    (T0 + 3 * HOUR, "touch b and readme", {"app/b.py": "9\n", "docs/readme.md": "y\n"}),
]


def tree_digest(repo: Path) -> str:
    """Digest of every file under ``repo`` including ``.git``."""
    h = hashlib.sha256()
    for path in sorted(p for p in repo.rglob("*") if p.is_file()):
        h.update(str(path.relative_to(repo)).encode())
        h.update(path.read_bytes())
    return h.hexdigest()


# --------------------------------------------------------------------------- correctness

def test_churn_and_co_change_on_crafted_history(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    idx = build_history_index(repo)
    assert idx.state == HISTORY_OK and idx.reasons == ()
    assert len(idx.commits) == 4 and idx.stats.commits_in_window == 4
    churn = {c.path: c for c in idx.churn}
    assert churn["app/a.py"].commits == 3
    assert churn["app/b.py"].commits == 3
    assert churn["docs/readme.md"].commits == 2
    assert churn["app/a.py"].last_changed_at == T0 + 2 * HOUR
    assert churn["app/b.py"].last_changed_at == T0 + 3 * HOUR
    # a.py: +1 (initial), +1 (touch a and b), +1 (touch a only); nothing deleted.
    assert (churn["app/a.py"].lines_added, churn["app/a.py"].lines_deleted) == (3, 0)
    assert (churn["app/b.py"].lines_added, churn["app/b.py"].lines_deleted) == (3, 2)
    pairs = {(c.path_a, c.path_b): c.count for c in idx.co_change}
    assert pairs[("app/a.py", "app/b.py")] == 2
    assert pairs[("app/b.py", "docs/readme.md")] == 2
    assert pairs[("app/a.py", "docs/readme.md")] == 1
    assert all(a < b for a, b in pairs)


def test_build_is_deterministic(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    first = build_history_index(repo)
    second = build_history_index(repo)
    assert first == second
    assert [c.path for c in first.churn] == sorted(c.path for c in first.churn)
    counts = [c.count for c in first.co_change]
    assert counts == sorted(counts, reverse=True)


def test_head_sha_and_commit_order_are_newest_first(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    idx = build_history_index(repo)
    assert idx.commits[0].sha == idx.head_sha
    times = [c.committed_at for c in idx.commits]
    assert times == sorted(times, reverse=True)


def test_merge_commits_carry_no_paths(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    _git(repo, "checkout", "-q", "-b", "side")
    (repo / "side.py").write_text("s\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "side work", when=T0 + 4 * HOUR)
    _git(repo, "checkout", "-q", "main")
    (repo / "main_only.py").write_text("m\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "main work", when=T0 + 5 * HOUR)
    _git(repo, "merge", "-q", "--no-ff", "-m", "merge side", "side",
         when=T0 + 6 * HOUR)
    idx = build_history_index(repo)
    merge = idx.commits[0]
    assert merge.parent_count == 2 and merge.paths == ()
    churn = {c.path: c.commits for c in idx.churn}
    assert churn["side.py"] == 1 and churn["main_only.py"] == 1


# --------------------------------------------------------------------------- bounds

def test_commit_window_cap_is_loud(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    idx = build_history_index(repo, limits=HistoryLimits.from_values(max_commits=2))
    assert idx.state == HISTORY_TRUNCATED
    assert len(idx.commits) == 2
    assert any("capped at 2 commits" in r for r in idx.reasons)
    assert {c.path for c in idx.churn} == {"app/a.py", "app/b.py", "docs/readme.md"}
    assert {c.path: c.commits for c in idx.churn}["app/a.py"] == 1


def test_day_window_is_anchored_to_head_not_the_wall_clock(tmp_path):
    repo = make_repo(tmp_path, [
        (T0, "ancient", {"old.py": "1\n"}),
        (T0 + 200 * DAY, "recent one", {"new.py": "1\n"}),
        (T0 + 201 * DAY, "recent two", {"new.py": "2\n"}),
    ])
    idx = build_history_index(repo, limits=HistoryLimits.from_values(max_days=30))
    assert idx.state == HISTORY_OK  # the age window is by design, not degradation
    assert [c.subject for c in idx.commits] == ["recent two", "recent one"]
    assert idx.window_start == T0 + 201 * DAY - 30 * DAY
    assert [c.path for c in idx.churn] == ["new.py"]


def test_bulk_commits_are_counted_but_not_churn(tmp_path):
    bulk = {f"gen/f{i:03}.py": "x\n" for i in range(60)}
    repo = make_repo(tmp_path, [
        (T0, "bulk reformat", bulk),
        (T0 + HOUR, "real change", {"gen/f001.py": "y\n", "gen/f002.py": "y\n"}),
    ])
    idx = build_history_index(repo)
    assert idx.stats.bulk_commits_skipped == 1
    bulk_commit = next(c for c in idx.commits if c.subject == "bulk reformat")
    assert bulk_commit.is_bulk and bulk_commit.paths == ()
    assert {c.path: c.commits for c in idx.churn} == {"gen/f001.py": 1, "gen/f002.py": 1}
    assert [(c.path_a, c.path_b, c.count) for c in idx.co_change] == [
        ("gen/f001.py", "gen/f002.py", 1)]


def test_path_and_pair_caps_are_loud(tmp_path):
    repo = make_repo(tmp_path, [
        (T0, "five files", {f"m/f{i}.py": "x\n" for i in range(5)}),
    ])
    idx = build_history_index(
        repo, limits=HistoryLimits.from_values(max_tracked_paths=3))
    assert idx.state == HISTORY_TRUNCATED and len(idx.churn) == 3
    assert any("churn tracking capped at 3 paths" in r for r in idx.reasons)
    idx = build_history_index(
        repo, limits=HistoryLimits.from_values(max_co_change_pairs=4))
    assert idx.state == HISTORY_TRUNCATED and len(idx.co_change) == 4
    assert any("co-change capped at 4 pairs" in r for r in idx.reasons)


def test_output_cap_and_timeout_degrade_without_crashing(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    capped = build_history_index(
        repo, limits=HistoryLimits.from_values(max_output_bytes=1))
    assert capped.state == HISTORY_TRUNCATED
    assert any("size cap" in r for r in capped.reasons)

    def slow_runner(root, args, *, max_output_bytes, timeout):
        if args[0] == "log":
            return run_git(root, args, max_output_bytes=max_output_bytes,
                           timeout=0.2,
                           git_exe=(sys.executable, "-c",
                                    "import time; time.sleep(30)"))
        return run_git(root, args, max_output_bytes=max_output_bytes,
                       timeout=timeout)

    slow = build_history_index(repo, runner=slow_runner)
    assert slow.state == HISTORY_TRUNCATED
    assert any("time budget" in r for r in slow.reasons)


def test_limits_clamp_hostile_values():
    lim = HistoryLimits.from_values(
        max_commits=10**9, max_days=-5, max_files_per_commit="lots",
        max_tracked_paths=True, max_co_change_pairs=0,
        max_output_bytes=10**12, max_seconds=10**6, bogus=1)
    assert lim.max_commits == hist_limits.HARD_MAX_COMMITS
    assert lim.max_days == hist_limits.DEFAULT_MAX_DAYS
    assert lim.max_files_per_commit == hist_limits.DEFAULT_MAX_FILES_PER_COMMIT
    assert lim.max_tracked_paths == hist_limits.DEFAULT_MAX_TRACKED_PATHS
    assert lim.max_co_change_pairs == hist_limits.DEFAULT_MAX_CO_CHANGE_PAIRS
    assert lim.max_output_bytes == hist_limits.HARD_MAX_OUTPUT_BYTES
    assert lim.max_seconds == hist_limits.HARD_MAX_SECONDS
    assert HistoryLimits.from_values() == HistoryLimits()


# --------------------------------------------------------------------------- degradation labels

def test_shallow_clone_is_labelled_and_boundary_is_not_churn(tmp_path):
    origin = make_repo(tmp_path, CRAFTED, name="origin")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--depth", "2", origin.as_uri(),
                    str(clone)], check=True, capture_output=True,
                   env=dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull))
    idx = build_history_index(clone)
    assert idx.shallow is True and idx.state == HISTORY_SHALLOW
    assert idx.reasons and "shallow clone" in idx.reasons[0]
    assert idx.stats.boundary_commits == 1
    boundary = [c for c in idx.commits if c.is_boundary]
    assert len(boundary) == 1 and boundary[0].paths == ()
    # Only the newest commit is real churn; the boundary commit's
    # whole-tree "added" listing must not be counted.
    assert {c.path: c.commits for c in idx.churn} == {
        "app/b.py": 1, "docs/readme.md": 1}


def test_unavailable_states_never_raise(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    for root in (None, "", str(tmp_path / "missing"), plain):
        idx = build_history_index(root)
        assert idx.state == HISTORY_UNAVAILABLE and not idx.is_available
        assert idx.reasons and idx.commits == () and idx.churn == ()
    empty = tmp_path / "empty"
    empty.mkdir()
    _git(empty, "init", "-q", "-b", "main")
    idx = build_history_index(empty)
    assert idx.state == HISTORY_UNAVAILABLE
    assert "no readable commits" in idx.reasons[0]


def test_git_missing_degrades_to_unavailable(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)

    def no_git(root, args, **kw):
        return run_git(root, args, git_exe="/nonexistent/git-binary", **kw)

    idx = build_history_index(repo, runner=no_git)
    assert idx.state == HISTORY_UNAVAILABLE and "git is not available" in idx.reasons[0]


def test_unexpected_failure_is_contained(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)

    def boom(root, args, **kw):
        raise RuntimeError("synthetic failure")

    idx = build_history_index(repo, runner=boom)
    assert idx.state == HISTORY_UNAVAILABLE
    assert "RuntimeError" in idx.reasons[0] and "synthetic" not in idx.reasons[0]


# --------------------------------------------------------------------------- privacy / untrusted text

def test_privacy_baseline_paths_never_enter_the_index(tmp_path):
    repo = make_repo(tmp_path, [
        (T0, "add files", {
            ".env": "A=1\n", "config/.env.production": "B=2\n",
            "keys/server.pem": "k\n", "secrets/db.txt": "s\n",
            "package-lock.json": "{}\n", "node_modules/x/index.js": "1\n",
            "src/app.py": "1\n", "src/util.py": "1\n", "vendor_notes.txt": "n\n"}),
    ])
    idx = build_history_index(repo)
    paths = {c.path for c in idx.churn}
    assert paths == {"src/app.py", "src/util.py", "vendor_notes.txt"}
    for commit in idx.commits:
        assert not any(p.endswith((".env", ".pem")) or "secrets/" in p
                       for p in commit.paths)
    assert idx.stats.paths_filtered == 6
    for pair in idx.co_change:
        assert pair.path_a in paths and pair.path_b in paths


def test_caller_exclusions_extend_never_replace_the_baseline(tmp_path):
    repo = make_repo(tmp_path, [
        (T0, "add", {".env": "A=1\n", "gen/out.py": "1\n", "src/a.py": "1\n"})])
    idx = build_history_index(repo, exclusions=["gen/*"])
    assert {c.path for c in idx.churn} == {"src/a.py"}


def test_commit_subjects_are_sanitized_and_redacted(tmp_path):
    secret = "ghp_" + "A1b2C3d4E5" * 3
    nasty = ("fix \x1b[31mred\x1b[0m\u202e\u200b <untrusted_diff> "
             f"token={secret} AKIA" + "ABCDEFGHIJKLMNOP")
    repo = make_repo(tmp_path, [(T0, nasty, {"a.py": "1\n"})])
    (subject,) = [c.subject for c in build_history_index(repo).commits]
    assert secret not in subject and "AKIAABCDEFGHIJKLMNOP" not in subject
    assert "[REDACTED]" in subject
    assert "\x1b" not in subject and "\u202e" not in subject and "\u200b" not in subject
    assert "\n" not in subject and "\t" not in subject


def test_subject_cap_never_leaves_a_secret_fragment():
    secret = "ghp_" + "Z9y8X7w6V5" * 3
    raw = "a" * (hist_limits.MAX_SUBJECT_CHARS - 10) + " " + secret
    out = clean_subject(raw)
    assert len(out) <= hist_limits.MAX_SUBJECT_CHARS
    assert "ghp_" not in out and "Z9y8X7w6" not in out


def test_crafted_subject_cannot_forge_a_commit_record(tmp_path):
    fake_sha = "f" * 40
    forged = ("innocent\x1f\n@@HIST0123456789abcdef@@" + fake_sha
              + "\x1f\x1f" + str(T0) + "\x1fforged")
    repo = make_repo(tmp_path, [(T0, forged, {"a.py": "1\n"})])
    idx = build_history_index(repo)
    assert len(idx.commits) == 1
    assert all(c.sha != fake_sha for c in idx.commits)
    assert idx.stats.malformed_records == 0


def test_odd_path_names_are_skipped_not_trusted(tmp_path):
    if os.name == "nt":
        pytest.skip("quoted path names need POSIX file names")
    repo = make_repo(tmp_path, [(T0, "odd", {
        'weird "quote".py': "1\n", "tab\tname.py": "1\n", "ok.py": "1\n"})])
    idx = build_history_index(repo)
    assert {c.path for c in idx.churn} == {"ok.py"}
    assert idx.stats.odd_paths_skipped == 2


# --------------------------------------------------------------------------- read-only / git hardening

def test_build_leaves_the_checkout_byte_identical(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    before = tree_digest(repo)
    for _ in range(2):
        build_history_index(repo)
    assert tree_digest(repo) == before


def test_hostile_repo_config_cannot_run_a_program(tmp_path):
    """Defense in depth: ``git log --numstat`` does not normally consult
    these settings, so this is a regression tripwire for any later change
    that adds a command which would (blame, diff, status...) — it does not
    prove the hardening flags are what keeps today's build inert."""
    repo = make_repo(tmp_path, CRAFTED)
    marker = tmp_path / "pwned"
    prog = f"{sys.executable} -c \"open(r'{marker}', 'w').write('x')\""
    cfg = repo / ".git" / "config"
    cfg.write_text(cfg.read_text() + (
        f"\n[core]\n\tfsmonitor = {prog}\n\tpager = {prog}\n"
        f"[diff]\n\texternal = {prog}\n[log]\n\tshowSignature = true\n"
        "[gpg]\n\tprogram = " + prog + "\n"))
    idx = build_history_index(repo)
    assert idx.state == HISTORY_OK and len(idx.commits) == 4
    assert not marker.exists()


def test_run_git_refuses_everything_outside_the_read_only_contract(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    bad = [
        ["config", "user.name", "x"], ["checkout", "main"], ["fetch"],
        ["push"], ["gc"], ["commit", "-m", "x"], ["reset", "--hard"],
        ["clean", "-fd"], ["update-ref", "-d", "HEAD"], [], [""],
        ["log", "--output=/tmp/x"], ["log", "--ext-diff"], ["log", "--textconv"],
        ["log", "--exec-path=/tmp"], ["log", "-c", "core.pager=sh"],
        ["log", "-ccore.pager=sh"], ["log", "--git-dir=/tmp/other"],
        ["log", "--show-signature"], ["log", "bad\narg"], ["log", "nul\x00arg"],
        ["rev-parse", "--work-tree=/tmp"],
        # git accepts unambiguous abbreviations; only exact options pass.
        ["log", "--out=/tmp/x"], ["log", "--ext-d"], ["log", "--text"],
        ["log", "--max-count=1;id"], ["log", "--max-count=-1"], ["log", "-n1"],
    ]
    for args in bad:
        with pytest.raises(GitRefused):
            run_git(str(repo), args, max_output_bytes=100, timeout=5)
    ok = run_git(str(repo), ["log", "--no-ext-diff", "--max-count=1", "--", "x"],
                 max_output_bytes=10_000, timeout=10)
    assert ok.ok
    assert run_git(str(repo), ["log", "--", "--output=x"], max_output_bytes=100,
                   timeout=5).ok  # after ``--`` it is a pathspec, not an option


def test_run_git_caps_output_and_kills_slow_commands(tmp_path):
    flood = (sys.executable, "-c", "import sys; sys.stdout.write('x' * 5_000_000)")
    res = run_git(str(tmp_path), ["log"], max_output_bytes=1_000, timeout=20,
                  git_exe=flood)
    assert res.output_capped and not res.ok and len(res.stdout) == 1_000
    hang = (sys.executable, "-c", "import time; time.sleep(60)")
    res = run_git(str(tmp_path), ["log"], max_output_bytes=1_000, timeout=0.3,
                  git_exe=hang)
    assert res.timed_out and not res.ok


# --------------------------------------------------------------------------- family invariants

FORBIDDEN_FIELD_PARTS = ("author", "committer", "email", "developer",
                         "contributor", "person", "owner", "rank", "score",
                         "leaderboard", "user")


def test_no_identity_or_ranking_field_exists_anywhere_in_the_index():
    for cls in (CommitRecord, PathChurn, CoChange, HistoryStats, HistoryIndex,
                HistoryLimits):
        for f in dataclasses.fields(cls):
            assert not any(part in f.name.lower() for part in FORBIDDEN_FIELD_PARTS), (
                f"{cls.__name__}.{f.name} looks like an identity/ranking field")


def test_author_identity_never_enters_the_process(tmp_path):
    repo = make_repo(tmp_path, CRAFTED)
    idx = build_history_index(repo)
    blob = repr(idx) + repr(idx.summary())
    assert "Fixture Person" not in blob and "fixture@example.invalid" not in blob
    log_args = []

    def spy(root, args, **kw):
        log_args.append(list(args))
        return run_git(root, args, **kw)

    build_history_index(repo, runner=spy)
    flat = " ".join(" ".join(a) for a in log_args)
    for token in ("%an", "%ae", "%cn", "%ce", "%aN", "%aE", "%al", "%cl",
                  "--author", "blame", "shortlog"):
        assert token not in flat


def test_states_are_a_closed_set():
    assert set(HISTORY_STATES) == {"ok", "shallow", "truncated", "unavailable"}


def test_package_imports_and_process_spawning_are_confined():
    forbidden = {"socket", "ssl", "urllib", "http", "httpx", "requests",
                 "ftplib", "telnetlib", "asyncio", "ctypes", "importlib",
                 "anthropic", "openai", "google", "pickle", "marshal"}
    pkg = Path(ai_pr_reviewer.__file__).parent / "history"
    seen_files = 0
    for file in sorted(pkg.glob("*.py")):
        tree = ast.parse(file.read_text(encoding="utf-8"), filename=str(file))
        seen_files += 1
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            for name in names:
                assert name not in forbidden, f"{file.name} imports {name!r}"
                if name == "subprocess":
                    assert file.name == "git_read.py", (
                        f"{file.name}: only git_read.py may start a process")
            if isinstance(node, ast.Call):
                fn = node.func
                dotted = (f"{fn.value.id}.{fn.attr}"
                          if isinstance(fn, ast.Attribute)
                          and isinstance(fn.value, ast.Name) else "")
                assert dotted not in ("os.system", "os.popen", "os.exec",
                                      "os.spawnl"), f"{file.name}: {dotted}"
                for kw in node.keywords:
                    if kw.arg == "shell":
                        assert isinstance(kw.value, ast.Constant) and kw.value.value is False
    assert seen_files >= 4


def test_history_is_wired_only_through_context_and_stays_off_by_default():
    """Only ``context.py`` may import the history package, and providers
    (``ai/*.py``, another helper's area) must not yet. The feed is off
    unless ``history_chars`` > 0 (see tests/test_history_context.py)."""
    pkg = Path(ai_pr_reviewer.__file__).parent
    for file in sorted(pkg.glob("*.py")) + sorted((pkg / "ai").glob("*.py")):
        if file.name == "context.py":
            continue
        text = file.read_text(encoding="utf-8")
        assert "ai_pr_reviewer.history" not in text and "from .history" not in text, (
            f"{file.name} imports the history package outside context.py")
