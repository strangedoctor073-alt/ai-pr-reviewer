"""V4.4-E01-T01 — the only place the history package runs ``git``.

Hard rules (threat model: repository content is untrusted, nothing from the
checkout is executed):

* **read-only subcommands only** — an allowlist (``log``, ``rev-parse``);
  anything else is refused before a process is created;
* **argument arrays, never a shell** — ``shell`` is never enabled and no
  string is interpolated into a command line;
* **no repository-controlled execution** — textconv/external-diff/
  signature-verification/fsmonitor/hooks are switched off on the command
  line, and system/global git config is ignored, so a hostile ``.git/config``
  or attribute file cannot make ``git log`` run a helper program;
* **bounded** — stdout is read up to a byte cap and the process is killed on
  a wall-clock timeout; stderr is discarded (its text is never surfaced);
* **no network** — no allowlisted subcommand touches a remote.

Everything that can go wrong comes back as a :class:`GitResult` with
``ok=False``; this module does not raise on git failures.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from dataclasses import dataclass

#: Read-only plumbing/porcelain this package may run.
ALLOWED_SUBCOMMANDS = frozenset({"log", "rev-parse"})

#: Options this package may pass. An exact allowlist rather than a denylist:
#: git accepts unambiguous *abbreviations* of long options (``--out`` for
#: ``--output``), so a denylist of dangerous names can be walked around,
#: while anything not listed here is refused outright.
_ALLOWED_OPTIONS = frozenset({
    "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
    "--numstat", "--no-merges", "--first-parent",
    "--verify", "--quiet", "--is-shallow-repository", "--git-path",
})
#: ``--name=value`` options and the shape their value must have. ``--format``
#: carries only a format string built by this package (no command execution
#: is possible through a pretty-format string).
_ALLOWED_VALUE_OPTIONS = {
    "--max-count": re.compile(r"^[0-9]{1,9}$"),
    "--skip": re.compile(r"^[0-9]{1,9}$"),
    "--format": re.compile(r"^[^\x00]{1,512}$"),
}

#: ``-c`` pairs placed before the subcommand. Each closes one way a
#: repository-local config could execute a program during ``git log``.
_HARDENING_CONFIG = (
    "core.quotepath=false",
    "core.fsmonitor=false",
    "core.hooksPath=" + os.devnull,
    "diff.external=",
    "log.showSignature=false",
    "gc.auto=0",
)


class GitRefused(ValueError):
    """The requested command violates the read-only contract (a bug in the
    caller, not an environment failure)."""


@dataclass(frozen=True)
class GitResult:
    ok: bool
    stdout: bytes = b""
    #: stdout hit the byte cap and the process was stopped.
    output_capped: bool = False
    timed_out: bool = False
    #: git could not be started at all (not installed / not executable).
    unavailable: bool = False
    returncode: int | None = None


def find_git() -> str | None:
    """Absolute path of the ``git`` executable, or ``None``."""
    return shutil.which("git")


def _validate_args(args) -> list[str]:
    cleaned: list[str] = []
    for arg in args:
        if not isinstance(arg, str):
            raise GitRefused("git arguments must be strings")
        if "\x00" in arg or "\n" in arg or "\r" in arg:
            # ``--format`` values carry no raw newlines either: separators
            # are expressed as ``%x1f`` escapes that git expands itself.
            raise GitRefused("git argument contains a control character")
        cleaned.append(arg)
    if not cleaned or cleaned[0] not in ALLOWED_SUBCOMMANDS:
        raise GitRefused(
            f"git subcommand not allowed: {cleaned[0] if cleaned else ''!r}")
    for arg in cleaned[1:]:
        if arg == "--":
            break  # everything after is a pathspec, never an option
        if not arg.startswith("-"):
            continue  # a revision (``HEAD``) or an option's argument
        name, eq, value = arg.partition("=")
        if eq and name in _ALLOWED_VALUE_OPTIONS:
            if not _ALLOWED_VALUE_OPTIONS[name].match(value):
                raise GitRefused(f"git option value not allowed: {name!r}")
        elif arg not in _ALLOWED_OPTIONS:
            raise GitRefused(f"git option not allowed: {name!r}")
    return cleaned


def _clean_env() -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", ""),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "XDG_CONFIG_HOME": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_PAGER": "cat",
    }
    for key in ("SYSTEMROOT", "TEMP", "TMP", "TMPDIR", "LANG"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def run_git(root: str, args, *, max_output_bytes: int, timeout: float,
            git_exe=None) -> GitResult:
    """Run one allowlisted read-only ``git`` command inside ``root``.

    ``git_exe`` is a test seam: an executable path or an argv prefix
    replacing the real ``git`` (the safety checks still run first). Raises
    :class:`GitRefused` only for a contract violation by the caller.
    """
    cleaned = _validate_args(args)
    exe = git_exe if git_exe is not None else find_git()
    if exe is None:
        return GitResult(ok=False, unavailable=True)
    prefix = [exe] if isinstance(exe, str) else [str(p) for p in exe]
    cmd = [*prefix, "--no-pager", "-C", root]
    for pair in _HARDENING_CONFIG:
        cmd += ["-c", pair]
    cmd += cleaned

    try:
        proc = subprocess.Popen(  # noqa: S603 — argv list, allowlisted
            cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=_clean_env(), shell=False)
    except OSError:
        return GitResult(ok=False, unavailable=True)

    buf = bytearray()
    state = {"capped": False}

    def _pump() -> None:
        stream = proc.stdout
        try:
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    return
                room = max_output_bytes - len(buf)
                if len(chunk) > room:
                    buf.extend(chunk[:max(room, 0)])
                    state["capped"] = True
                    _kill(proc)
                    return
                buf.extend(chunk)
        except (OSError, ValueError):
            return

    reader = threading.Thread(target=_pump, daemon=True)
    reader.start()
    reader.join(timeout)
    timed_out = reader.is_alive()
    if timed_out:
        _kill(proc)
        reader.join(2.0)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        _kill(proc)
    returncode = proc.returncode
    stopped = timed_out or state["capped"]
    return GitResult(
        ok=(returncode == 0) and not stopped,
        stdout=bytes(buf), output_capped=state["capped"],
        timed_out=timed_out, returncode=returncode)


def _kill(proc: subprocess.Popen) -> None:
    try:
        proc.kill()
    except OSError:
        pass
