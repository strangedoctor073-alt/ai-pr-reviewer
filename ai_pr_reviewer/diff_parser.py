"""Parse unified diffs (as returned by GitHub's diff endpoints) into structured
per-file hunks with accurate NEW-file line numbers, so findings can be posted
as inline review comments on the right lines."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HunkLine:
    tag: str            # " " context | "+" added | "-" removed | "\\" meta
    old_no: int | None
    new_no: int | None
    text: str


@dataclass
class Hunk:
    old_start: int = 0
    old_count: int = 0
    new_start: int = 0
    new_count: int = 0
    lines: list[HunkLine] = field(default_factory=list)


@dataclass
class FileDiff:
    old_path: str
    new_path: str
    is_new: bool = False
    is_deleted: bool = False
    is_binary: bool = False
    is_rename: bool = False
    hunks: list[Hunk] = field(default_factory=list)

    @property
    def path(self) -> str:
        return self.new_path or self.old_path

    @property
    def additions(self) -> int:
        return sum(1 for h in self.hunks for l in h.lines if l.tag == "+")

    @property
    def deletions(self) -> int:
        return sum(1 for h in self.hunks for l in h.lines if l.tag == "-")

    def new_line_numbers(self) -> set[int]:
        """All line numbers that exist in the new file within these hunks
        (added lines and context lines — the only lines GitHub allows
        inline comments on)."""
        out: set[int] = set()
        for h in self.hunks:
            for l in h.lines:
                if l.tag in ("+", " ") and l.new_no is not None:
                    out.add(l.new_no)
        return out

    def added_lines(self) -> list[tuple[int, str]]:
        """(new_file_line_number, text) for every added line."""
        return [(l.new_no, l.text) for h in self.hunks for l in h.lines
                if l.tag == "+" and l.new_no is not None]

    def to_diff_text(self) -> str:
        """Re-render this file's diff section (used to build LLM prompts)."""
        old = self.old_path or "/dev/null"
        new = self.new_path or "/dev/null"
        out = [f"--- a/{old}", f"+++ b/{new}"]
        for h in self.hunks:
            out.append(f"@@ -{h.old_start},{h.old_count} +{h.new_start},{h.new_count} @@")
            for l in h.lines:
                out.append(l.tag + l.text)
        return "\n".join(out)


def _split_lines(text: str) -> list[str]:
    """Split on ``\\n`` only. ``str.splitlines()`` would also split on form feed,
    NEL, U+2028/2029 and bare ``\\r`` — characters that can legitimately sit
    inside ONE source line — which shifts every later line number in the hunk."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()          # trailing newline, not an extra blank context line
    return lines


def _strip_prefix(path: str) -> str:
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


def parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """Parse a multi-file unified diff. Tolerates `diff --git` headers,
    /dev/null files, renames and binary entries."""
    files: list[FileDiff] = []
    cur: FileDiff | None = None
    cur_hunk: Hunk | None = None
    expect_old = False   # next "---" line is a header
    expect_new = False   # next "+++" line is a header
    old_no = new_no = 0

    lines = _split_lines(diff_text)
    i = 0
    n = len(lines)
    while i < n:
        raw = lines[i]
        line = raw.rstrip("\r")

        if line.startswith("diff --git "):
            paths = line[len("diff --git "):].split()
            old_p, new_p = (paths + ["", ""])[:2]
            cur = FileDiff(old_path=_strip_prefix(old_p), new_path=_strip_prefix(new_p))
            files.append(cur)
            cur_hunk = None
            expect_old = True
            expect_new = False
            i += 1
            continue

        if cur is None:
            # Diff without `diff --git` headers: accept bare ---/+++ pairs.
            if line.startswith("--- ") and not expect_old:
                cur = FileDiff(old_path="", new_path="")
                files.append(cur)
                expect_old = True  # reuse handling below
            else:
                i += 1
                continue

        if expect_old and line.startswith("--- "):
            p = line[4:].split("\t")[0].strip()
            cur.old_path = "" if p == "/dev/null" else _strip_prefix(p)
            expect_old, expect_new = False, True
            i += 1
            continue

        if expect_new and line.startswith("+++ "):
            p = line[4:].split("\t")[0].strip()
            if p == "/dev/null":
                cur.is_deleted = True
                cur.new_path = ""
            else:
                cur.new_path = _strip_prefix(p)
            expect_new = False
            i += 1
            continue

        # File metadata flags (order-independent, between header and first hunk).
        if cur_hunk is None:
            if line.startswith("new file mode"):
                cur.is_new = True
                i += 1
                continue
            if line.startswith("deleted file mode"):
                cur.is_deleted = True
                i += 1
                continue
            if line.startswith("rename from "):
                cur.is_rename = True
                cur.old_path = line[len("rename from "):].strip()
                i += 1
                continue
            if line.startswith("rename to "):
                cur.is_rename = True
                cur.new_path = line[len("rename to "):].strip()
                i += 1
                continue
            if line.startswith("Binary files ") or line.startswith("GIT binary patch"):
                cur.is_binary = True
                i += 1
                continue
            if line.startswith("index ") or line.startswith("similarity ") \
                    or line.startswith("mode "):
                i += 1
                continue
            if line.startswith("@@"):
                cur_hunk = _parse_hunk_header(line)
                if cur_hunk is not None:
                    cur.hunks.append(cur_hunk)
                    old_no = cur_hunk.old_start
                    new_no = cur_hunk.new_start
                i += 1
                continue
            # Unknown metadata or blank line between files.
            i += 1
            continue

        # Inside a hunk: content lines.
        if line.startswith("@@"):
            cur_hunk = _parse_hunk_header(line)
            if cur_hunk is not None:
                cur.hunks.append(cur_hunk)
                old_no = cur_hunk.old_start
                new_no = cur_hunk.new_start
            i += 1
            continue

        if line.startswith("+"):
            cur_hunk.lines.append(HunkLine("+", None, new_no, line[1:]))
            new_no += 1
        elif line.startswith("-"):
            cur_hunk.lines.append(HunkLine("-", old_no, None, line[1:]))
            old_no += 1
        elif line.startswith("\\"):
            cur_hunk.lines.append(HunkLine("\\", None, None, line[1:]))
        elif line.startswith("diff --git"):
            continue  # handled at top of loop next iteration
        else:
            # Context line (starts with a space, or an empty line that lost
            # its leading space to trailing-strip).
            text = line[1:] if line.startswith(" ") else line
            cur_hunk.lines.append(HunkLine(" ", old_no, new_no, text))
            old_no += 1
            new_no += 1
        i += 1

    return [f for f in files if f.hunks or f.is_binary]


def _parse_hunk_header(line: str) -> Hunk | None:
    """Parse `@@ -1,3 +1,4 @@ optional section heading`."""
    import re

    m = re.match(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", line)
    if not m:
        return None
    old_start = int(m.group(1))
    old_count = int(m.group(2)) if m.group(2) is not None else 1
    new_start = int(m.group(3))
    new_count = int(m.group(4)) if m.group(4) is not None else 1
    return Hunk(old_start=old_start, old_count=old_count,
                new_start=new_start, new_count=new_count)


def chunk_files(files: list[FileDiff], max_chars: int = 80_000,
                max_lines_per_file: int = 3_000) -> list[str]:
    """Greedily pack file diffs into prompt batches under a character budget.
    Extremely large files get their added/context lines truncated."""
    batches: list[str] = []
    current: list[str] = []
    size = 0

    for f in files:
        text = f.to_diff_text()
        lines = _split_lines(text)
        truncated = False
        if len(lines) > max_lines_per_file:
            lines = lines[:max_lines_per_file]
            lines.append("... [diff truncated: file too large for review]")
            truncated = True
        text = "\n".join(lines)
        if truncated or len(text) > max_chars:
            # Oversized file: its own batch.
            if current:
                batches.append("\n\n".join(current))
                current, size = [], 0
            batches.append(text)
            continue
        if size + len(text) > max_chars and current:
            batches.append("\n\n".join(current))
            current, size = [], 0
        current.append(text)
        size += len(text) + 2

    if current:
        batches.append("\n\n".join(current))
    return batches


def diff_stats(files: list[FileDiff]) -> dict[str, int]:
    """Totals for a parsed diff: ``{"files": n, "additions": n, "deletions": n}``.

    Works on any ``parse_unified_diff`` result — full-PR or incremental
    (``GitHubClient.compare_commits``) alike. Binary files count as files but
    contribute no additions or deletions.
    """
    return {
        "files": len(files),
        "additions": sum(f.additions for f in files),
        "deletions": sum(f.deletions for f in files),
    }
