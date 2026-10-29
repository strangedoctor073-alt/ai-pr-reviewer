"""V4.6-E07-T04 — append-only local event log with replay.

Internal test/diagnostic data ONLY: the log is never part of the public
report contract (report JSON stays additive-only) and never egresses —
it is a local file whose path the caller passed in. There is no default
location and nothing is written until an ``EventLog`` is constructed
with an explicit path, so flag-OFF runs create no file at all.

Append-only enforcement (pinned by the ``_log_violations`` AST scan):

* the ONLY file-handle mode anywhere in this module is ``"a"`` — open
  for append, write the new line, close. Existing bytes are never
  rewritten, truncated or seeked;
* retention is REFUSAL-based: once ``MAX_LOG_BYTES`` or
  ``MAX_LOG_EVENTS`` is reached, ``append`` refuses with a label and
  leaves the file byte-for-byte untouched. Deleting or rewriting old
  lines would be destructive pruning — it needs human sign-off, so this
  generation simply stops accepting (plan §C.4 gates: size/retention
  caps as refusals);
* ``replay`` revalidates every line through ``validate_event`` (schema
  validation on read): a corrupt or foreign line is skipped with a
  content-free label — one bad line never kills a replay, and everything
  appended through this class replays back equal (replay-equality).

Redaction runs AGAIN at append (idempotent — ``deliver`` already scrubbed
before dispatch): the log's safety must not depend on how it got wired.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .redact import redact_event
from .schema import (MAX_PAYLOAD_JSON_CHARS, EventEnvelope, validate_event)

# Size/retention caps — all refusal thresholds, never truncation points.
MAX_LOG_BYTES = 1_048_576                   # 1 MiB per log file
MAX_LOG_EVENTS = 1_000
# Provably above any legal envelope line: payload JSON is capped at
# MAX_PAYLOAD_JSON_CHARS and re-serialized identically here; the scalar
# fields plus worst-case escaping fit in the remaining 8 KiB headroom.
MAX_EVENT_LOG_LINE_CHARS = MAX_PAYLOAD_JSON_CHARS + 8_192


@dataclass(frozen=True)
class ReplayResult:
    """Replayed envelopes in file order + content-free refusal labels for
    lines that failed JSON or schema validation (line numbers, never
    line content)."""

    events: tuple[EventEnvelope, ...]
    refused: tuple[str, ...]


class EventLog:
    """One append-only JSONL file of validated, redacted envelopes."""

    def __init__(self, path: "str | Path") -> None:
        self.path = Path(path)

    def _line_count(self) -> int:
        return self.path.read_bytes().count(b"\n")

    def append(self, event: object) -> str | None:
        """Append one event. Returns ``None`` on success, a content-free
        refusal label otherwise. NEVER raises — not for invalid input,
        not for a full log, not for an unwritable path."""
        try:
            safe = redact_event(event)
            line = json.dumps(safe.to_dict(), ensure_ascii=False,
                              separators=(",", ":")) + "\n"
        except ValueError as exc:
            return f"event log append refused ({exc})"
        except Exception as exc:            # noqa: BLE001 — log must not raise
            return f"event log append refused ({type(exc).__name__})"

        if len(line.encode("utf-8")) > MAX_EVENT_LOG_LINE_CHARS:
            return "event log append refused (line size cap exceeded)"
        try:
            if self.path.exists():
                # Read-only retention checks: refusal leaves old bytes intact.
                if self.path.stat().st_size >= MAX_LOG_BYTES:
                    return "event log append refused (log byte cap reached)"
                if self.line_count() >= MAX_LOG_EVENTS:
                    return "event log append refused (log event cap reached)"
            # The only handle mode in this module: append (AST-enforced).
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line)
        except OSError as exc:
            return f"event log append refused ({type(exc).__name__})"
        return None

    def line_count(self) -> int:
        return self._line_count() if self.path.exists() else 0

    def replay(self) -> ReplayResult:
        """Read every line back through schema validation. Read-only:
        a corrupt line is skipped with a label, never repaired or
        deleted (rewriting existing bytes would break append-only)."""
        if not self.path.exists():
            return ReplayResult(events=(), refused=())
        try:
            text = self.path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return ReplayResult(events=(), refused=("log unreadable",))
        events: list[EventEnvelope] = []
        refused: list[str] = []
        for number, raw in enumerate(text.splitlines(), start=1):
            if not raw.strip():
                continue
            try:
                decoded: Any = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                refused.append(f"log line {number} skipped (invalid JSON)")
                continue
            try:
                events.append(validate_event(decoded))
            except ValueError as exc:
                refused.append(f"log line {number} skipped ({exc})")
        return ReplayResult(events=tuple(events), refused=tuple(refused))
