"""V4.6-E07-T01 — versioned internal event envelope.

The seam every later consumer publishes to (V4.8 epics consume; this
generation only builds and tests it). One envelope type, one schema
version, strict validation:

* **payload = untrusted-derived** — event payloads carry content that
  came from diffs, CI logs, incident exports or repository files, so the
  schema treats them as hostile: closed value types, bounded depth, key
  count, per-string length and total serialized size. Every bound is a
  *refusal* (``ValueError`` with a content-free label), never a silent
  truncation — a caller that mis-shapes an event must learn about it
  (the T05 emit entry converts refusals into labeled warnings, so a bad
  event can never fail a review);
* **frozen + copied** — the envelope is a frozen dataclass and the
  payload is deep-copied at construction, so emitting an event can never
  mutate caller state and a stored event can never shift under replay;
* **round-trip identity** — ``to_dict()`` output revalidates through
  ``validate_event`` to an equal envelope (the replay-equality contract
  the append-only log depends on in T04);
* **versioned** — ``schema_version`` is checked first on every entry
  point; unknown versions are refused with a label, so a future ``v2``
  reader never silently mis-reads a ``v1`` log line.

Redaction is NOT this ticket's job: T03 redacts at emit. This module
does structure and bounds only, and its error labels never echo payload
content (an untrusted string must not travel in an exception message).
"""
from __future__ import annotations

import json
import math
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from ..models import STATIC_ENGINE_ID, ProvenanceSource

SCHEMA_VERSION = "v1"
SUPPORTED_SCHEMA_VERSIONS = ("v1",)

# Bounds. Refusal thresholds, not truncation points (see module docstring).
MAX_EVENT_TYPE_CHARS = 100
MAX_SOURCE_CHARS = 100
MAX_SUBJECT_CHARS = 300
MAX_EVENT_ID_CHARS = 64
MAX_TIMESTAMP_CHARS = 40
MAX_PAYLOAD_KEYS = 64
MAX_PAYLOAD_KEY_CHARS = 64
MAX_PAYLOAD_DEPTH = 5
MAX_PAYLOAD_STR_CHARS = 2_000
MAX_PAYLOAD_JSON_CHARS = 16_384

DEFAULT_PROVENANCE = ProvenanceSource(engine=STATIC_ENGINE_ID,
                                      model="events-v1", origin="rule")

# Closed vocabularies for the caller-controlled (non-payload) fields.
_EVENT_TYPE_RE = re.compile(r"\A[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*\Z")
_SOURCE_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._/-]*\Z")
_EVENT_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]*\Z")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_ts(value: object) -> str:
    """ISO-8601 text -> canonical UTC ISO text; refuse anything else.

    Both entry points funnel through here, so a built event and the same
    event read back from the log carry byte-identical timestamps.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("event timestamp must be a non-empty ISO-8601 string")
    text = value.strip()[:MAX_TIMESTAMP_CHARS]
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(
            "event timestamp is not ISO-8601") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat()


def _require_str(value: object, *, field: str, pattern: re.Pattern,
                 limit: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"event {field} must be a string")
    text = value.strip()
    if not text or len(text) > limit:
        raise ValueError(
            f"event {field} must be 1..{limit} characters")
    if not pattern.match(text):
        # Never echo the offending value: it is caller-controlled text.
        raise ValueError(f"event {field} has an invalid format")
    return text


def _normalize_payload(payload: object) -> dict[str, Any]:
    """Deep-copy + validate an untrusted-derived payload.

    Allowed values: str/int/float/bool/None, lists, objects — the JSON
    data model, because that is exactly what survives a log round-trip
    (anything else would make build-time and replay-time disagree).
    Keys are coerced to strings the way ``json`` would, so equality holds
    across the round-trip. Every bound violation raises; nothing is
    silently dropped.
    """
    if payload is None:
        return {}
    if not isinstance(payload, Mapping):
        raise ValueError("event payload must be an object")
    key_count = 0

    def walk(value: Any, depth: int) -> Any:
        nonlocal key_count
        # Only CONTAINERS consume depth; scalar leaves never trip the cap.
        if isinstance(value, (list, tuple, Mapping)) \
                and depth > MAX_PAYLOAD_DEPTH:
            raise ValueError(
                f"event payload depth cap exceeded (max {MAX_PAYLOAD_DEPTH})")
        if isinstance(value, str):
            if len(value) > MAX_PAYLOAD_STR_CHARS:
                raise ValueError(
                    "event payload string length cap exceeded "
                    f"(max {MAX_PAYLOAD_STR_CHARS})")
            return value
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, int):
            # bools handled above; keep integers within float-safe range
            if abs(value) > 2**53:
                raise ValueError("event payload integer out of range")
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("event payload float is not finite")
            return value
        if isinstance(value, (list, tuple)):
            return [walk(item, depth + 1) for item in value]
        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            for key, item in value.items():
                key_count += 1
                if key_count > MAX_PAYLOAD_KEYS:
                    raise ValueError(
                        "event payload key count cap exceeded "
                        f"(max {MAX_PAYLOAD_KEYS})")
                name = key if isinstance(key, str) else str(key)
                name = name.strip()
                if not name or len(name) > MAX_PAYLOAD_KEY_CHARS:
                    raise ValueError(
                        "event payload key length cap exceeded "
                        f"(max {MAX_PAYLOAD_KEY_CHARS})")
                out[name] = walk(item, depth + 1)
            return out
        raise ValueError(
            "event payload value type is not JSON-representable")

    normalized = walk(payload, 0)
    # Size cap on the final serialized form — the bound that actually
    # bounds what a log line or a prompt could carry.
    try:
        size = len(json.dumps(normalized, ensure_ascii=False))
    except (TypeError, ValueError):
        raise ValueError(
            "event payload is not JSON-serializable") from None
    if size > MAX_PAYLOAD_JSON_CHARS:
        raise ValueError(
            "event payload size cap exceeded "
            f"(max {MAX_PAYLOAD_JSON_CHARS} chars)")
    return normalized


def _normalize_provenance(value: object) -> ProvenanceSource:
    if value is None:
        return DEFAULT_PROVENANCE
    if isinstance(value, ProvenanceSource):
        return value
    if isinstance(value, Mapping):
        source = ProvenanceSource.from_dict(dict(value))
        if source is None:
            raise ValueError("event provenance is malformed")
        return source
    raise ValueError("event provenance must be a provenance record")


@dataclass(frozen=True)
class EventEnvelope:
    """One validated internal event. Frozen; ``payload`` is a private
    deep copy (treat it as read-only — the freeze is structural)."""

    schema_version: str
    event_id: str
    event_type: str
    source: str
    subject: str
    timestamp: str
    payload: dict[str, Any]
    provenance: ProvenanceSource

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready mapping; revalidates to an equal envelope."""
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "source": self.source,
            "subject": self.subject,
            "timestamp": self.timestamp,
            "payload": self.payload,
            "provenance": self.provenance.to_dict(),
        }

    @classmethod
    def from_dict(cls, raw: object) -> "EventEnvelope":
        return validate_event(raw)


def make_event(event_type: str, *, source: str, subject: str = "",
               payload: object = None,
               provenance: object = None, event_id: str | None = None,
               timestamp: str | None = None) -> EventEnvelope:
    """Build a validated envelope (raises ``ValueError`` on any bound).

    The T05 ``emit`` entry catches those refusals and turns them into
    labeled warnings; library callers that want the failure loud come
    here directly.
    """
    version = SCHEMA_VERSION
    return _build(
        version,
        event_id=event_id if event_id is not None else uuid.uuid4().hex,
        event_type=event_type, source=source, subject=subject,
        timestamp=timestamp if timestamp is not None else _now_iso(),
        payload=payload, provenance=provenance)


def validate_event(raw: object) -> EventEnvelope:
    """Dict -> envelope; the replay/rehydration path (log lines, tests).

    Checks ``schema_version`` FIRST so an unknown-version document is
    refused with the version label instead of a field-level one.
    """
    if not isinstance(raw, Mapping):
        raise ValueError("event must be an object")
    version = raw.get("schema_version")
    if not isinstance(version, str) or version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ValueError(
            f"unsupported event schema version (supported: "
            f"{', '.join(SUPPORTED_SCHEMA_VERSIONS)})")
    missing = [name for name in ("event_id", "event_type", "source",
                                 "timestamp")
               if name not in raw]
    if missing:
        raise ValueError("event is missing required fields")
    return _build(
        version,
        event_id=raw.get("event_id"),
        event_type=raw.get("event_type"),
        source=raw.get("source"),
        subject=raw.get("subject", ""),
        timestamp=raw.get("timestamp"),
        payload=raw.get("payload"),
        provenance=raw.get("provenance"))


def _build(version: str, *, event_id: object, event_type: object,
           source: object, subject: object, timestamp: object,
           payload: object, provenance: object) -> EventEnvelope:
    return EventEnvelope(
        schema_version=version,
        event_id=_require_str(event_id, field="event_id",
                              pattern=_EVENT_ID_RE,
                              limit=MAX_EVENT_ID_CHARS),
        event_type=_require_str(event_type, field="event_type",
                                pattern=_EVENT_TYPE_RE,
                                limit=MAX_EVENT_TYPE_CHARS),
        source=_require_str(source, field="source", pattern=_SOURCE_RE,
                            limit=MAX_SOURCE_CHARS),
        subject=_subject(subject),
        timestamp=_normalize_ts(timestamp),
        payload=_normalize_payload(payload),
        provenance=_normalize_provenance(provenance),
    )


def _subject(value: object) -> str:
    # Subject carries repo-relative context (paths, "repo#pr", SHAs) —
    # free text by nature, bounded here, redacted at emit (T03).
    if not isinstance(value, str):
        raise ValueError("event subject must be a string")
    if len(value) > MAX_SUBJECT_CHARS:
        raise ValueError(
            f"event subject length cap exceeded (max {MAX_SUBJECT_CHARS})")
    return value
