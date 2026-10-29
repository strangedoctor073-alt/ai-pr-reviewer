"""V4.6-E07 — internal event platform v1.

T01: versioned envelope schema — payload is untrusted-derived and every
bound is a labeled refusal, round-trip identity holds (replay
foundation), unknown schema versions are refused first. Fixtures are
deterministic synthetic events; no network, no queue, no worker anywhere
in the package (pinned by the T05 negative architecture test).
"""
from __future__ import annotations

import sys
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ai_pr_reviewer.events import (MAX_PAYLOAD_JSON_CHARS,  # noqa: E402
                                   SCHEMA_VERSION,
                                   SUPPORTED_SCHEMA_VERSIONS,
                                   EventEnvelope, make_event,
                                   validate_event)
from ai_pr_reviewer.events.schema import (MAX_EVENT_ID_CHARS,      # noqa: E402
                                          MAX_EVENT_TYPE_CHARS,
                                          MAX_PAYLOAD_DEPTH,
                                          MAX_PAYLOAD_KEYS,
                                          MAX_PAYLOAD_KEY_CHARS,
                                          MAX_PAYLOAD_STR_CHARS,
                                          MAX_SUBJECT_CHARS, DEFAULT_PROVENANCE)
from ai_pr_reviewer.models import ProvenanceSource                # noqa: E402

MODULE_PATH = ROOT / "ai_pr_reviewer" / "events" / "schema.py"


def _event(**kwargs) -> EventEnvelope:
    kwargs.setdefault("source", "ai_pr_reviewer.test")
    kwargs.setdefault("subject", "acme/api#42")
    kwargs.setdefault("timestamp", "2026-01-15T10:00:00+00:00")
    kwargs.setdefault("event_id", "evt-1")
    return make_event(kwargs.pop("event_type", "review.started"), **kwargs)


# ------------------------------------------------------------- happy path

def test_build_defaults_and_round_trip():
    event = _event(payload={"path": "src/app.py", "count": 2})
    assert event.schema_version == SCHEMA_VERSION == "v1"
    assert event.event_id == "evt-1"
    assert event.provenance == DEFAULT_PROVENANCE
    assert (event.provenance.engine, event.provenance.model,
            event.provenance.origin) == ("static", "events-v1", "rule")

    # to_dict -> validate -> equal envelope (the replay contract T04 uses)
    again = validate_event(event.to_dict())
    assert again == event
    assert again.to_dict() == event.to_dict()


def test_generated_id_and_timestamp_when_omitted():
    event = make_event("review.started", source="s.x",
                       timestamp="2026-01-15T10:00:00+00:00")
    assert len(event.event_id) == 32      # uuid4 hex
    assert all(c in "0123456789abcdef" for c in event.event_id)

    event = make_event("review.started", source="s.x",
                       event_id="e1", timestamp="2026-01-15T10:00:00+00:00")
    assert event.timestamp == "2026-01-15T10:00:00+00:00"

    event = make_event("review.started", source="s.x", event_id="e1")
    assert event.timestamp.endswith("+00:00")        # UTC everywhere


def test_envelope_is_frozen_and_payload_is_a_private_copy():
    payload = {"path": "src/app.py"}
    event = _event(payload=payload)
    with pytest.raises(FrozenInstanceError):
        event.payload = {}
    # mutating the caller's dict after emit can never change the event
    payload["path"] = "attacker/controlled.py"
    payload["extra"] = "x"
    assert event.payload == {"path": "src/app.py"}


# --------------------------------------------------------- schema versioning

@pytest.mark.parametrize("bad_version", ["v2", "V1", 1, None, ""])
def test_unknown_schema_version_is_refused_first(bad_version):
    raw = _event().to_dict()
    raw["schema_version"] = bad_version
    with pytest.raises(ValueError, match="unsupported event schema version"):
        validate_event(raw)


def test_missing_schema_version_is_refused():
    raw = _event().to_dict()
    del raw["schema_version"]
    with pytest.raises(ValueError, match="unsupported event schema version"):
        validate_event(raw)

    with pytest.raises(ValueError, match="unsupported event schema version"):
        validate_event({"event_type": "x"})


def test_non_object_event_is_refused():
    for raw in ([], "event", 7, None):
        with pytest.raises(ValueError, match="must be an object"):
            validate_event(raw)


def test_supported_versions_are_pinned_to_v1():
    assert SUPPORTED_SCHEMA_VERSIONS == ("v1",)


def test_missing_required_fields_are_labeled():
    raw = {"schema_version": "v1"}
    with pytest.raises(ValueError, match="missing required fields"):
        validate_event(raw)
    raw = _event().to_dict()
    del raw["event_type"]
    with pytest.raises(ValueError, match="missing required fields"):
        validate_event(raw)


# ------------------------------------------------------------ field formats

@pytest.mark.parametrize("event_type", [
    "Review Started",          # spaces
    "REVIEW.STARTED",          # upper case
    "review..started",         # empty segment
    ".review",                 # leading separator
    "review started!",         # punctuation
    "",
])
def test_event_type_format_is_closed(event_type):
    with pytest.raises(ValueError):
        make_event(event_type, source="s.x", event_id="e1",
                   timestamp="2026-01-15T10:00:00+00:00")


def test_event_type_over_limit_is_refused():
    with pytest.raises(ValueError, match="1..100"):
        make_event("a" * (MAX_EVENT_TYPE_CHARS + 1), source="s.x",
                   event_id="e1", timestamp="2026-01-15T10:00:00+00:00")


@pytest.mark.parametrize("field,value,match", [
    ("event_id", "bad id!", "invalid format"),
    ("event_id", "a" * (MAX_EVENT_ID_CHARS + 1), "1..64"),
    ("event_id", 7, "must be a string"),
    ("source", "has space", "invalid format"),
    ("source", "", "1..100"),
    ("subject", 42, "must be a string"),
    ("subject", "s" * (MAX_SUBJECT_CHARS + 1), "length cap exceeded"),
])
def test_field_bounds_are_refusals(field, value, match):
    kwargs = {"source": "s.x", "subject": "", "event_id": "e1",
              "timestamp": "2026-01-15T10:00:00+00:00"}
    kwargs[field] = value
    with pytest.raises(ValueError, match=match):
        make_event("review.started", **kwargs)


def test_subject_defaults_to_empty_and_validate_tolerates_absence():
    event = make_event("review.started", source="s.x", event_id="e1",
                       timestamp="2026-01-15T10:00:00+00:00")
    assert event.subject == ""
    raw = event.to_dict()
    del raw["subject"]
    assert validate_event(raw).subject == ""
    # payload is optional on rehydration too (defaults to empty)
    del raw["payload"]
    assert validate_event(raw).payload == {}


# --------------------------------------------------------------- timestamps

@pytest.mark.parametrize("value,expected", [
    ("2026-01-15T12:00:00+02:00", "2026-01-15T10:00:00+00:00"),
    ("2026-01-15T10:00:00Z", "2026-01-15T10:00:00+00:00"),
    ("2026-01-15T10:00:00", "2026-01-15T10:00:00+00:00"),   # naive = UTC
    ("2026-01-15T10:00:00+00:00", "2026-01-15T10:00:00+00:00"),
])
def test_timestamps_normalize_to_utc(value, expected):
    event = _event(timestamp=value)
    assert event.timestamp == expected
    # ...and the normalization is idempotent across the round-trip
    assert validate_event(event.to_dict()).timestamp == expected


@pytest.mark.parametrize("value", ["not-a-date", "", "2026-13-45T99:00:00",
                                   42])
def test_bad_timestamps_are_refused(value):
    with pytest.raises(ValueError, match="timestamp"):
        make_event("review.started", source="s.x", event_id="e1",
                   timestamp=value)


def test_null_timestamp_in_a_stored_event_is_refused():
    # ``timestamp=None`` at BUILD time means "now" (the auto marker); a
    # stored event carrying JSON null must still be refused on replay.
    raw = _event().to_dict()
    raw["timestamp"] = None
    with pytest.raises(ValueError, match="timestamp"):
        validate_event(raw)


# -------------------------------------------------- untrusted-derived payload

def test_payload_must_be_an_object():
    with pytest.raises(ValueError, match="payload must be an object"):
        _event(payload=["not", "an", "object"])
    with pytest.raises(ValueError, match="payload must be an object"):
        _event(payload="raw string")


def test_non_json_values_are_refused():
    for value in (b"bytes", {1, 2}, object(), {"k": b"v"}):
        with pytest.raises(ValueError, match="not JSON-representable"):
            _event(payload={"v": value})


def test_payload_depth_cap_is_a_refusal():
    shallow: dict = {"leaf": 1}
    # exactly MAX_PAYLOAD_DEPTH levels below the top: allowed
    for _ in range(MAX_PAYLOAD_DEPTH):
        shallow = {"n": shallow}
    _event(payload=shallow)

    deep: dict = {"leaf": 1}
    for _ in range(MAX_PAYLOAD_DEPTH + 1):     # one level past the cap
        deep = {"n": deep}
    with pytest.raises(ValueError, match="depth cap exceeded"):
        _event(payload=deep)


def test_payload_key_count_cap_is_a_refusal():
    ok = {f"k{i}": i for i in range(MAX_PAYLOAD_KEYS)}
    _event(payload=ok)                         # exactly at the cap: allowed
    with pytest.raises(ValueError, match="key count cap exceeded"):
        _event(payload={f"k{i}": i for i in range(MAX_PAYLOAD_KEYS + 1)})


def test_payload_string_and_key_length_caps():
    _event(payload={"s": "x" * MAX_PAYLOAD_STR_CHARS})   # at the cap: fine
    with pytest.raises(ValueError, match="string length cap exceeded"):
        _event(payload={"s": "x" * (MAX_PAYLOAD_STR_CHARS + 1)})
    with pytest.raises(ValueError, match="key length cap exceeded"):
        _event(payload={"k" * (MAX_PAYLOAD_KEY_CHARS + 1): 1})
    with pytest.raises(ValueError, match="key length cap exceeded"):
        _event(payload={"  ": 1})               # blank keys refused too


def test_payload_total_size_cap_is_a_refusal():
    with pytest.raises(ValueError, match="size cap exceeded"):
        _event(payload={f"k{i}": "x" * MAX_PAYLOAD_STR_CHARS
                        for i in range(10)})
    assert MAX_PAYLOAD_JSON_CHARS == 16_384


def test_non_finite_numbers_are_refused():
    with pytest.raises(ValueError, match="not finite"):
        _event(payload={"v": float("nan")})
    with pytest.raises(ValueError, match="not finite"):
        _event(payload={"v": float("inf")})
    with pytest.raises(ValueError, match="integer out of range"):
        _event(payload={"v": 2**53 + 1})


def test_key_coercion_and_tuple_normalization_match_json_round_trip():
    event = _event(payload={5: "x", "xs": (1, 2)})
    assert event.payload == {"5": "x", "xs": [1, 2]}
    assert validate_event(event.to_dict()) == event


# --------------------------------------------------------------- provenance

def test_provenance_defaults_and_round_trips():
    custom = ProvenanceSource(engine="static", model="ci_intel",
                              origin="rule", agent="t")
    event = _event(provenance=custom)
    assert event.provenance == custom
    assert validate_event(event.to_dict()).provenance == custom

    # mapping form rehydrates to the same record
    raw = event.to_dict()
    assert validate_event(raw).provenance == custom


def test_malformed_provenance_is_refused():
    with pytest.raises(ValueError, match="provenance"):
        _event(provenance=["not", "a", "record"])
    with pytest.raises(ValueError, match="provenance"):
        _event(provenance="static")


# ------------------------------------------------------------- read-only T01

_BANNED_MODULES = {"subprocess", "socket", "ssl", "urllib", "httpx",
                   "requests", "queue", "threading", "multiprocessing",
                   "concurrent", "asyncio", "pathlib", "os", "io"}
_BANNED_CALLS = {"eval", "exec", "compile", "__import__", "open"}


def _violations(source: str) -> list[str]:
    """T01 is structure-only: no file/process/network access and no
    queue/worker/threading primitives in the schema module."""
    import ast
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
            if name.split(".")[0] in _BANNED_MODULES:
                hits.append(f"import {name}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in _BANNED_CALLS:
            hits.append(f"call {node.func.id}()")
    return hits


def test_schema_module_stays_pure_no_io_no_threads():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert _violations(source) == []

    # self-check: the scan catches what it exists to catch
    assert _violations("import threading\n")
    assert _violations("import queue\nqueue.Queue()\n")
    assert _violations("open('f')\n")
    assert not _violations("import json\njson.dumps({})\n")
