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


# ============================================================ V4.6-E07-T02
# In-process dispatcher: bounded pending buffer, backpressure (drop-newest,
# counted), FIFO non-recursive delivery, handler quarantine. Zero threads,
# zero queue-module use — plain lists only.

from ai_pr_reviewer.events.bus import (MAX_DRAIN_STEPS,      # noqa: E402
                                       MAX_PENDING_EVENTS,
                                       MAX_SUBSCRIBERS,
                                       EventBus)

BUS_MODULE_PATH = ROOT / "ai_pr_reviewer" / "events" / "bus.py"


def test_fan_out_is_fifo_in_subscription_order():
    bus = EventBus()
    order: list[tuple[str, str]] = []
    bus.subscribe(lambda ev: order.append(("a", ev.event_id)))
    bus.subscribe(lambda ev: order.append(("b", ev.event_id)))
    bus.emit(_event(event_id="e1"))
    bus.emit(_event(event_id="e2"))
    assert order == [("a", "e1"), ("b", "e1"), ("a", "e2"), ("b", "e2")]
    assert bus.pending_count == 0
    assert bus.stats.to_dict() == {"events": 2, "deliveries": 4,
                                   "dropped": 0, "quarantined": 0}


def test_duplicate_subscription_is_idempotent_and_unsubscribe_is_safe():
    bus = EventBus()
    seen: list[str] = []

    def handler(ev):
        seen.append(ev.event_id)

    bus.subscribe(handler)
    bus.subscribe(handler)
    assert bus.subscriber_count == 1

    bus.emit(_event(event_id="e1"))
    assert seen == ["e1"]

    bus.unsubscribe(handler)
    bus.unsubscribe(handler)                 # unknown handler: no-op
    assert bus.subscriber_count == 0
    bus.emit(_event(event_id="e2"))
    assert seen == ["e1"]


def test_subscriber_cap_is_a_refusal():
    bus = EventBus()
    handlers = []

    def make(i):
        def handler(ev):
            pass
        handlers.append(handler)
        return handler

    for _ in range(MAX_SUBSCRIBERS):
        bus.subscribe(make(0))
    assert bus.subscriber_count == MAX_SUBSCRIBERS
    with pytest.raises(ValueError, match="subscriber cap"):
        bus.subscribe(make(0))

    with pytest.raises(TypeError, match="callable"):
        bus.subscribe("not callable")


def test_bus_only_accepts_validated_envelopes():
    bus = EventBus()
    with pytest.raises(ValueError, match="EventEnvelope"):
        bus.emit("review.started")
    with pytest.raises(ValueError, match="EventEnvelope"):
        bus.emit({"event_type": "review.started"})


def test_reentrant_emit_is_fifo_and_never_recurses():
    bus = EventBus()
    seen: list[str] = []
    depth = [0]
    max_depth = [0]

    def handler(ev):
        depth[0] += 1
        max_depth[0] = max(max_depth[0], depth[0])
        seen.append(ev.event_id)
        if ev.event_id == "first":
            bus.emit(_event(event_id="second"))
        depth[0] -= 1

    bus.subscribe(handler)
    bus.emit(_event(event_id="first"))
    # the re-entrant event is buffered and delivered after the current
    # dispatch completes — delivery depth is always 1
    assert seen == ["first", "second"]
    assert max_depth[0] == 1
    assert bus.pending_count == 0


def test_backpressure_drops_newest_and_counts_exactly():
    bus = EventBus()
    seen: list[str] = []
    flooded = [False]

    def handler(ev):
        if not flooded[0]:
            flooded[0] = True
            for i in range(MAX_PENDING_EVENTS + 6):
                bus.emit(_event(event_id=f"flood-{i}"))
        else:
            seen.append(ev.event_id)

    bus.subscribe(handler)
    bus.emit(_event(event_id="seed"))
    # buffer held MAX_PENDING_EVENTS; the 6 newest were dropped+counted
    assert bus.stats.dropped == 6
    assert bus.pending_count == 0
    assert len(seen) == MAX_PENDING_EVENTS
    assert seen[0] == "flood-0"


def test_raising_handler_is_quarantined_and_delivery_continues():
    bus = EventBus()
    good: list[str] = []
    bad_calls: list[str] = []

    def bad(ev):
        bad_calls.append(ev.event_id)
        raise RuntimeError("boom")

    def ok(ev):
        good.append(ev.event_id)

    bus.subscribe(bad)
    bus.subscribe(ok)
    bus.emit(_event(event_id="e1"))
    # the failure never reached the emitter, and `ok` still got the event
    assert good == ["e1"]
    assert bus.stats.quarantined == 1
    assert bus.subscriber_count == 1

    bus.emit(_event(event_id="e2"))
    assert bad_calls == ["e1"]               # quarantined: never again
    assert good == ["e1", "e2"]
    assert bus.stats.quarantined == 1
    assert bus.stats.deliveries == 2         # only successful invocations


def test_emit_work_is_bounded_with_a_self_feeding_handler():
    bus = EventBus()

    def chatty(ev):
        bus.emit(_event(event_id=(ev.event_id + "x")[:60]))

    bus.subscribe(chatty)
    bus.emit(_event(event_id="s"))
    # one emit() ran a bounded slice of work, then returned with the
    # re-fed event still buffered — no livelock, no unbounded growth
    assert bus.stats.events == MAX_DRAIN_STEPS
    assert bus.pending_count == 1
    assert bus.stats.dropped == 0            # one in, one out: never full


def test_bus_module_stays_free_of_queue_worker_thread_symbols():
    assert _violations(BUS_MODULE_PATH.read_text(encoding="utf-8")) == []
    assert _violations("import queue\n")     # self-check (shared scanner)


# ============================================================ V4.6-E07-T03
# Redaction-on-emit + schema validation at one chokepoint: every string
# leaving through an event is scrubbed, invalid/unredactable events are
# DROPPED with content-free labels, and deliver() never raises.

from ai_pr_reviewer.events.redact import deliver, redact_event  # noqa: E402

REDACT_MODULE_PATH = ROOT / "ai_pr_reviewer" / "events" / "redact.py"

# One credential per redact_secrets pattern family (same corpus discipline
# as the incident/infra tickets): none may reach a subscriber.
LEAK_CORPUS = {
    "aws": "AKIA" + "ABCDEFGHIJKLMNOP",
    "gh": "ghp_" + "Abcdefghijklmnopqrstuvwxyz012345",
    "sk": "sk-" + "abcdefghijkmnopqrstuvwxyz012345",
    "slack": "xoxb-abcdefghij-1234567890",
    "google": "AIza" + "SyA" * 10 + "abc",
    "bearer": "bearer " + "A" * 30,
    "kv": "password: hunter2hunter2",
    "db": "postgres://user:secretpass99@db:5432/x",
}


def test_free_text_fields_are_redacted_before_dispatch():
    bus = EventBus()
    received: list[EventEnvelope] = []
    bus.subscribe(received.append)

    payload = {f"field_{i}": tok for i, tok in enumerate(LEAK_CORPUS.values())}
    payload["ghp_Abcdefghijklmnopqrstuvwxyz012345"] = "key token"  # token key
    event = _event(subject=f"leak {' '.join(LEAK_CORPUS.values())}",
                   payload=payload)

    assert deliver(bus, event) is None
    assert len(received) == 1
    got = received[0]
    blob = got.subject + str(got.payload)
    for tok in LEAK_CORPUS.values():
        assert tok not in blob
    assert "[REDACTED]" in got.subject
    assert "[REDACTED]" in got.payload          # the token key collapsed too
    # the delivered envelope still satisfies the schema (replay contract)
    assert validate_event(got.to_dict()) == got
    # ...and the caller's original event was never mutated
    assert LEAK_CORPUS["aws"] in event.subject


def test_configured_scrub_layers_after_pattern_redaction():
    token = "hunter2hunter2hunter2"     # matches no redact_secrets pattern
    event = _event(payload={"secret": token},
                   provenance=ProvenanceSource(engine="static",
                                               model=token))
    # pattern redaction alone leaves the configured credential alone...
    assert redact_event(event).payload["secret"] == token
    # ...the scrub layer removes it from payload AND provenance
    got = redact_event(event,
                       scrub=lambda t: t.replace(token, "[REDACTED]"))
    assert got.payload["secret"] == "[REDACTED]"
    assert got.provenance.model == "[REDACTED]"


def test_credential_shaped_closed_vocab_field_is_dropped_not_emitted():
    """A token that VALIDLY builds (source format allows alnum) must be
    refused after redaction, because '[REDACTED]' is not a valid source:
    drop-with-label beats emitting it unredacted."""
    bus = EventBus()
    received: list[EventEnvelope] = []
    bus.subscribe(received.append)

    event = make_event("review.started", source=LEAK_CORPUS["aws"],
                       event_id="e1",
                       timestamp="2026-01-15T10:00:00+00:00")
    label = deliver(bus, event)
    assert isinstance(label, str)
    assert label.startswith("event dropped (")
    assert LEAK_CORPUS["aws"] not in label       # content-free label
    assert received == []                        # nothing left unredacted


def test_deliver_accepts_raw_dicts_through_schema_validation():
    bus = EventBus()
    received: list[EventEnvelope] = []
    bus.subscribe(received.append)
    raw = _event(payload={"path": "src/app.py"}).to_dict()
    assert deliver(bus, raw) is None
    assert len(received) == 1
    assert received[0].payload == {"path": "src/app.py"}


def test_deliver_never_raises_and_labels_do_not_echo_content():
    bus = EventBus()
    received: list[EventEnvelope] = []
    bus.subscribe(received.append)

    good = _event().to_dict()
    unknown_version = dict(good, schema_version="v9",
                           payload={"marker": "hunter2"})
    missing = {"schema_version": "v1"}
    hostile_payload = dict(good, payload={"v": b"bytes-MARKER-01"})
    deep: dict = {"leaf": 1}
    for _ in range(8):
        deep = {"n": deep}

    for bad in ([], "event", 7, None, {}, unknown_version, missing,
                hostile_payload, dict(good, payload=[1, 2]),
                dict(good, payload={"v": deep}),
                dict(good, event_type="Bad Type"),
                dict(good, timestamp="not-a-date")):
        label = deliver(bus, bad)
        assert isinstance(label, str) and label.startswith("event dropped (")
        # no untrusted content may travel in the warning
        assert "hunter2" not in label and "MARKER" not in label
    assert received == []                        # every refusal dropped


def test_hex_runs_in_payload_are_redacted_like_report_output():
    """Deliberate: subscribers see post-redaction content only, so a
    40-hex SHA in a payload is treated exactly like report output."""
    bus = EventBus()
    received: list[EventEnvelope] = []
    bus.subscribe(received.append)
    sha = "a" * 40
    assert deliver(bus, _event(payload={"head_sha": sha,
                                        "msg": f"change {sha} done"})) is None
    assert received[0].payload["head_sha"] == "[REDACTED]"
    assert sha not in received[0].payload["msg"]


def test_redaction_is_identity_for_clean_events_and_idempotent():
    event = _event(payload={"path": "src/app.py", "count": 2})
    once = redact_event(event)
    assert once == event                         # clean content unchanged
    assert redact_event(once) == once            # idempotent


def test_payload_key_collision_after_redaction_is_a_refusal():
    tok_a = "ghp_" + "Abcdefghijklmnopqrstuvwxyz012345"
    tok_b = "ghp_ZYXWVUTSRQPONMLKJIHGFEDCBA9876543210"
    event = _event(payload={tok_a: 1, tok_b: 2})
    with pytest.raises(ValueError, match="collision after redaction"):
        redact_event(event)
    bus = EventBus()
    assert deliver(bus, event) == \
        "event dropped (event payload key collision after redaction)"


def test_bus_disabled_path_still_validates_and_labels():
    # bus=None: no dispatch attempted, the safety half still runs
    assert deliver(None, _event(payload={"ok": 1})) is None
    assert isinstance(deliver(None, {"schema_version": "v9"}), str)


def test_redact_module_stays_free_of_queue_worker_io_symbols():
    assert _violations(REDACT_MODULE_PATH.read_text(encoding="utf-8")) == []


# ============================================================ V4.6-E07-T04
# Subscriber contracts (self-contained telemetry/analytics/dashboard-sync
# reference sinks — no edits to the real modules) + append-only JSONL log:
# append-mode-only AST enforcement, refusal-based retention that never
# rewrites bytes, replay-equality, and zero coupling to reporter/telemetry/
# dashboard modules (the event log is internal, never public report data).

from ai_pr_reviewer.events import log as log_module        # noqa: E402
from ai_pr_reviewer.events.log import (MAX_EVENT_LOG_LINE_CHARS,  # noqa: E402
                                       MAX_LOG_BYTES, MAX_LOG_EVENTS,
                                       EventLog)
from ai_pr_reviewer.events.subscribers import (MAX_SINK_KEYS,  # noqa: E402
                                               MAX_SYNC_BUFFER,
                                               SUBSCRIBER_CONTRACT,
                                               AnalyticsSink,
                                               DashboardSyncSink,
                                               LogSubscriber,
                                               TelemetrySink)

DESTRUCTIVE_CALLS = {"write_text", "write_bytes", "unlink", "rename",
                     "replace", "truncate", "mkdir", "rmdir", "touch",
                     "remove"}
_IO_BANNED_MODULES = {"queue", "threading", "multiprocessing", "concurrent",
                      "asyncio", "socket", "subprocess", "ssl", "urllib",
                      "httpx", "requests", "os", "io"}


def _log_violations(source: str) -> list[str]:
    """Append-only contract: the ONLY handle mode is ``"a"`` (visible at
    the call site as a constant), no destructive path call, no
    queue/worker/network import."""
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
            if name.split(".")[0] in _IO_BANNED_MODULES:
                hits.append(f"import {name}")
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "open":
            hits.append("builtin open() (mode must be visible at call site)")
        elif isinstance(func, ast.Attribute):
            if func.attr == "open":
                mode_ok = False
                if node.args:
                    first = node.args[0]
                    if isinstance(first, ast.Constant) \
                            and isinstance(first.value, str):
                        mode = first.value
                        mode_ok = mode.startswith("a") and not any(
                            c in mode for c in "wrx+")
                if not mode_ok:
                    hits.append("open() without a plain append mode")
            elif func.attr in DESTRUCTIVE_CALLS:
                hits.append(f"destructive call {func.attr}()")
    return hits


def test_log_module_is_append_only_no_rewrite_no_delete():
    source = (ROOT / "ai_pr_reviewer" / "events" / "log.py").read_text(
        encoding="utf-8")
    assert _log_violations(source) == []

    # self-check: every shape the contract exists to catch is caught
    assert _log_violations('p.open("w")\n')
    assert _log_violations('p.open("a+")\n')
    assert _log_violations('p.open("r")\n')
    assert _log_violations('p.write_text("x")\n')
    assert _log_violations('p.unlink()\n')
    assert _log_violations('open("a")\n')
    assert _log_violations('import threading\n')
    # ...and the legal shapes stay legal
    assert not _log_violations('p.open("a", encoding="utf-8")\n')
    assert not _log_violations('p.read_text(encoding="utf-8")\n')
    assert not _log_violations('import json\nfrom pathlib import Path\n')


def test_log_append_never_rewrites_existing_bytes(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    assert log.append(_event(event_id="a")) is None
    first_bytes = path.read_bytes()
    assert log.append(_event(event_id="b")) is None
    second_bytes = path.read_bytes()
    # the first line is byte-for-byte untouched; the new line only appends
    assert second_bytes[:len(first_bytes)] == first_bytes
    assert second_bytes.count(b"\n") == 2
    assert log.line_count() == 2


def test_replay_equality_for_both_append_paths(tmp_path):
    originals = [_event(event_id=f"e{i}",
                        payload={"i": i, "path": f"src/f{i}.py"})
                 for i in range(3)]

    # path 1: deliver -> bus -> LogSubscriber
    log = EventLog(tmp_path / "bus.jsonl")
    bus = EventBus()
    bus.subscribe(LogSubscriber(log))
    for event in originals:
        assert deliver(bus, event) is None
    result = log.replay()
    assert result.refused == ()
    assert result.events == tuple(originals)

    # path 2: direct append (redaction runs again — idempotent here)
    direct = EventLog(tmp_path / "direct.jsonl")
    for event in originals:
        assert direct.append(event) is None
    assert direct.replay().events == tuple(originals)


def test_log_redacts_even_when_wired_without_deliver(tmp_path):
    """Defense in depth: append scrubs on its own, so the log is safe no
    matter how it got wired (deliver already scrubbed before dispatch)."""
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    token = LEAK_CORPUS["gh"]
    assert log.append(_event(subject=f"leak {token}",
                             payload={"v": token})) is None
    replayed = log.replay().events[0]
    assert token not in replayed.subject
    assert token not in str(replayed.payload)
    assert "[REDACTED]" in replayed.subject


def test_replay_skips_corrupt_lines_with_content_free_labels(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    log.append(_event(event_id="a"))
    log.append(_event(event_id="b"))
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    lines.insert(1, "\n")                          # blank: skipped silently
    lines.insert(2, "NOT-JSON-MARKER{\n")          # corrupt: labeled
    lines.insert(3, '{"schema_version": "v9"}\n')  # wrong version: labeled
    path.write_text("".join(lines), encoding="utf-8")

    result = log.replay()
    assert [e.event_id for e in result.events] == ["a", "b"]
    assert len(result.refused) == 2
    assert result.refused[0].startswith(
        "log line 3 skipped (invalid JSON")
    assert result.refused[1].startswith(
        "log line 4 skipped (unsupported event schema version")
    joined = "".join(result.refused)
    assert "MARKER" not in joined and "v9" not in joined

    # replay is read-only: the corrupt line is still there afterwards
    assert "NOT-JSON-MARKER" in path.read_text(encoding="utf-8")


def test_retention_caps_refuse_without_touching_existing_bytes(
        tmp_path, monkeypatch):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    assert log.append(_event(event_id="e1")) is None

    monkeypatch.setattr(log_module, "MAX_LOG_EVENTS", 1)
    before = path.read_bytes()
    label = log.append(_event(event_id="e2"))
    assert label == "event log append refused (log event cap reached)"
    assert path.read_bytes() == before            # byte-for-byte untouched

    monkeypatch.setattr(log_module, "MAX_LOG_EVENTS", 1_000)
    monkeypatch.setattr(log_module, "MAX_LOG_BYTES", 1)
    label = log.append(_event(event_id="e3"))
    assert label == "event log append refused (log byte cap reached)"
    assert path.read_bytes() == before

    # caps are refusal thresholds, not tunables hiding in env/config
    assert MAX_LOG_BYTES == 1_048_576 and MAX_LOG_EVENTS == 1_000


def test_line_size_cap_refuses_but_a_max_payload_event_fits(tmp_path,
                                                             monkeypatch):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    # a payload at the schema cap still fits the log's headroom (per-string
    # cap is 2_000, so the bulk rides on multiple keys)
    big = {f"k{i}": "y" * 1_950 for i in range(8)}
    assert log.append(_event(payload=big)) is None
    line = path.read_text(encoding="utf-8").splitlines()[0]
    assert len(line) > 15_000
    assert len(line) < MAX_EVENT_LOG_LINE_CHARS

    # mechanism: any line over the cap is refused, never truncated
    monkeypatch.setattr(log_module, "MAX_EVENT_LOG_LINE_CHARS", 50)
    before = path.read_bytes()
    label = log.append(_event(event_id="tiny"))
    assert label == "event log append refused (line size cap exceeded)"
    assert path.read_bytes() == before


def test_append_and_replay_never_raise_on_hostile_or_unwritable_input(
        tmp_path):
    log = EventLog(tmp_path / "ok.jsonl")
    for bad in ("garbage", [], None, 7, {"schema_version": "v9"},
                {"event_type": "x"}):
        assert isinstance(log.append(bad), str)
    assert log.line_count() == 0                  # nothing written

    # unwritable: parent directory does not exist -> label, no file
    missing = EventLog(tmp_path / "nope" / "events.jsonl")
    assert isinstance(missing.append(_event()), str)
    assert not (tmp_path / "nope").exists()

    # a path that IS a directory -> label (OSError), never a traceback
    as_dir = EventLog(tmp_path)
    assert isinstance(as_dir.append(_event()), str)

    # replay counterparts: absent file = empty result, unreadable = label
    assert missing.replay().events == ()
    assert as_dir.replay().refused == ("log unreadable",)


def test_subscriber_contract_is_data_and_sinks_are_bounded():
    assert isinstance(SUBSCRIBER_CONTRACT, tuple) and SUBSCRIBER_CONTRACT
    assert all(isinstance(rule, str) and rule for rule in SUBSCRIBER_CONTRACT)
    for sink in (TelemetrySink(), AnalyticsSink(), DashboardSyncSink()):
        assert callable(sink)

    # bounded key caps with counted overflow (contract rule 4)
    telemetry = TelemetrySink()
    analytics = AnalyticsSink()
    for i in range(MAX_SINK_KEYS + 10):
        event = _event(event_type=f"t{i}.x", event_id=f"e{i}")
        telemetry(event)
        analytics(event)
    assert len(telemetry.rows()) == MAX_SINK_KEYS
    assert telemetry.overflow == 10
    assert telemetry.total == MAX_SINK_KEYS
    assert len(analytics.rows()) == MAX_SINK_KEYS
    assert analytics.overflow == 10


def test_reference_sink_rows_are_deterministic_across_runs():
    events = [_event(event_id=f"e{i}", event_type=("review.started" if i % 2
                                                   else "review.finished"),
                     subject=f"acme/api#{i % 3}",
                     timestamp=f"2026-01-15T10:00:{i:02d}+00:00")
              for i in range(6)]

    def run():
        t, a = TelemetrySink(), AnalyticsSink()
        for event in events:
            t(event)
            a(event)
        return t.rows(), a.rows()

    first, second = run(), run()
    assert first == second                          # sorted, hash-seed safe
    t = TelemetrySink()
    for event in events:
        t(event)
    assert t.rows() == [{"event_type": "review.finished", "count": 3},
                        {"event_type": "review.started", "count": 3}]


def test_dashboard_sync_buffer_drops_newest_and_snapshots_scalars_only():
    sink = DashboardSyncSink()
    for i in range(MAX_SYNC_BUFFER + 3):
        sink(_event(event_id=f"e{i}"))
    assert sink.pending == MAX_SYNC_BUFFER
    assert sink.dropped == 3                       # drop-newest, counted

    snapshot = sink.snapshot()
    assert len(snapshot) == MAX_SYNC_BUFFER
    assert [row["event_id"] for row in snapshot] == \
        [f"e{i}" for i in range(MAX_SYNC_BUFFER)]  # chronological order
    for row in snapshot:
        # payload never rides along in a dashboard row (untrusted content
        # stays behind the subscriber; a consumer needing it reads the log)
        assert set(row) == {"event_id", "event_type", "source", "subject",
                            "timestamp"}
        assert "payload" not in row
    # snapshot is a copy: mutating it cannot touch the sink
    snapshot[0]["event_type"] = "tampered"
    assert sink.snapshot()[0]["event_type"] == "review.started"


def test_all_reference_subscribers_survive_delivered_leak_events(tmp_path):
    bus = EventBus()
    telemetry, analytics, dashboard = TelemetrySink(), AnalyticsSink(), \
        DashboardSyncSink()
    log = EventLog(tmp_path / "events.jsonl")
    log_sink = LogSubscriber(log)
    for sink in (telemetry, analytics, dashboard, log_sink):
        bus.subscribe(sink)

    payload = {f"field_{i}": tok for i, tok in enumerate(LEAK_CORPUS.values())}
    assert deliver(bus, _event(subject=" ".join(LEAK_CORPUS.values()),
                               payload=payload)) is None
    assert telemetry.total == 1
    assert analytics.rows()[0]["count"] == 1
    assert dashboard.pending == 1
    assert log_sink.labels == []                  # log accepted
    replayed = log.replay().events[0]
    blob = replayed.subject + str(replayed.payload)
    for token in LEAK_CORPUS.values():
        assert token not in blob                  # subscribers saw redacted


def test_events_package_never_imports_public_contract_modules():
    """The event log/sinks are internal: reporter (H4), telemetry and the
    dashboard (H2) stay untouched by this epic — the plan's exit criterion
    that the event log is never part of the public report contract."""
    import ast
    forbidden = {"reporter", "dashboard", "telemetry"}
    hits: list[str] = []
    for path in sorted((ROOT / "ai_pr_reviewer" / "events").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                # module + alias names: `from ai_pr_reviewer import
                # telemetry` hides the target in the ALIAS, not the module
                names = [node.module or ""] + [a.name for a in node.names]
            else:
                names = []
            for name in names:
                if any(part in forbidden for part in name.split(".")):
                    hits.append(f"{path.name}: {name}")
    assert hits == []

    # self-check: relative and absolute forms are both caught
    for snippet, expected in (("from .. import reporter", True),
                              ("import dashboard.app", True),
                              ("from ai_pr_reviewer import telemetry", True),
                              ("from ..schema import EventEnvelope", False)):
        node = ast.parse(snippet).body[0]
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        else:
            names = [node.module or ""] + [a.name for a in node.names]
        hit = any(any(p in forbidden for p in n.split("."))
                  for n in names)
        assert hit is expected


# ============================================================ V4.6-E07-T05
# Module-level emit() with the EVENT_BUS flag (plain env, default OFF),
# synchronous delivery, bus-disabled equivalence, and the negative
# architecture pin: this generation adds ZERO queue/worker symbols.

from ai_pr_reviewer.cli import parse_args                    # noqa: E402
from ai_pr_reviewer.config import Config, load_config        # noqa: E402
from ai_pr_reviewer.events import emit as emit_module        # noqa: E402
from ai_pr_reviewer.events.emit import bus_for, emit, get_bus  # noqa: E402

# Pre-existing threading/worker use, pinned as the exact baseline: the
# plan's zero-queue/worker criterion is a NEW-occurrence rule (removing
# someone else's sanctioned thread is out of scope for this epic, too —
# flag it, don't fix it). Any entry outside this set fails the test;
# queue/asyncio/multiprocessing currently have ZERO occurrences, so the
# first one anywhere is a new occurrence by construction.
_WORKER_BASELINE = frozenset({
    ("ai_pr_reviewer/circuit.py", "import threading"),
    ("ai_pr_reviewer/history/git_read.py", "call Thread"),
    ("ai_pr_reviewer/history/git_read.py", "import threading"),
    ("ai_pr_reviewer/orchestration/executor.py", "call ThreadPoolExecutor"),
    ("ai_pr_reviewer/orchestration/executor.py", "import concurrent"),
    ("ai_pr_reviewer/provider_registry.py", "import threading"),
    ("dashboard/app.py", "import threading"),
    ("dashboard/feedback_store.py", "import threading"),
    ("dashboard/storage.py", "import threading"),
})

_WORKER_SYMBOLS = {"Thread", "ThreadPoolExecutor", "ProcessPoolExecutor",
                   "Queue", "SimpleQueue", "create_task", "ensure_future",
                   "Process"}
_WORKER_MODULES = {"threading", "queue", "asyncio", "multiprocessing",
                   "concurrent"}


def _worker_scan(rel: str, source: str) -> set[tuple[str, str]]:
    import ast
    hits: set[tuple[str, str]] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            names = [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        else:
            names = []
        for name in names:
            top = name.split(".")[0]
            if top in _WORKER_MODULES:
                hits.add((rel, f"import {top}"))
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name) and func.id in _WORKER_SYMBOLS:
                hits.add((rel, f"call {func.id}"))
            elif isinstance(func, ast.Attribute) \
                    and func.attr in _WORKER_SYMBOLS:
                hits.add((rel, f"call {func.attr}"))
    return hits


def test_generation_adds_zero_queue_or_worker_symbols():
    hits: set[tuple[str, str]] = set()
    for pkg in ("ai_pr_reviewer", "dashboard"):
        for path in sorted((ROOT / pkg).rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            hits |= _worker_scan(rel, path.read_text(encoding="utf-8"))
    new = hits - _WORKER_BASELINE
    assert new == set(), f"new queue/worker symbols: {sorted(new)}"

    # self-check: the scanner sees what it exists to see
    assert _worker_scan("x.py", "import json\n") == set()
    assert _worker_scan("x.py", "import threading\n") == {
        ("x.py", "import threading")}
    assert _worker_scan("x.py", "import asyncio\n") == {
        ("x.py", "import asyncio")}
    assert _worker_scan("x.py", "ThreadPoolExecutor(max_workers=2)\n") == {
        ("x.py", "call ThreadPoolExecutor")}
    # a package NAME that mentions concurrency is not an import of it
    assert _worker_scan(
        "x.py", "import ai_pr_reviewer.orchestration\n") == set()


def test_emit_module_itself_is_free_of_queue_worker_io_symbols():
    source = (ROOT / "ai_pr_reviewer" / "events" / "emit.py").read_text(
        encoding="utf-8")
    assert _violations(source) == []


def _cfg(enabled: bool) -> Config:
    return Config(repo="acme/api", pr_number=1, severity_threshold="low",
                  max_comments=20, event_bus=enabled)


def test_event_bus_flag_is_plain_env_default_off(monkeypatch):
    monkeypatch.delenv("EVENT_BUS", raising=False)
    assert load_config(parse_args([])).event_bus is False

    monkeypatch.setenv("EVENT_BUS", "true")
    assert load_config(parse_args([])).event_bus is True

    # deliberately NOT an action input: INPUT_* must not enable it
    monkeypatch.delenv("EVENT_BUS", raising=False)
    monkeypatch.setenv("INPUT_EVENT_BUS", "1")
    assert load_config(parse_args([])).event_bus is False

    # and no CLI flag exists
    with pytest.raises(SystemExit):
        parse_args(["--event-bus"])


def test_disabled_emit_is_zero_surface_even_with_garbage_input(
        monkeypatch):
    monkeypatch.setattr(emit_module, "_BUS", None)
    cfg = _cfg(False)
    assert bus_for(cfg) is None              # nothing to subscribe to
    # a benign event changes no state at all
    assert emit(_event(payload={"ok": 1}), cfg=cfg) == []
    assert get_bus() is None                 # no singleton was created
    # safety still runs when disabled: labels come back, dispatch never
    warnings = emit({"schema_version": "v9"}, cfg=cfg)
    assert warnings and warnings[0].startswith("event dropped (")
    assert get_bus() is None


def test_enabled_emit_is_synchronous_and_reports_backpressure(
        monkeypatch):
    monkeypatch.setattr(emit_module, "_BUS", None)
    cfg = _cfg(True)
    bus = bus_for(cfg)
    assert isinstance(bus, EventBus)
    assert bus_for(cfg) is bus               # cached singleton
    assert get_bus() is bus

    seen: list[str] = []

    def hungry(ev):
        seen.append(ev.event_id)
        if ev.event_id == "seed":
            for i in range(MAX_PENDING_EVENTS + 6):
                emit(_event(event_id=f"f{i}"), cfg=cfg)  # re-entrant entry

    bus.subscribe(hungry)
    warnings = emit(_event(event_id="seed"), cfg=cfg)
    # synchronous: delivery already happened when emit() returned
    assert seen[0] == "seed"
    assert len(seen) == 1 + MAX_PENDING_EVENTS
    assert bus.stats.dropped == 6
    assert warnings == ["event bus dropped 6 pending event(s) "
                        "(backpressure)"]


def test_bus_disabled_equivalence_matches_empty_bus(monkeypatch):
    """Flag OFF ≡ flag ON with zero subscribers: identical warnings,
    zero deliveries either way — disabling the bus changes nothing
    observable."""
    monkeypatch.setattr(emit_module, "_BUS", None)
    off_cfg, on_cfg = _cfg(False), _cfg(True)

    events = [_event(event_id=f"e{i}", payload={"i": i}) for i in range(3)]
    off_warnings = [emit(ev, cfg=off_cfg) for ev in events]
    bus = bus_for(on_cfg)                    # enabled, NO subscriber yet
    assert bus is not None and bus.subscriber_count == 0
    on_warnings = [emit(ev, cfg=on_cfg) for ev in events]
    assert off_warnings == on_warnings == [[], [], []]
    # equivalence is about what anyone SUBSCRIBED can observe: envelopes
    # were processed (stats.events counts them) but nothing was DELIVERED
    stats = bus.stats.to_dict()
    assert stats["deliveries"] == 0
    assert stats["dropped"] == 0 and stats["quarantined"] == 0

    # hostile input: byte-identical labels with the bus off or on
    hostile = {"schema_version": "v9"}
    assert emit(hostile, cfg=off_cfg) == emit(hostile, cfg=on_cfg)

    # and once a subscriber EXISTS, flag OFF still delivers nothing:
    # the flag gates the entry, not just bus construction
    seen: list[str] = []
    bus.subscribe(lambda ev: seen.append(ev.event_id))
    assert emit(_event(event_id="late"), cfg=off_cfg) == []
    assert seen == []
    assert emit(_event(event_id="late"), cfg=on_cfg) == []
    assert seen == ["late"]                 # flag ON does deliver
