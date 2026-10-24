"""Telemetry spine (V3-E02 · ADR-014): counts and durations only.

Content-free by construction (``COST_TOKEN_ARCHITECTURE.md`` §3.4): a
record may carry provider/model names, token counts, durations, status
classes and opaque ids — never diffs, prompts, finding text, file paths
or secrets. The run-level serialization chokepoint
(:func:`to_telemetry_row`, added with the report plumbing in
V3-E02-T02) is the single place records leave the process: report JSON,
storage rows and dashboard aggregates all read from it.

Absence is a *typed state*, never a fake zero:

``ok``
    the provider reported token usage.
``unavailable``
    calls ran but the provider gave no usage block (or a malformed one).
``n/a``
    no provider call happened at all — the deterministic rule engine
    spends no tokens, so reporting ``0`` would be a lie about a
    different thing.

Local-first (ADR-014): these records are persisted only where the user
already persists reports — there is no telemetry egress to any endpoint
we operate.
"""
from __future__ import annotations

import json
import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Mapping

STATE_OK = "ok"                    # the provider reported token usage
STATE_UNAVAILABLE = "unavailable"  # calls ran, the provider gave no usage
STATE_NA = "n/a"                   # no provider call happened (static/mock)

USAGE_STATES = (STATE_OK, STATE_UNAVAILABLE, STATE_NA)

# Serialization bounds — a run has at most ``batch_count`` calls and a
# bounded number of retry/failover events, but the caps make that an
# invariant rather than an assumption (counts stay cheap to aggregate).
_MAX_CALLS = 200
_MAX_EVENTS = 200


def event_ts() -> str:
    """UTC timestamp for telemetry events (second resolution)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _as_int(value: object) -> int | None:
    """A token count must be a plain ``int`` — bools and strings are
    "not reported", never coerced into a number."""
    return value if type(value) is int else None


@dataclass
class UsageRecord:
    """Token usage for one provider call, or one aggregated provider run.

    ``None`` token fields mean "not reported" — deliberately distinct
    from ``0`` (V3-E02-T01: never fake a zero).
    """

    provider: str = ""
    model: str = ""
    input_tokens: int | None = None
    output_tokens: int | None = None
    duration_ms: int | None = None
    state: str = STATE_NA

    @classmethod
    def for_call(cls, provider: str, model: str,
                 input_tokens: object, output_tokens: object,
                 duration_ms: int | None = None) -> "UsageRecord":
        """Build the record for one provider response.

        Anything that is not a plain ``int`` counts as "not reported";
        if *neither* side reported, the call's state is ``unavailable``.
        """
        inputs = _as_int(input_tokens)
        outputs = _as_int(output_tokens)
        if inputs is None and outputs is None:
            return cls(provider=provider, model=model,
                       duration_ms=duration_ms, state=STATE_UNAVAILABLE)
        return cls(provider=provider, model=model, input_tokens=inputs,
                   output_tokens=outputs, duration_ms=duration_ms,
                   state=STATE_OK)

    @classmethod
    def na(cls, provider: str = "", model: str = "") -> "UsageRecord":
        """No provider call happened — the deterministic engine's state."""
        return cls(provider=provider, model=model, state=STATE_NA)

    @property
    def unavailable(self) -> bool:
        return self.state == STATE_UNAVAILABLE

    def to_dict(self) -> dict:
        return {
            "provider": self.provider,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "duration_ms": self.duration_ms,
            "state": self.state,
        }


def summarize_calls(provider: str, model: str,
                    calls: list[UsageRecord]) -> UsageRecord:
    """Aggregate a provider's per-call records into one run-level record.

    * no calls at all -> ``n/a`` (nothing ran);
    * calls but none reported usage -> ``unavailable``;
    * otherwise the sums over the calls that *did* report, marked
      ``ok`` — a mixed run under-counts rather than inventing the
      missing half.
    """
    if not calls:
        return UsageRecord.na(provider, model)
    reported = [c for c in calls if c.state == STATE_OK]
    durations = [c.duration_ms for c in calls
                 if type(c.duration_ms) is int]
    duration = sum(durations) if durations else None
    if not reported:
        return UsageRecord(provider=provider, model=model,
                           duration_ms=duration, state=STATE_UNAVAILABLE)
    return UsageRecord(
        provider=provider, model=model,
        input_tokens=sum(c.input_tokens or 0 for c in reported),
        output_tokens=sum(c.output_tokens or 0 for c in reported),
        duration_ms=duration, state=STATE_OK)


# ---------------------------------------------------------------------- T02

# Allowlists. Anything not on these lists is dropped structurally at the
# chokepoint — telemetry can only ever carry the shapes below (COST §3.4:
# a payload never contains code, diffs, paths or prompt content).
_RUN_FIELDS = ("schema", "provider", "model", "batch_count", "fallback_used",
               "usage", "calls", "events",
               # V4-E11-T07 (additive): display-only cost estimate block.
               "cost")
_CALL_FIELDS = ("provider", "model", "input_tokens", "output_tokens",
                "duration_ms", "state")
_EVENT_FIELDS = ("type", "backend", "from", "to", "attempt", "delay_ms",
                 "status", "error", "reason", "ts")
# V3-E02-T06: event *values* are an allowlist too. An event whose ``type``
# is not one of these is an unapproved payload and is dropped whole —
# adding an event type means adding it here, next to its producer.
_EVENT_TYPES = ("retry", "provider_error", "failover", "circuit",
                "static_fallback")
_INT_EVENT_FIELDS = ("attempt", "delay_ms", "status")
# A telemetry string is a name/status scalar, never a document: bound it
# so a stray blob (prompt, diff, stack trace) cannot ride along in a
# scalar field even if a future caller feeds one in.
_MAX_STR = 200
_SCHEMA_VERSION = 1


@dataclass
class RunTelemetry:
    """One run's telemetry block — one per analysis outcome.

    Built by the provider (or the static engine) that produced the
    outcome; converted to its serializable form exactly once, via
    :func:`to_telemetry_row`.
    """

    provider: str = ""
    model: str = ""
    batch_count: int = 0
    fallback_used: bool = False
    usage: UsageRecord = field(default_factory=UsageRecord.na)
    calls: list[UsageRecord] = field(default_factory=list)
    events: list[dict] = field(default_factory=list)


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]+")


def _bounded_str(value: object) -> str:
    """A scalar telemetry string must *be* a string — a dict/list smuggled
    through an allowed key is dropped to ``""``.

    V4-E11 (debt 11 ground rule): provider warning/error text reaches rows
    through here, so it gets *safe formatting* — control characters (ESC,
    CR/LF, NUL, U+2028/9 ...) collapse to one space so a payload cannot
    forge log lines or terminal sequences — then fence-neutralization +
    ``redact_secrets``, and only **then** the length bound. Truncating
    last means a secret straddling the bound is redacted whole instead of
    being cut into a prefix the scrubber no longer recognizes.
    """
    if not isinstance(value, str):
        return ""
    from .security import OPEN_TAG_RE, redact_secrets
    text = _CONTROL_RE.sub(" ", value)
    text = redact_secrets(OPEN_TAG_RE.sub("[neutralized-fence-tag]", text))
    return text if len(text) <= _MAX_STR else text[:_MAX_STR]


def _redact(value):
    """Scrub every string on its way out of the process.

    Two transforms, both owned by ``security.py`` so there is exactly one
    implementation of each:

    * fence-marker neutralization — the same ``OPEN_TAG_RE`` substitution
      ``wrap_untrusted_diff`` performs; a spoofed ``<untrusted_diff>``
      fence must never reach a report or a stored row;
    * ``redact_secrets`` — the credential-pattern scrubber.

    Applied recursively to every string in the row. Idempotent, so the
    storage/report boundaries can re-apply the same sanitizer safely.
    """
    if isinstance(value, str):
        from .security import OPEN_TAG_RE, redact_secrets
        return redact_secrets(OPEN_TAG_RE.sub("[neutralized-fence-tag]", value))
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, dict):
        return {k: _redact(v) for k, v in value.items()}
    return value


def _sanitize_usage(raw: object) -> dict:
    """Allowlist + coerce one usage block (call records share its shape).

    * only ``_CALL_FIELDS`` keys survive — planted keys (paths, prompts,
      finding text) are dropped structurally;
    * token/duration values must be plain ints, else "not reported"
      (never coerced, never faked);
    * ``state`` must be one of ``USAGE_STATES``; anything else becomes
      the typed ``unavailable`` state **and its token counts are
      dropped** — an untrusted state can never claim a measurement.
    """
    source = raw if isinstance(raw, dict) else {}
    state = source.get("state")
    state = state if state in USAGE_STATES else STATE_UNAVAILABLE
    inputs = _as_int(source.get("input_tokens"))
    outputs = _as_int(source.get("output_tokens"))
    if state != STATE_OK:
        inputs = outputs = None
    return {
        "provider": _bounded_str(source.get("provider")),
        "model": _bounded_str(source.get("model")),
        "input_tokens": inputs,
        "output_tokens": outputs,
        "duration_ms": _as_int(source.get("duration_ms")),
        "state": state,
    }


def _sanitize_event(raw: object) -> dict | None:
    """Allowlist + coerce one event; ``None`` means "drop this event".

    The ``type`` value must be one of ``_EVENT_FIELDS``' sibling
    ``_EVENT_TYPES`` — an unknown type is unapproved payload, so the
    whole event goes rather than carrying its (possibly content-bearing)
    fields. String values are bounded; int fields must be ints.
    """
    if not isinstance(raw, dict):
        return None
    etype = raw.get("type")
    if etype not in _EVENT_TYPES:
        return None
    out: dict = {}
    for key in _EVENT_FIELDS:
        if key not in raw:
            continue
        if key == "type":
            out[key] = etype
        elif key in _INT_EVENT_FIELDS:
            out[key] = _as_int(raw[key])
        else:
            out[key] = _bounded_str(raw[key])
    return out


def _sanitize_row(raw: object) -> dict:
    """The one row sanitizer: key allowlist + typed coercion + value
    allowlists + bounds + redaction/fence scrubbing (V3-E02-T06).

    A plain dict in, an approved row out — input keys that are not on
    ``_RUN_FIELDS`` never make it to the output, so arbitrary payloads
    cannot be persisted or reported by handing this function a dict.
    """
    source = raw if isinstance(raw, dict) else {}
    raw_calls = source.get("calls")
    calls = ([_sanitize_usage(c) for c in raw_calls[:_MAX_CALLS]
              if isinstance(c, dict)] if isinstance(raw_calls, list) else [])
    raw_events = source.get("events")
    events = ([e for e in (_sanitize_event(ev)
                           for ev in raw_events[:_MAX_EVENTS])
               if e is not None] if isinstance(raw_events, list) else [])
    usage = _sanitize_usage(source.get("usage"))
    row = {
        "schema": _SCHEMA_VERSION,
        "provider": _bounded_str(source.get("provider")),
        "model": _bounded_str(source.get("model")),
        "batch_count": _as_int(source.get("batch_count")) or 0,
        "fallback_used": bool(source.get("fallback_used")),
        "usage": usage,
        "calls": calls,
        "events": events,
        "cost": _sanitize_cost(source.get("cost"), usage, calls),
    }
    return _redact(row)


def to_telemetry_row(tel: RunTelemetry) -> dict:
    """THE telemetry serialization chokepoint (COST §3.4 · V3-E02-T02).

    Two invariants enforced here, on every path out of the process:

    * **allowlist** — only the fields named in ``_RUN_FIELDS`` /
      ``_CALL_FIELDS`` / ``_EVENT_FIELDS`` survive, and only the
      ``_EVENT_TYPES`` / ``USAGE_STATES`` values; anything a caller
      tacks onto a record (a planted key, a path, prompt text) is
      dropped structurally;
    * **redaction** — every string value passes through fence
      neutralization + ``redact_secrets`` before it can reach a report
      or storage.

    Implementation note (V3-E02-T06): the heavy lifting lives in
    :func:`_sanitize_row`, shared with :func:`sanitize_telemetry`, so
    the storage/report boundaries enforce the *same* contract rather
    than a second, divergent one.
    """
    return _sanitize_row({
        "schema": _SCHEMA_VERSION,
        "provider": tel.provider,
        "model": tel.model,
        "batch_count": tel.batch_count,
        "fallback_used": tel.fallback_used,
        "usage": tel.usage.to_dict(),
        "calls": [c.to_dict() for c in tel.calls[:_MAX_CALLS]],
        "events": [ev for ev in tel.events[:_MAX_EVENTS]
                   if isinstance(ev, dict)],
    })


def sanitize_telemetry(payload: object) -> dict | None:
    """Boundary sanitizer for an already-serialized telemetry payload
    (V3-E02-T06): the *same* allowlist + coercion + redaction
    :func:`to_telemetry_row` applies, expressed over a plain dict.

    Storage backends and ``ReviewResult.to_dict`` call this so nothing
    arbitrary can be persisted or reported by handing them a raw dict —
    the invariant is structural at every boundary, not by convention.
    Idempotent on rows that already went through the chokepoint.

    Returns ``None`` for anything that is not a dict (a caller bug or an
    injection attempt — there is nothing to persist).
    """
    if not isinstance(payload, dict):
        return None
    return _sanitize_row(payload)


# ------------------------------------------------------- V4-E11-T07 · cost
# DISPLAY ONLY (V4_THREAT_MODEL §6, EPIC_BACKLOG rejected scope "cost-based
# routing"). Nothing in this section may be imported by any routing,
# retry, circuit, context-selection or orchestration module; the review
# gate in tests/test_telemetry.py fails the build if one ever does.
#
# No model id and no price is shipped in source (repo discipline: model
# ids are operator-supplied — see test_release_hardening). The price table
# is *data the operator provides*:
#
#   AI_PR_REVIEWER_PRICE_TABLE='{"<model-id>": {"input_per_mtok": 1.0,
#                                               "output_per_mtok": 2.0}}'
#
# Keys match the reported model exactly, or by a trailing ``*`` prefix
# (longest prefix wins). Prices are USD per million tokens. Absent table or
# unmatched model => state ``unpriced`` (no number — "no data beats a
# fabricated number"), never a guess.
COST_STATE_ESTIMATED = "estimated"
COST_STATE_UNPRICED = "unpriced"        # usage reported, no price for it
COST_STATE_UNAVAILABLE = "unavailable"  # calls ran, provider gave no usage
COST_STATE_NA = "n/a"                   # no provider call happened
COST_STATES = (COST_STATE_ESTIMATED, COST_STATE_UNPRICED,
               COST_STATE_UNAVAILABLE, COST_STATE_NA)
COST_CURRENCY = "USD"

PRICE_TABLE_ENV = "AI_PR_REVIEWER_PRICE_TABLE"
# Price drift band (proposed baseline, uncalibrated — ADR-014: "price
# tables drift → cost figures labeled estimates"). Per-entry override via
# ``band_pct``.
DEFAULT_BAND_PCT = 15.0
_MAX_PRICE_ENTRIES = 64
_MAX_PRICE_KEY = 100
_MAX_PRICE_PER_MTOK = 1_000_000.0
_MAX_PRICE_JSON_CHARS = 20_000
_MAX_COST_USD = 10_000_000.0


@dataclass(frozen=True)
class Price:
    """USD per million tokens for one table entry."""

    input_per_mtok: float
    output_per_mtok: float
    band_pct: float = DEFAULT_BAND_PCT


def _num(value: object, hi: float) -> float | None:
    """A finite, non-negative real within bounds — bools/strings are not
    numbers (same stance as ``_as_int``)."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    f = float(value)
    return f if math.isfinite(f) and 0.0 <= f <= hi else None


def parse_price_table(raw: object) -> dict[str, Price]:
    """Strictly parse a ``{model-key: {...}}`` mapping. Invalid entries are
    skipped (never raised, never coerced); bounded in count and key size."""
    if not isinstance(raw, dict):
        return {}
    table: dict[str, Price] = {}
    for key, entry in raw.items():
        if len(table) >= _MAX_PRICE_ENTRIES:
            break
        if (not isinstance(key, str) or not key.strip()
                or len(key) > _MAX_PRICE_KEY or not isinstance(entry, dict)):
            continue
        inp = _num(entry.get("input_per_mtok"), _MAX_PRICE_PER_MTOK)
        out = _num(entry.get("output_per_mtok"), _MAX_PRICE_PER_MTOK)
        if inp is None or out is None:
            continue
        band = _num(entry.get("band_pct", DEFAULT_BAND_PCT), 100.0)
        table[key.strip()] = Price(inp, out, DEFAULT_BAND_PCT
                                   if band is None else band)
    return table


def load_price_table(environ: Mapping[str, str] | None = None,
                     ) -> dict[str, Price]:
    """The operator's price table from ``AI_PR_REVIEWER_PRICE_TABLE``;
    ``{}`` on absence or *any* problem (cost display must never fail a
    review)."""
    env = os.environ if environ is None else environ
    text = env.get(PRICE_TABLE_ENV, "")
    if not text or len(text) > _MAX_PRICE_JSON_CHARS:
        return {}
    try:
        return parse_price_table(json.loads(text))
    except (ValueError, RecursionError):
        return {}


def lookup_price(table: Mapping[str, Price], model: object) -> Price | None:
    """Exact key first, then the longest trailing-``*`` prefix key."""
    if not isinstance(model, str) or not model:
        return None
    exact = table.get(model)
    if exact is not None:
        return exact
    best: tuple[int, Price] | None = None
    for key, price in table.items():
        if key.endswith("*") and model.startswith(key[:-1]):
            if best is None or len(key) > best[0]:
                best = (len(key), price)
    return best[1] if best else None


def _cost_block(state: str, low: float | None = None,
                high: float | None = None) -> dict:
    return {"state": state, "currency": COST_CURRENCY,
            "low": low, "high": high, "display_only": True}


def estimate_cost(usage: Mapping, calls: Iterable[Mapping] | None = None,
                  table: Mapping[str, Price] | None = None) -> dict:
    """Price table × reported usage -> an estimated cost *band* (display
    only). Pure function of its inputs; ``table`` defaults to the operator
    table from the environment.

    * usage ``n/a`` / ``unavailable`` map to the same-named cost state;
    * per-call usage (each priced by its own reported model — failover
      runs mix models) is used when any call reported, else the run-level
      usage block;
    * **all-or-nothing**: if any reporting model has no price the whole
      estimate is ``unpriced`` — a partial sum would read as a total;
    * mixed runs inherit ``summarize_calls``' under-count: only reported
      tokens are priced.
    """
    state = usage.get("state") if isinstance(usage, Mapping) else None
    if state == STATE_NA:
        return _cost_block(COST_STATE_NA)
    if state != STATE_OK:
        return _cost_block(COST_STATE_UNAVAILABLE)
    prices = load_price_table() if table is None else table
    reported = [c for c in (calls or ())
                if isinstance(c, Mapping) and c.get("state") == STATE_OK]
    units = reported or [usage]
    band_lo = band_hi = 0.0
    for unit in units:
        price = lookup_price(prices, unit.get("model"))
        inp, out = _as_int(unit.get("input_tokens")), _as_int(
            unit.get("output_tokens"))
        if price is None:
            return _cost_block(COST_STATE_UNPRICED)
        usd = ((inp or 0) * price.input_per_mtok
               + (out or 0) * price.output_per_mtok) / 1_000_000
        band_lo += usd * (1 - price.band_pct / 100)
        band_hi += usd * (1 + price.band_pct / 100)
    return _cost_block(COST_STATE_ESTIMATED, round(band_lo, 6),
                       round(band_hi, 6))


def _sanitize_cost(raw: object, usage: dict, calls: list) -> dict:
    """Carry a well-formed, *consistent* cost block through; recompute
    otherwise. Consistency mirrors the usage rule ("an untrusted state can
    never claim a measurement"): the cost state must be compatible with
    the row's own usage state, numbers must be finite, bounded and
    ordered, and ``display_only`` is forced ``True`` — a payload cannot
    turn the estimate into anything but a display value.
    """
    if isinstance(raw, dict):
        cstate = raw.get("state")
        ustate = usage.get("state")
        compatible = {STATE_OK: (COST_STATE_ESTIMATED, COST_STATE_UNPRICED),
                      STATE_UNAVAILABLE: (COST_STATE_UNAVAILABLE,),
                      STATE_NA: (COST_STATE_NA,)}.get(ustate, ())
        if cstate in compatible and raw.get("currency") == COST_CURRENCY:
            if cstate == COST_STATE_ESTIMATED:
                low = _num(raw.get("low"), _MAX_COST_USD)
                high = _num(raw.get("high"), _MAX_COST_USD)
                if low is not None and high is not None and low <= high:
                    return _cost_block(cstate, round(low, 6), round(high, 6))
            else:
                return _cost_block(cstate)
    return estimate_cost(usage, calls)


# ------------------------------------------------------ V4-E11-T06 · latency
def percentile(values: Iterable[object], pct: float) -> int | float | None:
    """Nearest-rank percentile (deterministic, no interpolation) over the
    plain-int/float values; ``None`` for no data (never a fake 0)."""
    nums = sorted(v for v in values
                  if isinstance(v, (int, float)) and not isinstance(v, bool)
                  and math.isfinite(v))
    if not nums:
        return None
    rank = max(1, math.ceil(pct / 100 * len(nums)))
    return nums[min(rank, len(nums)) - 1]


def summarize_latency(durations_ms: Iterable[object]) -> dict:
    """``{n, p50, p95, max}`` over reported durations; the percentile
    fields are ``None`` when ``n == 0``."""
    vals = [v for v in durations_ms
            if isinstance(v, (int, float)) and not isinstance(v, bool)
            and math.isfinite(v)]
    return {"n": len(vals), "p50": percentile(vals, 50),
            "p95": percentile(vals, 95), "max": max(vals) if vals else None}


def latency_from_rows(rows: Iterable[object]) -> dict:
    """Per-call and per-run latency summaries over telemetry rows (stored,
    ingested or harness-captured). Rows are untrusted dicts: only plain-int
    durations count."""
    per_call: list[object] = []
    per_run: list[object] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        usage = row.get("usage")
        if isinstance(usage, dict):
            per_run.append(usage.get("duration_ms"))
        for call in (row.get("calls") or ()):
            if isinstance(call, dict):
                per_call.append(call.get("duration_ms"))
    return {"per_call_ms": summarize_latency(per_call),
            "per_run_ms": summarize_latency(per_run)}


__all__ = [
    "STATE_NA", "STATE_OK", "STATE_UNAVAILABLE", "USAGE_STATES",
    "RunTelemetry", "UsageRecord", "event_ts", "sanitize_telemetry",
    "summarize_calls", "to_telemetry_row",
    # V4-E11 (display-only cost; latency summaries) — never routing inputs.
    "COST_STATES", "PRICE_TABLE_ENV", "Price", "estimate_cost",
    "latency_from_rows", "load_price_table", "lookup_price",
    "parse_price_table", "percentile", "summarize_latency",
]
