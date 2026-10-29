"""V4.6-E07-T03 — redaction-on-emit + schema validation.

``deliver`` is the emit boundary: the only sanctioned way an envelope
crosses into the bus (and, later, the append-only log). Two invariants,
both enforced here rather than trusted to callers:

* **schema validation at emit** — anything that is not yet an
  ``EventEnvelope`` runs through ``validate_event`` first, so unknown
  schema versions, missing fields and bound violations are refused at
  the same chokepoint that redacts;
* **redaction before anyone sees it** — every string that leaves through
  an event (``event_type``, ``source``, ``subject``, ``event_id``,
  ``timestamp``, payload keys and values, provenance fields) passes
  ``redact_secrets`` plus the caller's configured scrub. This includes
  40-hex runs, deliberately: subscribers see only post-redaction content,
  the same rule report output obeys.

Refusal is the answer when redaction cannot preserve a closed-vocabulary
field — a credential-shaped ``source`` redacts to "[REDACTED]", which no
longer matches the source format. The event is then DROPPED with a
content-free label: never emitted unredacted, never raised at the caller.
``deliver`` therefore never raises; schema refusals, redaction refusals
and bound violations all come back as a warning string (``None`` on
success), and those labels echo no payload content (an untrusted string
must not travel in a warning).
"""
from __future__ import annotations

from typing import Any, Callable

from ..models import ProvenanceSource
from ..security import redact_secrets
from .bus import EventBus
from .schema import EventEnvelope, make_event, validate_event

Scrub = Callable[[str], str] | None


def _clean(value: str, scrub: Scrub) -> str:
    """Pattern redaction first, then the configured-credential scrub —
    the same order every other redaction boundary in the package uses."""
    out = redact_secrets(value)
    if scrub is not None:
        out = str(scrub(out))
    return out


def _clean_opt(value: str | None, scrub: Scrub) -> str | None:
    return None if value is None else _clean(value, scrub)


def _walk(value: Any, scrub: Scrub) -> Any:
    if isinstance(value, str):
        return _clean(value, scrub)
    if isinstance(value, list):
        return [_walk(item, scrub) for item in value]
    if isinstance(value, dict):
        return _walk_keys(value, scrub)
    return value                          # numbers/bools/None: no text


def _walk_keys(payload: dict, scrub: Scrub) -> dict:
    """Redact keys and values; two keys collapsing to the same redacted
    name is a refusal, never a silent overwrite of payload content."""
    out: dict[str, Any] = {}
    for key, item in payload.items():
        new_key = _clean(key, scrub)
        if new_key in out:
            raise ValueError(
                "event payload key collision after redaction")
        out[new_key] = _walk(item, scrub)
    return out


def redact_event(event: object, *, scrub: Scrub = None) -> EventEnvelope:
    """Validate (if needed) + redact every string of ``event``.

    Returns a NEW envelope; the input is never mutated. Raises
    ``ValueError`` with a content-free label on any refusal — schema,
    bounds or redaction-induced format breakage — so a credential can
    never leave this package inside a field that redaction invalidated.
    """
    if not isinstance(event, EventEnvelope):
        # schema validation first: unknown version refused with its label
        event = validate_event(event)
    provenance = event.provenance
    return make_event(
        _clean(event.event_type, scrub),
        source=_clean(event.source, scrub),
        subject=_clean(event.subject, scrub),
        payload=_walk_keys(event.payload, scrub),
        provenance=ProvenanceSource(
            engine=_clean_opt(provenance.engine, scrub),
            model=_clean_opt(provenance.model, scrub),
            origin=_clean_opt(provenance.origin, scrub),
            agent=_clean_opt(provenance.agent, scrub)),
        event_id=_clean(event.event_id, scrub),
        timestamp=_clean(event.timestamp, scrub),
    )


def deliver(bus: EventBus | None, event: object, *,
            scrub: Scrub = None) -> str | None:
    """Validate + redact, then dispatch to ``bus``. NEVER raises.

    Returns ``None`` on success, otherwise a content-free warning label
    describing the refusal (the event is dropped — invalid or
    unredactable events must not fail a review). ``bus=None`` is the
    bus-disabled path: redaction and validation still run, only
    dispatch is skipped, so the safety properties hold with the bus off.
    """
    try:
        safe = redact_event(event, scrub=scrub)
    except ValueError as exc:
        return f"event dropped ({exc})"
    except Exception as exc:              # noqa: BLE001 — emit must not raise
        return f"event dropped ({type(exc).__name__})"
    if bus is not None:
        bus.emit(safe)
    return None
