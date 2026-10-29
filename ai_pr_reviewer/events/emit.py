"""V4.6-E07-T05 — module-level ``emit()``: synchronous dispatch with a
bus-disabled fallback.

Flag-gated by ``Config.event_bus`` (plain env ``EVENT_BUS``, default OFF
— enabling a default-off feature needs human sign-off per plan §F). The
entry is duck-typed on the config via ``getattr``, so the events package
never imports config/CLI layers and a future producer can pass its own
config straight through.

* **enabled** — the process-wide bus is created on first use and
  ``deliver`` validates + redacts + dispatches INLINE: subscriber
  delivery and backpressure counting finish before ``emit`` returns.
  Nothing is deferred, buffered to a thread or handed to a worker;
* **disabled (synchronous fallback)** — the same validation and
  redaction run with zero dispatch: no bus object exists, no subscriber
  can attach, nothing is written. Refusal labels still come back,
  because validation and redaction are safety properties, not features.
  The equivalence tests pin ``flag OFF ≡ flag ON with no subscribers``.

H9 adds no orchestrator hook: nothing in the review path calls ``emit``
yet (producers arrive with the V4.8 consumers), so a flag-OFF run is
byte-for-byte the baseline run — equivalence is pinned at the entry
point itself.
"""
from __future__ import annotations

from .bus import EventBus
from .redact import Scrub, deliver

_BUS: EventBus | None = None


def get_bus() -> EventBus | None:
    """The process-wide bus, or None while nothing enabled it."""
    return _BUS


def bus_for(cfg) -> EventBus | None:
    """The bus if the config enables it (created on demand), else None.

    This is also the subscription gate: ``bus_for(cfg) is None`` means
    the flag is off and there is nothing to subscribe to — callers never
    need to read the flag themselves.
    """
    if cfg is None or not getattr(cfg, "event_bus", False):
        return None
    global _BUS
    if _BUS is None:
        _BUS = EventBus()
    return _BUS


def emit(event: object, *, cfg=None, scrub: Scrub = None) -> list[str]:
    """Validate + redact + (when enabled) dispatch. Never raises.

    Returns content-free warnings: schema/redaction refusal labels, plus
    — when THIS call's dispatch overflowed the bounded buffer — a
    counted backpressure notice. Flag OFF takes the synchronous
    fallback: identical validation/redaction, zero dispatch.
    """
    warnings: list[str] = []
    bus = bus_for(cfg)
    before = bus.stats.dropped if bus is not None else 0
    label = deliver(bus, event, scrub=scrub)
    if label is not None:
        warnings.append(label)
    if bus is not None:
        dropped = bus.stats.dropped - before
        if dropped:
            warnings.append(
                f"event bus dropped {dropped} pending event(s) "
                f"(backpressure)")
    return warnings
