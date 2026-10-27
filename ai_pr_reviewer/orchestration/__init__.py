"""Bounded multi-task review orchestration (V4.0, ADR-006).

``orchestrator.py`` stays the composition root. This package holds the
pieces that run *several* analysis tasks inside one review:

* :mod:`.executor` - the bounded in-process scheduler (V4.0-E01-T01/T02/T04);
* :mod:`.outcome`  - how task results become one honest outcome, including
  the degraded cases (V4.0-E01-T03);
* :mod:`.runner`   - the opt-in entry point the orchestrator calls when the
  fan-out flag is on (V4.0-E01-T05).

Everything here is in-process: no queue, no worker, no network of its own.
Importing this package performs no work and imports nothing heavy.
"""
